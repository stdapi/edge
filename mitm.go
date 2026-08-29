// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"

	"github.com/fox-toolkit/edge/internal/stringsutil"

	"golang.org/x/net/http2"
)

// tlsHandshakeRecord is the TLS record type of a handshake message. A connection whose first
// byte is anything else is not TLS, which is how a CONNECT to a plaintext port is detected.
const tlsHandshakeRecord = 0x16

// downstreamProtocols are the ALPN identifiers the proxy is willing to speak to a client
// over TCP, in the order it prefers them. HTTP/3 is not here: it runs over QUIC, which never
// reaches this path.
var downstreamProtocols = []string{"h2", "http/1.1"}

// intercept terminates an intercepted connection and serves the requests it carries.
func (p *Proxy) intercept(ctx context.Context, conn *peekConn, sess *Session) error {
	head, err := conn.Peek(1)
	if err != nil {
		// A client that opens a tunnel and sends nothing is not an error worth reporting.
		return nil
	}

	if head[0] != tlsHandshakeRecord {
		// A CONNECT to a plaintext port, or a transparent connection carrying clear HTTP.
		sess.target.Scheme = "http"
		return p.serveIntercepted(ctx, conn, sess, HTTP11)
	}

	if p.cfg.ca == nil {
		return fmt.Errorf("%w: %w", ErrNoCertificateAuthority, errNoCA)
	}

	tlsConn := tls.Server(conn, p.serverTLSConfig(sess))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("tls handshake with client for %s: %w", sess.target.Authority(), err)
	}

	state := tlsConn.ConnectionState()
	sess.tlsState = &state
	sess.target.Scheme = "https"
	// The server name the client asked for is what it believes it is talking to. It is a
	// better identity than the CONNECT authority, which an explicit proxy client may write
	// as an address.
	if state.ServerName != "" {
		sess.target.Host = state.ServerName
	}
	sess.proto = protocolFromALPN(state.NegotiatedProtocol)

	return p.serveIntercepted(ctx, tlsConn, sess, sess.proto)
}

// serverTLSConfig builds the configuration the proxy presents to an intercepted client. The
// whole configuration is decided from the ClientHello so the certificate matches the name
// the client asked for and the negotiated protocol matches what it offered.
func (p *Proxy) serverTLSConfig(sess *Session) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			sess.clientHello = &ClientHello{
				ServerName:        chi.ServerName,
				ALPN:              slices.Clone(chi.SupportedProtos),
				SupportedVersions: slices.Clone(chi.SupportedVersions),
				CipherSuites:      slices.Clone(chi.CipherSuites),
			}

			name := chi.ServerName
			if name == "" {
				// A client that sends no SNI, typically one connecting to an IP address,
				// still needs a certificate for the authority it asked to reach.
				name = sess.target.Host
			}

			return &tls.Config{
				MinVersion: tls.VersionTLS12,
				NextProtos: negotiateALPN(chi.SupportedProtos, downstreamProtocols),
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return p.cfg.ca.Leaf(name)
				},
			}, nil
		},
	}
}

// negotiateALPN returns the protocols to offer back to a client, keeping the client's
// preference order. An offer with nothing in common leaves ALPN unset, which falls back to
// HTTP/1.1 rather than failing the handshake with no_application_protocol.
func negotiateALPN(offered, supported []string) []string {
	if len(offered) == 0 {
		return nil
	}
	out := make([]string, 0, len(offered))
	for _, proto := range offered {
		if slices.Contains(supported, proto) {
			out = append(out, proto)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// serveIntercepted runs the HTTP server side of an intercepted connection. The requests it
// reads are ordinary origin-form requests, which is exactly what the routing tree expects.
func (p *Proxy) serveIntercepted(ctx context.Context, conn net.Conn, sess *Session, proto Protocol) error {
	if sess.remoteAddr == nil {
		sess.remoteAddr = conn.RemoteAddr()
	}
	if sess.localAddr == nil {
		sess.localAddr = conn.LocalAddr()
	}

	if proto == HTTP2 {
		sess.proto = HTTP2
		p.srv.h2.ServeConn(conn, &http2.ServeConnOpts{
			Context:    context.WithValue(ctx, sessionKey{}, sess),
			BaseConfig: p.srv.mitm,
			Handler:    http.HandlerFunc(p.serveInterceptedRequest),
		})
		return nil
	}

	sess.proto = HTTP11
	ln := newSingleConnListener(conn, sess)
	err := p.srv.mitm.Serve(ln)
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// serveInterceptedRequest routes one request read off an intercepted connection.
func (p *Proxy) serveInterceptedRequest(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromRequest(r)
	if sess == nil {
		sess = newSession(r.Context(), nil, Target{}, Intercept, protoOfRequest(r))
	}

	if r.TLS == nil && sess.tlsState != nil {
		// http.Server only recognizes a bare *tls.Conn, and the connection it was handed
		// is wrapped. Handlers still expect Request.TLS to describe the handshake.
		r.TLS = sess.tlsState
	}

	p.serve(w, r, sess, interceptedTarget(r, sess))
}

// interceptedTarget resolves the target of a request read off an intercepted connection.
// The Host header is what the client addressed the request to and is what an origin would
// route on, so it wins over the authority of the connection; the port comes from the
// connection, since an origin-form request carries none of its own.
func interceptedTarget(r *http.Request, sess *Session) Target {
	scheme := sess.target.Scheme
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host, port := splitHostPort(r.Host)
	if host == "" {
		host = sess.target.Host
	}
	if port == "" {
		port = sess.target.Port
	}
	if port == "" {
		port = defaultPort(scheme)
	}

	return Target{Scheme: scheme, Host: stringsutil.ToLowerASCIIString(host), Port: port}
}
