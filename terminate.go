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
	"time"

	"github.com/fox-toolkit/edge/internal/stringsutil"
)

// tlsHandshakeRecord is the TLS record type of a handshake message. A connection whose first
// byte is anything else is not TLS, which is how a CONNECT to a plaintext port is detected.
const tlsHandshakeRecord = 0x16

// terminate takes over an admitted connection, terminating TLS when there is TLS, works out
// what the traffic is, and serves it.
//
// What a connection is comes from the traffic alone, the negotiated ALPN when the client
// offered one and the first bytes otherwise. That fixes the kinds that could serve it, most
// specific first, and the tree picks among those. An HTTP connection with only a stream entry
// on its authority is served as a stream, and both see it in the clear.
func (p *Proxy) terminate(ctx context.Context, conn *peekConn, sess *Session) error {
	head, err := conn.Peek(1)
	if err != nil {
		// A client that opens a connection and sends nothing is not an error worth
		// reporting.
		return nil
	}

	if head[0] != tlsHandshakeRecord {
		// A CONNECT to a plaintext port.
		sess.target.Scheme = "http"
		return p.servePlain(ctx, conn, sess)
	}

	if p.cfg.ca == nil {
		return fmt.Errorf("%w: %w", ErrNoCertificateAuthority, errNoCA)
	}
	if err := p.placeTLS(ctx, conn, sess); err != nil {
		return err
	}

	tlsConn := tls.Server(conn, p.serverTLSConfig(sess))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("tls handshake with client for %s: %w", sess.target.Authority(), err)
	}

	state := tlsConn.ConnectionState()
	sess.tlsState.Store(&state)

	candidates := candidatesForALPN(state.NegotiatedProtocol, KindTCP)
	if candidates == nil {
		// The client offered no ALPN, so nothing has said what this is. Past the handshake
		// the payload is in the clear, which is exactly what the sniff reads.
		peeked := newPeekConn(tlsConn, nil, defaultPeekSize)
		return p.serveCandidates(ctx, peeked, sess, sniffStreamCandidates(peeked, p.cfg.server.sniffTimeout), &state)
	}
	return p.serveCandidates(ctx, tlsConn, sess, candidates, &state)
}

// placeTLS decides the authority a TLS connection is routed on, before the handshake commits
// the proxy to a certificate. The server name routes when the client sent one, the destination
// the connection was headed to is what the proxy dials, and name verification stands between
// the two. Nothing is consumed, the handshake reads the same bytes after.
func (p *Proxy) placeTLS(ctx context.Context, conn *peekConn, sess *Session) error {
	hello, err := p.peekClientHello(conn)
	if err != nil {
		return err
	}

	target := sess.target
	target.Scheme = "https"
	if target.Port == "" {
		target.Port = "443"
	}
	named := hello != nil && hello.ServerName != ""
	if named {
		target.Host = stringsutil.ToLowerASCIIString(hello.ServerName)
	}
	if target.Host == "" {
		return errors.New("edge: TLS connection with no server name and no destination")
	}

	target, admitted, verdict := p.targetForTransparent(ctx, target, sess.upstream, named, KindHTTP, KindTCP)
	switch verdict {
	case nameMismatch:
		return errNameMismatch
	case nameUnresolved:
		return errNameUnresolved
	}
	if !admitted {
		return ErrConnectionRejected
	}
	sess.target = target
	if hello != nil {
		sess.clientHello.Store(hello)
	}
	return nil
}

// peekClientHello reads the ClientHello waiting on conn without consuming it, nil when there
// is none it can read, and refuses the connection when the hello offers Encrypted Client
// Hello and the proxy rejects that.
func (p *Proxy) peekClientHello(conn *peekConn) (*ClientHello, error) {
	raw, err := peekHandshakeRecords(conn)
	if p.cfg.rejectECH {
		if err != nil {
			return nil, errECHUnverifiable
		}
		if cerr := checkECH(raw); cerr != nil {
			return nil, cerr
		}
	}
	if err != nil {
		return nil, nil
	}
	return clientHelloFromRecords(raw), nil
}

// servePlain serves a connection without TLS, routed on the authority of its first request.
func (p *Proxy) servePlain(ctx context.Context, conn *peekConn, sess *Session) error {
	candidates := sniffStreamCandidates(conn, p.cfg.server.sniffTimeout)
	sess.servableAs = candidates
	if !slices.Contains(candidates, KindHTTP) {
		return p.serveCandidates(ctx, conn, sess, candidates, nil)
	}
	placed := p.placePlain(ctx, conn, sess)
	if placed == plainTimedOut {
		return writeRawStatus(conn, http.StatusRequestTimeout)
	}
	if placed != plainRefused && p.admitsAny(sess.target, candidates...) {
		return p.serveCandidates(ctx, conn, sess, candidates, nil)
	}
	// Refused in HTTP, once for all when the first request has a host, as a handshake ends on a
	// server name nothing admits. Without a host, each request is routed on its own.
	sess.kind = KindHTTP
	sess.perRequest = true
	sess.refused = placed != plainNameless
	return p.serveHTTPConnection(conn, sess, nil)
}

// plainPlacement is the outcome of placePlain.
type plainPlacement uint8

const (
	plainNameless plainPlacement = iota
	plainNamed
	plainRefused
	plainTimedOut
)

// placePlain routes a plaintext HTTP connection on the host of its first request, as placeTLS
// does on the server name, verification included. The port stays the connection's, and nothing
// is consumed, the server reads the same bytes after.
func (p *Proxy) placePlain(ctx context.Context, conn *peekConn, sess *Session) plainPlacement {
	if d := p.cfg.server.readHeaderTimeout; d > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(d))
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	// The read-ahead was sized for a ClientHello, and a header block runs to what the server
	// accepts.
	limit := p.cfg.server.maxHeaderBytes
	conn.max = max(conn.max, limit)

	authority, err := peekAuthority(conn, limit)
	if isTimeout(err) {
		return plainTimedOut
	}
	host, _ := splitHostPort(authority)
	if host == "" {
		return plainNameless
	}
	target := sess.target
	target.Host = stringsutil.ToLowerASCIIString(host)
	verified, ok := p.verifyRequestHost(ctx, sess, target, KindHTTP, KindTCP)
	if !ok {
		return plainRefused
	}
	sess.target = verified
	if verified.Host != target.Host {
		return plainNameless
	}
	return plainNamed
}

// serveCandidates serves the connection at the finest granularity its authority admits, and
// closes it when none is admitted.
func (p *Proxy) serveCandidates(ctx context.Context, conn net.Conn, sess *Session, candidates []Kind, state *tls.ConnectionState) error {
	sess.servableAs = candidates
	if kind, e, params := p.firstAdmittedWith(sess.target, candidates); kind != 0 {
		sess.kind = kind
		if kind == KindHTTP {
			return p.serveHTTPConnection(conn, sess, state)
		}
		return p.serveTerminatedStream(ctx, conn, sess, state, e, params)
	}

	return ErrConnectionRejected
}

// serveHTTPConnection records the version the handshake settled on and hands the connection to
// the HTTP server.
func (p *Proxy) serveHTTPConnection(conn net.Conn, sess *Session, state *tls.ConnectionState) error {
	if state != nil {
		sess.setProtocol(protocolFromALPN(state.NegotiatedProtocol))
	}
	if sess.Protocol() == 0 {
		sess.setProtocol(HTTP11)
	}
	return p.serveTerminatedHTTP(conn, sess)
}

// serveTerminatedStream runs the [TCP] handler admitting this authority. The stream is in the
// clear here, whatever it was wrapped in on the wire.
func (p *Proxy) serveTerminatedStream(ctx context.Context, conn net.Conn, sess *Session,
	state *tls.ConnectionState, e *entry, params []Param,
) error {
	sess.closer = conn
	sess.entry.Store(e)
	if sess.remoteAddr == nil {
		sess.remoteAddr = conn.RemoteAddr()
	}
	if sess.localAddr == nil {
		sess.localAddr = conn.LocalAddr()
	}
	if !p.srv.admitSession(sess) {
		return ErrConnectionRejected
	}
	defer p.srv.trackSession(sess, false)

	c := &TCPCtx{
		ctx:      ctx,
		p:        p,
		sess:     sess,
		entry:    e,
		client:   heldConn{Conn: conn},
		params:   params,
		target:   sess.target,
		identity: sess.identity,
		tlsState: state,
	}
	defer c.close()

	handler, _ := e.serve.(TCP)
	if handler == nil {
		return errors.New("edge: TCP entry with no handler")
	}
	if err := runKindHandler(p, sess, func() error { return handler(c) }); err != nil {
		return err
	}
	return nil
}

// serverTLSConfig builds the configuration the proxy presents to a terminated client. The
// whole configuration is decided from the ClientHello so the certificate matches the name the
// client asked for and the negotiated protocol matches what it offered.
func (p *Proxy) serverTLSConfig(sess *Session) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			sess.clientHello.Store(&ClientHello{
				ServerName:        chi.ServerName,
				ALPN:              slices.Clone(chi.SupportedProtos),
				SupportedVersions: slices.Clone(chi.SupportedVersions),
				CipherSuites:      slices.Clone(chi.CipherSuites),
			})

			name := chi.ServerName
			if name == "" {
				// A client that sends no SNI, typically one connecting to an IP address,
				// still needs a certificate for the authority it asked to reach.
				name = sess.target.Host
			}

			return &tls.Config{
				MinVersion: tls.VersionTLS12,
				NextProtos: negotiateALPN(chi.SupportedProtos, KindTCP),
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					return p.cfg.ca.Leaf(name)
				},
			}, nil
		},
	}
}

// serveTerminatedHTTP runs the HTTP server side of a terminated connection. The requests it
// reads are ordinary origin-form requests, which is exactly what the routing tree expects.
//
// One server serves both protocols. An HTTP/2 client, ALPN or not, opens with the connection
// preface, which the server detects on the plaintext it is handed and answers natively. That
// single path ties every terminated connection to the server's graceful shutdown.
func (p *Proxy) serveTerminatedHTTP(conn net.Conn, sess *Session) error {
	if sess.remoteAddr == nil {
		sess.remoteAddr = conn.RemoteAddr()
	}
	if sess.localAddr == nil {
		sess.localAddr = conn.LocalAddr()
	}

	// Every terminated connection settles here, however it arrived, so this is the single
	// point where its session is registered with a target a reader can rely on.
	sess.closer = conn
	if !p.srv.admitSession(sess) {
		return ErrConnectionRejected
	}
	defer p.srv.trackSession(sess, false)

	ln := newSingleConnListener(conn, sess)
	err := p.srv.term.Serve(ln)
	ln.wait()
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// serveTerminatedRequest routes one request read off a terminated connection.
func (p *Proxy) serveTerminatedRequest(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromRequest(r)
	if sess == nil {
		sess = newSession(p, r.Context(), nil, Target{}, KindHTTP, protoOfRequest(r))
	}
	// A plaintext connection is announced as HTTP/1.1 before http.Server has had a chance to
	// read a connection preface. The request knows what was negotiated.
	sess.setProtocol(protoOfRequest(r))

	if sess.refused {
		w.Header().Set("Connection", "close")
		p.writeStatus(w, r, http.StatusForbidden, "no entry admits this authority")
		return
	}

	if state := sess.tlsState.Load(); r.TLS == nil && state != nil {
		// http.Server only recognizes an unwrapped *tls.Conn, and the connection it was
		// handed is wrapped. Handlers still expect Request.TLS to describe the handshake.
		r.TLS = state
	}

	target, ok := terminatedTarget(r, sess)
	if !ok {
		p.writeStatus(w, r, http.StatusBadRequest, errRequestTargetPort.Error())
		return
	}
	if sess.upstream.IsValid() && sess.TLS() == nil {
		// The server name of a TLS connection was checked in placeTLS.
		if target, ok = p.verifyRequestHost(r.Context(), sess, target, KindHTTP); !ok {
			p.writeStatus(w, r, http.StatusForbidden, "the host does not resolve to the destination")
			return
		}
	}

	// Nothing on a terminated connection is challenged, since the client believes it is
	// talking to the origin. The identity is the one of whatever established the connection,
	// or none.
	p.dispatchRequest(w, r, sess, target, sess.identity)
}

// terminatedTarget resolves the target of a request read off a terminated connection. The Host
// header is what the client addressed the request to and is what an origin would route on, so
// it wins over the authority of the connection. The port comes from the connection, since an
// origin-form request has none of its own.
func terminatedTarget(r *http.Request, sess *Session) (Target, bool) {
	scheme := sess.target.Scheme
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host, port := splitHostPort(r.Host)
	port, ok := canonicalPort(port)
	if !ok {
		return Target{}, false
	}
	if host == "" {
		host = sess.target.Host
	}
	if port == "" {
		port = sess.target.Port
	}
	if port == "" {
		port = defaultPort(scheme)
	}

	return Target{Scheme: scheme, Host: stringsutil.ToLowerASCIIString(host), Port: port}, true
}
