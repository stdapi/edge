// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"cmp"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/stdapi/edge/internal/stringsutil"
)

// serveConnect handles a CONNECT request. The authority decides whether the connection is
// terminated so its traffic can be routed, or refused.
//
// Nothing has been negotiated at this point, so the admission here only asks whether the
// authority is known at all. Which kind the connection carries is decided once the traffic
// says so, past the handshake, and an authority that admits no kind the connection turns
// out to speak is refused there instead.
func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request, identity string) {
	target, err := targetFromConnect(r)
	if err != nil {
		p.writeStatus(w, r, http.StatusBadRequest, err.Error())
		return
	}

	if !p.admitsAny(target, KindHTTP, KindTCP) {
		p.writeStatus(w, r, http.StatusForbidden, "no entry admits this authority")
		return
	}

	if r.ProtoMajor >= 2 {
		p.connectStream(w, r, target, identity)
		return
	}
	p.connectHijack(w, r, target, identity)
}

// connectHijack takes over an HTTP/1.1 connection after CONNECT.
func (p *Proxy) connectHijack(w http.ResponseWriter, r *http.Request, target Target, identity string) {
	rc := http.NewResponseController(w)
	client, brw, err := rc.Hijack()
	if err != nil {
		p.writeStatus(w, r, http.StatusInternalServerError, "cannot hijack the connection for CONNECT")
		return
	}

	// Anything the reader buffered past the CONNECT request is already payload: a client that
	// writes its ClientHello without waiting for the 200 would otherwise lose it.
	var early []byte
	if n := brw.Reader.Buffered(); n > 0 {
		early, _ = brw.Peek(n)
	}
	conn := newPeekConn(client, early, clientHelloPeekSize)

	ctx, cancel := p.hijackedContext(r)
	defer cancel()

	// The hijacked connection is the front one, so its handshake describes the proxy and not
	// the tunnel. The session takes the addresses alone and the tunnel's own termination
	// fills in the TLS state.
	sess := newSession(p, ctx, nil, target, 0, 0)
	sess.remoteAddr = client.RemoteAddr()
	sess.localAddr = client.LocalAddr()
	sess.identity = identity
	sess.setDestination(target)
	if s := sessionFromRequest(r); s != nil {
		sess.remoteAddr = s.remoteAddr
		sess.localAddr = s.localAddr
	}

	// A hijacked connection is invisible to http.Server, so only the registry can end it.
	if !p.srv.tryTrack(conn) {
		_ = conn.Close()
		return
	}
	defer func() {
		_ = conn.Close()
		p.srv.untrack(conn)
	}()

	// Termination answers before reaching the upstream: a handler may serve the whole
	// exchange locally, and the client needs the connection open to send its ClientHello.
	if werr := writeRawStatus(brw, http.StatusOK); werr != nil {
		return
	}
	if ierr := p.terminate(ctx, conn, sess); ierr != nil {
		p.logf(ctx, slog.LevelDebug, "connection closed", sess, ierr)
	}
}

// hijackedContext returns the context of a connection taken over after r, the one
// ConnContext built, which ends when the connection closes. The request context ends at the
// hijack and would cut a handshake or a dial there.
func (p *Proxy) hijackedContext(r *http.Request) (context.Context, context.CancelFunc) {
	base := context.WithoutCancel(r.Context())
	if s := sessionFromRequest(r); s != nil {
		base = s.Context()
	}
	return p.untilShutdown(base)
}

// untilShutdown returns a child of base that also ends with the proxy. Mounted in a server of
// its own the proxy has no ConnContext, so a shutdown is watched for explicitly.
func (p *Proxy) untilShutdown(base context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(base)
	go func() {
		select {
		case <-p.srv.ctx.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// connectStream handles a CONNECT carried on an HTTP/2 or HTTP/3 stream, where the stream
// itself is the connection rather than the whole transport.
func (p *Proxy) connectStream(w http.ResponseWriter, r *http.Request, target Target, identity string) {
	front := sessionFromRequest(r)
	var local, remote net.Addr
	if front != nil {
		local, remote = front.localAddr, front.remoteAddr
	}

	stream := newH2Stream(w, r, local, remote)
	cut := streamCut{stream}
	sess := newSession(p, r.Context(), nil, target, 0, 0)
	sess.localAddr, sess.remoteAddr = local, remote
	sess.identity = identity
	sess.setDestination(target)
	sess.closer = cut

	// A refused registration means the proxy is stopping. Returning would let net/http answer
	// 200 for a connection that is already gone, so the stream is reset instead.
	if !p.srv.tryTrack(cut) {
		panic(http.ErrAbortHandler)
	}
	defer func() {
		_ = stream.Close()
		stream.finish()
		p.srv.untrack(cut)
		if stream.aborted.Load() {
			// A return ends the stream cleanly, where the relay failed, and an HTTP/2 handler
			// has no other way to reset it.
			panic(http.ErrAbortHandler)
		}
	}()

	stream.writeHeader(http.StatusOK)

	pc := newPeekConn(stream, nil, clientHelloPeekSize)
	if err := p.terminate(r.Context(), pc, sess); err != nil {
		p.logf(r.Context(), slog.LevelDebug, "stream closed", sess, err)
	}
}

// targetFromConnect reads the authority out of a CONNECT request. A CONNECT target must
// carry a port, but a client that omits it clearly means the default for a secure connection.
func targetFromConnect(r *http.Request) (Target, error) {
	authority := r.Host
	if r.URL != nil && r.URL.Host != "" {
		authority = r.URL.Host
	}
	host, port, ok := splitAuthority(authority)
	if !ok {
		return Target{}, errors.New("CONNECT target is not a host and a port")
	}
	host = canonicalHost(host)
	if host == "" {
		return Target{}, errors.New("CONNECT requires an authority target")
	}
	port = cmp.Or(port, "443")

	return Target{
		Scheme: schemeForPort(port),
		Host:   stringsutil.ToLowerASCIIString(host),
		Port:   port,
	}, nil
}

// writeRawStatus writes a status line on a hijacked connection, where the http.Server
// response machinery is no longer available, with the status text as the body of an error.
func writeRawStatus(w io.Writer, code int) error {
	reason := http.StatusText(code)
	if code == http.StatusOK {
		reason = "Connection established"
	}

	var body string
	if code >= http.StatusBadRequest {
		body = reason + "\n"
	}

	sb := make([]byte, 0, 128+len(body))
	sb = append(sb, "HTTP/1.1 "...)
	sb = strconv.AppendInt(sb, int64(code), 10)
	sb = append(sb, ' ')
	sb = append(sb, reason...)
	sb = append(sb, "\r\n"...)
	if body != "" {
		sb = append(sb, "Content-Type: text/plain; charset=utf-8\r\nContent-Length: "...)
		sb = strconv.AppendInt(sb, int64(len(body)), 10)
		sb = append(sb, "\r\n"...)
	} else if code < 200 || code > 299 {
		// RFC 9110 9.3.6, a 2xx answer to CONNECT has no framing fields.
		sb = append(sb, "Content-Length: 0\r\n"...)
	}
	sb = append(sb, "\r\n"...)
	sb = append(sb, body...)

	if _, err := w.Write(sb); err != nil {
		return err
	}
	if f, ok := w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}
