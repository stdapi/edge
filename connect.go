// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"cmp"
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/fox-toolkit/edge/internal/stringsutil"
)

// serveConnect handles a CONNECT request. The authority decides whether the connection is
// terminated so its traffic can be routed, or refused.
//
// Nothing has been negotiated at this point, so the admission here only asks whether the
// authority is known at all. Which kind the connection carries is decided once the traffic
// says so, past the handshake, and an authority that admits no kind the connection turns
// out to speak is refused there instead.
func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request, identity string) {
	target, ok := targetFromConnect(r)
	if !ok {
		http.Error(w, "edge: CONNECT requires an authority target", http.StatusBadRequest)
		return
	}

	if !p.admitsAny(target, KindHTTP, KindTCP) {
		http.Error(w, "edge: connection rejected, no entry admits this authority", http.StatusForbidden)
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
		http.Error(w, "edge: cannot hijack the connection for CONNECT", http.StatusInternalServerError)
		return
	}

	// Anything the reader buffered past the CONNECT request is already payload: a client that
	// writes its ClientHello without waiting for the 200 would otherwise lose it.
	conn := newPeekConn(client, brw.Reader)

	// The connection outlives the request that opened it, so what bounds it is the connection,
	// not the request. ConnContext built exactly that context and handed it to the session, and
	// it ends when the connection closes. The request context is one cancel deeper and ends
	// with the request, which for a hijacked connection is at the hijack: borrowing it would
	// cut a handshake or a dial the moment net/http considered the CONNECT over.
	base := context.WithoutCancel(r.Context())
	if s := sessionFromRequest(r); s != nil {
		base = s.Context()
	}
	ctx, cancel := context.WithCancel(base)
	defer cancel()
	// Mounted in a server of its own the proxy has no ConnContext, and the fallback above
	// carries no cancellation, so a shutdown is watched for explicitly.
	go func() {
		select {
		case <-p.srv.closed:
			cancel()
		case <-ctx.Done():
		}
	}()

	sess := newSession(ctx, client, target, 0, 0)
	sess.identity = identity
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
	if werr := writeRawStatus(brw, http.StatusOK, ""); werr != nil {
		return
	}
	pc := conn
	if p.cfg.rejectECH {
		// The reader behind conn is sized for requests, not for a full ClientHello.
		pc = newPeekConnSize(conn, clientHelloPeekSize)
		if err := inspectECH(pc); err != nil {
			p.logf(ctx, slog.LevelDebug, "connection closed", sess, err)
			return
		}
	}
	if ierr := p.terminate(ctx, pc, sess); ierr != nil {
		p.logf(ctx, slog.LevelDebug, "connection closed", sess, ierr)
	}
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
	sess := newSession(r.Context(), nil, target, 0, 0)
	sess.localAddr, sess.remoteAddr = local, remote
	sess.identity = identity

	// A refused registration means the proxy is stopping. Returning would let net/http answer
	// 200 for a connection that is already gone, so the stream is reset instead.
	if !p.srv.tryTrack(stream) {
		panic(http.ErrAbortHandler)
	}
	defer func() {
		_ = stream.Close()
		p.srv.untrack(stream)
	}()

	w.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(w).Flush()

	pc := newPeekConn(stream, nil)
	if p.cfg.rejectECH {
		pc = newPeekConnSize(stream, clientHelloPeekSize)
		if err := inspectECH(pc); err != nil {
			p.logf(r.Context(), slog.LevelDebug, "stream closed", sess, err)
			return
		}
	}
	if err := p.terminate(r.Context(), pc, sess); err != nil {
		p.logf(r.Context(), slog.LevelDebug, "stream closed", sess, err)
	}
}

// targetFromConnect reads the authority out of a CONNECT request. A CONNECT target must
// carry a port, but a client that omits it clearly means the default for a secure connection.
func targetFromConnect(r *http.Request) (Target, bool) {
	authority := r.Host
	if r.URL != nil && r.URL.Host != "" {
		authority = r.URL.Host
	}
	if authority == "" {
		return Target{}, false
	}

	host, port := splitHostPort(authority)
	if host == "" {
		return Target{}, false
	}
	port = cmp.Or(port, "443")

	return Target{
		Scheme: schemeForPort(port),
		Host:   stringsutil.ToLowerASCIIString(host),
		Port:   port,
	}, true
}

// writeRawStatus writes a bare status line on a hijacked connection, where the http.Server
// response machinery is no longer available.
func writeRawStatus(brw *bufio.ReadWriter, code int, detail string) error {
	reason := http.StatusText(code)
	if code == http.StatusOK {
		reason = "Connection established"
	}

	var body string
	if detail != "" {
		body = "edge: " + detail
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
	} else {
		sb = append(sb, "Content-Length: 0\r\n"...)
	}
	sb = append(sb, "\r\n"...)
	sb = append(sb, body...)

	if _, err := brw.Write(sb); err != nil {
		return err
	}
	return brw.Flush()
}

func (p *Proxy) logf(ctx context.Context, level slog.Level, msg string, sess *Session, err error) {
	if !p.cfg.logger.Enabled(ctx, level) {
		return
	}
	attrs := []any{slog.String("target", sess.target.String())}
	if sess.remoteAddr != nil {
		attrs = append(attrs, slog.String("client", sess.remoteAddr.String()))
	}
	attrs = append(attrs,
		slog.Uint64("session", sess.id),
		slog.String("kind", sess.kind.String()),
	)
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	p.cfg.logger.Log(ctx, level, "edge: "+msg, attrs...)
}
