// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/fox-toolkit/edge/internal/stringsutil"
)

// serveConnect handles a CONNECT request. The authority decides whether the connection is
// relayed byte for byte, terminated so its requests can be routed, or refused.
func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	target, ok := targetFromConnect(r)
	if !ok {
		http.Error(w, "edge: CONNECT requires an authority target", http.StatusBadRequest)
		return
	}

	action := p.ActionFor(target)
	if action == Reject {
		http.Error(w, "edge: connection rejected, no interceptor or tunnel matches this authority", http.StatusForbidden)
		return
	}

	if r.ProtoMajor >= 2 {
		p.connectStream(w, r, target, action)
		return
	}
	p.connectHijack(w, r, target, action)
}

// connectHijack takes over an HTTP/1.1 connection after CONNECT.
func (p *Proxy) connectHijack(w http.ResponseWriter, r *http.Request, target Target, action Action) {
	rc := http.NewResponseController(w)
	client, brw, err := rc.Hijack()
	if err != nil {
		http.Error(w, "edge: cannot hijack the connection for CONNECT", http.StatusInternalServerError)
		return
	}

	// Anything the reader buffered past the CONNECT request is already tunnel payload: a
	// client that writes its ClientHello without waiting for the 200 would otherwise lose it.
	conn := newPeekConn(client, brw.Reader)

	sess := newSession(r.Context(), client, target, action, HTTP11)
	if s := sessionFromRequest(r); s != nil {
		sess.remoteAddr = s.remoteAddr
		sess.localAddr = s.localAddr
	}

	p.srv.track(conn, true)
	p.srv.wg.Add(1)
	defer func() {
		p.srv.track(conn, false)
		p.srv.wg.Done()
		_ = conn.Close()
	}()

	if action == Tunnel {
		sess.closer = conn
		if !p.srv.admitSession(sess) {
			_ = writeRawStatus(brw, http.StatusForbidden,
				"connection rejected, no interceptor or tunnel matches this authority")
			return
		}
		defer p.srv.trackSession(sess, false)

		upstream, derr := p.dialUpstream(r.Context(), target)
		if derr != nil {
			_ = writeRawStatus(brw, http.StatusBadGateway, derr.Error())
			p.logf(r.Context(), slog.LevelWarn, "tunnel dial failed", sess, derr)
			return
		}
		defer func() { _ = upstream.Close() }()

		if werr := writeRawStatus(brw, http.StatusOK, ""); werr != nil {
			return
		}
		if _, _, terr := tunnel(conn, upstream, p.cfg.server.tunnelIdleTimeout); terr != nil {
			p.logf(r.Context(), slog.LevelDebug, "tunnel closed", sess, terr)
		}
		return
	}

	// Interception answers before reaching the upstream: a handler may serve the whole
	// exchange locally, and the client needs the tunnel open to send its ClientHello.
	if werr := writeRawStatus(brw, http.StatusOK, ""); werr != nil {
		return
	}
	if ierr := p.intercept(r.Context(), conn, sess); ierr != nil {
		p.logf(r.Context(), slog.LevelDebug, "intercepted connection closed", sess, ierr)
	}
}

// connectStream handles a CONNECT carried on an HTTP/2 or HTTP/3 stream, where the stream
// itself is the tunnel rather than the whole connection.
func (p *Proxy) connectStream(w http.ResponseWriter, r *http.Request, target Target, action Action) {
	front := sessionFromRequest(r)
	var local, remote net.Addr
	if front != nil {
		local, remote = front.localAddr, front.remoteAddr
	}

	stream := newH2Stream(w, r, local, remote)
	sess := newSession(r.Context(), nil, target, action, protoOfRequest(r))
	sess.localAddr, sess.remoteAddr = local, remote

	p.srv.track(stream, true)
	p.srv.wg.Add(1)
	defer func() {
		p.srv.track(stream, false)
		p.srv.wg.Done()
		_ = stream.Close()
	}()

	if action == Tunnel {
		// Nothing has been written to the stream yet, so a refusal here is an ordinary status
		// rather than a tunnel granted and then torn down.
		sess.closer = stream
		if !p.srv.admitSession(sess) {
			http.Error(w, "edge: connection rejected, no interceptor or tunnel matches this authority",
				http.StatusForbidden)
			return
		}
		defer p.srv.trackSession(sess, false)

		upstream, err := p.dialUpstream(r.Context(), target)
		if err != nil {
			http.Error(w, "edge: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = upstream.Close() }()

		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()

		if _, _, terr := tunnel(stream, upstream, p.cfg.server.tunnelIdleTimeout); terr != nil {
			p.logf(r.Context(), slog.LevelDebug, "tunnel closed", sess, terr)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(w).Flush()

	if err := p.intercept(r.Context(), newPeekConn(stream, nil), sess); err != nil {
		p.logf(r.Context(), slog.LevelDebug, "intercepted stream closed", sess, err)
	}
}

// dialUpstream opens a TCP connection to target using the configured dialer.
func (p *Proxy) dialUpstream(ctx context.Context, target Target) (net.Conn, error) {
	dial := p.cfg.transport.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	conn, err := dial(ctx, "tcp", target.Authority())
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target.Authority(), err)
	}
	return conn, nil
}

// targetFromConnect reads the authority out of a CONNECT request. A CONNECT target must
// carry a port, but a client that omits it clearly means the default for a tunnel.
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
		slog.String("action", sess.action.String()),
	)
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	p.cfg.logger.Log(ctx, level, "edge: "+msg, attrs...)
}
