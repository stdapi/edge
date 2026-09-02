// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// serveWebSocketUpgrade completes the handshake against the origin and, once it answers 101,
// hands the frames to the [WebSocket] handler.
//
// The handshake itself is forwarded as the client wrote it. A WebSocket entry serves what is
// past the 101, which is where the connection stops being HTTP, so an entry wanting a say on
// the handshake registers an [HTTP] one on the same path instead.
func (p *Proxy) serveWebSocketUpgrade(c *routeCtx, w http.ResponseWriter, r *http.Request, sess *Session) {
	handler, _ := c.entry.serve.(WebSocket)
	if handler == nil {
		p.writeStatus(w, r, http.StatusInternalServerError, "entry has no WebSocket handler")
		return
	}

	resp, err := c.http.Forward()
	if err != nil {
		p.writeStatus(w, r, http.StatusBadGateway, "websocket handshake failed: "+err.Error())
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// The origin declined the upgrade. Its answer is an ordinary response and travels
		// back as one.
		if werr := writeResponse(w, r, resp); werr != nil {
			p.logf(r.Context(), slog.LevelDebug, "write websocket handshake response", sess, werr)
		}
		return
	}

	if werr := p.spliceWebSocket(c, w, r, resp, handler); werr != nil {
		p.logf(r.Context(), slog.LevelDebug, "websocket closed", sess, werr)
	}
}

// spliceWebSocket takes over both ends of an upgraded connection and runs the frame handler
// between them.
func (p *Proxy) spliceWebSocket(c *routeCtx, w http.ResponseWriter, r *http.Request, resp *http.Response, handler WebSocket) error {
	backend, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return errors.New("edge: upstream returned 101 without a writable body")
	}
	defer func() { _ = backend.Close() }()

	rc := http.NewResponseController(w)
	client, brw, err := rc.Hijack()
	if err != nil {
		return fmt.Errorf("hijack for websocket upgrade: %w", err)
	}
	defer func() { _ = client.Close() }()

	// After the hijack http.Server neither closes nor waits for the connection, so tracking
	// it here is what lets a shutdown and a route change reach it. A refusal means the proxy
	// is stopping, and the 101 has not been written yet, so the client sees the upgrade fail.
	pipe := &upgradedPipe{client: client, backend: backend}
	sess := p.pipeSession(c, r, KindWebSocket, c.entry, pipe)
	// The handler owns the request it is handed, so the copy is what a later decision reads.
	sess.upgrade = r.Clone(r.Context())

	if !p.srv.tryTrack(pipe) {
		return nil
	}
	defer p.srv.untrack(pipe)

	// The 101 has not reached the client yet, so a connection the entries would now decide
	// differently is refused with an ordinary status.
	if !p.srv.admitSession(sess) {
		p.logf(r.Context(), slog.LevelDebug, "upgrade refused, the entries changed while it was admitted", sess, nil)
		return writeRawStatus(brw, http.StatusForbidden)
	}
	defer p.srv.trackSession(sess, false)

	// Response.Write copies the body after the headers, and here the body is the connection
	// itself. Leaving it in place would block forever draining a stream that only ends when
	// the peers are done talking.
	resp.Body = nil
	if err := resp.Write(brw); err != nil {
		return fmt.Errorf("write upgrade response: %w", err)
	}
	if err := brw.Flush(); err != nil {
		return fmt.Errorf("flush upgrade response: %w", err)
	}

	wc := &WebSocketCtx{
		ctx:      r.Context(),
		p:        p,
		sess:     sess,
		entry:    c.entry,
		req:      r,
		resp:     resp,
		client:   readWriteCloser{r: brw, w: brw, c: client},
		backend:  backend,
		params:   c.capturedParams(),
		target:   Target{Scheme: c.scheme, Host: c.host, Port: c.port},
		identity: c.identity,
		maxFrame: p.cfg.server.maxFrameBytes,
	}

	return runKindHandler(p, sess, func() error { return handler(wc) })
}

// serveUpgradedStream serves what an upgrade left behind as the byte stream it now is. HTTP
// ends at the 101, so the bytes past it are served by the stream entry admitting the
// authority, or refused when there is none.
func (p *Proxy) serveUpgradedStream(c *routeCtx, w http.ResponseWriter, r *http.Request, resp *http.Response, sess *Session) error {
	target := Target{Scheme: c.scheme, Host: c.host, Port: c.port}
	e, params := p.admitWith(target, KindTCP)
	if e == nil {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		p.writeStatus(w, r, http.StatusForbidden, "upgrade refused, nothing serves the stream it switches to")
		return nil
	}

	handler, _ := e.serve.(TCP)
	if handler == nil {
		return errors.New("edge: TCP entry with no handler")
	}

	backend, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return errors.New("edge: upstream returned 101 without a writable body")
	}
	defer func() { _ = backend.Close() }()

	rc := http.NewResponseController(w)
	client, brw, err := rc.Hijack()
	if err != nil {
		return fmt.Errorf("hijack for protocol upgrade: %w", err)
	}
	defer func() { _ = client.Close() }()

	pipe := &upgradedPipe{client: client, backend: backend}
	upSess := p.pipeSession(c, r, KindTCP, e, pipe)

	if !p.srv.tryTrack(pipe) {
		return nil
	}
	defer p.srv.untrack(pipe)

	if !p.srv.admitSession(upSess) {
		p.logf(r.Context(), slog.LevelDebug, "upgrade refused, the entries changed while it was admitted", upSess, nil)
		return writeRawStatus(brw, http.StatusForbidden)
	}
	defer p.srv.trackSession(upSess, false)

	resp.Body = nil
	if err := resp.Write(brw); err != nil {
		return fmt.Errorf("write upgrade response: %w", err)
	}
	if err := brw.Flush(); err != nil {
		return fmt.Errorf("flush upgrade response: %w", err)
	}

	sc := &TCPCtx{
		ctx:      r.Context(),
		p:        p,
		sess:     upSess,
		entry:    e,
		client:   heldConn{Conn: bufferedConn{Conn: client, r: brw}},
		params:   params,
		target:   target,
		identity: c.identity,
		tlsState: upSess.TLS(),
	}
	// The far side is the connection the 101 left behind. Marking the dial done makes Relay
	// use it instead of opening another.
	sc.up.Conn = pipeConn{ReadWriteCloser: backend}
	sc.dialOnce.Do(func() {})
	defer sc.close()

	return runKindHandler(p, upSess, func() error { return handler(sc) })
}

// readWriteCloser joins the buffered reader and writer of a hijacked connection to the
// connection's own Close. Anything the reader buffered past the handshake is already frame
// data, so reads must go through it.
type readWriteCloser struct {
	r io.Reader
	w io.Writer
	c io.Closer
}

func (rw readWriteCloser) Read(b []byte) (int, error) { return rw.r.Read(b) }
func (rw readWriteCloser) Close() error               { return rw.c.Close() }
func (rw readWriteCloser) Write(b []byte) (int, error) {
	n, err := rw.w.Write(b)
	if err != nil {
		return n, err
	}
	if f, ok := rw.w.(interface{ Flush() error }); ok {
		return n, f.Flush()
	}
	return n, nil
}

// bufferedConn reads through a buffer that already holds bytes of the stream, the ones a
// hijack handed back or a CONNECT response left behind.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// pipeConn adapts what an upgrade left behind to a net.Conn. The body of a 101 is a byte pipe
// with no addresses and no deadlines of its own, and closing it is what ends it.
type pipeConn struct {
	io.ReadWriteCloser
}

func (pipeConn) LocalAddr() net.Addr              { return emptyAddr{} }
func (pipeConn) RemoteAddr() net.Addr             { return emptyAddr{} }
func (pipeConn) SetDeadline(time.Time) error      { return nil }
func (pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (pipeConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = pipeConn{}

// upgradedPipe is what an upgrade leaves behind, the client socket joined to the upstream one.
// Closing it ends both directions.
type upgradedPipe struct {
	client  net.Conn
	backend io.Closer
}

func (u *upgradedPipe) Close() error {
	cerr := u.client.Close()
	berr := u.backend.Close()
	return errors.Join(cerr, berr)
}

// pipeSession describes the connection an upgrade leaves behind, served by e.
//
// It gets a session of its own because a request routes on its Host header, which can differ
// from the CONNECT authority. Reusing the connection's would report an authority the pipe does
// not talk to, and a sweep would keep the wrong one.
func (p *Proxy) pipeSession(c *routeCtx, r *http.Request, kind Kind, e *entry, pipe io.Closer) *Session {
	target := Target{Scheme: c.scheme, Host: c.host, Port: c.port}
	sess := newSession(p, r.Context(), nil, target, kind, protoOfRequest(r))
	sess.closer = pipe
	sess.entry.Store(e)
	// An upgrade outlives the request that established it, so a revocation can only reach it
	// through the identity that request carried.
	sess.identity = c.identity

	front := c.sess
	if front == nil {
		return sess
	}
	sess.remoteAddr = front.remoteAddr
	sess.localAddr = front.localAddr
	sess.clientHello.Store(front.clientHello.Load())
	sess.upstream, sess.dial = front.upstream, front.dial
	sess.transparent = front.transparent
	if state := front.tlsState.Load(); state != nil {
		sess.tlsState.Store(state)
	} else {
		// The explicit proxy reached over TLS builds its session before the handshake, so
		// the state only exists behind the connection.
		sess.tlsConn = front.tlsConn
	}
	return sess
}
