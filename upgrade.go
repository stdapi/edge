// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
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
		// back as one, and ends the client connection before its next bytes, which may be frames.
		w.Header().Set("Connection", "close")
		c.rq.markHeader()
		if werr := writeResponse(w, r, resp); werr != nil {
			p.logf(r.Context(), slog.LevelDebug, "write websocket handshake response", sess, werr)
			abortIfCut(w, r, werr)
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
	raw, top := c.takeUpstreamConn()
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
	sessionFromRequest(r).handOver()

	sctx, scancel := p.webSocketContext(r)
	defer scancel()
	// After the hijack http.Server neither closes nor waits for the connection, so tracking
	// it here is what lets a shutdown and a route change reach it. A refusal means the proxy
	// is stopping, and the 101 has not been written yet, so the client sees the upgrade fail.
	pipe := &upgradedPipe{client: client, backend: backend, raw: raw, accepted: make(chan struct{})}
	sess := p.pipeSession(c, r, KindWebSocket, c.entry, pipe, sctx, scancel)
	// The handler owns the request it is handed, so the copy is what a later decision reads.
	sess.upgrade = r.Clone(r.Context())

	if !p.srv.trackRegistered(pipe) {
		// The cut started, which gives both connections their failed end.
		abort(client)
		if raw != nil {
			abort(raw)
		}
		return nil
	}
	defer p.srv.untrack(pipe)

	// The 101 has not reached the client yet, so a connection the entries would now decide
	// differently is refused with an ordinary status.
	if aerr := p.srv.admitSession(sess, nil); aerr != nil {
		if raw != nil {
			abort(raw)
		}
		if errors.Is(aerr, errSessionEnded) {
			abort(client)
			return aerr
		}
		p.logf(r.Context(), slog.LevelDebug, "upgrade refused, the entries changed while it was admitted", sess, nil)
		werr := writeRawStatus(brw, http.StatusForbidden)
		closeNormally(client)
		return werr
	}
	defer p.srv.untrackSession(sess)
	p.srv.requests.release(c.rq)

	// Response.Write copies the body after the headers, and here the body is the connection
	// itself. Leaving it in place would block forever draining a stream that only ends when
	// the peers are done talking.
	resp.Body = nil
	err = resp.Write(brw)
	if err == nil {
		err = brw.Flush()
	}
	if err != nil {
		// The client did not get the 101, a failed end of its leg, which the origin that sent it
		// gets too, I1.
		close(pipe.accepted)
		_ = sess.endBy(causePeerFailed, time.Now().Add(alertWriteTimeout))
		return fmt.Errorf("write upgrade response: %w", err)
	}

	ctx, cancel := context.WithCancelCause(sctx)
	defer cancel(nil)
	wc := &WebSocketCtx{
		ctx:      ctx,
		cancel:   cancel,
		p:        p,
		sess:     sess,
		entry:    c.entry,
		req:      r,
		resp:     resp,
		params:   c.capturedParams(),
		target:   Target{Scheme: c.scheme, Host: c.host, Port: c.port},
		identity: c.identity,
		maxFrame: p.cfg.server.maxFrameBytes,
	}
	wc.setHops(client, &hijackedReader{br: brw.Reader, conn: client}, backend, raw, top)
	defer wc.stop()
	pipe.ws.Store(wc)
	close(pipe.accepted)
	if sess.end.first() != causeNone {
		// A closer that ran during the 101 ends the session with its Close frames, I1.
		<-sess.end.done
		return nil
	}

	herr := runKindHandler(p, sess, func() error { return handler(wc) })
	cs := causeReturned
	if herr != nil {
		cs = causeHandlerErr
	}
	_ = sess.endBy(cs, time.Now().Add(alertWriteTimeout))
	return herr
}

// webSocketContext returns the context of a WebSocket session, with the values of the
// connection's context and an end of its own. Edge closes the client connection while the
// closing handshake goes on toward the origin.
func (p *Proxy) webSocketContext(r *http.Request) (context.Context, context.CancelFunc) {
	base := r.Context()
	if s := sessionFromRequest(r); s != nil {
		base = s.Context()
	}
	return context.WithCancel(context.WithoutCancel(base))
}

// serveUpgradedStream serves what an upgrade left behind as the byte stream it now is. HTTP
// ends at the 101, so the bytes past it are served by the stream entry admitting the
// authority, or refused when there is none.
func (p *Proxy) serveUpgradedStream(c *routeCtx, w http.ResponseWriter, r *http.Request, resp *http.Response, sess *Session) error {
	target := Target{Scheme: c.scheme, Host: c.host, Port: c.port}
	raw, top := c.takeUpstreamConn()
	e, params := p.admitWith(target, KindTCP)
	if e == nil {
		// The origin switched protocols for a stream the proxy refuses, and gets its failed end.
		if raw != nil {
			abort(raw)
		}
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
	sessionFromRequest(r).handOver()

	ctx, cancel := p.hijackedContext(r)
	defer cancel()
	pipe := &upgradedPipe{client: client, backend: backend, raw: raw}
	upSess := p.pipeSession(c, r, KindTCP, e, pipe, ctx, cancel)

	sc := &TCPCtx{
		ctx:      ctx,
		p:        p,
		sess:     upSess,
		entry:    e,
		client:   heldConn{Conn: bufferedConn{Conn: client, r: &hijackedReader{br: brw.Reader, conn: client}}},
		params:   params,
		target:   target,
		identity: c.identity,
	}
	if target.Scheme == "https" {
		// On a TLS front listener the session's state is the front's own, not a handshake
		// with this origin.
		sc.tlsState = upSess.TLS()
	}
	// The far side is the connection the 101 left behind. Marking the dial done makes Relay
	// use it instead of opening another.
	sc.up.Conn = pipeConn{ReadWriteCloser: backend, raw: raw, top: top}
	sc.dialOnce.Do(func() {})
	upSess.closer = (*tcpCloser)(sc)

	if !p.srv.trackRegistered(pipe) {
		// The cut started, which gives both connections their failed end.
		abort(client)
		if raw != nil {
			abort(raw)
		}
		return nil
	}
	defer p.srv.untrack(pipe)

	if aerr := p.srv.admitSession(upSess, nil); aerr != nil {
		if raw != nil {
			abort(raw)
		}
		if errors.Is(aerr, errSessionEnded) {
			abort(client)
			return aerr
		}
		p.logf(r.Context(), slog.LevelDebug, "upgrade refused, the entries changed while it was admitted", upSess, nil)
		werr := writeRawStatus(brw, http.StatusForbidden)
		closeNormally(client)
		return werr
	}
	defer p.srv.untrackSession(upSess)
	p.srv.requests.release(c.rq)

	resp.Body = nil
	if err = resp.Write(brw); err == nil {
		err = brw.Flush()
	}
	if err != nil {
		// The client did not get the 101, a failed end of its leg, which the origin that sent it
		// gets too, I1.
		_ = upSess.endBy(causePeerFailed, time.Now().Add(alertWriteTimeout))
		return fmt.Errorf("write upgrade response: %w", err)
	}

	err = runKindHandler(p, upSess, func() error { return handler(sc) })
	sc.end(err)
	return err
}

// hijackedReader reads a hijacked connection through the buffer net/http handed back until it
// is drained, then through that buffer reset onto the connection. A read through net/http's
// own reader cancels the request context on any error, a half-close included.
type hijackedReader struct {
	br    *bufio.Reader
	conn  net.Conn
	reset bool
}

func (r *hijackedReader) Read(b []byte) (int, error) {
	if !r.reset && r.br.Buffered() == 0 {
		r.br.Reset(r.conn)
		r.reset = true
	}
	return r.br.Read(b)
}

// bufferedConn reads through a buffer that already holds bytes of the stream, the ones a
// hijack handed back or a CONNECT response left behind.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// CloseWrite forwards the half-close, which the embedded net.Conn does not promote.
func (c bufferedConn) CloseWrite() error { return closeWrite(c.Conn) }

func (c bufferedConn) Abort() { abort(c.Conn) }

// pipeConn adapts what an upgrade left behind to a net.Conn. The body of a 101 is a byte pipe
// with no addresses and no deadlines of its own, and closing it is what ends it.
type pipeConn struct {
	io.ReadWriteCloser
	// raw is the socket of the upstream connection the 101 arrived on and top the connection
	// over it, TLS included, both nil when the proxy could not record them.
	raw, top net.Conn
}

// CloseWrite half-closes the upstream connection, a close_notify under TLS.
func (c pipeConn) CloseWrite() error {
	if c.top == nil {
		return c.Close()
	}
	return closeWrite(c.top)
}

// Abort resets the upstream connection, which closing the body of the 101 ends with a FIN.
func (c pipeConn) Abort() {
	if c.raw != nil {
		abort(c.raw)
	}
	_ = c.Close()
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
	// raw is the socket under backend, nil when the transport handed over none.
	raw net.Conn
	// accepted is closed once the 101 of a WebSocket session was written or failed, ws set
	// when it was written. It is nil on a pipe served by a TCP entry.
	accepted chan struct{}
	// ws is the WebSocket served on the pipe once its handler runs.
	ws atomic.Pointer[WebSocketCtx]
}

func (u *upgradedPipe) Close() error { return u.endBy(causeCut, time.Now().Add(alertWriteTimeout)) }

func (u *upgradedPipe) endBy(c cause, deadline time.Time) error {
	failed := formOf(framed, c, false) == formFailed
	if u.accepted != nil && !failed {
		// A framed session gets its acceptance first, the 101 in progress.
		waitUntil(u.accepted, deadline)
	}
	if ws := u.ws.Load(); ws != nil {
		if failed {
			ws.abortHops(deadline)
			return nil
		}
		ws.endBy(c == causeClosed || c == causeCut, deadline)
		return nil
	}
	if failed || c == causeCut || c == causeClosed || u.accepted != nil {
		// No handler runs, so the pipe ends as a byte stream, each leg with its failed end.
		var wg sync.WaitGroup
		wg.Go(func() { abortBy(u.client, deadline) })
		switch b := u.backend.(type) {
		case net.Conn:
			abortBy(b, deadline)
		default:
			if u.raw != nil {
				abortBy(u.raw, deadline)
			}
		}
		wg.Wait()
		return u.backend.Close()
	}
	cerr := u.client.Close()
	berr := u.backend.Close()
	return errors.Join(cerr, berr)
}

// pipeSession describes the connection an upgrade leaves behind, served by e, living under ctx.
//
// It gets a session of its own because a request routes on its Host header, which can differ
// from the CONNECT authority. Reusing the connection's would report an authority the pipe does
// not talk to, and a sweep would keep the wrong one.
func (p *Proxy) pipeSession(c *routeCtx, r *http.Request, kind Kind, e *entry, pipe *upgradedPipe,
	ctx context.Context, cancel context.CancelFunc,
) *Session {
	target := Target{Scheme: c.scheme, Host: c.host, Port: c.port}
	sess := newSession(p, ctx, nil, target, kind, protoOfRequest(r))
	sess.cancel = cancel
	sess.closer = pipe
	// The socket rides what the connection that sent the upgrade rides, docs/lifecycle.md
	// Handover.
	if from := sessionFromRequest(r); from != nil {
		sess.carrier = from.carrier
	}
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
		sess.pendingTLS = front.pendingTLS
	}
	return sess
}
