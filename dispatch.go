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
	"runtime"
	"strconv"
	"strings"
)

// dispatchRequest serves one request under the action registered for the authority it names,
// which is not always the authority the connection was opened for.
func (p *Proxy) dispatchRequest(w http.ResponseWriter, r *http.Request, sess *Session, target Target) {
	tree := p.getTree()
	c := tree.pool.Get().(*Context)
	defer tree.pool.Put(c)

	switch tree.actionFor(c, target) {
	case Reject:
		http.Error(w, "edge: connection rejected, no interceptor or tunnel matches this authority", http.StatusForbidden)
	case Tunnel:
		p.relay(c, w, r, sess, target)
	default:
		p.serve(c, w, r, sess, target)
	}
}

// serve routes one intercepted request on c.tree, runs its handler and writes the result back
// to the client.
func (p *Proxy) serve(c *Context, w http.ResponseWriter, r *http.Request, sess *Session, target Target) {
	c.reset(sess, r, target.Scheme, target.Host, target.Port)

	handler := p.noInterceptor
	if r.Method != "" {
		if idx, n := c.tree.lookup(r.Method, target.Host, routingPath(r), c, false); n != nil {
			c.interceptor = n.entries[idx]
			handler = c.interceptor.hall
		}
	}
	if c.interceptor == nil {
		// A lookup that failed may have left captures behind from a branch it backtracked
		// out of, and no interceptor means no names to read them under.
		*c.params = (*c.params)[:0]
		c.scope = NoInterceptorHandler
	}

	resp, err := p.runHandler(c, handler)
	if err != nil {
		resp = p.onError(c, err)
		if resp == nil {
			resp = Status(http.StatusBadGateway)
		}
	}
	if resp == nil {
		resp = Status(http.StatusBadGateway)
	}

	if werr := writeResponse(c, w, r, resp, Intercept); werr != nil {
		p.logf(r.Context(), slog.LevelDebug, "write response", sess, werr)
	}
}

// relay forwards a request a tunnel asked the proxy not to look at. No interceptor is consulted
// and no middleware runs, so a tunneled authority stays unobserved even when it arrives as a
// plain request the proxy had to parse to route it at all.
func (p *Proxy) relay(c *Context, w http.ResponseWriter, r *http.Request, sess *Session, target Target) {
	c.reset(sess, r, target.Scheme, target.Host, target.Port)

	resp, err := c.Forward()
	if err != nil {
		p.logf(r.Context(), slog.LevelWarn, "relay failed", sess, err)
		http.Error(w, "edge: "+err.Error(), http.StatusBadGateway)
		return
	}
	if werr := writeResponse(c, w, r, resp, Tunnel); werr != nil {
		p.logf(r.Context(), slog.LevelDebug, "write relayed response", sess, werr)
	}
}

// runHandler calls the handler and turns a panic into a [PanicError]. Nothing is logged here,
// the error takes the normal path and the [ErrorHandler] decides what a panic answers.
func (p *Proxy) runHandler(c *Context, handler HandlerFunc) (resp *http.Response, err error) {
	defer func() {
		rec := recover()
		if rec == nil {
			return
		}
		if e, ok := rec.(error); ok && errors.Is(e, http.ErrAbortHandler) {
			// The caller deliberately aborted; let net/http see it.
			panic(rec)
		}
		resp = nil
		err = &PanicError{Value: rec, Stack: stacktrace(panicStackSkip)}
	}()

	return handler(c)
}

const (
	// panicStackFrames bounds what a capture costs.
	panicStackFrames = 16
	// panicStackSkip drops runtime.Callers, stacktrace, the deferred closure and
	// runtime.gopanic, so the first frame reported is the one that panicked.
	panicStackSkip = 3
)

// stacktrace formats the call stack of its caller, dropping the first skip frames and keeping
// at most panicStackFrames of what is left.
func stacktrace(skip int) string {
	pcs := make([]uintptr, panicStackFrames)
	n := runtime.Callers(skip+1, pcs)
	if n == 0 {
		return ""
	}

	var sb strings.Builder
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		sb.WriteString(frame.Function)
		sb.WriteString("\n\t")
		sb.WriteString(frame.File)
		sb.WriteByte(':')
		sb.WriteString(strconv.Itoa(frame.Line))
		if !more {
			break
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

// writeResponse relays resp to the client. action is what let the request through, which an
// upgrade needs because past the 101 it becomes a connection of its own.
func writeResponse(c *Context, w http.ResponseWriter, r *http.Request, resp *http.Response, action Action) error {
	// An upgrade takes ownership of the body, which is the tunnel rather than a payload.
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return spliceUpgrade(c, w, r, resp, action)
	}

	if resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	dst := w.Header()
	for k, vv := range resp.Header {
		dst[k] = append(dst[k][:0:0], vv...)
	}

	// Trailers must be announced before the header block is written, and their values only
	// exist once the body has been fully read.
	announceTrailers(dst, resp)

	w.WriteHeader(resp.StatusCode)

	if resp.Body == nil || resp.Body == http.NoBody || !bodyAllowed(r.Method, resp.StatusCode) {
		return nil
	}

	rc := http.NewResponseController(w)
	buf := getCopyBuf()
	defer putCopyBuf(buf)

	_, err := io.CopyBuffer(flushWriter{w: w, rc: rc}, resp.Body, buf)

	for k, vv := range resp.Trailer {
		for _, v := range vv {
			dst.Add(http.TrailerPrefix+k, v)
		}
	}

	if err != nil && !isClientGone(err) {
		return fmt.Errorf("copy response body: %w", err)
	}
	return nil
}

// announceTrailers copies the trailer names the upstream declared into the response header,
// so an HTTP/1.1 client knows to expect them after the body.
func announceTrailers(dst http.Header, resp *http.Response) {
	if len(resp.Trailer) == 0 {
		return
	}
	names := make([]string, 0, len(resp.Trailer))
	for k := range resp.Trailer {
		names = append(names, k)
	}
	dst.Set("Trailer", strings.Join(names, ", "))
}

// bodyAllowed reports whether a response to this method and status may carry a body.
func bodyAllowed(method string, status int) bool {
	if method == http.MethodHead {
		return false
	}
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == http.StatusNoContent, status == http.StatusNotModified:
		return false
	}
	return true
}

// flushWriter flushes after every write so a streamed response reaches the client as it is
// produced. Without it a server-sent event stream sits in the response buffer.
type flushWriter struct {
	w  io.Writer
	rc *http.ResponseController
}

func (f flushWriter) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	if err != nil {
		return n, err
	}
	if ferr := f.rc.Flush(); ferr != nil && !errors.Is(ferr, http.ErrNotSupported) {
		return n, ferr
	}
	return n, nil
}

// upgradedPipe is what an upgrade leaves behind, the client socket joined to the upstream one.
// Closing it ends both directions, which is the only way to stop a splice.
type upgradedPipe struct {
	client  net.Conn
	backend io.Closer
}

func (u *upgradedPipe) Close() error {
	cerr := u.client.Close()
	berr := u.backend.Close()
	return errors.Join(cerr, berr)
}

// pipeSession describes the pipe an upgrade left behind.
//
// It gets a session of its own because a request routes on its Host header, which can differ
// from the CONNECT authority. Reusing the connection's would report an authority the pipe does
// not talk to, and a sweep would keep the wrong one.
func pipeSession(c *Context, r *http.Request, action Action, pipe io.Closer) *Session {
	target := Target{Scheme: c.scheme, Host: c.host, Port: c.port}
	sess := newSession(r.Context(), nil, target, action, protoOfRequest(r))
	sess.closer = pipe

	front := c.sess
	if front == nil {
		return sess
	}
	sess.remoteAddr = front.remoteAddr
	sess.localAddr = front.localAddr
	sess.clientHello = front.clientHello
	sess.upstream = front.upstream
	sess.transparent = front.transparent
	if state := front.tlsState.Load(); state != nil {
		sess.tlsState.Store(state)
	} else {
		// The explicit proxy reached over TLS builds its session before the handshake, so the
		// state only exists behind the connection.
		sess.tlsConn = front.tlsConn
	}
	return sess
}

// spliceUpgrade completes a protocol upgrade, WebSocket being the common case. Past the 101
// the connection is no longer HTTP, so both ends are joined and relayed byte for byte.
func spliceUpgrade(c *Context, w http.ResponseWriter, r *http.Request, resp *http.Response, action Action) error {
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

	// After the hijack http.Server neither closes nor waits for the connection, so tracking it
	// here is what lets a shutdown and a route change reach the pipe.
	pipe := &upgradedPipe{client: client, backend: backend}
	sess := pipeSession(c, r, action, pipe)

	c.p.srv.track(pipe, true)
	c.p.srv.wg.Add(1)
	defer func() {
		c.p.srv.track(pipe, false)
		c.p.srv.wg.Done()
	}()

	// The 101 has not reached the client yet, so a pipe the tree no longer accepts is refused
	// with an ordinary status rather than granted and then torn down.
	if !c.p.srv.admitSession(sess) {
		return writeRawStatus(brw, http.StatusForbidden,
			"connection rejected, no interceptor or tunnel matches this authority")
	}
	defer c.p.srv.trackSession(sess, false)

	// Response.Write copies the body after the headers, and here the body is the pipe. Leaving
	// it in place would block forever trying to drain a stream that only ends when the peers
	// are done talking.
	resp.Body = nil
	if err := resp.Write(brw); err != nil {
		return fmt.Errorf("write upgrade response: %w", err)
	}
	if err := brw.Flush(); err != nil {
		return fmt.Errorf("flush upgrade response: %w", err)
	}

	errc := make(chan error, 2)
	go func() {
		buf := getCopyBuf()
		defer putCopyBuf(buf)
		_, cerr := io.CopyBuffer(backend, brw, buf)
		errc <- cerr
	}()
	go func() {
		buf := getCopyBuf()
		defer putCopyBuf(buf)
		_, cerr := io.CopyBuffer(client, backend, buf)
		errc <- cerr
	}()

	<-errc
	return nil
}

func isClientGone(err error) bool {
	return errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, http.ErrHandlerTimeout) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.EOF)
}
