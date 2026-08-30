// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"
	"strings"
)

// serve routes one intercepted request, runs its handler and writes the result back to the
// client.
func (p *Proxy) serve(w http.ResponseWriter, r *http.Request, sess *Session, target Target) {
	tree := p.getTree()
	c := tree.pool.Get().(*Context)
	defer tree.pool.Put(c)
	c.reset(sess, r, target.Scheme, target.Host, target.Port)

	handler := p.noInterceptor
	if r.Method != "" {
		if idx, n := tree.lookup(r.Method, target.Host, routingPath(r), c, false); n != nil {
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

	if werr := writeResponse(w, r, resp); werr != nil {
		p.logf(r.Context(), slog.LevelDebug, "write response", sess, werr)
	}
}

// relay forwards a request a tunnel asked the proxy not to look at. No interceptor is consulted
// and no middleware runs: a tunneled authority stays unobserved even when it arrives as a
// plain request the proxy had to parse to route it at all.
func (p *Proxy) relay(w http.ResponseWriter, r *http.Request, sess *Session, target Target) {
	tree := p.getTree()
	c := tree.pool.Get().(*Context)
	defer tree.pool.Put(c)
	c.reset(sess, r, target.Scheme, target.Host, target.Port)

	resp, err := c.Forward()
	if err != nil {
		p.logf(r.Context(), slog.LevelWarn, "relay failed", sess, err)
		http.Error(w, "edge: "+err.Error(), http.StatusBadGateway)
		return
	}
	if werr := writeResponse(w, r, resp); werr != nil {
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

// writeResponse relays resp to the client.
func writeResponse(w http.ResponseWriter, r *http.Request, resp *http.Response) error {
	// An upgrade takes ownership of the body, which is the tunnel rather than a payload.
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return spliceUpgrade(w, r, resp)
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

// spliceUpgrade completes a protocol upgrade, WebSocket being the common case. Past the 101
// the connection is no longer HTTP, so both ends are joined and relayed byte for byte.
func spliceUpgrade(w http.ResponseWriter, r *http.Request, resp *http.Response) error {
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

	// Response.Write copies the body after the headers, and here the body is the tunnel:
	// leaving it in place would block forever trying to drain a stream that only ends when
	// the peers are done talking.
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
