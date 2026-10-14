// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// dispatchRequest routes one request and runs whatever serves it. The lookup runs on the tree
// as it stands now, so an entry added or removed while the connection was open applies to
// this request.
func (p *Proxy) dispatchRequest(w http.ResponseWriter, r *http.Request, sess *Session, target Target, identity string) {
	tree := p.getTree()
	c := tree.pool.Get().(*routeCtx)
	defer tree.pool.Put(c)

	if isExtendedConnect(r) {
		// RFC 8441 turns a stream into something that is no longer HTTP, the way a 101 does,
		// and there is no hijack on an HTTP/2 stream. The proxy refuses it here, before the
		// exchange fails further in.
		p.writeStatus(w, r, http.StatusNotImplemented, "extended CONNECT is not served, WebSocket goes over HTTP/1.1")
		return
	}

	if r.Method == http.MethodConnect {
		// The front answers a CONNECT before anything is routed, so one reaching here was sent
		// to a terminated connection. Its target has no path, and a lookup without one reaches
		// the admission of its authority.
		p.writeStatus(w, r, http.StatusNotImplemented, "CONNECT is not served on a terminated connection")
		return
	}

	c.reset(sess, r, target.Scheme, target.Host, target.Port)
	c.client, c.body = r, r.Body
	c.identity = identity

	c.entry = tree.route(c, false)
	if c.entry == nil {
		p.writeStatus(w, r, http.StatusForbidden, "no entry matches this request")
		return
	}
	if r.ProtoMajor == 3 {
		body := &h3Body{ReadCloser: r.Body, w: w}
		r.Body, c.body = body, body
		defer body.handlerReturned()
	}

	switch c.entry.kind {
	case KindGRPC:
		p.serveGRPC(c, w, r, sess)
	case KindWebSocket:
		p.serveWebSocketUpgrade(c, w, r, sess)
	default:
		p.serveHTTPEntry(c, w, r, sess)
	}
}

// serveHTTPEntry runs an [HTTP] handler and writes what it returns back to the client.
func (p *Proxy) serveHTTPEntry(c *routeCtx, w http.ResponseWriter, r *http.Request, sess *Session) {
	handler, _ := c.entry.serve.(HTTP)
	if handler == nil {
		p.writeStatus(w, r, http.StatusInternalServerError, "entry has no HTTP handler")
		return
	}

	if r.ProtoAtLeast(1, 1) {
		// RFC 9110 15.2, an HTTP/1.0 client is sent no 1xx, and net/http would send one.
		c.w = w
		// The HTTP/1.1 server answers any other expectation with a 417 before the handler runs.
		c.expectContinue = r.ProtoMajor == 1 && r.ContentLength != 0 && len(r.Header["Expect"]) > 0
	}
	resp, err := runHTTPHandler(&c.http, handler)
	if err != nil {
		resp = p.onError(&c.http, err)
		if _, ok := errors.AsType[requestReset](err); ok {
			// HTTP has no status for a canceled request.
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			abortResponse(w)
		}
	}
	if resp == nil {
		resp = Status(http.StatusBadGateway)
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		// Past the 101 the connection is no longer HTTP, so the entry that served the
		// handshake cannot serve what follows. What follows is a byte stream in the clear,
		// served by a stream entry when one admits the authority and refused otherwise, since
		// nothing may be relayed unobserved.
		if err := p.serveUpgradedStream(c, w, r, resp, sess); err != nil {
			p.logf(r.Context(), slog.LevelDebug, "upgraded stream closed", sess, err)
		}
		return
	}

	if werr := writeResponse(w, r, resp); werr != nil {
		p.logf(r.Context(), slog.LevelDebug, "write response", sess, werr)
		abortIfCut(w, werr)
	}
}

// serveGRPC runs a [GRPC] handler. The call is a request like any other underneath, so the
// answer travels back the same way.
func (p *Proxy) serveGRPC(c *routeCtx, w http.ResponseWriter, r *http.Request, sess *Session) {
	handler, _ := c.entry.serve.(GRPC)
	if handler == nil {
		p.writeStatus(w, r, http.StatusInternalServerError, "entry has no gRPC handler")
		return
	}

	gc := &c.grpc
	gc.ctx = r.Context()
	gc.w = w
	err := runKindHandler(p, sess, func() error { return handler(gc) })
	if opened, cut := gc.finishOpenCall(err); opened {
		// The response of an open call was written while the handler ran.
		if err != nil {
			p.logf(r.Context(), slog.LevelDebug, "grpc handler", sess, err)
		}
		if cut != nil {
			p.logf(r.Context(), slog.LevelDebug, "grpc response", sess, cut)
			abortIfCut(w, cut)
		}
		return
	}
	if err == nil {
		var resp *http.Response
		if resp, err = gc.response(); err == nil {
			if werr := writeResponse(w, r, resp); werr != nil {
				p.logf(r.Context(), slog.LevelDebug, "write gRPC response", sess, werr)
				abortIfCut(w, werr)
			}
			return
		}
	}
	// The call failed after the handler had a response in hand. Nothing will write it, so
	// nothing else will close the upstream body it holds.
	gc.discard()

	// A failed call is still a 200 carrying a status, which is how a gRPC client reads an
	// error at all.
	p.logf(r.Context(), slog.LevelDebug, "grpc call failed", sess, err)
	code := statusOf(err)
	resp := grpcStatusResponse(code, code.String())
	if werr := writeResponse(w, r, resp); werr != nil {
		p.logf(r.Context(), slog.LevelDebug, "write gRPC status", sess, werr)
	}
}

// runHTTPHandler calls the handler and turns a panic into a [PanicError]. Nothing is logged
// here, the error takes the normal path and the [ErrorHandler] decides what a panic answers.
func runHTTPHandler(c *HTTPCtx, handler HTTP) (resp *http.Response, err error) {
	defer func() {
		rec := recover()
		if rec == nil {
			return
		}
		if e, ok := rec.(error); ok && errors.Is(e, http.ErrAbortHandler) {
			// The caller aborted on purpose, and net/http must see it.
			panic(rec)
		}
		resp = nil
		err = &PanicError{Value: rec, Stack: stacktrace(panicStackSkip)}
	}()

	return handler(c)
}

// runKindHandler calls a handler that produces no response and turns a panic into an error the
// caller reports. A response handler routes its panic through the [ErrorHandler] instead.
func runKindHandler(p *Proxy, sess *Session, fn func() error) (err error) {
	defer func() {
		rec := recover()
		if rec == nil {
			return
		}
		err = &PanicError{Value: rec, Stack: stacktrace(panicStackSkip)}
		p.cfg.logger.Error("edge: handler panic",
			slog.String("target", sess.target.String()),
			slog.Any("panic", rec))
	}()
	return fn()
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

// writeResponse relays resp to the client.
func writeResponse(w http.ResponseWriter, r *http.Request, resp *http.Response) error {
	if resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	dst := w.Header()
	for k, vv := range resp.Header {
		dst[k] = append(dst[k][:0:0], vv...)
	}
	if _, ok := dst["Content-Type"]; !ok {
		// A nil value is how a server is told not to sniff a type the response never declared.
		dst["Content-Type"] = nil
	}

	// Trailers must be announced before the header block is written, and their values only
	// exist once the body has been fully read.
	announceTrailers(dst, resp)

	w.WriteHeader(resp.StatusCode)

	if resp.Body == nil || resp.Body == http.NoBody || !bodyAllowed(r.Method, resp.StatusCode) {
		return nil
	}

	rc := http.NewResponseController(w)
	_, err := copyStream(flushWriter{w: w, rc: rc}, resp.Body, nil)

	for k, vv := range resp.Trailer {
		for _, v := range vv {
			dst.Add(http.TrailerPrefix+k, v)
		}
	}

	switch {
	case err == nil:
		return nil
	case errors.As(err, new(writeError)):
		if isClientGone(err) {
			return nil
		}
		return fmt.Errorf("copy response body: %w", err)
	default:
		return fmt.Errorf("%w: %w", errBodyCut, err)
	}
}

// errBodyCut is returned by writeResponse when the body it relays failed before its end.
var errBodyCut = errors.New("response body cut short")

// abortIfCut resets the response when err is errBodyCut. A return would end it cleanly and the
// client would read a complete body.
func abortIfCut(w http.ResponseWriter, err error) {
	if errors.Is(err, errBodyCut) {
		abortResponse(w)
	}
}

func abortResponse(w http.ResponseWriter) {
	if hs, ok := w.(http3.HTTPStreamer); ok {
		// RFC 9114 4.1.1 resets an abandoned response with H3_REQUEST_CANCELLED, where quic-go
		// resets an aborted handler with H3_INTERNAL_ERROR.
		str := hs.HTTPStream()
		str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	}
	panic(http.ErrAbortHandler)
}

// announceTrailers copies the trailer names the upstream declared into the response header, so
// an HTTP/1.1 client knows to expect them after the body.
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

// isExtendedConnect reports whether the request is an RFC 8441 or RFC 9220 CONNECT, one
// carrying a :protocol pseudo header.
func isExtendedConnect(r *http.Request) bool {
	return extendedConnectProtocol(r) != ""
}

// extendedConnectProtocol returns the :protocol of an extended CONNECT, or an empty string
// for a plain one. Go's HTTP/2 server surfaces the pseudo header as an ordinary one, and
// quic-go's HTTP/3 server puts it where the version normally is.
func extendedConnectProtocol(r *http.Request) string {
	if r == nil || r.Method != http.MethodConnect {
		return ""
	}
	if v := r.Header.Get(":protocol"); v != "" {
		return v
	}
	if r.ProtoMajor == 3 && !strings.HasPrefix(r.Proto, "HTTP/") {
		return r.Proto
	}
	return ""
}

func isClientGone(err error) bool {
	return errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, http.ErrHandlerTimeout) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.EOF)
}

// requestReset is a read of an HTTP/3 request body that failed on a RESET_STREAM of the client.
// The client cancels the request that way and may still read the response.
type requestReset struct{ error }

func (e requestReset) Unwrap() error { return e.error }

// h3Body is the body of an HTTP/3 request. The upstream transports close it from goroutines of
// their own, after the handler may have returned.
type h3Body struct {
	io.ReadCloser
	w        http.ResponseWriter
	mu       sync.Mutex // the use of w against the return of the handler
	returned bool
	closed   atomic.Bool
}

func (b *h3Body) handlerReturned() {
	b.mu.Lock()
	b.returned = true
	b.mu.Unlock()
}

func (b *h3Body) Read(p []byte) (int, error) {
	if b.closed.Load() {
		return 0, http.ErrBodyReadAfterClose
	}
	n, err := b.ReadCloser.Read(p)
	switch {
	case err == nil, errors.Is(err, io.EOF):
	case b.closed.Load():
		err = http.ErrBodyReadAfterClose
	default:
		if se, ok := errors.AsType[*quic.StreamError](err); ok && se.Remote {
			err = requestReset{err}
		}
	}
	return n, err
}

// Close ends a read in progress with a read deadline. The Close of quic-go sends STOP_SENDING
// with H3_REQUEST_CANCELLED, which gRPC maps to CANCELLED, where quic-go sends STOP_SENDING with
// H3_NO_ERROR when the handler returns, and past that return the stream is the server's.
func (b *h3Body) Close() error {
	if b.closed.Swap(true) {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.returned {
		return nil
	}
	return http.NewResponseController(b.w).SetReadDeadline(time.Unix(1, 0))
}
