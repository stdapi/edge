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
	"strings"
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
		http.Error(w, "edge: extended CONNECT is not served, WebSocket goes over HTTP/1.1",
			http.StatusNotImplemented)
		return
	}

	c.reset(sess, r, target.Scheme, target.Host, target.Port)
	c.identity = identity

	idx, n := tree.lookup(target.Host, routingPath(r), c, false)
	if n == nil {
		// A lookup that failed may have left captures behind from a branch it backtracked
		// out of, and no entry means no names to read them under.
		*c.params = (*c.params)[:0]
		http.Error(w, "edge: no entry matches this request", http.StatusForbidden)
		return
	}
	c.entry = n.entries[idx]

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
		http.Error(w, "edge: entry has no HTTP handler", http.StatusInternalServerError)
		return
	}

	resp, err := runHTTPHandler(&c.http, handler)
	if err != nil {
		resp = p.onError(&c.http, err)
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
	}
}

// serveGRPC runs a [GRPC] handler. The call is a request like any other underneath, so the
// answer travels back the same way.
func (p *Proxy) serveGRPC(c *routeCtx, w http.ResponseWriter, r *http.Request, sess *Session) {
	handler, _ := c.entry.serve.(GRPC)
	if handler == nil {
		http.Error(w, "edge: entry has no gRPC handler", http.StatusInternalServerError)
		return
	}

	gc := &c.grpc
	gc.ctx = r.Context()
	gc.w = w
	err := runKindHandler(p, sess, func() error { return handler(gc) })
	if gc.finishOpenCall() {
		// The response of an open call was written while the handler ran.
		if err != nil {
			p.logf(r.Context(), slog.LevelDebug, "grpc handler", sess, err)
		}
		return
	}
	if err == nil {
		var resp *http.Response
		if resp, err = gc.response(); err == nil {
			if werr := writeResponse(w, r, resp); werr != nil {
				p.logf(r.Context(), slog.LevelDebug, "write gRPC response", sess, werr)
			}
			return
		}
	}
	// The call failed after the handler had a response in hand. Nothing will write it, so
	// nothing else will close the upstream body it holds.
	gc.discard()

	// A failed call is still a 200 carrying a status, which is how a gRPC client reads an
	// error at all.
	resp := grpcStatusResponse(statusOf(err), err.Error())
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

// isExtendedConnect reports whether the request is an RFC 8441 CONNECT, which carries a
// :protocol pseudo header. Go's HTTP/2 server advertises the setting and surfaces the pseudo
// header as an ordinary one.
func isExtendedConnect(r *http.Request) bool {
	return r != nil && r.Method == http.MethodConnect && r.Header.Get(":protocol") != ""
}

func isClientGone(err error) bool {
	return errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, http.ErrHandlerTimeout) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.EOF)
}
