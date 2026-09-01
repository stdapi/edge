// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"iter"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// errCallRefused ends a call whose method no entry matches any more. The message that
// arrived is refused before it is delivered, and the client is answered with Unavailable.
var errCallRefused = errors.New("edge: no entry matches this call any more")

const callRefusedMessage = "no entry matches this call any more"

// maxGRPCMessage bounds one message the proxy will buffer to hand a handler. The gRPC
// protocol puts a 4 byte length on the wire, so a peer can announce 4 GiB.
const maxGRPCMessage = 16 << 20

// Code is a gRPC status code, as defined by the gRPC protocol.
type Code uint32

const (
	// OK means the call succeeded.
	OK Code = 0
	// Canceled means the operation was cancelled, typically by the caller.
	Canceled Code = 1
	// Unknown is an error whose code the server could not determine.
	Unknown Code = 2
	// InvalidArgument means the client sent an argument the server rejects.
	InvalidArgument Code = 3
	// DeadlineExceeded means the deadline expired before the operation completed.
	DeadlineExceeded Code = 4
	// NotFound means the requested entity was not found.
	NotFound Code = 5
	// AlreadyExists means the entity a client tried to create is already there.
	AlreadyExists Code = 6
	// PermissionDenied means the caller is not allowed to run the operation.
	PermissionDenied Code = 7
	// ResourceExhausted means a quota is exhausted or the system is out of capacity.
	ResourceExhausted Code = 8
	// FailedPrecondition means the system is not in the state the operation requires.
	FailedPrecondition Code = 9
	// Aborted means the operation was aborted, typically on a concurrency conflict.
	Aborted Code = 10
	// OutOfRange means the operation was attempted past the valid range.
	OutOfRange Code = 11
	// Unimplemented means the operation is not implemented or not supported.
	Unimplemented Code = 12
	// Internal means an invariant the system depends on was broken.
	Internal Code = 13
	// Unavailable means the service is currently unavailable, and a retry may work.
	Unavailable Code = 14
	// DataLoss means data was lost or corrupted unrecoverably.
	DataLoss Code = 15
	// Unauthenticated means the caller has no valid credentials.
	Unauthenticated Code = 16
)

func (c Code) String() string {
	names := [...]string{
		"OK", "Canceled", "Unknown", "InvalidArgument", "DeadlineExceeded", "NotFound",
		"AlreadyExists", "PermissionDenied", "ResourceExhausted", "FailedPrecondition",
		"Aborted", "OutOfRange", "Unimplemented", "Internal", "Unavailable", "DataLoss",
		"Unauthenticated",
	}
	if int(c) < len(names) {
		return names[c]
	}
	return "Code(" + strconv.FormatUint(uint64(c), 10) + ")"
}

// MessageReader returns the messages of one direction of a call, or of both when built by
// [MergeMessages]. It is not safe for concurrent use. The message it returns is valid until
// the next ReadMessage on the same reader.
type MessageReader struct {
	ctx  context.Context
	read func() (*MessageCtx, error)
}

// ReadMessage returns the next message and blocks until one arrives. It returns an error once
// no message will arrive, and once no entry matches the call any more, in which case the
// message that arrived is refused and the call is answered with [Unavailable].
func (r *MessageReader) ReadMessage() (*MessageCtx, error) { return r.read() }

// MergeMessages returns a reader over the messages of a and b. When one of them ends with
// io.EOF the other is still read, and the merged reader ends with io.EOF once both have
// ended. Any other error ends it immediately. a and b must not be read elsewhere afterwards.
func MergeMessages(a, b *MessageReader) *MessageReader {
	m := &merged[*MessageCtx]{ctx: a.ctx, a: a.read, b: b.read}
	return &MessageReader{ctx: a.ctx, read: m.read}
}

// MessageCtx is one length-prefixed message and the decision about it. A message reaches the
// far side only through [MessageCtx.Forward] or [MessageCtx.Send].
type MessageCtx struct {
	call       *grpcCall
	payload    []byte
	compressed bool
	inbound    bool
}

// Bytes returns the message payload, encoded as the peers agreed. It is valid until the next
// read on the reader that returned it.
func (m *MessageCtx) Bytes() []byte { return m.payload }

// Compressed reports whether the compressed flag is set, in which case the payload is
// compressed with the encoding named by grpc-encoding.
func (m *MessageCtx) Compressed() bool { return m.compressed }

// Inbound reports whether the server sent the message toward the client.
func (m *MessageCtx) Inbound() bool { return m.inbound }

// Forward sends the message unchanged.
func (m *MessageCtx) Forward() error { return m.Send(m.payload) }

// Send sends b in place of the message, in its direction and with the same compressed flag.
// A send toward the origin fails once the request stream is half-closed, and a send toward
// the client fails until the origin has answered.
func (m *MessageCtx) Send(b []byte) error {
	return m.call.writeMessage(m.inbound, m.compressed, b)
}

// Reply sends b, uncompressed, to the peer the message came from. The other peer receives
// nothing. The limits of [MessageCtx.Send] apply.
func (m *MessageCtx) Reply(b []byte) error {
	return m.call.writeMessage(!m.inbound, false, b)
}

// Drop discards the message. It is equivalent to returning without sending.
func (m *MessageCtx) Drop() error { return nil }

// msgSource reads length-prefixed messages into a reusable buffer, the error sticky. admit,
// when set, is asked once a header has arrived and refuses the message when it answers false.
type msgSource struct {
	r     io.Reader
	admit func() bool
	err   error
	msg   []byte
	hdr   [5]byte
}

func (s *msgSource) next() (payload []byte, compressed bool, err error) {
	if s.err != nil {
		return nil, false, s.err
	}
	payload, compressed, s.err = s.step()
	return payload, compressed, s.err
}

func (s *msgSource) step() ([]byte, bool, error) {
	if _, err := io.ReadFull(s.r, s.hdr[:]); err != nil {
		// io.EOF on the header means the stream ended on a message boundary. A reset or a
		// truncated header must not be turned into a clean end, since the far side would then
		// read a complete call that was cut short.
		return nil, false, err
	}
	if s.admit != nil && !s.admit() {
		return nil, false, errCallRefused
	}
	length := binary.BigEndian.Uint32(s.hdr[1:])
	if length > maxGRPCMessage {
		return nil, false, errors.New("edge: gRPC message larger than the proxy will buffer")
	}
	if cap(s.msg) < int(length) {
		s.msg = make([]byte, length)
	}
	s.msg = s.msg[:length]
	if _, err := io.ReadFull(s.r, s.msg); err != nil {
		return nil, false, err
	}
	return s.msg, s.hdr[0] != 0, nil
}

// GRPCCtx is one gRPC call, handed to a [GRPC] handler. The pattern that selected it is the
// hostname and the full method name, which is what a gRPC client puts in the request path.
//
// A gRPC entry and an HTTP entry can share a path. A request whose content type is gRPC is
// served by the gRPC entry, any other request by the HTTP entry.
//
// The call keeps its handler, and every message is checked against the entries as they stand
// when it arrives. Once no entry matches the method any more, the message is refused, the
// call is answered with [Unavailable] and closed toward the origin.
//
// It is not safe for concurrent use and is returned to a pool once the handler returns, so
// anything kept past that must be copied.
type GRPCCtx struct {
	http *HTTPCtx
	ctx  context.Context
	resp *http.Response
	err  error
	// w is the response writer of a call opened by the handler.
	w    http.ResponseWriter
	call *grpcCall

	initMu sync.Mutex
}

// reset clears the per-call state. The routeCtx resets the http view.
func (c *GRPCCtx) reset() {
	c.ctx = nil
	c.resp = nil
	c.err = nil
	c.w = nil
	c.call = nil
}

// grpcRoute is what a call needs to ask the tree again whether an entry still matches it. It
// is copied out of the pooled routing state, since the question outlives the handler.
type grpcRoute struct {
	p      *Proxy
	sess   *Session
	req    *http.Request
	scheme string
	host   string
	port   string
}

func (r *grpcRoute) admitted() bool {
	tree := r.p.getTree()
	c := tree.pool.Get().(*routeCtx)
	c.reset(r.sess, r.req, r.scheme, r.host, r.port)
	_, n := tree.lookup(r.host, routingPath(r.req), c, false)
	tree.pool.Put(c)
	return n != nil
}

// markRefused puts the status of a refused call in the trailers of a response being relayed,
// where the client reads it once the body ends.
func markRefused(resp *http.Response) {
	if resp.Trailer == nil {
		resp.Trailer = make(http.Header, 2)
	}
	resp.Trailer.Set("Grpc-Status", strconv.FormatUint(uint64(Unavailable), 10))
	resp.Trailer.Set("Grpc-Message", grpcPercentEncode(callRefusedMessage))
}

// messageGate passes a stream of length-prefixed messages through and asks, once the header
// of each has arrived, whether the tree still matches the call. Reads never cross a message
// boundary, so nothing is buffered beyond the five header bytes held back for the question.
type messageGate struct {
	r      io.ReadCloser
	admit  func() bool
	refuse func()
	err    error
	left   int64
	hdr    [5]byte
	hdrN   int
	hdrOut int
}

func (g *messageGate) Read(b []byte) (int, error) {
	if g.err != nil {
		return 0, g.err
	}
	if len(b) == 0 {
		return 0, nil
	}
	if g.left > 0 {
		n, err := g.r.Read(b[:min(int64(len(b)), g.left)])
		g.left -= int64(n)
		if g.left == 0 {
			g.hdrN, g.hdrOut = 0, 0
		}
		return n, err
	}
	if g.hdrOut < g.hdrN {
		return g.handOut(b), nil
	}
	for g.hdrN < len(g.hdr) {
		n, err := g.r.Read(g.hdr[g.hdrN:])
		g.hdrN += n
		if err != nil {
			// What was read is handed out first, so the far side sees the same truncated
			// header a direct read would have produced.
			g.err = err
			if g.hdrN > 0 && g.hdrN < len(g.hdr) {
				n := g.hdrN
				g.hdrN = 0
				return copy(b, g.hdr[:n]), nil
			}
			if g.hdrN == 0 {
				return 0, err
			}
			break
		}
	}
	if !g.admit() {
		g.refuse()
		g.err = errCallRefused
		return 0, g.err
	}
	g.left = int64(binary.BigEndian.Uint32(g.hdr[1:]))
	return g.handOut(b), nil
}

// handOut delivers the header bytes not yet delivered, and steps to the next message when
// the message carried no body.
func (g *messageGate) handOut(b []byte) int {
	n := copy(b, g.hdr[g.hdrOut:g.hdrN])
	g.hdrOut += n
	if g.hdrOut == len(g.hdr) && g.left == 0 {
		g.hdrN, g.hdrOut = 0, 0
	}
	return n
}

func (g *messageGate) Close() error { return g.r.Close() }

// grpcCall is the state of a call the handler owns. It is allocated per call, since a pump
// still blocked in a body read when the handler returns must find a dead call and never the
// pooled context serving the next one.
type grpcCall struct {
	route        grpcRoute
	ctx          context.Context
	w            http.ResponseWriter
	req          *http.Request
	outPw        *io.PipeWriter
	inPw         *io.PipeWriter
	inPr         *io.PipeReader
	upResp       *http.Response
	upErr        error
	cancel       context.CancelFunc
	respCh       chan struct{}
	outR         *MessageReader
	inR          *MessageReader
	trailerNames []string
	outBuf       []byte
	inBuf        []byte
	wg           sync.WaitGroup
	mu           sync.Mutex // opened, outClosed, respCh and the readers
	outMu        sync.Mutex // writes toward the origin
	inMu         sync.Mutex // writes toward the client
	bodyMu       sync.Mutex // upstream body reads against the trailer read, filled inside the EOF read
	opened       bool
	outClosed    bool
	inDone       bool
	// refused records that a message was refused, so the response ends on a status the
	// client can read.
	refused bool
}

func (c *GRPCCtx) routeOf() grpcRoute {
	r := c.http.r
	return grpcRoute{p: r.p, sess: r.sess, req: r.req, scheme: r.scheme, host: r.host, port: r.port}
}

// get returns the call state, creating it on first use.
func (c *GRPCCtx) get() *grpcCall {
	c.initMu.Lock()
	defer c.initMu.Unlock()
	if c.call == nil {
		c.call = &grpcCall{ctx: c.ctx, route: c.routeOf()}
	}
	return c.call
}

// isOpen reports whether the handler committed the call with [GRPCCtx.Open].
func (c *GRPCCtx) isOpen() bool {
	c.initMu.Lock()
	call := c.call
	c.initMu.Unlock()
	return call != nil && call.isOpen()
}

// HTTP returns the request-level view of the call, for the headers and the request itself.
func (c *GRPCCtx) HTTP() *HTTPCtx { return c.http }

// Context returns the context of the request.
func (c *GRPCCtx) Context() context.Context { return c.ctx }

// Session returns the client connection this call arrived on.
func (c *GRPCCtx) Session() *Session { return c.http.Session() }

// Target returns the authority this call is addressed to.
func (c *GRPCCtx) Target() Target { return c.http.Target() }

// Identity returns what the configured authenticator reported for the connection, or an empty
// string when none did.
func (c *GRPCCtx) Identity() string { return c.http.Identity() }

// FullMethod returns the full method name, "/package.Service/Method", which is the path of
// the request.
func (c *GRPCCtx) FullMethod() string {
	if c.http.r.req == nil || c.http.r.req.URL == nil {
		return ""
	}
	return c.http.r.req.URL.Path
}

// Service returns the fully qualified service name of the call.
func (c *GRPCCtx) Service() string {
	full := strings.TrimPrefix(c.FullMethod(), "/")
	if i := strings.LastIndexByte(full, '/'); i >= 0 {
		return full[:i]
	}
	return ""
}

// Method returns the method name of the call, without its service.
func (c *GRPCCtx) Method() string {
	full := c.FullMethod()
	if i := strings.LastIndexByte(full, '/'); i >= 0 {
		return full[i+1:]
	}
	return ""
}

// Timeout returns the deadline the client asked for, as the grpc-timeout header spells it, and
// whether it sent one.
func (c *GRPCCtx) Timeout() (string, bool) {
	if c.http.r.req == nil {
		return "", false
	}
	v := c.http.r.req.Header.Get("Grpc-Timeout")
	return v, v != ""
}

// Metadata returns the first value of the named call metadata, which travels as a request
// header.
func (c *GRPCCtx) Metadata(key string) string { return c.http.Header(key) }

// Pattern returns the pattern of the matched entry.
func (c *GRPCCtx) Pattern() string { return c.http.Pattern() }

// Entry returns the matched entry.
func (c *GRPCCtx) Entry() Entry[GRPC] { return Entry[GRPC]{e: c.http.r.entry} }

// Params returns an iterator over the parameters matched in the pattern.
func (c *GRPCCtx) Params() iter.Seq[Param] { return c.http.Params() }

// Param returns the value matched for the named parameter, or an empty string.
func (c *GRPCCtx) Param(name string) string { return c.http.Param(name) }

// Proxy returns the [Proxy] serving this call.
func (c *GRPCCtx) Proxy() *Proxy { return c.http.Proxy() }

// Forward sends the call to the origin and streams the response back unchanged, every message
// still checked against the entries as it arrives.
func (c *GRPCCtx) Forward() error {
	if c.isOpen() {
		return errors.New("edge: call already opened")
	}
	route := c.routeOf()
	var refused atomic.Bool
	refuse := func() { refused.Store(true) }

	req := c.http.r.req
	if req != nil && req.Body != nil && req.Body != http.NoBody {
		// The transport keeps reading the body after Forward returns, so the gate is its
		// own allocation and the request is handed back as it was.
		body := req.Body
		req.Body = &messageGate{r: body, admit: route.admitted, refuse: refuse}
		defer func() { req.Body = body }()
	}

	resp, err := c.http.Forward()
	if err != nil {
		c.err = err
		return err
	}
	if resp.Body != nil && resp.Body != http.NoBody {
		gate := &messageGate{r: resp.Body, admit: route.admitted}
		gate.refuse = func() {
			refused.Store(true)
			markRefused(resp)
		}
		resp.Body = &refusedBody{gate: gate, resp: resp, refused: &refused}
	}
	c.setResponse(resp)
	return nil
}

// refusedBody is the response body of a forwarded call. A refusal in either direction ends
// it, and the status the client reads is put in the trailers as it ends.
type refusedBody struct {
	gate    *messageGate
	resp    *http.Response
	refused *atomic.Bool
}

func (b *refusedBody) Read(p []byte) (int, error) {
	n, err := b.gate.Read(p)
	if err != nil && b.refused.Load() {
		markRefused(b.resp)
	}
	return n, err
}

func (b *refusedBody) Close() error { return b.gate.Close() }

// Open sends the request headers to the origin and gives the handler the call. The handler
// then reads [GRPCCtx.Outbound] and [GRPCCtx.Inbound] and decides each message. A forwarded
// response message reaches the client as it is sent, and the trailers of the origin follow
// once the handler returns.
//
// An [GRPCCtx.Inbound] the handler never asked for is relayed unchanged once the handler
// returns. One it read and left before its end is cut with the call.
//
// Call Open before any goroutine reads. [GRPCCtx.Fail] and [GRPCCtx.Respond] fail after
// Open.
func (c *GRPCCtx) Open() error {
	if c.resp != nil {
		return errors.New("edge: call already answered locally")
	}
	req := c.http.r.req
	if req == nil {
		return errors.New("edge: no request to open")
	}
	if c.w == nil {
		return errors.New("edge: call cannot stream a response here")
	}
	return c.get().open(c.http, req, c.w)
}

// CloseSend half-closes the call toward the origin, which ends the request stream. A read of
// [GRPCCtx.Outbound] that reaches its end while the call is open half-closes as well.
func (c *GRPCCtx) CloseSend() error {
	c.initMu.Lock()
	call := c.call
	c.initMu.Unlock()
	if call == nil {
		return nil
	}
	return call.closeSend()
}

// Outbound returns the reader of the request messages. It can be read before [GRPCCtx.Open],
// so a handler can decide on the first message and fail the call before the origin is
// reached. Its end is sticky, and a read that reaches it while the call is open half-closes
// the call toward the origin.
func (c *GRPCCtx) Outbound() *MessageReader {
	var body io.Reader = http.NoBody
	if req := c.http.r.req; req != nil && req.Body != nil {
		body = req.Body
	}
	return c.get().outbound(body)
}

// Inbound returns the reader of the response messages. The call must be open, and the first
// read blocks until the origin answers.
func (c *GRPCCtx) Inbound() *MessageReader { return c.get().inbound() }

// finishOpenCall tears an open call down once the handler has returned, and reports whether
// there was one.
func (c *GRPCCtx) finishOpenCall() bool {
	if !c.isOpen() {
		return false
	}
	c.call.finish()
	return true
}

func (k *grpcCall) isOpen() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.opened
}

func (k *grpcCall) open(h *HTTPCtx, req *http.Request, w http.ResponseWriter) error {
	k.mu.Lock()
	if k.opened {
		k.mu.Unlock()
		return nil
	}
	outPr, outPw := io.Pipe()
	inPr, inPw := io.Pipe()
	ctx, cancel := context.WithCancel(req.Context())
	k.w, k.req = w, req
	k.outPw, k.inPw, k.inPr = outPw, inPw, inPr
	k.cancel = cancel
	k.respCh = make(chan struct{})
	k.opened = true
	k.mu.Unlock()

	out := req.WithContext(ctx)
	out.Body = outPr
	// The handler decides which messages go up, so the declared length no longer holds.
	out.ContentLength = -1

	// finish joins both goroutines before the context returns to its pool, so the round trip
	// may read the pooled state.
	k.wg.Go(func() {
		resp, err := h.ForwardRequest(out)
		if err != nil {
			k.upErr = err
			// Nothing else ends a write into the pipe once the transport gave up on it.
			_ = outPr.CloseWithError(err)
		} else {
			k.upResp = resp
			// The trailer names are known with the headers, and the values are written by
			// the body read that returns EOF. The names are copied before that read can
			// happen.
			for name := range resp.Trailer {
				k.trailerNames = append(k.trailerNames, name)
			}
		}
		close(k.respCh)
	})
	k.wg.Go(k.serveResponse)
	return nil
}

func (k *grpcCall) closeSend() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.opened || k.outClosed {
		return nil
	}
	k.outClosed = true
	return k.outPw.Close()
}

func (k *grpcCall) outbound(body io.Reader) *MessageReader {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.outR != nil {
		return k.outR
	}

	src := &msgSource{r: body, admit: k.route.admitted}
	mc := &MessageCtx{call: k, inbound: false}
	k.outR = &MessageReader{ctx: k.ctx, read: func() (*MessageCtx, error) {
		payload, compressed, err := src.next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				_ = k.closeSend()
			}
			if errors.Is(err, errCallRefused) {
				k.refuse()
			}
			return nil, err
		}
		mc.payload, mc.compressed = payload, compressed
		return mc, nil
	}}
	return k.outR
}

func (k *grpcCall) inbound() *MessageReader {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.inR != nil {
		return k.inR
	}

	var src *msgSource
	mc := &MessageCtx{call: k, inbound: true}
	k.inR = &MessageReader{ctx: k.ctx, read: func() (*MessageCtx, error) {
		if src == nil {
			if err := k.waitResponse(); err != nil {
				return nil, err
			}
			src = &msgSource{r: k.upResp.Body, admit: k.route.admitted}
		}
		k.bodyMu.Lock()
		payload, compressed, err := src.next()
		if errors.Is(err, io.EOF) {
			k.inDone = true
		}
		k.bodyMu.Unlock()
		if err != nil {
			if errors.Is(err, errCallRefused) {
				k.refuse()
			}
			return nil, err
		}
		mc.payload, mc.compressed = payload, compressed
		return mc, nil
	}}
	return k.inR
}

func (k *grpcCall) refuse() {
	k.mu.Lock()
	k.refused = true
	k.mu.Unlock()
}

func (k *grpcCall) isRefused() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.refused
}

// waitResponse blocks until the origin answered the open call, and returns the error when it
// did not.
func (k *grpcCall) waitResponse() error {
	k.mu.Lock()
	ch := k.respCh
	k.mu.Unlock()
	if ch == nil {
		return errors.New("edge: call not opened")
	}
	select {
	case <-ch:
	case <-k.ctx.Done():
		return k.ctx.Err()
	}
	return k.upErr
}

// writeMessage frames b toward one side of the call in one write. The pipe delivers each
// write as one read, and one read is one DATA frame.
func (k *grpcCall) writeMessage(inbound, compressed bool, b []byte) error {
	if len(b) > maxGRPCMessage {
		return errors.New("edge: gRPC message larger than the proxy will write")
	}
	k.mu.Lock()
	opened, ch := k.opened, k.respCh
	k.mu.Unlock()
	if !opened {
		return errors.New("edge: call not opened")
	}

	w, mu, buf := io.Writer(k.outPw), &k.outMu, &k.outBuf
	if inbound {
		select {
		case <-ch:
		default:
			return errors.New("edge: no response to write into before the origin answered")
		}
		w, mu, buf = k.inPw, &k.inMu, &k.inBuf
	}

	mu.Lock()
	defer mu.Unlock()
	*buf = appendGRPCMessage((*buf)[:0], compressed, b)
	_, err := w.Write(*buf)
	return err
}

// serveResponse writes the response of an open call while the handler runs, so a forwarded
// response message reaches the client before the handler returns. Only this goroutine uses
// the response writer.
func (k *grpcCall) serveResponse() {
	<-k.respCh

	if k.upErr != nil {
		resp := grpcStatusResponse(statusOf(k.upErr), k.upErr.Error())
		if k.isRefused() {
			resp = grpcStatusResponse(Unavailable, callRefusedMessage)
		}
		_ = writeResponse(k.w, k.req, resp)
		// Drain the pipe, so a handler still sending toward the client does not block.
		_, _ = io.Copy(io.Discard, k.inPr)
		return
	}

	resp := k.upResp
	dst := k.w.Header()
	for name, vv := range resp.Header {
		dst[name] = append(vv[:0:0], vv...)
	}
	// The handler decides which messages go down, so the declared length no longer holds.
	dst.Del("Content-Length")
	if len(k.trailerNames) > 0 {
		dst.Set("Trailer", strings.Join(k.trailerNames, ", "))
	}
	k.w.WriteHeader(resp.StatusCode)

	rc := http.NewResponseController(k.w)
	buf := getCopyBuf()
	_, _ = io.CopyBuffer(flushWriter{w: k.w, rc: rc}, k.inPr, buf)
	putCopyBuf(buf)

	k.bodyMu.Lock()
	defer k.bodyMu.Unlock()
	if k.isRefused() {
		// The origin's trailers never arrived or no longer apply, and the client reads the
		// refusal instead.
		dst.Set(http.TrailerPrefix+"Grpc-Status", strconv.FormatUint(uint64(Unavailable), 10))
		dst.Set(http.TrailerPrefix+"Grpc-Message", grpcPercentEncode(callRefusedMessage))
		return
	}
	if !k.inDone {
		return
	}
	for name, vv := range resp.Trailer {
		for _, v := range vv {
			dst.Add(http.TrailerPrefix+name, v)
		}
	}
}

// finish tears the call down once the handler has returned. The send side is closed, a
// response the handler never read is relayed, what is still pending upstream is canceled, and
// the goroutines are joined before the context returns to its pool.
func (k *grpcCall) finish() {
	_ = k.closeSend()
	k.mu.Lock()
	untouched := k.inR == nil
	k.mu.Unlock()
	if untouched {
		k.relayInbound()
	}
	k.cancel()
	_ = k.inPw.Close()
	k.wg.Wait()
	if k.upResp != nil && k.upResp.Body != nil {
		_ = k.upResp.Body.Close()
	}
}

// relayInbound relays the response unchanged, for a handler that never read the inbound
// reader.
func (k *grpcCall) relayInbound() {
	if k.waitResponse() != nil {
		return
	}
	k.bodyMu.Lock()
	defer k.bodyMu.Unlock()
	buf := getCopyBuf()
	_, err := io.CopyBuffer(k.inPw, k.upResp.Body, buf)
	putCopyBuf(buf)
	if err == nil {
		k.inDone = true
	}
}

// Fail answers the call with a trailers-only response, and the origin is not reached.
//
//	return c.Fail(edge.Unavailable, "upstream flaky")
func (c *GRPCCtx) Fail(code Code, msg string) error {
	if c.isOpen() {
		return errors.New("edge: call already opened")
	}
	c.setResponse(grpcStatusResponse(code, msg))
	return nil
}

// Respond answers the call with messages and a status, and the origin is not reached.
func (c *GRPCCtx) Respond(code Code, msg string, messages ...[]byte) error {
	if c.isOpen() {
		return errors.New("edge: call already opened")
	}
	resp := grpcStatusResponse(code, msg)
	if len(messages) > 0 {
		var body []byte
		for _, m := range messages {
			body = appendGRPCMessage(body, false, m)
		}
		resp.Body = io.NopCloser(strings.NewReader(string(body)))
		resp.ContentLength = int64(len(body))
		// A response with messages puts the status in the trailers, where the client reads
		// it.
		resp.Trailer = http.Header{
			"Grpc-Status":  []string{strconv.FormatUint(uint64(code), 10)},
			"Grpc-Message": []string{grpcPercentEncode(msg)},
		}
		resp.Header.Del("Grpc-Status")
		resp.Header.Del("Grpc-Message")
	}
	c.setResponse(resp)
	return nil
}

// setResponse records what the handler decided, closing the body of anything it replaces. A
// handler that forwards and then answers locally would otherwise leave the upstream response
// open, and it has no way to close it itself.
func (c *GRPCCtx) setResponse(resp *http.Response) {
	if c.resp != nil && c.resp != resp && c.resp.Body != nil {
		_ = c.resp.Body.Close()
	}
	c.resp = resp
}

// discard closes whatever the handler left behind, for a call that ends without its response
// being written.
func (c *GRPCCtx) discard() {
	if c.resp != nil && c.resp.Body != nil {
		_ = c.resp.Body.Close()
	}
	c.resp = nil
}

// response returns what the handler decided, or an Internal status when it decided nothing.
func (c *GRPCCtx) response() (*http.Response, error) {
	if c.err != nil {
		return nil, c.err
	}
	if c.resp == nil {
		return grpcStatusResponse(Internal, "handler produced no response"), nil
	}
	return c.resp, nil
}

// statusOf maps a failure of the proxy's own to the status a gRPC client reads. A canceled
// or expired context is reported as such, anything else as the origin being unavailable.
func statusOf(err error) Code {
	switch {
	case errors.Is(err, context.Canceled):
		return Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return DeadlineExceeded
	}
	return Unavailable
}

func grpcStatusResponse(code Code, msg string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header: http.Header{
			"Content-Type": []string{"application/grpc"},
			"Grpc-Status":  []string{strconv.FormatUint(uint64(code), 10)},
			"Grpc-Message": []string{grpcPercentEncode(msg)},
		},
		Body:          http.NoBody,
		ContentLength: 0,
	}
}

// grpcPercentEncode escapes a status message the way the gRPC protocol requires, every byte
// outside the printable ASCII range and the percent itself written as %XX.
func grpcPercentEncode(msg string) string {
	needs := false
	for i := range len(msg) {
		if msg[i] < 0x20 || msg[i] > 0x7e || msg[i] == '%' {
			needs = true
			break
		}
	}
	if !needs {
		return msg
	}
	const hex = "0123456789ABCDEF"
	out := make([]byte, 0, len(msg)*3)
	for i := range len(msg) {
		b := msg[i]
		if b < 0x20 || b > 0x7e || b == '%' {
			out = append(out, '%', hex[b>>4], hex[b&0xf])
			continue
		}
		out = append(out, b)
	}
	return string(out)
}

// appendGRPCMessage frames payload into dst. The callers bound payload, msgSource for a
// message read off the wire and writeMessage for one a handler sends.
func appendGRPCMessage(dst []byte, compressed bool, payload []byte) []byte {
	var hdr [5]byte
	if compressed {
		hdr[0] = 1
	}
	//nolint:gosec // bounded by the callers
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	dst = append(dst, hdr[:]...)
	return append(dst, payload...)
}

// isGRPCRequest reports whether the request is a gRPC call, the precondition of [KindGRPC].
func isGRPCRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/grpc") {
		return false
	}
	// "application/grpc-web" is a different protocol on the same prefix, framed for a
	// browser.
	rest := ct[len("application/grpc"):]
	return rest == "" || rest[0] == ';' || rest[0] == '+'
}
