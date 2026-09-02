// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"iter"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// errCallRefused ends a call whose method no entry matches any more. The message that
// arrived is refused before it is delivered, and the client is answered with Unavailable.
var errCallRefused = errors.New("edge: no entry matches this call any more")

// The gRPC protocol puts a 4 byte length on the wire, so a peer can announce 4 GiB.
var errMessageTooLarge = errors.New("edge: gRPC message larger than the proxy will buffer")

var errNotOpened = errors.New("edge: call not opened")

const defaultMaxMessageBytes = 16 << 20

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
func (m *MessageCtx) Forward() error {
	return m.call.writeMessage(m.inbound, m.compressed, m.payload)
}

// Send sends b in place of the message, in its direction, with the compressed flag clear. A
// send toward the origin fails once the request stream is half-closed, and a send toward the
// client fails until the origin has answered.
func (m *MessageCtx) Send(b []byte) error { return m.call.writeMessage(m.inbound, false, b) }

// SendCompressed sends b in place of the message, in its direction, with the compressed flag
// set. b must be compressed with the encoding grpc-encoding declares. The limits of
// [MessageCtx.Send] apply.
func (m *MessageCtx) SendCompressed(b []byte) error {
	return m.call.writeMessage(m.inbound, true, b)
}

// Reply sends b, with the compressed flag clear, to the peer the message came from. The other
// peer receives nothing. The limits of [MessageCtx.Send] apply.
func (m *MessageCtx) Reply(b []byte) error { return m.call.writeMessage(!m.inbound, false, b) }

// ReplyCompressed sends b, with the compressed flag set, to the peer the message came from.
// The other peer receives nothing. The limits of [MessageCtx.Send] apply.
func (m *MessageCtx) ReplyCompressed(b []byte) error {
	return m.call.writeMessage(!m.inbound, true, b)
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
	max   int
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
	if int64(length) > int64(s.max) {
		return nil, false, errMessageTooLarge
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
	resp.Trailer.Set("Grpc-Message", grpcPercentEncode(Unavailable.String()))
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
	if len(b) == 0 {
		return 0, nil
	}
	// Header bytes not yet delivered go out before the body and before a sticky error. A
	// read shorter than a header would otherwise reorder the stream.
	if g.hdrOut < g.hdrN {
		return g.handOut(b), nil
	}
	if g.err != nil {
		return 0, g.err
	}
	if g.left > 0 {
		n, err := g.r.Read(b[:min(int64(len(b)), g.left)])
		g.left -= int64(n)
		if g.left == 0 {
			g.hdrN, g.hdrOut = 0, 0
		}
		return n, err
	}
	for g.hdrN < len(g.hdr) {
		n, err := g.r.Read(g.hdr[g.hdrN:])
		g.hdrN += n
		if err != nil {
			g.err = err
			if g.hdrN < len(g.hdr) {
				// What was read is handed out first, so the far side sees the same
				// truncated header a direct read would have produced.
				if g.hdrN == 0 {
					return 0, err
				}
				return g.handOut(b), nil
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
	ctx          context.Context
	w            http.ResponseWriter
	upErr        error
	req          *http.Request
	outPw        *io.PipeWriter
	inPw         *io.PipeWriter
	inPr         *io.PipeReader
	upResp       *http.Response
	cancel       context.CancelFunc
	respCh       chan struct{}
	outR         *MessageReader
	inR          *MessageReader
	route        grpcRoute
	msg          string
	trailerNames []string
	outBuf       []byte
	inBuf        []byte
	wg           sync.WaitGroup
	max          int
	mu           sync.Mutex // opened, outClosed, respCh and the readers
	outMu        sync.Mutex // writes toward the origin
	inMu         sync.Mutex // writes toward the client
	bodyMu       sync.Mutex // upstream body reads against the trailer read, filled inside the EOF read
	code         Code
	opened       bool
	outClosed    bool
	outRead      bool
	inDone       bool
	ended        bool
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
		c.call = &grpcCall{ctx: c.ctx, route: c.routeOf(), max: c.http.r.p.cfg.server.maxMessageBytes}
	}
	return c.call
}

func (c *GRPCCtx) current() *grpcCall {
	c.initMu.Lock()
	defer c.initMu.Unlock()
	return c.call
}

// isOpen reports whether the handler committed the call with [GRPCCtx.Open].
func (c *GRPCCtx) isOpen() bool {
	call := c.current()
	return call != nil && call.isOpen()
}

// Request returns the request of the call. The call metadata is its headers. Changes made
// before [GRPCCtx.Open] or [GRPCCtx.Forward] are sent to the origin.
func (c *GRPCCtx) Request() *http.Request { return c.http.r.req }

// SetRequest replaces the request sent to the origin. It has no effect after [GRPCCtx.Open]
// or [GRPCCtx.Forward].
func (c *GRPCCtx) SetRequest(r *http.Request) { c.http.SetRequest(r) }

// Response returns the response of the origin. It blocks until the origin answers, and
// returns an error if the call is not open or the origin fails. Header must not be modified.
// Trailer is set once [GRPCCtx.Inbound] has ended. A call that ends on the trailers of the
// origin sends them as they stand when the handler returns.
func (c *GRPCCtx) Response() (*http.Response, error) {
	call := c.current()
	if call == nil {
		return nil, errNotOpened
	}
	if err := call.waitResponse(); err != nil {
		return nil, err
	}
	return call.upResp, nil
}

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

// Timeout returns the timeout the client sent in grpc-timeout and whether it sent a valid one.
func (c *GRPCCtx) Timeout() (time.Duration, bool) {
	if c.http.r.req == nil {
		return 0, false
	}
	return parseGRPCTimeout(c.http.r.req.Header.Get("Grpc-Timeout"))
}

// A grpc-timeout value is at most eight digits and a unit.
func parseGRPCTimeout(v string) (time.Duration, bool) {
	if len(v) < 2 || len(v) > 9 {
		return 0, false
	}
	var unit time.Duration
	switch v[len(v)-1] {
	case 'H':
		unit = time.Hour
	case 'M':
		unit = time.Minute
	case 'S':
		unit = time.Second
	case 'm':
		unit = time.Millisecond
	case 'u':
		unit = time.Microsecond
	case 'n':
		unit = time.Nanosecond
	default:
		return 0, false
	}
	var n int64
	for i := range len(v) - 1 {
		d := v[i]
		if d < '0' || d > '9' {
			return 0, false
		}
		n = n*10 + int64(d-'0')
	}
	if n > math.MaxInt64/int64(unit) {
		return time.Duration(math.MaxInt64), true
	}
	return time.Duration(n) * unit, true
}

// DecodeBinaryMetadata decodes the value of a call metadata whose key ends in -bin, base64
// with or without padding.
func DecodeBinaryMetadata(v string) ([]byte, error) {
	if len(v)%4 == 0 {
		return base64.StdEncoding.DecodeString(v)
	}
	return base64.RawStdEncoding.DecodeString(v)
}

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
	if call := c.current(); call != nil && call.outboundRead() {
		return errors.New("edge: request stream already read")
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
		gate := &messageGate{r: resp.Body, admit: route.admitted, refuse: refuse}
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
// response message reaches the client as it is sent.
//
// An [GRPCCtx.Inbound] the handler never asked for is relayed unchanged once the handler
// returns. The call ends on the trailers of the origin when the handler returns after Inbound
// ended, and otherwise on a status the proxy sets, the one given to [GRPCCtx.Fail], the one
// the returned error maps to, or [Internal].
//
// Call Open before any goroutine reads. [GRPCCtx.Respond] fails after Open.
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
	call := c.current()
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

func (c *GRPCCtx) finishOpenCall(err error) bool {
	if !c.isOpen() {
		return false
	}
	c.call.finish(err)
	return true
}

func (k *grpcCall) isOpen() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.opened
}

func (k *grpcCall) outboundRead() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.outRead
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
			h.r.p.logf(ctx, slog.LevelDebug, "grpc call failed", h.r.sess, err)
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

	src := &msgSource{r: body, admit: k.route.admitted, max: k.max}
	mc := &MessageCtx{call: k, inbound: false}
	k.outR = &MessageReader{ctx: k.ctx, read: func() (*MessageCtx, error) {
		k.mu.Lock()
		k.outRead = true
		k.mu.Unlock()
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
			src = &msgSource{r: k.upResp.Body, admit: k.route.admitted, max: k.max}
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

// The first status set is what the client reads.
func (k *grpcCall) end(code Code, msg string) {
	k.mu.Lock()
	if !k.ended {
		k.code, k.msg, k.ended = code, msg, true
	}
	k.mu.Unlock()
}

func (k *grpcCall) status() (code Code, msg string, ended bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.code, k.msg, k.ended
}

func (k *grpcCall) refuse() { k.end(Unavailable, Unavailable.String()) }

func (k *grpcCall) fail(code Code, msg string) {
	k.end(code, msg)
	_ = k.closeSend()
	k.cancel()
	_ = k.inPw.Close()
}

// waitResponse blocks until the origin answered the open call, and returns the error when it
// did not.
func (k *grpcCall) waitResponse() error {
	k.mu.Lock()
	ch := k.respCh
	k.mu.Unlock()
	if ch == nil {
		return errNotOpened
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
	k.mu.Lock()
	opened, ch, maxBytes := k.opened, k.respCh, k.max
	k.mu.Unlock()
	if !opened {
		return errNotOpened
	}
	if len(b) > maxBytes {
		return errMessageTooLarge
	}

	w, mu, buf := io.Writer(k.outPw), &k.outMu, &k.outBuf
	if inbound {
		select {
		case <-ch:
		default:
			return errors.New("edge: no response to write into before the origin answered")
		}
		if k.upErr != nil {
			return k.upErr
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
		// The pipe ends when the handler has ended the call, and the status is read after.
		_, _ = io.Copy(io.Discard, k.inPr)
		code, msg, ended := k.status()
		if !ended {
			code = statusOf(k.upErr)
			msg = code.String()
		}
		_ = writeResponse(k.w, k.req, grpcStatusResponse(code, msg))
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
	_, cerr := io.CopyBuffer(flushWriter{w: k.w, rc: rc}, k.inPr, buf)
	putCopyBuf(buf)
	if cerr != nil {
		// Nothing reads the pipe once the client is gone, and a handler still sending toward
		// it must not block. The handler may still be running and writing the trailers.
		_ = k.inPr.CloseWithError(cerr)
		return
	}

	k.bodyMu.Lock()
	defer k.bodyMu.Unlock()
	if code, msg, ended := k.status(); ended {
		// The origin's trailers never arrived or no longer apply, and the client reads this
		// status instead.
		dst.Set(http.TrailerPrefix+"Grpc-Status", strconv.FormatUint(uint64(code), 10))
		dst.Set(http.TrailerPrefix+"Grpc-Message", grpcPercentEncode(msg))
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

// finish tears the call down once the handler has returned with err. The goroutines are
// joined before the context returns to its pool.
func (k *grpcCall) finish(err error) {
	_ = k.closeSend()
	k.mu.Lock()
	untouched := k.inR == nil && !k.ended
	k.mu.Unlock()
	if err == nil && untouched {
		err = k.relayInbound()
	}
	k.bodyMu.Lock()
	done := k.inDone
	k.bodyMu.Unlock()
	switch {
	case err != nil:
		code := statusOf(err)
		k.end(code, code.String())
	case !done:
		k.end(Internal, Internal.String())
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
func (k *grpcCall) relayInbound() error {
	if err := k.waitResponse(); err != nil {
		return err
	}
	k.bodyMu.Lock()
	defer k.bodyMu.Unlock()
	buf := getCopyBuf()
	_, err := io.CopyBuffer(k.inPw, k.upResp.Body, buf)
	putCopyBuf(buf)
	if err == nil {
		k.inDone = true
	}
	return err
}

// Fail ends the call with a status. Before [GRPCCtx.Open] it answers with a trailers-only
// response and the origin is not reached. After Open the client reads the status in the
// trailers, after the messages already sent, and the origin is canceled. The first status set
// on an open call is the one the client reads.
//
//	return c.Fail(edge.Unavailable, "upstream flaky")
func (c *GRPCCtx) Fail(code Code, msg string) error {
	if call := c.current(); call != nil && call.isOpen() {
		call.fail(code, msg)
		return nil
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
	c.err = nil
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
// or expired context is reported as such, a message over the bound as the resource it
// exhausted, anything else as the origin being unavailable.
func statusOf(err error) Code {
	switch {
	case errors.Is(err, context.Canceled):
		return Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return DeadlineExceeded
	case errors.Is(err, errMessageTooLarge):
		return ResourceExhausted
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
