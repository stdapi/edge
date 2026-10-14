// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
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

var errSendCut = errors.New("edge: call ended before the end of its request stream")

var errNotGRPCResponse = errors.New("edge: the origin answered with a response that is not gRPC")

var errOriginStopped = errors.New("edge: the origin no longer reads the request stream")

// upstreamError is a failure reaching the origin, before it answered.
type upstreamError struct{ error }

func (e upstreamError) Unwrap() error { return e.error }

const defaultMaxMessageBytes = 16 << 20

// Code is a gRPC status code, as defined by the gRPC protocol.
type Code uint32

const (
	// CodeOK means the call succeeded.
	CodeOK Code = 0
	// CodeCanceled means the operation was cancelled, typically by the caller.
	CodeCanceled Code = 1
	// CodeUnknown is an error whose code the server could not determine.
	CodeUnknown Code = 2
	// CodeInvalidArgument means the client sent an argument the server rejects.
	CodeInvalidArgument Code = 3
	// CodeDeadlineExceeded means the deadline expired before the operation completed.
	CodeDeadlineExceeded Code = 4
	// CodeNotFound means the requested entity was not found.
	CodeNotFound Code = 5
	// CodeAlreadyExists means the entity a client tried to create is already there.
	CodeAlreadyExists Code = 6
	// CodePermissionDenied means the caller is not allowed to run the operation.
	CodePermissionDenied Code = 7
	// CodeResourceExhausted means a quota is exhausted or the system is out of capacity.
	CodeResourceExhausted Code = 8
	// CodeFailedPrecondition means the system is not in the state the operation requires.
	CodeFailedPrecondition Code = 9
	// CodeAborted means the operation was aborted, typically on a concurrency conflict.
	CodeAborted Code = 10
	// CodeOutOfRange means the operation was attempted past the valid range.
	CodeOutOfRange Code = 11
	// CodeUnimplemented means the operation is not implemented or not supported.
	CodeUnimplemented Code = 12
	// CodeInternal means an invariant the system depends on was broken.
	CodeInternal Code = 13
	// CodeUnavailable means the service is currently unavailable, and a retry may work.
	CodeUnavailable Code = 14
	// CodeDataLoss means data was lost or corrupted unrecoverably.
	CodeDataLoss Code = 15
	// CodeUnauthenticated means the caller has no valid credentials.
	CodeUnauthenticated Code = 16
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
// message that arrived is refused and the call is answered with [CodeUnavailable].
func (r *MessageReader) ReadMessage() (*MessageCtx, error) { return r.read() }

// MergeMessages returns a reader over the messages of a and b. When one of them ends with
// io.EOF the other is still read, and the merged reader ends with io.EOF once both have
// ended. Any other error ends it immediately. a and b must not be read elsewhere afterwards.
func MergeMessages(a, b *MessageReader) *MessageReader {
	m := &merged[*MessageCtx]{ctx: a.ctx, a: a.read, b: b.read, apart: a.ctx != b.ctx}
	return &MessageReader{ctx: a.ctx, read: m.read}
}

// MessageCtx is one length-prefixed message and the decision about it. A message reaches the
// far side only through [MessageCtx.Forward] or [MessageCtx.Send].
type MessageCtx struct {
	call    *grpcCall
	payload []byte
	flag    byte
	inbound bool
}

// Bytes returns the message payload, encoded as the peers agreed. It is valid until the next
// read on the reader that returned it.
func (m *MessageCtx) Bytes() []byte { return m.payload }

// Compressed reports whether the compressed flag is set to any value other than 0, in which
// case the payload is compressed with the encoding grpc-encoding declares.
func (m *MessageCtx) Compressed() bool { return m.flag != 0 }

// Inbound reports whether the server sent the message toward the client.
func (m *MessageCtx) Inbound() bool { return m.inbound }

// Forward sends the message unchanged, its flag byte included. The limits of
// [MessageCtx.Send] apply.
func (m *MessageCtx) Forward() error {
	return m.call.writeMessage(m.inbound, m.flag, m.payload)
}

// Send sends b in place of the message, in its direction, with the compressed flag clear. A
// send toward the origin fails once the request stream is half-closed or the origin stops
// reading it, and is dropped once [GRPCCtx.Outbound] has ended on the end of the response. A
// send toward the client fails until the origin has answered.
func (m *MessageCtx) Send(b []byte) error { return m.call.writeMessage(m.inbound, 0, b) }

// SendCompressed sends b in place of the message, in its direction, with the compressed flag
// set. b must be compressed with the encoding grpc-encoding declares. The limits of
// [MessageCtx.Send] apply.
func (m *MessageCtx) SendCompressed(b []byte) error {
	return m.call.writeMessage(m.inbound, 1, b)
}

// Reply sends b, with the compressed flag clear, to the peer the message came from. The other
// peer receives nothing. The limits of [MessageCtx.Send] apply.
func (m *MessageCtx) Reply(b []byte) error { return m.call.writeMessage(!m.inbound, 0, b) }

// ReplyCompressed sends b, with the compressed flag set, to the peer the message came from.
// The other peer receives nothing. The limits of [MessageCtx.Send] apply.
func (m *MessageCtx) ReplyCompressed(b []byte) error {
	return m.call.writeMessage(!m.inbound, 1, b)
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

func (s *msgSource) next() (payload []byte, flag byte, err error) {
	if s.err != nil {
		return nil, 0, s.err
	}
	payload, flag, s.err = s.step()
	return payload, flag, s.err
}

func (s *msgSource) step() ([]byte, byte, error) {
	if _, err := io.ReadFull(s.r, s.hdr[:]); err != nil {
		// io.EOF on the header means the stream ended on a message boundary. A reset or a
		// truncated header must not be turned into a clean end, since the far side would then
		// read a complete call that was cut short.
		return nil, 0, err
	}
	if s.admit != nil && !s.admit() {
		return nil, 0, errCallRefused
	}
	length := binary.BigEndian.Uint32(s.hdr[1:])
	if int64(length) > int64(s.max) {
		return nil, 0, errMessageTooLarge
	}
	if cap(s.msg) < int(length) {
		s.msg = make([]byte, length)
	}
	s.msg = s.msg[:length]
	if _, err := io.ReadFull(s.r, s.msg); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, 0, err
	}
	return s.msg, s.hdr[0], nil
}

// GRPCCtx is one gRPC call, handed to a [GRPC] handler. The pattern that selected it is the
// hostname and the full method name, which is what a gRPC client puts in the request path.
//
// A gRPC entry and an HTTP entry can share a path. A request whose content type is gRPC is
// served by the gRPC entry, any other request by the HTTP entry.
//
// The call keeps its handler, and every message is checked against the entries as they stand
// when it arrives. Once no entry matches the method any more, the message is refused, the
// call is answered with [CodeUnavailable] and closed toward the origin.
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
	admitted := tree.route(c, false) != nil
	tree.pool.Put(c)
	return admitted
}

// markStatus puts the status the proxy ends a forwarded call on in the trailers of the response
// being relayed, where the client reads it once the body ends.
func markStatus(resp *http.Response, code Code) {
	if resp.Trailer == nil {
		resp.Trailer = make(http.Header, 2)
	}
	resp.Trailer.Set("Grpc-Status", strconv.FormatUint(uint64(code), 10))
	resp.Trailer.Set("Grpc-Message", grpcPercentEncode(code.String()))
}

// callEnd is the status the proxy ends a forwarded call on, the first one set.
type callEnd struct{ v atomic.Uint32 }

func (e *callEnd) set(code Code) { e.v.CompareAndSwap(0, uint32(code)+1) }

func (e *callEnd) get() (Code, bool) {
	v := e.v.Load()
	return Code(v - 1), v != 0
}

// messageGate passes a stream of length-prefixed messages through and asks, once the header
// of each has arrived, whether the tree still matches the call. Reads never cross a message
// boundary, so nothing is buffered beyond the five header bytes held back for the question.
type messageGate struct {
	r      io.ReadCloser
	admit  func() bool
	end    *callEnd
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
		g.noteReset(err)
		return n, err
	}
	for g.hdrN < len(g.hdr) {
		n, err := g.r.Read(g.hdr[g.hdrN:])
		g.hdrN += n
		if err != nil {
			g.noteReset(err)
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
		g.end.set(CodeUnavailable)
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

func (g *messageGate) noteReset(err error) {
	if _, ok := errors.AsType[requestReset](err); ok {
		g.end.set(CodeCanceled)
	}
}

func (g *messageGate) Close() error { return g.r.Close() }

// grpcCall is the state of a call the handler owns. It is allocated per call, since a pump
// still blocked in a body read when the handler returns must find a dead call and never the
// pooled context serving the next one.
type grpcCall struct {
	ctx          context.Context
	w            http.ResponseWriter
	upErr        error
	cut          error
	req          *http.Request
	outBody      io.Reader
	outPw        *io.PipeWriter
	send         sendBody
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
	sendWg       sync.WaitGroup // the relay of the request messages the handler left
	max          int
	mu           sync.Mutex // opened, outClosed, originDone, sendStopped, respCh and the readers
	outMu        sync.Mutex // writes toward the origin
	outSrcMu     sync.Mutex // reads of the request stream
	inMu         sync.Mutex // writes toward the client
	bodyMu       sync.Mutex // upstream body reads against the trailer read, filled inside the EOF read
	code         Code
	opened       bool
	outClosed    bool
	outEOF       bool
	outCut       bool
	outRead      bool
	inDone       bool
	ended        bool
	passthrough  bool
	trailersOnly bool
	originDone   bool
	sendStopped  bool
}

// sendBody is the request stream of an open call as the upstream transport reads it. The
// transport closes it once it stops reading, the only sign of an origin that ended a response
// the handler does not read.
type sendBody struct {
	*io.PipeReader
	call *grpcCall
}

func (b *sendBody) Close() error {
	b.call.originStoppedReading()
	return b.PipeReader.Close()
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

// DecodeBinaryMetadata decodes one value of a call metadata whose key ends in -bin, base64
// with or without padding. Several values joined with a comma in one field are split by the
// caller before each is decoded.
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
	end := new(callEnd)

	req := c.http.r.req
	if req != nil && req.Body != nil && req.Body != http.NoBody {
		// The transport keeps reading the body after Forward returns, so the gate is its
		// own allocation and the request is handed back as it was.
		body := req.Body
		req.Body = &messageGate{r: body, admit: route.admitted, end: end}
		defer func() { req.Body = body }()
	}

	resp, err := c.http.Forward()
	if err != nil {
		err = upstreamError{err}
		c.err = err
		return err
	}
	if resp.Body != nil && resp.Body != http.NoBody {
		gate := &messageGate{r: resp.Body, admit: route.admitted, end: end}
		resp.Body = &refusedBody{gate: gate, resp: resp, end: end}
	}
	c.setResponse(resp)
	return nil
}

// refusedBody is the response body of a forwarded call. A refusal in either direction ends
// it, as does a reset of the request stream by the client, and the status the client reads is
// put in the trailers as it ends.
type refusedBody struct {
	gate *messageGate
	resp *http.Response
	end  *callEnd
}

func (b *refusedBody) Read(p []byte) (int, error) {
	n, err := b.gate.Read(p)
	if err == nil {
		return n, nil
	}
	code, ended := b.end.get()
	if !ended || code == CodeCanceled && errors.Is(err, io.EOF) {
		// An origin that completes its response after the reset ends the call on its own
		// trailers.
		return n, err
	}
	markStatus(b.resp, code)
	// The call ends on the status in the trailers, and any other error would reset it.
	return n, io.EOF
}

func (b *refusedBody) Close() error { return b.gate.Close() }

// Open sends the request headers to the origin and gives the handler the call. The handler
// then reads [GRPCCtx.Outbound] and [GRPCCtx.Inbound] and decides each message. A forwarded
// response message reaches the client as it is sent.
//
// An [GRPCCtx.Inbound] the handler never asked for is relayed unchanged once the handler
// returns, and so is what remains of [GRPCCtx.Outbound] when it returns nil without
// [GRPCCtx.Fail] or [GRPCCtx.CloseSend]. The call ends on the trailers of the origin when the
// handler returns after Inbound ended, and otherwise on a status the proxy sets, the one given
// to [GRPCCtx.Fail], the one the returned error maps to, or [CodeInternal]. A status the proxy
// sets resets what remains of Outbound toward the origin. A response with a status other than
// 200 or a content type other than gRPC is relayed unchanged with no status set, and Inbound
// ends once it is relayed.
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
// reached. Its end is sticky, a read that reaches it while the call is open half-closes the
// call toward the origin, and a read that fails or a return with an error before that end
// resets it. It also ends once the origin has answered with no message, or once
// [GRPCCtx.Inbound] has reached its end. When an origin reached over HTTP/2 stops reading the
// request stream before Inbound is asked for, a read returns an error, and a handler that
// returns it without asking for Inbound ends the call on the response of the origin.
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

func (c *GRPCCtx) finishOpenCall(err error) (opened bool, cut error) {
	if !c.isOpen() {
		return false, nil
	}
	return true, c.call.finish(err)
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
	k.send = sendBody{PipeReader: outPr, call: k}
	out.Body = &k.send
	// The handler decides which messages go up, so the declared length no longer holds.
	out.ContentLength = -1

	// finish joins both goroutines before the context returns to its pool, so the round trip
	// may read the pooled state.
	k.wg.Go(func() {
		resp, err := h.ForwardRequest(out)
		if err != nil {
			k.upErr = upstreamError{err}
			h.r.p.logf(ctx, slog.LevelDebug, "grpc call failed", h.r.sess, err)
			// Nothing else ends a write into the pipe once the transport gave up on it.
			_ = outPr.CloseWithError(k.upErr)
		} else {
			k.upResp = resp
			k.passthrough = resp.StatusCode != http.StatusOK || !isGRPCContentType(resp.Header.Get("Content-Type"))
			_, status := resp.Header["Grpc-Status"]
			k.trailersOnly = !k.passthrough && status
			// The trailer names are known with the headers, and the values are written by
			// the body read that returns EOF. The names are copied before that read can
			// happen.
			for name := range resp.Trailer {
				k.trailerNames = append(k.trailerNames, name)
			}
		}
		close(k.respCh)
		if k.trailersOnly {
			k.originEnded()
		}
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

// originEnded ends the request stream once the origin has ended its response, as a forwarded
// call does. A read of the client's request stream in progress returns.
func (k *grpcCall) originEnded() {
	k.mu.Lock()
	if k.originDone {
		k.mu.Unlock()
		return
	}
	k.originDone = true
	body := k.outBody
	k.mu.Unlock()
	// The HTTP/1.1 server does not end a read in progress on a Close, it waits for it.
	if c, ok := body.(io.Closer); ok && k.req.ProtoMajor >= 2 {
		_ = c.Close()
	}
}

// originStoppedReading ends the request stream once the transport stops reading it, before
// Inbound is asked for. The origin may have ended its response or reset it, so the call ends
// on the response once the handler returns.
func (k *grpcCall) originStoppedReading() {
	k.mu.Lock()
	if k.outClosed || k.inR != nil {
		k.mu.Unlock()
		return
	}
	k.outClosed, k.sendStopped = true, true
	body := k.outBody
	k.mu.Unlock()
	if c, ok := body.(io.Closer); ok && k.req.ProtoMajor >= 2 {
		_ = c.Close()
	}
}

// endSend ends the request stream toward the origin, cleanly when the outbound source reached
// its end on a message boundary and with err otherwise, which the transport sends as a reset.
func (k *grpcCall) endSend(err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.opened || k.outClosed {
		return
	}
	k.outClosed = true
	if k.outEOF {
		_ = k.outPw.Close()
		return
	}
	k.outCut = true
	_ = k.outPw.CloseWithError(err)
}

// markCut records a failure of the response body of the origin, which resets the client
// stream once the handler returned. A failure that follows a reset sent toward the origin is
// its echo and is not recorded.
func (k *grpcCall) markCut(err error) {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, errCallRefused), errors.Is(err, errMessageTooLarge),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return
	}
	k.mu.Lock()
	if !k.outCut && k.cut == nil {
		k.cut = fmt.Errorf("%w: %w", errBodyCut, err)
	}
	k.mu.Unlock()
}

func (k *grpcCall) outbound(body io.Reader) *MessageReader {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.outR != nil {
		return k.outR
	}

	k.outBody = body
	src := &msgSource{r: body, admit: k.route.admitted, max: k.max}
	mc := &MessageCtx{call: k, inbound: false}
	k.outR = &MessageReader{ctx: k.ctx, read: func() (*MessageCtx, error) {
		k.mu.Lock()
		k.outRead = true
		originDone, sendStopped := k.originDone, k.sendStopped
		k.mu.Unlock()
		if sendStopped && !originDone {
			return nil, errOriginStopped
		}
		// A pump of MergeMessages may still be reading when the relay that follows the
		// handler starts.
		k.outSrcMu.Lock()
		defer k.outSrcMu.Unlock()
		var payload []byte
		var flag byte
		err := io.EOF
		if !originDone {
			payload, flag, err = src.next()
		}
		if err != nil {
			k.mu.Lock()
			switch {
			case k.originDone:
				err = io.EOF
			case k.sendStopped:
				err = errOriginStopped
			}
			k.outEOF = errors.Is(err, io.EOF)
			k.mu.Unlock()
			if errors.Is(err, errCallRefused) {
				k.refuse()
			}
			k.endSend(err)
			return nil, err
		}
		mc.payload, mc.flag = payload, flag
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
			if k.passthrough {
				// serveResponse relays the response, and its trailers are set once it is done.
				k.wg.Wait()
				return nil, io.EOF
			}
			src = &msgSource{r: k.upResp.Body, admit: k.route.admitted, max: k.max}
		}
		k.bodyMu.Lock()
		payload, flag, err := src.next()
		if errors.Is(err, io.EOF) {
			k.inDone = true
		}
		k.bodyMu.Unlock()
		if errors.Is(err, io.EOF) {
			k.originEnded()
		}
		if err != nil {
			if errors.Is(err, errCallRefused) {
				k.refuse()
			}
			k.markCut(err)
			return nil, err
		}
		mc.payload, mc.flag = payload, flag
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

func (k *grpcCall) refuse() { k.end(CodeUnavailable, CodeUnavailable.String()) }

func (k *grpcCall) fail(code Code, msg string) {
	k.end(code, msg)
	k.endSend(errSendCut)
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
func (k *grpcCall) writeMessage(inbound bool, flag byte, b []byte) error {
	k.mu.Lock()
	opened, ch, maxBytes := k.opened, k.respCh, k.max
	originDone, sendStopped := k.originDone, k.sendStopped
	k.mu.Unlock()
	if !opened {
		return errNotOpened
	}
	switch {
	case inbound:
	case originDone:
		return nil
	case sendStopped:
		return errOriginStopped
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
		if k.passthrough {
			return errNotGRPCResponse
		}
		w, mu, buf = k.inPw, &k.inMu, &k.inBuf
	}

	mu.Lock()
	defer mu.Unlock()
	*buf = appendGRPCFrame((*buf)[:0], flag, b)
	_, err := w.Write(*buf)
	if err != nil && !inbound {
		k.mu.Lock()
		originDone, sendStopped = k.originDone, k.sendStopped
		k.mu.Unlock()
		switch {
		case originDone:
			return nil
		case sendStopped:
			return errOriginStopped
		}
	}
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

	if k.passthrough {
		err := writeResponse(k.w, k.req, k.upResp)
		if errors.Is(err, errBodyCut) {
			k.mu.Lock()
			k.cut = err
			k.mu.Unlock()
		} else if err == nil {
			k.originEnded()
		}
		return
	}

	resp := k.upResp
	dst := k.w.Header()
	for name, vv := range resp.Header {
		if k.trailersOnly && isGRPCStatusField(name) {
			continue
		}
		dst[name] = append(vv[:0:0], vv...)
	}
	// The handler decides which messages go down, so the declared length no longer holds.
	dst.Del("Content-Length")
	if len(k.trailerNames) > 0 {
		dst.Set("Trailer", strings.Join(k.trailerNames, ", "))
	}
	var w io.Writer
	var late *lateHeader
	if k.trailersOnly {
		// The status of a trailers-only response is sent once the call ends, in the header
		// section when no message preceded it and in the trailers otherwise.
		late = &lateHeader{w: k.w, rc: http.NewResponseController(k.w), code: resp.StatusCode}
		w = late
	} else {
		k.w.WriteHeader(resp.StatusCode)
		w = flushWriter{w: k.w, rc: http.NewResponseController(k.w)}
	}

	buf := getCopyBuf()
	_, cerr := io.CopyBuffer(w, k.inPr, buf)
	putCopyBuf(buf)
	if cerr != nil {
		// Nothing reads the pipe once the client is gone, and a handler still sending toward
		// it must not block. The handler may still be running and writing the trailers.
		_ = k.inPr.CloseWithError(cerr)
		return
	}

	k.bodyMu.Lock()
	defer k.bodyMu.Unlock()
	prefix, statusKey, msgKey := http.TrailerPrefix, http.TrailerPrefix+"Grpc-Status", http.TrailerPrefix+"Grpc-Message"
	if late != nil && !late.wrote {
		prefix, statusKey, msgKey = "", "Grpc-Status", "Grpc-Message"
		defer k.w.WriteHeader(resp.StatusCode)
	}
	if code, msg, ended := k.status(); ended {
		// The origin's trailers never arrived or no longer apply, and the client reads this
		// status instead.
		dst.Set(statusKey, strconv.FormatUint(uint64(code), 10))
		dst.Set(msgKey, grpcPercentEncode(msg))
		return
	}
	if !k.inDone {
		return
	}
	trailer := resp.Trailer
	if late != nil {
		trailer = resp.Header
	}
	for name, vv := range trailer {
		if late != nil && !isGRPCStatusField(name) {
			continue
		}
		for _, v := range vv {
			dst.Add(prefix+name, v)
		}
	}
}

func isGRPCStatusField(name string) bool {
	return name == "Grpc-Status" || name == "Grpc-Message" || name == "Grpc-Status-Details-Bin"
}

// lateHeader writes the header section of a response at its first write, and flushes every
// write.
type lateHeader struct {
	w     http.ResponseWriter
	rc    *http.ResponseController
	code  int
	wrote bool
}

func (l *lateHeader) Write(b []byte) (int, error) {
	if !l.wrote {
		l.wrote = true
		l.w.WriteHeader(l.code)
	}
	return flushWriter{w: l.w, rc: l.rc}.Write(b)
}

// finish tears the call down once the handler has returned with err. The goroutines are
// joined before the context returns to its pool. It returns an error wrapping errBodyCut when
// the client stream must be reset.
func (k *grpcCall) finish(err error) error {
	if errors.Is(err, errOriginStopped) {
		err = nil
	}
	k.mu.Lock()
	untouched := k.inR == nil && !k.ended
	relay := err == nil && !k.ended && !k.outClosed
	outR := k.outR
	k.mu.Unlock()
	if relay {
		if outR == nil {
			var body io.Reader = http.NoBody
			if k.req.Body != nil {
				body = k.req.Body
			}
			outR = k.outbound(body)
		}
		// The response is relayed meanwhile, so a client still sending does not stall it.
		k.sendWg.Go(func() { k.relayOutbound(outR) })
	} else {
		k.endSend(errSendCut)
	}
	if err == nil && untouched {
		err = k.relayInbound()
	}
	if k.answered() && k.passthrough {
		// The relay runs to its end, as Forward does, before the origin is canceled.
		k.wg.Wait()
	}
	k.mu.Lock()
	handlerEnded := k.ended
	k.mu.Unlock()
	// A pump of MergeMessages may be in a read of the response under bodyMu, and an HTTP/3
	// upstream keeps the response open past a reset of the request stream.
	k.cancel()
	k.bodyMu.Lock()
	done := k.inDone
	k.bodyMu.Unlock()
	switch {
	case err != nil:
		code := statusOf(err)
		k.end(code, code.String())
	case !done:
		k.end(CodeInternal, CodeInternal.String())
	}
	_ = k.inPw.Close()
	if relay {
		// The response has ended, and the client may never end a request stream nothing
		// reads any more.
		k.closeOutBody()
		k.endSend(errSendCut)
		k.sendWg.Wait()
	}
	k.wg.Wait()
	if k.upResp != nil && k.upResp.Body != nil {
		_ = k.upResp.Body.Close()
	}
	k.mu.Lock()
	cut := k.cut
	k.mu.Unlock()
	// A status set before the cut is what the client reads, except on a relayed response
	// where no status can be written.
	if cut != nil && (k.passthrough || !handlerEnded) {
		return cut
	}
	return nil
}

func (k *grpcCall) relayOutbound(r *MessageReader) {
	for {
		m, err := r.read()
		if err != nil {
			return
		}
		if err := m.Forward(); err != nil {
			return
		}
	}
}

func (k *grpcCall) closeOutBody() {
	k.mu.Lock()
	body := k.outBody
	k.mu.Unlock()
	if c, ok := body.(io.Closer); ok {
		_ = c.Close()
	}
}

func (k *grpcCall) answered() bool {
	k.mu.Lock()
	ch := k.respCh
	k.mu.Unlock()
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// relayInbound relays the response unchanged, for a handler that never read the inbound
// reader.
func (k *grpcCall) relayInbound() error {
	if err := k.waitResponse(); err != nil {
		return err
	}
	if k.passthrough {
		return nil
	}
	k.bodyMu.Lock()
	defer k.bodyMu.Unlock()
	_, err := copyStream(k.inPw, k.upResp.Body, nil)
	if err == nil {
		k.inDone = true
		return nil
	}
	if !errors.As(err, new(writeError)) {
		k.markCut(err)
	}
	return err
}

// Fail ends the call with a status. Before [GRPCCtx.Open] it answers with a trailers-only
// response and the origin is not reached. After Open the client reads the status in the
// trailers, after the messages already sent, and the origin is canceled. The first status set
// on an open call is the one the client reads.
//
//	return c.Fail(edge.CodeUnavailable, "upstream flaky")
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
		return grpcStatusResponse(CodeInternal, "handler produced no response"), nil
	}
	return c.resp, nil
}

// statusOf maps a failure of the proxy's own to the status a gRPC client reads. A canceled
// or expired context is reported as such, and so is a reset of the request stream by the
// client, a message over the bound as the resource it exhausted, a refused call or a failure
// before the origin answered as the origin being unavailable, anything else as unknown.
func statusOf(err error) Code {
	_, reset := errors.AsType[requestReset](err)
	_, upstream := errors.AsType[upstreamError](err)
	switch {
	case errors.Is(err, context.Canceled), reset:
		return CodeCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return CodeDeadlineExceeded
	case errors.Is(err, errMessageTooLarge):
		return CodeResourceExhausted
	case errors.Is(err, errCallRefused), upstream:
		return CodeUnavailable
	}
	return CodeUnknown
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
	var flag byte
	if compressed {
		flag = 1
	}
	return appendGRPCFrame(dst, flag, payload)
}

func appendGRPCFrame(dst []byte, flag byte, payload []byte) []byte {
	hdr := [5]byte{flag}
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
	return isGRPCContentType(r.Header.Get("Content-Type"))
}

func isGRPCContentType(ct string) bool {
	const prefix = "application/grpc"
	if len(ct) < len(prefix) || !strings.EqualFold(ct[:len(prefix)], prefix) {
		return false
	}
	// "application/grpc-web" is a different protocol on the same prefix, framed for a
	// browser.
	rest := ct[len(prefix):]
	return rest == "" || rest[0] == ';' || rest[0] == '+'
}
