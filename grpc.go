// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"iter"
	"net/http"

	"strconv"
	"strings"
)

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

// GRPCOption shapes what forwarding a gRPC call does.
type GRPCOption interface{ applyGRPC(*grpcConfig) }

type grpcOptionFunc func(*grpcConfig)

func (f grpcOptionFunc) applyGRPC(c *grpcConfig) { f(c) }

type grpcConfig struct {
	onMessage func(*GRPCMessage) error
}

// OnMessage runs fn for every message of a forwarded call, in both directions. fn decides what
// reaches the far side: [GRPCMessage.Forward] passes it on, [GRPCMessage.Send] replaces it,
// and returning without either drops it from the stream.
//
// The two directions run on their own goroutines, so on a bidirectional call fn is called from
// both at once. The answering direction also runs while the response is written, which is after
// the handler returned.
func OnMessage(fn func(*GRPCMessage) error) GRPCOption {
	return grpcOptionFunc(func(c *grpcConfig) { c.onMessage = fn })
}

// GRPCMessage is one length-prefixed message of a call.
type GRPCMessage struct {
	out        io.Writer
	payload    []byte
	compressed bool
	inbound    bool
}

// Bytes returns the message payload, still encoded as the peers agreed. It is only valid
// until the callback returns.
func (m *GRPCMessage) Bytes() []byte { return m.payload }

// Compressed reports whether the message carries the compression flag, in which case its bytes
// are compressed with whatever grpc-encoding named.
func (m *GRPCMessage) Compressed() bool { return m.compressed }

// Inbound reports whether the message is travelling from the server toward the client.
func (m *GRPCMessage) Inbound() bool { return m.inbound }

// Forward passes the message on unchanged.
func (m *GRPCMessage) Forward() error { return m.Send(m.payload) }

// Send passes b on in place of the message the callback was given. Replacing a compressed
// message keeps its flag, so b must be encoded the same way.
func (m *GRPCMessage) Send(b []byte) error {
	return writeGRPCMessage(m.out, m.compressed, b)
}

// Drop removes the message from the stream. It is what not forwarding already does, spelled
// out so a handler reads as a decision rather than as a missing branch.
func (m *GRPCMessage) Drop() error { return nil }

// GRPCCtx is one gRPC call, handed to a [GRPC] handler. The pattern that selected it is the
// hostname and the full method name, which is what a gRPC client puts in the request path.
//
// A gRPC entry and an HTTP entry can name the same path. The request tells them apart: a call
// whose content type says gRPC takes the gRPC entry, anything else takes the HTTP one.
type GRPCCtx struct {
	http *HTTPCtx
	ctx  context.Context
	resp *http.Response
	err  error
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

// Forward sends the call upstream and streams the answer back.
//
//	return c.Forward(edge.OnMessage(func(m *edge.GRPCMessage) error {
//		count.Add(1)
//		return m.Forward()
//	}))
func (c *GRPCCtx) Forward(opts ...GRPCOption) error {
	cfg := &grpcConfig{}
	for _, o := range opts {
		o.applyGRPC(cfg)
	}

	req := c.http.r.req
	if cfg.onMessage != nil && req != nil && req.Body != nil {
		// The body is rewritten as it is read, so the upstream sees exactly the messages the
		// callback passed on. The rewriting happens on the reader rather than in a goroutine
		// behind a pipe: a body read on its own goroutine also fills the trailer map, which
		// whoever writes the response is reading at the same time.
		req.Body = &grpcPump{src: req.Body, fn: cfg.onMessage}
	}

	resp, err := c.http.Forward()
	if err != nil {
		c.err = err
		return err
	}

	if cfg.onMessage != nil && resp.Body != nil {
		resp.Body = &grpcPump{src: resp.Body, fn: cfg.onMessage, inbound: true}
	}

	c.setResponse(resp)
	return nil
}

// Fail answers the call with a status instead of reaching the server. The answer is a
// trailers-only response, which is what a gRPC server sends when it fails before producing
// any message.
//
//	return c.Fail(edge.Unavailable, "upstream flaky")
func (c *GRPCCtx) Fail(code Code, msg string) error {
	c.setResponse(grpcStatusResponse(code, msg))
	return nil
}

// Respond answers the call with messages and a status, without reaching the server.
func (c *GRPCCtx) Respond(code Code, msg string, messages ...[]byte) error {
	resp := grpcStatusResponse(code, msg)
	if len(messages) > 0 {
		var body []byte
		for _, m := range messages {
			body = appendGRPCMessage(body, false, m)
		}
		resp.Body = io.NopCloser(strings.NewReader(string(body)))
		resp.ContentLength = int64(len(body))
		// A response carrying messages puts the status in the trailers, where a client
		// reading the stream expects it, rather than in the headers.
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

// response returns what the handler decided, or a bare Internal status when it decided
// nothing.
func (c *GRPCCtx) response() (*http.Response, error) {
	if c.err != nil {
		return nil, c.err
	}
	if c.resp == nil {
		return grpcStatusResponse(Internal, "handler produced no response"), nil
	}
	return c.resp, nil
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

// grpcPump reads length-prefixed messages off src as its own reader is read, hands each to the
// callback, and serves what the callback passed on. A message the callback neither forwards nor
// replaces is left out of the stream.
//
// It rewrites on the read path on purpose. Doing it on a goroutine behind a pipe would read the
// body concurrently with whoever writes the response, and reading a body to its end is what
// fills the trailer map that writer reads.
type grpcPump struct {
	src     io.ReadCloser
	err     error
	fn      func(*GRPCMessage) error
	msg     []byte
	out     bytes.Buffer
	hdr     [5]byte
	inbound bool
}

func (p *grpcPump) Read(b []byte) (int, error) {
	for p.out.Len() == 0 {
		if p.err != nil {
			return 0, p.err
		}
		p.err = p.step()
	}
	n, _ := p.out.Read(b)
	return n, nil
}

func (p *grpcPump) step() error {
	if _, err := io.ReadFull(p.src, p.hdr[:]); err != nil {
		// io.EOF here means the stream ended on a message boundary, which is how a call
		// ends. Anything else, a reset or a truncated header, is a failure and must not be
		// handed on as a clean close: the far side would read a complete-looking call that
		// was cut short.
		return err
	}
	length := binary.BigEndian.Uint32(p.hdr[1:])
	if length > maxGRPCMessage {
		return errors.New("edge: gRPC message larger than the proxy will buffer")
	}
	if cap(p.msg) < int(length) {
		p.msg = make([]byte, length)
	}
	p.msg = p.msg[:length]
	if _, err := io.ReadFull(p.src, p.msg); err != nil {
		return err
	}

	m := &GRPCMessage{payload: p.msg, out: &p.out, compressed: p.hdr[0] != 0, inbound: p.inbound}
	return p.fn(m)
}

func (p *grpcPump) Close() error { return p.src.Close() }

func writeGRPCMessage(w io.Writer, compressed bool, payload []byte) error {
	if len(payload) > maxGRPCMessage {
		return errors.New("edge: gRPC message larger than the proxy will write")
	}
	var hdr [5]byte
	if compressed {
		hdr[0] = 1
	}
	//nolint:gosec // bounded by the check above
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// appendGRPCMessage frames payload into dst. The caller owns the bound: only messages the
// handler produced reach it, never a peer's.
func appendGRPCMessage(dst []byte, compressed bool, payload []byte) []byte {
	var hdr [5]byte
	if compressed {
		hdr[0] = 1
	}
	//nolint:gosec // a locally built message, not one read off the wire
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	dst = append(dst, hdr[:]...)
	return append(dst, payload...)
}

// isGRPCRequest reports whether the request carries a gRPC call. It is the precondition of
// [KindGRPC]: the content type says so, never the tree.
func isGRPCRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/grpc") {
		return false
	}
	// "application/grpc-web" is a different protocol on the same prefix, framed for a
	// browser rather than for h2.
	rest := ct[len("application/grpc"):]
	return rest == "" || rest[0] == ';' || rest[0] == '+'
}
