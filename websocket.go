// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Opcode is the frame type of a WebSocket frame (RFC 6455 section 5.2).
type Opcode uint8

const (
	// OpContinuation carries the rest of a fragmented message.
	OpContinuation Opcode = 0x0
	// OpText carries UTF-8 payload.
	OpText Opcode = 0x1
	// OpBinary carries arbitrary payload.
	OpBinary Opcode = 0x2
	// OpClose ends the connection.
	OpClose Opcode = 0x8
	// OpPing asks the peer for a Pong.
	OpPing Opcode = 0x9
	// OpPong answers a Ping, or is sent unsolicited as a keepalive.
	OpPong Opcode = 0xA
)

func (o Opcode) String() string {
	switch o {
	case OpContinuation:
		return "continuation"
	case OpText:
		return "text"
	case OpBinary:
		return "binary"
	case OpClose:
		return "close"
	case OpPing:
		return "ping"
	case OpPong:
		return "pong"
	default:
		return "reserved(" + strconv.Itoa(int(o)) + ")"
	}
}

// Control reports whether the opcode is a control frame, which RFC 6455 section 5.5 bounds to
// 125 payload bytes and forbids fragmenting.
func (o Opcode) Control() bool { return o&0x8 != 0 }

// closeTooBig is RFC 6455's 1009, what a peer sends when a frame is larger than it will
// process.
const closeTooBig = 1009

// Frame is one WebSocket frame as it arrived, unmasked. The payload is only valid while the
// callback that received it runs.
type Frame struct {
	payload []byte
	opcode  Opcode
	fin     bool
	rsv     uint8
	inbound bool
}

// Opcode returns the frame type.
func (f Frame) Opcode() Opcode { return f.opcode }

// Fin reports whether this frame completes its message.
func (f Frame) Fin() bool { return f.fin }

// RSV returns the three reserved bits, which an extension negotiated at the handshake gives
// meaning to.
func (f Frame) RSV() uint8 { return f.rsv }

// Payload returns the frame payload, unmasked. It is only valid until the callback returns.
func (f Frame) Payload() []byte { return f.payload }

// Inbound reports whether the frame is travelling from the origin toward the client.
func (f Frame) Inbound() bool { return f.inbound }

// CloseCode returns the status code of a close frame, or zero when the frame is not a close
// or carries no code.
func (f Frame) CloseCode() uint16 {
	if f.opcode != OpClose || len(f.payload) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(f.payload)
}

// WebSocketOption shapes what relaying a WebSocket connection does.
type WebSocketOption interface{ applyWebSocket(*wsConfig) }

type wsOptionFunc func(*wsConfig)

func (f wsOptionFunc) applyWebSocket(c *wsConfig) { f(c) }

type wsConfig struct {
	drop    func(Frame) bool
	onFrame func(*FrameCtx) error
}

// DropFrame swallows every frame fn accepts instead of relaying it. Dropping a Ping is how a
// client's keepalive is tested; dropping a Close leaves the peers to time out.
func DropFrame(fn func(Frame) bool) WebSocketOption {
	return wsOptionFunc(func(c *wsConfig) { c.drop = fn })
}

// OnFrame runs fn for every frame, in both directions. fn decides what happens to it:
// [FrameCtx.Forward] relays it, [FrameCtx.Send] relays something else, and returning without
// either drops it.
func OnFrame(fn func(*FrameCtx) error) WebSocketOption {
	return wsOptionFunc(func(c *wsConfig) { c.onFrame = fn })
}

// FrameCtx is one frame being relayed, and the decision about it.
type FrameCtx struct {
	ctx context.Context
	w   *wsWriter
	Frame
}

// Forward relays the frame unchanged.
func (f *FrameCtx) Forward() error { return f.w.write(f.Frame) }

// Send relays frame in place of the one the callback was given, in the same direction.
func (f *FrameCtx) Send(frame Frame) error {
	frame.inbound = f.inbound
	return f.w.write(frame)
}

// Inject writes an extra frame in the same direction, on top of forwarding.
func (f *FrameCtx) Inject(frame Frame) error {
	frame.inbound = f.inbound
	return f.w.write(frame)
}

// Drop discards the frame. It is what not forwarding already does, spelled out so a handler
// reads as a decision rather than as a missing branch.
func (f *FrameCtx) Drop() error { return nil }

// NewFrame returns a frame carrying payload, marked as completing its message.
func NewFrame(op Opcode, payload []byte) Frame {
	return Frame{opcode: op, payload: payload, fin: true}
}

// WebSocketCtx is one WebSocket connection, handed to a [WebSocket] handler once the 101 has
// been exchanged. Past that point the connection is no longer HTTP, so the unit is the frame.
//
// The handshake itself is an HTTP request and is routed as one. A connection whose upgrade
// matches no WebSocket entry is not relayed blind: the request is served by whatever HTTP
// entry matched it, and with none it is refused.
type WebSocketCtx struct {
	ctx      context.Context
	client   io.ReadWriteCloser
	backend  io.ReadWriteCloser
	p        *Proxy
	sess     *Session
	entry    *entry
	req      *http.Request
	resp     *http.Response
	target   Target
	identity string
	params   []Param
	maxFrame int
}

// Context returns a context canceled when the connection ends.
func (c *WebSocketCtx) Context() context.Context { return c.ctx }

// Session returns the session of this connection. An upgrade gets a session of its own, since
// it routes on the request that established it rather than on the connection's authority.
func (c *WebSocketCtx) Session() *Session { return c.sess }

// Target returns the authority the connection was established with.
func (c *WebSocketCtx) Target() Target { return c.target }

// Identity returns what the configured authenticator reported for the connection that carried
// the upgrade, or an empty string when none did.
func (c *WebSocketCtx) Identity() string { return c.identity }

// Request returns the request that upgraded the connection.
func (c *WebSocketCtx) Request() *http.Request { return c.req }

// Response returns the 101 the origin answered with.
func (c *WebSocketCtx) Response() *http.Response { return c.resp }

// Subprotocol returns the subprotocol the origin selected, or an empty string.
func (c *WebSocketCtx) Subprotocol() string {
	if c.resp == nil {
		return ""
	}
	return c.resp.Header.Get("Sec-Websocket-Protocol")
}

// Pattern returns the pattern of the matched entry.
func (c *WebSocketCtx) Pattern() string {
	if c.entry == nil {
		return ""
	}
	return c.entry.pattern.str
}

// Entry returns the matched entry.
func (c *WebSocketCtx) Entry() Entry[WebSocket] { return Entry[WebSocket]{e: c.entry} }

// Params returns an iterator over the parameters matched in the pattern.
func (c *WebSocketCtx) Params() iter.Seq[Param] { return slices.Values(c.params) }

// Param returns the value matched for the named parameter, or an empty string.
func (c *WebSocketCtx) Param(name string) string {
	for _, p := range c.params {
		if p.Key == name {
			return p.Value
		}
	}
	return ""
}

// Proxy returns the [Proxy] serving this connection.
func (c *WebSocketCtx) Proxy() *Proxy { return c.p }

// Relay carries the frames both ways until either peer closes. Without options every frame is
// forwarded unchanged, which is what an origin would have seen without the proxy.
func (c *WebSocketCtx) Relay(opts ...WebSocketOption) error {
	cfg := &wsConfig{}
	for _, o := range opts {
		o.applyWebSocket(cfg)
	}

	// The proxy is the server toward the client and the client toward the origin, so the
	// masking rule of RFC 6455 section 5.3 runs one way on each side.
	toOrigin := &wsWriter{w: c.backend, mask: true}
	toClient := &wsWriter{w: c.client, mask: false}

	var wg sync.WaitGroup
	var upErr, downErr error
	wg.Go(func() {
		upErr = c.pump(cfg, c.client, toOrigin, toClient, false)
		_ = c.backend.Close()
	})
	wg.Go(func() {
		downErr = c.pump(cfg, c.backend, toClient, toOrigin, true)
		_ = c.client.Close()
	})
	wg.Wait()

	return errors.Join(filterCopyErr(upErr), filterCopyErr(downErr))
}

// pump reads frames off src and hands each to the configured callbacks, which decide what
// reaches dst. back is the writer answering the peer src reads from.
func (c *WebSocketCtx) pump(cfg *wsConfig, src io.Reader, dst, back *wsWriter, inbound bool) error {
	r := &wsReader{r: src, max: c.maxFrame}
	for {
		f, err := r.read()
		if err != nil {
			if errors.Is(err, errFrameTooBig) {
				// RFC 6455 section 7.4.1: the peer that will not process the frame is the
				// one that says so, and it says it to whoever sent it.
				_ = back.write(closeFrame(closeTooBig, "frame too big"))
			}
			return err
		}
		f.inbound = inbound

		if cfg.drop != nil && cfg.drop(f) {
			continue
		}
		if cfg.onFrame != nil {
			fc := &FrameCtx{Frame: f, w: dst, ctx: c.ctx}
			if herr := cfg.onFrame(fc); herr != nil {
				return herr
			}
			continue
		}
		if werr := dst.write(f); werr != nil {
			return werr
		}
	}
}

func closeFrame(code uint16, reason string) Frame {
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload, code)
	copy(payload[2:], reason)
	return Frame{opcode: OpClose, payload: payload, fin: true}
}

var errFrameTooBig = errors.New("edge: websocket frame larger than the configured limit")

// wsReader reads RFC 6455 frames off a stream, unmasking what the client masked.
type wsReader struct {
	r   io.Reader
	buf []byte
	max int
}

func (r *wsReader) read() (Frame, error) {
	var head [2]byte
	if _, err := io.ReadFull(r.r, head[:]); err != nil {
		return Frame{}, err
	}

	f := Frame{
		fin:    head[0]&0x80 != 0,
		rsv:    (head[0] >> 4) & 0x7,
		opcode: Opcode(head[0] & 0x0f),
	}
	masked := head[1]&0x80 != 0
	length := uint64(head[1] & 0x7f)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r.r, ext[:]); err != nil {
			return Frame{}, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r.r, ext[:]); err != nil {
			return Frame{}, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}

	if f.opcode.Control() {
		// RFC 6455 section 5.5: a control frame carries at most 125 bytes and is never
		// fragmented. A peer breaking that is not speaking WebSocket.
		if length > 125 || !f.fin {
			return Frame{}, fmt.Errorf("edge: malformed websocket control frame")
		}
	}
	if r.max > 0 && length > uint64(r.max) {
		return Frame{}, errFrameTooBig
	}

	var key [4]byte
	if masked {
		if _, err := io.ReadFull(r.r, key[:]); err != nil {
			return Frame{}, err
		}
	}

	if uint64(cap(r.buf)) < length {
		r.buf = make([]byte, length)
	}
	r.buf = r.buf[:length]
	if _, err := io.ReadFull(r.r, r.buf); err != nil {
		return Frame{}, err
	}
	if masked {
		for i := range r.buf {
			r.buf[i] ^= key[i%4]
		}
	}
	f.payload = r.buf
	return f, nil
}

// wsWriter writes RFC 6455 frames, masking them when it speaks as a client. Writes are
// serialized: both directions of a relay may inject into the same side.
type wsWriter struct {
	w    io.Writer
	mu   sync.Mutex
	hdr  [14]byte
	mask bool
}

func (w *wsWriter) write(f Frame) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	n := 2
	w.hdr[0] = byte(f.opcode) | (f.rsv << 4)
	if f.fin {
		w.hdr[0] |= 0x80
	}

	length := len(f.payload)
	switch {
	case length < 126:
		w.hdr[1] = byte(length)
	case length <= 0xffff:
		w.hdr[1] = 126
		binary.BigEndian.PutUint16(w.hdr[2:], uint16(length))
		n += 2
	default:
		w.hdr[1] = 127
		binary.BigEndian.PutUint64(w.hdr[2:], uint64(length))
		n += 8
	}

	var key [4]byte
	if w.mask {
		w.hdr[1] |= 0x80
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		copy(w.hdr[n:], key[:])
		n += 4
	}

	if _, err := w.w.Write(w.hdr[:n]); err != nil {
		return err
	}
	if length == 0 {
		return nil
	}
	if !w.mask {
		_, err := w.w.Write(f.payload)
		return err
	}

	// Masking rewrites the payload, and the buffer belongs to the reader that produced it,
	// so the transformation goes to a copy.
	out := make([]byte, length)
	for i := range out {
		out[i] = f.payload[i] ^ key[i%4]
	}
	_, err := w.w.Write(out)
	return err
}

// isWebSocketUpgrade reports whether the request is a WebSocket handshake. It is the
// precondition of [KindWebSocket]: the traffic says so, never the tree.
//
// Only the HTTP/1.1 handshake is recognized. RFC 8441 carries WebSocket over an extended
// CONNECT stream instead, which the proxy refuses with 501 rather than serve half way.
func isWebSocketUpgrade(r *http.Request) bool {
	return r != nil && r.ProtoMajor == 1 && r.Method == http.MethodGet &&
		strings.EqualFold(upgradeType(r.Header), "websocket")
}
