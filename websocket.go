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

// closeTooBig is the RFC 6455 status code 1009, sent for a frame larger than the receiver
// accepts.
const closeTooBig = 1009

// Frame is one WebSocket frame, unmasked. The payload is valid until the next read on the
// reader that returned it.
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

// Payload returns the unmasked payload. It is valid until the next read on the reader that
// returned the frame.
func (f Frame) Payload() []byte { return f.payload }

// Inbound reports whether the origin sent the frame toward the client.
func (f Frame) Inbound() bool { return f.inbound }

// CloseCode returns the status code of a close frame, or zero when the frame is not a close
// frame or has no code.
func (f Frame) CloseCode() uint16 {
	if f.opcode != OpClose || len(f.payload) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(f.payload)
}

// FrameReader returns frames one at a time, from one direction or from both when built by
// [MergeFrames]. It is not safe for concurrent use. The frame it returns is valid until the
// next ReadFrame on the same reader.
type FrameReader struct {
	ctx  context.Context
	read func() (*FrameCtx, error)
}

// ReadFrame returns the next frame and blocks until one arrives. It returns an error once no
// frame will arrive.
func (r *FrameReader) ReadFrame() (*FrameCtx, error) { return r.read() }

// MergeFrames returns a reader over the frames of a and b. When one of them ends with io.EOF
// the other is still read, and the merged reader ends with io.EOF once both have ended. Any
// other error ends it immediately. a and b must not be read elsewhere afterwards.
func MergeFrames(a, b *FrameReader) *FrameReader {
	m := &merged[*FrameCtx]{ctx: a.ctx, a: a.read, b: b.read}
	return &FrameReader{ctx: a.ctx, read: m.read}
}

// FrameCtx is one frame and the decision about it. A frame reaches the far side only through
// [FrameCtx.Forward] or [FrameCtx.Send].
type FrameCtx struct {
	w    *wsWriter
	back *wsWriter
	Frame
}

// Forward relays the frame unchanged.
func (f *FrameCtx) Forward() error { return f.w.write(f.Frame) }

// Send writes frame in the direction of this one.
func (f *FrameCtx) Send(frame Frame) error {
	frame.inbound = f.inbound
	return f.w.write(frame)
}

// Reply writes frame to the peer this one came from. The other peer receives nothing.
func (f *FrameCtx) Reply(frame Frame) error {
	frame.inbound = !f.inbound
	return f.back.write(frame)
}

// Drop discards the frame. It is equivalent to returning without forwarding.
func (f *FrameCtx) Drop() error { return nil }

// NewFrame returns a frame with payload and the FIN bit set.
func NewFrame(op Opcode, payload []byte) Frame {
	return Frame{opcode: op, payload: payload, fin: true}
}

// WebSocketCtx is one WebSocket connection, handed to a [WebSocket] handler once the 101 has
// been exchanged. The handshake is routed as an HTTP request. A connection whose upgrade
// matches no WebSocket entry is served by the HTTP entry that matched, and refused when none
// did.
type WebSocketCtx struct {
	ctx      context.Context
	client   io.ReadWriteCloser
	backend  io.ReadWriteCloser
	p        *Proxy
	sess     *Session
	entry    *entry
	req      *http.Request
	resp     *http.Response
	wOrigin  *wsWriter
	wClient  *wsWriter
	outR     *FrameReader
	inR      *FrameReader
	target   Target
	identity string
	params   []Param
	maxFrame int
	initOnce sync.Once
}

// Context returns a context canceled when the connection ends.
func (c *WebSocketCtx) Context() context.Context { return c.ctx }

// Session returns the session of this connection. An upgrade has a session of its own.
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

// Outbound returns the reader of the frames sent by the client toward the origin.
func (c *WebSocketCtx) Outbound() *FrameReader {
	c.init()
	return c.outR
}

// Inbound returns the reader of the frames sent by the origin toward the client.
func (c *WebSocketCtx) Inbound() *FrameReader {
	c.init()
	return c.inR
}

func (c *WebSocketCtx) init() {
	c.initOnce.Do(func() {
		// The proxy is the server toward the client and the client toward the origin, so the
		// masking rule of RFC 6455 section 5.3 runs one way on each side.
		c.wOrigin = &wsWriter{w: c.backend, mask: true}
		c.wClient = &wsWriter{w: c.client, mask: false}
		c.outR = c.newFrameReader(c.client, c.wOrigin, c.wClient, false)
		c.inR = c.newFrameReader(c.backend, c.wClient, c.wOrigin, true)
	})
}

func (c *WebSocketCtx) newFrameReader(src io.Reader, dst, back *wsWriter, inbound bool) *FrameReader {
	r := &wsReader{r: src, max: c.maxFrame}
	fc := &FrameCtx{w: dst, back: back}
	return &FrameReader{ctx: c.ctx, read: func() (*FrameCtx, error) {
		f, err := r.read()
		if err != nil {
			if errors.Is(err, errFrameTooBig) {
				// Under RFC 6455 section 7.4.1 the peer that refuses the frame sends the
				// close, to the sender of the frame.
				_ = back.write(closeFrame(closeTooBig, "frame too big"))
			}
			return nil, err
		}
		f.inbound = inbound
		fc.Frame = f
		return fc, nil
	}}
}

// Relay relays every frame in both directions until either peer closes. A connection is
// driven either by Relay or by its readers.
func (c *WebSocketCtx) Relay() error {
	c.init()

	var wg sync.WaitGroup
	var upErr, downErr error
	wg.Go(func() {
		upErr = pumpFrames(c.outR)
		_ = c.backend.Close()
	})
	wg.Go(func() {
		downErr = pumpFrames(c.inR)
		_ = c.client.Close()
	})
	wg.Wait()

	return errors.Join(filterCopyErr(upErr), filterCopyErr(downErr))
}

func pumpFrames(r *FrameReader) error {
	for {
		f, err := r.ReadFrame()
		if err != nil {
			return err
		}
		if werr := f.Forward(); werr != nil {
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
		// RFC 6455 section 5.5 limits a control frame to 125 bytes and forbids fragmenting
		// it. A peer that breaks that does not implement WebSocket.
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

// wsWriter writes RFC 6455 frames, masked when the proxy writes as a client. Writes are
// serialized, since both directions of a relay may write to the same side.
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

// isWebSocketUpgrade reports whether the request is a WebSocket handshake, the precondition
// of [KindWebSocket]. Only the HTTP/1.1 handshake is recognized. The RFC 8441 extended
// CONNECT is refused with 501.
func isWebSocketUpgrade(r *http.Request) bool {
	return r != nil && r.ProtoMajor == 1 && r.Method == http.MethodGet &&
		strings.EqualFold(upgradeType(r.Header), "websocket")
}
