// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"iter"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
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

// The RFC 6455 status codes edge sends when a frame breaks the protocol.
const (
	closeGoingAway     = 1001
	closeProtocolError = 1002
	closeTooBig        = 1009
)

// wsCloseTimeout bounds the wait for the rest of the closing handshake once a peer has sent
// its Close and ended its stream, or once edge waits for the origin to close.
const wsCloseTimeout = 5 * time.Second

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
	m := &merged[*FrameCtx]{ctx: a.ctx, a: a.read, b: b.read, apart: a.ctx != b.ctx}
	return &FrameReader{ctx: a.ctx, read: m.read}
}

// FrameCtx is one frame and the decision about it. A frame reaches the far side only through
// [FrameCtx.Forward] or [FrameCtx.Send].
type FrameCtx struct {
	w    *wsHop
	back *wsHop
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
	cancel   context.CancelCauseFunc
	p        *Proxy
	sess     *Session
	entry    *entry
	req      *http.Request
	resp     *http.Response
	outR     *FrameReader
	inR      *FrameReader
	timer    *time.Timer
	target   Target
	identity string
	params   []Param
	toClient wsHop
	toOrigin wsHop
	maxFrame int
	mu       sync.Mutex
	initOnce sync.Once
	done     bool
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

// setHops sets the two connections of c. The proxy is the server toward the client and the
// client toward the origin, so the masking rule of RFC 6455 section 5.3 runs one way on each.
func (c *WebSocketCtx) setHops(client net.Conn, clientR io.Reader, backend io.ReadWriteCloser) {
	c.toClient.c, c.toClient.peer, c.toClient.server = c, &c.toOrigin, true
	c.toClient.conn, c.toClient.r, c.toClient.w.w = client, clientR, client
	c.toOrigin.c, c.toOrigin.peer = c, &c.toClient
	c.toOrigin.conn, c.toOrigin.r, c.toOrigin.w.w, c.toOrigin.w.mask = pipeConn{ReadWriteCloser: backend}, backend, backend, true
}

func (c *WebSocketCtx) init() {
	c.initOnce.Do(func() {
		c.outR = c.newFrameReader(&c.toClient, false)
		c.inR = c.newFrameReader(&c.toOrigin, true)
	})
}

func (c *WebSocketCtx) newFrameReader(src *wsHop, inbound bool) *FrameReader {
	r := &wsReader{r: src.r, max: c.maxFrame, masked: src.server}
	fc := &FrameCtx{w: src.peer, back: src}
	return &FrameReader{ctx: c.ctx, read: func() (*FrameCtx, error) {
		f, err := r.read()
		if err != nil {
			return nil, src.readEnded(err)
		}
		if f.opcode == OpClose {
			src.closeCrossed(&src.recvClose)
		}
		f.inbound = inbound
		fc.Frame = f
		return fc, nil
	}}
}

// Relay relays every frame in both directions until the connection ends. A connection is
// driven either by Relay or by its readers.
func (c *WebSocketCtx) Relay() error {
	c.init()

	var wg sync.WaitGroup
	var upErr, downErr error
	wg.Go(func() { upErr = pumpFrames(c.outR) })
	wg.Go(func() { downErr = pumpFrames(c.inR) })
	wg.Wait()

	return errors.Join(filterFrameErr(upErr), filterFrameErr(downErr))
}

// filterFrameErr drops the errors that are the normal end of a relay, a frame the peer sent
// after a Close included.
func filterFrameErr(err error) error {
	if errors.Is(err, errAfterClose) {
		return nil
	}
	return filterCopyErr(err)
}

func (c *WebSocketCtx) waitLocked() {
	if c.timer == nil && !c.done {
		c.timer = time.AfterFunc(wsCloseTimeout, c.expire)
	}
}

func (c *WebSocketCtx) expire() {
	c.mu.Lock()
	client, origin := c.toClient.endLocked(hopClose), c.toOrigin.endLocked(hopClose)
	c.cancelIfEndedLocked()
	c.mu.Unlock()
	c.toClient.finish(client)
	c.toOrigin.finish(origin)
}

// stop keeps the close timer from outliving the handler.
func (c *WebSocketCtx) stop() {
	c.mu.Lock()
	c.done = true
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
}

// hopEnd is how edge ends the connection of a hop.
type hopEnd uint8

const (
	hopOpen hopEnd = iota
	hopClose
	hopAbort
)

// wsHop is one connection of a WebSocket, toward the client with edge as its server or toward
// the origin with edge as its client, and where the closing handshake stands on it. The state
// is guarded by the mutex of c.
type wsHop struct {
	conn      net.Conn
	r         io.Reader
	c         *WebSocketCtx
	peer      *wsHop
	w         wsWriter
	server    bool
	recvClose bool
	sentClose bool
	eof       bool
	ended     bool
}

func (h *wsHop) write(f Frame) error {
	if err := h.w.write(f); err != nil {
		if !errors.Is(err, errAfterClose) {
			h.writeFailed()
		}
		return err
	}
	if f.opcode == OpClose {
		h.closeCrossed(&h.sentClose)
	}
	return nil
}

// closeCrossed records a Close received from h or sent to h, flag being one of the two.
func (h *wsHop) closeCrossed(flag *bool) {
	h.c.mu.Lock()
	*flag = true
	end := h.settleLocked()
	h.c.cancelIfEndedLocked()
	h.c.mu.Unlock()
	h.finish(end)
}

// settleLocked ends h once both Close frames crossed it. RFC 6455 section 7.1.1 has the
// server close the TCP connection first, so toward the origin edge waits for it, bounded.
func (h *wsHop) settleLocked() hopEnd {
	if !h.recvClose {
		return hopOpen
	}
	if !h.sentClose {
		if h.eof {
			h.c.waitLocked()
		}
		return hopOpen
	}
	if h.server || h.eof {
		return h.endLocked(hopClose)
	}
	h.c.waitLocked()
	return hopOpen
}

// readEnded handles the error that ended a read of h and returns the one the reader returns.
func (h *wsHop) readEnded(err error) error {
	c := h.c
	if fe, ok := errors.AsType[*frameError](err); ok {
		// Under RFC 6455 section 7.1.7 a Close precedes the end, and the other peer reads 1001
		// because edge leaves it.
		c.mu.Lock()
		toSelf, toPeer := !h.sentClose && !h.ended, !h.peer.sentClose && !h.peer.ended
		h.sentClose, h.peer.sentClose = true, true
		self, peer := h.endLocked(hopClose), h.peer.endLocked(hopClose)
		c.cancelIfEndedLocked()
		c.mu.Unlock()
		if toSelf {
			h.writeClose(fe.code)
		}
		if toPeer {
			h.peer.writeClose(closeGoingAway)
		}
		h.finish(self)
		h.peer.finish(peer)
		return err
	}

	var self, peer hopEnd
	c.mu.Lock()
	switch {
	case h.ended:
		err = io.EOF
	case errors.Is(err, io.EOF):
		h.eof = true
		if h.recvClose {
			self = h.settleLocked()
		} else {
			self, peer = h.endLocked(hopClose), h.peer.endLocked(hopClose)
		}
	case errors.Is(err, net.ErrClosed):
		// A connection closed on this side, by a Session Close, ends the other one cleanly.
		self, peer = h.endLocked(hopClose), h.peer.endLocked(hopClose)
	default:
		self, peer = h.endLocked(hopClose), h.peer.endLocked(hopAbort)
	}
	c.cancelIfEndedLocked()
	c.mu.Unlock()
	h.finish(self)
	h.peer.finish(peer)
	return err
}

// writeClose writes a Close of edge's own, bounded so a peer that stopped reading cannot keep
// the reader of the other hop waiting. The connection toward the origin has no deadline, so
// it is closed once the bound passes.
func (h *wsHop) writeClose(code uint16) {
	_ = h.conn.SetWriteDeadline(time.Now().Add(wsCloseTimeout))
	t := time.AfterFunc(wsCloseTimeout, func() { _ = h.conn.Close() })
	_ = h.w.write(closeFrame(code))
	t.Stop()
	_ = h.conn.SetWriteDeadline(time.Time{})
}

func (h *wsHop) writeFailed() {
	h.c.mu.Lock()
	var self, peer hopEnd
	if !h.ended {
		how := hopAbort
		if h.peer.recvClose && h.peer.sentClose {
			how = hopClose
		}
		self, peer = h.endLocked(hopClose), h.peer.endLocked(how)
	}
	h.c.cancelIfEndedLocked()
	h.c.mu.Unlock()
	h.finish(self)
	h.peer.finish(peer)
}

func (h *wsHop) endLocked(how hopEnd) hopEnd {
	if h.ended {
		return hopOpen
	}
	h.ended = true
	return how
}

func (c *WebSocketCtx) cancelIfEndedLocked() {
	if c.toClient.ended && c.toOrigin.ended {
		c.cancel(errSourcesEnded)
	}
}

func (h *wsHop) finish(how hopEnd) {
	switch how {
	case hopClose:
		_ = h.conn.Close()
	case hopAbort:
		abort(h.conn)
	}
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

func closeFrame(code uint16) Frame {
	return Frame{opcode: OpClose, payload: binary.BigEndian.AppendUint16(nil, code), fin: true}
}

// frameError is a frame that breaks RFC 6455, and code is the status of the Close edge sends
// to its sender.
type frameError struct {
	msg  string
	code uint16
}

func (e *frameError) Error() string { return e.msg }

var errAfterClose = errors.New("edge: websocket frame written after a Close")

var (
	errFrameTooBig  = &frameError{msg: "edge: websocket frame larger than the configured limit", code: closeTooBig}
	errFrameMask    = &frameError{msg: "edge: websocket frame masked against its direction", code: closeProtocolError}
	errFrameLength  = &frameError{msg: "edge: websocket frame length with its most significant bit set", code: closeProtocolError}
	errFrameControl = &frameError{msg: "edge: malformed websocket control frame", code: closeProtocolError}
)

// wsReader reads RFC 6455 frames off a stream, unmasking what the client masked. masked is
// whether the frames must be masked, which RFC 6455 section 5.1 requires from a client only.
type wsReader struct {
	r      io.Reader
	buf    []byte
	max    int
	masked bool
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

	// The key is read before the checks, so a refused header leaves nothing unread and the
	// close reaches the peer as a FIN.
	var key [4]byte
	if masked {
		if _, err := io.ReadFull(r.r, key[:]); err != nil {
			return Frame{}, err
		}
	}

	if masked != r.masked {
		return Frame{}, errFrameMask
	}
	if length>>63 != 0 {
		return Frame{}, errFrameLength
	}
	// RFC 6455 section 5.5 limits a control frame to 125 bytes and forbids fragmenting it.
	if f.opcode.Control() && (length > 125 || !f.fin) {
		return Frame{}, errFrameControl
	}
	if r.max > 0 && length > uint64(r.max) {
		return Frame{}, errFrameTooBig
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
	w      io.Writer
	mu     sync.Mutex
	hdr    [14]byte
	mask   bool
	closed bool
}

func (w *wsWriter) write(f Frame) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// RFC 6455 section 5.5.1 allows no data frame after a Close, and edge sends nothing at all.
	if w.closed {
		return errAfterClose
	}
	w.closed = f.opcode == OpClose

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
	return r != nil && r.ProtoMajor == 1 && r.ProtoMinor >= 1 && r.Method == http.MethodGet &&
		strings.EqualFold(upgradeType(r.Header), "websocket")
}
