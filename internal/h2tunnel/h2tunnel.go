// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

// Package h2tunnel speaks the client side of HTTP/2 for CONNECT streams, each served as a
// net.Conn. It exists because the HTTP/2 client of the standard library refuses the
// :protocol pseudo-header, so an extended CONNECT, RFC 8441, cannot be sent through it.
//
// The connection carries nothing but CONNECT streams. It does not accept pushes, does not
// send priorities, and has no request body semantics beyond the bytes of a stream.
package h2tunnel

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	// window is the receive window advertised for every stream, and connWindow the one the
	// connection is raised to, so that a stream nothing reads starves no other.
	window     = 1 << 20
	connWindow = 16 << 20
	// defaultWindow is the initial window of RFC 9113 section 6.9.2, before any SETTINGS.
	defaultWindow = 65535
	// maxHeaderBytes bounds the header list of a response, and of a request before the
	// encoder.
	maxHeaderBytes = 64 << 10
	// hpackTableSize is the decoding table size of RFC 9113 section 6.5.2.
	hpackTableSize = 4096
	// writeTimeout bounds one write on the socket. A peer that reads nothing for that long
	// ends the connection.
	writeTimeout = 30 * time.Second
	// closeTimeout bounds the GOAWAY a close sends, and the write it may have to wait out.
	closeTimeout = time.Second
	// chunkBacklog is how many chunks a stream buffers before the small payloads that follow
	// join one chunk of chunkMin or more, so a peer sending tiny frames to a reader that
	// fell behind costs no chunk per frame, and a reader that keeps up copies nothing.
	chunkBacklog = 8
	chunkMin     = 4 << 10
	// maxDataFrame bounds a DATA frame the connection sends, whatever the peer allows.
	maxDataFrame = 256 << 10
	// outBound is how far serve encodes ahead of the write goroutine. Past it, DATA waits.
	outBound = 64 << 10
	// maxControlFrames bounds the acks a peer provokes while the socket takes none. The
	// connection ends past it.
	maxControlFrames = 1024
	// creditRefresh is the least a WINDOW_UPDATE grants while the reader keeps up.
	// creditFlush is how much a reader consumes before telling serve, and creditIdle the
	// least it grants back when it stops to wait.
	creditRefresh = window / 2
	creditFlush   = 32 << 10
	creditIdle    = 4 << 10
	// maxStreamID is the last stream ID a client may use, RFC 9113 section 5.1.1.
	maxStreamID = 1<<31 - 1
	// msgQueue bounds the messages waiting for serve, and frameQueue the frames read ahead
	// of it.
	msgQueue   = 128
	frameQueue = 16
)

var (
	// ErrGoAway is returned by Open once the peer sent GOAWAY. The connection still serves
	// the streams it had, and a new one goes on another connection.
	ErrGoAway = errors.New("h2tunnel: the peer is going away")
	// ErrExtendedConnect is returned by Open when the peer did not enable the extended
	// CONNECT protocol, RFC 8441 section 3.
	ErrExtendedConnect = errors.New("h2tunnel: the peer does not support extended CONNECT")
	errTooManyStreams  = errors.New("h2tunnel: the peer's concurrent stream limit is reached")
	errInvalidHeader   = errors.New("h2tunnel: invalid header field")
	errNoAuthority     = errors.New("h2tunnel: a CONNECT needs an authority")
	errNoTarget        = errors.New("h2tunnel: an extended CONNECT needs a scheme and a path")
	errStreamClosed    = errors.New("h2tunnel: stream closed")
	errHeadersTooLarge = errors.New("h2tunnel: request headers too large")
	errKeepAlive       = errors.New("h2tunnel: the peer stopped answering")
	errControlFlood    = errors.New("h2tunnel: too many control frames owed to a peer that reads none")
)

// Request describes one CONNECT. Protocol is the :protocol of an extended CONNECT and empty
// for a plain one, which carries Authority alone.
type Request struct {
	Header    http.Header
	Protocol  string
	Scheme    string
	Authority string
	Path      string
}

// Response is what the peer answered a CONNECT with, headers only.
type Response struct {
	Header     http.Header
	StatusCode int
}

// Conn is a client HTTP/2 connection carrying CONNECT streams. Its state and that of its
// streams belong to one goroutine, serve. readFrames hands it every frame and waits for it
// to be processed, writeLoop takes the bytes it encoded and reports once they are on the
// socket, and every caller sends it a message. serve never waits on the socket.
type Conn struct {
	lastRead   time.Time
	pingSentAt time.Time
	nc         net.Conn
	err        error
	fr         *http2.Framer
	// out is what the framer encodes into, and spare the buffer the write goroutine has or
	// had. The two are swapped at every handoff.
	outW       outWriter
	out, spare *bytes.Buffer
	enc        *hpack.Encoder

	streams map[uint32]*Stream

	frames       chan frame
	readMore     chan struct{}
	msgs         chan msg
	writeCh      chan *bytes.Buffer
	wroteCh      chan error
	done         chan struct{}
	ended        chan struct{}
	settingsSeen chan struct{}
	keepTimer    *time.Timer
	// ready lists the streams with a write pending, served round robin from rr.
	ready   []*Stream
	control []control
	// creditDue lists the streams with a WINDOW_UPDATE due.
	creditDue []*Stream

	encBuf bytes.Buffer

	recv      inflow
	keepAlive time.Duration

	sendWindow    int64
	initialWindow int64
	maxStreams    int64
	maxHeaderList int64
	rr            int
	queuedControl int
	maxFrameSize  uint32
	nextID        uint32

	canOpen         atomic.Bool
	writing         bool
	sawSettings     bool
	pingSent        bool
	extendedConnect bool
	// retired refuses new streams, the peer sent GOAWAY or the owner retired the
	// connection, and the connection ends with its last stream.
	retired bool
}

type outWriter struct{ buf *bytes.Buffer }

func (w *outWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }

// frame is one frame read. A DATA frame is copied out of the framer, which reuses its
// buffer and its DATA frame, and a frame that still references the buffer is gated, the
// next read waiting for serve to be done with it.
type frame struct {
	f      http2.Frame
	err    error
	data   []byte
	id     uint32
	length uint32
	isData bool
	end    bool
	gated  bool
}

type msgKind uint8

const (
	msgOpen msgKind = iota
	msgWrite
	msgCloseWrite
	msgCloseStream
	msgRead
	msgWriteDeadline
	msgWriteTimeout
	msgRetire
	msgClose
	msgFunc
)

type msg struct {
	t     time.Time
	s     *Stream
	open  *openReq
	fn    func()
	data  []byte
	n     int64
	code  http2.ErrCode
	kind  msgKind
	grant grant
}

// grant says when the credit of a read is granted back to the peer.
type grant uint8

const (
	// grantBatch waits for creditRefresh.
	grantBatch grant = iota
	// grantLow waits for creditRefresh unless the peer has less window left than is owed,
	// the reader having stopped to wait.
	grantLow
	// grantAll grants at once, the stream having ended.
	grantAll
)

type openReq struct {
	reply chan openReply
	req   Request
}

type openReply struct {
	resp *Response
	err  error
}

type controlKind uint8

const (
	ctlHeaders controlKind = iota
	ctlSettingsAck
	ctlPingAck
	ctlPing
	ctlReset
)

type control struct {
	s    *Stream
	req  *Request
	ping [8]byte
	id   uint32
	code http2.ErrCode
	kind controlKind
}

// inflow accounts a receive window, avail being what the peer may still send, unsent what
// was consumed and not yet granted back, and due what the next WINDOW_UPDATE grants.
type inflow struct {
	avail  int64
	unsent int64
	due    int64
}

func (f *inflow) take(n int64) bool {
	if n > f.avail {
		return false
	}
	f.avail -= n
	return true
}

// add records n bytes consumed, and makes them due to the peer unless g says to wait.
func (f *inflow) add(n int64, g grant) {
	f.unsent += n
	switch g {
	case grantBatch:
		if f.unsent < creditRefresh {
			return
		}
	case grantLow:
		if f.unsent < creditRefresh && f.unsent < f.avail {
			return
		}
	}
	f.avail += f.unsent
	f.due += f.unsent
	f.unsent = 0
}

// Client starts an HTTP/2 connection on nc, the client preface and SETTINGS written, and
// reads it until it ends. nc is closed when the connection ends. With a keepAlive, a PING
// goes out after that much silence from the peer, and the connection ends when the ack
// takes longer than that.
func Client(nc net.Conn, keepAlive time.Duration) (*Conn, error) {
	c := &Conn{
		nc:            nc,
		out:           new(bytes.Buffer),
		spare:         new(bytes.Buffer),
		streams:       make(map[uint32]*Stream),
		frames:        make(chan frame, frameQueue),
		readMore:      make(chan struct{}, 1),
		msgs:          make(chan msg, msgQueue),
		writeCh:       make(chan *bytes.Buffer, 1),
		wroteCh:       make(chan error, 1),
		done:          make(chan struct{}),
		ended:         make(chan struct{}),
		settingsSeen:  make(chan struct{}),
		keepAlive:     keepAlive,
		sendWindow:    defaultWindow,
		recv:          inflow{avail: connWindow},
		initialWindow: defaultWindow,
		maxStreams:    1<<32 - 1,
		maxHeaderList: 1<<32 - 1,
		maxFrameSize:  16384,
		nextID:        1,
	}
	c.outW.buf = c.out
	c.fr = http2.NewFramer(&c.outW, bufio.NewReader(nc))
	c.fr.ReadMetaHeaders = hpack.NewDecoder(hpackTableSize, nil)
	c.fr.MaxHeaderListSize = maxHeaderBytes
	// Nothing raises SETTINGS_MAX_FRAME_SIZE, so that is the largest frame the peer may send.
	c.fr.SetMaxReadFrameSize(16384)
	c.enc = hpack.NewEncoder(&c.encBuf)

	c.out.WriteString(http2.ClientPreface)
	if err := c.fr.WriteSettings(
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: window},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: maxHeaderBytes},
	); err != nil {
		_ = nc.Close()
		return nil, err
	}
	if err := c.fr.WriteWindowUpdate(0, connWindow-defaultWindow); err != nil {
		_ = nc.Close()
		return nil, err
	}
	_ = nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := nc.Write(c.out.Bytes()); err != nil {
		_ = nc.Close()
		return nil, err
	}
	c.out.Reset()
	c.lastRead = time.Now()
	c.canOpen.Store(true)
	go c.writeLoop()
	go c.readFrames()
	go c.serve()
	return c, nil
}

// readFrames reads the frames and hands them to serve. The framer reuses its buffer and its
// DATA frame, so DATA is copied out and a frame still referencing the buffer waits for
// serve to be done with it.
func (c *Conn) readFrames() {
	for {
		f, err := c.fr.ReadFrame()
		fr := frame{err: err}
		switch f := f.(type) {
		case nil:
		case *http2.DataFrame:
			fr.isData, fr.id, fr.length, fr.end = true, f.StreamID, f.Length, f.StreamEnded()
			if d := f.Data(); len(d) > 0 {
				fr.data = bytes.Clone(d)
			}
		case *http2.MetaHeadersFrame, *http2.WindowUpdateFrame, *http2.RSTStreamFrame, *http2.PingFrame, *http2.PriorityFrame:
			// Nothing of these references the buffer once read.
			fr.f = f
		default:
			fr.f, fr.gated = f, true
		}
		select {
		case c.frames <- fr:
		case <-c.done:
			return
		}
		if err != nil {
			var se http2.StreamError
			if !errors.As(err, &se) {
				return
			}
		}
		if !fr.gated {
			continue
		}
		select {
		case <-c.readMore:
		case <-c.done:
			return
		}
	}
}

// writeLoop writes what serve hands it. The socket's write deadline is serve's alone, so
// the one a shutdown sets is never raised back.
func (c *Conn) writeLoop() {
	for buf := range c.writeCh {
		_, err := c.nc.Write(buf.Bytes())
		c.wroteCh <- err
	}
}

func (c *Conn) serve() {
	var timerC <-chan time.Time
	if c.keepAlive > 0 {
		c.keepTimer = time.NewTimer(c.keepAlive)
		timerC = c.keepTimer.C
	}
	for c.err == nil {
		select {
		case fr := <-c.frames:
			c.onFrame(fr)
		case err := <-c.wroteCh:
			c.wrote(err)
		case m := <-c.msgs:
			c.onMsg(m)
		case <-timerC:
			c.onKeepAlive()
		}
		if c.err == nil {
			c.pump()
			c.refreshCanOpen()
		}
	}
}

func (c *Conn) wrote(err error) {
	c.writing = false
	c.spare.Reset()
	if err != nil {
		c.shutdown(err, false, 0)
	}
}

// send hands m to serve, and reports false once the connection ended.
func (c *Conn) send(m msg) bool {
	select {
	case c.msgs <- m:
		return true
	case <-c.done:
		return false
	}
}

func (c *Conn) onMsg(m msg) {
	s := m.s
	switch m.kind {
	case msgOpen:
		c.open(s, m.open)
	case msgWrite:
		switch {
		case s.gone:
			s.reply(0, s.err)
		case s.localEnd || s.pending.active:
			s.reply(0, errStreamClosed)
		case s.writeExpired():
			s.reply(0, os.ErrDeadlineExceeded)
		case len(m.data) == 0:
			s.reply(0, nil)
		default:
			s.pending = writeReq{data: m.data, active: true}
			c.markReady(s)
		}
	case msgCloseWrite:
		switch {
		case s.gone:
			s.reply(0, s.err)
		case s.localEnd || s.pending.active:
			s.reply(0, errStreamClosed)
		default:
			s.pending = writeReq{endStream: true, active: true}
			c.markReady(s)
		}
	case msgCloseStream:
		if !s.gone {
			c.closeStream(s, errStreamClosed, m.code)
		}
	case msgRead:
		c.credit(s, m.n, m.grant)
	case msgWriteDeadline:
		if s.gone {
			return
		}
		if s.writeTimer != nil {
			s.writeTimer.Stop()
			s.writeTimer = nil
		}
		s.writeDeadline = m.t
		if m.t.IsZero() {
			return
		}
		if d := time.Until(m.t); d > 0 {
			s.writeTimer = time.AfterFunc(d, func() { c.send(msg{kind: msgWriteTimeout, s: s}) })
			return
		}
		c.expireWrite(s)
	case msgWriteTimeout:
		if !s.gone && s.writeExpired() {
			c.expireWrite(s)
		}
	case msgRetire:
		c.retired = true
		c.drained()
	case msgClose:
		c.shutdown(net.ErrClosed, true, http2.ErrCodeNo)
	case msgFunc:
		m.fn()
	}
}

func (c *Conn) open(s *Stream, req *openReq) {
	var refused error
	switch {
	case c.retired:
		refused = ErrGoAway
	case req.req.Protocol != "" && !c.extendedConnect:
		refused = ErrExtendedConnect
	case int64(len(c.streams)) >= c.maxStreams:
		refused = errTooManyStreams
	case int64(req.req.headerSize()) > min(maxHeaderBytes, c.maxHeaderList):
		// The bound comes before the encoder, whose table keeps every field it indexes
		// whether the block goes out or not.
		refused = errHeadersTooLarge
	}
	if refused != nil {
		req.reply <- openReply{err: refused}
		return
	}
	s.id = c.nextID
	c.nextID += 2
	if c.nextID > maxStreamID {
		c.retired = true
	}
	s.sendWindow = c.initialWindow
	s.recv = inflow{avail: window}
	s.open = req
	c.streams[s.id] = s
	c.refreshCanOpen()
	c.control = append(c.control, control{kind: ctlHeaders, s: s, req: &req.req})
}

// refreshCanOpen is called where a caller may observe the change before serve ends its
// turn, a stream opened or closed.
func (c *Conn) refreshCanOpen() {
	c.canOpen.Store(c.err == nil && !c.retired && int64(len(c.streams)) < c.maxStreams)
}

// expireWrite ends the pending write of s at its deadline. A write nothing of has left
// keeps the stream and its windows. A write cut mid-way ends the stream, a byte stream that
// lost track of what left cannot go on.
func (c *Conn) expireWrite(s *Stream) {
	if !s.pending.active {
		return
	}
	if s.pending.off > 0 {
		s.reply(s.pending.off, os.ErrDeadlineExceeded)
		s.pending = writeReq{}
		c.closeStream(s, errStreamClosed, http2.ErrCodeCancel)
		return
	}
	s.pending = writeReq{}
	c.unready(s)
	s.reply(0, os.ErrDeadlineExceeded)
}

// credit grants back n bytes read on s, or on the connection alone with a nil s. What is
// due goes out in one WINDOW_UPDATE however many grants it merges.
func (c *Conn) credit(s *Stream, n int64, g grant) {
	c.recv.add(n, g)
	if s == nil || s.gone || s.remoteEnd {
		return
	}
	s.recv.add(n, g)
	if s.recv.due > 0 && !s.creditDue {
		s.creditDue = true
		c.creditDue = append(c.creditDue, s)
	}
}

func (c *Conn) markReady(s *Stream) {
	if !s.ready {
		s.ready = true
		c.ready = append(c.ready, s)
	}
}

func (c *Conn) unready(s *Stream) {
	if !s.ready {
		return
	}
	s.ready = false
	for i, r := range c.ready {
		if r == s {
			last := len(c.ready) - 1
			c.ready[i] = c.ready[last]
			c.ready[last] = nil
			c.ready = c.ready[:last]
			break
		}
	}
	if c.rr >= len(c.ready) {
		c.rr = 0
	}
}

// pump encodes what can go out and hands it to the write goroutine when it is free.
func (c *Conn) pump() {
	for c.err == nil {
		for c.out.Len() < outBound && c.encodeOne() {
		}
		if c.err != nil || c.writing || c.out.Len() == 0 {
			return
		}
		c.writing = true
		_ = c.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
		c.writeCh <- c.out
		c.out, c.spare = c.spare, c.out
		c.outW.buf = c.out
	}
}

// encodeOne encodes one frame into out, a control frame first, then the credit due, then
// DATA from the next ready stream whose windows allow it, and reports whether it encoded
// anything.
func (c *Conn) encodeOne() bool {
	if len(c.control) > 0 {
		ctl := c.control[0]
		c.control[0] = control{}
		c.control = c.control[1:]
		return c.encoded(c.encodeControl(ctl))
	}
	if c.recv.due > 0 {
		incr := c.recv.due
		c.recv.due = 0
		return c.encoded(c.fr.WriteWindowUpdate(0, uint32(incr))) //nolint:gosec // at most a window
	}
	for len(c.creditDue) > 0 {
		s := c.creditDue[0]
		c.creditDue[0] = nil
		c.creditDue = c.creditDue[1:]
		s.creditDue = false
		if s.gone || s.recv.due == 0 {
			continue
		}
		incr := s.recv.due
		s.recv.due = 0
		return c.encoded(c.fr.WriteWindowUpdate(s.id, uint32(incr))) //nolint:gosec // at most a window
	}
	n := len(c.ready)
	for i := range n {
		idx := (c.rr + i) % n
		s := c.ready[idx]
		if !c.encodeData(s) {
			if c.err != nil {
				return false
			}
			continue
		}
		c.rr = (idx + 1) % n
		if !s.pending.active {
			c.unready(s)
		}
		return true
	}
	return false
}

// encoded reports whether the framer took the frame, and ends the connection when it did
// not.
func (c *Conn) encoded(err error) bool {
	if err != nil {
		c.shutdown(err, false, 0)
		return false
	}
	return true
}

func (c *Conn) encodeControl(ctl control) error {
	switch ctl.kind {
	case ctlHeaders:
		if ctl.s.gone {
			return nil
		}
		return c.encodeHeaders(ctl.s, ctl.req)
	case ctlSettingsAck:
		c.queuedControl--
		return c.fr.WriteSettingsAck()
	case ctlPingAck:
		c.queuedControl--
		return c.fr.WritePing(true, ctl.ping)
	case ctlPing:
		return c.fr.WritePing(false, ctl.ping)
	case ctlReset:
		return c.fr.WriteRSTStream(ctl.id, ctl.code)
	}
	return nil
}

func (c *Conn) encodeHeaders(s *Stream, req *Request) error {
	c.encBuf.Reset()
	c.field(":method", "CONNECT")
	if req.Protocol != "" {
		c.field(":scheme", req.Scheme)
		c.field(":path", req.Path)
	}
	c.field(":authority", req.Authority)
	if req.Protocol != "" {
		c.field(":protocol", req.Protocol)
	}
	for k, vv := range req.Header {
		name := strings.ToLower(k)
		for _, v := range vv {
			c.field(name, v)
		}
	}
	s.headersSent = true
	// A block past the frame size goes on in CONTINUATION frames, which nothing may come
	// between, so the whole of it is encoded here.
	block := c.encBuf.Bytes()
	size := int(c.maxFrameSize)
	n := min(len(block), size)
	if err := c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: s.id, BlockFragment: block[:n], EndHeaders: n == len(block)}); err != nil {
		return err
	}
	for off := n; off < len(block); off += size {
		end := min(off+size, len(block))
		if err := c.fr.WriteContinuation(s.id, end == len(block), block[off:end]); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) field(name, value string) {
	_ = c.enc.WriteField(hpack.HeaderField{Name: name, Value: value})
}

// encodeData encodes one DATA frame of the pending write of s, and reports whether the
// windows let it.
func (c *Conn) encodeData(s *Stream) bool {
	p := &s.pending
	rem := p.data[p.off:]
	n := max(min(int64(len(rem)), int64(c.maxFrameSize), maxDataFrame, s.sendWindow, c.sendWindow), 0)
	if n == 0 && len(rem) > 0 {
		return false
	}
	last := int(n) == len(rem)
	if !c.encoded(c.fr.WriteData(s.id, p.endStream && last, rem[:n])) {
		return false
	}
	s.sendWindow -= n
	c.sendWindow -= n
	p.off += int(n)
	if !last {
		return true
	}
	if p.endStream {
		s.localEnd = true
	}
	total := len(p.data)
	*p = writeReq{}
	s.reply(total, nil)
	if s.localEnd && s.remoteEnd {
		c.closeStream(s, errStreamClosed, http2.ErrCodeNo)
	}
	return true
}

func (c *Conn) onFrame(fr frame) {
	if fr.gated {
		defer func() {
			if c.err == nil {
				c.readMore <- struct{}{}
			}
		}()
	}
	err := fr.err
	if err == nil {
		c.lastRead = time.Now()
		err = c.handle(fr)
		if err == nil {
			return
		}
	}
	var se http2.StreamError
	if errors.As(err, &se) {
		// A malformed frame on one stream ends that stream, RFC 9113 section 5.4.2.
		c.resetStream(se)
		return
	}
	if errors.Is(err, io.EOF) {
		// The peer hung up without a GOAWAY, which no stream may mistake for its own
		// clean end.
		err = io.ErrUnexpectedEOF
	}
	var ce http2.ConnectionError
	switch {
	case errors.As(err, &ce):
		c.shutdown(err, true, http2.ErrCode(ce))
	case errors.Is(err, http2.ErrFrameTooLarge):
		c.shutdown(err, true, http2.ErrCodeFrameSize)
	case errors.Is(err, errControlFlood):
		c.shutdown(err, true, http2.ErrCodeEnhanceYourCalm)
	default:
		c.shutdown(err, false, 0)
	}
}

// handle applies one frame. A stream error ends that stream, any other error the connection.
func (c *Conn) handle(fr frame) error {
	if !c.sawSettings {
		if _, ok := fr.f.(*http2.SettingsFrame); !ok {
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
	}
	if fr.isData {
		return c.handleData(fr)
	}
	switch f := fr.f.(type) {
	case *http2.SettingsFrame:
		return c.handleSettings(f)
	case *http2.MetaHeadersFrame:
		return c.handleHeaders(f)
	case *http2.WindowUpdateFrame:
		return c.handleWindowUpdate(f)
	case *http2.PingFrame:
		return c.handlePing(f)
	case *http2.RSTStreamFrame:
		if c.idle(f.StreamID) {
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		if s := c.streams[f.StreamID]; s != nil {
			s.fromPeer = true
			c.closeStream(s, http2.StreamError{StreamID: f.StreamID, Code: f.ErrCode}, f.ErrCode)
		}
		return nil
	case *http2.GoAwayFrame:
		return c.handleGoAway(f)
	case *http2.PushPromiseFrame:
		return http2.ConnectionError(http2.ErrCodeProtocol)
	case *http2.PriorityFrame:
		// A stream cannot depend on itself, RFC 9113 section 5.3.1. The rest of a
		// PRIORITY frame is nothing to a client.
		if f.StreamDep == f.StreamID {
			return http2.StreamError{StreamID: f.StreamID, Code: http2.ErrCodeProtocol}
		}
		return nil
	}
	// Anything unknown, RFC 9113 section 4.1.
	return nil
}

// idle reports whether no stream ever existed with id, on which any frame but HEADERS and
// PRIORITY is a connection error, RFC 9113 section 5.1.
func (c *Conn) idle(id uint32) bool {
	return id%2 == 0 || id >= c.nextID
}

func (c *Conn) handleSettings(f *http2.SettingsFrame) error {
	if f.IsAck() {
		if !c.sawSettings {
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		return nil
	}
	err := f.ForeachSetting(func(s http2.Setting) error {
		if err := s.Valid(); err != nil {
			return err
		}
		switch s.ID {
		case http2.SettingEnablePush:
			// A server may only say 0, RFC 9113 section 6.5.2.
			if s.Val != 0 {
				return http2.ConnectionError(http2.ErrCodeProtocol)
			}
		case http2.SettingInitialWindowSize:
			// The change applies to every open stream, RFC 9113 section 6.9.2.
			delta := int64(s.Val) - c.initialWindow
			c.initialWindow = int64(s.Val)
			for _, st := range c.streams {
				st.sendWindow += delta
				if st.sendWindow > maxStreamID {
					return http2.ConnectionError(http2.ErrCodeFlowControl)
				}
			}
		case http2.SettingMaxFrameSize:
			c.maxFrameSize = s.Val
		case http2.SettingMaxConcurrentStreams:
			c.maxStreams = int64(s.Val)
		case http2.SettingMaxHeaderListSize:
			c.maxHeaderList = int64(s.Val)
		case http2.SettingEnableConnectProtocol:
			// Once enabled it stays enabled, RFC 8441 section 3.
			if c.extendedConnect && s.Val == 0 {
				return http2.ConnectionError(http2.ErrCodeProtocol)
			}
			c.extendedConnect = s.Val == 1
		case http2.SettingHeaderTableSize:
			c.enc.SetMaxDynamicTableSize(s.Val)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := c.queueControl(control{kind: ctlSettingsAck}); err != nil {
		return err
	}
	if !c.sawSettings {
		c.sawSettings = true
		close(c.settingsSeen)
	}
	return nil
}

// queueControl queues a frame the peer provoked, and ends the connection when it provoked
// more than the socket takes.
func (c *Conn) queueControl(ctl control) error {
	if c.queuedControl >= maxControlFrames {
		return errControlFlood
	}
	c.queuedControl++
	c.control = append(c.control, ctl)
	return nil
}

func (c *Conn) handleHeaders(f *http2.MetaHeadersFrame) error {
	if c.idle(f.StreamID) {
		return http2.ConnectionError(http2.ErrCodeProtocol)
	}
	s := c.streams[f.StreamID]
	if s == nil {
		return nil
	}
	if f.HasPriority() && f.Priority.StreamDep == f.StreamID {
		return http2.StreamError{StreamID: f.StreamID, Code: http2.ErrCodeProtocol}
	}
	if s.remoteEnd {
		return http2.StreamError{StreamID: f.StreamID, Code: http2.ErrCodeStreamClosed}
	}
	if f.Truncated {
		return http2.StreamError{StreamID: f.StreamID, Code: http2.ErrCodeEnhanceYourCalm}
	}
	status := f.PseudoValue("status")
	if status == "" && (!s.answered || s.connected || !f.StreamEnded() || len(f.PseudoFields()) > 0) {
		// Trailers alone may follow a refusal, RFC 9113 section 8.1, and nothing but DATA
		// a connected stream, section 8.5.
		return http2.StreamError{StreamID: f.StreamID, Code: http2.ErrCodeProtocol}
	}
	if status != "" {
		code, ok := parseStatus(status)
		if !ok || s.answered {
			return http2.StreamError{StreamID: f.StreamID, Code: http2.ErrCodeProtocol}
		}
		if code < 200 {
			// Informational, the answer is still to come.
			if f.StreamEnded() {
				return http2.StreamError{StreamID: f.StreamID, Code: http2.ErrCodeProtocol}
			}
			return nil
		}
		header := make(http.Header, len(f.RegularFields()))
		for _, hf := range f.RegularFields() {
			if connectionSpecific(hf.Name, hf.Value) {
				return http2.StreamError{StreamID: f.StreamID, Code: http2.ErrCodeProtocol}
			}
			header.Add(hf.Name, hf.Value)
		}
		s.answered = true
		s.connected = code < 300
		if s.open != nil {
			s.open.reply <- openReply{resp: &Response{StatusCode: code, Header: header}}
			s.open = nil
		}
	}
	if f.StreamEnded() {
		return c.endRemote(s)
	}
	return nil
}

// parseStatus reads the three digits of a :status, RFC 9113 section 8.3.2.
func parseStatus(status string) (int, bool) {
	if len(status) != 3 {
		return 0, false
	}
	for i := range 3 {
		if status[i] < '0' || status[i] > '9' {
			return 0, false
		}
	}
	code, _ := strconv.Atoi(status)
	return code, code >= 100
}

func (c *Conn) handleData(fr frame) error {
	if c.idle(fr.id) {
		return http2.ConnectionError(http2.ErrCodeProtocol)
	}
	// Padding counts against the windows, RFC 9113 section 6.9.1.
	n := int64(fr.length)
	if !c.recv.take(n) {
		return http2.ConnectionError(http2.ErrCodeFlowControl)
	}
	s := c.streams[fr.id]
	if s == nil || s.remoteEnd || !s.answered {
		// A stream that ended still had its window on the connection.
		c.credit(nil, n, grantAll)
		switch {
		case s == nil:
			return nil
		case s.remoteEnd:
			return http2.StreamError{StreamID: fr.id, Code: http2.ErrCodeStreamClosed}
		}
		// DATA before the answer, RFC 9113 section 8.1.
		return http2.StreamError{StreamID: fr.id, Code: http2.ErrCodeProtocol}
	}
	if !s.recv.take(n) {
		c.credit(nil, n, grantAll)
		return http2.StreamError{StreamID: fr.id, Code: http2.ErrCodeFlowControl}
	}
	if len(fr.data) > 0 {
		s.deliver(fr.data)
	}
	// The padding is consumed at once, the data when read.
	if pad := n - int64(len(fr.data)); pad > 0 {
		c.credit(s, pad, grantBatch)
	}
	if fr.end {
		return c.endRemote(s)
	}
	return nil
}

// endRemote records the peer's END_STREAM on s, past which its DATA is an error and the
// reads end on EOF once drained. A stream cannot end before its answer, so Open always
// gets one.
func (c *Conn) endRemote(s *Stream) error {
	if !s.answered {
		return http2.StreamError{StreamID: s.id, Code: http2.ErrCodeProtocol}
	}
	s.remoteEnd = true
	s.endReads(io.EOF)
	if s.localEnd {
		c.closeStream(s, errStreamClosed, http2.ErrCodeNo)
	}
	return nil
}

func (c *Conn) handleWindowUpdate(f *http2.WindowUpdateFrame) error {
	if f.StreamID != 0 && c.idle(f.StreamID) {
		return http2.ConnectionError(http2.ErrCodeProtocol)
	}
	if f.Increment == 0 {
		if f.StreamID == 0 {
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		return http2.StreamError{StreamID: f.StreamID, Code: http2.ErrCodeProtocol}
	}
	if f.StreamID == 0 {
		c.sendWindow += int64(f.Increment)
		if c.sendWindow > maxStreamID {
			return http2.ConnectionError(http2.ErrCodeFlowControl)
		}
		return nil
	}
	if s := c.streams[f.StreamID]; s != nil {
		s.sendWindow += int64(f.Increment)
		if s.sendWindow > maxStreamID {
			return http2.StreamError{StreamID: f.StreamID, Code: http2.ErrCodeFlowControl}
		}
	}
	return nil
}

func (c *Conn) handlePing(f *http2.PingFrame) error {
	if f.IsAck() {
		c.pingSent = false
		return nil
	}
	return c.queueControl(control{kind: ctlPingAck, ping: f.Data})
}

func (c *Conn) handleGoAway(f *http2.GoAwayFrame) error {
	c.retired = true
	for id, s := range c.streams {
		if id > f.LastStreamID {
			// The peer did not take the stream, so nothing resets it.
			s.fromPeer = true
			c.closeStream(s, ErrGoAway, http2.ErrCodeNo)
		}
	}
	if f.ErrCode != http2.ErrCodeNo {
		return http2.ConnectionError(f.ErrCode)
	}
	c.drained()
	return nil
}

// onKeepAlive runs at the keepalive period. A PING goes out after a silence, and a peer
// silent for another period past it ends the connection. Any frame counts as life.
func (c *Conn) onKeepAlive() {
	now := time.Now()
	if c.pingSent {
		if !c.lastRead.After(c.pingSentAt) {
			c.shutdown(errKeepAlive, false, 0)
			return
		}
		c.pingSent = false
	}
	idle := now.Sub(c.lastRead)
	if idle >= c.keepAlive {
		c.pingSent = true
		c.pingSentAt = now
		c.control = append(c.control, control{kind: ctlPing})
		c.keepTimer.Reset(c.keepAlive)
		return
	}
	c.keepTimer.Reset(c.keepAlive - idle)
}

// resetStream ends the stream of se and tells the peer. The reset is owed by a stream the
// connection opened, so it counts against no bound.
func (c *Conn) resetStream(se http2.StreamError) {
	if s := c.streams[se.StreamID]; s != nil {
		c.closeStream(s, se, se.Code)
	}
}

// closeStream ends s with err. The peer is told with RST_STREAM and code unless it ended
// the stream itself, or the stream ended in both directions, or its HEADERS never left.
func (c *Conn) closeStream(s *Stream, err error, code http2.ErrCode) {
	if s.gone {
		return
	}
	s.gone = true
	delete(c.streams, s.id)
	if s.writeTimer != nil {
		s.writeTimer.Stop()
		s.writeTimer = nil
	}
	if s.headersSent && !s.fromPeer && (!s.localEnd || !s.remoteEnd) {
		c.control = append(c.control, control{kind: ctlReset, id: s.id, code: code})
	}
	if s.pending.active {
		s.reply(s.pending.off, err)
		s.pending = writeReq{}
	}
	c.unready(s)
	if s.open != nil {
		s.open.reply <- openReply{err: err}
		s.open = nil
	}
	s.err = err
	local := err == net.ErrClosed || err == errStreamClosed && !s.remoteEnd
	c.credit(nil, s.closeReads(err, local), grantAll)
	c.refreshCanOpen()
	close(s.closed)
	c.drained()
}

// drained ends a connection nothing may open on once its last stream ended.
func (c *Conn) drained() {
	if c.retired && len(c.streams) == 0 {
		c.shutdown(ErrGoAway, true, http2.ErrCodeNo)
	}
}

// shutdown ends the connection with err. goAway says whether the peer is told, on a best
// effort bounded by closeTimeout.
func (c *Conn) shutdown(err error, goAway bool, code http2.ErrCode) {
	if c.err != nil {
		return
	}
	c.err = err
	c.canOpen.Store(false)
	if c.keepTimer != nil {
		c.keepTimer.Stop()
	}
	for _, s := range c.streams {
		s.fromPeer = true
		c.closeStream(s, err, http2.ErrCodeNo)
	}
	close(c.done)
	// A write stuck on the socket returns at the deadline, and the write goroutine with it.
	_ = c.nc.SetWriteDeadline(time.Now().Add(closeTimeout))
	if c.writing {
		<-c.wroteCh
		c.writing = false
	}
	close(c.writeCh)
	if goAway {
		c.out.Reset()
		if werr := c.fr.WriteGoAway(0, code, nil); werr == nil {
			_ = c.nc.SetWriteDeadline(time.Now().Add(closeTimeout))
			_, _ = c.nc.Write(c.out.Bytes())
		}
	}
	_ = c.nc.Close()
	close(c.ended)
}

// CanOpen reports whether the connection takes a new stream, which it does until it ends,
// the peer sends GOAWAY, the peer's concurrent stream limit is reached, or Retire is called.
func (c *Conn) CanOpen() bool { return c.canOpen.Load() }

// Retire refuses new streams and ends the connection once the last open one ends.
func (c *Conn) Retire() { c.send(msg{kind: msgRetire}) }

// Err returns the error that ended the connection, nil while it lives.
func (c *Conn) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}

// Done is closed when the connection ends, before its socket is closed.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Close ends the connection, every stream on it with net.ErrClosed, and returns once the
// socket is closed.
func (c *Conn) Close() error {
	c.send(msg{kind: msgClose})
	<-c.ended
	return nil
}

// Open sends a CONNECT and returns the stream once the peer answered it, with the answer.
// A refusal is an answer, the stream then carries whatever the peer sent behind it.
func (c *Conn) Open(ctx context.Context, req Request) (*Stream, *Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := req.validate(); err != nil {
		return nil, nil, err
	}
	select {
	case <-c.settingsSeen:
	case <-c.done:
		return nil, nil, c.Err()
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	s := &Stream{
		c:      c,
		wrote:  make(chan writeResult, 1),
		closed: make(chan struct{}),
	}
	s.cond.L = &s.mu
	o := &openReq{req: req, reply: make(chan openReply, 1)}
	if !c.send(msg{kind: msgOpen, s: s, open: o}) {
		return nil, nil, c.Err()
	}
	select {
	case r := <-o.reply:
		if r.err != nil {
			return nil, nil, r.err
		}
		return s, r.resp, nil
	case <-c.done:
		return nil, nil, c.Err()
	case <-ctx.Done():
		// Serve reads the caller's request until the stream is closed, so Open does not
		// return before it is.
		if c.send(msg{kind: msgCloseStream, s: s, code: http2.ErrCodeCancel}) {
			select {
			case <-s.closed:
			case <-c.done:
			}
		}
		return nil, nil, ctx.Err()
	}
}

// validate refuses a CONNECT without an authority, RFC 9113 section 8.5, an extended one
// without a scheme and a path, RFC 8441 section 4, and a field name or value HTTP/2
// forbids, sections 8.2.1 and 8.2.2.
func (req Request) validate() error {
	if req.Authority == "" {
		return errNoAuthority
	}
	if req.Protocol != "" && (req.Scheme == "" || req.Path == "") {
		return errNoTarget
	}
	for _, v := range []string{req.Scheme, req.Authority, req.Path, req.Protocol} {
		if !validValue(v) {
			return errInvalidHeader
		}
	}
	for k, vv := range req.Header {
		if !httpguts.ValidHeaderFieldName(k) {
			return errInvalidHeader
		}
		for _, v := range vv {
			if !validValue(v) || connectionSpecific(strings.ToLower(k), v) {
				return errInvalidHeader
			}
		}
	}
	return nil
}

// connectionSpecific reports whether a field of a lowercase name is one HTTP/2 forbids in a
// message, RFC 9113 section 8.2.2.
func connectionSpecific(name, value string) bool {
	switch name {
	case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
		return true
	case "te":
		return value != "trailers"
	}
	return false
}

// validValue reports whether v may be a field value, RFC 9113 section 8.2.1, which no
// space or tab may start or end.
func validValue(v string) bool {
	if v == "" {
		return true
	}
	first, last := v[0], v[len(v)-1]
	return httpguts.ValidHeaderFieldValue(v) && first != ' ' && first != '\t' && last != ' ' && last != '\t'
}

// headerSize is the size of the header list, RFC 7541 section 4.1, which the encoded block
// does not exceed.
func (req Request) headerSize() int {
	n := len(":method") + len("CONNECT") + len(":authority") + len(req.Authority) + 3*32
	if req.Protocol != "" {
		n += len(":scheme") + len(req.Scheme) + len(":path") + len(req.Path) + len(":protocol") + len(req.Protocol) + 3*32
	}
	for k, vv := range req.Header {
		for _, v := range vv {
			n += len(k) + len(v) + 32
		}
	}
	return n
}

// Stream is one CONNECT stream as a net.Conn. mu guards chunks, readErr, unsent, returned
// and the read deadline, which the readers share with serve, and cond wakes every reader.
// wmu serializes the writers, wrote is serve's answer to the pending write, and closed is
// closed once the stream ended, err set before. serve owns the rest.
type Stream struct {
	writeDeadline time.Time
	readDeadline  time.Time
	readErr       error
	err           error
	c             *Conn
	wrote         chan writeResult
	closed        chan struct{}
	open          *openReq
	writeTimer    *time.Timer
	readTimer     *time.Timer
	cond          sync.Cond
	chunks        [][]byte
	pending       writeReq
	recv          inflow
	// unsent is what the reader consumed and has not told serve, and returned says serve
	// granted back what was held when the stream ended, so a read grants nothing more.
	unsent      int64
	sendWindow  int64
	mu          sync.Mutex
	wmu         sync.Mutex
	id          uint32
	returned    bool
	tailOwned   bool
	ready       bool
	creditDue   bool
	gone        bool
	headersSent bool
	localEnd    bool
	remoteEnd   bool
	answered    bool
	connected   bool
	fromPeer    bool
}

type writeReq struct {
	data      []byte
	off       int
	endStream bool
	active    bool
}

type writeResult struct {
	err error
	n   int
}

func (s *Stream) reply(n int, err error) {
	select {
	case s.wrote <- writeResult{n: n, err: err}:
	default:
	}
}

func (s *Stream) writeExpired() bool {
	return !s.writeDeadline.IsZero() && !time.Now().Before(s.writeDeadline)
}

// deliver buffers b for the readers. Past chunkBacklog chunks, a payload under chunkMin
// joins the last chunk when that one is the stream's own buffer, and starts one otherwise.
func (s *Stream) deliver(b []byte) {
	s.mu.Lock()
	switch n := len(s.chunks); {
	case s.tailOwned && len(b) < chunkMin:
		s.chunks[n-1] = append(s.chunks[n-1], b...)
	case n < chunkBacklog || len(b) >= chunkMin:
		s.chunks = append(s.chunks, b)
		s.tailOwned = false
	default:
		s.chunks = append(s.chunks, append(make([]byte, 0, chunkMin), b...))
		s.tailOwned = true
	}
	s.cond.Broadcast()
	s.mu.Unlock()
}

// endReads ends the reads with err once the buffered chunks are drained.
func (s *Stream) endReads(err error) {
	s.mu.Lock()
	if s.readErr == nil {
		s.readErr = err
	}
	s.cond.Broadcast()
	s.mu.Unlock()
}

// closeReads is endReads for a stream that ended, and returns what was consumed or
// buffered and never granted back, accounted on the connection by the caller. A stream
// closed here reads nothing more, one the peer ended drains to its end.
func (s *Stream) closeReads(err error, local bool) int64 {
	s.mu.Lock()
	held := s.unsent
	for _, chunk := range s.chunks {
		held += int64(len(chunk))
	}
	switch {
	case local:
		s.readErr = err
		s.chunks = nil
		s.tailOwned = false
	case s.readErr == nil:
		s.readErr = err
	}
	s.unsent = 0
	s.returned = true
	if s.readTimer != nil {
		s.readTimer.Stop()
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	return held
}

// Read returns the bytes the peer sent, in order.
func (s *Stream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if !s.readDeadline.IsZero() && !time.Now().Before(s.readDeadline) {
			return 0, os.ErrDeadlineExceeded
		}
		if len(s.chunks) > 0 {
			n := copy(b, s.chunks[0])
			if n == len(s.chunks[0]) {
				s.chunks[0] = nil
				s.chunks = s.chunks[1:]
				if len(s.chunks) == 0 {
					s.tailOwned = false
				}
			} else {
				s.chunks[0] = s.chunks[0][n:]
			}
			if !s.returned {
				s.unsent += int64(n)
				if s.unsent >= creditFlush {
					s.flush(grantBatch)
				}
			}
			return n, nil
		}
		if s.readErr != nil {
			return 0, s.readErr
		}
		// Nothing to read, so what was consumed is granted back before the wait.
		if !s.returned && s.unsent >= creditIdle {
			s.flush(grantLow)
			continue
		}
		s.cond.Wait()
	}
}

// flush tells serve what the reader consumed, with mu released for the send.
func (s *Stream) flush(g grant) {
	n := s.unsent
	s.unsent = 0
	s.mu.Unlock()
	s.c.send(msg{kind: msgRead, s: s, n: n, grant: g})
	s.mu.Lock()
}

// Write sends b, waiting for the windows to open and never interleaving with another write.
func (s *Stream) Write(b []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.submit(msg{kind: msgWrite, s: s, data: b})
}

// CloseWrite ends the proxy-bound direction with END_STREAM.
func (s *Stream) CloseWrite() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.submit(msg{kind: msgCloseWrite, s: s})
	return err
}

// submit hands a write to serve and waits for its answer, or for the end of the stream or
// of the connection.
func (s *Stream) submit(m msg) (int, error) {
	select {
	case <-s.wrote:
	default:
	}
	if !s.c.send(m) {
		return 0, s.c.Err()
	}
	select {
	case r := <-s.wrote:
		return r.n, r.err
	case <-s.closed:
		select {
		case r := <-s.wrote:
			return r.n, r.err
		default:
			return 0, s.err
		}
	case <-s.c.done:
		select {
		case r := <-s.wrote:
			return r.n, r.err
		default:
			return 0, s.c.Err()
		}
	}
}

// Close ends the stream. The peer is told with RST_STREAM unless it ended the stream first.
func (s *Stream) Close() error {
	if s.c.send(msg{kind: msgCloseStream, s: s, code: http2.ErrCodeCancel}) {
		select {
		case <-s.closed:
		case <-s.c.done:
		}
	}
	return nil
}

func (s *Stream) LocalAddr() net.Addr  { return s.c.nc.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr { return s.c.nc.RemoteAddr() }

func (s *Stream) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}

// SetReadDeadline wakes every blocked Read, at once when t has passed and at t otherwise.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	if s.readTimer != nil {
		s.readTimer.Stop()
	}
	if d := time.Until(t); !t.IsZero() && d > 0 {
		if s.readTimer == nil {
			s.readTimer = time.AfterFunc(d, s.wakeReaders)
		} else {
			s.readTimer.Reset(d)
		}
	}
	s.cond.Broadcast()
	return nil
}

func (s *Stream) wakeReaders() {
	s.mu.Lock()
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.c.send(msg{kind: msgWriteDeadline, s: s, t: t})
	return nil
}

var _ net.Conn = (*Stream)(nil)
