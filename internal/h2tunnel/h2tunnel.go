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

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	// window is the receive window advertised for every stream and raised on the connection,
	// and the peer must send WINDOW_UPDATEs for what it consumes the same way.
	window = 1 << 20
	// defaultWindow is the initial window of RFC 9113 section 6.9.2, before any SETTINGS.
	defaultWindow = 65535
	// maxHeaderBytes bounds the header block of a response.
	maxHeaderBytes = 64 << 10
	// hpackTableSize is the decoding table size of RFC 9113 section 6.5.2.
	hpackTableSize = 4096
	// writeTimeout bounds one frame on the socket. A peer that reads nothing for that long
	// ends the connection.
	writeTimeout = 30 * time.Second
	// closeTimeout bounds the GOAWAY a close sends.
	closeTimeout = time.Second
	// writeQueue bounds the frames waiting for the writer.
	writeQueue = 256
)

var (
	// ErrGoAway is returned by Open once the peer sent GOAWAY. The connection still serves
	// the streams it had, and a new one goes on another connection.
	ErrGoAway = errors.New("h2tunnel: the peer is going away")
	// ErrExtendedConnect is returned by Open when the peer did not enable the extended
	// CONNECT protocol, RFC 8441 section 3.
	ErrExtendedConnect = errors.New("h2tunnel: the peer does not support extended CONNECT")
	errTooManyStreams  = errors.New("h2tunnel: the peer's concurrent stream limit is reached")
	errClosed          = errors.New("h2tunnel: connection closed")
	errStreamClosed    = errors.New("h2tunnel: stream closed")
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

// Conn is a client HTTP/2 connection carrying CONNECT streams.
type Conn struct {
	nc           net.Conn
	err          error
	fr           *http2.Framer
	bw           *bufio.Writer
	enc          *hpack.Encoder
	streams      map[uint32]*Stream
	settingsSeen chan struct{}

	done chan struct{}
	// writes feeds the one goroutine writing frames, and the encoder with them, so a socket
	// that stopped taking bytes blocks nothing but that goroutine. writerDone is closed
	// when it returns.
	writes     chan writeRequest
	writerDone chan struct{}
	// encBuf is what enc writes to, reused by the writer.
	encBuf bytes.Buffer
	// sendWindow is what the peer lets the connection send, and recvUnacked what the peer
	// sent and the streams consumed since the last WINDOW_UPDATE on the connection.
	sendWindow  int64
	recvUnacked int64
	// peer settings, read once under mu when a stream is opened.
	initialWindow   int64
	maxStreams      int64
	settingsOnce    sync.Once
	doneOnce        sync.Once
	mu              sync.Mutex
	nextID          uint32
	maxFrameSize    uint32
	extendedConnect bool
	goAway          bool
}

// Client starts an HTTP/2 connection on nc, the client preface and SETTINGS written, and
// reads it until it ends. nc is closed when the connection ends.
func Client(nc net.Conn) (*Conn, error) {
	bw := bufio.NewWriter(nc)
	c := &Conn{
		nc:            nc,
		bw:            bw,
		fr:            http2.NewFramer(bw, bufio.NewReader(nc)),
		streams:       make(map[uint32]*Stream),
		nextID:        1,
		sendWindow:    defaultWindow,
		initialWindow: defaultWindow,
		maxFrameSize:  16384,
		maxStreams:    1<<32 - 1,
		settingsSeen:  make(chan struct{}),
		done:          make(chan struct{}),
		writes:        make(chan writeRequest, writeQueue),
		writerDone:    make(chan struct{}),
	}
	c.enc = hpack.NewEncoder(&c.encBuf)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(hpackTableSize, nil)
	c.fr.MaxHeaderListSize = maxHeaderBytes

	_ = nc.SetWriteDeadline(time.Now().Add(writeTimeout))
	err := c.writeNow(func(fr *http2.Framer) error {
		if _, err := bw.WriteString(http2.ClientPreface); err != nil {
			return err
		}
		if err := fr.WriteSettings(
			http2.Setting{ID: http2.SettingEnablePush, Val: 0},
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: window},
			http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: maxHeaderBytes},
		); err != nil {
			return err
		}
		return fr.WriteWindowUpdate(0, window-defaultWindow)
	})
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	go c.writeLoop()
	go c.readLoop()
	return c, nil
}

type writeRequest struct {
	f func(*http2.Framer) error
	// res receives the outcome, nil when the caller does not wait for it.
	res chan error
}

// write has the writer run f and flush, and returns its outcome, or the connection's error
// once it ended.
func (c *Conn) write(f func(*http2.Framer) error) error {
	req := writeRequest{f: f, res: make(chan error, 1)}
	select {
	case c.writes <- req:
	case <-c.done:
		return c.Err()
	}
	select {
	case err := <-req.res:
		return err
	case <-c.done:
		return c.Err()
	}
}

// tryWrite queues f without waiting for it and drops it when the queue is full.
func (c *Conn) tryWrite(f func(*http2.Framer) error) {
	select {
	case c.writes <- writeRequest{f: f}:
	default:
	}
}

func (c *Conn) writeLoop() {
	for {
		select {
		case req := <-c.writes:
			_ = c.nc.SetWriteDeadline(time.Now().Add(writeTimeout))
			err := c.writeNow(req.f)
			if req.res != nil {
				req.res <- err
			}
			if err != nil {
				// fail waits for writerDone, so it is closed first.
				close(c.writerDone)
				c.fail(err, false)
				return
			}
		case <-c.done:
			close(c.writerDone)
			return
		}
	}
}

// writeNow runs f with the framer and flushes what it wrote, on the writer's goroutine or
// before it starts.
func (c *Conn) writeNow(f func(*http2.Framer) error) error {
	if err := f(c.fr); err != nil {
		return err
	}
	return c.bw.Flush()
}

// CanOpen reports whether the connection takes a new stream, which it does until it ends or
// the peer sends GOAWAY.
func (c *Conn) CanOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err == nil && !c.goAway
}

// Err returns the error that ended the connection, nil while it lives.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Done is closed when the connection ends.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Close ends the connection, every stream on it with net.ErrClosed.
func (c *Conn) Close() error {
	c.fail(errClosed, true)
	return nil
}

// fail ends the connection with err. goAway says whether the peer is told, on a best
// effort bounded by closeTimeout.
func (c *Conn) fail(err error, goAway bool) {
	c.doneOnce.Do(func() {
		c.mu.Lock()
		c.err = err
		streams := c.streams
		c.streams = nil
		c.mu.Unlock()
		close(c.done)
		// A frame the writer is stuck on returns at the deadline, and the writer with it.
		_ = c.nc.SetWriteDeadline(time.Now().Add(closeTimeout))
		<-c.writerDone
		if goAway {
			_ = c.writeNow(func(fr *http2.Framer) error {
				return fr.WriteGoAway(0, http2.ErrCodeNo, nil)
			})
		}
		_ = c.nc.Close()
		for _, s := range streams {
			s.end(err)
		}
	})
}

// Open sends a CONNECT and returns the stream once the peer answered it, with the answer.
// A refusal is an answer, the stream then carries whatever the peer sent behind it.
func (c *Conn) Open(ctx context.Context, req Request) (*Stream, *Response, error) {
	select {
	case <-c.settingsSeen:
	case <-c.done:
		return nil, nil, c.Err()
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}

	s := &Stream{
		c:          c,
		readReady:  make(chan struct{}, 1),
		writeReady: make(chan struct{}, 1),
		resp:       make(chan *Response, 1),
		done:       make(chan struct{}),
	}
	c.mu.Lock()
	switch {
	case c.err != nil:
		c.mu.Unlock()
		return nil, nil, c.err
	case c.goAway:
		c.mu.Unlock()
		return nil, nil, ErrGoAway
	case req.Protocol != "" && !c.extendedConnect:
		c.mu.Unlock()
		return nil, nil, ErrExtendedConnect
	case int64(len(c.streams)) >= c.maxStreams:
		c.mu.Unlock()
		return nil, nil, errTooManyStreams
	}
	s.id = c.nextID
	c.nextID += 2
	s.sendWindow = c.initialWindow
	s.recvWindow = window
	c.streams[s.id] = s
	c.mu.Unlock()

	err := c.write(func(fr *http2.Framer) error {
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
		if c.encBuf.Len() > int(c.maxFrameSize) {
			return errors.New("h2tunnel: request headers exceed a frame")
		}
		return fr.WriteHeaders(http2.HeadersFrameParam{StreamID: s.id, BlockFragment: c.encBuf.Bytes(), EndHeaders: true})
	})
	if err != nil {
		c.fail(err, false)
		return nil, nil, err
	}

	select {
	case resp := <-s.resp:
		return s, resp, nil
	case <-s.done:
		return nil, nil, s.err
	case <-ctx.Done():
		s.reset(http2.ErrCodeCancel)
		return nil, nil, ctx.Err()
	}
}

func (c *Conn) field(name, value string) {
	_ = c.enc.WriteField(hpack.HeaderField{Name: name, Value: value})
}

func (c *Conn) readLoop() {
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// The peer hung up without a GOAWAY, which no stream may mistake for its
				// own clean end.
				err = io.ErrUnexpectedEOF
			}
			var se http2.StreamError
			if errors.As(err, &se) {
				// A malformed frame on one stream ends that stream, RFC 9113 section 5.4.2.
				c.resetStream(se.StreamID, se.Code, false)
				continue
			}
			c.fail(err, false)
			return
		}
		if err := c.handle(f); err != nil {
			c.fail(err, false)
			return
		}
	}
}

// handle applies one frame. An error is a connection error.
func (c *Conn) handle(f http2.Frame) error {
	switch f := f.(type) {
	case *http2.SettingsFrame:
		return c.handleSettings(f)
	case *http2.MetaHeadersFrame:
		return c.handleHeaders(f)
	case *http2.DataFrame:
		return c.handleData(f)
	case *http2.WindowUpdateFrame:
		return c.handleWindowUpdate(f)
	case *http2.PingFrame:
		if f.IsAck() {
			return nil
		}
		return c.write(func(fr *http2.Framer) error { return fr.WritePing(true, f.Data) })
	case *http2.RSTStreamFrame:
		c.resetStream(f.StreamID, f.ErrCode, true)
		return nil
	case *http2.GoAwayFrame:
		return c.handleGoAway(f)
	case *http2.PushPromiseFrame:
		return http2.ConnectionError(http2.ErrCodeProtocol)
	}
	// PRIORITY and anything unknown, RFC 9113 section 4.1.
	return nil
}

func (c *Conn) handleSettings(f *http2.SettingsFrame) error {
	if f.IsAck() {
		return nil
	}
	c.mu.Lock()
	err := f.ForeachSetting(func(s http2.Setting) error {
		switch s.ID {
		case http2.SettingInitialWindowSize:
			if s.Val > 1<<31-1 {
				return http2.ConnectionError(http2.ErrCodeFlowControl)
			}
			// The change applies to every open stream, RFC 9113 section 6.9.2.
			delta := int64(s.Val) - c.initialWindow
			c.initialWindow = int64(s.Val)
			for _, st := range c.streams {
				st.addSendWindow(delta)
			}
		case http2.SettingMaxFrameSize:
			if s.Val < 16384 || s.Val > 1<<24-1 {
				return http2.ConnectionError(http2.ErrCodeProtocol)
			}
			c.maxFrameSize = s.Val
		case http2.SettingMaxConcurrentStreams:
			c.maxStreams = int64(s.Val)
		case http2.SettingEnableConnectProtocol:
			c.extendedConnect = s.Val == 1
		}
		return nil
	})
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := c.write(func(fr *http2.Framer) error { return fr.WriteSettingsAck() }); err != nil {
		return err
	}
	c.settingsOnce.Do(func() { close(c.settingsSeen) })
	return nil
}

func (c *Conn) handleHeaders(f *http2.MetaHeadersFrame) error {
	s := c.stream(f.StreamID)
	if s == nil {
		return nil
	}
	if status := f.PseudoValue("status"); status != "" {
		code, err := strconv.Atoi(status)
		if err != nil {
			return http2.StreamError{StreamID: f.StreamID, Code: http2.ErrCodeProtocol}
		}
		if code >= 100 && code < 200 {
			// Informational, the answer is still to come.
			return nil
		}
		header := make(http.Header, len(f.RegularFields()))
		for _, hf := range f.RegularFields() {
			header.Add(hf.Name, hf.Value)
		}
		select {
		case s.resp <- &Response{StatusCode: code, Header: header}:
		default:
		}
	}
	if f.StreamEnded() {
		s.endRead(io.EOF)
	}
	return nil
}

func (c *Conn) handleData(f *http2.DataFrame) error {
	// Padding counts against the windows, RFC 9113 section 6.9.1.
	n := int64(f.Header().Length)
	s := c.stream(f.StreamID)
	if s == nil {
		// A stream that ended still had its window on the connection.
		return c.consumed(nil, n)
	}
	s.mu.Lock()
	if n > s.recvWindow {
		s.mu.Unlock()
		return http2.ConnectionError(http2.ErrCodeFlowControl)
	}
	s.recvWindow -= n
	if len(f.Data()) > 0 {
		s.chunks = append(s.chunks, bytes.Clone(f.Data()))
	}
	s.mu.Unlock()
	s.signal(s.readReady)
	if f.StreamEnded() {
		s.endRead(io.EOF)
	}
	// The padding is consumed at once, the data when read.
	return c.consumed(s, n-int64(len(f.Data())))
}

// consumed accounts n bytes as read on s, or on the connection alone with a nil s, and sends
// the WINDOW_UPDATEs due once half a window is owed.
func (c *Conn) consumed(s *Stream, n int64) error {
	if n == 0 {
		return nil
	}
	var stream, conn uint32
	if s != nil {
		s.mu.Lock()
		s.recvUnacked += n
		if s.recvUnacked >= window/2 && s.readErr == nil {
			stream = uint32(s.recvUnacked) //nolint:gosec // at most a window
			s.recvWindow += s.recvUnacked
			s.recvUnacked = 0
		}
		s.mu.Unlock()
	}
	c.mu.Lock()
	c.recvUnacked += n
	if c.recvUnacked >= window/2 {
		conn = uint32(c.recvUnacked) //nolint:gosec // at most a window per stream
		c.recvUnacked = 0
	}
	c.mu.Unlock()
	if stream == 0 && conn == 0 {
		return nil
	}
	return c.write(func(fr *http2.Framer) error {
		if stream != 0 {
			if err := fr.WriteWindowUpdate(s.id, stream); err != nil {
				return err
			}
		}
		if conn != 0 {
			return fr.WriteWindowUpdate(0, conn)
		}
		return nil
	})
}

func (c *Conn) handleWindowUpdate(f *http2.WindowUpdateFrame) error {
	if f.Increment == 0 {
		if f.StreamID == 0 {
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		c.resetStream(f.StreamID, http2.ErrCodeProtocol, false)
		return nil
	}
	if f.StreamID == 0 {
		c.mu.Lock()
		c.sendWindow += int64(f.Increment)
		if c.sendWindow > 1<<31-1 {
			c.mu.Unlock()
			return http2.ConnectionError(http2.ErrCodeFlowControl)
		}
		streams := make([]*Stream, 0, len(c.streams))
		for _, s := range c.streams {
			streams = append(streams, s)
		}
		c.mu.Unlock()
		for _, s := range streams {
			s.signal(s.writeReady)
		}
		return nil
	}
	if s := c.stream(f.StreamID); s != nil {
		s.addSendWindow(int64(f.Increment))
	}
	return nil
}

func (c *Conn) handleGoAway(f *http2.GoAwayFrame) error {
	c.mu.Lock()
	c.goAway = true
	var unserved []*Stream
	for id, s := range c.streams {
		if id > f.LastStreamID {
			unserved = append(unserved, s)
			delete(c.streams, id)
		}
	}
	c.mu.Unlock()
	for _, s := range unserved {
		s.end(ErrGoAway)
	}
	if f.ErrCode != http2.ErrCodeNo {
		return http2.ConnectionError(f.ErrCode)
	}
	return nil
}

func (c *Conn) stream(id uint32) *Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streams[id]
}

// resetStream ends the stream id with code, which the peer sent when fromPeer, and is sent
// to it otherwise, a frame of the stream being malformed.
func (c *Conn) resetStream(id uint32, code http2.ErrCode, fromPeer bool) {
	c.mu.Lock()
	s := c.streams[id]
	delete(c.streams, id)
	c.mu.Unlock()
	if s == nil {
		return
	}
	if fromPeer {
		s.fromPeer.Store(true)
	} else {
		c.tryWrite(func(fr *http2.Framer) error { return fr.WriteRSTStream(id, code) })
	}
	s.end(http2.StreamError{StreamID: id, Code: code})
}

// Stream is one CONNECT stream as a net.Conn.
type Stream struct {
	// readErr ends the reads once the chunks are drained, io.EOF on the peer's END_STREAM.
	readErr error
	// err ends the stream in both directions.
	err           error
	c             *Conn
	done          chan struct{}
	readReady     chan struct{}
	writeReady    chan struct{}
	resp          chan *Response
	readDeadline  atomic.Pointer[time.Time]
	writeDeadline atomic.Pointer[time.Time]
	chunks        [][]byte
	// recvWindow is what the peer may still send, recvUnacked what was consumed and not
	// yet granted back.
	recvWindow  int64
	recvUnacked int64
	sendWindow  int64
	doneOnce    sync.Once

	mu sync.Mutex
	// wmu serializes the writers, so one write's frames are never interleaved with another's.
	wmu sync.Mutex
	id  uint32

	fromPeer atomic.Bool
	closed   bool
	// windowReturned says end gave the connection window back for what was buffered.
	windowReturned bool
}

func (s *Stream) signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (s *Stream) addSendWindow(delta int64) {
	s.mu.Lock()
	s.sendWindow += delta
	s.mu.Unlock()
	s.signal(s.writeReady)
}

// endRead ends the reads with err once the buffered chunks are drained.
func (s *Stream) endRead(err error) {
	s.mu.Lock()
	if s.readErr == nil {
		s.readErr = err
	}
	s.mu.Unlock()
	s.signal(s.readReady)
}

// end ends the stream in both directions with err. What was buffered and never read goes
// back to the connection window.
func (s *Stream) end(err error) {
	s.doneOnce.Do(func() {
		s.mu.Lock()
		s.err = err
		if s.readErr == nil {
			s.readErr = err
		}
		// The reads still deliver what was buffered, accounted on the connection now.
		var buffered int64
		for _, chunk := range s.chunks {
			buffered += int64(len(chunk))
		}
		s.windowReturned = true
		s.mu.Unlock()
		close(s.done)
		s.signal(s.readReady)
		s.signal(s.writeReady)
		if buffered > 0 {
			_ = s.c.consumed(nil, buffered)
		}
	})
}

// Read returns the bytes the peer sent, in order.
func (s *Stream) Read(b []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.chunks) > 0 {
			n := copy(b, s.chunks[0])
			if n == len(s.chunks[0]) {
				s.chunks = s.chunks[1:]
			} else {
				s.chunks[0] = s.chunks[0][n:]
			}
			returned := s.windowReturned
			s.mu.Unlock()
			if !returned {
				_ = s.c.consumed(s, int64(n))
			}
			return n, nil
		}
		if s.readErr != nil {
			err := s.readErr
			s.mu.Unlock()
			return 0, err
		}
		s.mu.Unlock()

		if err := s.wait(s.readReady, &s.readDeadline); err != nil {
			return 0, err
		}
	}
}

// wait blocks until ready is signalled or the deadline passes.
func (s *Stream) wait(ready <-chan struct{}, deadline *atomic.Pointer[time.Time]) error {
	var timeout <-chan time.Time
	if dl := deadline.Load(); dl != nil && !dl.IsZero() {
		if !time.Now().Before(*dl) {
			return os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(time.Until(*dl))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-ready:
		return nil
	case <-timeout:
		return os.ErrDeadlineExceeded
	}
}

// Write sends b, waiting for the windows to open and never interleaving with another write.
func (s *Stream) Write(b []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	written := 0
	for written < len(b) {
		n, err := s.writeFrame(b[written:])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// writeFrame sends what the windows and the frame size allow of b, waiting for a window
// when both are empty.
func (s *Stream) writeFrame(b []byte) (int, error) {
	for {
		// The connection lock comes first, the order the read loop takes them in.
		s.c.mu.Lock()
		s.mu.Lock()
		if s.err != nil || s.closed {
			err := s.err
			if err == nil {
				err = errStreamClosed
			}
			s.mu.Unlock()
			s.c.mu.Unlock()
			return 0, err
		}
		n := min(int64(len(b)), s.sendWindow, s.c.sendWindow, int64(s.c.maxFrameSize))
		if n > 0 {
			s.sendWindow -= n
			s.c.sendWindow -= n
		}
		s.mu.Unlock()
		s.c.mu.Unlock()
		if n > 0 {
			if err := s.c.write(func(fr *http2.Framer) error { return fr.WriteData(s.id, false, b[:n]) }); err != nil {
				return 0, err
			}
			return int(n), nil
		}
		if err := s.wait(s.writeReady, &s.writeDeadline); err != nil {
			return 0, err
		}
	}
}

// CloseWrite ends the proxy-bound direction with END_STREAM.
func (s *Stream) CloseWrite() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	if s.err != nil || s.closed {
		s.mu.Unlock()
		return errStreamClosed
	}
	s.closed = true
	s.mu.Unlock()
	return s.c.write(func(fr *http2.Framer) error { return fr.WriteData(s.id, true, nil) })
}

// Close ends the stream. The peer is told with RST_STREAM unless it ended the stream first.
func (s *Stream) Close() error {
	s.reset(http2.ErrCodeCancel)
	return nil
}

func (s *Stream) reset(code http2.ErrCode) {
	c := s.c
	c.mu.Lock()
	if c.streams[s.id] != s {
		c.mu.Unlock()
		s.end(errStreamClosed)
		return
	}
	delete(c.streams, s.id)
	c.mu.Unlock()
	if !s.fromPeer.Load() {
		c.tryWrite(func(fr *http2.Framer) error { return fr.WriteRSTStream(s.id, code) })
	}
	s.end(errStreamClosed)
}

func (s *Stream) LocalAddr() net.Addr  { return s.c.nc.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr { return s.c.nc.RemoteAddr() }

func (s *Stream) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	s.readDeadline.Store(&t)
	s.signal(s.readReady)
	return nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Store(&t)
	s.signal(s.writeReady)
	return nil
}

var _ net.Conn = (*Stream)(nil)
