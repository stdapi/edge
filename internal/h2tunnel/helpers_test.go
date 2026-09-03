// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package h2tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Test helpers: peers of every kind, sockets, and the peer the tables drive.

// echoServer serves CONNECT by echoing the stream, and hands each request to seen.
func echoServer(t *testing.T, seen func(*http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			seen(r)
		}
		if r.Method != http.MethodConnect {
			http.Error(w, "not a CONNECT", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("X-Refuse") != "" {
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				_ = rc.Flush()
			}
			if err != nil {
				return
			}
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func dial(t *testing.T, srv *httptest.Server) *Conn {
	t.Helper()
	cfg := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	cfg.NextProtos = []string{"h2"}
	tc, err := tls.Dial("tcp", srv.Listener.Addr().String(), cfg)
	require.NoError(t, err)
	require.Equal(t, "h2", tc.ConnectionState().NegotiatedProtocol)
	c, err := Client(tc, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func open(t *testing.T, c *Conn, header http.Header) (*Stream, *Response) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, resp, err := c.Open(ctx, Request{Authority: "origin.test:443", Header: header})
	require.NoError(t, err)
	return s, resp
}

// fakePeer is the server end of a TCP connection, reading the client preface, sending the
// settings the test asks for and answering every HEADERS with 200. What it does past that
// is the test's.
type fakePeer struct {
	fr     *http2.Framer
	enc    *hpack.Encoder
	encBuf bytes.Buffer
	wmu    sync.Mutex
	mu     sync.Mutex
	// connWindow is what the client lets the peer send on the connection.
	connWindow int64
}

func startFakePeer(nc net.Conn, settings ...http2.Setting) (*fakePeer, error) {
	p := &fakePeer{fr: http2.NewFramer(nc, nc), connWindow: defaultWindow}
	p.fr.ReadMetaHeaders = hpack.NewDecoder(hpackTableSize, nil)
	p.enc = hpack.NewEncoder(&p.encBuf)
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(nc, preface); err != nil {
		return nil, err
	}
	return p, p.fr.WriteSettings(settings...)
}

func (p *fakePeer) answer(id uint32) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	p.encBuf.Reset()
	_ = p.enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	return p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: p.encBuf.Bytes(), EndHeaders: true})
}

func (p *fakePeer) writeData(id uint32, b []byte) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	p.mu.Lock()
	p.connWindow -= int64(len(b))
	p.mu.Unlock()
	return p.fr.WriteData(id, false, b)
}

func (p *fakePeer) window() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connWindow
}

func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	server = <-accepted
	require.NotNil(t, server)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

// memPipe is a connected pair in memory with a buffer in each direction, so a write never
// waits for a read the way net.Pipe's does. Fuzzing opens one per input, which a TCP pair
// would run the ephemeral ports out with.
func memPipe() (a, b net.Conn) {
	ab, ba := newMemBuf(), newMemBuf()
	return &memConn{r: ba, w: ab}, &memConn{r: ab, w: ba}
}

type memBuf struct {
	mu       sync.Mutex
	cond     *sync.Cond
	buf      []byte
	closed   bool
	deadline time.Time
}

func newMemBuf() *memBuf {
	b := &memBuf{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

type memConn struct {
	r, w *memBuf
}

func (c *memConn) Read(p []byte) (int, error) {
	b := c.r
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.buf) == 0 {
		if b.closed {
			return 0, io.EOF
		}
		if !b.deadline.IsZero() {
			if !time.Now().Before(b.deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			time.AfterFunc(time.Until(b.deadline), b.cond.Broadcast)
		}
		b.cond.Wait()
	}
	n := copy(p, b.buf)
	b.buf = b.buf[n:]
	return n, nil
}

func (c *memConn) Write(p []byte) (int, error) {
	b := c.w
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	b.buf = append(b.buf, p...)
	b.cond.Broadcast()
	return len(p), nil
}

func (c *memConn) Close() error {
	for _, b := range []*memBuf{c.r, c.w} {
		b.mu.Lock()
		b.closed = true
		b.cond.Broadcast()
		b.mu.Unlock()
	}
	return nil
}

func (c *memConn) SetReadDeadline(t time.Time) error {
	c.r.mu.Lock()
	c.r.deadline = t
	c.r.cond.Broadcast()
	c.r.mu.Unlock()
	return nil
}

func (c *memConn) LocalAddr() net.Addr              { return emptyAddr{} }
func (c *memConn) RemoteAddr() net.Addr             { return emptyAddr{} }
func (c *memConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

type emptyAddr struct{}

func (emptyAddr) Network() string { return "mem" }
func (emptyAddr) String() string  { return "mem" }

// stuckPeer answers n streams, then stops reading its socket, and returns the streams
// once the client's writer is stuck on it, the first of them filling the socket.
func stuckPeer(t *testing.T, n int) (*Conn, []*Stream) {
	return silentPeer(t, n, true)
}

// silentPeer answers n streams, then stops reading its socket. With fill, the first stream
// fills the socket so the client's writer is stuck before it returns.
func silentPeer(t *testing.T, n int, fill bool) (*Conn, []*Stream) {
	t.Helper()
	cli, srv := tcpPair(t)
	answered := make(chan struct{}, n)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 24})
		if err != nil {
			return
		}
		_ = peer.fr.WriteWindowUpdate(0, 1<<28)
		seen := 0
		for seen < n {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
				answered <- struct{}{}
				seen++
			}
		}
		// Nothing reads the socket from here on.
	}()
	conn, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	streams := make([]*Stream, 0, n)
	for range n {
		s, _, oerr := conn.Open(ctx, Request{Authority: "origin.test:443"})
		require.NoError(t, oerr)
		<-answered
		streams = append(streams, s)
	}
	if fill {
		go func() { _, _ = streams[0].Write(make([]byte, 64<<20)) }()
		time.Sleep(300 * time.Millisecond)
	}
	return conn, streams
}

// onLoop runs fn on the serve goroutine and returns once it ran, or at once when the
// connection ended.
func (c *Conn) onLoop(fn func()) {
	done := make(chan struct{})
	if c.send(msg{kind: msgFunc, fn: func() { fn(); close(done) }}) {
		select {
		case <-done:
		case <-c.done:
		}
	}
}

// writeHeaders writes any header block, what answer cannot.
func (p *fakePeer) writeHeaders(id uint32, end bool, fields ...hpack.HeaderField) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	p.encBuf.Reset()
	for _, f := range fields {
		_ = p.enc.WriteField(f)
	}
	return p.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      id,
		BlockFragment: p.encBuf.Bytes(),
		EndHeaders:    true,
		EndStream:     end,
	})
}

// peerOn starts a fake peer on srv that runs onHeaders for every HEADERS it reads.
func peerOn(srv net.Conn, onHeaders func(p *fakePeer, id uint32), settings ...http2.Setting) {
	go func() {
		p, err := startFakePeer(srv, settings...)
		if err != nil {
			return
		}
		for {
			f, rerr := p.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok && onHeaders != nil {
				onHeaders(p, mh.StreamID)
			}
		}
	}()
}

// openAsync runs Open on a goroutine and hands back the error it ends with.
func openAsync(c *Conn, req Request) <-chan error {
	ch := make(chan error, 1)
	go func() {
		_, _, err := c.Open(context.Background(), req)
		ch <- err
	}()
	return ch
}

// stuckConn is a socket whose writes stick until the write deadline in force passes, so a
// shutdown is bounded only by the deadline it sets.
type stuckConn struct {
	reads    *memBuf
	closedAt chan time.Time
	mu       sync.Mutex
	deadline time.Time
	stick    bool
	inWrite  bool
}

func newStuckConn() *stuckConn {
	return &stuckConn{reads: newMemBuf(), closedAt: make(chan time.Time, 4)}
}

// feed hands bytes to the client's reader.
func (g *stuckConn) feed(b []byte) {
	g.reads.mu.Lock()
	g.reads.buf = append(g.reads.buf, b...)
	g.reads.cond.Broadcast()
	g.reads.mu.Unlock()
}

func (g *stuckConn) Read(p []byte) (int, error) { return (&memConn{r: g.reads, w: g.reads}).Read(p) }

func (g *stuckConn) Write(p []byte) (int, error) {
	g.mu.Lock()
	stick := g.stick
	g.inWrite = stick
	g.mu.Unlock()
	if !stick {
		return len(p), nil
	}
	for {
		g.mu.Lock()
		dl := g.deadline
		g.mu.Unlock()
		g.reads.mu.Lock()
		closed := g.reads.closed
		g.reads.mu.Unlock()
		if closed || (!dl.IsZero() && !time.Now().Before(dl)) {
			return 0, net.ErrClosed
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (g *stuckConn) SetWriteDeadline(t time.Time) error {
	g.mu.Lock()
	g.deadline = t
	g.mu.Unlock()
	return nil
}

func (g *stuckConn) writing() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inWrite
}

func (g *stuckConn) setStick() {
	g.mu.Lock()
	g.stick = true
	g.mu.Unlock()
}

func (g *stuckConn) Close() error {
	select {
	case g.closedAt <- time.Now():
	default:
	}
	g.reads.mu.Lock()
	g.reads.closed = true
	g.reads.cond.Broadcast()
	g.reads.mu.Unlock()
	return nil
}

func (g *stuckConn) LocalAddr() net.Addr             { return emptyAddr{} }
func (g *stuckConn) RemoteAddr() net.Addr            { return emptyAddr{} }
func (g *stuckConn) SetDeadline(time.Time) error     { return nil }
func (g *stuckConn) SetReadDeadline(time.Time) error { return nil }

// peerWriter feeds frames to the client's read side.
type peerWriter struct{ g *stuckConn }

func (w *peerWriter) Write(p []byte) (int, error) { w.g.feed(p); return len(p), nil }

func newBufioReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }

// creditPeer answers every HEADERS, tracks what the client lets it send on the connection
// and adds back every connection WINDOW_UPDATE.
func creditPeer(t *testing.T, srv net.Conn, answered chan<- uint32, settings ...http2.Setting) *fakePeer {
	t.Helper()
	ready := make(chan *fakePeer, 1)
	go func() {
		peer, err := startFakePeer(srv, settings...)
		if err != nil {
			close(ready)
			return
		}
		ready <- peer
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			switch f := f.(type) {
			case *http2.MetaHeadersFrame:
				_ = peer.answer(f.StreamID)
				answered <- f.StreamID
			case *http2.WindowUpdateFrame:
				if f.StreamID == 0 {
					peer.mu.Lock()
					peer.connWindow += int64(f.Increment)
					peer.mu.Unlock()
				}
			}
		}
	}()
	p := <-ready
	require.NotNil(t, p)
	return p
}

// peer is the far end of a connection, driven in a linear sequence: write what the peer
// sends, want what the client must send back, with every wait bounded.
type peer struct {
	t      *testing.T
	c      *Conn
	nc     net.Conn
	fr     *http2.Framer
	enc    *hpack.Encoder
	encBuf bytes.Buffer
	// nextID is the stream id the client's next HEADERS is expected on.
	nextID uint32
}

const wantTimeout = 3 * time.Second

// newPeer connects a client and reads its preface, sends the peer's SETTINGS and takes the
// ack, so a case starts on a settled connection.
func newPeer(t *testing.T, settings ...http2.Setting) *peer {
	t.Helper()
	p := dialPeer(t)
	p.writeSettings(settings...)
	p.wantSettingsAck()
	return p
}

// dialPeer is newPeer before the peer said anything.
func dialPeer(t *testing.T) *peer {
	t.Helper()
	cli, srv := tcpPair(t)
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	p := &peer{t: t, c: c, nc: srv, fr: http2.NewFramer(srv, srv), nextID: 1}
	p.fr.ReadMetaHeaders = hpack.NewDecoder(hpackTableSize, nil)
	p.fr.SetMaxReadFrameSize(1 << 24)
	p.enc = hpack.NewEncoder(&p.encBuf)
	preface := make([]byte, len(http2.ClientPreface))
	_ = srv.SetReadDeadline(time.Now().Add(wantTimeout))
	_, err = io.ReadFull(srv, preface)
	require.NoError(t, err)
	require.Equal(t, http2.ClientPreface, string(preface), "the client preface, RFC 9113 section 3.4")
	sf := p.wantSettings()
	require.False(t, sf.IsAck(), "the client's first frame is its SETTINGS, RFC 9113 section 3.4")
	return p
}

// readFrame returns the client's next frame, within wantTimeout.
func (p *peer) readFrame() (http2.Frame, error) {
	_ = p.nc.SetReadDeadline(time.Now().Add(wantTimeout))
	return p.fr.ReadFrame()
}

// next returns the client's next frame of type T, passing over the others.
func next[T http2.Frame](p *peer, what string) T {
	p.t.Helper()
	for {
		f, err := p.readFrame()
		require.NoError(p.t, err, "waiting for %s", what)
		if f, ok := f.(T); ok {
			return f
		}
	}
}

func (p *peer) wantSettings() *http2.SettingsFrame {
	p.t.Helper()
	return next[*http2.SettingsFrame](p, "SETTINGS")
}

func (p *peer) wantSettingsAck() {
	p.t.Helper()
	for {
		f := next[*http2.SettingsFrame](p, "SETTINGS ack")
		if f.IsAck() {
			return
		}
	}
}

// wantHeaders returns the client's next HEADERS, on the stream id expected next.
func (p *peer) wantHeaders() *http2.MetaHeadersFrame {
	p.t.Helper()
	f := next[*http2.MetaHeadersFrame](p, "HEADERS")
	require.Equal(p.t, p.nextID, f.StreamID, "stream ids go up by two, RFC 9113 section 5.1.1")
	p.nextID += 2
	return f
}

func (p *peer) wantData(id uint32) *http2.DataFrame {
	p.t.Helper()
	for {
		f := next[*http2.DataFrame](p, "DATA")
		if f.StreamID == id {
			return f
		}
	}
}

func (p *peer) wantRST(id uint32, code http2.ErrCode) {
	p.t.Helper()
	f := next[*http2.RSTStreamFrame](p, "RST_STREAM")
	require.Equal(p.t, id, f.StreamID)
	require.Equal(p.t, code, f.ErrCode)
}

func (p *peer) wantGoAway(code http2.ErrCode) *http2.GoAwayFrame {
	p.t.Helper()
	f := next[*http2.GoAwayFrame](p, "GOAWAY")
	require.Equal(p.t, code, f.ErrCode)
	return f
}

func (p *peer) wantWindowUpdate(id uint32) uint32 {
	p.t.Helper()
	for {
		f := next[*http2.WindowUpdateFrame](p, "WINDOW_UPDATE")
		if f.StreamID == id {
			return f.Increment
		}
	}
}

func (p *peer) wantPingAck(data [8]byte) {
	p.t.Helper()
	for {
		f := next[*http2.PingFrame](p, "PING ack")
		if f.IsAck() {
			require.Equal(p.t, data, f.Data)
			return
		}
	}
}

// wantClosed reads to the end of the socket, which the client closes within closeTimeout
// of a connection error.
func (p *peer) wantClosed() {
	p.t.Helper()
	for {
		if _, err := p.readFrame(); err != nil {
			require.False(p.t, errors.Is(err, os.ErrDeadlineExceeded), "the client kept the socket open")
			return
		}
	}
}

// wantConnectionError is what a connection error looks like from the peer, RFC 9113
// section 5.4.1: a GOAWAY with the code, then the socket closed, and the connection ended.
func (p *peer) wantConnectionError(code http2.ErrCode) {
	p.t.Helper()
	p.wantGoAway(code)
	p.wantClosed()
	select {
	case <-p.c.Done():
	case <-time.After(wantTimeout):
		p.t.Fatal("the connection did not end")
	}
	require.Error(p.t, p.c.Err())
}

// wantStreamError is what a stream error looks like from the peer, RFC 9113 section 5.4.2:
// a RST_STREAM with the code, the connection going on.
func (p *peer) wantStreamError(id uint32, code http2.ErrCode) {
	p.t.Helper()
	p.wantRST(id, code)
	p.wantAlive()
}

// wantAlive proves the connection goes on with a PING the client answers.
func (p *peer) wantAlive() {
	p.t.Helper()
	data := [8]byte{'a', 'l', 'i', 'v', 'e'}
	p.writePing(false, data)
	p.wantPingAck(data)
	require.NoError(p.t, p.c.Err())
}

// wantNothing reads for a while and fails on any frame of type T.
func wantNothing[T http2.Frame](p *peer, what string) {
	p.t.Helper()
	_ = p.nc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			require.True(p.t, errors.Is(err, os.ErrDeadlineExceeded), "the socket ended waiting for no %s: %v", what, err)
			return
		}
		if _, ok := f.(T); ok {
			p.t.Fatalf("the client sent %s: %v", what, f)
		}
	}
}

func (p *peer) writeSettings(settings ...http2.Setting) {
	require.NoError(p.t, p.fr.WriteSettings(settings...))
}

func (p *peer) writeSettingsAck() {
	require.NoError(p.t, p.fr.WriteSettingsAck())
}

// writeHeaders sends a header block, END_HEADERS set, on id.
func (p *peer) writeHeaders(id uint32, end bool, fields ...hpack.HeaderField) {
	p.t.Helper()
	require.NoError(p.t, p.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: p.block(fields...), EndHeaders: true, EndStream: end,
	}))
}

// writeBlock sends a header block as given, END_HEADERS set, on id.
func (p *peer) writeBlock(id uint32, end bool, block []byte) {
	p.t.Helper()
	require.NoError(p.t, p.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: block, EndHeaders: true, EndStream: end,
	}))
}

// block encodes fields with the peer's encoder.
func (p *peer) block(fields ...hpack.HeaderField) []byte {
	p.encBuf.Reset()
	for _, f := range fields {
		_ = p.enc.WriteField(f)
	}
	return bytes.Clone(p.encBuf.Bytes())
}

func status(code string) hpack.HeaderField {
	return hpack.HeaderField{Name: ":status", Value: code}
}

// answer sends 200 on id.
func (p *peer) answer(id uint32) {
	p.t.Helper()
	p.writeHeaders(id, false, status("200"))
}

func (p *peer) writeData(id uint32, end bool, b []byte) {
	require.NoError(p.t, p.fr.WriteData(id, end, b))
}

func (p *peer) writeRST(id uint32, code http2.ErrCode) {
	require.NoError(p.t, p.fr.WriteRSTStream(id, code))
}

func (p *peer) writePing(ack bool, data [8]byte) {
	require.NoError(p.t, p.fr.WritePing(ack, data))
}

func (p *peer) writeGoAway(last uint32, code http2.ErrCode) {
	require.NoError(p.t, p.fr.WriteGoAway(last, code, nil))
}

func (p *peer) writeWindowUpdate(id, inc uint32) {
	require.NoError(p.t, p.fr.WriteWindowUpdate(id, inc))
}

func (p *peer) writePriority(id uint32, prio http2.PriorityParam) {
	require.NoError(p.t, p.fr.WritePriority(id, prio))
}

// writeRaw sends one frame byte by byte, for what the framer would not write.
func (p *peer) writeRaw(typ http2.FrameType, flags http2.Flags, id uint32, payload []byte) {
	p.t.Helper()
	hdr := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), byte(typ), byte(flags)}
	hdr = binary.BigEndian.AppendUint32(hdr, id)
	_, err := p.nc.Write(append(hdr, payload...))
	require.NoError(p.t, err)
}

// open starts a CONNECT on a goroutine and returns what it ends with through wait.
func (p *peer) open(req Request) *opening {
	o := &opening{done: make(chan struct{})}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), wantTimeout)
		defer cancel()
		o.s, o.resp, o.err = p.c.Open(ctx, req)
		close(o.done)
	}()
	return o
}

type opening struct {
	s    *Stream
	resp *Response
	err  error
	done chan struct{}
}

func (o *opening) wait(t *testing.T) (*Stream, *Response, error) {
	t.Helper()
	select {
	case <-o.done:
	case <-time.After(wantTimeout):
		t.Fatal("Open did not return")
	}
	return o.s, o.resp, o.err
}

// connect opens a CONNECT the peer answers with 200, and returns the stream and its id.
func (p *peer) connect() (*Stream, uint32) {
	p.t.Helper()
	o := p.open(Request{Authority: "origin.test:443"})
	id := p.wantHeaders().StreamID
	p.answer(id)
	s, resp, err := o.wait(p.t)
	require.NoError(p.t, err)
	require.Equal(p.t, http.StatusOK, resp.StatusCode)
	return s, id
}

// read returns what the stream reads next, within wantTimeout.
func (p *peer) read(s *Stream) ([]byte, error) {
	p.t.Helper()
	_ = s.SetReadDeadline(time.Now().Add(wantTimeout))
	buf := make([]byte, 1<<16)
	n, err := s.Read(buf)
	return buf[:n], err
}

// wantReadAll wants the stream to read n bytes, in as many reads as it takes.
func (p *peer) wantReadAll(s *Stream, n int) []byte {
	p.t.Helper()
	_ = s.SetReadDeadline(time.Now().Add(wantTimeout))
	buf := make([]byte, n)
	_, err := io.ReadFull(s, buf)
	require.NoError(p.t, err)
	return buf
}

// wantRead wants the stream to read exactly b next.
func (p *peer) wantRead(s *Stream, b []byte) {
	p.t.Helper()
	got, err := p.read(s)
	require.NoError(p.t, err)
	require.Equal(p.t, b, got)
}

// wantReadError wants the stream's reads to end with err.
func (p *peer) wantReadError(s *Stream, err error) {
	p.t.Helper()
	_, got := p.read(s)
	require.ErrorIs(p.t, got, err)
}

// wantReadCode wants the stream's reads to end with a stream error of code.
func (p *peer) wantReadCode(s *Stream, code http2.ErrCode) {
	p.t.Helper()
	_, err := p.read(s)
	var se http2.StreamError
	require.ErrorAs(p.t, err, &se, "read ended with %v", err)
	require.Equal(p.t, code, se.Code)
}
