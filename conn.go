// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	copyBufSize = 32 * 1024
	// halfClosedIdleTimeout bounds how long the remaining direction of a relay may sit silent
	// once the other one is done.
	halfClosedIdleTimeout = 30 * time.Second
	defaultPeekSize       = 4096
)

var copyBufPool = sync.Pool{New: func() any { return new([copyBufSize]byte) }}

// peekConn is a net.Conn that reads ahead for a sniff and hands the bytes on. The read-ahead
// is released once consumed, so a placed connection keeps no buffer of its own.
type peekConn struct {
	net.Conn
	buf []byte
	max int
}

func newPeekConn(c net.Conn, buffered []byte, max int) *peekConn {
	return &peekConn{Conn: c, buf: buffered[:len(buffered):len(buffered)], max: max}
}

func (c *peekConn) Read(b []byte) (int, error) {
	if len(c.buf) == 0 {
		return c.Conn.Read(b)
	}
	n := copy(b, c.buf)
	c.buf = c.buf[n:]
	if len(c.buf) == 0 {
		c.buf = nil
	}
	return n, nil
}

func (c *peekConn) Buffered() int { return len(c.buf) }

// Peek returns the next n bytes without consuming them, [bufio.ErrBufferFull] past max, and
// what arrived before a read error.
func (c *peekConn) Peek(n int) ([]byte, error) {
	if n > c.max {
		return c.buf, bufio.ErrBufferFull
	}
	empty := 0
	for len(c.buf) < n {
		if cap(c.buf) < n {
			grown := make([]byte, len(c.buf), min(c.max, max(n, 2*cap(c.buf), defaultPeekSize)))
			copy(grown, c.buf)
			c.buf = grown
		}
		m, err := c.Conn.Read(c.buf[len(c.buf):cap(c.buf)])
		c.buf = c.buf[:len(c.buf)+m]
		if err != nil {
			return c.buf, err
		}
		if m == 0 {
			empty++
			if empty == 100 {
				return c.buf, io.ErrNoProgress
			}
		}
	}
	return c.buf[:n], nil
}

// CloseWrite forwards the half-close, which the embedded net.Conn does not promote.
func (c *peekConn) CloseWrite() error { return closeWrite(c.Conn) }

func (c *peekConn) Abort() { abort(c.Conn) }

// closeWriter is implemented by connections that can be half-closed, which is how a relay
// tells the far end that one direction is done without tearing down the other.
type closeWriter interface {
	CloseWrite() error
}

// singleConnListener hands a single connection to a net.Listener consumer and then reports
// that it is closed. It is how one already-accepted connection is served by http.Server,
// which has no ServeConn.
type singleConnListener struct {
	conn net.Conn
	addr net.Addr
	// done releases the accept loop; connDone only closes with the connection itself. They
	// are separate because a shutdown closes the listener while the connection may still be
	// serving a request, and the two events must not be mistaken for one another.
	done     chan struct{}
	connDone chan struct{}
	once     sync.Once
	mu       sync.Mutex
	taken    bool
}

func newSingleConnListener(c net.Conn, sess *Session, state *tls.ConnectionState) *singleConnListener {
	l := &singleConnListener{
		addr:     c.LocalAddr(),
		done:     make(chan struct{}),
		connDone: make(chan struct{}),
	}
	// Closing the connection closes the listener, so the accept loop set up for it returns
	// instead of blocking forever on a second Accept that will never be served.
	sc := &servedConn{Conn: c, sess: sess, l: l}
	l.conn = sc
	if state != nil {
		l.conn = &tlsServedConn{servedConn: sc, state: state}
	}
	return l
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	if c != nil {
		l.taken = true
	}
	l.mu.Unlock()

	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.addr }

// wait blocks until the served connection is closed. The transport under it belongs to the
// caller of Serve and dies the moment that caller returns, while Serve itself returns as
// soon as the listener closes, which a shutdown does with the connection still serving a
// request. Waiting on the connection rather than on Serve is what lets that request finish.
//
// A connection Serve never accepted is not waited on: Serve refused it before taking it
// over, so it never closes, and the caller still owns it.
func (l *singleConnListener) wait() {
	l.mu.Lock()
	taken := l.taken
	l.mu.Unlock()
	if taken {
		<-l.connDone
	}
}

// servedConn is the connection handed to http.Server for an intercepted connection. It
// carries the session so ConnContext can attach it to every request read off the
// connection, and it closes its listener so the accept loop ends with it.
type servedConn struct {
	net.Conn
	sess *Session
	l    *singleConnListener
	once sync.Once
}

func (c *servedConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

func (c *servedConn) Abort() {
	abort(c.Conn)
	c.release()
}

func (c *servedConn) release() {
	c.once.Do(func() {
		close(c.l.connDone)
		_ = c.l.Close()
	})
}

// tlsServedConn gives http.Server the handshake of a terminated TLS connection, so that ALPN
// selects HTTP/2 or HTTP/1.1, RFC 7301 section 3.2.
type tlsServedConn struct {
	*servedConn
	state *tls.ConnectionState
}

func (c *tlsServedConn) ConnectionState() tls.ConnectionState { return *c.state }

func servedConnOf(c net.Conn) *servedConn {
	switch c := c.(type) {
	case *servedConn:
		return c
	case *tlsServedConn:
		return c.servedConn
	}
	return nil
}

// cancelConn fires the cancel of the session context from Close. Every close path in
// net/http and in this package funnels through Close, so one hook covers them all.
type cancelConn struct {
	net.Conn
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
}

func (c *cancelConn) arm(cancel context.CancelFunc) {
	c.mu.Lock()
	closed := c.closed
	if !closed {
		c.cancel = cancel
	}
	c.mu.Unlock()
	if closed {
		cancel()
	}
}

func (c *cancelConn) Close() error {
	err := c.Conn.Close()
	c.mu.Lock()
	cancel := c.cancel
	c.cancel = nil
	c.closed = true
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return err
}

func (c *cancelConn) Abort() {
	lingerZero(c.Conn)
	_ = c.Close()
}

// CloseWrite forwards the half-close, which the embedded net.Conn does not promote.
func (c *cancelConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// cancelListener wraps the front listeners so each accepted connection can carry the
// cancel of its session context.
type cancelListener struct {
	net.Listener
}

func (l cancelListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// Wrapping a connection that already carries TLS would hide the handshake from
	// net/http, so it is served untouched and its session context never ends.
	if _, ok := c.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return c, nil
	}
	return &cancelConn{Conn: c}, nil
}

// idleTracker closes both ends of a relay once neither direction has moved a byte for the
// configured duration. A zero duration leaves it disarmed until a half-close arms it, since a
// relay open in both directions can legitimately carry a long-lived silent stream.
type idleTracker struct {
	timer   *time.Timer
	conns   []net.Conn
	timeout time.Duration
	armed   atomic.Bool
	mu      sync.Mutex
	stopped bool
}

func newIdleTracker(timeout time.Duration, conns ...net.Conn) *idleTracker {
	t := &idleTracker{timeout: timeout, conns: conns}
	if timeout > 0 {
		t.start(timeout)
	}
	return t
}

// arm starts the timer when none is running, which is what a half-close does.
func (t *idleTracker) arm(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped || t.timer != nil {
		return
	}
	t.start(d)
}

// start must be called with the lock held, or before the tracker is shared.
func (t *idleTracker) start(d time.Duration) {
	t.timeout = d
	t.timer = time.AfterFunc(d, func() {
		for _, c := range t.conns {
			_ = c.Close()
		}
	})
	t.armed.Store(true)
}

// touch is a no-op on a nil tracker, which is what a copy with no idleness to track passes.
func (t *idleTracker) touch() {
	if t == nil || !t.armed.Load() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.stopped {
		t.timer.Reset(t.timeout)
	}
}

func (t *idleTracker) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = true
	if t.timer != nil {
		t.timer.Stop()
	}
}

// h2Stream adapts an HTTP/2 or HTTP/3 CONNECT stream to a net.Conn, so the same termination
// code serves it as an HTTP/1.1 hijacked connection.
//
// Writes are serialized and refused once the stream is closed. A response writer is only
// valid while its handler runs, and the HTTP/2 server writes some frames from goroutines it
// does not wait for: without the guard, one of those could reach the writer after the
// CONNECT handler returned.
type h2Stream struct {
	r       *deadlineReader
	body    io.ReadCloser
	w       http.ResponseWriter
	flusher http.Flusher
	local   net.Addr
	remote  net.Addr

	cmu      sync.Mutex
	wmu      sync.Mutex
	closed   atomic.Bool
	aborted  atomic.Bool
	sent     bool // guarded by wmu
	finished bool // guarded by cmu
}

func newH2Stream(w http.ResponseWriter, r *http.Request, local, remote net.Addr) *h2Stream {
	s := &h2Stream{r: newDeadlineReader(r.Body), body: r.Body, w: w, local: local, remote: remote}
	if f, ok := w.(http.Flusher); ok {
		s.flusher = f
	}
	return s
}

func (s *h2Stream) Read(b []byte) (int, error) {
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := s.r.Read(b)
	if err != nil {
		if se, ok := errors.AsType[*quic.StreamError](err); ok && se.Remote {
			// RFC 9114 4.4, a client resetting its direction has the proxy reset the other.
			if hs, ok := s.w.(http3.HTTPStreamer); ok {
				s.reset(hs, http3.ErrCodeRequestCanceled)
			}
		}
	}
	return n, err
}

// writeHeader writes and flushes the response header under the write lock, so a stream closed
// first gets no header and a reset waits for a header being written before it flushes the writer.
func (s *h2Stream) writeHeader(code int) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed.Load() {
		return
	}
	s.w.WriteHeader(code)
	if s.flusher != nil {
		s.flusher.Flush()
	}
}

func (s *h2Stream) Write(b []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed.Load() || s.sent {
		return 0, net.ErrClosed
	}

	n, err := s.w.Write(b)
	// A CONNECT stream is a byte pipe with no framing of its own: without an explicit
	// flush the data sits in the response buffer until enough of it accumulates.
	if s.flusher != nil {
		s.flusher.Flush()
	}
	return n, err
}

func (s *h2Stream) Close() error {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if !s.stop(false) {
		return nil
	}
	return s.body.Close()
}

// stop refuses every later write and reports whether the stream was open. With reset, or when a
// write is in flight, it resets an HTTP/2 stream. The caller holds cmu.
func (s *h2Stream) stop(reset bool) bool {
	if s.closed.Swap(true) {
		return false
	}
	// A deadline in the past resets the stream at once. The write in flight returns only once
	// the reset is written to the connection, which a client that stopped reading delays.
	if reset || !s.wmu.TryLock() {
		_ = http.NewResponseController(s.w).SetWriteDeadline(time.Now())
		return true
	}
	s.wmu.Unlock()
	return true
}

// idle returns once no write is in flight.
func (s *h2Stream) idle() {
	s.wmu.Lock()
	s.wmu.Unlock() //nolint:staticcheck // an empty section is the barrier
}

// Abort closes the stream and resets it, an HTTP/3 stream with H3_CONNECT_ERROR and an HTTP/2
// stream with INTERNAL_ERROR.
func (s *h2Stream) Abort() {
	hs, ok := s.w.(http3.HTTPStreamer)
	if ok {
		s.reset(hs, http3.ErrCodeConnectError)
		return
	}
	// A stream already closed is reset by its handler on return.
	s.aborted.Store(true)
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if s.finished || !s.stop(true) {
		return
	}
	_ = s.body.Close()
}

// streamCut ends a CONNECT stream with a reset when [Session.Close] or a shutdown cut closes it.
// A clean end would read as the origin closing the connection, RFC 9113 section 8.5.
type streamCut struct{ s *h2Stream }

func (c streamCut) Close() error {
	c.s.Abort()
	return nil
}

func (s *h2Stream) reset(hs http3.HTTPStreamer, code http3.ErrCode) {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if s.finished {
		return
	}
	// HTTPStream flushes the response writer, so stop first ends any write in flight. Closing
	// the body cancels the read with a code of its own, so it comes last.
	open := s.stop(false)
	s.idle()
	str := hs.HTTPStream()
	str.CancelWrite(quic.StreamErrorCode(code))
	str.CancelRead(quic.StreamErrorCode(code))
	if open {
		_ = s.body.Close()
	}
}

// finish closes the stream before its handler returns. The response writer is invalid past that
// return, and every later call on the stream leaves it alone.
func (s *h2Stream) finish() {
	s.cmu.Lock()
	s.finished = true
	if s.stop(false) {
		_ = s.body.Close()
	}
	s.cmu.Unlock()
	s.idle()
}

// CloseWrite ends the proxy-to-client direction of an HTTP/3 stream, which goes on receiving. An
// HTTP/2 handler cannot end its half of a stream alone, so on HTTP/2 it is a no-op.
func (s *h2Stream) CloseWrite() error {
	hs, ok := s.w.(http3.HTTPStreamer)
	if !ok {
		return nil
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	if s.sent {
		return nil
	}
	s.sent = true
	return hs.HTTPStream().Close()
}

func (s *h2Stream) LocalAddr() net.Addr  { return s.local }
func (s *h2Stream) RemoteAddr() net.Addr { return s.remote }

func (s *h2Stream) SetDeadline(t time.Time) error { return s.SetReadDeadline(t) }

// SetReadDeadline bounds a read the way a socket would. An HTTP/2 request body has no
// deadline of its own, and the protocol sniff needs one: without it a stream carrying a
// server-first protocol parks the read forever instead of being served as the byte stream it
// is.
func (s *h2Stream) SetReadDeadline(t time.Time) error {
	s.r.setDeadline(t)
	return nil
}

// SetWriteDeadline bounds the writes that follow. Past it the server resets the stream and a
// blocked write returns.
func (s *h2Stream) SetWriteDeadline(t time.Time) error {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	return http.NewResponseController(s.w).SetWriteDeadline(t)
}

// deadlineReader gives a reader that has no deadline of its own one, by keeping at most one
// read outstanding and handing back what it produced on the next call. A read the deadline cut
// short is not lost: it is still running, and its result is the first thing the next read
// sees.
type deadlineReader struct {
	r        io.Reader
	err      error
	res      chan readResult
	deadline time.Time
	// changed is closed when the deadline moves under a blocked read.
	changed chan struct{}
	// buf is the one buffer the reading goroutine fills. It is handed out again only once
	// that goroutine has delivered and rest is drained, so a read never writes into bytes a
	// caller is still holding.
	buf  []byte
	rest []byte
	mu   sync.Mutex
	// pending is set while a read goroutine is still running for this reader.
	pending bool
	waiting int
}

type readResult struct {
	err error
	b   []byte
}

func newDeadlineReader(r io.Reader) *deadlineReader {
	return &deadlineReader{r: r, res: make(chan readResult, 1)}
}

func (d *deadlineReader) setDeadline(t time.Time) {
	d.mu.Lock()
	d.deadline = t
	d.wakeLocked()
	d.mu.Unlock()
}

// wakeLocked wakes the blocked reads, which look again at the deadline, the bytes left and the
// error. d.mu must be held.
func (d *deadlineReader) wakeLocked() {
	if d.waiting > 0 && d.changed != nil {
		close(d.changed)
		d.changed = nil
	}
}

func (d *deadlineReader) Read(b []byte) (int, error) {
	d.mu.Lock()
	for {
		if len(d.rest) > 0 {
			n := copy(b, d.rest)
			d.rest = d.rest[n:]
			d.mu.Unlock()
			return n, nil
		}
		if d.err != nil {
			err := d.err
			d.mu.Unlock()
			return 0, err
		}
		if !d.pending {
			d.pending = true
			if cap(d.buf) < len(b) {
				d.buf = make([]byte, max(len(b), copyBufSize))
			}
			buf := d.buf[:cap(d.buf)]
			go func() {
				n, err := d.r.Read(buf)
				d.res <- readResult{b: buf[:n], err: err}
			}()
		}

		deadline := d.deadline
		if d.changed == nil {
			d.changed = make(chan struct{})
		}
		changed := d.changed
		d.waiting++
		d.mu.Unlock()

		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}

		var res readResult
		got := false
		select {
		case res = <-d.res:
			got = true
		case <-timeout:
		case <-changed:
		}
		if timer != nil {
			timer.Stop()
		}
		d.mu.Lock()
		d.waiting--
		if !got {
			if changed != d.changed {
				continue
			}
			d.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}

		d.pending = false
		d.err = res.err
		n := copy(b, res.b)
		d.rest = res.b[n:]
		d.wakeLocked()
		err := d.err
		if n > 0 {
			// The bytes come first; the error is reported on the read that finds nothing
			// left, which is what a socket does.
			err = nil
		}
		d.mu.Unlock()
		return n, err
	}
}

type emptyAddr struct{}

func (emptyAddr) Network() string { return "peek" }
func (emptyAddr) String() string  { return "peek" }

func getCopyBuf() []byte  { return copyBufPool.Get().(*[copyBufSize]byte)[:] }
func putCopyBuf(b []byte) { copyBufPool.Put((*[copyBufSize]byte)(b[:copyBufSize])) }

// cancelConnOf finds the wrapper under a connection, reaching through the TLS layer
// [Proxy.ServeTLS] adds and the schemeConn over it.
func cancelConnOf(c net.Conn) *cancelConn {
	for {
		switch cc := c.(type) {
		case *cancelConn:
			return cc
		case interface{ NetConn() net.Conn }:
			c = cc.NetConn()
		default:
			return nil
		}
	}
}

// writeError is an error of the destination of a copy, which is how the end of a copy is
// passed to the side that did not fail.
type writeError struct{ error }

func (e writeError) Unwrap() error { return e.error }

func copyStream(dst io.Writer, src io.Reader, idle *idleTracker) (int64, error) {
	buf := getCopyBuf()
	defer putCopyBuf(buf)

	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			idle.touch()
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total, writeError{werr}
			}
			if w != n {
				return total, writeError{io.ErrShortWrite}
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return total, nil
			}
			return total, rerr
		}
	}
}

func halfClose(c net.Conn) { _ = closeWrite(c) }

// endCopy passes the end of a copy from src to dst on. A clean end half-closes dst, and a
// failure of either side resets the other.
func endCopy(src, dst net.Conn, err error) {
	switch {
	case filterCopyErr(err) == nil:
		halfClose(dst)
	case errors.As(err, new(writeError)):
		abort(src)
	default:
		abort(dst)
	}
}

// aborter is implemented by connections that can end so their peer reads a failure, a reset
// TCP connection or a reset stream.
type aborter interface {
	Abort()
}

// abort ends c so its peer reads a failure where a close reads a clean end.
func abort(c net.Conn) {
	switch c := c.(type) {
	case aborter:
		c.Abort()
	case *tls.Conn:
		// Closing the TLS layer sends close_notify, which reads as a clean end.
		abort(c.NetConn())
	case *net.TCPConn:
		_ = c.SetLinger(0)
		_ = c.Close()
	default:
		_ = c.Close()
	}
}

// tlsConn wraps the TLS connections the proxy serves and dials itself. crypto/tls gives its
// close_notify a write deadline of five seconds, and a peer that stopped reading makes a close
// last that long.
type tlsConn struct {
	*tls.Conn
	socket tlsSocket
}

func tlsServer(c net.Conn, cfg *tls.Config) *tlsConn {
	tc := &tlsConn{socket: tlsSocket{Conn: c}}
	tc.Conn = tls.Server(&tc.socket, cfg)
	return tc
}

func tlsClient(c net.Conn, cfg *tls.Config) *tlsConn {
	tc := &tlsConn{socket: tlsSocket{Conn: c}}
	tc.Conn = tls.Client(&tc.socket, cfg)
	return tc
}

// The first Close or CloseWrite also bounds a write already blocked, such as an alert of the
// reader, which crypto/tls sends under the lock the close_notify waits for.
func (c *tlsConn) Close() error {
	if !c.socket.closing.Swap(true) {
		_ = c.socket.SetWriteDeadline(time.Time{})
	}
	return c.Conn.Close()
}

func (c *tlsConn) CloseWrite() error {
	if !c.socket.closing.Swap(true) {
		_ = c.socket.SetWriteDeadline(time.Time{})
	}
	return c.Conn.CloseWrite()
}

func (c *tlsConn) Abort() { abort(c.socket.Conn) }

func (c *tlsConn) NetConn() net.Conn { return c.socket.Conn }

type tlsSocket struct {
	net.Conn
	closing atomic.Bool
	failed  atomic.Bool
}

func (s *tlsSocket) Write(b []byte) (int, error) {
	n, err := s.Conn.Write(b)
	if err != nil {
		s.failed.Store(true)
	}
	return n, err
}

// SetWriteDeadline caps every write deadline at alertWriteTimeout once a close has begun. After
// a failed write the deadline expires at once, as the peer could not decrypt a later record.
func (s *tlsSocket) SetWriteDeadline(t time.Time) error {
	if s.closing.Load() {
		now := time.Now()
		switch {
		case s.failed.Load():
			t = now
		case t.IsZero() || t.After(now.Add(alertWriteTimeout)):
			t = now.Add(alertWriteTimeout)
		}
	}
	return s.Conn.SetWriteDeadline(t)
}

// SetDeadline keeps the write deadline under the cap of SetWriteDeadline.
func (s *tlsSocket) SetDeadline(t time.Time) error {
	if !s.closing.Load() {
		return s.Conn.SetDeadline(t)
	}
	if err := s.SetReadDeadline(t); err != nil {
		return err
	}
	return s.SetWriteDeadline(t)
}

// tlsListener is [tls.NewListener] for a [tlsConn].
type tlsListener struct {
	net.Listener
	cfg *tls.Config
}

func (l tlsListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return tlsServer(c, l.cfg), nil
}

func lingerZero(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
}

// closeWrite ends the write direction of c, or closes it when it cannot half-close.
func closeWrite(c net.Conn) error {
	if cw, ok := c.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// filterCopyErr drops the errors that are the normal end of a relay rather than a fault.
func filterCopyErr(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return nil
	}
	return err
}

var _ net.Conn = (*h2Stream)(nil)
