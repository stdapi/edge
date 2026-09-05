// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

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

func newSingleConnListener(c net.Conn, sess *Session) *singleConnListener {
	l := &singleConnListener{
		addr:     c.LocalAddr(),
		done:     make(chan struct{}),
		connDone: make(chan struct{}),
	}
	// Closing the connection closes the listener, so the accept loop set up for it returns
	// instead of blocking forever on a second Accept that will never be served.
	l.conn = &servedConn{Conn: c, sess: sess, l: l}
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
	c.once.Do(func() {
		close(c.l.connDone)
		_ = c.l.Close()
	})
	return err
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

	wmu    sync.Mutex
	closed atomic.Bool
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
	return s.r.Read(b)
}

func (s *h2Stream) Write(b []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed.Load() {
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
	if s.closed.Swap(true) {
		return nil
	}
	// A write in flight returns once the stream is reset, which a deadline in the past does
	// at once. The barrier then leaves the response writer idle for the caller.
	if !s.wmu.TryLock() {
		_ = http.NewResponseController(s.w).SetWriteDeadline(time.Now())
		s.wmu.Lock()
	}
	s.wmu.Unlock()
	return s.body.Close()
}

// CloseWrite ends the proxy-to-client direction. An HTTP/2 stream has no way to do that
// without ending the stream, so it is a no-op and the stream is torn down by Close.
func (s *h2Stream) CloseWrite() error { return nil }

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
	deadline atomic.Pointer[time.Time]
	// buf is the one buffer the reading goroutine fills. It is handed out again only once
	// that goroutine has delivered and rest is drained, so a read never writes into bytes a
	// caller is still holding.
	buf  []byte
	rest []byte
	mu   sync.Mutex
	// pending is set while a read goroutine is still running for this reader.
	pending bool
}

type readResult struct {
	err error
	b   []byte
}

func newDeadlineReader(r io.Reader) *deadlineReader {
	return &deadlineReader{r: r, res: make(chan readResult, 1)}
}

func (d *deadlineReader) setDeadline(t time.Time) { d.deadline.Store(&t) }

func (d *deadlineReader) Read(b []byte) (int, error) {
	d.mu.Lock()
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
	d.mu.Unlock()

	var timeout <-chan time.Time
	if dl := d.deadline.Load(); dl != nil && !dl.IsZero() {
		timer := time.NewTimer(time.Until(*dl))
		defer timer.Stop()
		timeout = timer.C
	}

	select {
	case res := <-d.res:
		d.mu.Lock()
		d.pending = false
		d.err = res.err
		n := copy(b, res.b)
		d.rest = res.b[n:]
		err := d.err
		if n > 0 {
			// The bytes come first; the error is reported on the read that finds nothing
			// left, which is what a socket does.
			err = nil
		}
		d.mu.Unlock()
		return n, err
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	}
}

type emptyAddr struct{}

func (emptyAddr) Network() string { return "peek" }
func (emptyAddr) String() string  { return "peek" }

func getCopyBuf() []byte  { return copyBufPool.Get().(*[copyBufSize]byte)[:] }
func putCopyBuf(b []byte) { copyBufPool.Put((*[copyBufSize]byte)(b[:copyBufSize])) }

// cancelConnOf finds the wrapper under a connection, reaching through the TLS layer
// [Proxy.ServeTLS] adds.
func cancelConnOf(c net.Conn) *cancelConn {
	if cc, ok := c.(*cancelConn); ok {
		return cc
	}
	if tc, ok := c.(*tls.Conn); ok {
		if cc, ok := tc.NetConn().(*cancelConn); ok {
			return cc
		}
	}
	return nil
}

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
				return total, werr
			}
			if w != n {
				return total, io.ErrShortWrite
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
