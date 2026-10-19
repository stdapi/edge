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
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stdapi/edge/internal/netutil"
)

const (
	copyBufSize     = 32 * 1024
	defaultPeekSize = 4096
)

var copyBufPool = sync.Pool{New: func() any { return new([copyBufSize]byte) }}

// peekConn is a net.Conn that reads ahead for a sniff and hands the bytes on. The read-ahead
// is released once consumed, so a placed connection keeps no buffer of its own.
type peekConn struct {
	net.Conn
	// err is the error a read of Peek returned, which a socket reports once, so Read returns it
	// once the bytes before it are delivered. A timeout stays out of it, since a later read may
	// succeed.
	err error
	buf []byte
	max int
	// lateHello has the first read refuse a TLS ClientHello, set on a connection placed at its
	// sniff timeout, which the proxy can no longer terminate.
	lateHello bool
}

// errLateClientHello ends a connection placed as a byte stream after its client began TLS.
var errLateClientHello = errors.New("edge: a ClientHello after the sniff timeout, which the proxy cannot terminate")

func newPeekConn(c net.Conn, buffered []byte, max int) *peekConn {
	return &peekConn{Conn: c, buf: buffered[:len(buffered):len(buffered)], max: max}
}

func (c *peekConn) Read(b []byte) (int, error) {
	if c.lateHello {
		hello, err := c.clientHello()
		if hello {
			return 0, errLateClientHello
		}
		if isTimeout(err) {
			// A read that times out before the first bytes decides nothing.
			return 0, err
		}
		// The bytes buffered are delivered first, then the error of the peek.
		c.lateHello = false
	}
	if len(c.buf) == 0 {
		if err := c.err; err != nil {
			c.err = nil
			return 0, err
		}
		return c.Conn.Read(b)
	}
	n := copy(b, c.buf)
	c.buf = c.buf[n:]
	if len(c.buf) == 0 {
		c.buf = nil
	}
	return n, nil
}

// clientHello reports whether the next bytes are the record header of a TLS ClientHello, with
// the error of the read that left the question open.
func (c *peekConn) clientHello() (bool, error) {
	head, err := c.Peek(1)
	if err != nil || head[0] != tlsHandshakeRecord {
		return false, err
	}
	head, err = c.Peek(6)
	if err != nil {
		return false, err
	}
	return head[1] == 0x03 && head[5] == tlsClientHello, nil
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
		if c.err != nil {
			return c.buf, c.err
		}
		if cap(c.buf) < n {
			grown := make([]byte, len(c.buf), min(c.max, max(n, 2*cap(c.buf), defaultPeekSize)))
			copy(grown, c.buf)
			c.buf = grown
		}
		m, err := c.Conn.Read(c.buf[len(c.buf):cap(c.buf)])
		c.buf = c.buf[:len(c.buf)+m]
		if err != nil {
			if !isTimeout(err) {
				c.err = err
			}
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

// connQueue is the listener of a server the proxy hands connections to, the front's accept
// loop deciding which server serves each.
type connQueue struct {
	addr   net.Addr
	conns  chan net.Conn
	done   chan struct{}
	once   sync.Once
	closed atomic.Bool
}

func newConnQueue(addr net.Addr) *connQueue {
	return &connQueue{addr: addr, conns: make(chan net.Conn), done: make(chan struct{})}
}

// push hands c to the server, and reports false once the queue is closed, the server shut
// down.
func (q *connQueue) push(c net.Conn) bool {
	if q.closed.Load() {
		return false
	}
	select {
	case q.conns <- c:
		return true
	case <-q.done:
		return false
	}
}

func (q *connQueue) Accept() (net.Conn, error) {
	select {
	case c := <-q.conns:
		return c, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

func (q *connQueue) Close() error {
	q.once.Do(func() {
		q.closed.Store(true)
		close(q.done)
	})
	return nil
}

func (q *connQueue) Addr() net.Addr { return q.addr }

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

// servedOf returns the servedConn of a connection accepted from a singleConnListener.
func servedOf(c net.Conn) *servedConn {
	if t, ok := c.(*tlsServedConn); ok {
		return t.servedConn
	}
	return c.(*servedConn)
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

// isTaken reports whether a server accepted the connection.
func (l *singleConnListener) isTaken() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.taken
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
	// begun runs at the first byte read, set while the drain may end the connection.
	begun atomic.Pointer[func()]
	once  sync.Once
	// timedOut is that of sessionCancel, for the read header timeout, and ending that of
	// sessionCancel, past which a timeout is no read header timeout.
	timedOut atomic.Bool
	ending   atomic.Bool
}

func (c *servedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil && isTimeout(err) {
		c.timedOut.Store(true)
	}
	if n > 0 && c.begun.Load() != nil {
		if f := c.begun.Swap(nil); f != nil {
			(*f)()
		}
	}
	return n, err
}

func (c *servedConn) Close() error {
	if c.timedOut.Load() && !c.ending.Load() && (c.sess == nil || !c.sess.requested.Load() && c.sess.end.first() == causeNone) {
		// The read header timeout is a failed cause, docs/lifecycle.md Timers.
		c.Abort()
		return nil
	}
	err := c.Conn.Close()
	c.release()
	return err
}

// CloseWrite forwards the half-close, which the embedded net.Conn does not promote.
func (c *servedConn) CloseWrite() error { return closeWrite(c.Conn) }

func (c *servedConn) Abort() {
	abort(c.Conn)
	c.release()
}

func (c *servedConn) release() {
	c.once.Do(func() {
		if c.sess != nil && c.sess.p != nil {
			// The requests read off the connection end with it.
			c.sess.endRequests()
		}
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

// sessionCancel fires the cancel of a session context once its connection closed. Every close
// path in net/http and in this package funnels through Close, so one hook covers them all.
type sessionCancel struct {
	cancel context.CancelFunc
	// sess is the session of the connection, set by the ConnContext of its server while a cut
	// may close the connection, and timedOut is set once a read of it timed out.
	sess atomic.Pointer[Session]
	// done is closed once the connection closed, made on first use under mu.
	done     chan struct{}
	mu       sync.Mutex
	closed   bool
	timedOut atomic.Bool
	// ending is set once the normal end of the connection began, the timeouts of its read and
	// discard then being no read header timeout.
	ending atomic.Bool
	// peer is how the peer ended the connection as a read or a failed write reported it,
	// peerClean or peerFailed, zero before.
	peer atomic.Uint32
	// halfClosed is set once the connection half-closed, past which a failed write is no end
	// of its peer.
	halfClosed atomic.Bool
}

// closedCh returns a channel closed once the connection closed.
func (s *sessionCancel) closedCh() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done == nil {
		s.done = make(chan struct{})
		if s.closed {
			close(s.done)
		}
	}
	return s.done
}

const (
	peerClean uint32 = 1 + iota
	peerFailed
)

// noteRead records how a read of the connection ended.
func (s *sessionCancel) noteRead(err error) {
	if err != nil && isTimeout(err) {
		s.timedOut.Store(true)
		return
	}
	notePeerEnd(&s.peer, err)
}

// noteWrite records a failed write as the failed end of the peer, as noteRead does a failed
// read, unless the connection half-closed or its normal end began first. net/http ends a
// connection at a failed write, before reading the frames still behind it.
func (s *sessionCancel) noteWrite(err error) {
	if peerEndIn(err) == 0 || s.ending.Load() || s.halfClosed.Load() {
		return
	}
	s.peer.CompareAndSwap(0, peerFailed)
}

// notePeerEnd records in peer the end of its peer a read error reports, once.
func notePeerEnd(peer *atomic.Uint32, err error) {
	if p := peerEndIn(err); p != 0 {
		peer.CompareAndSwap(0, p)
	}
}

// peerEndIn is the end of the peer the error of a read or a write reports, zero for a timer or a
// close on this side.
func peerEndIn(err error) uint32 {
	switch {
	case err == nil, isTimeout(err), errors.Is(err, net.ErrClosed):
		return 0
	case errors.Is(err, io.EOF):
		return peerClean
	}
	return peerFailed
}

// peerEndOf returns how the peer of c ended it, zero before. The socket of a front keeps the one
// record of the layers over it, where a failed end a TLS layer reads replaces a clean one and any
// other end counts only first. A TLS layer over no such socket keeps its own.
func peerEndOf(c net.Conn) uint32 {
	for range 8 {
		if c == nil {
			return 0
		}
		switch w := c.(type) {
		case *tlsConn:
			if p := w.peer.Load(); p != 0 {
				return p
			}
		case *cancelConn:
			return w.peer.Load()
		case *boundedTLSConn:
			return w.peer.Load()
		}
		c = inner(c)
	}
	return 0
}

// causeOfEnd is the cause the close of the connection gives its session when no other cause
// ended it first.
func (s *sessionCancel) causeOfEnd() cause {
	peer := s.peer.Load()
	switch {
	case s.headerTimedOut():
		return causeTimeout
	case peer == peerFailed:
		return causePeerFailed
	case peer == peerClean:
		return causePeer
	case s.timedOut.Load():
		return causeIdle
	}
	return causeReturned
}

// headerTimedOut reports whether a read timed out before a request reached a handler, the read
// header timeout of the first request, which gives the connection its failed end,
// docs/lifecycle.md Timers. net/http also times out its own reads with a past deadline once a
// request began.
func (s *sessionCancel) headerTimedOut() bool {
	if !s.timedOut.Load() || s.ending.Load() {
		return false
	}
	// A session that a cause ended has its closer decide the form.
	sess := s.sess.Load()
	return sess == nil || !sess.requested.Load() && sess.end.first() == causeNone
}

func (s *sessionCancel) arm(cancel context.CancelFunc) {
	s.mu.Lock()
	closed := s.closed
	if !closed {
		s.cancel = cancel
	}
	s.mu.Unlock()
	if closed {
		cancel()
	}
}

// fire starts the closer of the session once the connection closed, which ends the units on
// the connection, I1 and I3, then cancels the session context, so the units the context ends
// read the cause of their carrier. The closer closes the layers over this one, so it runs off
// the Close in progress, the session registered until it ended.
func (s *sessionCancel) fire() {
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	if !s.closed && s.done != nil {
		close(s.done)
	}
	s.closed = true
	s.mu.Unlock()
	if sess := s.sess.Load(); sess != nil && sess.p != nil && sess.end.first() == causeNone {
		c := s.causeOfEnd()
		go func() {
			_ = sess.endBy(c, time.Now().Add(alertWriteTimeout))
			if cancel != nil {
				cancel()
			}
		}()
		return
	}
	if cancel != nil {
		cancel()
	}
}

// cancelConn is a connection of a plaintext front. Its Close ends its session context.
type cancelConn struct {
	net.Conn
	sessionCancel
}

func (c *cancelConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.noteRead(err)
	return n, err
}

func (c *cancelConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil {
		c.noteWrite(err)
	}
	return n, err
}

func (c *cancelConn) Close() error {
	if c.headerTimedOut() {
		lingerZero(c.Conn)
	}
	err := c.Conn.Close()
	c.fire()
	return err
}

func (c *cancelConn) Abort() {
	lingerZero(c.Conn)
	_ = c.Close()
}

// CloseWrite forwards the half-close, which the embedded net.Conn does not promote.
func (c *cancelConn) CloseWrite() error {
	c.halfClosed.Store(true)
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
	// net/http serves as TLS any connection with a ConnectionState method.
	if tc, ok := c.(*tls.Conn); ok {
		return &boundedTLSConn{Conn: tc, done: make(chan struct{})}, nil
	}
	if _, ok := c.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return c, nil
	}
	return &cancelConn{Conn: c}, nil
}

// boundedTLSConn bounds the close of a TLS connection the caller's listener established, as
// tlsConn does for the connections the proxy creates: its close_notify is written within
// alertWriteTimeout, none after a failed write, and a later Close returns once the first ended.
type boundedTLSConn struct {
	*tls.Conn
	done chan struct{}
	sessionCancel
	once   sync.Once
	failed atomic.Bool
	// noNotify is set once the connection half-closed with a FIN and no close_notify, which its
	// Close then writes neither.
	noNotify atomic.Bool
}

func (c *boundedTLSConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil {
		c.failed.Store(true)
		c.noteWrite(err)
	}
	return n, err
}

func (c *boundedTLSConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.noteRead(err)
	return n, err
}

func (c *boundedTLSConn) Close() error {
	c.once.Do(func() {
		defer close(c.done)
		switch {
		case c.headerTimedOut():
			abort(c.NetConn())
			return
		case c.noNotify.Load():
			_ = c.NetConn().Close()
			return
		}
		c.bounded(c.Conn.Close)
	})
	<-c.done
	c.fire()
	return nil
}

// CloseWrite half-closes the connection as tlsConn does, close_notify then the half-close of its
// socket on TLS 1.3, nothing before Close on TLS 1.2.
func (c *boundedTLSConn) CloseWrite() error {
	if c.ConnectionState().Version < tls.VersionTLS13 {
		return nil
	}
	c.halfClosed.Store(true)
	c.bounded(c.Conn.CloseWrite)
	return closeWrite(c.NetConn())
}

// bounded runs a close that writes a close_notify, and resets the socket instead after a
// failed write or once alertWriteTimeout has passed.
func (c *boundedTLSConn) bounded(close func() error) {
	c.boundedBy(time.Now().Add(alertWriteTimeout), close)
}

// boundedBy is bounded ending at deadline.
func (c *boundedTLSConn) boundedBy(deadline time.Time, close func() error) {
	if c.failed.Load() {
		abort(c.NetConn())
		return
	}
	closed := make(chan struct{})
	go func() {
		_ = close()
		closed <- struct{}{}
	}()
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case <-closed:
	case <-t.C:
		abort(c.NetConn())
		<-closed
	}
}

func (c *boundedTLSConn) Abort() { abort(c.NetConn()) }

// idleTracker resets both ends of a relay once neither direction has moved a byte for the
// configured duration. A zero duration leaves it disarmed.
type idleTracker struct {
	timer   *time.Timer
	conns   []net.Conn
	timeout time.Duration
	armed   atomic.Bool
	// expired is set once the timer fired, its failed ends replacing the end of each copy.
	expired atomic.Bool
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

// start must be called with the lock held, or before the tracker is shared.
func (t *idleTracker) start(d time.Duration) {
	t.timeout = d
	t.timer = time.AfterFunc(d, func() {
		t.expired.Store(true)
		var wg sync.WaitGroup
		for _, c := range t.conns {
			wg.Go(func() { abortAfterFlush(c) })
		}
		wg.Wait()
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
	r        *deadlineReader
	body     io.ReadCloser
	w        http.ResponseWriter
	flushErr flushErrorer
	flusher  http.Flusher
	local    net.Addr
	remote   net.Addr
	// str is the HTTP/3 stream once taken from its response writer, which is not safe for
	// concurrent use, guarded by wmu.
	str *http3.Stream

	// wdeadline is the HTTP/2 write deadline. net/http resets the stream when its own deadline
	// passes, a write in flight or not.
	wdeadline time.Time   // guarded by dmu
	wtimer    *time.Timer // guarded by dmu

	cmu      sync.Mutex
	wmu      sync.Mutex
	dmu      sync.Mutex
	closed   atomic.Bool
	aborted  atomic.Bool
	expired  atomic.Bool
	sent     bool // guarded by wmu
	header   bool // guarded by wmu, set once the response header is written
	finished bool // guarded by cmu
}

func newH2Stream(w http.ResponseWriter, r *http.Request, local, remote net.Addr) *h2Stream {
	s := &h2Stream{r: newDeadlineReader(r.Body), body: r.Body, w: w, local: local, remote: remote}
	if f, ok := w.(flushErrorer); ok {
		s.flushErr = f
	} else if f, ok := w.(http.Flusher); ok {
		s.flusher = f
	}
	return s
}

// flushErrorer is the flush with an error that http.ResponseController looks for first.
type flushErrorer interface{ FlushError() error }

func (s *h2Stream) flush() error {
	if s.flushErr != nil {
		return s.flushErr.FlushError()
	}
	if s.flusher != nil {
		s.flusher.Flush()
	}
	return nil
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
				s.reset(hs, http3.ErrCodeConnectError)
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
	s.header = true
	_ = s.flush()
}

func (s *h2Stream) Write(b []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed.Load() || s.sent {
		return 0, net.ErrClosed
	}
	if s.expired.Load() {
		return 0, os.ErrDeadlineExceeded
	}

	n, err := s.w.Write(b)
	// A CONNECT stream is a byte pipe with no framing of its own: without an explicit
	// flush the data sits in the response buffer until enough of it accumulates. Bytes a
	// failed flush left in the buffer were not sent.
	if ferr := s.flush(); err == nil && ferr != nil {
		return 0, ferr
	}
	return n, err
}

func (s *h2Stream) Close() error {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if !s.stop(false) {
		return nil
	}
	return s.endReads()
}

// endReads ends the reads of the request body. The Close of an HTTP/3 body sends STOP_SENDING
// H3_REQUEST_CANCELLED, so the reads end with a read deadline there, and quic-go sends
// STOP_SENDING H3_NO_ERROR, or its own code, as the handler returns. Called with cmu locked.
func (s *h2Stream) endReads() error {
	if _, ok := s.w.(http3.HTTPStreamer); !ok {
		return s.body.Close()
	}
	s.wmu.Lock()
	str := s.str
	s.wmu.Unlock()
	if str != nil {
		// quic-go leaves a stream it handed over alone as the handler returns.
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		return nil
	}
	return http.NewResponseController(s.w).SetReadDeadline(time.Unix(1, 0))
}

// takeLocked returns the HTTP/3 stream of hs, taken once. The caller holds wmu.
func (s *h2Stream) takeLocked(hs http3.HTTPStreamer) *http3.Stream {
	if s.str == nil {
		s.str = hs.HTTPStream()
	}
	return s.str
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

// streamCut ends a CONNECT stream with a reset, and the context of its session, when
// [Session.Close] or a shutdown cut closes it. A clean end would read as the origin closing the
// connection, RFC 9113 section 8.5.
type streamCut struct {
	s      *h2Stream
	cancel context.CancelFunc
	// sess is the session of the stream, nil for none.
	sess *Session
}

func (c *streamCut) Close() error {
	if c.sess != nil && c.sess.end.first() != causeNone {
		// The closer of the session decided the forms of the stream, which ends as its handler
		// returns, I1.
		c.cancel()
		return nil
	}
	return c.endBy(causeCut, time.Now())
}

func (c *streamCut) endBy(cs cause, _ time.Time) error {
	if formOf(byteStream, cs, false) == formNormal {
		_ = c.s.Close()
	} else {
		c.s.Abort()
	}
	c.cancel()
	return nil
}

func (s *h2Stream) reset(hs http3.HTTPStreamer, code http3.ErrCode) {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if s.finished {
		return
	}
	// HTTPStream flushes the response writer, so stop first ends any write in flight. The reads
	// end last.
	open := s.stop(false)
	s.wmu.Lock()
	header := s.header
	s.wmu.Unlock()
	if !header {
		// HTTPStream would write a 200 first, so the handler resets the stream as it returns,
		// with H3_INTERNAL_ERROR, docs/lifecycle.md Limits.
		s.aborted.Store(true)
		if open {
			_ = s.endReads()
		}
		return
	}
	s.wmu.Lock()
	str := s.takeLocked(hs)
	s.wmu.Unlock()
	str.CancelWrite(quic.StreamErrorCode(code))
	str.CancelRead(quic.StreamErrorCode(code))
}

// finish closes the stream before its handler returns. The response writer is invalid past that
// return, and every later call on the stream leaves it alone.
func (s *h2Stream) finish() {
	s.cmu.Lock()
	s.finished = true
	if s.stop(false) {
		_ = s.endReads()
	}
	s.cmu.Unlock()
	// A timer still armed would keep the stream reachable until its deadline.
	s.dmu.Lock()
	if s.wtimer != nil {
		s.wtimer.Stop()
	}
	s.dmu.Unlock()
	s.idle()
}

func (s *h2Stream) http3() bool {
	_, ok := s.w.(http3.HTTPStreamer)
	return ok
}

// CloseWrite ends the proxy-to-client direction of an HTTP/3 stream, which goes on receiving. An
// HTTP/2 handler cannot end its half of a stream alone, so on HTTP/2 the stream stops reading,
// its reads return io.EOF, and the end of the handler ends the stream.
func (s *h2Stream) CloseWrite() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	if s.sent {
		return nil
	}
	s.sent = true
	hs, ok := s.w.(http3.HTTPStreamer)
	if !ok {
		s.r.end(io.EOF)
		return s.body.Close()
	}
	return s.takeLocked(hs).Close()
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

// SetWriteDeadline bounds the writes that follow, as on a socket. On HTTP/2 a write still
// blocked when the deadline passes resets the stream, the only way it returns.
func (s *h2Stream) SetWriteDeadline(t time.Time) error {
	if _, ok := s.w.(http3.HTTPStreamer); ok {
		s.cmu.Lock()
		defer s.cmu.Unlock()
		if s.closed.Load() {
			return net.ErrClosed
		}
		return http.NewResponseController(s.w).SetWriteDeadline(t)
	}
	s.dmu.Lock()
	defer s.dmu.Unlock()
	if s.closed.Load() {
		return net.ErrClosed
	}
	s.wdeadline = t
	s.expired.Store(false)
	if s.wtimer != nil {
		s.wtimer.Stop()
	}
	if t.IsZero() {
		return nil
	}
	if d := time.Until(t); d > 0 {
		if s.wtimer == nil {
			s.wtimer = time.AfterFunc(d, s.expire)
		} else {
			s.wtimer.Reset(d)
		}
		return nil
	}
	s.expireLocked()
	return nil
}

// expire runs when the write deadline passes, and does nothing when the deadline moved after
// the timer was armed.
func (s *h2Stream) expire() {
	s.dmu.Lock()
	defer s.dmu.Unlock()
	if s.wdeadline.IsZero() || time.Now().Before(s.wdeadline) {
		return
	}
	s.expireLocked()
}

// expireLocked fails the writes that follow and resets the stream under the one in flight. dmu
// must be held.
func (s *h2Stream) expireLocked() {
	s.expired.Store(true)
	if s.wmu.TryLock() {
		s.wmu.Unlock()
		return
	}
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if !s.closed.Load() {
		_ = http.NewResponseController(s.w).SetWriteDeadline(time.Now())
	}
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
	// ended keeps the error end set past a read in flight.
	ended   bool
	waiting int
}

type readResult struct {
	err error
	b   []byte
}

func newDeadlineReader(r io.Reader) *deadlineReader {
	return &deadlineReader{r: r, res: make(chan readResult, 1)}
}

// end makes every later read return err, the bytes not yet read dropped.
func (d *deadlineReader) end(err error) {
	d.mu.Lock()
	d.ended, d.err, d.rest = true, err, nil
	d.wakeLocked()
	d.mu.Unlock()
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
		if d.ended {
			err := d.err
			d.mu.Unlock()
			return 0, err
		}
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
func cancelConnOf(c net.Conn) *sessionCancel {
	for {
		switch cc := c.(type) {
		case *cancelConn:
			return &cc.sessionCancel
		case *boundedTLSConn:
			return &cc.sessionCancel
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

// endCopy passes the end of a copy from src to dst on. The peer's end of src half-closes dst,
// and any other end of either side resets the other, a close or a deadline on this side
// included.
func endCopy(src, dst net.Conn, err error) {
	switch {
	case err == nil || errors.Is(err, io.EOF):
		if t := tlsOf(src); t != nil && t.socket.eof.Load() {
			// The peer ended its socket without close_notify, which the other side reads as
			// such too.
			finWithoutNotify(dst)
			return
		}
		halfClose(dst)
	case errors.As(err, new(writeError)):
		// What src was sent before still reaches it, I2.
		abortAfterFlush(src)
	default:
		abortAfterFlush(dst)
	}
}

// abortAfterFlush gives c its failed end once the bytes written to it have left its socket,
// waiting at most alertWriteTimeout. A reset discards the bytes still queued on the socket.
func abortAfterFlush(c net.Conn) { abortBy(c, time.Now().Add(alertWriteTimeout)) }

// abortBy is the failed end of TCP: a reset once the peer acknowledged what was written to c,
// waiting at most until deadline, docs/lifecycle.md End forms.
func abortBy(c net.Conn, deadline time.Time) {
	if sock := socketOf(c); sock != nil {
		for time.Now().Before(deadline) {
			if n, err := netutil.UnsentBytes(sock); err != nil || n == 0 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	abort(c)
}

// socketOf returns the socket under the wrappers of c, nil when there is none.
func socketOf(c net.Conn) net.Conn {
	for range 8 {
		if _, ok := c.(syscall.Conn); ok || c == nil {
			return c
		}
		c = inner(c)
	}
	return nil
}

// inner returns the connection c wraps, nil when c wraps none or is not a wrapper of this
// package.
func inner(c net.Conn) net.Conn {
	switch w := c.(type) {
	case *peekConn:
		return w.Conn
	case *heldConn:
		return w.Conn
	case bufferedConn:
		return w.Conn
	case *servedConn:
		return w.Conn
	case *tlsServedConn:
		return w.Conn
	case *cancelConn:
		return w.Conn
	case transparentConn:
		return w.Conn
	case *shapedConn:
		return w.Conn
	case *ownConn:
		return w.Conn
	case *gatedConn:
		return w.Conn
	case normalEnd:
		return w.Conn
	case tlsSchemeConn:
		return w.Conn
	case pipeConn:
		if w.top != nil {
			return w.top
		}
		return w.raw
	case interface{ NetConn() net.Conn }:
		return w.NetConn()
	}
	return nil
}

// tlsOf returns the TLS connection of the proxy under the wrappers of c, nil when there is none.
func tlsOf(c net.Conn) *tlsConn {
	for range 8 {
		if t, ok := c.(*tlsConn); ok || c == nil {
			return t
		}
		c = inner(c)
	}
	return nil
}

// boundedTLSOf returns the TLS connection of a caller's listener under the wrappers of c, nil
// when there is none.
func boundedTLSOf(c net.Conn) *boundedTLSConn {
	for range 8 {
		if t, ok := c.(*boundedTLSConn); ok || c == nil {
			return t
		}
		c = inner(c)
	}
	return nil
}

// finWithoutNotify half-closes c with a FIN alone, and a TLS connection under it closes later
// with no close_notify.
func finWithoutNotify(c net.Conn) {
	if b := boundedTLSOf(c); b != nil {
		b.noNotify.Store(true)
		halfClose(b.NetConn())
		return
	}
	t := tlsOf(c)
	if t == nil {
		halfClose(c)
		return
	}
	t.noNotify.Store(true)
	halfClose(t.socket.Conn)
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
	once   sync.Once
	// noNotify closes the connection with no close_notify, its peer having ended without one.
	noNotify atomic.Bool
	// peer is how the peer ended the connection as a read of the TLS layer reported it,
	// peerClean or peerFailed, zero before. Over the socket of a front, the TLS layer writes the
	// record of that socket instead.
	peer atomic.Uint32
}

func (c *tlsConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err == nil {
		return n, nil
	}
	peer := frontPeerOf(c.socket.Conn)
	if peer == nil {
		notePeerEnd(&c.peer, err)
		return n, err
	}
	// A failed end of TLS replaces the FIN under it, and a failed end the socket observed first
	// stays.
	if p := peerEndIn(err); p == peerFailed {
		peer.Store(p)
	} else if p != 0 {
		peer.CompareAndSwap(0, p)
	}
	return n, err
}

// frontPeerOf returns the record of the end of the peer the socket of a front under c keeps, nil
// when c is over no such socket.
func frontPeerOf(c net.Conn) *atomic.Uint32 {
	for range 8 {
		switch w := c.(type) {
		case nil:
			return nil
		case *cancelConn:
			return &w.peer
		case *boundedTLSConn:
			return &w.peer
		}
		c = inner(c)
	}
	return nil
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
// reader, which crypto/tls sends under the lock the close_notify waits for. A later Close
// returns once the first has ended, so a caller closing the socket under it next cannot cut
// the close_notify.
func (c *tlsConn) Close() error {
	err := net.ErrClosed
	c.once.Do(func() {
		if c.noNotify.Load() {
			err = c.socket.Close()
			return
		}
		if !c.socket.closing.Swap(true) {
			_ = c.socket.SetWriteDeadline(time.Time{})
		}
		err = c.Conn.Close()
	})
	return err
}

// CloseWrite half-closes the connection, its close_notify then the half-close of its socket.
// TLS 1.2 has no half-close, a peer closes on a close_notify, RFC 5246 section 7.2.1, so there
// the half-close waits for Close.
func (c *tlsConn) CloseWrite() error {
	if c.ConnectionState().Version < tls.VersionTLS13 {
		return nil
	}
	if err := c.closeNotify(); err != nil {
		return err
	}
	if s := h2StreamOf(c.socket.Conn); s != nil && !s.http3() {
		// The close_notify is the half-close, which the HTTP/2 stream cannot send.
		return nil
	}
	return closeWrite(c.socket.Conn)
}

// h2StreamOf returns the stream under c, or nil when c is not one.
func h2StreamOf(c net.Conn) *h2Stream {
	for range 8 {
		if s, ok := c.(*h2Stream); ok || c == nil {
			return s
		}
		c = inner(c)
	}
	return nil
}

// closeNotify writes the close_notify of the connection.
func (c *tlsConn) closeNotify() error {
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
	// failed is set once a write failed, past which no close_notify goes out, and cut once one
	// left a record cut short, which only a reset may follow.
	failed atomic.Bool
	cut    atomic.Bool
	// eof is set once a read reached the end of the socket.
	eof atomic.Bool
	// limit caps the write deadlines of a close in nanoseconds since the epoch, zero for T from
	// each of them.
	limit atomic.Int64
}

func (s *tlsSocket) Read(b []byte) (int, error) {
	n, err := s.Conn.Read(b)
	if errors.Is(err, io.EOF) {
		s.eof.Store(true)
	}
	return n, err
}

// Close resets the socket after a write that left a record cut short, a close_notify included.
func (s *tlsSocket) Close() error {
	if s.cut.Load() {
		abort(s.Conn)
		return nil
	}
	return s.Conn.Close()
}

func (s *tlsSocket) Write(b []byte) (int, error) {
	n, err := s.Conn.Write(b)
	if err != nil {
		s.failed.Store(true)
		if n > 0 && n < len(b) {
			s.cut.Store(true)
		}
	}
	return n, err
}

// SetWriteDeadline caps every write deadline at alertWriteTimeout once a close has begun. After
// a failed write the deadline expires at once, as the peer could not decrypt a later record.
func (s *tlsSocket) SetWriteDeadline(t time.Time) error {
	if s.closing.Load() {
		now := time.Now()
		bound := now.Add(alertWriteTimeout)
		if limit := s.limit.Load(); limit != 0 && limit < bound.UnixNano() {
			bound = time.Unix(0, limit)
		}
		switch {
		case s.failed.Load():
			t = now
		case t.IsZero() || t.After(bound):
			t = bound
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

// closeNormally gives c the normal end of its transport within alertWriteTimeout: a
// close_notify under TLS, then a FIN, what the peer still sends read and discarded until its
// own FIN, and the close.
func closeNormally(c net.Conn) { closeNormallyBy(c, time.Now().Add(alertWriteTimeout)) }

// closeNormallyBy is closeNormally ending at deadline.
func closeNormallyBy(c net.Conn, deadline time.Time) {
	// The timeouts of the reads and of the discard below are no read header timeout.
	w := c
	for range 8 {
		if w == nil {
			break
		}
		if sc := servedConnOf(w); sc != nil {
			sc.ending.Store(true)
		}
		if sc := cancelConnOf(w); sc != nil {
			sc.ending.Store(true)
			break
		}
		w = inner(w)
	}
	// A peek buffer and the frame parser of a schemeConn keep state their own reader may be
	// using, so the end goes to what they wrap, the layers below ending in their own order.
	for range 4 {
		switch w := c.(type) {
		case *peekConn:
			c = w.Conn
			continue
		case *schemeConn:
			c = w.Conn
			continue
		case tlsSchemeConn:
			c = w.Conn
			continue
		}
		break
	}
	switch tc := c.(type) {
	case *tlsConn:
		if !tc.noNotify.Load() && !tc.socket.failed.Load() {
			tc.socket.limit.Store(deadline.UnixNano())
			_ = tc.closeNotify()
		}
		if tc.socket.cut.Load() {
			// A record cut short, the failed end of TLS.
			abort(tc.socket.Conn)
			return
		}
		c = tc.NetConn()
	case *boundedTLSConn:
		// Whatever the version, the close_notify of a normal end, which resets the socket
		// after a failed write, and none after a FIN with no close_notify.
		if !tc.noNotify.Load() {
			tc.boundedBy(deadline, tc.Conn.CloseWrite)
		}
		c = tc.NetConn()
	default:
		// A wrapper that keeps its own Close still has its close_notify go first, on TLS 1.2
		// too, under the same deadline.
		if bc := boundedTLSOf(c); bc != nil {
			if !bc.noNotify.Load() {
				bc.boundedBy(deadline, bc.Conn.CloseWrite)
			}
		} else if tc := tlsOf(c); tc != nil {
			if !tc.noNotify.Load() && !tc.socket.failed.Load() {
				tc.socket.limit.Store(deadline.UnixNano())
				_ = tc.closeNotify()
			}
			if tc.socket.cut.Load() {
				abort(c)
				return
			}
		}
	}
	if cw, ok := c.(closeWriter); ok {
		// The close at the deadline also ends a half-close stuck behind a write, and a read with
		// a deadline that does nothing.
		t := time.AfterFunc(time.Until(deadline), func() { _ = c.Close() })
		if cw.CloseWrite() == nil {
			_ = c.SetReadDeadline(deadline)
			_, _ = io.Copy(io.Discard, c)
		}
		t.Stop()
	}
	_ = c.Close()
}

// closeWrite ends the write direction of c, or closes it when it cannot half-close.
func closeWrite(c net.Conn) error {
	if cw, ok := c.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// filterCopyErr drops the end of a relay that is the peer's normal end. A close or a deadline
// on this side reset the other leg, and is reported.
func filterCopyErr(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

var _ net.Conn = (*h2Stream)(nil)

// temporaryAccept reports an accept failure the listener recovers from, the file descriptor
// limit or a connection aborted before it was accepted, on which net/http backs off.
func temporaryAccept(err error) bool {
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return true
	}
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) || errors.Is(err, syscall.ECONNABORTED)
}

// normalEnd closes its connection with the normal end of its transport.
type normalEnd struct{ net.Conn }

func (c normalEnd) Close() error { return c.closeBy(time.Now().Add(alertWriteTimeout)) }

func (c normalEnd) closeBy(deadline time.Time) error { return c.endBy(causeClosed, deadline) }

func (c normalEnd) endBy(cs cause, deadline time.Time) error {
	if formOf(framed, cs, false) == formFailed {
		abortBy(c.Conn, deadline)
		_ = c.Conn.Close()
		return nil
	}
	if sc := cancelConnOf(c.Conn); cs == causeCut && sc != nil && sc.sess.Load() != nil && sc.sess.Load().Protocol() == HTTP2 {
		// The cut gave the connection its GOAWAY, and net/http writes the end of each stream
		// and the GOAWAY from its own goroutines, then closes the connection once its streams
		// ended. The normal end under it waits for that close, within the deadline.
		waitUntil(sc.closedCh(), deadline)
	}
	closeNormallyBy(c.Conn, deadline)
	// The wrappers closeNormally went under have their own Close, the cancel of a session
	// context among them.
	_ = c.Conn.Close()
	return nil
}
