// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	copyBufSize = 32 * 1024
	// defaultPeekSize covers a protocol discriminator and the buffering http.Server would
	// have done anyway on the connection it is handed.
	defaultPeekSize = 4096
)

var copyBufPool = sync.Pool{New: func() any { return new([copyBufSize]byte) }}

func getCopyBuf() []byte  { return copyBufPool.Get().(*[copyBufSize]byte)[:] }
func putCopyBuf(b []byte) { copyBufPool.Put((*[copyBufSize]byte)(b[:copyBufSize])) }

// peekConn is a net.Conn whose reads go through a buffered reader, so bytes consumed to
// sniff the protocol are still delivered to whatever ends up serving the connection.
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func newPeekConn(c net.Conn, buffered *bufio.Reader) *peekConn {
	if buffered == nil {
		buffered = bufio.NewReaderSize(c, defaultPeekSize)
	}
	return &peekConn{Conn: c, r: buffered}
}

// newPeekConnSize returns a peekConn whose buffer is large enough to hold size bytes, for a
// caller that needs to look further ahead than a protocol discriminator.
func newPeekConnSize(c net.Conn, size int) *peekConn {
	return &peekConn{Conn: c, r: bufio.NewReaderSize(c, size)}
}

func (c *peekConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// CloseWrite forwards the half-close, which the embedded net.Conn does not promote.
func (c *peekConn) CloseWrite() error { return closeWrite(c.Conn) }

// Peek returns the next n bytes without consuming them.
func (c *peekConn) Peek(n int) ([]byte, error) { return c.r.Peek(n) }

// closeWriter is implemented by connections that can be half-closed, which is how a tunnel
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
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
}

func newSingleConnListener(c net.Conn, sess *Session) *singleConnListener {
	l := &singleConnListener{addr: c.LocalAddr(), done: make(chan struct{})}
	// Closing the connection closes the listener, so the accept loop set up for it returns
	// instead of blocking forever on a second Accept that will never be served.
	l.conn = &servedConn{Conn: c, sess: sess, l: l}
	return l
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
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
	c.once.Do(func() { _ = c.l.Close() })
	return err
}

// tunnel relays bytes between client and upstream until both directions are done. It
// returns the number of bytes sent in each direction.
//
// Each direction is closed for writing as soon as its source is exhausted, so a peer that
// half-closes gets a half-close on the other side instead of a connection that stays open
// waiting for data that will never come.
func tunnel(client, upstream net.Conn, idleTimeout time.Duration) (sent, received int64, err error) {
	var (
		wg      sync.WaitGroup
		toUp    int64
		toDown  int64
		upErr   error
		downErr error
	)

	idle := newIdleTracker(idleTimeout, client, upstream)
	defer idle.stop()

	wg.Go(func() {
		toUp, upErr = copyStream(upstream, client, idle)
		halfClose(upstream)
	})
	wg.Go(func() {
		toDown, downErr = copyStream(client, upstream, idle)
		halfClose(client)
	})
	wg.Wait()

	return toUp, toDown, errors.Join(filterCopyErr(upErr), filterCopyErr(downErr))
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

// filterCopyErr drops the errors that are the normal end of a tunnel rather than a fault.
func filterCopyErr(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil
	}
	return err
}

// idleTracker closes both ends of a tunnel once neither direction has moved a byte for the
// configured duration. A zero duration disables it, which is the default: a tunnel can
// legitimately carry a long-lived stream the proxy knows nothing about.
type idleTracker struct {
	timer   *time.Timer
	timeout time.Duration
	mu      sync.Mutex
	stopped bool
}

func newIdleTracker(timeout time.Duration, conns ...net.Conn) *idleTracker {
	t := &idleTracker{timeout: timeout}
	if timeout <= 0 {
		return t
	}
	t.timer = time.AfterFunc(timeout, func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return t
}

func (t *idleTracker) touch() {
	if t.timer == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.stopped {
		t.timer.Reset(t.timeout)
	}
}

func (t *idleTracker) stop() {
	if t.timer == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = true
	t.timer.Stop()
}

// h2Stream adapts an HTTP/2 or HTTP/3 CONNECT stream to a net.Conn, so the same tunneling
// and interception code serves it as an HTTP/1.1 hijacked connection.
//
// Writes are serialized and refused once the stream is closed. A response writer is only
// valid while its handler runs, and the HTTP/2 server writes some frames from goroutines it
// does not wait for: without the guard, one of those could reach the writer after the
// CONNECT handler returned.
type h2Stream struct {
	r       io.ReadCloser
	w       io.Writer
	flusher http.Flusher
	local   net.Addr
	remote  net.Addr

	wmu    sync.Mutex
	closed atomic.Bool
}

func newH2Stream(w http.ResponseWriter, r *http.Request, local, remote net.Addr) *h2Stream {
	s := &h2Stream{r: r.Body, w: w, local: local, remote: remote}
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
	// Wait for a write in flight to finish, so the caller can rely on the response writer
	// being idle once Close returns.
	s.wmu.Lock()
	s.wmu.Unlock() //nolint:staticcheck // acquire and release, this is a barrier not a critical section
	return s.r.Close()
}

// CloseWrite ends the proxy-to-client direction. An HTTP/2 stream has no way to do that
// without ending the stream, so it is a no-op and the stream is torn down by Close.
func (s *h2Stream) CloseWrite() error { return nil }

func (s *h2Stream) LocalAddr() net.Addr  { return s.local }
func (s *h2Stream) RemoteAddr() net.Addr { return s.remote }

func (s *h2Stream) SetDeadline(time.Time) error      { return nil }
func (s *h2Stream) SetReadDeadline(time.Time) error  { return nil }
func (s *h2Stream) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*h2Stream)(nil)
