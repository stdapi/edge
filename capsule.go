// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	// capsuleDatagram is the DATAGRAM capsule type, RFC 9297 section 3.5.
	capsuleDatagram = 0
	// capsuleHeadroom is the room a datagram keeps ahead of its payload for a capsule header,
	// the DATAGRAM type and the length of anything under 2^30 bytes.
	capsuleHeadroom = 5
	// maxCapsuleDatagram is the UDP payload RFC 9298 section 5 allows after a context ID. Past
	// it a datagram of context ID 0 aborts the stream, and a capsule of another context ID is
	// dropped without being buffered.
	maxCapsuleDatagram = 65527
	// capsuleQueue bounds the DATAGRAM capsules read off an HTTP/3 stream and not yet received.
	capsuleQueue = 16
)

// errTunnelMalformed ends a tunnel whose stream ended inside a capsule, RFC 9297 section 3.3,
// or delivered a datagram of context ID 0 past maxCapsuleDatagram. The stream is aborted.
var errTunnelMalformed = errors.New("edge: malformed tunnel stream")

// errTunnelFIN ends a tunnel after its stream ended between two capsules. It is both
// errTunnelEnded and io.EOF.
var errTunnelFIN = fmt.Errorf("%w: %w", errTunnelEnded, io.EOF)

// tunnelPipe moves the datagrams of one CONNECT-UDP tunnel, as HTTP Datagrams on an HTTP/3
// stream or as DATAGRAM capsules on a byte stream. Every datagram starts with its context ID.
type tunnelPipe interface {
	// recv returns the next datagram, in a slice the caller owns, to one reader at a time.
	recv(ctx context.Context) ([]byte, error)
	// send writes b, whose first capsuleHeadroom bytes are room for a capsule header.
	send(b []byte) error
	setReadDeadline(t time.Time) error
	setWriteDeadline(t time.Time) error
	// close ends the pipe in both directions and unblocks recv and send.
	close() error
	// closeBy is close within deadline.
	closeBy(deadline time.Time) error
	// fail ends the pipe at once with its failed end. A closer calls it only before the normal
	// end of the pipe began.
	fail()
}

type h3DatagramStream interface {
	io.ReadWriter
	Close() error
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	SetWriteDeadline(time.Time) error
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
	Context() context.Context
}

func oversized(b []byte) bool {
	id, n, err := quicvarint.Parse(b)
	return err == nil && id == 0 && len(b)-n > maxCapsuleDatagram
}

func cutShort(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errTunnelMalformed
	}
	return err
}

// frameCapsule encodes the DATAGRAM capsule header of b in its headroom and returns the
// capsule.
func frameCapsule(b []byte) []byte {
	n := uint64(len(b) - capsuleHeadroom) //nolint:gosec // the headroom is part of every b
	start := capsuleHeadroom - 1 - quicvarint.Len(n)
	b[start] = capsuleDatagram
	quicvarint.Append(b[start+1:start+1], n)
	return b[start:]
}

// datagramPipe is a tunnel on an HTTP/3 stream, its datagrams in QUIC DATAGRAM frames or in
// DATAGRAM capsules on the stream, RFC 9297 section 3.5. Capsules of other types are dropped,
// and the end of the stream ends the tunnel.
type datagramPipe struct {
	str  h3DatagramStream
	base context.Context
	wake context.Context
	// readErr is the error that ended the read of the stream, set before readDone is closed.
	readErr  error
	ended    error
	deadline atomic.Pointer[time.Time]
	// caps queues the DATAGRAM capsules, and each one cancels wake so a recv waiting on a
	// QUIC datagram picks it up.
	caps chan []byte
	done chan struct{}
	// readDone is closed once the read of the stream ended.
	readDone   chan struct{}
	cancelWake context.CancelFunc
	// timer is armed by recv alone.
	timer *time.Timer
	// checked runs once wakeFor found the capsule queue empty, set by tests alone.
	checked   func()
	closeOnce sync.Once
	mu        sync.Mutex
	// capsules sends the datagrams as capsules, to a peer without SETTINGS_H3_DATAGRAM.
	capsules bool
}

func newDatagramPipe(str h3DatagramStream, capsules bool) *datagramPipe {
	return &datagramPipe{
		str:      str,
		capsules: capsules,
		caps:     make(chan []byte, capsuleQueue),
		done:     make(chan struct{}),
		readDone: make(chan struct{}),
	}
}

// streamFailed reports whether the peer reset the stream or broke its framing, waiting for the
// read of the stream to end, which the end of its connection makes prompt, until deadline. A read
// still running at deadline gives the failed end, I4.
func (p *datagramPipe) streamFailed(deadline time.Time) bool {
	if !waitUntil(p.readDone, deadline) {
		return true
	}
	if errors.Is(p.readErr, io.ErrUnexpectedEOF) || errors.Is(p.readErr, errTunnelMalformed) {
		return true
	}
	se, ok := errors.AsType[*quic.StreamError](p.readErr)
	return ok && se.Remote
}

// run reads the capsules of the stream until it ends, then calls onEnd, failed reporting any end
// but a FIN between two capsules or a clean end of the connection.
func (p *datagramPipe) run(onEnd func(failed bool)) {
	go func() {
		// The capsule parser reports an end of the stream inside a capsule as
		// io.ErrUnexpectedEOF, and one between two capsules as io.EOF.
		rerr := p.readCapsules()
		if endedWithConn(rerr) {
			// quic-go reports the end of the connection to a read ahead of a reset of the
			// stream that arrived with it, and the next read reports the reset.
			if _, err := p.str.Read(make([]byte, 1)); err != nil {
				if se, ok := errors.AsType[*quic.StreamError](err); ok && se.Remote {
					rerr = err
				}
			}
		}
		p.readErr = rerr
		close(p.readDone)
		var err error
		switch {
		case errors.Is(rerr, io.ErrUnexpectedEOF) || errors.Is(rerr, errTunnelMalformed):
			p.abort()
			err = errTunnelMalformed
		case errors.Is(rerr, io.EOF):
			err = errTunnelFIN
		default:
			err = &tunnelEnd{cause: rerr}
		}
		p.wakeRecv(err)
		onEnd(!cleanEnd(rerr))
	}()
}

// endCause is the error that ended ctx, the request context of pipe. quic-go cancels an HTTP/3
// request context with no cause once its stream ends, where the stream's context has the error
// that ended its connection.
func endCause(ctx context.Context, pipe tunnelPipe) error {
	cause := context.Cause(ctx)
	if dp, ok := pipe.(*datagramPipe); ok && errors.Is(cause, context.Canceled) {
		if sc := dp.str.Context(); sc.Err() != nil {
			return context.Cause(sc)
		}
	}
	return cause
}

// tunnelEnd is errTunnelEnded with the error that ended the stream, which it does not unwrap
// to, since a timeout among them would read as one a reader retries.
type tunnelEnd struct{ cause error }

func (e *tunnelEnd) Error() string        { return errTunnelEnded.Error() }
func (e *tunnelEnd) Is(target error) bool { return target == errTunnelEnded }

// cleanEnd reports whether err ends a carrier cleanly: a FIN, or an end of its QUIC connection
// quicCleanEnd reads as normal, which fails only the messages in flight.
func cleanEnd(err error) bool {
	if end, ok := errors.AsType[*tunnelEnd](err); ok {
		err = end.cause
	}
	return errors.Is(err, io.EOF) || quicCleanEnd(err)
}

// quicCleanEnd reports whether err is the normal end of a QUIC connection: an application code
// of no error, H3_NO_ERROR or the code 0 quic-go closes an idle pooled HTTP/3 connection with,
// or the idle timeout. Any other code, a transport error and a stateless reset are failures.
func quicCleanEnd(err error) bool {
	if appErr, ok := errors.AsType[*quic.ApplicationError](err); ok {
		return appErr.ErrorCode == h3NoError || appErr.ErrorCode == 0
	}
	_, idle := errors.AsType[*quic.IdleTimeoutError](err)
	return idle
}

func (p *datagramPipe) readCapsules() error {
	parser := http3.NewCapsuleParser(p.str)
	for {
		typ, r, err := parser.Next()
		if err != nil {
			return err
		}
		if typ != capsuleDatagram {
			if err = r.Discard(); err != nil {
				return err
			}
			continue
		}
		b, err := readDatagramCapsule(r)
		if err != nil {
			return err
		}
		if b == nil {
			continue
		}
		select {
		case p.caps <- b:
		case <-p.done:
			return errTunnelEnded
		}
		p.wakeRecv(nil)
	}
}

// readDatagramCapsule returns the datagram of a DATAGRAM capsule, nil for one dropped.
func readDatagramCapsule(r http3.CapsuleReader) ([]byte, error) {
	id, err := quicvarint.Read(r)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, err
	}
	payload := r.Remaining()
	if payload > maxCapsuleDatagram {
		if id == 0 {
			return nil, errTunnelMalformed
		}
		return nil, r.Discard()
	}
	b := quicvarint.Append(make([]byte, 0, quicvarint.Len(id)+int(payload)), id)
	n := len(b)
	b = b[:n+int(payload)]
	if _, err := io.ReadFull(r, b[n:]); err != nil {
		return nil, err
	}
	return b, nil
}

// wakeRecv has a recv waiting on a QUIC datagram look again, and records why the stream
// ended when ended is not nil.
func (p *datagramPipe) wakeRecv(ended error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ended != nil && p.ended == nil {
		p.ended = ended
	}
	if p.cancelWake != nil {
		p.cancelWake()
	}
}

// wakeFor returns a queued capsule, or the context a recv under ctx waits on. The context is
// renewed once a capsule or the end of the stream cancelled it, and costs nothing while QUIC
// datagrams alone arrive. The queue is checked under the lock wakeRecv takes, so a capsule
// queued after the check cancels the context returned.
func (p *datagramPipe) wakeFor(ctx context.Context) ([]byte, context.Context, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case b := <-p.caps:
		return b, nil, nil
	default:
	}
	if p.checked != nil {
		p.checked()
	}
	if p.ended != nil {
		return nil, nil, p.ended
	}
	if p.wake == nil || p.base != ctx || p.wake.Err() != nil {
		if p.cancelWake != nil {
			p.cancelWake()
		}
		p.base = ctx
		p.wake, p.cancelWake = context.WithCancel(ctx)
	}
	return nil, p.wake, nil
}

func (p *datagramPipe) recv(ctx context.Context) ([]byte, error) {
	for {
		b, wake, err := p.wakeFor(ctx)
		if b != nil || err != nil {
			return b, err
		}
		var dl time.Time
		if d := p.deadline.Load(); d != nil {
			dl = *d
		}
		if !dl.IsZero() {
			p.armDeadline(dl)
		}
		b, err = p.str.ReceiveDatagram(wake)
		if !dl.IsZero() {
			p.timer.Stop()
		}
		switch {
		case err == nil:
			if oversized(b) {
				p.abort()
				p.wakeRecv(errTunnelMalformed)
				return nil, errTunnelMalformed
			}
			return b, nil
		case ctx.Err() != nil:
		case !dl.IsZero() && !time.Now().Before(dl):
			return nil, os.ErrDeadlineExceeded
		case wake.Err() != nil:
			continue
		default:
			// The receive side of the stream ended, and run reports it once its read returns. A
			// truncated capsule aborts the stream first.
			<-wake.Done()
			continue
		}
		// The error of a stream or a connection is sticky, and some report themselves as a
		// timeout, which a reader would retry.
		return nil, &tunnelEnd{cause: endCause(ctx, p)}
	}
}

// armDeadline has the timer of the pipe cancel wake at dl, so a recv under a deadline
// allocates nothing.
func (p *datagramPipe) armDeadline(dl time.Time) {
	if p.timer == nil {
		p.timer = time.AfterFunc(time.Until(dl), func() { p.wakeRecv(nil) })
		return
	}
	p.timer.Reset(time.Until(dl))
}

func (p *datagramPipe) send(b []byte) error {
	if p.capsules {
		_, err := p.str.Write(frameCapsule(b))
		return err
	}
	return p.str.SendDatagram(b[capsuleHeadroom:])
}

func (p *datagramPipe) setReadDeadline(t time.Time) error { p.deadline.Store(&t); return nil }

func (p *datagramPipe) setWriteDeadline(t time.Time) error {
	if p.capsules {
		return p.str.SetWriteDeadline(t)
	}
	return nil
}

// abort resets the stream in both directions with H3_MESSAGE_ERROR, RFC 9114 section 4.1.2.
func (p *datagramPipe) abort() {
	p.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeMessageError))
	p.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeMessageError))
}

func (p *datagramPipe) closeBy(time.Time) error { return p.close() }

// fail resets the stream with H3_CONNECT_ERROR, unless close ended it first.
func (p *datagramPipe) fail() {
	p.closeOnce.Do(func() {
		close(p.done)
		p.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeConnectError))
		p.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
	})
}

// close ends the stream once with a FIN, and stops the peer's side without an error, RFC 9114
// section 4.1.1. A later close does nothing.
func (p *datagramPipe) close() error {
	var err error
	p.closeOnce.Do(func() {
		close(p.done)
		err = p.str.Close()
		p.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	})
	return err
}

// capsulePipe is a tunnel on a byte stream, its datagrams in DATAGRAM capsules, RFC 9297. The
// stream is a CONNECT stream over HTTP/2 or a connection an Upgrade left behind over HTTP/1.1.
//
// The reader picks up where a read deadline cut it, so a datagram flow can wait out its idle
// deadline on the stream and go on reading. Nothing else may read from br once the pipe has
// it.
type capsulePipe struct {
	conn net.Conn
	br   *bufio.Reader
	// pending is the datagram being read, filled up to n. skip is what is left of a capsule
	// being dropped, one of another type or too large.
	pending []byte
	n       int
	skip    uint64
	// socket marks a pipe on a connection.
	socket bool
}

func newCapsulePipe(conn net.Conn, br *bufio.Reader) *capsulePipe {
	return &capsulePipe{conn: conn, br: br}
}

// newSocketCapsulePipe is newCapsulePipe on a connection an Upgrade left behind, the pipe's
// alone, which ends with the normal end of its transport.
func newSocketCapsulePipe(conn net.Conn, br *bufio.Reader) *capsulePipe {
	return &capsulePipe{conn: conn, br: br, socket: true}
}

// recv returns the next datagram, and aborts the stream when it ends inside a capsule or
// delivers a datagram of context ID 0 past maxCapsuleDatagram.
func (p *capsulePipe) recv(context.Context) ([]byte, error) {
	b, err := p.next()
	if errors.Is(err, errTunnelMalformed) {
		// RFC 9297 section 3.3 calls for PROTOCOL_ERROR on HTTP/2, which Go's server cannot send,
		// so an HTTP/2 stream is reset with INTERNAL_ERROR.
		abort(p.conn)
	}
	return b, err
}

func (p *capsulePipe) next() ([]byte, error) {
	for {
		if p.skip > 0 {
			n, err := p.br.Discard(int(min(p.skip, 1<<30)))
			p.skip -= uint64(n) //nolint:gosec // never negative, Discard counts bytes
			if err != nil {
				return nil, cutShort(err)
			}
			continue
		}
		if p.pending != nil {
			n, err := io.ReadFull(p.br, p.pending[p.n:])
			p.n += n
			if err != nil {
				return nil, cutShort(err)
			}
			b := p.pending
			p.pending, p.n = nil, 0
			return b, nil
		}
		typ, length, hdr, err := p.header()
		if err != nil {
			return nil, err
		}
		keep := typ == capsuleDatagram
		if keep {
			if keep, err = p.keepDatagram(hdr, length); err != nil {
				return nil, err
			}
		}
		if _, err := p.br.Discard(hdr); err != nil {
			return nil, err
		}
		if !keep {
			p.skip = length
			continue
		}
		p.pending = make([]byte, length)
	}
}

// header peeks the type and the length of the next capsule. The end of the stream is clean
// before its first byte alone.
func (p *capsulePipe) header() (typ, length uint64, n int, err error) {
	typ, tl, err := p.peekVarint(0)
	if err == nil {
		length, n, err = p.peekVarint(tl)
		n += tl
	}
	if err != nil && p.br.Buffered() > 0 {
		err = cutShort(err)
	}
	return typ, length, n, err
}

// keepDatagram peeks the context ID of a DATAGRAM capsule of length bytes behind a header of
// hdr bytes, and reports whether the datagram is read or dropped. A context ID longer than
// the capsule is dropped, and so is a payload past maxCapsuleDatagram of another context ID.
func (p *capsulePipe) keepDatagram(hdr int, length uint64) (bool, error) {
	if length == 0 {
		return false, nil
	}
	b, err := p.br.Peek(hdr + 1)
	if err != nil {
		return false, cutShort(err)
	}
	l := 1 << (b[hdr] >> 6)
	if uint64(l) > length {
		return false, nil
	}
	id, _, err := p.peekVarint(hdr)
	if err != nil {
		return false, cutShort(err)
	}
	if length-uint64(l) <= maxCapsuleDatagram {
		return true, nil
	}
	if id == 0 {
		return false, errTunnelMalformed
	}
	return false, nil
}

func (p *capsulePipe) peekVarint(off int) (uint64, int, error) {
	b, err := p.br.Peek(off + 1)
	if err != nil {
		return 0, 0, err
	}
	l := 1 << (b[off] >> 6)
	if b, err = p.br.Peek(off + l); err != nil {
		return 0, 0, err
	}
	v, _, err := quicvarint.Parse(b[off:])
	return v, l, err
}

// send writes b as one DATAGRAM capsule, its header encoded in the headroom so the stream
// sees a single write.
func (p *capsulePipe) send(b []byte) error {
	_, err := p.conn.Write(frameCapsule(b))
	return err
}

func (p *capsulePipe) setReadDeadline(t time.Time) error  { return p.conn.SetReadDeadline(t) }
func (p *capsulePipe) setWriteDeadline(t time.Time) error { return p.conn.SetWriteDeadline(t) }

func (p *capsulePipe) fail() { abort(p.conn) }

// close ends the stream with its half-close first, so an HTTP/2 stream the proxy opened ends
// with END_STREAM before the reset that stops its peer. A write still pending delays the
// half-close for T at most.
func (p *capsulePipe) close() error { return p.closeBy(time.Now().Add(alertWriteTimeout)) }

func (p *capsulePipe) closeBy(deadline time.Time) error {
	if p.socket {
		closeNormallyBy(p.conn, deadline)
		return nil
	}
	if cw, ok := p.conn.(closeWriter); ok {
		_ = p.conn.SetWriteDeadline(deadline)
		_ = cw.CloseWrite()
	}
	return p.conn.Close()
}
