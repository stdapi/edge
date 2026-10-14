// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"errors"
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
}

type h3DatagramStream interface {
	io.ReadWriter
	Close() error
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	SetWriteDeadline(time.Time) error
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
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
	str      h3DatagramStream
	base     context.Context
	wake     context.Context
	ended    error
	deadline atomic.Pointer[time.Time]
	// caps queues the DATAGRAM capsules, and each one cancels wake so a recv waiting on a
	// QUIC datagram picks it up.
	caps       chan []byte
	done       chan struct{}
	cancelWake context.CancelFunc
	// timer is armed by recv alone.
	timer *time.Timer
	// checked runs once wakeFor found the capsule queue empty, set by tests alone.
	checked func()
	// code is the STOP_SENDING close sends, the request cancelled from the proxy and no
	// error from the client.
	code      quic.StreamErrorCode
	closeOnce sync.Once
	mu        sync.Mutex
	// capsules sends the datagrams as capsules, to a peer without SETTINGS_H3_DATAGRAM.
	capsules bool
}

func newDatagramPipe(str h3DatagramStream, code quic.StreamErrorCode, capsules bool) *datagramPipe {
	return &datagramPipe{
		str:      str,
		code:     code,
		capsules: capsules,
		caps:     make(chan []byte, capsuleQueue),
		done:     make(chan struct{}),
	}
}

// run reads the capsules on the stream and calls onEnd when the stream ends.
func (p *datagramPipe) run(onEnd func()) {
	go func() {
		err := errTunnelEnded
		// The capsule parser reports an end of the stream inside a capsule as
		// io.ErrUnexpectedEOF, and one between two capsules as io.EOF.
		if rerr := p.readCapsules(); errors.Is(rerr, io.ErrUnexpectedEOF) || errors.Is(rerr, errTunnelMalformed) {
			p.abort()
			err = errTunnelMalformed
		}
		p.wakeRecv(err)
		onEnd()
	}()
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
		}
		// The error of a stream or a connection is sticky, and some report themselves as a
		// timeout, which a reader would retry.
		return nil, errTunnelEnded
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

// close ends the stream once, and a later close does nothing.
func (p *datagramPipe) close() error {
	var err error
	p.closeOnce.Do(func() {
		close(p.done)
		err = p.str.Close()
		p.str.CancelRead(p.code)
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
}

func newCapsulePipe(conn net.Conn, br *bufio.Reader) *capsulePipe {
	return &capsulePipe{conn: conn, br: br}
}

// recv returns the next datagram, and aborts the stream when it ends inside a capsule or
// delivers a datagram of context ID 0 past maxCapsuleDatagram.
func (p *capsulePipe) recv(context.Context) ([]byte, error) {
	b, err := p.next()
	if errors.Is(err, errTunnelMalformed) {
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

// close ends the tunnel without waiting. The close_notify a TLS connection sends from Close
// waits up to five seconds on a client that stopped reading, so the close runs apart.
func (p *capsulePipe) close() error {
	go func() { _ = p.conn.Close() }()
	return nil
}
