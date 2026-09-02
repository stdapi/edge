// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
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
	// maxCapsuleDatagram bounds a DATAGRAM capsule a peer sends, a context ID ahead of the
	// 65527 bytes of UDP payload RFC 9298 section 5 allows. A larger one is dropped without
	// being buffered.
	maxCapsuleDatagram = 8 + 65527
)

// tunnelPipe moves the datagrams of one CONNECT-UDP tunnel, as HTTP Datagrams on an HTTP/3
// stream or as DATAGRAM capsules on a byte stream. Every datagram starts with its context ID.
type tunnelPipe interface {
	// recv returns the next datagram, in a slice the caller owns.
	recv(ctx context.Context) ([]byte, error)
	// send writes b, whose first capsuleHeadroom bytes are room for a capsule header.
	send(b []byte) error
	setReadDeadline(t time.Time) error
	setWriteDeadline(t time.Time) error
	// close ends the pipe in both directions and unblocks recv and send.
	close() error
}

type h3DatagramStream interface {
	io.Reader
	Close() error
	CancelRead(quic.StreamErrorCode)
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

// datagramPipe is a tunnel on an HTTP/3 stream, its datagrams in QUIC DATAGRAM frames. The
// capsules on the stream itself are read and dropped, RFC 9297 section 3.2, and the end of
// the stream ends the tunnel.
type datagramPipe struct {
	str      h3DatagramStream
	deadline atomic.Pointer[time.Time]
	// code is the STOP_SENDING close sends, the request cancelled from the proxy and no
	// error from the client.
	code quic.StreamErrorCode
}

func newDatagramPipe(str h3DatagramStream, code quic.StreamErrorCode) *datagramPipe {
	return &datagramPipe{str: str, code: code}
}

// run reads the capsules on the stream and calls onEnd when the stream ends.
func (p *datagramPipe) run(onEnd func()) {
	go p.drainCapsules(onEnd)
}

func (p *datagramPipe) drainCapsules(onEnd func()) {
	parser := http3.NewCapsuleParser(p.str)
	for {
		_, r, err := parser.Next()
		if err != nil {
			break
		}
		if err := r.Discard(); err != nil {
			break
		}
	}
	onEnd()
}

func (p *datagramPipe) recv(ctx context.Context) ([]byte, error) {
	rctx := ctx
	if dl := p.deadline.Load(); dl != nil && !dl.IsZero() {
		var cancel context.CancelFunc
		rctx, cancel = context.WithDeadline(ctx, *dl)
		defer cancel()
	}
	b, err := p.str.ReceiveDatagram(rctx)
	if err == nil {
		return b, nil
	}
	if rctx.Err() != nil && ctx.Err() == nil {
		return nil, os.ErrDeadlineExceeded
	}
	// The error of a stream or a connection is sticky, and some report themselves as a
	// timeout, which a reader would retry.
	return nil, errTunnelEnded
}

func (p *datagramPipe) send(b []byte) error { return p.str.SendDatagram(b[capsuleHeadroom:]) }

func (p *datagramPipe) setReadDeadline(t time.Time) error { p.deadline.Store(&t); return nil }
func (p *datagramPipe) setWriteDeadline(time.Time) error  { return nil }

func (p *datagramPipe) close() error {
	err := p.str.Close()
	p.str.CancelRead(p.code)
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

func (p *capsulePipe) recv(context.Context) ([]byte, error) {
	for {
		if p.skip > 0 {
			n, err := p.br.Discard(int(min(p.skip, 1<<30)))
			p.skip -= uint64(n) //nolint:gosec // never negative, Discard counts bytes
			if err != nil {
				return nil, err
			}
			continue
		}
		if p.pending != nil {
			n, err := io.ReadFull(p.br, p.pending[p.n:])
			p.n += n
			if err != nil {
				return nil, err
			}
			b := p.pending
			p.pending, p.n = nil, 0
			return b, nil
		}
		typ, length, hdr, err := p.header()
		if err != nil {
			return nil, err
		}
		if _, err := p.br.Discard(hdr); err != nil {
			return nil, err
		}
		if typ != capsuleDatagram || length > maxCapsuleDatagram {
			p.skip = length
			continue
		}
		p.pending = make([]byte, length)
	}
}

func (p *capsulePipe) header() (typ, length uint64, n int, err error) {
	typ, tl, err := p.peekVarint(0)
	if err != nil {
		return 0, 0, 0, err
	}
	length, ll, err := p.peekVarint(tl)
	if err != nil {
		return 0, 0, 0, err
	}
	return typ, length, tl + ll, nil
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
	n := uint64(len(b) - capsuleHeadroom) //nolint:gosec // the headroom is part of every b
	start := capsuleHeadroom - 1 - quicvarint.Len(n)
	b[start] = capsuleDatagram
	quicvarint.Append(b[start+1:start+1], n)
	_, err := p.conn.Write(b[start:])
	return err
}

func (p *capsulePipe) setReadDeadline(t time.Time) error  { return p.conn.SetReadDeadline(t) }
func (p *capsulePipe) setWriteDeadline(t time.Time) error { return p.conn.SetWriteDeadline(t) }
func (p *capsulePipe) close() error                       { return p.conn.Close() }
