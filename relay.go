// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// Relayer relays byte streams between two connections. The zero value sets no idle timeout.
type Relayer struct {
	// IdleTimeout closes both connections once neither direction has transferred a byte for
	// this long. Zero disables it.
	IdleTimeout time.Duration
}

// Relay copies bytes in both directions between a and b and returns once both directions have
// ended. When one direction ends, the connection it was writing to is half-closed, and when it
// fails, the other connection is reset. aToB and bToA count the bytes written to b and to a.
func (r *Relayer) Relay(a, b net.Conn) (aToB, bToA int64, err error) {
	var (
		wg   sync.WaitGroup
		aErr error
		bErr error
	)

	idle := newIdleTracker(r.IdleTimeout, a, b)
	defer idle.stop()

	wg.Go(func() {
		aToB, aErr = copyStream(b, a, idle)
		endCopy(a, b, aErr)
		idle.arm(halfClosedIdleTimeout)
	})
	wg.Go(func() {
		bToA, bErr = copyStream(a, b, idle)
		endCopy(b, a, bErr)
		idle.arm(halfClosedIdleTimeout)
	})
	wg.Wait()

	return aToB, bToA, errors.Join(filterCopyErr(aErr), filterCopyErr(bErr))
}

// Relay copies bytes in both directions between a and b with a zero [Relayer].
func Relay(a, b net.Conn) (aToB, bToA int64, err error) {
	return (&Relayer{}).Relay(a, b)
}

// Throttled returns c with its writes limited to bytesPerSecond. Wrapping one connection of a
// relay limits one direction. Zero or negative disables the limit. A write in progress
// completes its pacing before a close of c takes effect, for at most one second.
func Throttled(c net.Conn, bytesPerSecond int) net.Conn {
	return &shapedConn{Conn: c, rate: bytesPerSecond}
}

// Delayed returns c with every write held for d before it reaches c. A write in progress
// completes its delay before a close of c takes effect.
func Delayed(c net.Conn, d time.Duration) net.Conn {
	return &shapedConn{Conn: c, delay: d}
}

// shapedConn holds each write for the delay, then paces it at the rate. A write is split into
// chunks of at most one second of rate, so a single sleep never pays for more than that.
type shapedConn struct {
	net.Conn
	rate  int
	delay time.Duration
}

func (s *shapedConn) Write(b []byte) (int, error) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	if s.rate <= 0 {
		return s.Conn.Write(b)
	}

	written := 0
	for len(b) > 0 {
		chunk := min(len(b), s.rate)
		n, err := s.Conn.Write(b[:chunk])
		written += n
		if err != nil {
			return written, err
		}
		b = b[n:]
		wait := time.Duration(float64(n) / float64(s.rate) * float64(time.Second))
		if wait > 0 {
			time.Sleep(wait)
		}
	}
	return written, nil
}

// CloseWrite half-closes the wrapped connection.
func (s *shapedConn) CloseWrite() error { return closeWrite(s.Conn) }

func (s *shapedConn) Abort() { abort(s.Conn) }

// sleepCtx sleeps for d and reports false when ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if ctx == nil {
		time.Sleep(d)
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
