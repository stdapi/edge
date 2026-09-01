// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"io"
	"time"
)

// RelayOption shapes what a relay does with the bytes it carries. The options apply to both
// directions unless one names a direction itself.
type RelayOption interface{ applyRelay(*relayConfig) }

type relayOptionFunc func(*relayConfig)

func (f relayOptionFunc) applyRelay(c *relayConfig) { f(c) }

type relayConfig struct {
	onBytes func(sent, received int64)
	rate    int
	delay   time.Duration
	idle    time.Duration
}

// Throttle caps a relay at n bytes per second in each direction. Zero leaves it uncapped.
func Throttle(n int) RelayOption {
	return relayOptionFunc(func(c *relayConfig) { c.rate = n })
}

// Delay holds what it applies to for d before writing it: every chunk of a relay, in each
// direction, or the datagram being forwarded. It adds latency without reordering a stream,
// which has no unit to reorder, while datagrams delayed by different amounts do reorder.
func Delay(d time.Duration) interface {
	RelayOption
	DatagramOption
} {
	return delayOption(d)
}

type delayOption time.Duration

func (d delayOption) applyRelay(c *relayConfig)       { c.delay = time.Duration(d) }
func (d delayOption) applyDatagram(c *datagramConfig) { c.delay = time.Duration(d) }

// IdleTimeout closes a relay once neither direction has moved a byte for d. Zero, the
// default, leaves it open: a stream can legitimately stay silent for a long time.
func IdleTimeout(d time.Duration) RelayOption {
	return relayOptionFunc(func(c *relayConfig) { c.idle = d })
}

// OnClose reports how many bytes a relay carried once it ends, sent counting the bytes that
// went upstream.
func OnClose(fn func(sent, received int64)) RelayOption {
	return relayOptionFunc(func(c *relayConfig) { c.onBytes = fn })
}

func newRelayConfig(opts []RelayOption) *relayConfig {
	cfg := &relayConfig{}
	for _, o := range opts {
		o.applyRelay(cfg)
	}
	return cfg
}

// relayWriter applies the shaping of a relay to one direction: it holds each chunk for the
// configured delay, then releases it at no more than the configured rate.
//
// The rate is enforced by sleeping for the time the bytes just written are worth, which keeps
// a single reader goroutine per direction and needs no timer. A burst larger than one second
// of budget is split, so a large read cannot pay for itself in one sleep and then run free.
type relayWriter struct {
	w     io.Writer
	ctx   context.Context
	rate  int
	delay time.Duration
}

func (s relayWriter) Write(b []byte) (int, error) {
	if s.delay > 0 && !sleepCtx(s.ctx, s.delay) {
		return 0, s.ctx.Err()
	}
	if s.rate <= 0 {
		return s.w.Write(b)
	}

	written := 0
	for len(b) > 0 {
		chunk := min(len(b), s.rate)
		n, err := s.w.Write(b[:chunk])
		written += n
		if err != nil {
			return written, err
		}
		b = b[n:]
		wait := time.Duration(float64(n) / float64(s.rate) * float64(time.Second))
		if wait > 0 && !sleepCtx(s.ctx, wait) {
			return written, s.ctx.Err()
		}
	}
	return written, nil
}

// sleepCtx waits for d and reports whether it ran to completion rather than being cut short
// by ctx.
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
