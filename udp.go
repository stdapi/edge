// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"context"
	"iter"
	"net/netip"
	"slices"
	"time"
)

// DatagramOption configures how a datagram is sent.
type DatagramOption interface{ applyDatagram(*datagramConfig) }

type datagramConfig struct {
	delay time.Duration
}

// Delay holds the datagram for d before it is sent. The payload is copied, so the handler may
// return before the send. Datagrams delayed by different amounts may be reordered.
func Delay(d time.Duration) DatagramOption { return delayOption(d) }

type delayOption time.Duration

func (d delayOption) applyDatagram(c *datagramConfig) { c.delay = time.Duration(d) }

// datagramSink is what a datagram context writes through. The demultiplexer owning the flow
// implements it.
type datagramSink interface {
	toOrigin(b []byte) error
	toClient(b []byte) error
	toAddr(addr string, b []byte) error
}

// DatagramCtx is one datagram, handed to a [UDP] handler. A handler receives the datagrams of
// both directions of a flow, and each datagram is routed on its own.
//
// A context is not safe for concurrent use and is reused once the handler returns, so
// anything kept past that must be copied.
type DatagramCtx struct {
	ctx      context.Context
	sink     datagramSink
	p        *Proxy
	sess     *Session
	entry    *entry
	target   Target
	client   netip.AddrPort
	origin   netip.AddrPort
	identity string
	payload  []byte
	params   []Param
	seq      uint64
	inbound  bool
}

// Context returns a context canceled when the flow ends.
func (c *DatagramCtx) Context() context.Context { return c.ctx }

// Bytes returns the payload. It is valid until the handler returns.
func (c *DatagramCtx) Bytes() []byte { return c.payload }

// Inbound reports whether the origin sent the datagram toward the client.
func (c *DatagramCtx) Inbound() bool { return c.inbound }

// Seq returns the index of this datagram in its flow, counted per direction and starting at
// zero.
func (c *DatagramCtx) Seq() uint64 { return c.seq }

// Target returns the authority the client was headed to.
func (c *DatagramCtx) Target() Target { return c.target }

// Client returns the address the client is sending from.
func (c *DatagramCtx) Client() netip.AddrPort { return c.client }

// Origin returns the address of the origin the datagram was received from, or is headed to.
// A reply to a datagram sent with [DatagramCtx.SendTo] reports the address it was sent to.
func (c *DatagramCtx) Origin() netip.AddrPort { return c.origin }

// Session returns the flow this datagram belongs to.
func (c *DatagramCtx) Session() *Session { return c.sess }

// Identity returns what the configured authenticator reported for the flow, or an empty
// string when none did.
func (c *DatagramCtx) Identity() string { return c.identity }

// Pattern returns the pattern of the matched entry.
func (c *DatagramCtx) Pattern() string {
	if c.entry == nil {
		return ""
	}
	return c.entry.pattern.str
}

// Entry returns the matched entry.
func (c *DatagramCtx) Entry() Entry[UDP] { return Entry[UDP]{e: c.entry} }

// Params returns an iterator over the parameters matched in the pattern.
func (c *DatagramCtx) Params() iter.Seq[Param] { return slices.Values(c.params) }

// Param returns the value matched for the named parameter, or an empty string.
func (c *DatagramCtx) Param(name string) string {
	for _, p := range c.params {
		if p.Key == name {
			return p.Value
		}
	}
	return ""
}

// Proxy returns the [Proxy] serving this flow.
func (c *DatagramCtx) Proxy() *Proxy { return c.p }

// Forward sends the datagram unchanged, in its direction.
func (c *DatagramCtx) Forward(opts ...DatagramOption) error {
	return c.Send(c.payload, opts...)
}

// Send sends b in place of the datagram, in its direction. A handler that calls none of
// Send, Reply and Forward drops the datagram.
func (c *DatagramCtx) Send(b []byte, opts ...DatagramOption) error {
	return c.write(c.inbound, b, opts)
}

// Reply sends b to the peer the datagram came from. The other peer receives nothing.
func (c *DatagramCtx) Reply(b []byte, opts ...DatagramOption) error {
	return c.write(!c.inbound, b, opts)
}

// SendTo sends b to addr, given as host:port, in place of the origin the client addressed. The
// replies of addr arrive on this flow as inbound datagrams with [DatagramCtx.Origin] set to its
// address, and reach the client from the origin it addressed. It returns [ErrTooManyOrigins]
// once the flow has reached its limit of origins.
func (c *DatagramCtx) SendTo(addr string, b []byte, opts ...DatagramOption) error {
	cfg := &datagramConfig{}
	for _, o := range opts {
		o.applyDatagram(cfg)
	}
	if cfg.delay > 0 {
		kept := slices.Clone(b)
		ctx, sink := c.ctx, c.sink
		go func() {
			if sleepCtx(ctx, cfg.delay) {
				_ = sink.toAddr(addr, kept)
			}
		}()
		return nil
	}
	return c.sink.toAddr(addr, b)
}

func (c *DatagramCtx) write(inbound bool, b []byte, opts []DatagramOption) error {
	cfg := &datagramConfig{}
	for _, o := range opts {
		o.applyDatagram(cfg)
	}
	if cfg.delay > 0 {
		kept := slices.Clone(b)
		ctx, sink := c.ctx, c.sink
		go func() {
			if sleepCtx(ctx, cfg.delay) {
				_ = writeDatagram(sink, inbound, kept)
			}
		}()
		return nil
	}
	return writeDatagram(c.sink, inbound, b)
}

func writeDatagram(sink datagramSink, inbound bool, b []byte) error {
	if inbound {
		return sink.toClient(b)
	}
	return sink.toOrigin(b)
}

// Drop discards the datagram. It is equivalent to returning without sending.
func (c *DatagramCtx) Drop() error { return nil }
