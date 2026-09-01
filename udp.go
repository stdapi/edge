// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"iter"
	"net/netip"
	"slices"
	"time"
)

// DatagramOption shapes what forwarding one datagram does.
type DatagramOption interface{ applyDatagram(*datagramConfig) }

type datagramConfig struct {
	delay time.Duration
}

// datagramSink is what a datagram context writes through. The demultiplexer owning the flow
// implements it.
type datagramSink interface {
	toOrigin(b []byte) error
	toClient(b []byte) error
}

// DatagramCtx is one datagram, handed to a [UDP] handler in the direction it was travelling.
//
// The unit here is the datagram, which is what makes loss and reordering expressible: dropping
// one is something the network does anyway, so a handler may do it too. Every datagram is
// routed on its own, so removing the entry stops the flow at the next one.
//
// A context is not safe for concurrent use and may be reused as soon as the handler
// returns, so anything kept must be copied.
type DatagramCtx struct {
	ctx      context.Context
	sink     datagramSink
	p        *Proxy
	sess     *Session
	entry    *entry
	target   Target
	client   netip.AddrPort
	identity string
	payload  []byte
	params   []Param
	seq      uint64
	inbound  bool
}

// Context returns a context canceled when the flow ends.
func (c *DatagramCtx) Context() context.Context { return c.ctx }

// Bytes returns the payload of the datagram. It is only valid until the handler returns, so
// anything kept must be copied.
func (c *DatagramCtx) Bytes() []byte { return c.payload }

// Inbound reports whether the datagram is travelling from the origin toward the client. A
// handler sees both directions of its flow.
func (c *DatagramCtx) Inbound() bool { return c.inbound }

// Seq returns the index of this datagram in its flow, counted per direction and starting at
// zero.
func (c *DatagramCtx) Seq() uint64 { return c.seq }

// Target returns the authority the client was headed to.
func (c *DatagramCtx) Target() Target { return c.target }

// Client returns the address the client is sending from.
func (c *DatagramCtx) Client() netip.AddrPort { return c.client }

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

// Forward sends the datagram on, unchanged, in the direction it was travelling.
func (c *DatagramCtx) Forward(opts ...DatagramOption) error {
	return c.Send(c.payload, opts...)
}

// Send forwards b in place of the datagram the handler was given, in the direction it was
// travelling. A handler that calls neither Send nor Forward drops the datagram.
func (c *DatagramCtx) Send(b []byte, opts ...DatagramOption) error {
	cfg := &datagramConfig{}
	for _, o := range opts {
		o.applyDatagram(cfg)
	}
	if cfg.delay > 0 {
		kept := slices.Clone(b)
		ctx, sink, inbound := c.ctx, c.sink, c.inbound
		go func() {
			if sleepCtx(ctx, cfg.delay) {
				_ = writeDatagram(sink, inbound, kept)
			}
		}()
		return nil
	}
	return writeDatagram(c.sink, c.inbound, b)
}

func writeDatagram(sink datagramSink, inbound bool, b []byte) error {
	if inbound {
		return sink.toClient(b)
	}
	return sink.toOrigin(b)
}

// Drop discards the datagram. It is what not forwarding already does, spelled out so a
// handler reads as a decision rather than as a missing branch.
func (c *DatagramCtx) Drop() error { return nil }
