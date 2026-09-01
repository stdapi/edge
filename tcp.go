// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"iter"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// TCPCtx is one byte stream, handed to a [TCP] handler in the clear. When the client spoke
// TLS the proxy terminated it, so what the handler reads and writes is the plaintext, and
// what [TCPCtx.Dial] opens upstream carries the same TLS the client asked for.
//
// The unit here is the whole stream. A stream has nothing to drop, and an entry removed while
// it runs governs the next connection rather than this one.
type TCPCtx struct {
	ctx     context.Context
	conn    net.Conn
	dialed  net.Conn
	dialErr error
	p       *Proxy
	sess    *Session
	entry   *entry
	// tlsState describes the handshake the proxy terminated with the client, nil when the
	// stream arrived in the clear.
	tlsState *tls.ConnectionState

	target   Target
	upstream netip.AddrPort
	identity string
	params   []Param

	dialOnce sync.Once
}

// Context returns a context canceled when the connection ends.
func (c *TCPCtx) Context() context.Context { return c.ctx }

// Session returns the client connection this stream belongs to.
func (c *TCPCtx) Session() *Session { return c.sess }

// Target returns the authority the client was headed to.
func (c *TCPCtx) Target() Target { return c.target }

// Identity returns what the configured authenticator reported for the connection, or an empty
// string when none did.
func (c *TCPCtx) Identity() string { return c.identity }

// ALPN returns the application protocol negotiated with the client, or an empty string when
// the stream carries no TLS or the client offered none.
func (c *TCPCtx) ALPN() string {
	if c.tlsState == nil {
		return ""
	}
	return c.tlsState.NegotiatedProtocol
}

// TLS returns the state of the handshake terminated with the client, or nil for a stream that
// arrived in the clear.
func (c *TCPCtx) TLS() *tls.ConnectionState { return c.tlsState }

// Client returns the client side of the stream, in the clear. Reading it consumes the bytes,
// so a handler either drives both sides itself or calls [TCPCtx.Relay].
func (c *TCPCtx) Client() net.Conn { return c.conn }

// Pattern returns the pattern of the matched entry.
func (c *TCPCtx) Pattern() string {
	if c.entry == nil {
		return ""
	}
	return c.entry.pattern.str
}

// Entry returns the matched entry.
func (c *TCPCtx) Entry() Entry[TCP] { return Entry[TCP]{e: c.entry} }

// Params returns an iterator over the parameters matched in the pattern.
func (c *TCPCtx) Params() iter.Seq[Param] { return slices.Values(c.params) }

// Param returns the value matched for the named parameter, or an empty string.
func (c *TCPCtx) Param(name string) string {
	for _, p := range c.params {
		if p.Key == name {
			return p.Value
		}
	}
	return ""
}

// Proxy returns the [Proxy] serving this stream.
func (c *TCPCtx) Proxy() *Proxy { return c.p }

// Dial opens the upstream side of the stream and returns it, opening it once however many
// times it is called. When the client spoke TLS the connection is wrapped in a handshake
// carrying the same server name and the same protocol the proxy negotiated with the client.
//
// That commits both sides to one protocol before the origin has been asked. A client offering
// several and an origin speaking only the second connect directly but fail here, because a
// relay whose two ends speak different protocols carries nothing. The alternative, dialing the
// origin before answering the client, would let the origin's failures and its latency show
// through the handshake instead.
//
// The caller does not own the returned connection: it is closed when the handler returns.
func (c *TCPCtx) Dial() (net.Conn, error) {
	c.dialOnce.Do(func() { c.dialed, c.dialErr = c.dial() })
	return c.dialed, c.dialErr
}

func (c *TCPCtx) dial() (net.Conn, error) {
	addr := c.target.Authority()
	if c.upstream.IsValid() {
		// A transparently redirected stream goes back to the address the client had already
		// resolved, which behind a redirect may be the only one that resolves at all.
		addr = c.upstream.String()
	}

	dial := c.p.cfg.transport.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	conn, err := dial(c.ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	if c.tlsState == nil {
		return conn, nil
	}

	cfg := c.p.cfg.transport.upstreamTLSConfig()
	cfg.ServerName = c.target.Host
	if c.tlsState.NegotiatedProtocol != "" {
		cfg.NextProtos = []string{c.tlsState.NegotiatedProtocol}
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(c.ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tls handshake with %s: %w", addr, err)
	}
	return tc, nil
}

// Relay opens the upstream side and copies bytes both ways until either end is done. It
// returns when both directions have finished.
//
//	return c.Relay(edge.Throttle(256<<10), edge.Delay(50*time.Millisecond))
func (c *TCPCtx) Relay(opts ...RelayOption) error {
	upstream, err := c.Dial()
	if err != nil {
		return err
	}
	cfg := newRelayConfig(opts)

	var (
		wg      sync.WaitGroup
		toUp    int64
		toDown  int64
		upErr   error
		downErr error
	)

	idle := newIdleTracker(cfg.idle, c.conn, upstream)
	defer idle.stop()

	up := relayWriter{w: upstream, ctx: c.ctx, rate: cfg.rate, delay: cfg.delay}
	down := relayWriter{w: c.conn, ctx: c.ctx, rate: cfg.rate, delay: cfg.delay}

	wg.Go(func() {
		toUp, upErr = copyStream(up, c.conn, idle)
		halfClose(upstream)
		idle.arm(halfClosedIdleTimeout)
	})
	wg.Go(func() {
		toDown, downErr = copyStream(down, upstream, idle)
		halfClose(c.conn)
		idle.arm(halfClosedIdleTimeout)
	})
	wg.Wait()

	if cfg.onBytes != nil {
		cfg.onBytes(toUp, toDown)
	}
	return errors.Join(filterCopyErr(upErr), filterCopyErr(downErr))
}
