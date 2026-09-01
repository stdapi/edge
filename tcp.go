// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"iter"
	"net"
	"slices"
	"sync"
	"time"
)

// TCPCtx is one byte stream, handed to a [TCP] handler. When the client used TLS, the proxy
// terminated it, so the handler reads and writes plaintext and [TCPCtx.Dial] opens the
// upstream connection with the same TLS parameters. An entry removed while the stream is open
// applies to the next connection.
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
	identity string
	params   []Param
	extra    []net.Conn

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

// ALPN returns the application protocol negotiated with the client, or an empty string
// without TLS or when the client offered none.
func (c *TCPCtx) ALPN() string {
	if c.tlsState == nil {
		return ""
	}
	return c.tlsState.NegotiatedProtocol
}

// TLS returns the state of the handshake terminated with the client, or nil for a stream that
// arrived in the clear.
func (c *TCPCtx) TLS() *tls.ConnectionState { return c.tlsState }

// Client returns the client side of the stream, in plaintext. A read consumes the bytes,
// which are then not relayed.
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

// Dial opens the upstream connection and returns it. It dials once, and every later call
// returns the same connection. When the client used TLS, the upstream handshake uses the same
// server name and the same application protocol the proxy negotiated with the client, and an
// origin that rejects that protocol fails the dial. The connection is closed when the handler
// returns.
func (c *TCPCtx) Dial() (net.Conn, error) {
	c.dialOnce.Do(func() { c.dialed, c.dialErr = c.dial() })
	return c.dialed, c.dialErr
}

func (c *TCPCtx) dial() (net.Conn, error) {
	// The destination the client fixed comes first, which behind a redirect may be the only
	// address that resolves at all.
	addr := c.sess.dialAddr()
	if addr == "" {
		addr = c.target.Authority()
	}
	return c.dialAddr(c.ctx, addr, c.target.Host)
}

// DialTo opens a connection to addr, given as host:port, with the transport the proxy is
// configured with and the TLS parameters of [TCPCtx.Dial], the server name taken from addr.
// Set a dial timeout through ctx. Every call opens a new connection, closed when the handler
// returns.
func (c *TCPCtx) DialTo(ctx context.Context, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("edge: dial %q: %w", addr, err)
	}
	conn, err := c.dialAddr(ctx, addr, host)
	if err != nil {
		return nil, err
	}
	c.extra = append(c.extra, conn)
	return conn, nil
}

func (c *TCPCtx) dialAddr(ctx context.Context, addr, serverName string) (net.Conn, error) {
	dial := c.p.cfg.transport.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	if c.tlsState == nil {
		return conn, nil
	}

	cfg := c.p.cfg.transport.upstreamTLSConfig()
	cfg.ServerName = serverName
	if c.tlsState.NegotiatedProtocol != "" {
		cfg.NextProtos = []string{c.tlsState.NegotiatedProtocol}
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tls handshake with %s: %w", addr, err)
	}
	return tc, nil
}

// close releases the connections the handler opened, once the handler has returned.
func (c *TCPCtx) close() {
	if c.dialed != nil {
		_ = c.dialed.Close()
	}
	for _, conn := range c.extra {
		_ = conn.Close()
	}
}

// Relay dials the upstream connection and relays the stream in both directions until both
// have ended. Shaping, byte counts and an idle timeout are available through [Relay],
// [Relayer], [Throttled] and [Delayed].
//
//	up, err := c.Dial()
//	if err != nil {
//		return err
//	}
//	_, _, err = edge.Relay(c.Client(), edge.Throttled(up, 256<<10))
func (c *TCPCtx) Relay() error {
	upstream, err := c.Dial()
	if err != nil {
		return err
	}
	_, _, err = Relay(c.conn, upstream)
	return err
}
