// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"iter"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/fox-toolkit/edge/internal/stringsutil"
)

var errAlreadyTLS = errors.New("edge: the stream is already under TLS")

// TCPCtx is the byte stream handed to a [TCP] handler. When the client uses TLS, the proxy
// terminates it. The handler reads and writes plaintext, and [TCPCtx.Dial] opens the upstream
// connection with the same TLS parameters. For protocols that negotiate TLS in band, the
// handler calls [TCPCtx.StartTLS]. Removing an entry does not affect a stream already open.
type TCPCtx struct {
	ctx     context.Context
	dialErr error
	p       *Proxy
	sess    *Session
	entry   *entry
	client  heldConn
	up      heldConn
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

// TLS returns the state of the handshake terminated with the client, or nil while the stream
// is in the clear.
func (c *TCPCtx) TLS() *tls.ConnectionState { return c.tlsState }

// Client returns the client side of the stream, in plaintext. A read consumes the bytes,
// which are then not relayed. The connection returned stays valid across
// [TCPCtx.StartTLS], reading and writing the terminated stream after it.
func (c *TCPCtx) Client() net.Conn { return &c.client }

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
// origin that rejects that protocol fails the dial. The connection returned stays valid
// across [TCPCtx.StartTLS], which upgrades it in place, and is closed when the handler
// returns.
func (c *TCPCtx) Dial() (net.Conn, error) {
	c.dialOnce.Do(func() { c.up.Conn, c.dialErr = c.dial() })
	if c.dialErr != nil {
		return nil, c.dialErr
	}
	return &c.up, nil
}

func (c *TCPCtx) dial() (net.Conn, error) {
	// The destination the client fixed comes first, which behind a redirect may be the only
	// address that resolves at all.
	addr := c.sess.dialAddr()
	if addr == "" {
		addr = c.target.Authority()
	}
	return c.dialAddr(c.ctx, addr, c.serverName())
}

// serverName is the name the upstream handshake verifies, the one the client sent or the
// target's without one.
func (c *TCPCtx) serverName() string {
	if c.tlsState != nil && c.tlsState.ServerName != "" {
		return stringsutil.ToLowerASCIIString(c.tlsState.ServerName)
	}
	return c.target.Host
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
	scheme := "http"
	if c.tlsState != nil {
		scheme = "https"
	}
	conn, err := c.p.srv.fwd.up.dial(ctx, "tcp", addr, scheme)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	if c.tlsState == nil {
		return conn, nil
	}
	return c.upgradeTLS(ctx, conn, addr, serverName)
}

// upgradeTLS runs the upstream handshake on conn, mirroring the one terminated with the
// client, and closes conn when it fails.
func (c *TCPCtx) upgradeTLS(ctx context.Context, conn net.Conn, addr, serverName string) (net.Conn, error) {
	cfg := c.p.cfg.transport.upstreamTLSConfig()
	cfg.ServerName = serverName
	if c.tlsState.NegotiatedProtocol != "" {
		cfg.NextProtos = []string{c.tlsState.NegotiatedProtocol}
	}
	if timeout := c.p.cfg.transport.TLSHandshakeTimeout; timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tls handshake with %s: %w", addr, err)
	}
	return tc, nil
}

// StartTLS switches an unencrypted stream to TLS, terminating the handshake the client
// sends next. It is meant for protocols that negotiate TLS in band, such as SMTP with
// STARTTLS or Postgres with SSLRequest. It should be called after relaying the prelude and
// before reading anything else.
//
// The client is presented a certificate for the server name it sends, or for the target if
// it sends none. If Dial has been called, its connection is switched to TLS as well, with
// the same server name and protocol and the trust settings of the [Transport].
//
// After a call to StartTLS, the connections returned by [TCPCtx.Client] and [TCPCtx.Dial]
// remain valid, and reads and writes on them are plaintext. [TCPCtx.TLS] and [Session.TLS]
// return the state of the client handshake, and [TCPCtx.Target] is not affected.
//
// StartTLS returns an error if the stream is already using TLS, if the proxy has no
// certificate authority, or if either handshake fails.
func (c *TCPCtx) StartTLS() error {
	if c.sess.TLS() != nil {
		return errAlreadyTLS
	}
	p := c.p
	if p.cfg.ca == nil {
		return fmt.Errorf("%w: %w", ErrNoCertificateAuthority, errNoCA)
	}

	conn, ok := c.client.Conn.(*peekConn)
	if !ok {
		conn = newPeekConn(c.client.Conn, nil, clientHelloPeekSize)
		c.client.Conn = conn
	}
	if timeout := p.cfg.transport.TLSHandshakeTimeout; timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}

	hello, err := p.peekClientHello(conn)
	if err != nil {
		return err
	}
	// The entry is decided, so the name picks the certificate and is verified, never routed.
	if hello != nil && hello.ServerName != "" && p.cfg.verifyNames == VerifyReject && c.sess.upstream.IsValid() {
		switch p.nameResolvesTo(c.ctx, stringsutil.ToLowerASCIIString(hello.ServerName), c.sess.upstream) {
		case nameMismatch:
			return errNameMismatch
		case nameUnresolved:
			return errNameUnresolved
		}
	}

	tlsConn := tls.Server(conn, p.serverTLSConfig(c.sess))
	if err := tlsConn.HandshakeContext(c.ctx); err != nil {
		return fmt.Errorf("tls handshake with client for %s: %w", c.target.Authority(), err)
	}
	state := tlsConn.ConnectionState()
	c.tlsState = &state
	c.client.Conn = tlsConn
	c.sess.tlsState.Store(&state)

	if c.up.Conn != nil {
		addr := cmp.Or(c.sess.dialAddr(), c.target.Authority())
		up, err := c.upgradeTLS(c.ctx, c.up.Conn, addr, c.serverName())
		if err != nil {
			return err
		}
		c.up.Conn = up
	}
	return nil
}

// heldConn is a connection as the handler holds it. StartTLS replaces the connection under
// it, so a handler holding it across the call reads plaintext after.
type heldConn struct {
	net.Conn
}

// CloseWrite half-closes the connection under it.
func (s *heldConn) CloseWrite() error { return closeWrite(s.Conn) }

func (s *heldConn) Abort() { abort(s.Conn) }

// close releases the connections the handler opened, once the handler has returned.
func (c *TCPCtx) close() {
	if c.up.Conn != nil {
		_ = c.up.Close()
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
	_, _, err = Relay(&c.client, upstream)
	return err
}
