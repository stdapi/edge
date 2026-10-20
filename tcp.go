// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

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

	"github.com/stdapi/edge/internal/stringsutil"
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
	// mu guards the legs against the closer, which ends them from another goroutine and sets
	// closed.
	mu      sync.Mutex
	alerted bool
	closed  bool
	// ending is set once the normal end of the legs began.
	ending bool
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
// returns. If Dial fails and the handler returns an error, the client connection is reset.
func (c *TCPCtx) Dial() (net.Conn, error) {
	c.dialOnce.Do(func() {
		conn, err := c.dial()
		if err == nil {
			err = c.keep(conn, &c.up.Conn)
		}
		c.dialErr = err
	})
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
	if c.ctx.Err() != nil {
		// A dial after the end of the session opens nothing, I1.
		return nil, net.ErrClosed
	}
	// The closer of the session cancels a dial in progress, whatever ctx, I1.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("edge: dial %q: %w", addr, err)
	}
	conn, err := c.dialAddr(ctx, addr, host)
	if err != nil {
		if c.ctx.Err() != nil {
			// The dial the closer canceled fails as any dial after it.
			return nil, net.ErrClosed
		}
		return nil, err
	}
	if err := c.keep(conn, nil); err != nil {
		return nil, err
	}
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
	tc := tlsClient(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		// A failed TLS layer gives what is under it its failed end, I2.
		abort(conn)
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
// certificate authority, if the read of the ClientHello fails, if it refuses a ClientHello the
// stream ended inside or one [WithRejectECH] or [WithNameVerification] rejects, or if either
// handshake fails. Without a certificate authority or on a
// refused ClientHello, the client is sent a fatal TLS alert. The connection returned by
// [TCPCtx.Client] remains open.
func (c *TCPCtx) StartTLS() error {
	if c.sess.TLS() != nil {
		return errAlreadyTLS
	}
	p := c.p
	if p.cfg.ca == nil {
		return c.refuseTLS(c.client.Conn, alertInternalError, fmt.Errorf("%w: %w", ErrNoCertificateAuthority, errNoCA))
	}

	conn, ok := c.client.Conn.(*peekConn)
	if !ok {
		conn = newPeekConn(c.client.Conn, nil, clientHelloPeekSize)
		c.swap(&c.client.Conn, conn)
	}
	// The handler requests the termination a connection placed at its sniff timeout refuses.
	conn.lateHello = false
	// The read header timeout bounds the ClientHello and the handshake, as on any connection the
	// proxy terminates.
	if timeout := p.cfg.server.readHeaderTimeout; timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}

	hello, alert, err := p.peekClientHello(conn)
	if err != nil && alert == 0 {
		return err
	}
	if err != nil {
		return c.refuseTLS(conn, alert, err)
	}
	// The entry is decided, so the name picks the certificate and is verified, never routed.
	if hello != nil && hello.ServerName != "" && p.cfg.verifyNames == VerifyReject && c.sess.upstream.IsValid() {
		switch p.nameResolvesTo(c.ctx, stringsutil.ToLowerASCIIString(hello.ServerName), c.sess.upstream) {
		case nameMismatch:
			return c.refuseTLS(conn, alertUnrecognizedName, errNameMismatch)
		case nameUnresolved:
			return c.refuseTLS(conn, alertUnrecognizedName, errNameUnresolved)
		}
	}

	tc := tlsServer(conn, p.serverTLSConfig(c.sess, true))
	if err := tc.HandshakeContext(c.ctx); err != nil {
		// crypto/tls reports the alert it sent as a local error, and sends none on a read error.
		var local *net.OpError
		c.alerted = errors.As(err, &local) && local.Op == "local error"
		return fmt.Errorf("tls handshake with client for %s: %w", c.target.Authority(), err)
	}
	state := tc.ConnectionState()
	c.tlsState = &state
	c.swap(&c.client.Conn, tc)
	c.sess.tlsState.Store(&state)

	if c.up.Conn != nil {
		addr := cmp.Or(c.sess.dialAddr(), c.target.Authority())
		up, err := c.upgradeTLS(c.ctx, c.up.Conn, addr, c.serverName())
		if err != nil {
			return err
		}
		c.swap(&c.up.Conn, up)
	}
	return nil
}

// refuseTLS sends the client a fatal alert and returns err. The connection stays the
// handler's, and the end after the handler returns drains it as lingerClose does.
func (c *TCPCtx) refuseTLS(conn net.Conn, alert byte, err error) error {
	if writeAlert(conn, alert) == nil {
		c.alerted = true
	}
	return err
}

// lingerAfterAlert runs lingerClose on the client once the handler returned, when StartTLS
// sent an alert.
func (c *TCPCtx) lingerAfterAlert() {
	if c.alerted {
		c.alerted = false
		lingerClose(c.client.Conn)
		_ = c.client.Close()
	}
}

// heldConn is a connection as the handler holds it. StartTLS replaces the connection under
// it, so a handler holding it across the call reads plaintext after.
type heldConn struct {
	net.Conn
}

// CloseWrite half-closes the connection under it.
func (s *heldConn) CloseWrite() error { return closeWrite(s.Conn) }

func (s *heldConn) Abort() { abort(s.Conn) }

// keep records a leg the handler opened, in *slot or among the extra legs when slot is nil, and
// ends it with an error once the closer has run.
func (c *TCPCtx) keep(conn net.Conn, slot *net.Conn) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		abort(conn)
		return net.ErrClosed
	}
	if slot != nil {
		*slot = conn
	} else {
		c.extra = append(c.extra, conn)
	}
	return nil
}

// swap replaces the connection of a leg, the closer reading it under the same lock.
func (c *TCPCtx) swap(slot *net.Conn, conn net.Conn) {
	c.mu.Lock()
	*slot = conn
	c.mu.Unlock()
}

// legs ends the use of every leg and returns them, the client first, and whether their normal
// end had begun. normal begins it.
func (c *TCPCtx) legs(normal bool) ([]net.Conn, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ending := c.ending
	c.ending = c.ending || normal
	c.closed = true
	legs := make([]net.Conn, 0, 2+len(c.extra))
	legs = append(legs, c.client.Conn)
	if c.up.Conn != nil {
		legs = append(legs, c.up.Conn)
	}
	return append(legs, c.extra...), ending
}

// end runs the closer of the session once the handler returned err, I1. A client leg that got
// a TLS alert ends first with the normal end of TCP, the alert being an answer, I2.
func (c *TCPCtx) end(err error) {
	c.lingerAfterAlert()
	cs := causeReturned
	if err != nil {
		cs = causeHandlerErr
	}
	_ = c.sess.endBy(cs, time.Now().Add(alertWriteTimeout))
}

var errNoHandler = errors.New("edge: TCP entry with no handler")

// tcpCloser is the closer of a session a TCP handler serves, which gives every leg the form of
// a byte stream.
type tcpCloser TCPCtx

func (t *tcpCloser) endBy(c cause, deadline time.Time) error {
	if formOf(byteStream, c, false) == formNormal {
		legs, _ := (*TCPCtx)(t).legs(true)
		var wg sync.WaitGroup
		for _, l := range legs {
			wg.Go(func() { closeNormallyBy(l, deadline) })
		}
		wg.Wait()
		return nil
	}
	legs, ending := (*TCPCtx)(t).legs(false)
	var wg sync.WaitGroup
	for _, l := range legs {
		if ending {
			// The normal end has begun, and the close completes it.
			_ = l.Close()
			continue
		}
		wg.Go(func() { abortBy(l, deadline) })
	}
	wg.Wait()
	return nil
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
