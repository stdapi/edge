// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/fox-toolkit/edge/internal/stringsutil"
)

// clientHelloPeekSize bounds how much of a TLS ClientHello the proxy will buffer to read the
// server name. A ClientHello carrying post-quantum key shares runs to a few kilobytes; past
// this the connection is handled without a server name rather than buffered without limit.
const clientHelloPeekSize = 16 * 1024

// OriginalDestination resolves the address a transparently redirected connection was headed
// to before the redirect. It is what makes transparent mode work for a client that sends no
// server name, and what lets the proxy reach the same origin the client had resolved.
//
// The zero result with a nil error means the destination is unknown, which is not an error:
// the proxy then falls back to the server name or the Host header.
type OriginalDestination func(net.Conn) (netip.AddrPort, error)

// ListenAndServeTransparent listens on addr and serves redirected connections. Unlike an
// explicit proxy, the client is not configured to use it: its traffic is routed here by the
// network, and the proxy works out where each connection was headed.
func (p *Proxy) ListenAndServeTransparent(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return p.ServeTransparent(ln)
}

// ServeTransparent accepts redirected connections on ln and serves them.
//
// The destination of a connection is resolved in this order: the original destination
// reported by [WithOriginalDestination], the server name of a TLS ClientHello, and the Host
// header of a plaintext request. A connection with none of the three cannot be placed and is
// closed.
func (p *Proxy) ServeTransparent(ln net.Listener) error {
	if p.srv.closing.Load() {
		return ErrProxyClosed
	}
	p.srv.trackListener(&ln, true)
	defer p.srv.trackListener(&ln, false)

	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if p.srv.closing.Load() {
				return ErrProxyClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				// A temporary accept failure, typically the file descriptor limit. Back
				// off instead of spinning on it.
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0

		p.srv.wg.Add(1)
		go func() {
			defer p.srv.wg.Done()
			if err := p.ServeConn(conn); err != nil {
				p.cfg.logger.Debug("edge: transparent connection closed", slog.String("error", err.Error()))
			}
		}()
	}
}

// ServeConn serves one already accepted connection as if it had been transparently
// redirected. It takes ownership of conn and closes it when done.
func (p *Proxy) ServeConn(conn net.Conn) error {
	p.srv.track(conn, true)
	defer func() {
		p.srv.track(conn, false)
		_ = conn.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A shutdown cancels the work in flight on this connection.
	go func() {
		select {
		case <-p.srv.closed:
			cancel()
		case <-ctx.Done():
		}
	}()

	peeked := newPeekConnSize(conn, clientHelloPeekSize)

	var origin netip.AddrPort
	if p.cfg.originalDst != nil {
		addr, err := p.cfg.originalDst(conn)
		if err != nil {
			return fmt.Errorf("resolve original destination: %w", err)
		}
		origin = addr
	}

	head, err := peeked.Peek(1)
	if err != nil {
		return nil
	}

	if head[0] == tlsHandshakeRecord {
		return p.serveTransparentTLS(ctx, peeked, origin)
	}
	return p.serveTransparentPlain(ctx, peeked, origin)
}

// serveTransparentTLS reads the server name out of the ClientHello without consuming it,
// decides what to do with the connection, and either relays it untouched or terminates it.
func (p *Proxy) serveTransparentTLS(ctx context.Context, conn *peekConn, origin netip.AddrPort) error {
	hello, _ := peekClientHello(conn.r)

	target := Target{Scheme: "https"}
	if hello != nil && hello.ServerName != "" {
		target.Host = stringsutil.ToLowerASCIIString(hello.ServerName)
	}
	if origin.IsValid() {
		target.Port = fmt.Sprint(origin.Port())
		if target.Host == "" {
			target.Host = origin.Addr().Unmap().String()
		}
	}
	if target.Port == "" {
		target.Port = "443"
	}
	if target.Host == "" {
		return errors.New("edge: transparent TLS connection with no server name and no original destination")
	}

	sess := newSession(ctx, conn, target, p.Decide(target), HTTP11)
	sess.upstream = origin
	if hello != nil {
		sess.clientHello = hello
	}

	switch sess.action {
	case Reject:
		return ErrConnectionRejected
	case Tunnel:
		upstream, err := p.dialTransparentUpstream(ctx, target, origin)
		if err != nil {
			return err
		}
		defer func() { _ = upstream.Close() }()
		_, _, err = tunnel(conn, upstream, p.cfg.server.tunnelIdleTimeout)
		return err
	default:
		return p.intercept(ctx, conn, sess)
	}
}

// serveTransparentPlain serves a redirected plaintext connection. There is nothing to sniff:
// the destination is the Host header of each request, so the connection is parsed and every
// request placed on its own.
func (p *Proxy) serveTransparentPlain(ctx context.Context, conn *peekConn, origin netip.AddrPort) error {
	target := Target{Scheme: "http", Port: "80"}
	if origin.IsValid() {
		target.Host = origin.Addr().Unmap().String()
		target.Port = fmt.Sprint(origin.Port())
	}

	sess := newSession(ctx, conn, target, Intercept, HTTP11)
	sess.upstream = origin
	sess.transparent = true

	ln := newSingleConnListener(conn, sess)
	err := p.srv.mitm.Serve(ln)
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// dialTransparentUpstream reaches the origin a redirected connection was headed to. The
// address the client had already resolved is preferred over resolving the name again, which
// could land on a different member of the same pool or on nothing at all when the name only
// resolves inside the client's own network.
func (p *Proxy) dialTransparentUpstream(ctx context.Context, target Target, origin netip.AddrPort) (net.Conn, error) {
	if origin.IsValid() {
		dial := p.cfg.transport.DialContext
		if dial == nil {
			dial = (&net.Dialer{Timeout: 30 * time.Second}).DialContext
		}
		conn, err := dial(ctx, "tcp", origin.String())
		if err != nil {
			return nil, fmt.Errorf("dial original destination %s: %w", origin, err)
		}
		return conn, nil
	}
	return p.dialUpstream(ctx, target)
}

// peekClientHello parses the TLS ClientHello waiting in br without consuming it, so the
// handshake can still be completed by whatever ends up owning the connection.
//
// Go's own TLS server does the parsing: a hand-rolled ClientHello parser would have to keep
// up with every extension a client may add, and would be a parser fed by the network.
func peekClientHello(br *bufio.Reader) (*ClientHello, error) {
	raw, err := peekHandshakeRecords(br)
	if err != nil {
		return nil, err
	}

	var captured *ClientHello
	err = tls.Server(&replayConn{r: raw}, &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			captured = &ClientHello{
				ServerName:        chi.ServerName,
				ALPN:              append([]string(nil), chi.SupportedProtos...),
				SupportedVersions: append([]uint16(nil), chi.SupportedVersions...),
				CipherSuites:      append([]uint16(nil), chi.CipherSuites...),
			}
			// The handshake has served its purpose; stopping it here keeps the parse to
			// exactly the ClientHello.
			return nil, errStopHandshake
		},
	}).Handshake()

	if captured != nil {
		return captured, nil
	}
	if err == nil {
		err = errors.New("edge: no ClientHello in the peeked bytes")
	}
	return nil, err
}

var errStopHandshake = errors.New("edge: client hello captured")

// peekHandshakeRecords returns the TLS records holding the complete first handshake message,
// without consuming them from br.
func peekHandshakeRecords(br *bufio.Reader) ([]byte, error) {
	const recordHeader = 5

	// The first record carries the handshake header, whose 3 byte length says how much of
	// the message is still to come.
	head, err := br.Peek(recordHeader + 4)
	if err != nil {
		return nil, fmt.Errorf("peek TLS record header: %w", err)
	}
	if head[0] != tlsHandshakeRecord {
		return nil, errors.New("edge: not a TLS handshake record")
	}
	if head[recordHeader] != 0x01 {
		return nil, errors.New("edge: first handshake message is not a ClientHello")
	}

	want := int(head[recordHeader+1])<<16 | int(head[recordHeader+2])<<8 | int(head[recordHeader+3])
	want += 4 // the handshake header itself

	total := 0
	payload := 0
	for payload < want {
		next, err := br.Peek(total + recordHeader)
		if err != nil {
			return nil, fmt.Errorf("peek TLS record: %w", err)
		}
		length := int(next[total+3])<<8 | int(next[total+4])
		total += recordHeader + length
		payload += length
		if total > clientHelloPeekSize {
			return nil, errors.New("edge: ClientHello larger than the peek buffer")
		}
	}

	return br.Peek(total)
}

// replayConn feeds already-read bytes to a TLS server that is only meant to parse them.
// Writes are discarded: nothing it produces reaches the client, whose handshake is completed
// later by the real server.
type replayConn struct {
	r []byte
	// off must be advanced across reads, which is why every method takes a pointer
	// receiver: on a value receiver the offset would reset and the TLS reader would see the
	// same record header forever.
	off int
}

func (c *replayConn) Read(b []byte) (int, error) {
	if c.off >= len(c.r) {
		return 0, io.EOF
	}
	n := copy(b, c.r[c.off:])
	c.off += n
	return n, nil
}

func (c *replayConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *replayConn) Close() error                     { return nil }
func (c *replayConn) LocalAddr() net.Addr              { return emptyAddr{} }
func (c *replayConn) RemoteAddr() net.Addr             { return emptyAddr{} }
func (c *replayConn) SetDeadline(time.Time) error      { return nil }
func (c *replayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *replayConn) SetWriteDeadline(time.Time) error { return nil }

type emptyAddr struct{}

func (emptyAddr) Network() string { return "peek" }
func (emptyAddr) String() string  { return "peek" }

var _ net.Conn = (*replayConn)(nil)
