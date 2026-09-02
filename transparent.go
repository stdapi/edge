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
	"net/netip"
	"time"
)

// clientHelloPeekSize bounds how much of a TLS ClientHello the proxy will buffer to read the
// server name. A ClientHello carrying post-quantum key shares runs to a few kilobytes; past
// this the connection is handled without a server name rather than buffered without limit.
const clientHelloPeekSize = 16 * 1024

// ListenAndServeTransparent listens on addr and serves redirected connections. Unlike an
// explicit proxy, the client is not configured to use it: its traffic is routed here by the
// network, and the proxy works out where each connection was headed.
func (p *Proxy) ListenAndServeTransparent(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	return p.ServeTransparent(TransparentListener(ln))
}

// ServeTransparent accepts redirected connections on ln and serves them.
//
// The destination of a connection is resolved from what an [OriginalDestination] connection
// reports, then the server name of a TLS ClientHello, then the Host header of a plaintext
// request. A connection with none of the three cannot be placed and is closed. Wrap ln in
// [TransparentListener] for the first of them.
func (p *Proxy) ServeTransparent(ln net.Listener) error {
	// A refused registration means a shutdown started; accepting would run a loop nothing
	// ever closes.
	if !p.srv.tryTrackListener(&ln) {
		return ErrProxyClosed
	}
	defer p.srv.untrackListener(&ln)

	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if p.srv.closing.Load() {
				return ErrProxyClosed
			}
			if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
				// A temporary accept failure, typically the file descriptor limit. Back
				// off instead of spinning on it.
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0

		p.srv.wg.Go(func() {
			if err := p.ServeConn(conn); err != nil {
				p.cfg.logger.Debug("edge: transparent connection closed", slog.String("error", err.Error()))
			}
		})
	}
}

// ServeConn serves one already accepted connection as if it had been transparently
// redirected. It takes ownership of conn and closes it when done.
func (p *Proxy) ServeConn(conn net.Conn) error {
	if !p.srv.tryTrack(conn) {
		_ = conn.Close()
		return ErrProxyClosed
	}
	defer func() {
		_ = conn.Close()
		p.srv.untrack(conn)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A shutdown aborts the handshake and the dials still in flight on this connection.
	// Requests being served are not on this context; they drain through the server.
	go func() {
		select {
		case <-p.srv.closed:
			cancel()
		case <-ctx.Done():
		}
	}()

	peeked := newPeekConnSize(conn, clientHelloPeekSize)

	var origin netip.AddrPort
	if od, ok := conn.(OriginalDestination); ok {
		addr, err := od.OriginalDestination()
		if err != nil {
			p.cfg.logger.Debug("edge: no original destination", slog.String("error", err.Error()))
		}
		origin = redirectedTo(addr, conn.LocalAddr())
	}
	if !origin.IsValid() {
		// Behind TPROXY the lookup has nothing to answer and the guard above would refuse
		// the socket's own address, the one place the destination actually is.
		if tc, ok := conn.(interface{ divertedTo() (netip.AddrPort, bool) }); ok {
			if diverted, ok := tc.divertedTo(); ok {
				origin = diverted
			}
		}
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

// serveTransparentTLS serves a redirected TLS connection. The destination is the authority
// it starts from, and the server name in the ClientHello replaces it before the handshake, see
// [Proxy.placeTLS].
func (p *Proxy) serveTransparentTLS(ctx context.Context, conn *peekConn, origin netip.AddrPort) error {
	target := Target{Scheme: "https", Port: "443"}
	if origin.IsValid() {
		target.Port = fmt.Sprint(origin.Port())
		target.Host = origin.Addr().Unmap().String()
	}

	sess := newSession(ctx, conn, target, 0, 0)
	sess.transparent = true
	sess.setUpstream(origin)
	return p.terminate(ctx, conn, sess)
}

// serveTransparentPlain serves a redirected connection that is not TLS. What it carries is
// already in the clear, so the first bytes name what it is, and the destination is the only
// authority the connection has for an admission to answer on.
//
// HTTP is the residual: its requests each name an authority of their own, so a connection the
// destination cannot place is still parsed and every request placed on its own.
func (p *Proxy) serveTransparentPlain(ctx context.Context, conn *peekConn, origin netip.AddrPort) error {
	target := Target{Scheme: "http", Port: "80"}
	if origin.IsValid() {
		target = Target{
			Scheme: schemeForPort(fmt.Sprint(origin.Port())),
			Host:   origin.Addr().Unmap().String(),
			Port:   fmt.Sprint(origin.Port()),
		}
	}

	sess := newSession(ctx, conn, target, 0, 0)
	sess.transparent = true
	sess.setUpstream(origin)
	sess.perRequest = true

	return p.serveCandidates(ctx, conn, sess, sniffStreamCandidates(conn, p.cfg.server.sniffTimeout), nil)
}

// redirectedTo reports where a redirected connection was headed, or the zero value. A lookup
// on a connection that was not redirected answers with the listener's own address, which
// would send the proxy back into its own socket.
func redirectedTo(origin netip.AddrPort, local net.Addr) netip.AddrPort {
	if !origin.IsValid() {
		return netip.AddrPort{}
	}
	origin = netip.AddrPortFrom(origin.Addr().Unmap(), origin.Port())
	if origin == addrPort(local) {
		return netip.AddrPort{}
	}
	return origin
}

// clientHelloFromRecords parses the TLS records in raw and returns what the client offered,
// or nil when they hold no ClientHello. Go's own TLS server does the parsing, since a
// hand-rolled parser would have to keep up with every extension a client may add, and would
// be a parser fed by the network.
func clientHelloFromRecords(raw []byte) *ClientHello {
	var captured *ClientHello
	_ = tls.Server(&replayConn{r: raw}, &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			captured = &ClientHello{
				ServerName:        chi.ServerName,
				ALPN:              append([]string(nil), chi.SupportedProtos...),
				SupportedVersions: append([]uint16(nil), chi.SupportedVersions...),
				CipherSuites:      append([]uint16(nil), chi.CipherSuites...),
			}
			// The handshake has served its purpose. Stopping it here keeps the parse to
			// exactly the ClientHello.
			return nil, errStopHandshake
		},
	}).Handshake()
	return captured
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
		if next[total] != tlsHandshakeRecord {
			// Counting another record type into the message would build a ClientHello the
			// origin's record layer never assembles.
			return nil, errors.New("edge: non-handshake record inside the ClientHello")
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

var _ net.Conn = (*replayConn)(nil)
