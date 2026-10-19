// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
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
// A connection is routed on the server name of its TLS ClientHello, or on the authority of
// the first request of a plaintext HTTP connection, and dialed to the destination an
// [OriginalDestination] connection reports. A connection opening with the HTTP/2 preface is
// routed on that destination, each of its requests on its own authority. A connection with
// neither a name nor a destination cannot be placed and is closed. Wrap ln in
// [TransparentListener] for the destination.
// It always returns a non-nil error and closes ln. After [Proxy.Shutdown] or [Proxy.Close] has
// begun, the returned error is [ErrProxyClosed], once ln is closed.
func (p *Proxy) ServeTransparent(ln net.Listener) error {
	return p.acceptEach(ln, p.serveRedirected, "transparent connection closed")
}

func (p *Proxy) acceptEach(ln net.Listener, serve func(net.Conn) error, closed string) error {
	// A refused registration means a shutdown started; accepting would run a loop nothing
	// ever closes.
	if !p.srv.tryTrackListener(&ln) {
		// As net/http's Serve does.
		_ = ln.Close()
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
			if temporaryAccept(err) {
				// Back off instead of spinning on it.
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			_ = ln.Close()
			return err
		}
		delay = 0

		// Tracked at its accept, so a drain that starts before its goroutine runs serves it.
		if !p.srv.tryTrack(conn) {
			abort(conn)
			continue
		}
		go func() {
			if err := serve(conn); err != nil {
				p.cfg.logger.Debug("edge: "+closed, slog.String("error", err.Error()))
			}
		}()
	}
}

// ServeConn serves one already accepted connection as if it had been transparently
// redirected. It takes ownership of conn and closes it when done. It returns once the
// connection ended: [ErrProxyClosed] when called after [Proxy.Shutdown] or [Proxy.Close]
// started or once a cut ended it, nil when a normal cause such as [Session.Close] or a refusal
// ended it, and otherwise the error that ended it.
func (p *Proxy) ServeConn(conn net.Conn) error {
	if !p.srv.tryTrack(conn) {
		abort(conn)
		return ErrProxyClosed
	}
	var sess *Session
	err := p.serveRedirectedAs(conn, &sess)
	if p.srv.cutting() {
		// The error a handler returns on the end of its context is the cut's.
		return ErrProxyClosed
	}
	if sess != nil {
		switch c := sess.end.first(); {
		case c == causeCut:
			err = ErrProxyClosed
		case c != causeNone && !c.failed():
			err = nil
		}
	}
	return err
}

// serveRedirected serves a redirected connection [server.tryTrack] admitted, and untracks it.
func (p *Proxy) serveRedirected(conn net.Conn) error { return p.serveRedirectedAs(conn, nil) }

// serveRedirectedAs is serveRedirected, which sets *registered to the session it registers when
// registered is not nil.
func (p *Proxy) serveRedirectedAs(conn net.Conn, registered **Session) error {
	defer func() {
		_ = conn.Close()
		p.srv.untrack(conn)
	}()

	// The session context ends with the session, by its closer or its end, and a drain leaves
	// it running.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	peeked := newPeekConn(conn, nil, clientHelloPeekSize)

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

	head, err := peekFirst(peeked, p.cfg.server.sniffTimeout)
	silent := isTimeout(err)
	if err != nil && !silent {
		if errors.Is(err, io.EOF) {
			return nil
		}
		// A peer reset before the first byte, the connection closed with it.
		return err
	}
	if p.fromItself(conn.RemoteAddr(), conn.LocalAddr(), origin) {
		abort(conn)
		return nil
	}

	if !silent && head[0] == tlsHandshakeRecord {
		return p.serveTransparentTLS(ctx, cancel, peeked, origin, registered)
	}
	return p.serveTransparentPlain(ctx, cancel, peeked, origin, silent, registered)
}

// serveTransparentTLS serves a redirected TLS connection. The destination is the authority
// it starts from, and the server name in the ClientHello replaces it before the handshake, see
// [Proxy.placeTLS].
func (p *Proxy) serveTransparentTLS(ctx context.Context, cancel context.CancelFunc, conn *peekConn, origin netip.AddrPort, registered **Session) error {
	target := Target{Scheme: "https", Port: "443"}
	if origin.IsValid() {
		target.Port = fmt.Sprint(origin.Port())
		target.Host = origin.Addr().Unmap().String()
	}

	sess := newSession(p, ctx, conn, target, 0, 0)
	sess.cancel = cancel
	sess.transparent = true
	sess.setUpstream(origin)
	if !p.srv.registerSession(sess, (*pendingSocket)(conn)) {
		conn.Abort()
		return ErrProxyClosed
	}
	if registered != nil {
		*registered = sess
	}
	defer p.srv.untrackSession(sess)
	return p.terminate(ctx, conn, sess)
}

// serveTransparentPlain serves a redirected connection that is not TLS, as a byte stream when
// it sent nothing within the sniff timeout.
func (p *Proxy) serveTransparentPlain(ctx context.Context, cancel context.CancelFunc, conn *peekConn, origin netip.AddrPort, silent bool, registered **Session) error {
	target := Target{Scheme: "http", Port: "80"}
	if origin.IsValid() {
		target = Target{
			Scheme: schemeForPort(fmt.Sprint(origin.Port())),
			Host:   origin.Addr().Unmap().String(),
			Port:   fmt.Sprint(origin.Port()),
		}
	}

	sess := newSession(p, ctx, conn, target, 0, 0)
	sess.cancel = cancel
	sess.transparent = true
	sess.setUpstream(origin)
	if !p.srv.registerSession(sess, (*pendingSocket)(conn)) {
		conn.Abort()
		return ErrProxyClosed
	}
	if registered != nil {
		*registered = sess
	}
	defer p.srv.untrackSession(sess)
	if silent {
		return p.serveSilent(ctx, conn, sess)
	}
	return p.servePlain(ctx, conn, sess)
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
// or nil and the alert Go's TLS server sent on them, zero when it sent none. Go's own TLS
// server does the parsing, since a hand-rolled parser would have to keep up with every
// extension a client may add, and would be a parser fed by the network.
func clientHelloFromRecords(raw []byte) (*ClientHello, byte) {
	var captured *ClientHello
	conn := &replayConn{r: raw}
	_ = tls.Server(conn, &tls.Config{
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
	if captured != nil {
		// The alert is the one errStopHandshake made it send.
		return captured, 0
	}
	return nil, conn.alert
}

var errStopHandshake = errors.New("edge: client hello captured")

// peekHandshakeRecords returns the TLS records holding the complete first handshake message,
// without consuming them from br.
func peekHandshakeRecords(conn *peekConn) ([]byte, error) {
	const recordHeader = 5

	// The 4 byte handshake header may itself be fragmented across records, so its length is
	// only known once 4 bytes of payload have arrived.
	var head [4]byte
	got, want, total := 0, -1, 0
	for want < 0 || got < want {
		next, err := conn.Peek(total + recordHeader)
		if err != nil {
			return nil, fmt.Errorf("peek TLS record: %w", err)
		}
		if next[total] != tlsHandshakeRecord {
			// Counting another record type into the message would build a ClientHello the
			// origin's record layer never assembles.
			return nil, errors.New("edge: non-handshake record inside the ClientHello")
		}
		length := int(next[total+3])<<8 | int(next[total+4])
		if length == 0 {
			return nil, errors.New("edge: empty handshake record")
		}
		if total+recordHeader+length > clientHelloPeekSize {
			return nil, errors.New("edge: ClientHello larger than the peek buffer")
		}
		if got < len(head) {
			rec, err := conn.Peek(total + recordHeader + length)
			if err != nil {
				return nil, fmt.Errorf("peek TLS record: %w", err)
			}
			n := copy(head[got:], rec[total+recordHeader:])
			if got == 0 && head[0] != 0x01 {
				return nil, errors.New("edge: first handshake message is not a ClientHello")
			}
			if got+n == len(head) {
				want = len(head) + (int(head[1])<<16 | int(head[2])<<8 | int(head[3]))
			}
		}
		total += recordHeader + length
		got += length
	}

	return conn.Peek(total)
}

// replayConn feeds already-read bytes to a TLS server that is only meant to parse them.
// Nothing it writes reaches the client, whose handshake is completed later by the real server,
// so only the description of its first alert is kept, for the caller to send.
type replayConn struct {
	r []byte
	// off must be advanced across reads, which is why every method takes a pointer
	// receiver: on a value receiver the offset would reset and the TLS reader would see the
	// same record header forever.
	off   int
	alert byte
}

func (c *replayConn) Read(b []byte) (int, error) {
	if c.off >= len(c.r) {
		return 0, io.EOF
	}
	n := copy(b, c.r[c.off:])
	c.off += n
	return n, nil
}

func (c *replayConn) Write(b []byte) (int, error) {
	if c.alert == 0 && len(b) >= 7 && b[0] == tlsAlertRecord {
		c.alert = b[6]
	}
	return len(b), nil
}

func (c *replayConn) Close() error                     { return nil }
func (c *replayConn) LocalAddr() net.Addr              { return emptyAddr{} }
func (c *replayConn) RemoteAddr() net.Addr             { return emptyAddr{} }
func (c *replayConn) SetDeadline(time.Time) error      { return nil }
func (c *replayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *replayConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.Conn = (*replayConn)(nil)
