// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// transparentOOBSize bounds the control data one datagram can carry. The largest message a
// platform returns is an IPv6 socket address.
const transparentOOBSize = 512

// OriginalDestination is a connection that reports the address it was headed to before a
// redirect sent it to the proxy. [TransparentListener] returns connections that implement it,
// and [Proxy.ServeConn] asks any connection that does.
//
// The zero result with a nil error means the destination is unknown, which is not an error.
// The proxy then falls back to the server name or the Host header.
//
// Implementation must be comparable.
type OriginalDestination interface {
	net.Conn
	OriginalDestination() (netip.AddrPort, error)
}

// PacketOriginalDestination is a packet connection that reports where the datagram it last
// returned was headed. [TransparentPacketConn] returns one, and [Proxy.ServeTransparentUDP] asks a
// connection that implements it.
type PacketOriginalDestination interface {
	net.PacketConn
	OriginalDestination(remote net.Addr) (netip.AddrPort, error)
}

// transparentReplier is a packet conn whose deployment delivers datagrams with their
// destination intact, TPROXY, so a reply must leave from that destination or the client's
// connected socket drops it.
type transparentReplier interface {
	transparentReplies() bool
	replySocket(origin netip.AddrPort) (net.PacketConn, error)
}

// TransparentListener returns ln with every accepted connection able to report where it was
// headed before the redirect. [Proxy.ListenAndServeTransparent] wraps the listener it opens,
// so this is for a listener of your own.
//
// The lookup reads SO_ORIGINAL_DST on Linux and asks the pf state table on macOS, which needs
// read access to /dev/pf. Anywhere else, and on a connection that was not redirected, it
// answers with nothing and the proxy places the connection by its server name or its Host
// header. Behind a Linux TPROXY rule, on a listener with IP_TRANSPARENT set, no lookup is
// needed and the accepted socket itself reports the destination. A wildcard bound listener
// cannot tell a diverted connection from a direct one on its own port, so bind the listener
// to a specific address there.
func TransparentListener(ln net.Listener) net.Listener {
	return transparentListener{Listener: ln, addr: addrPort(ln.Addr())}
}

type transparentListener struct {
	net.Listener
	addr netip.AddrPort
}

func (l transparentListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return transparentConn{Conn: c, listener: l.addr}, nil
}

type transparentConn struct {
	net.Conn
	listener netip.AddrPort
}

func (c transparentConn) OriginalDestination() (netip.AddrPort, error) {
	return originalDstSocket(c.Conn)
}

// divertedTo reports the destination of a connection a TPROXY rule diverted. The accepted
// socket owns the client's chosen destination as its own address, so the answer is read off
// the socket once it provably differs from the listener.
func (c transparentConn) divertedTo() (netip.AddrPort, bool) {
	if !tcpTransparentMode(c.Conn) {
		return netip.AddrPort{}, false
	}
	return divertedOrigin(addrPort(c.LocalAddr()), c.listener)
}

// divertedOrigin tells a diverted connection from a direct one. TPROXY keeps the original
// port, so a port other than the listener's settles it, and on the listener's own port only
// a specific bind can still discriminate. The ambiguous case reads as direct, which places
// the connection by its server name or its Host header rather than dialing the proxy itself.
func divertedOrigin(local, listener netip.AddrPort) (netip.AddrPort, bool) {
	if !local.IsValid() || !listener.IsValid() {
		return netip.AddrPort{}, false
	}
	origin := netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	if local.Port() != listener.Port() {
		return origin, true
	}
	if listener.Addr().IsUnspecified() || origin.Addr() == listener.Addr().Unmap() {
		return netip.AddrPort{}, false
	}
	return origin, true
}

// CloseWrite forwards the half-close, which the embedded net.Conn does not promote.
func (c transparentConn) CloseWrite() error { return closeWrite(c.Conn) }

// TransparentPacketConn returns pc with the socket options a redirected datagram needs, so
// [Proxy.ServeTransparentUDP] can place each datagram by the address it was headed to. A Linux
// redirect does not preserve that address, so there connections are placed by their server
// name and [Session.Upstream] reports nothing.
//
// On Linux, when the socket has IP_TRANSPARENT set behind a TPROXY rule, every datagram
// reports the address it was headed to and replies are sent from that address. This needs
// CAP_NET_ADMIN or CAP_NET_RAW.
//
// It needs a *net.UDPConn, and on Linux an nftables or an iptables redirect or TPROXY rule,
// on macOS an rdr rule in pf with read access to /dev/pf. No other platform is supported.
func TransparentPacketConn(pc net.PacketConn) (net.PacketConn, error) {
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("edge: transparent datagrams need a *net.UDPConn, got %T", pc)
	}
	if err := setTransparentPacketOptions(udp); err != nil {
		return nil, err
	}

	return &transparentPacketConn{
		UDPConn: udp,
		oob:     make([]byte, transparentOOBSize),
		local:   addrPort(udp.LocalAddr()),
		tproxy:  udpTransparentMode(udp),
	}, nil
}

// transparentPacketConn records where the datagram it last returned was headed. The proxy
// places each datagram before reading the next, so one entry is enough, and a peer other than
// that one is answered with nothing rather than with the wrong address.
type transparentPacketConn struct {
	*net.UDPConn
	local netip.AddrPort
	// from and dst hold the peer and the destination of the last datagram read, guarded by mu.
	from netip.AddrPort
	dst  netip.AddrPort
	oob  []byte
	mu   sync.Mutex
	// tproxy is set when the socket carries IP_TRANSPARENT, so nothing rewrites replies on
	// their way back and they must leave from the origin's own address.
	tproxy bool
}

func (c *transparentPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, oobn, _, from, err := c.ReadMsgUDPAddrPort(b, c.oob)
	if err != nil {
		return n, nil, err
	}

	dst := originalDstFromOOB(c.oob[:oobn], from, c.local)

	c.mu.Lock()
	c.from, c.dst = from, dst
	c.mu.Unlock()

	return n, net.UDPAddrFromAddrPort(from), nil
}

func (c *transparentPacketConn) OriginalDestination(remote net.Addr) (netip.AddrPort, error) {
	peer := addrPort(remote)

	c.mu.Lock()
	defer c.mu.Unlock()
	if peer != c.from {
		return netip.AddrPort{}, nil
	}
	return c.dst, nil
}

// exactOriginalDestination reports whether the destination is read from the datagram itself
// rather than looked up by address.
func (c *transparentPacketConn) exactOriginalDestination() bool { return origDstExact }

func (c *transparentPacketConn) transparentReplies() bool { return c.tproxy }

func (c *transparentPacketConn) replySocket(origin netip.AddrPort) (net.PacketConn, error) {
	return listenTransparentReply(origin)
}

var _ PacketOriginalDestination = (*transparentPacketConn)(nil)
var _ transparentReplier = (*transparentPacketConn)(nil)
