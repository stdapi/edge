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
// returned was headed. [TransparentPacketConn] returns one, and [Proxy.ServeQUIC] asks a
// connection that implements it.
type PacketOriginalDestination interface {
	net.PacketConn
	OriginalDestination(remote net.Addr) (netip.AddrPort, error)
}

// TransparentListener returns ln with every accepted connection able to report where it was
// headed before the redirect. [Proxy.ListenAndServeTransparent] wraps the listener it opens,
// so this is for a listener of your own.
//
// The lookup reads SO_ORIGINAL_DST on Linux and asks the pf state table on macOS, which needs
// read access to /dev/pf. Anywhere else, and on a connection that was not redirected, it
// answers with nothing and the proxy places the connection by its server name or its Host
// header. Behind TPROXY the socket already carries the original address and no lookup is
// needed.
func TransparentListener(ln net.Listener) net.Listener {
	return transparentListener{Listener: ln}
}

type transparentListener struct{ net.Listener }

func (l transparentListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return transparentConn{Conn: c}, nil
}

type transparentConn struct{ net.Conn }

func (c transparentConn) OriginalDestination() (netip.AddrPort, error) {
	return originalDstSocket(c.Conn)
}

// CloseWrite forwards the half-close, which the embedded net.Conn does not promote.
func (c transparentConn) CloseWrite() error { return closeWrite(c.Conn) }

// TransparentPacketConn returns pc with the socket options a redirected datagram needs. The
// connection reports where each datagram was headed and [Proxy.ServeQUIC] reads it back.
//
// It needs a *net.UDPConn, and on Linux an nftables or an iptables redirect, on macOS an rdr
// rule in pf with read access to /dev/pf. No other platform is supported.
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

var _ PacketOriginalDestination = (*transparentPacketConn)(nil)
