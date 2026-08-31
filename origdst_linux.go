// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

//go:build linux

package edge

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// ip6tSoOriginalDst is IP6T_SO_ORIGINAL_DST from linux/netfilter_ipv6/ip6_tables.h. It
// shares its numeric value with SO_ORIGINAL_DST but lives at the IPPROTO_IPV6 level, and
// x/sys/unix does not export it.
const ip6tSoOriginalDst = 80

// origDstExact reports that the destination is read from the control message attached to
// each datagram. A redirect rewrites it before delivery, so the exact path only sees the
// listener's own address there and stays dormant.
const origDstExact = true

// originalDstSocket asks netfilter, through the socket, which address the connection was
// headed to before the redirect. A connection that was not redirected answers with the
// address of the listener itself.
func originalDstSocket(c net.Conn) (netip.AddrPort, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("edge: original destination needs a TCP connection, got %T", c)
	}

	raw, err := tc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("edge: raw connection: %w", err)
	}

	var (
		addr      netip.AddrPort
		lookupErr error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		addr, lookupErr = originalDst(int(fd), tc.LocalAddr())
	})
	if ctrlErr != nil {
		return netip.AddrPort{}, fmt.Errorf("edge: control socket: %w", ctrlErr)
	}
	return addr, lookupErr
}

// originalDst reads SO_ORIGINAL_DST, choosing the option level from the family the listener
// is bound to. A dual-stack listener reports IPv4 peers as IPv4-mapped, so the family of the
// local address is what decides, not the family of the peer.
func originalDst(fd int, local net.Addr) (netip.AddrPort, error) {
	tcpLocal, _ := local.(*net.TCPAddr)
	if tcpLocal != nil && tcpLocal.IP.To4() == nil {
		if addr, err := originalDst6(fd); err == nil {
			return addr, nil
		}
		// A dual-stack socket carrying a mapped IPv4 peer answers on the IPv4 level.
	}
	return originalDst4(fd)
}

func originalDst4(fd int) (netip.AddrPort, error) {
	// SO_ORIGINAL_DST returns a sockaddr_in. The kernel has no dedicated getsockopt wrapper
	// for it, so it is read through the option that returns a raw 16 byte blob.
	mreq, err := unix.GetsockoptIPv6Mreq(fd, unix.IPPROTO_IP, unix.SO_ORIGINAL_DST)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("edge: SO_ORIGINAL_DST: %w", err)
	}
	raw := mreq.Multiaddr
	port := binary.BigEndian.Uint16(raw[2:4])
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(raw[4:8])), port), nil
}

func originalDst6(fd int) (netip.AddrPort, error) {
	mtu, err := unix.GetsockoptIPv6MTUInfo(fd, unix.IPPROTO_IPV6, ip6tSoOriginalDst)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("edge: IP6T_SO_ORIGINAL_DST: %w", err)
	}
	return netip.AddrPortFrom(netip.AddrFrom16(mtu.Addr.Addr), ntohs(mtu.Addr.Port)), nil
}

func ntohs(v uint16) uint16 {
	return v<<8 | v>>8
}

// setTransparentPacketOptions asks the socket to report the pre-redirect destination of every
// datagram it delivers. A socket bound to one family refuses the option of the other, so it
// fails only when neither is accepted.
func setTransparentPacketOptions(c *net.UDPConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return fmt.Errorf("edge: raw connection: %w", err)
	}

	var errV4, errV6 error
	ctrlErr := raw.Control(func(fd uintptr) {
		errV4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVORIGDSTADDR, 1)
		errV6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
	})
	if ctrlErr != nil {
		return fmt.Errorf("edge: control socket: %w", ctrlErr)
	}
	if errV4 != nil && errV6 != nil {
		return fmt.Errorf("edge: IP_RECVORIGDSTADDR: %w", errV4)
	}
	return nil
}

// originalDstFromOOB reads the address netfilter recorded for a redirected datagram. The zero
// value means the datagram carried no such message, which is what a datagram that was not
// redirected looks like.
func originalDstFromOOB(oob []byte, _, _ netip.AddrPort) netip.AddrPort {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}
	}

	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_ORIGDSTADDR:
			// sockaddr_in, laid out as family, port, address.
			if len(m.Data) < 8 {
				continue
			}
			port := binary.BigEndian.Uint16(m.Data[2:4])
			return netip.AddrPortFrom(netip.AddrFrom4([4]byte(m.Data[4:8])), port)
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_ORIGDSTADDR:
			// sockaddr_in6, laid out as family, port, flow label, address, scope.
			if len(m.Data) < 24 {
				continue
			}
			port := binary.BigEndian.Uint16(m.Data[2:4])
			return netip.AddrPortFrom(netip.AddrFrom16([16]byte(m.Data[8:24])).Unmap(), port)
		}
	}
	return netip.AddrPort{}
}
