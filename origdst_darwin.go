// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

//go:build darwin

package edge

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// On macOS the redirect is done by pf, which rewrites the destination of the packet and
// keeps the original in its state table. Recovering it means asking pf, through a
// DIOCNATLOOK ioctl on /dev/pf.
//
// The request structure is laid out by hand rather than mirrored as a Go struct: pfioc_natlook
// mixes 16 byte address unions with a 4 byte port union, and writing the offsets out is both
// shorter than getting the equivalent Go struct to pack identically and easier to check
// against bsd/net/pfvar.h.
const (
	// pfioc_natlook fields, in bytes.
	natlookSaddr   = 0  // struct pf_addr, 16 bytes
	natlookDaddr   = 16 // struct pf_addr
	natlookRsaddr  = 32 // struct pf_addr
	natlookRdaddr  = 48 // struct pf_addr
	natlookSxport  = 64 // union pf_state_xport, 4 bytes, port in the first 2
	natlookDxport  = 68 // union pf_state_xport
	natlookRdxport = 76 // union pf_state_xport
	natlookAf      = 80
	natlookProto   = 81
	natlookDir     = 83
	natlookSize    = 84

	// _IOWR('D', 23, struct pfioc_natlook) with sizeof == 84.
	diocNatlook = 0xC0544417

	pfDirectionOut = 2
	afInet         = 2  // AF_INET
	afInet6        = 30 // AF_INET6 on Darwin
)

var (
	pfOnce sync.Once
	pfDev  *os.File
	pfErr  error
)

// pfDevice opens /dev/pf once and hands the same descriptor to every lookup.
func pfDevice() (*os.File, error) {
	pfOnce.Do(func() {
		pfDev, pfErr = os.OpenFile("/dev/pf", os.O_RDONLY, 0)
		if pfErr != nil {
			pfErr = fmt.Errorf("edge: open /dev/pf, transparent mode needs read access to it: %w", pfErr)
		}
	})
	return pfDev, pfErr
}

// originalDstSocket asks the pf state table which address the connection was headed to before
// the redirect.
func originalDstSocket(c net.Conn) (netip.AddrPort, error) {
	client, err := addrPortOf(c.RemoteAddr())
	if err != nil {
		return netip.AddrPort{}, err
	}
	proxy, err := addrPortOf(c.LocalAddr())
	if err != nil {
		return netip.AddrPort{}, err
	}
	return natlook(unix.IPPROTO_TCP, client, proxy)
}

// setTransparentPacketOptions asks the socket to report the address each datagram was
// delivered to, which a wildcard bound socket does not carry in its own local address and
// which the pf lookup needs. A socket bound to one family refuses the option of the other,
// so it fails only when neither is accepted.
func setTransparentPacketOptions(c *net.UDPConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return fmt.Errorf("edge: raw connection: %w", err)
	}

	var errV4, errV6 error
	ctrlErr := raw.Control(func(fd uintptr) {
		errV4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVDSTADDR, 1)
		errV6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
	})
	if ctrlErr != nil {
		return fmt.Errorf("edge: control socket: %w", ctrlErr)
	}
	if errV4 != nil && errV6 != nil {
		return fmt.Errorf("edge: IP_RECVDSTADDR: %w", errV4)
	}
	return nil
}

// originalDstFromOOB asks pf where a redirected datagram was headed. Unlike netfilter, pf
// reports nothing with the datagram itself, so the answer comes from its state table and the
// control data only says which address the datagram arrived on.
func originalDstFromOOB(oob []byte, from, local netip.AddrPort) netip.AddrPort {
	dst, ok := datagramLocalAddr(oob, local)
	if !ok {
		return netip.AddrPort{}
	}
	origin, err := natlook(unix.IPPROTO_UDP, from, dst)
	if err != nil {
		return netip.AddrPort{}
	}
	return origin
}

// datagramLocalAddr returns the address the datagram was delivered to. Neither control
// message carries a port, so the port is the socket's own.
func datagramLocalAddr(oob []byte, local netip.AddrPort) (netip.AddrPort, bool) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, false
	}

	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_RECVDSTADDR:
			// struct in_addr.
			if len(m.Data) < 4 {
				continue
			}
			return netip.AddrPortFrom(netip.AddrFrom4([4]byte(m.Data[:4])), local.Port()), true
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_PKTINFO:
			// struct in6_pktinfo, the address first.
			if len(m.Data) < 16 {
				continue
			}
			return netip.AddrPortFrom(netip.AddrFrom16([16]byte(m.Data[:16])).Unmap(), local.Port()), true
		}
	}

	if local.Addr().IsUnspecified() {
		return netip.AddrPort{}, false
	}
	return local, true
}

// natlook asks the pf state table which address client was headed to when it reached proxy.
func natlook(proto byte, client, proxy netip.AddrPort) (netip.AddrPort, error) {
	dev, err := pfDevice()
	if err != nil {
		return netip.AddrPort{}, err
	}

	src, dst := client.Addr().Unmap(), proxy.Addr().Unmap()
	if src.Is4() != dst.Is4() {
		return netip.AddrPort{}, fmt.Errorf("edge: mismatched address families on %s and %s", client, proxy)
	}
	af := byte(afInet6)
	if src.Is4() {
		af = afInet
	}

	var buf [natlookSize]byte
	putPFAddr(buf[natlookSaddr:], src)
	putPFAddr(buf[natlookDaddr:], dst)
	binary.BigEndian.PutUint16(buf[natlookSxport:], client.Port())
	binary.BigEndian.PutUint16(buf[natlookDxport:], proxy.Port())
	buf[natlookAf] = af
	buf[natlookProto] = proto
	buf[natlookDir] = pfDirectionOut

	if err := ioctlPF(dev, diocNatlook, buf[:]); err != nil {
		return netip.AddrPort{}, fmt.Errorf("edge: DIOCNATLOOK for %s: %w", client, err)
	}

	// pf answers in rdaddr/rdxport: the destination the client had actually written.
	addr, ok := pfAddr(buf[natlookRdaddr:], af)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("edge: DIOCNATLOOK returned an unusable address for %s", client)
	}
	port := binary.BigEndian.Uint16(buf[natlookRdxport:])
	return netip.AddrPortFrom(addr, port), nil
}

func ioctlPF(dev *os.File, req uint, arg []byte) error {
	raw, err := dev.SyscallConn()
	if err != nil {
		return err
	}
	var ioctlErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		// x/sys keeps its libSystem ioctl unexported and its exported helpers all fix either
		// the request or the struct, so the raw trap is the only way in. The stdlib Syscall
		// is the same trap without the deprecation notice.
		//nolint:staticcheck // no exported wrapper reaches a custom ioctl request
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(req), uintptr(unsafe.Pointer(&arg[0])))
		if errno != 0 {
			ioctlErr = errno
			return
		}
		ioctlErr = nil
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	return ioctlErr
}

func putPFAddr(dst []byte, addr netip.Addr) {
	clear(dst[:16])
	if a := addr.Unmap(); a.Is4() {
		v4 := a.As4()
		copy(dst, v4[:])
		return
	}
	v6 := addr.As16()
	copy(dst, v6[:])
}

func pfAddr(src []byte, af byte) (netip.Addr, bool) {
	if af == afInet {
		return netip.AddrFrom4([4]byte(src[:4])), true
	}
	return netip.AddrFrom16([16]byte(src[:16])).Unmap(), true
}

func addrPortOf(a net.Addr) (netip.AddrPort, error) {
	tcp, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("edge: original destination needs a TCP address, got %T", a)
	}
	return tcp.AddrPort(), nil
}
