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

// OriginalDestinationSocket recovers the address a connection was headed to before pf
// redirected it, by looking it up in the pf state table.
//
// It needs read access to /dev/pf, which means running as root or granting the binary that
// access some other way. When the lookup fails the proxy falls back to the TLS server name
// or the Host header, so an unprivileged process still works for anything that carries one.
func OriginalDestinationSocket(c net.Conn) (netip.AddrPort, error) {
	pfOnce.Do(func() {
		pfDev, pfErr = os.OpenFile("/dev/pf", os.O_RDONLY, 0)
		if pfErr != nil {
			pfErr = fmt.Errorf("edge: open /dev/pf, transparent mode needs read access to it: %w", pfErr)
		}
	})
	if pfErr != nil {
		return netip.AddrPort{}, pfErr
	}

	client, err := addrPortOf(c.RemoteAddr())
	if err != nil {
		return netip.AddrPort{}, err
	}
	proxy, err := addrPortOf(c.LocalAddr())
	if err != nil {
		return netip.AddrPort{}, err
	}
	if client.Addr().Is4In6() != proxy.Addr().Is4In6() {
		return netip.AddrPort{}, fmt.Errorf("edge: mismatched address families on %s and %s", client, proxy)
	}

	var buf [natlookSize]byte
	af := byte(afInet6)
	if client.Addr().Unmap().Is4() {
		af = afInet
	}

	putPFAddr(buf[natlookSaddr:], client.Addr())
	putPFAddr(buf[natlookDaddr:], proxy.Addr())
	binary.BigEndian.PutUint16(buf[natlookSxport:], client.Port())
	binary.BigEndian.PutUint16(buf[natlookDxport:], proxy.Port())
	buf[natlookAf] = af
	buf[natlookProto] = unix.IPPROTO_TCP
	buf[natlookDir] = pfDirectionOut

	if err := ioctlPF(pfDev, diocNatlook, buf[:]); err != nil {
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
		// x/sys/unix exposes a typed wrapper per ioctl it knows about and keeps the generic
		// one unexported, so a request carrying a struct it has never heard of has to go
		// through the raw syscall.
		//nolint:staticcheck // no wrapper exists for a custom ioctl request
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
