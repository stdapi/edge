// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

//go:build !linux && !darwin

package edge

import (
	"errors"
	"net"
	"net/netip"
)

func originalDstSocket(net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("edge: original destination lookup is not implemented on this platform")
}

func setTransparentPacketOptions(*net.UDPConn) error {
	return errors.New("edge: transparent datagrams are not implemented on this platform")
}

func originalDstFromOOB([]byte, netip.AddrPort, netip.AddrPort) netip.AddrPort {
	return netip.AddrPort{}
}
