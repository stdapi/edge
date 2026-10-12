// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

//go:build darwin

package netutil

import (
	"golang.org/x/sys/unix"
)

func setDontFragment(fd int) error {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return err
	}
	if _, ok := sa.(*unix.SockaddrInet6); ok {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
}

func dontFragment(fd int) (bool, error) {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return false, err
	}
	level, opt := unix.IPPROTO_IP, unix.IP_DONTFRAG
	if _, ok := sa.(*unix.SockaddrInet6); ok {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG
	}
	v, err := unix.GetsockoptInt(fd, level, opt)
	return v != 0, err
}
