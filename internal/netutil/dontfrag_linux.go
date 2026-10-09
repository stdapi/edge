// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

//go:build linux

package netutil

import (
	"errors"

	"golang.org/x/sys/unix"
)

// setDontFragment sets both families, an IPv6 socket sending to IPv4-mapped addresses
// following the IPv4 option.
func setDontFragment(fd int) error {
	v4 := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
	v6 := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
	if v4 != nil && v6 != nil {
		return errors.Join(v4, v6)
	}
	return nil
}

func dontFragment(fd int) (bool, error) {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return false, err
	}
	level, opt, want := unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO
	if _, ok := sa.(*unix.SockaddrInet6); ok {
		level, opt, want = unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO
	}
	v, err := unix.GetsockoptInt(fd, level, opt)
	return v == want, err
}
