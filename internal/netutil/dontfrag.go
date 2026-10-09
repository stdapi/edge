// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package netutil

import (
	"net"
	"syscall"
)

// SetDontFragment sets the Don't Fragment bit on the datagrams c sends, on Linux and darwin,
// when c exposes its socket through [syscall.Conn]. It does nothing elsewhere.
func SetDontFragment(c net.Conn) error {
	return control(c, setDontFragment)
}

// DontFragment reports whether the datagrams c sends have the Don't Fragment bit set.
func DontFragment(c net.Conn) (bool, error) {
	var set bool
	err := control(c, func(fd int) error {
		var err error
		set, err = dontFragment(fd)
		return err
	})
	return set, err
}

func control(c net.Conn, f func(fd int) error) error {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := raw.Control(func(fd uintptr) { ferr = f(int(fd)) }); err != nil {
		return err
	}
	return ferr
}
