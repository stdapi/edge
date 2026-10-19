// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package netutil

import (
	"errors"
	"net"
	"syscall"
)

// UnsentBytes returns how many bytes written to the TCP socket c its kernel has not yet sent
// or had acknowledged, errors.ErrUnsupported where the platform does not report it.
func UnsentBytes(c net.Conn) (int, error) {
	if _, ok := c.(syscall.Conn); !ok {
		return 0, errors.ErrUnsupported
	}
	var n int
	err := control(c, func(fd int) error {
		var err error
		n, err = unsentBytes(fd)
		return err
	})
	return n, err
}
