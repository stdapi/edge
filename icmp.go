// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

//go:build !plan9 && !wasip1

package edge

import (
	"errors"
	"syscall"
)

// icmpError reports whether err is what the kernel makes of an ICMP message received for a
// connected UDP socket, handed to its next read or write. An unconnected socket never sees one,
// and QUIC finds its path MTU and its peer's absence on its own, so a read skips it and a write
// is retried.
func icmpError(err error) bool {
	errno, ok := errors.AsType[syscall.Errno](err)
	if !ok {
		return false
	}
	switch errno {
	case syscall.EMSGSIZE, syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH,
		syscall.EHOSTDOWN, syscall.ENOPROTOOPT, syscall.EACCES, syscall.EPROTO:
		return true
	}
	return false
}
