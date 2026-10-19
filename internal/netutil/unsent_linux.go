// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

//go:build linux

package netutil

import "golang.org/x/sys/unix"

func unsentBytes(fd int) (int, error) {
	return unix.IoctlGetInt(fd, unix.SIOCOUTQ)
}
