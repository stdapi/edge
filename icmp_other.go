// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

//go:build plan9 || wasip1

package edge

// icmpError reports false where no ICMP message reaches a socket.
func icmpError(error) bool { return false }
