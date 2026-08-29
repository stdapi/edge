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

// OriginalDestinationSocket is not available on this platform. Transparent mode still works
// for clients that send a TLS server name or a Host header; supply your own
// [OriginalDestination] to [WithOriginalDestination] to do better.
func OriginalDestinationSocket(net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("edge: original destination lookup is not implemented on this platform")
}
