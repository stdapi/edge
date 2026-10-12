// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"net/netip"
	"strings"
)

// maxAddrKey is the longest key the address root holds: one kind byte and one byte per bit
// of a full IPv6 address.
const maxAddrKey = 1 + 128

// appendPrefixKey appends the address-root key of p to dst: a kind byte, then one byte per
// prefix bit, most significant first. A longer prefix extends the key of every shorter one
// covering it, which is what makes the radix walk a longest-prefix match, and only keys
// built here ever enter the address root, so no host read off the wire is walked against it.
func appendPrefixKey(dst []byte, p netip.Prefix) []byte {
	addr := p.Addr()
	base := 0
	if addr.Is4() {
		dst = append(dst, '4')
		// As16 carries an IPv4 address in its mapped form, so its bits start at byte 12.
		base = 12
	} else {
		dst = append(dst, '6')
	}
	raw := addr.As16()
	bits := p.Bits()
	for i := range bits / 8 {
		dst = append(dst, bitBytes[raw[base+i]][:]...)
	}
	if rem := bits % 8; rem != 0 {
		dst = append(dst, bitBytes[raw[base+bits/8]][:rem]...)
	}
	return dst
}

// bitBytes expands a byte into its eight key bytes, so encoding an address costs one copy
// per byte rather than one append per bit.
var bitBytes = func() (t [256][8]byte) {
	for i := range t {
		for b := range 8 {
			t[i][b] = '0' + byte(i>>(7-b))&1
		}
	}
	return t
}()

// prefixKey returns the address-root key of p. See appendPrefixKey.
func prefixKey(p netip.Prefix) string {
	return string(appendPrefixKey(make([]byte, 0, 1+p.Bits()), p))
}

// hostAddr reports whether host spells an address in a pattern, unmapped. A zoned literal
// is refused: a pattern must name what a lookup can be given, and the lookup drops zones.
func hostAddr(host string) (netip.Addr, bool) {
	if host == "" || !addrEdge[host[0]] || !addrEdge[host[len(host)-1]] {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// routingAddr reports whether a host read off the wire names an address, unmapped and with
// its zone dropped. The zone is a dial detail of the client's own host; deciding a zoned
// literal on the name patterns instead would let it slip past every address rule while the
// dial still reaches the address.
//
// A false positive on the guard costs a parse that fails.
func routingAddr(host string) (netip.Addr, bool) {
	if !maybeRoutingAddr(host) {
		return netip.Addr{}, false
	}
	if !addrEdge[host[len(host)-1]] {
		// A zoned literal, the one form whose end byte is free text.
		i := strings.IndexByte(host, '%')
		if i <= 0 {
			return netip.Addr{}, false
		}
		host = host[:i]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	return addr.Unmap(), true
}

// maybeRoutingAddr rules out most names without a scan, since an address starts and ends
// with a hex digit or a colon. Only the start holds for a zoned literal, and zones exist
// for IPv6 alone, whose spelling puts a colon within the first five bytes, so a failed end
// byte falls back to that bounded check. The table keeps it inlinable, which keeps every
// function call off the name lookup path.
func maybeRoutingAddr(host string) bool {
	return host != "" && addrEdge[host[0]] &&
		(addrEdge[host[len(host)-1]] || strings.IndexByte(host[:min(len(host), 5)], ':') >= 0)
}

// addrEdge marks the bytes an address may start or end with: hex digits and ':'.
var addrEdge = func() (t [256]bool) {
	for c := range 256 {
		b := byte(c)
		t[c] = b >= '0' && b <= '9' || b == ':' || (b|0x20) >= 'a' && (b|0x20) <= 'f'
	}
	return t
}()

// hostPrefix reports whether host names an address, exact or a range, and returns its
// prefix. It accepts non-canonical spellings that registration refuses, so a lookup by one
// lands in the address root and finds nothing rather than being mistaken for a name.
func hostPrefix(host string) (netip.Prefix, bool) {
	if strings.IndexByte(host, '/') >= 0 {
		p, err := netip.ParsePrefix(host)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p, true
	}
	if addr, ok := hostAddr(host); ok {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.Prefix{}, false
}
