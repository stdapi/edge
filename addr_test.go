// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net/http"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddr_HexFirstLiteralsAreRegistrable(t *testing.T) {
	p := testProxy(t)

	for _, pattern := range []string{"[fd00::1]", "[fe80::1]", "[dead:beef::1]", "[2001:db8::1]"} {
		_, err := p.Add[TCP](pattern, noopStream)
		require.NoError(t, err, pattern)
	}
	assert.Equal(t, true, p.Admits(target("[fd00::1]:443"), KindTCP))

	_, err := p.Add("[cafe::2]/api", noopHandler)
	require.NoError(t, err)
	assert.Equal(t, true, p.Admits(target("[cafe::2]:443"), KindHTTP))
}

func TestAddr_RangeSpellingIsCanonical(t *testing.T) {
	p := testProxy(t)

	for _, pattern := range []string{
		"[10.0.0.0/8]", "[fd00::/8]", "[0.0.0.0/0]", "[::/0]", "[10.0.0.0/8]:443", "[2001:db8::/32]",
	} {
		_, err := p.Add[TCP](pattern, noopStream)
		require.NoError(t, err, pattern)
	}

	for _, tc := range []struct{ pattern, hint string }{
		{"[10.0.0.1/8]", "write [10.0.0.0/8]"},
		{"[FD00::/8]", "write [fd00::/8]"},
		{"[fd00:0000::/8]", "write [fd00::/8]"},
		{"[fd00::/08]", "invalid address range"},
		{"[10.0.0.1/32]", "a full-length prefix is an address, write 10.0.0.1"},
		{"[::1/128]", "a full-length prefix is an address, write [::1]"},
		{"[::ffff:10.0.0.0/104]", "write [10.0.0.0/8]"},
		{"[::ffff:0:0/80]", "a mapped address range has no canonical form"},
		{"[fe80::%eth0/64]", "invalid address range"},
	} {
		_, err := p.Add[TCP](tc.pattern, noopStream)
		var pe *PatternError
		require.ErrorAs(t, err, &pe, tc.pattern)
		assert.Contains(t, pe.Error(), tc.hint, tc.pattern)
	}
}

func TestAddr_UnbracketedRangeIsRefused(t *testing.T) {
	p := testProxy(t)

	_, err := p.Add[TCP]("10.0.0.0/8", noopStream)
	var pe *PatternError
	require.ErrorAs(t, err, &pe)
	assert.Contains(t, pe.Error(), "an address range is written in brackets: [10.0.0.0/8]")

	_, err = p.Add("10.0.0.0/8", noopHandler)
	require.ErrorAs(t, err, &pe)
	assert.Contains(t, pe.Error(), "[10.0.0.0/8]")

	_, err = p.Add("10.0.0.0/8/api", noopHandler)
	require.ErrorAs(t, err, &pe)
	assert.Contains(t, pe.Error(), "[10.0.0.0/8]/api")

	// A numeric first segment past the address width is a path, not a range gone wrong.
	_, err = p.Add("10.0.0.0/1234", noopHandler)
	require.NoError(t, err)
}

func TestAddr_NumericPathsOnAddressHosts(t *testing.T) {
	p := testProxy(t)

	for _, pattern := range []string{
		"[::1]/8/metrics",
		"[2001:db8::1]/2/items",
		"10.1.2.3/8/metrics",
		"10.0.0.1/32",
	} {
		_, err := p.Add(pattern, noopHandler)
		require.NoError(t, err, pattern)
	}
	assert.NotZero(t, match(t, p, http.MethodGet, "https", "[::1]:443", "/8/metrics"))
	assert.NotZero(t, match(t, p, http.MethodGet, "https", "10.0.0.1:443", "/32"))
}

func TestAddr_HintsAreRegistrable(t *testing.T) {
	p := testProxy(t)

	for _, tc := range []struct{ pattern, hint string }{
		{"10.0.0.1/32", "a full-length prefix is an address, write 10.0.0.1"},
		{"[::ffff:10.0.0.1/128]", "a full-length prefix is an address, write 10.0.0.1"},
		{"10.0.0.0/33", "an authority pattern must not carry a path"},
		{"10.0.0.0/8/x", "an authority pattern must not carry a path"},
		{"10.1.2.3/8", "an authority pattern must not carry a path"},
	} {
		_, err := p.Add[TCP](tc.pattern, noopStream)
		var pe *PatternError
		require.ErrorAs(t, err, &pe, tc.pattern)
		assert.Contains(t, pe.Error(), tc.hint, tc.pattern)
	}
}

func TestAddr_ZonedLiteralIsDecidedAsItsAddress(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[TCP]("+{any}", noopStream)
	assert.Equal(t, false, p.Admits(target("[fe80::1%eth0]:443"), KindHTTP))
	assert.Equal(t, false, p.Admits(Target{Host: "fe80::1%eth", Port: "443"}, KindHTTP))

	p.MustAdd[TCP]("[fe80::/10]", noopStream)
	assert.Equal(t, true, p.Admits(target("[fe80::1%eth0]:443"), KindTCP))
	assert.Equal(t, true, p.Admits(Target{Host: "fe80::1%eth", Port: "443"}, KindTCP))

	p2 := testProxy(t)
	ic := p2.MustAdd("[fe80::1]/api", noopHandler)
	assert.Equal(t, ic, match(t, p2, http.MethodGet, "https", "[fe80::1%25eth0]:443", "/api"))
}

func TestAddr_HostKindsRouteSeparately(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("{a}/api", noopHandler)
	p.MustAdd("127.0.{a}.1/api", noopHandler)

	assert.NotZero(t, match(t, p, http.MethodGet, "https", "somename:443", "/api"))
	assert.Zero(t, match(t, p, http.MethodGet, "https", "[2001:db8::1]:443", "/api"))

	assert.NotZero(t, match(t, p, http.MethodGet, "https", "127.0.foo.1:443", "/api"))
	assert.Zero(t, match(t, p, http.MethodGet, "https", "127.0.5.1:443", "/api"))

	p2 := testProxy(t)
	p2.MustAdd[TCP]("+{any}", noopStream)
	assert.Equal(t, true, p2.Admits(target("example.com:443"), KindTCP))
	assert.Equal(t, false, p2.Admits(target("127.0.0.1:443"), KindHTTP))
	assert.Equal(t, false, p2.Admits(target("[2001:db8::1]:443"), KindHTTP))

	p2.MustAdd[TCP]("[0.0.0.0/0]", noopStream)
	p2.MustAdd[TCP]("[::/0]", noopStream)
	assert.Equal(t, true, p2.Admits(target("127.0.0.1:443"), KindTCP))
	assert.Equal(t, true, p2.Admits(target("[2001:db8::1]:443"), KindTCP))
	// A mapped target names an IPv4 address and falls under the IPv4 catch-all.
	assert.Equal(t, true, p2.Admits(target("[::ffff:127.0.0.1]:443"), KindTCP))
}

func TestAddr_LookupNormalizesTheWireSpelling(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[TCP]("[0.0.0.0/0]", noopStream)
	p.MustAdd[TCP]("[::/0]", noopStream)
	p.MustAdd("[2001:db8::1]/+{rest}", noopHandler)
	p.MustAdd("127.0.0.1/+{rest}", noopHandler)

	for _, host := range []string{"2001:db8::1", "2001:db8:0:0:0:0:0:1", "2001:0DB8::0001", "2001:db8::1."} {
		assert.Equal(t, true, p.Admits(Target{Host: host, Port: "443"}, KindHTTP), host)
		assert.NotZero(t, match(t, p, http.MethodGet, "https", "["+host+"]:443", "/x"), host)
	}
	for _, host := range []string{"127.0.0.1", "::ffff:127.0.0.1", "127.0.0.1."} {
		assert.Equal(t, true, p.Admits(Target{Host: host, Port: "443"}, KindHTTP), host)
	}
	assert.Equal(t, true, p.Admits(target("[2001:db8::2]:443"), KindTCP))
}

func TestAddr_AuthorityLookupCutsTheRootDot(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("example.com/+{rest}", noopHandler)
	assert.Equal(t, true, p.Admits(Target{Host: "example.com.", Port: "443"}, KindHTTP))
	assert.Equal(t, false, p.Admits(Target{Host: "other.com.", Port: "443"}, KindHTTP))
}

func TestAddr_LongestPrefixDecides(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[TCP]("[10.0.0.0/8]", noopStream)
	p.MustAdd("[10.1.0.0/16]/+{rest}", noopHandler)
	p.MustAdd("10.1.2.3/metrics", noopHandler)

	assert.Equal(t, true, p.Admits(target("10.9.9.9:443"), KindTCP))
	assert.Equal(t, true, p.Admits(target("10.1.9.9:443"), KindHTTP))
	assert.Equal(t, true, p.Admits(target("10.1.2.3:443"), KindHTTP))
	assert.Equal(t, false, p.Admits(target("11.0.0.1:443"), KindHTTP))
}

func TestAddr_PortMismatchFallsBackToTheShorterPrefix(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[TCP]("[10.0.0.0/8]", noopStream)
	p.MustAdd("[10.1.0.0/16]:8443/+{rest}", noopHandler)

	assert.Equal(t, true, p.Admits(target("10.1.2.3:8443"), KindHTTP))
	assert.Equal(t, true, p.Admits(target("10.1.2.3:443"), KindTCP))
}

func TestAddr_RequestRoutingUsesLongestPrefix(t *testing.T) {
	p := testProxy(t)
	eight := p.MustAdd("[10.0.0.0/8]/api", noopHandler)
	sixteen := p.MustAdd("[10.1.0.0/16]/api", noopHandler)
	exact := p.MustAdd("10.1.2.3/api", noopHandler)
	only16 := p.MustAdd("[10.1.0.0/16]/deep", noopHandler)
	wide := p.MustAdd("[10.0.0.0/8]/wide", noopHandler)

	assert.Equal(t, exact, match(t, p, http.MethodGet, "https", "10.1.2.3:443", "/api"))
	assert.Equal(t, sixteen, match(t, p, http.MethodGet, "https", "10.1.9.9:443", "/api"))
	assert.Equal(t, eight, match(t, p, http.MethodGet, "https", "10.9.9.9:443", "/api"))
	assert.Equal(t, only16, match(t, p, http.MethodGet, "https", "10.1.9.9:443", "/deep"))
	// /deep exists only under the /16, so an address outside it finds nothing.
	assert.Zero(t, match(t, p, http.MethodGet, "https", "10.9.9.9:443", "/deep"))
	// /wide misses under the /16, so the walk falls back to the /8 that serves it.
	assert.Equal(t, wide, match(t, p, http.MethodGet, "https", "10.1.9.9:443", "/wide"))
}

func TestAddr_PathParamsUnderARange(t *testing.T) {
	p := testProxy(t)
	ic := p.MustAdd("[10.0.0.0/8]/v1/{id}", func(c *HTTPCtx) (*http.Response, error) {
		assert.Equal(t, "42", c.Param("id"))
		assert.Equal(t, "10.5.6.7", c.Host())
		return Status(http.StatusOK), nil
	})
	assert.Equal(t, 1, ic.ParamsLen())

	got := match(t, p, http.MethodGet, "https", "10.5.6.7:443", "/v1/42")
	require.Equal(t, ic, got)
}

func TestAddr_SamePrefixConflicts(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[TCP]("[10.0.0.0/8]", noopStream)

	_, err := p.Add[TCP]("[10.0.0.0/8]", noopStream)
	var ce *EntryConflictError
	require.ErrorAs(t, err, &ce)

	// A different kind on the same prefix is not a conflict: the traffic tells them apart,
	// so both are registrable in either order.
	_, err = p.Add("[10.0.0.0/8]/api", noopHandler)
	require.NoError(t, err)

	p2 := testProxy(t)
	p2.MustAdd("[10.0.0.0/8]/api", noopHandler)
	_, err = p2.Add[TCP]("[10.0.0.0/8]", noopStream)
	require.NoError(t, err)
}

func TestAddr_RangeInterceptorImpliesItsAuthority(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("[fd00::/8]/api", noopHandler)

	entries := collectAuthorities(p)
	require.Len(t, entries, 1)
	assert.Equal(t, "[fd00::/8]", entries[0].Pattern())
	assert.Equal(t, "fd00::/8", entries[0].Host())
	assert.True(t, entries[0].Implied())
	assert.Equal(t, true, p.Admits(target("[fd42::1]:443"), KindHTTP))

	_, err := p.Delete[HTTP]("[fd00::/8]/api")
	require.NoError(t, err)
	assert.Empty(t, collectAuthorities(p))
	assert.Equal(t, false, p.Admits(target("[fd42::1]:443"), KindHTTP))
}

func TestAddr_RangeInterceptorPortScopesTheAuthority(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("[10.0.0.0/8]:8443/api", noopHandler)

	assert.Equal(t, true, p.Admits(target("10.1.2.3:8443"), KindHTTP))
	assert.Equal(t, false, p.Admits(target("10.1.2.3:443"), KindHTTP))
}

func TestAddr_NameIndexSpansBothWorlds(t *testing.T) {
	p := testProxy(t)
	ic := p.MustAdd("[10.0.0.0/8]/api", noopHandler, WithName[HTTP]("ranged"))
	assert.Equal(t, ic, namedHTTP(p, "ranged"))

	_, err := p.Add("other.test/api", noopHandler, WithName[HTTP]("ranged"))
	var nce *EntryNameConflictError
	require.ErrorAs(t, err, &nce)

	renamed, err := p.Update("[10.0.0.0/8]/api", noopHandler, WithName[HTTP]("renamed"))
	require.NoError(t, err)
	assert.Zero(t, namedHTTP(p, "ranged"))
	assert.Equal(t, renamed, namedHTTP(p, "renamed"))

	_, err = p.Delete[HTTP]("[10.0.0.0/8]/api")
	require.NoError(t, err)
	assert.Zero(t, namedHTTP(p, "renamed"))
}

func TestAddr_IterationAndLookupByPattern(t *testing.T) {
	p := testProxy(t)
	tn := p.MustAdd[TCP]("[fd00::/8]", noopStream)
	ic := p.MustAdd("[10.0.0.0/8]/api", noopHandler)
	named := p.MustAdd("api.test/v1", noopHandler, WithMethods[HTTP](http.MethodGet))

	// Three admissions: the declared stream entry and the two the request entries imply.
	assert.Equal(t, 3, admissionsLen(p))
	assert.Equal(t, 3, p.Len())

	require.Equal(t, ic, lookupHTTP(p, "[10.0.0.0/8]/api"))
	assert.True(t, p.Has[HTTP]("[10.0.0.0/8]/api"))
	assert.Zero(t, lookupHTTP(p, "[10.0.0.1/8]/api"), "an unregistrable spelling finds nothing")

	all := patternsOf(p.Iter().All())
	assert.Contains(t, all, ic.Pattern())
	assert.Contains(t, all, named.Pattern())

	patterns := make([]string, 0, 3)
	for a := range p.Iter().Admissions() {
		patterns = append(patterns, a.Pattern())
	}
	assert.ElementsMatch(t, []string{tn.Pattern(), "[10.0.0.0/8]", "api.test"}, patterns)

	found := slices.Collect(p.Iter().Entries("[10.0.0.0/8]/api"))
	require.Len(t, found, 1)
	assert.Equal(t, ic.Pattern(), found[0].Pattern())
}

func TestAddr_TransactionCoversTheAddressRoot(t *testing.T) {
	p := testProxy(t)

	txn := p.Txn(true)
	_, err := txn.Add[TCP]("[10.0.0.0/8]", noopStream)
	require.NoError(t, err)
	assert.Equal(t, true, txn.Admits(target("10.1.2.3:443"), KindTCP))
	assert.Equal(t, false, p.Admits(target("10.1.2.3:443"), KindHTTP))
	txn.Abort()
	assert.Equal(t, false, p.Admits(target("10.1.2.3:443"), KindHTTP))

	require.NoError(t, p.Updates(func(txn *Txn) error {
		_, err := txn.Add[TCP]("[10.0.0.0/8]", noopStream)
		return err
	}))
	assert.Equal(t, true, p.Admits(target("10.1.2.3:443"), KindTCP))

	require.NoError(t, p.Updates(func(txn *Txn) error { return txn.Truncate() }))
	assert.Equal(t, false, p.Admits(target("10.1.2.3:443"), KindHTTP))
}

func TestAddr_DeleteKeepsTheSurvivingPrefixes(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[TCP]("[10.0.0.0/8]", noopStream)
	p.MustAdd[TCP]("[10.1.0.0/16]", noopStream)
	p.MustAdd[TCP]("[10.1.2.0/24]", noopStream)

	_, err := p.Delete[TCP]("[10.1.0.0/16]")
	require.NoError(t, err)

	assert.Equal(t, true, p.Admits(target("10.1.2.3:443"), KindTCP))
	assert.Equal(t, true, p.Admits(target("10.1.9.9:443"), KindTCP))
	assert.Equal(t, true, p.Admits(target("10.9.9.9:443"), KindTCP))
	assert.Equal(t, false, p.Admits(target("11.0.0.1:443"), KindHTTP))

	_, err = p.Delete[TCP]("[10.0.0.0/8]")
	require.NoError(t, err)
	assert.Equal(t, true, p.Admits(target("10.1.2.3:443"), KindTCP))
	assert.Equal(t, false, p.Admits(target("10.1.9.9:443"), KindHTTP))
}
