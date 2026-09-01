// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser_KeyIsThePatternWithoutItsPort(t *testing.T) {
	p := testProxy(t)

	// Without a port, a name pattern is the key byte for byte.
	for _, raw := range []string{
		"api.stripe.com/v1/charges",
		"+{any}/v1/charges",
		"+{sub}.stripe.com/v1/{id}",
	} {
		pat, _, err := p.parsePattern(raw, KindHTTP)
		require.NoError(t, err, raw)
		assert.Equal(t, raw, pat.key, raw)
	}

	// With one, the key drops it, so a pattern naming a port and one naming none land on the
	// same node and are told apart by the port alone. An address host is keyed on its encoded
	// form, brackets and port dropped the same way.
	loKey := prefixKey(netip.PrefixFrom(netip.MustParseAddr("127.0.0.1"), 32))
	v6Key := prefixKey(netip.PrefixFrom(netip.MustParseAddr("::1"), 128))
	for _, tc := range []struct{ raw, key, port string }{
		{"api.stripe.com:8443/v1/charges", "api.stripe.com/v1/charges", "8443"},
		{"127.0.0.1/health", loKey + "/health", ""},
		{"127.0.0.1:8080/health", loKey + "/health", "8080"},
		{"[::1]:8080/health", v6Key + "/health", "8080"},
		{"[::1]/health", v6Key + "/health", ""},
	} {
		pat, _, err := p.parsePattern(tc.raw, KindHTTP)
		require.NoError(t, err, tc.raw)
		assert.Equal(t, tc.key, pat.key, tc.raw)
		assert.Equal(t, tc.port, pat.port, tc.raw)
		assert.Equal(t, tc.raw, pat.str, tc.raw)
		key, _ := patternKey(tc.raw)
		assert.Equal(t, tc.key, key, tc.raw)
	}
}
func TestParser_SchemeIsRefusedInAnInterceptorPattern(t *testing.T) {
	p := testProxy(t)

	for _, pattern := range []string{"https://api.test/v1", "http://api.test/v1"} {
		_, err := p.Add(pattern, noopHandler, WithMethods(http.MethodGet))
		var pe *PatternError
		require.ErrorAs(t, err, &pe, pattern)
		assert.Contains(t, pe.Error(), "it carries no scheme",
			"the error for %q must name what is refused", pattern)
	}

	// A port, on the other hand, is part of the pattern.
	for _, pattern := range []string{"api.test:8443/v1", "localhost:8080/api"} {
		_, err := p.Add(pattern, noopHandler, WithMethods(http.MethodGet))
		require.NoError(t, err, pattern)
	}
}
func TestParser_RegexpConstraintMayHoldAColon(t *testing.T) {
	p := testProxy(t, WithRegexpParam(true))

	// A colon inside a brace belongs to the constraint, not to a port. Both scans that name
	// a port have to skip the brace, or every regexp constrained hostname is refused.
	for _, pattern := range []string{
		`{sub:[a-z]+}.example.com/health`,
		`+{any:[a-z.]+}/health`,
	} {
		_, err := p.Add(pattern, noopHandler)
		require.NoError(t, err, pattern)
	}
	// Tunnels go on authorities no interceptor claims, since an interceptor and a tunnel cannot disagree
	// on the same authority.
	for _, pattern := range []string{
		`{sub:[a-z]+}.tunnelled.test`,
		`+{any:[a-z.]+}.also-tunnelled.test`,
	} {
		_, err := p.Add[TCP](pattern, noopStream)
		require.NoError(t, err, pattern)
	}

	// Past the last brace the colon is a port again, and both patterns split on it.
	p.MustAdd[TCP](`{sub:[a-z]+}.other.com:8080`, noopStream)
	pat, _, err := p.parseAuthorityPattern(`{sub:[a-z]+}.other.com:8080`)
	require.NoError(t, err)
	assert.Equal(t, `{sub:[a-z]+}.other.com`, pat.host)
	assert.Equal(t, "8080", pat.port)

	pat, _, err = p.parsePattern(`{sub:[a-z]+}.other.com:8080/health`, KindHTTP)
	require.NoError(t, err)
	assert.Equal(t, `{sub:[a-z]+}.other.com`, pat.host)
	assert.Equal(t, "8080", pat.port)

	// The same authority carries a stream entry, which is another kind and no conflict: the
	// pattern is well formed and the two never compete for one connection.
	_, err = p.Add(`{sub:[a-z]+}.other.com:8080/health`, noopHandler)
	require.NoError(t, err)
}
func TestParser_AddressLiteralMustBeCanonical(t *testing.T) {
	p := testProxy(t)

	// An address has exactly one spelling, bracketed as an authority carries it. Anything
	// else is refused with the form to use, so no two patterns reach one key.
	pat, _, err := p.parsePattern("[::1]/health", KindHTTP)
	require.NoError(t, err)
	assert.Equal(t, "::1", pat.host)
	assert.Equal(t, prefixKey(netip.PrefixFrom(netip.MustParseAddr("::1"), 128))+"/health", pat.key)

	for _, tc := range []struct{ pattern, hint string }{
		{"::1/health", "IPv6 literal must be bracketed"},
		{"[::0]/health", "non-canonical address literal, write [::]"},
		{"[::FF]/health", "non-canonical address literal, write [::ff]"},
		{"[0:0:0:0:0:0:0:1]/health", "non-canonical address literal, write [::1]"},
		{"[::ffff:127.0.0.1]/health", "non-canonical address literal, write 127.0.0.1"},
	} {
		_, _, err := p.parsePattern(tc.pattern, KindHTTP)
		var pe *PatternError
		require.ErrorAs(t, err, &pe, tc.pattern)
		assert.Contains(t, pe.Error(), tc.hint, tc.pattern)
	}
}
