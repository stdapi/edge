// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPath_MergeSlashes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/foo/bar", "/foo/bar"},
		{"//foo", "/foo"},
		{"/foo//bar", "/foo/bar"},
		{"/foo///bar//", "/foo/bar/"},
		{"/", "/"},
		{"", ""},
		{"/foo/%2F/bar", "/foo/%2F/bar"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, MergeSlashes(tc.in), "MergeSlashes(%q)", tc.in)
	}
}

func TestPath_CollapseDotSegments(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"/foo/bar", "/foo/bar", true},
		{"/foo/./bar", "/foo/bar", true},
		{"/foo/../bar", "/bar", true},
		{"/foo/bar/..", "/foo/", true},
		{"/foo/bar/.", "/foo/bar/", true},
		{"/a/b/c/../../d", "/a/d", true},
		{"/..", "", false},
		{"/foo/../..", "", false},
		{"/foo//bar", "/foo//bar", true},
	}
	for _, tc := range cases {
		got, ok := CollapseDotSegments(tc.in)
		assert.Equal(t, tc.ok, ok, "CollapseDotSegments(%q) ok", tc.in)
		if tc.ok {
			assert.Equal(t, tc.want, got, "CollapseDotSegments(%q)", tc.in)
		}
	}
}

func TestPath_NormalizationIsMatchTimeOnly(t *testing.T) {
	var seen string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.RequestURI
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(
		WithCA(ca),
		WithTransport(tr),
		WithMergeSlashes(true),
		WithCollapseDotSegments(true),
	)
	require.NoError(t, err)

	var routed string
	p.MustAddInterceptor([]string{http.MethodGet}, originHost(originURL)+"/v1/charges", func(c *Context) (*http.Response, error) {
		routed = c.RoutingPath()
		return c.Forward()
	})

	addr := startProxy(t, p)
	client := proxyClient(addr, ca.CertPool())

	// The messy form matches the clean route.
	resp, err := client.Get(origin.URL + "//v1/./sub/../charges")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	assert.Equal(t, "ok", string(body), "the normalized form must have matched the route")
	assert.Equal(t, "//v1/./sub/../charges", routed,
		"RoutingPath reports the canonical form of the wire path, not the normalized one")
	assert.Equal(t, "//v1/./sub/../charges", seen,
		"the origin must receive the target the client sent, not the one the proxy matched on")
}

func TestPath_EscapingDotSegmentMatchesNothing(t *testing.T) {
	p := testProxy(t, WithCollapseDotSegments(true))
	p.MustAddInterceptor([]string{http.MethodGet}, "api.test/v1/charges", noopHandler)

	// A ".." that walks above the root has no meaning, so it reaches no handler rather than
	// reaching one for a path it never asked for.
	path, ok := p.normalizeForMatch("/../v1/charges")
	assert.False(t, ok)
	assert.Empty(t, path)

	path, ok = p.normalizeForMatch("/v1/./charges")
	assert.True(t, ok)
	assert.Equal(t, "/v1/charges", path)
}

func TestPath_RoutingPathCanonicalization(t *testing.T) {
	cases := []struct{ target, want string }{
		{"/v1/charges", "/v1/charges"},
		// An escaped unreserved character is decoded, an escaped delimiter is not.
		{"/v1/%41", "/v1/A"},
		{"/v1/a%2Fb", "/v1/a%2Fb"},
		// Lowercase hex is normalized so a pattern and a request agree on one form.
		{"/v1/a%2fb", "/v1/a%2Fb"},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.target, nil)
		assert.Equal(t, tc.want, routingPath(req), "routingPath(%q)", tc.target)
	}

	assert.Empty(t, routingPath(nil))
}

func TestPath_KeyIsThePatternWithoutItsPort(t *testing.T) {
	p := testProxy(t)

	// Without a port, the pattern is the key byte for byte.
	for _, raw := range []string{
		"api.stripe.com/v1/charges",
		"127.0.0.1/health",
		"+{any}/v1/charges",
		"+{sub}.stripe.com/v1/{id}",
	} {
		pat, _, err := p.parsePattern(raw)
		require.NoError(t, err, raw)
		assert.Equal(t, raw, pat.key, raw)
	}

	// With one, the key drops it, so a pattern naming a port and one naming none land on the
	// same node and are told apart by the port alone.
	for _, tc := range []struct{ raw, key, port string }{
		{"api.stripe.com:8443/v1/charges", "api.stripe.com/v1/charges", "8443"},
		{"127.0.0.1:8080/health", "127.0.0.1/health", "8080"},
		{"[::1]:8080/health", "::1/health", "8080"},
		{"[::1]/health", "::1/health", ""},
	} {
		pat, _, err := p.parsePattern(tc.raw)
		require.NoError(t, err, tc.raw)
		assert.Equal(t, tc.key, pat.key, tc.raw)
		assert.Equal(t, tc.port, pat.port, tc.raw)
		assert.Equal(t, tc.raw, pat.str, tc.raw)
		assert.Equal(t, tc.key, patternKey(tc.raw), tc.raw)
	}
}

func TestPath_SchemeIsRefusedInAnInterceptorPattern(t *testing.T) {
	p := testProxy(t)

	for _, pattern := range []string{"https://api.test/v1", "http://api.test/v1"} {
		_, err := p.AddInterceptor([]string{http.MethodGet}, pattern, noopHandler)
		var pe *PatternError
		require.ErrorAs(t, err, &pe, pattern)
		assert.Contains(t, pe.Error(), "it carries no scheme",
			"the error for %q must name what is refused", pattern)
	}

	// A port, on the other hand, is part of the pattern.
	for _, pattern := range []string{"api.test:8443/v1", "localhost:8080/api"} {
		_, err := p.AddInterceptor([]string{http.MethodGet}, pattern, noopHandler)
		require.NoError(t, err, pattern)
	}
}

func TestPath_RegexpConstraintMayHoldAColon(t *testing.T) {
	p := testProxy(t, WithRegexpParam(true))

	// A colon inside a brace belongs to the constraint, not to a port. Both scans that name
	// a port have to skip the brace, or every regexp constrained hostname is refused.
	for _, pattern := range []string{
		`{sub:[a-z]+}.example.com/health`,
		`+{any:[a-z.]+}/health`,
	} {
		_, err := p.AddInterceptor(nil, pattern, noopHandler)
		require.NoError(t, err, pattern)
	}
	// Tunnels go on authorities no interceptor claims, since an interceptor and a tunnel cannot disagree
	// on the same authority.
	for _, pattern := range []string{
		`{sub:[a-z]+}.tunnelled.test`,
		`+{any:[a-z.]+}.also-tunnelled.test`,
	} {
		require.NoError(t, p.AddTunnel(pattern), pattern)
	}

	// Past the last brace the colon is a port again, and both patterns split on it.
	require.NoError(t, p.AddTunnel(`{sub:[a-z]+}.other.com:8080`))
	pat, _, err := p.parseAuthorityPattern(`{sub:[a-z]+}.other.com:8080`)
	require.NoError(t, err)
	assert.Equal(t, `{sub:[a-z]+}.other.com`, pat.host)
	assert.Equal(t, "8080", pat.port)

	pat, _, err = p.parsePattern(`{sub:[a-z]+}.other.com:8080/health`)
	require.NoError(t, err)
	assert.Equal(t, `{sub:[a-z]+}.other.com`, pat.host)
	assert.Equal(t, "8080", pat.port)

	// That authority is tunnelled, so an interceptor on it is refused as a conflict rather
	// than as a syntax error: the pattern is well formed, the authority is spoken for.
	_, err = p.AddInterceptor(nil, `{sub:[a-z]+}.other.com:8080/health`, noopHandler)
	assert.ErrorIs(t, err, ErrAuthorityConflict)
}

func TestPath_AddressLiteralMustBeCanonical(t *testing.T) {
	p := testProxy(t)

	// An address has exactly one spelling, bracketed as an authority carries it. Anything
	// else is refused with the form to use, so no two patterns reach one key.
	pat, _, err := p.parsePattern("[::1]/health")
	require.NoError(t, err)
	assert.Equal(t, "::1", pat.host)
	assert.Equal(t, "::1/health", pat.key)

	for _, tc := range []struct{ pattern, hint string }{
		{"::1/health", "IPv6 literal must be bracketed"},
		{"[::0]/health", "non-canonical address literal, write [::]"},
		{"[::FF]/health", "non-canonical address literal, write [::ff]"},
		{"[0:0:0:0:0:0:0:1]/health", "non-canonical address literal, write [::1]"},
		{"[::ffff:127.0.0.1]/health", "non-canonical address literal, write 127.0.0.1"},
	} {
		_, _, err := p.parsePattern(tc.pattern)
		var pe *PatternError
		require.ErrorAs(t, err, &pe, tc.pattern)
		assert.Contains(t, pe.Error(), tc.hint, tc.pattern)
	}
}
