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
