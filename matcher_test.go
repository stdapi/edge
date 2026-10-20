// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requestCtx(req *http.Request, scheme string) RequestContext {
	return onlyRequestContext{c: &routeCtx{req: req, scheme: scheme, params: new([]string)}}
}

func must[M RequestMatcher](m M, err error) M {
	if err != nil {
		panic(err)
	}
	return m
}

func TestMatcher_Match(t *testing.T) {
	cases := []struct {
		name    string
		matcher RequestMatcher
		method  string
		target  string
		header  http.Header
		remote  string
		proto   int
		scheme  string
		want    bool
	}{
		{name: "query value", matcher: must(MatchQuery("foo", "bar")), target: "/path?foo=bar", want: true},
		{name: "query other value", matcher: must(MatchQuery("foo", "bar")), target: "/path?foo=baz"},
		{name: "query missing key", matcher: must(MatchQuery("foo", "bar")), target: "/path?other=bar"},
		{name: "query without query string", matcher: must(MatchQuery("foo", "bar")), target: "/path"},
		{name: "query second value of a repeated key", matcher: must(MatchQuery("foo", "b")), target: "/path?foo=a&foo=b", want: true},
		{name: "query no value of a repeated key", matcher: must(MatchQuery("foo", "c")), target: "/path?foo=a&foo=b"},
		{name: "query empty value and missing key", matcher: must(MatchQuery("foo", "")), target: "/path"},
		{name: "query empty value and empty parameter", matcher: must(MatchQuery("foo", "")), target: "/path?foo=", want: true},
		{name: "query regexp", matcher: must(MatchQueryRegexp("version", "v[0-9]+")), target: "/x?version=v12", want: true},
		{name: "query regexp no match", matcher: must(MatchQueryRegexp("version", "v[0-9]+")), target: "/x?version=beta"},
		{name: "query regexp partial match", matcher: must(MatchQueryRegexp("version", "v[0-9]+")), target: "/x?version=xv1x"},
		{name: "query regexp missing key", matcher: must(MatchQueryRegexp("version", ".*")), target: "/x"},
		{name: "query regexp second value of a repeated key", matcher: must(MatchQueryRegexp("tenant", "ac.*")), target: "/x?tenant=other&tenant=acme", want: true},
		{name: "query regexp no value of a repeated key", matcher: must(MatchQueryRegexp("tenant", "ac.*")), target: "/x?tenant=a&tenant=b"},
		{name: "header value", matcher: must(MatchHeader("x-test-run", "run-42")), header: http.Header{"X-Test-Run": {"run-42"}}, want: true},
		{name: "header other value", matcher: must(MatchHeader("X-Test-Run", "run-42")), header: http.Header{"X-Test-Run": {"run-43"}}},
		{name: "header missing", matcher: must(MatchHeader("X-Test-Run", "run-42")), header: http.Header{"X-Other": {"run-42"}}},
		{name: "header without headers", matcher: must(MatchHeader("X-Test-Run", "run-42"))},
		{name: "header second value of a repeated key", matcher: must(MatchHeader("X-Tenant", "acme")), header: http.Header{"X-Tenant": {"other", "acme"}}, want: true},
		{name: "header no value of a repeated key", matcher: must(MatchHeader("X-Tenant", "acme")), header: http.Header{"X-Tenant": {"a", "b"}}},
		{name: "header regexp", matcher: must(MatchHeaderRegexp("X-Test-Run", "run-[0-9]+")), header: http.Header{"X-Test-Run": {"run-42"}}, want: true},
		{name: "header regexp no match", matcher: must(MatchHeaderRegexp("X-Test-Run", "run-[0-9]+")), header: http.Header{"X-Test-Run": {"run-x"}}},
		{name: "header regexp missing", matcher: must(MatchHeaderRegexp("X-Test-Run", ".*"))},
		{name: "header regexp second value of a repeated key", matcher: must(MatchHeaderRegexp("X-Tenant", "ac.*")), header: http.Header{"X-Tenant": {"other", "acme"}}, want: true},
		{name: "remote address", matcher: must(MatchRemoteIP("192.168.1.1")), remote: "192.168.1.1:4242", want: true},
		{name: "remote address in range", matcher: must(MatchRemoteIP("192.168.1.0/24")), remote: "192.168.1.100:4242", want: true},
		{name: "remote address out of range", matcher: must(MatchRemoteIP("192.168.1.0/24")), remote: "192.168.2.1:4242"},
		{name: "remote IPv6 address in range", matcher: must(MatchRemoteIP("2001:db8::/32")), remote: "[2001:db8::1]:4242", want: true},
		{name: "remote IPv4-mapped address in an IPv4 range", matcher: must(MatchRemoteIP("192.168.1.0/24")), remote: "[::ffff:192.168.1.100]:4242", want: true},
		{name: "remote IPv4-mapped range", matcher: must(MatchRemoteIP("::ffff:192.168.1.0/120")), remote: "192.168.1.100:4242", want: true},
		{name: "remote zoned link-local address", matcher: must(MatchRemoteIP("fe80::/10")), remote: "[fe80::1%eth0]:4242", want: true},
		{name: "remote address unparsable", matcher: must(MatchRemoteIP("0.0.0.0/0")), remote: "pipe"},
		{name: "scheme https", matcher: must(MatchScheme("https")), scheme: "https", want: true},
		{name: "scheme http", matcher: must(MatchScheme("http")), scheme: "http", want: true},
		{name: "scheme mismatch", matcher: must(MatchScheme("https")), scheme: "http"},
		{name: "scheme of the target with an https request URL", matcher: must(MatchScheme("https")), target: "https://a.test/", scheme: "http"},
		{name: "protocol HTTP/2", matcher: must(MatchProtocol(HTTP2)), proto: 2, want: true},
		{name: "protocol HTTP/3", matcher: must(MatchProtocol(HTTP3)), proto: 3, want: true},
		{name: "protocol mismatch", matcher: must(MatchProtocol(HTTP3)), proto: 2},
		{name: "method", matcher: must(MatchMethods(http.MethodGet)), method: http.MethodGet, want: true},
		{name: "method in a set", matcher: must(MatchMethods(http.MethodGet, http.MethodPost)), method: http.MethodPost, want: true},
		{name: "method out of a set", matcher: must(MatchMethods(http.MethodGet, http.MethodPost)), method: http.MethodDelete},
		{name: "method is case-sensitive", matcher: must(MatchMethods(http.MethodGet)), method: "get"},
		{name: "extension method", matcher: must(MatchMethods("PURGE")), method: "PURGE", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method, target := tc.method, tc.target
			if method == "" {
				method = http.MethodGet
			}
			if target == "" {
				target = "/"
			}
			req := httptest.NewRequest(method, target, nil)
			if tc.header != nil {
				req.Header = tc.header
			}
			if tc.remote != "" {
				req.RemoteAddr = tc.remote
			}
			if tc.proto != 0 {
				req.ProtoMajor, req.ProtoMinor = tc.proto, 0
			}
			assert.Equal(t, tc.want, tc.matcher.Match(requestCtx(req, tc.scheme)))
		})
	}
}

func TestMatcher_Equal(t *testing.T) {
	distinct := []RequestMatcher{
		must(MatchScheme("http")),
		must(MatchScheme("https")),
		must(MatchQuery("foo", "bar")),
		must(MatchQuery("baz", "bar")),
		must(MatchQuery("foo", "baz")),
		must(MatchQueryRegexp("foo", "bar")),
		must(MatchQueryRegexp("foo", "b.r")),
		must(MatchHeader("foo", "bar")),
		must(MatchHeader("baz", "bar")),
		must(MatchHeaderRegexp("foo", "bar")),
		must(MatchHeaderRegexp("foo", "b.r")),
		must(MatchRemoteIP("192.168.1.0/24")),
		must(MatchRemoteIP("192.168.2.0/24")),
		must(MatchRemoteIP("192.168.0.0/16")),
		must(MatchProtocol(HTTP11)),
		must(MatchProtocol(HTTP2)),
		must(MatchMethods(http.MethodGet)),
		must(MatchMethods(http.MethodGet, http.MethodPost)),
	}
	for i, a := range distinct {
		for j, b := range distinct {
			assert.Equal(t, i == j, a.Equal(b), "%v and %v", a, b)
		}
	}

	for _, tc := range []struct {
		name string
		a, b RequestMatcher
	}{
		{"scheme case", must(MatchScheme("HTTPS")), must(MatchScheme("https"))},
		{"header key case", must(MatchHeader("x-api-key", "v")), must(MatchHeader("X-Api-Key", "v"))},
		{"header regexp key case", must(MatchHeaderRegexp("x-api-key", "v.*")), must(MatchHeaderRegexp("X-Api-Key", "v.*"))},
		{"masked prefix", must(MatchRemoteIP("10.1.2.3/8")), must(MatchRemoteIP("10.0.0.0/8"))},
		{"mapped prefix", must(MatchRemoteIP("::ffff:10.0.0.0/104")), must(MatchRemoteIP("10.0.0.0/8"))},
		{"mapped address", must(MatchRemoteIP("::ffff:10.0.0.1")), must(MatchRemoteIP("10.0.0.1"))},
		{"address and full prefix", must(MatchRemoteIP("10.0.0.1")), must(MatchRemoteIP("10.0.0.1/32"))},
		{"method order and repetition", must(MatchMethods(http.MethodPost, http.MethodGet, http.MethodPost)), must(MatchMethods(http.MethodGet, http.MethodPost))},
	} {
		assert.True(t, tc.a.Equal(tc.b), tc.name)
		assert.True(t, tc.b.Equal(tc.a), tc.name)
	}
}

func TestMatcher_String(t *testing.T) {
	for _, tc := range []struct {
		matcher interface{ String() string }
		want    string
	}{
		{must(MatchScheme("HTTPS")), "scheme=https"},
		{must(MatchQuery("mode", "test")), "query:mode=test"},
		{must(MatchQueryRegexp("version", "v[0-9]+")), "query:version~=v[0-9]+"},
		{must(MatchHeader("x-test-run", "42")), "header:X-Test-Run=42"},
		{must(MatchHeaderRegexp("x-test-run", "[0-9]+")), "header:X-Test-Run~=[0-9]+"},
		{must(MatchRemoteIP("10.1.2.3/8")), "remoteip=10.0.0.0/8"},
		{must(MatchProtocol(HTTP2)), "proto=" + HTTP2.String()},
		{must(MatchMethods(http.MethodPost, http.MethodGet)), "method=GET,POST"},
	} {
		assert.Equal(t, tc.want, tc.matcher.String())
	}
}

func TestMatcher_Accessors(t *testing.T) {
	assert.Equal(t, "https", must(MatchScheme("HTTPS")).Scheme())

	q := must(MatchQuery("foo", ""))
	assert.Equal(t, "foo", q.Key())
	assert.Empty(t, q.Value())

	qre := must(MatchQueryRegexp("version", "v[0-9]+"))
	assert.Equal(t, "version", qre.Key())
	assert.Equal(t, "v[0-9]+", qre.Value())

	h := must(MatchHeader("x-test-run", "run-42"))
	assert.Equal(t, "X-Test-Run", h.Key())
	assert.Equal(t, "run-42", h.Value())

	hre := must(MatchHeaderRegexp("x-test-run", "run-[0-9]+"))
	assert.Equal(t, "X-Test-Run", hre.Key())
	assert.Equal(t, "run-[0-9]+", hre.Value())

	assert.Equal(t, netip.MustParsePrefix("2001:db8::1/128"), must(MatchRemoteIP("2001:db8::1")).Prefix())
	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), must(MatchRemoteIP("::ffff:10.0.0.0/104")).Prefix())
	assert.Equal(t, HTTP3, must(MatchProtocol(HTTP3)).Protocol())
	assert.Equal(t, []string{http.MethodGet, "PURGE"}, slices.Collect(must(MatchMethods("PURGE", http.MethodGet)).Methods()))
}

func TestMatcher_InvalidArguments(t *testing.T) {
	for name, build := range map[string]func() error{
		"scheme ws":                             func() error { _, err := MatchScheme("ws"); return err },
		"empty scheme":                          func() error { _, err := MatchScheme(""); return err },
		"empty query key":                       func() error { _, err := MatchQuery("", "v"); return err },
		"empty query regexp key":                func() error { _, err := MatchQueryRegexp("", "v"); return err },
		"empty query expression":                func() error { _, err := MatchQueryRegexp("k", ""); return err },
		"invalid query expression":              func() error { _, err := MatchQueryRegexp("k", "a{5,2}"); return err },
		"query capture group":                   func() error { _, err := MatchQueryRegexp("k", "(v[0-9]+)"); return err },
		"query expression escaping its anchors": func() error { _, err := MatchQueryRegexp("k", "a)|(?:"); return err },
		"empty header key":                      func() error { _, err := MatchHeader("", "v"); return err },
		"empty header regexp key":               func() error { _, err := MatchHeaderRegexp("", "v"); return err },
		"invalid header expression":             func() error { _, err := MatchHeaderRegexp("k", `\k`); return err },
		"header capture group":                  func() error { _, err := MatchHeaderRegexp("k", "(a|b)"); return err },
		"header expression escaping its anchors": func() error {
			_, err := MatchHeaderRegexp("k", "a)|(?:")
			return err
		},
		"header key with a space":         func() error { _, err := MatchHeader("X Foo", "v"); return err },
		"header key with a colon":         func() error { _, err := MatchHeader("X-Foo:", "v"); return err },
		"header Host":                     func() error { _, err := MatchHeader("host", "v"); return err },
		"header Transfer-Encoding":        func() error { _, err := MatchHeader("transfer-encoding", "chunked"); return err },
		"header regexp key with a space":  func() error { _, err := MatchHeaderRegexp("X Foo", "v"); return err },
		"header regexp Host":              func() error { _, err := MatchHeaderRegexp("Host", ".*"); return err },
		"header regexp Transfer-Encoding": func() error { _, err := MatchHeaderRegexp("Transfer-Encoding", ".*"); return err },
		"invalid address":                 func() error { _, err := MatchRemoteIP("not-an-ip"); return err },
		"empty address":                   func() error { _, err := MatchRemoteIP(""); return err },
		"zoned address":                   func() error { _, err := MatchRemoteIP("fe80::1%eth0"); return err },
		"invalid prefix length":           func() error { _, err := MatchRemoteIP("10.0.0.0/33"); return err },
		"zero protocol":                   func() error { _, err := MatchProtocol(0); return err },
		"unknown protocol":                func() error { _, err := MatchProtocol(Protocol(99)); return err },
		"no method":                       func() error { _, err := MatchMethods(); return err },
		"empty method":                    func() error { _, err := MatchMethods(""); return err },
		"method with a space":             func() error { _, err := MatchMethods("G ET"); return err },
		"method with a NUL":               func() error { _, err := MatchMethods("G\x00ET"); return err },
		"CONNECT":                         func() error { _, err := MatchMethods(http.MethodConnect); return err },
	} {
		assert.ErrorIs(t, build(), ErrInvalidMatcher, name)
	}
}

func TestMatcher_RegexpIsAnchored(t *testing.T) {
	q := must(MatchQueryRegexp("scope", "read|write"))
	for target, want := range map[string]bool{
		"/?scope=read":       true,
		"/?scope=write":      true,
		"/?scope=readBYPASS": false,
		"/?scope=EVILwrite":  false,
	} {
		assert.Equal(t, want, q.Match(requestCtx(httptest.NewRequest(http.MethodGet, target, nil), "https")), target)
	}

	h := must(MatchHeaderRegexp("X-Role", "admin|user|guest"))
	for value, want := range map[string]bool{
		"admin":       true,
		"user":        true,
		"guest":       true,
		"adminBYPASS": false,
		"EVILguest":   false,
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Role", value)
		assert.Equal(t, want, h.Match(requestCtx(req, "https")), value)
	}
}

func TestMatcher_NarrowsAnInterceptor(t *testing.T) {
	p := testProxy(t)

	beta, err := MatchHeader("X-Channel", "beta")
	require.NoError(t, err)

	special := p.MustAdd("api.test/v1/charges", noopHandler, WithRequestMatchers[HTTP](beta), WithMethods[HTTP](http.MethodGet))
	fallback := p.MustAdd("api.test/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))

	req := httptest.NewRequest(http.MethodGet, "/v1/charges", nil)
	req.Header.Set("X-Channel", "beta")
	got := matchRequest(t, p, "https", joinHostPort("api.test", "443"), req)
	assert.Equal(t, special, got, "the matched interceptor must win over the fallback")

	plain := httptest.NewRequest(http.MethodGet, "/v1/charges", nil)
	got = matchRequest(t, p, "https", joinHostPort("api.test", "443"), plain)
	assert.Equal(t, fallback, got)

	// An interceptor carrying matchers is identified by them.
	assert.Equal(t, special, lookupHTTP(p, "api.test/v1/charges", beta, mustMethods(http.MethodGet)))
	assert.Equal(t, fallback, lookupHTTP(p, "api.test/v1/charges", mustMethods(http.MethodGet)))
}

func TestMatcher_ProtocolAndRemoteIPComeFromTheRequest(t *testing.T) {
	p := testProxy(t)

	h3, err := MatchProtocol(HTTP3)
	require.NoError(t, err)
	lan, err := MatchRemoteIP("192.0.2.0/24")
	require.NoError(t, err)

	narrow := p.MustAdd("api.test/v1/charges", noopHandler, WithRequestMatchers[HTTP](h3, lan), WithMethods[HTTP](http.MethodGet))
	fallback := p.MustAdd("api.test/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))

	req := httptest.NewRequest(http.MethodGet, "/v1/charges", nil)
	req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/3.0", 3, 0
	req.RemoteAddr = "192.0.2.10:4242"
	assert.Equal(t, narrow, matchRequest(t, p, "https", "api.test:443", req))

	off := httptest.NewRequest(http.MethodGet, "/v1/charges", nil)
	off.RemoteAddr = "198.51.100.10:4242"
	assert.Equal(t, fallback, matchRequest(t, p, "https", "api.test:443", off))
}
