// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// matchCtx builds the sealed read-only view a matcher is handed, without going through a
// connection.
func matchCtx(t *testing.T, method, target, path string, headers http.Header) RequestContext {
	t.Helper()

	req := httptest.NewRequest(method, path, nil)
	if headers != nil {
		req.Header = headers
	}

	sess := &Session{proto: HTTP2, remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4242}}
	host, port := splitHostPort(target)

	c := &Context{
		req:    req,
		sess:   sess,
		scheme: "https",
		host:   host,
		port:   port,
		params: new([]string),
	}
	return onlyRequestContext{c: c}
}

func TestMatcher_Scheme(t *testing.T) {
	m, err := MatchScheme("HTTPS")
	require.NoError(t, err)
	assert.Equal(t, "https", m.Scheme())
	assert.Equal(t, "scheme=https", m.String())
	assert.True(t, m.Match(matchCtx(t, http.MethodGet, "a.test:443", "/", nil)))

	other, _ := MatchScheme("http")
	assert.False(t, m.Equal(other))
	assert.True(t, m.Equal(SchemeMatcher{scheme: "https"}))

	_, err = MatchScheme("ftp")
	assert.ErrorIs(t, err, ErrInvalidMatcher)
}

func TestMatcher_Port(t *testing.T) {
	m, err := MatchPort("8080")
	require.NoError(t, err)
	assert.Equal(t, "8080", m.Port())
	assert.Equal(t, "port=8080", m.String())

	assert.True(t, m.Match(matchCtx(t, http.MethodGet, "a.test:8080", "/", nil)))
	assert.False(t, m.Match(matchCtx(t, http.MethodGet, "a.test:9090", "/", nil)))

	for _, bad := range []string{"", "0", "70000", "80a", "080"} {
		_, err := MatchPort(bad)
		assert.ErrorIs(t, err, ErrInvalidMatcher, "port %q", bad)
	}
}

func TestMatcher_Query(t *testing.T) {
	m, err := MatchQuery("mode", "test")
	require.NoError(t, err)
	assert.Equal(t, "mode", m.Key())
	assert.Equal(t, "test", m.Value())

	assert.True(t, m.Match(matchCtx(t, http.MethodGet, "a.test:443", "/x?mode=test", nil)))
	assert.False(t, m.Match(matchCtx(t, http.MethodGet, "a.test:443", "/x?mode=live", nil)))
	assert.False(t, m.Match(matchCtx(t, http.MethodGet, "a.test:443", "/x", nil)))

	_, err = MatchQuery("", "test")
	assert.ErrorIs(t, err, ErrInvalidMatcher)
}

func TestMatcher_QueryRegexp(t *testing.T) {
	m, err := MatchQueryRegexp("version", "v[0-9]+")
	require.NoError(t, err)
	assert.Equal(t, "v[0-9]+", m.Value())

	assert.True(t, m.Match(matchCtx(t, http.MethodGet, "a.test:443", "/x?version=v12", nil)))
	assert.False(t, m.Match(matchCtx(t, http.MethodGet, "a.test:443", "/x?version=beta", nil)))
	// The expression is anchored, so a partial match is not a match.
	assert.False(t, m.Match(matchCtx(t, http.MethodGet, "a.test:443", "/x?version=xv1x", nil)))

	_, err = MatchQueryRegexp("version", "(v[0-9]+)")
	assert.ErrorIs(t, err, ErrInvalidMatcher, "a capture group must be refused")

	_, err = MatchQueryRegexp("version", "a)|(?:")
	assert.ErrorIs(t, err, ErrInvalidMatcher, "an expression that only balances inside the anchor must be refused")
}

func TestMatcher_Header(t *testing.T) {
	h := http.Header{"X-Test-Run": {"run-42"}}

	m, err := MatchHeader("x-test-run", "run-42")
	require.NoError(t, err)
	assert.Equal(t, "X-Test-Run", m.Key(), "the key must be canonicalized")
	assert.True(t, m.Match(matchCtx(t, http.MethodGet, "a.test:443", "/", h)))
	assert.False(t, m.Match(matchCtx(t, http.MethodGet, "a.test:443", "/", nil)))

	re, err := MatchHeaderRegexp("X-Test-Run", "run-[0-9]+")
	require.NoError(t, err)
	assert.True(t, re.Match(matchCtx(t, http.MethodGet, "a.test:443", "/", h)))
}

func TestMatcher_RemoteIP(t *testing.T) {
	m, err := MatchRemoteIP("192.0.2.0/24")
	require.NoError(t, err)
	assert.True(t, m.Match(matchCtx(t, http.MethodGet, "a.test:443", "/", nil)))

	other, err := MatchRemoteIP("198.51.100.0/24")
	require.NoError(t, err)
	assert.False(t, other.Match(matchCtx(t, http.MethodGet, "a.test:443", "/", nil)))
	assert.False(t, m.Equal(other))

	_, err = MatchRemoteIP("not-an-ip")
	assert.ErrorIs(t, err, ErrInvalidMatcher)
}

func TestMatcher_Protocol(t *testing.T) {
	m, err := MatchProtocol(HTTP2)
	require.NoError(t, err)
	assert.True(t, m.Match(matchCtx(t, http.MethodGet, "a.test:443", "/", nil)))

	other, _ := MatchProtocol(HTTP3)
	assert.False(t, other.Match(matchCtx(t, http.MethodGet, "a.test:443", "/", nil)))

	_, err = MatchProtocol(Protocol(99))
	assert.ErrorIs(t, err, ErrInvalidMatcher)
}

func TestMatcher_Func(t *testing.T) {
	m := MatcherFunc(func(c RequestContext) bool { return c.Method() == http.MethodPost })
	assert.True(t, m.Match(matchCtx(t, http.MethodPost, "a.test:443", "/", nil)))
	assert.False(t, m.Match(matchCtx(t, http.MethodGet, "a.test:443", "/", nil)))
	// Two function matchers are never equal, so a route carrying one cannot be identified
	// by its matchers.
	assert.False(t, m.Equal(m))
}

func TestMatcher_NarrowsARoute(t *testing.T) {
	p := testProxy(t)

	beta, err := MatchHeader("X-Channel", "beta")
	require.NoError(t, err)

	special := p.MustHandle([]string{http.MethodGet}, "api.test/v1/charges", noopHandler, WithMatcher(beta))
	fallback := p.MustHandle([]string{http.MethodGet}, "api.test/v1/charges", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/v1/charges", nil)
	req.Header.Set("X-Channel", "beta")
	got, _ := p.Match(Target{Scheme: "https", Host: "api.test", Port: "443"}, req)
	assert.Same(t, special, got, "the matched route must win over the fallback")

	plain := httptest.NewRequest(http.MethodGet, "/v1/charges", nil)
	got, _ = p.Match(Target{Scheme: "https", Host: "api.test", Port: "443"}, plain)
	assert.Same(t, fallback, got)

	// A route carrying matchers is identified by them.
	assert.Same(t, special, p.Route([]string{http.MethodGet}, "api.test/v1/charges", beta))
	assert.Same(t, fallback, p.Route([]string{http.MethodGet}, "api.test/v1/charges"))
}
