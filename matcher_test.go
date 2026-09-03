// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
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

	// No session: a matcher reads the request and nothing else.
	req.RemoteAddr = "192.0.2.10:4242"
	req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/2.0", 2, 0

	host, port := splitHostPort(target)
	c := &routeCtx{
		req:    req,
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

	// A matcher runs on requests the proxy parsed, so the zero protocol, what a connection
	// carrying no HTTP reports, is not one to match on.
	_, err = MatchProtocol(0)
	assert.ErrorIs(t, err, ErrInvalidMatcher)
}

// A key repeated in the query or the header is several values, and the matcher reads them
// all rather than the first alone.
func TestMatcher_ReadsEveryValueOfARepeatedKey(t *testing.T) {
	q, err := MatchQuery("tenant", "acme")
	require.NoError(t, err)
	qre, err := MatchQueryRegexp("tenant", "ac.*")
	require.NoError(t, err)

	c := matchCtx(t, http.MethodGet, "a.test:443", "/v1?tenant=other&tenant=acme", nil)
	assert.True(t, q.Match(c))
	assert.True(t, qre.Match(c))

	h, err := MatchHeader("X-Tenant", "acme")
	require.NoError(t, err)
	hre, err := MatchHeaderRegexp("X-Tenant", "ac.*")
	require.NoError(t, err)

	headers := http.Header{}
	headers.Add("X-Tenant", "other")
	headers.Add("X-Tenant", "acme")
	c = matchCtx(t, http.MethodGet, "a.test:443", "/v1", headers)
	assert.True(t, h.Match(c))
	assert.True(t, hre.Match(c))
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

// The protocol and the client address are read off the request, so a matcher on either
// narrows an interceptor with nothing but the request in hand.
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
