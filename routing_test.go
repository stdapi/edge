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

func testProxy(t *testing.T, opts ...Option) *Proxy {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(append([]Option{WithCA(ca)}, opts...)...)
	require.NoError(t, err)
	return p
}

func noopHandler(*Context) (*http.Response, error) { return Status(http.StatusOK), nil }

// match resolves the route that would serve method and rawURL.
func match(t *testing.T, p *Proxy, method, scheme, authority, path string) *Route {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	host, port := splitHostPort(authority)
	rte, _ := p.Match(Target{Scheme: scheme, Host: host, Port: port}, req)
	return rte
}

func TestRouting_SchemeIsOptional(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)

	for _, scheme := range []string{"http", "https"} {
		rte := match(t, p, http.MethodGet, scheme, "api.stripe.com:443", "/v1/charges")
		require.NotNil(t, rte, "scheme %s", scheme)
		assert.Equal(t, "api.stripe.com/v1/charges", rte.Pattern())
	}
}

func TestRouting_SchemeQualified(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler, WithScheme("https"))

	assert.NotNil(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Nil(t, match(t, p, http.MethodGet, "http", "api.stripe.com:80", "/v1/charges"))
}

func TestRouting_SchemeQualifiedBeatsUnqualified(t *testing.T) {
	p := testProxy(t)
	generic := p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
	secure := p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler, WithScheme("https"))

	// A route carrying a matcher is more constrained, so it is tried first.
	assert.Same(t, secure, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Same(t, generic, match(t, p, http.MethodGet, "http", "api.stripe.com:80", "/v1/charges"))
}

func TestRouting_PortIsOptional(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "localhost/api", noopHandler, WithPort("8080"))

	assert.NotNil(t, match(t, p, http.MethodGet, "http", "localhost:8080", "/api"))
	assert.Nil(t, match(t, p, http.MethodGet, "http", "localhost:9090", "/api"))
	assert.Nil(t, match(t, p, http.MethodGet, "http", "localhost:80", "/api"))
}

func TestRouting_StaticPathBeatsParam(t *testing.T) {
	p := testProxy(t)
	static := p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
	param := p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/{id}", noopHandler)

	assert.Same(t, static, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Same(t, param, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/ch_123"))
}

func TestRouting_StaticPathBeatsSchemeQualifiedParam(t *testing.T) {
	p := testProxy(t)
	static := p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
	p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/{id}", noopHandler, WithScheme("https"))

	// The scheme is a matcher rather than a tree edge precisely so it cannot promote a
	// parameter above a static segment.
	assert.Same(t, static, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
}

func TestRouting_HostWildcard(t *testing.T) {
	p := testProxy(t)
	wild := p.MustHandle([]string{http.MethodGet}, "+{sub}.stripe.com/v1/charges", noopHandler)
	exact := p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)

	assert.Same(t, exact, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Same(t, wild, match(t, p, http.MethodGet, "https", "a.b.stripe.com:443", "/v1/charges"))
	assert.Nil(t, match(t, p, http.MethodGet, "https", "stripe.com:443", "/v1/charges"))
}

func TestRouting_CapturesParams(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "+{sub}.stripe.com/v1/{id}/refunds/*{rest}", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/v1/ch_123/refunds/a/b", nil)
	rte, c, _ := p.Lookup(Target{Scheme: "https", Host: "a.b.stripe.com", Port: "443"}, req)
	require.NotNil(t, rte)
	defer c.Close()

	assert.Equal(t, "a.b", c.Param("sub"))
	assert.Equal(t, "ch_123", c.Param("id"))
	assert.Equal(t, "a/b", c.Param("rest"))
}

func TestRouting_AuthorityLessRouteMatchesEveryHost(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "/v1/charges", noopHandler)

	assert.NotNil(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.NotNil(t, match(t, p, http.MethodGet, "http", "example.test:80", "/v1/charges"))

	// It names no authority, so it cannot imply one to intercept.
	assert.Equal(t, 0, countRules(p))
}

func TestRouting_IPLiteralHost(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "127.0.0.1/health", noopHandler, WithPort("8080"))
	p.MustHandle([]string{http.MethodGet}, "::1/health", noopHandler, WithPort("8080"))

	assert.NotNil(t, match(t, p, http.MethodGet, "http", "127.0.0.1:8080", "/health"))
	assert.NotNil(t, match(t, p, http.MethodGet, "http", "[::1]:8080", "/health"))
	assert.Nil(t, match(t, p, http.MethodGet, "http", "127.0.0.2:8080", "/health"))
}

func TestRouting_MethodConstraint(t *testing.T) {
	p := testProxy(t)
	post := p.MustHandle([]string{http.MethodPost}, "api.stripe.com/v1/charges", noopHandler)
	any := p.MustHandle(nil, "api.stripe.com/v1/charges", noopHandler)

	assert.Same(t, post, match(t, p, http.MethodPost, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Same(t, any, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
}

func TestRouting_TrailingSlash(t *testing.T) {
	t.Run("exact by default", func(t *testing.T) {
		p := testProxy(t)
		p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
		assert.Nil(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges/"))
	})

	t.Run("relaxed", func(t *testing.T) {
		p := testProxy(t, WithTrailingSlash(RelaxedSlash))
		p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
		assert.NotNil(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges/"))
	})
}

func TestRouting_RejectsConnect(t *testing.T) {
	p := testProxy(t)
	_, err := p.Handle([]string{http.MethodConnect}, "api.stripe.com/", noopHandler)
	require.ErrorIs(t, err, ErrInvalidRoute)
	assert.Contains(t, err.Error(), "tunnel layer")
}

func TestRouting_ConflictDetection(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)

	_, err := p.Handle([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
	var conflict *RouteConflictError
	require.ErrorAs(t, err, &conflict)

	// Differing by a matcher is not a conflict: the matchers tell the two routes apart.
	_, err = p.Handle([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler, WithScheme("https"))
	require.NoError(t, err)
}

func countRules(p *Proxy) int {
	n := 0
	for range p.Rules() {
		n++
	}
	return n
}
