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

func testProxy(t *testing.T, opts ...ProxyOption) *Proxy {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(append([]ProxyOption{WithCA(ca)}, opts...)...)
	require.NoError(t, err)
	return p
}

func noopHandler(*Context) (*http.Response, error) { return Status(http.StatusOK), nil }

// match resolves the interceptor that would serve method and path on authority.
func match(t *testing.T, p *Proxy, method, scheme, authority, path string) *Interceptor {
	t.Helper()
	return matchRequest(t, p, scheme, authority, httptest.NewRequest(method, path, nil))
}

// matchRequest runs the lookup serve runs, without running a handler. It is the routing
// oracle the tests assert on: a real request, resolved the way a served one is.
func matchRequest(t *testing.T, p *Proxy, scheme, authority string, req *http.Request) *Interceptor {
	t.Helper()
	host, port := splitHostPort(authority)
	target := Target{Scheme: scheme, Host: host, Port: port}.normalized()

	tree := p.getTree()
	c := tree.pool.Get().(*Context)
	defer tree.pool.Put(c)
	c.reset(nil, req, target.Scheme, target.Host, target.Port)

	idx, n := tree.lookup(req.Method, target.Host, routingPath(req), c, false)
	if n == nil {
		return nil
	}
	return n.entries[idx]
}

func TestRouting_SchemeIsOptional(t *testing.T) {
	p := testProxy(t)
	p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)

	for _, scheme := range []string{"http", "https"} {
		ic := match(t, p, http.MethodGet, scheme, "api.stripe.com:443", "/v1/charges")
		require.NotNil(t, ic, "scheme %s", scheme)
		assert.Equal(t, "api.stripe.com/v1/charges", ic.Pattern())
	}
}

func TestRouting_SchemeQualified(t *testing.T) {
	p := testProxy(t)
	p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler, WithScheme("https"))

	assert.NotNil(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Nil(t, match(t, p, http.MethodGet, "http", "api.stripe.com:80", "/v1/charges"))
}

func TestRouting_SchemeQualifiedBeatsUnqualified(t *testing.T) {
	p := testProxy(t)
	generic := p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
	secure := p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler, WithScheme("https"))

	// An interceptor carrying a matcher is more constrained, so it is tried first.
	assert.Same(t, secure, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Same(t, generic, match(t, p, http.MethodGet, "http", "api.stripe.com:80", "/v1/charges"))
}

func TestRouting_PortIsOptional(t *testing.T) {
	p := testProxy(t)
	p.MustAddInterceptor([]string{http.MethodGet}, "localhost:8080/api", noopHandler)

	assert.NotNil(t, match(t, p, http.MethodGet, "http", "localhost:8080", "/api"))
	assert.Nil(t, match(t, p, http.MethodGet, "http", "localhost:9090", "/api"))
	assert.Nil(t, match(t, p, http.MethodGet, "http", "localhost:80", "/api"))
}

func TestRouting_StaticPathBeatsParam(t *testing.T) {
	p := testProxy(t)
	static := p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
	param := p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/{id}", noopHandler)

	assert.Same(t, static, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Same(t, param, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/ch_123"))
}

func TestRouting_StaticPathBeatsSchemeQualifiedParam(t *testing.T) {
	p := testProxy(t)
	static := p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
	p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/{id}", noopHandler, WithScheme("https"))

	// The scheme is a matcher rather than a tree edge precisely so it cannot promote a
	// parameter above a static segment.
	assert.Same(t, static, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
}

func TestRouting_HostWildcard(t *testing.T) {
	p := testProxy(t)
	wild := p.MustAddInterceptor([]string{http.MethodGet}, "+{sub}.stripe.com/v1/charges", noopHandler)
	exact := p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)

	assert.Same(t, exact, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Same(t, wild, match(t, p, http.MethodGet, "https", "a.b.stripe.com:443", "/v1/charges"))
	assert.Nil(t, match(t, p, http.MethodGet, "https", "stripe.com:443", "/v1/charges"))
}

func TestRouting_CapturesParams(t *testing.T) {
	p := testProxy(t)
	p.MustAddInterceptor([]string{http.MethodGet}, "+{sub}.stripe.com/v1/{id}/refunds/*{rest}", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/v1/ch_123/refunds/a/b", nil)

	tree := p.getTree()
	c := tree.pool.Get().(*Context)
	defer tree.pool.Put(c)
	c.reset(nil, req, "https", "a.b.stripe.com", "443")

	idx, n := tree.lookup(http.MethodGet, "a.b.stripe.com", "/v1/ch_123/refunds/a/b", c, false)
	require.NotNil(t, n)
	c.interceptor = n.entries[idx]

	assert.Equal(t, "a.b", c.Param("sub"))
	assert.Equal(t, "ch_123", c.Param("id"))
	assert.Equal(t, "a/b", c.Param("rest"))
}

func TestRouting_WildcardAuthorityMatchesEveryHost(t *testing.T) {
	p := testProxy(t)
	p.MustAddInterceptor([]string{http.MethodGet}, "+{any}/v1/charges", noopHandler)

	assert.NotNil(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.NotNil(t, match(t, p, http.MethodGet, "http", "example.test:80", "/v1/charges"))

	// It names every authority, so that is what it arms: the wildcard says out loud what
	// an omitted hostname used to leave to guesswork.
	assert.Equal(t, 1, countAuthorities(p))
	assert.Equal(t, Intercept, p.Decide(target("anything.test:443")))
}

// An interceptor must name the authority it intercepts. An omitted one used to be accepted and arm
// nothing, leaving a handler no connection could reach.
func TestRouting_HostnameIsRequired(t *testing.T) {
	p := testProxy(t)

	_, err := p.AddInterceptor([]string{http.MethodGet}, "/v1/charges", noopHandler)
	var pe *PatternError
	require.ErrorAs(t, err, &pe)
	assert.Contains(t, pe.Error(), "write +{any} to match every one")
}

func TestRouting_IPLiteralHost(t *testing.T) {
	p := testProxy(t)
	p.MustAddInterceptor([]string{http.MethodGet}, "127.0.0.1:8080/health", noopHandler)
	p.MustAddInterceptor([]string{http.MethodGet}, "[::1]:8080/health", noopHandler)

	assert.NotNil(t, match(t, p, http.MethodGet, "http", "127.0.0.1:8080", "/health"))
	assert.NotNil(t, match(t, p, http.MethodGet, "http", "[::1]:8080", "/health"))
	assert.Nil(t, match(t, p, http.MethodGet, "http", "127.0.0.2:8080", "/health"))
}

func TestRouting_MethodConstraint(t *testing.T) {
	p := testProxy(t)
	post := p.MustAddInterceptor([]string{http.MethodPost}, "api.stripe.com/v1/charges", noopHandler)
	any := p.MustAddInterceptor(nil, "api.stripe.com/v1/charges", noopHandler)

	assert.Same(t, post, match(t, p, http.MethodPost, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Same(t, any, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
}

func TestRouting_TrailingSlash(t *testing.T) {
	t.Run("exact by default", func(t *testing.T) {
		p := testProxy(t)
		p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
		assert.Nil(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges/"))
	})

	t.Run("relaxed", func(t *testing.T) {
		p := testProxy(t, WithTrailingSlash(RelaxedSlash))
		p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
		assert.NotNil(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges/"))
	})
}

func TestRouting_RejectsConnect(t *testing.T) {
	p := testProxy(t)
	_, err := p.AddInterceptor([]string{http.MethodConnect}, "api.stripe.com/", noopHandler)
	require.ErrorIs(t, err, ErrInvalidInterceptor)
	assert.Contains(t, err.Error(), "tunnel layer")
}

func TestRouting_ConflictDetection(t *testing.T) {
	p := testProxy(t)
	p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)

	_, err := p.AddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
	var conflict *InterceptorConflictError
	require.ErrorAs(t, err, &conflict)

	// Differing by a matcher is not a conflict: the matchers tell the two interceptors apart.
	_, err = p.AddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler, WithScheme("https"))
	require.NoError(t, err)
}

func countAuthorities(p *Proxy) int {
	n := 0
	for range p.Iter().Authorities() {
		n++
	}
	return n
}

// Two interceptors differing only by their port share a tree key and are told apart by the
// port alone. They are two entries, not a conflict and not one another's update.
func TestRouting_PortDiscriminatesTwoInterceptors(t *testing.T) {
	p := testProxy(t)

	api := p.MustAddInterceptor([]string{http.MethodGet}, "localhost:8080/api", noopHandler)
	ui := p.MustAddInterceptor([]string{http.MethodGet}, "localhost:3000/api", noopHandler)
	assert.Equal(t, 2, p.InterceptorsLen())

	assert.Same(t, api, match(t, p, http.MethodGet, "http", "localhost:8080", "/api"))
	assert.Same(t, ui, match(t, p, http.MethodGet, "http", "localhost:3000", "/api"))
	assert.Nil(t, match(t, p, http.MethodGet, "http", "localhost:9090", "/api"))

	// Each one arms only its own authority.
	assert.Equal(t, Intercept, p.Decide(target("localhost:8080")))
	assert.Equal(t, Intercept, p.Decide(target("localhost:3000")))
	assert.Equal(t, Reject, p.Decide(target("localhost:9090")))

	// The pattern identifies them, so no matcher has to be passed back to find one.
	assert.Same(t, api, p.Interceptor([]string{http.MethodGet}, "localhost:8080/api"))
	assert.Same(t, ui, p.Interceptor([]string{http.MethodGet}, "localhost:3000/api"))
	assert.Nil(t, p.Interceptor([]string{http.MethodGet}, "localhost/api"))

	deleted, err := p.DeleteInterceptor([]string{http.MethodGet}, "localhost:8080/api")
	require.NoError(t, err)
	assert.Same(t, api, deleted)
	assert.Same(t, ui, match(t, p, http.MethodGet, "http", "localhost:3000", "/api"))
	assert.Equal(t, Reject, p.Decide(target("localhost:8080")))
}

// An interceptor naming a port is more narrowly targeted than one accepting every port, so it
// is tried first whatever else narrows the other.
func TestRouting_PortOutranksTheRest(t *testing.T) {
	p := testProxy(t)

	beta, err := MatchHeader("X-Channel", "beta")
	require.NoError(t, err)

	// Registered least specific first, so only the ordering can put them back in order.
	any := p.MustAddInterceptor(nil, "localhost/api", noopHandler)
	header := p.MustAddInterceptor(nil, "localhost/api", noopHandler, WithMatcher(beta))
	get := p.MustAddInterceptor([]string{http.MethodGet}, "localhost/api", noopHandler)
	port := p.MustAddInterceptor(nil, "localhost:8080/api", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("X-Channel", "beta")

	got := matchRequest(t, p, "http", joinHostPort("localhost", "8080"), req)
	assert.Same(t, port, got, "the port beats a method and a matcher")

	got = matchRequest(t, p, "http", joinHostPort("localhost", "9090"), req)
	assert.Same(t, get, got, "off that port, the method tier decides")

	post := httptest.NewRequest(http.MethodPost, "/api", nil)
	post.Header.Set("X-Channel", "beta")
	got = matchRequest(t, p, "http", joinHostPort("localhost", "9090"), post)
	assert.Same(t, header, got, "off the method, the matcher tier decides")

	plain := httptest.NewRequest(http.MethodPost, "/api", nil)
	got = matchRequest(t, p, "http", joinHostPort("localhost", "9090"), plain)
	assert.Same(t, any, got, "with nothing left, the fallback")
}
