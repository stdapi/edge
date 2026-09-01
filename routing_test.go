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

func noopHandler(*HTTPCtx) (*http.Response, error) { return Status(http.StatusOK), nil }

// match resolves the interceptor that would serve method and path on authority.
func match(t *testing.T, p *Proxy, method, scheme, authority, path string) Entry[HTTP] {
	t.Helper()
	return matchRequest(t, p, scheme, authority, httptest.NewRequest(method, path, nil))
}

// matchRequest runs the lookup serve runs, without running a handler. It is the routing
// oracle the tests assert on: a real request, resolved the way a served one is.
func matchRequest(t *testing.T, p *Proxy, scheme, authority string, req *http.Request) Entry[HTTP] {
	t.Helper()
	host, port := splitHostPort(authority)
	target := Target{Scheme: scheme, Host: host, Port: port}.normalized()

	tree := p.getTree()
	c := tree.pool.Get().(*routeCtx)
	defer tree.pool.Put(c)
	c.reset(nil, req, target.Scheme, target.Host, target.Port)

	idx, n := tree.lookup(target.Host, routingPath(req), c, false)
	if n == nil {
		return Entry[HTTP]{}
	}
	return Entry[HTTP]{e: n.entries[idx]}
}

func TestRouting_SchemeIsOptional(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods(http.MethodGet))

	for _, scheme := range []string{"http", "https"} {
		ic := match(t, p, http.MethodGet, scheme, "api.stripe.com:443", "/v1/charges")
		require.NotZero(t, ic, "scheme %s", scheme)
		assert.Equal(t, "api.stripe.com/v1/charges", ic.Pattern())
	}
}

func TestRouting_SchemeQualified(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithScheme("https"), WithMethods(http.MethodGet))

	assert.NotZero(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Zero(t, match(t, p, http.MethodGet, "http", "api.stripe.com:80", "/v1/charges"))
}

func TestRouting_SchemeQualifiedBeatsUnqualified(t *testing.T) {
	p := testProxy(t)
	generic := p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods(http.MethodGet))
	secure := p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithScheme("https"), WithMethods(http.MethodGet))

	// An interceptor carrying a matcher is more constrained, so it is tried first.
	assert.Equal(t, secure, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Equal(t, generic, match(t, p, http.MethodGet, "http", "api.stripe.com:80", "/v1/charges"))
}

func TestRouting_PortIsOptional(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("localhost:8080/api", noopHandler, WithMethods(http.MethodGet))

	assert.NotZero(t, match(t, p, http.MethodGet, "http", "localhost:8080", "/api"))
	assert.Zero(t, match(t, p, http.MethodGet, "http", "localhost:9090", "/api"))
	assert.Zero(t, match(t, p, http.MethodGet, "http", "localhost:80", "/api"))
}

func TestRouting_StaticPathBeatsParam(t *testing.T) {
	p := testProxy(t)
	static := p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods(http.MethodGet))
	param := p.MustAdd("api.stripe.com/v1/{id}", noopHandler, WithMethods(http.MethodGet))

	assert.Equal(t, static, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Equal(t, param, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/ch_123"))
}

func TestRouting_StaticPathBeatsSchemeQualifiedParam(t *testing.T) {
	p := testProxy(t)
	static := p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods(http.MethodGet))
	p.MustAdd("api.stripe.com/v1/{id}", noopHandler, WithScheme("https"), WithMethods(http.MethodGet))

	// The scheme is a matcher rather than a tree edge precisely so it cannot promote a
	// parameter above a static segment.
	assert.Equal(t, static, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
}

func TestRouting_HostWildcard(t *testing.T) {
	p := testProxy(t)
	wild := p.MustAdd("+{sub}.stripe.com/v1/charges", noopHandler, WithMethods(http.MethodGet))
	exact := p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods(http.MethodGet))

	assert.Equal(t, exact, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Equal(t, wild, match(t, p, http.MethodGet, "https", "a.b.stripe.com:443", "/v1/charges"))
	assert.Zero(t, match(t, p, http.MethodGet, "https", "stripe.com:443", "/v1/charges"))
}

func TestRouting_CapturesParams(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("+{sub}.stripe.com/v1/{id}/refunds/*{rest}", noopHandler, WithMethods(http.MethodGet))

	req := httptest.NewRequest(http.MethodGet, "/v1/ch_123/refunds/a/b", nil)

	tree := p.getTree()
	rc := tree.pool.Get().(*routeCtx)
	defer tree.pool.Put(rc)
	rc.reset(nil, req, "https", "a.b.stripe.com", "443")

	idx, n := tree.lookup("a.b.stripe.com", "/v1/ch_123/refunds/a/b", rc, false)
	require.NotNil(t, n)
	rc.entry = n.entries[idx]

	c := &rc.http
	assert.Equal(t, "a.b", c.Param("sub"))
	assert.Equal(t, "ch_123", c.Param("id"))
	assert.Equal(t, "a/b", c.Param("rest"))
}

func TestRouting_WildcardAuthorityMatchesEveryHost(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("+{any}/v1/charges", noopHandler, WithMethods(http.MethodGet))

	assert.NotZero(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.NotZero(t, match(t, p, http.MethodGet, "http", "example.test:80", "/v1/charges"))

	// It names every authority, so that is what it arms: the wildcard says out loud what
	// an omitted hostname used to leave to guesswork.
	assert.Equal(t, 1, countAuthorities(p))
	assert.Equal(t, true, p.Admits(target("anything.test:443"), KindHTTP))
}

// An interceptor must name the authority it intercepts. An omitted one used to be accepted and arm
// nothing, leaving a handler no connection could reach.
func TestRouting_HostnameIsRequired(t *testing.T) {
	p := testProxy(t)

	_, err := p.Add("/v1/charges", noopHandler, WithMethods(http.MethodGet))
	var pe *PatternError
	require.ErrorAs(t, err, &pe)
	assert.Contains(t, pe.Error(), "write +{any} to match every hostname")
}

func TestRouting_IPLiteralHost(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("127.0.0.1:8080/health", noopHandler, WithMethods(http.MethodGet))
	p.MustAdd("[::1]:8080/health", noopHandler, WithMethods(http.MethodGet))

	assert.NotZero(t, match(t, p, http.MethodGet, "http", "127.0.0.1:8080", "/health"))
	assert.NotZero(t, match(t, p, http.MethodGet, "http", "[::1]:8080", "/health"))
	assert.Zero(t, match(t, p, http.MethodGet, "http", "127.0.0.2:8080", "/health"))
}

func TestRouting_MethodConstraint(t *testing.T) {
	p := testProxy(t)
	post := p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods(http.MethodPost))
	any := p.MustAdd("api.stripe.com/v1/charges", noopHandler)

	assert.Equal(t, post, match(t, p, http.MethodPost, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Equal(t, any, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
}

func TestRouting_TrailingSlash(t *testing.T) {
	t.Run("exact by default", func(t *testing.T) {
		p := testProxy(t)
		p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods(http.MethodGet))
		assert.Zero(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges/"))
	})

	t.Run("relaxed", func(t *testing.T) {
		p := testProxy(t, WithTrailingSlash(RelaxedSlash))
		p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods(http.MethodGet))
		assert.NotZero(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges/"))
	})
}

// CONNECT establishes a connection, it is never a request an entry serves, so a method
// matcher naming it could only ever be dead weight.
func TestRouting_RejectsConnect(t *testing.T) {
	p := testProxy(t)
	_, err := p.Add("api.stripe.com/", noopHandler, WithMethods(http.MethodConnect))
	require.ErrorIs(t, err, ErrInvalidMatcher)
	assert.Contains(t, err.Error(), "establishes a connection")
}

func TestRouting_ConflictDetection(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods(http.MethodGet))

	_, err := p.Add("api.stripe.com/v1/charges", noopHandler, WithMethods(http.MethodGet))
	var conflict *EntryConflictError
	require.ErrorAs(t, err, &conflict)

	// Differing by a matcher is not a conflict: the matchers tell the two interceptors apart.
	_, err = p.Add("api.stripe.com/v1/charges", noopHandler, WithScheme("https"), WithMethods(http.MethodGet))
	require.NoError(t, err)
}

func countAuthorities(p *Proxy) int {
	n := 0
	for range p.Iter().Admissions() {
		n++
	}
	return n
}

// Two interceptors differing only by their port share a tree key and are told apart by the
// port alone. They are two entries, not a conflict and not one another's update.
func TestRouting_PortDiscriminatesTwoInterceptors(t *testing.T) {
	p := testProxy(t)

	api := p.MustAdd("localhost:8080/api", noopHandler, WithMethods(http.MethodGet))
	ui := p.MustAdd("localhost:3000/api", noopHandler, WithMethods(http.MethodGet))
	assert.Equal(t, 2, p.Len())

	assert.Equal(t, api, match(t, p, http.MethodGet, "http", "localhost:8080", "/api"))
	assert.Equal(t, ui, match(t, p, http.MethodGet, "http", "localhost:3000", "/api"))
	assert.Zero(t, match(t, p, http.MethodGet, "http", "localhost:9090", "/api"))

	// Each one arms only its own authority.
	assert.Equal(t, true, p.Admits(target("localhost:8080"), KindHTTP))
	assert.Equal(t, true, p.Admits(target("localhost:3000"), KindHTTP))
	assert.Equal(t, false, p.Admits(target("localhost:9090"), KindHTTP))

	// The pattern identifies them, so no matcher has to be passed back to find one.
	assert.Equal(t, api, lookupHTTP(p, "localhost:8080/api", mustMethods(http.MethodGet)))
	assert.Equal(t, ui, lookupHTTP(p, "localhost:3000/api", mustMethods(http.MethodGet)))
	assert.Zero(t, lookupHTTP(p, "localhost/api", mustMethods(http.MethodGet)))

	deleted, err := p.Delete[HTTP]("localhost:8080/api", WithMethods(http.MethodGet))
	require.NoError(t, err)
	assert.Equal(t, api, deleted)
	assert.Equal(t, ui, match(t, p, http.MethodGet, "http", "localhost:3000", "/api"))
	assert.Equal(t, false, p.Admits(target("localhost:8080"), KindHTTP))
}

// An interceptor naming a port is more narrowly targeted than one accepting every port, so it
// is tried first whatever else narrows the other.
func TestRouting_PortOutranksTheRest(t *testing.T) {
	p := testProxy(t)

	beta, err := MatchHeader("X-Channel", "beta")
	require.NoError(t, err)

	// Registered least specific first, so only the ordering can put them back in order.
	any := p.MustAdd("localhost/api", noopHandler)
	header := p.MustAdd("localhost/api", noopHandler, WithMatcher(beta))
	get := p.MustAdd("localhost/api", noopHandler, WithMethods(http.MethodGet))
	port := p.MustAdd("localhost:8080/api", noopHandler)

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("X-Channel", "beta")

	got := matchRequest(t, p, "http", joinHostPort("localhost", "8080"), req)
	assert.Equal(t, port, got, "the port beats a method and a matcher")

	// Off that port the two narrowed entries are in the same tier, the method being a matcher
	// like any other, so priority orders them and insertion order breaks a tie.
	got = matchRequest(t, p, "http", joinHostPort("localhost", "9090"), req)
	assert.Equal(t, header, got, "equal priority, first registered wins")

	post := httptest.NewRequest(http.MethodPost, "/api", nil)
	post.Header.Set("X-Channel", "beta")
	got = matchRequest(t, p, "http", joinHostPort("localhost", "9090"), post)
	assert.Equal(t, header, got, "the header entry still accepts a POST")

	getOnly := httptest.NewRequest(http.MethodGet, "/api", nil)
	got = matchRequest(t, p, "http", joinHostPort("localhost", "9090"), getOnly)
	assert.Equal(t, get, got, "without the header, the method entry is the narrowed one left")

	plain := httptest.NewRequest(http.MethodPost, "/api", nil)
	got = matchRequest(t, p, "http", joinHostPort("localhost", "9090"), plain)
	assert.Equal(t, any, got, "with nothing left, the fallback")
}

// noopStream is the connection-level handler the routing tests register when what they check
// is the pattern, not what the handler does.
func noopStream(*TCPCtx) error { return nil }
