// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouting_SchemeIsOptional(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))

	for _, scheme := range []string{"http", "https"} {
		ic := match(t, p, http.MethodGet, scheme, "api.stripe.com:443", "/v1/charges")
		require.NotZero(t, ic, "scheme %s", scheme)
		assert.Equal(t, "api.stripe.com/v1/charges", ic.Pattern())
	}
}

func TestRouting_SchemeQualified(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithScheme[HTTP]("https"), WithMethods[HTTP](http.MethodGet))

	assert.NotZero(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Zero(t, match(t, p, http.MethodGet, "http", "api.stripe.com:80", "/v1/charges"))
}

func TestRouting_SchemeQualifiedBeatsUnqualified(t *testing.T) {
	p := testProxy(t)
	generic := p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))
	secure := p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithScheme[HTTP]("https"), WithMethods[HTTP](http.MethodGet))

	// An interceptor carrying a matcher is more constrained, so it is tried first.
	assert.Equal(t, secure, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Equal(t, generic, match(t, p, http.MethodGet, "http", "api.stripe.com:80", "/v1/charges"))
}

func TestRouting_PortIsOptional(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("localhost:8080/api", noopHandler, WithMethods[HTTP](http.MethodGet))

	assert.NotZero(t, match(t, p, http.MethodGet, "http", "localhost:8080", "/api"))
	assert.Zero(t, match(t, p, http.MethodGet, "http", "localhost:9090", "/api"))
	assert.Zero(t, match(t, p, http.MethodGet, "http", "localhost:80", "/api"))
}

func TestRouting_StaticPathBeatsParam(t *testing.T) {
	p := testProxy(t)
	static := p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))
	param := p.MustAdd("api.stripe.com/v1/{id}", noopHandler, WithMethods[HTTP](http.MethodGet))

	assert.Equal(t, static, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Equal(t, param, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/ch_123"))
}

func TestRouting_StaticPathBeatsSchemeQualifiedParam(t *testing.T) {
	p := testProxy(t)
	static := p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))
	p.MustAdd("api.stripe.com/v1/{id}", noopHandler, WithScheme[HTTP]("https"), WithMethods[HTTP](http.MethodGet))

	// The scheme is a matcher rather than a tree edge precisely so it cannot promote a
	// parameter above a static segment.
	assert.Equal(t, static, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
}

func TestRouting_HostWildcard(t *testing.T) {
	p := testProxy(t)
	wild := p.MustAdd("+{sub}.stripe.com/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))
	exact := p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))

	assert.Equal(t, exact, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Equal(t, wild, match(t, p, http.MethodGet, "https", "a.b.stripe.com:443", "/v1/charges"))
	assert.Zero(t, match(t, p, http.MethodGet, "https", "stripe.com:443", "/v1/charges"))
}

func TestRouting_CapturesParams(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("+{sub}.stripe.com/v1/{id}/refunds/*{rest}", noopHandler, WithMethods[HTTP](http.MethodGet))

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
	p.MustAdd("+{any}/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))

	assert.NotZero(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
	assert.NotZero(t, match(t, p, http.MethodGet, "http", "example.test:80", "/v1/charges"))

	// It names every authority, so that is what it arms: the wildcard says out loud what
	// an omitted hostname used to leave to guesswork.
	assert.Equal(t, 1, countAuthorities(p))
	assert.Equal(t, true, p.Admits(target("anything.test:443"), KindHTTP))
}

func TestRouting_HostnameIsRequired(t *testing.T) {
	p := testProxy(t)

	_, err := p.Add("/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))
	var pe *PatternError
	require.ErrorAs(t, err, &pe)
	assert.Contains(t, pe.Error(), "write +{any} to match every hostname")
}

func TestRouting_IPLiteralHost(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("127.0.0.1:8080/health", noopHandler, WithMethods[HTTP](http.MethodGet))
	p.MustAdd("[::1]:8080/health", noopHandler, WithMethods[HTTP](http.MethodGet))

	assert.NotZero(t, match(t, p, http.MethodGet, "http", "127.0.0.1:8080", "/health"))
	assert.NotZero(t, match(t, p, http.MethodGet, "http", "[::1]:8080", "/health"))
	assert.Zero(t, match(t, p, http.MethodGet, "http", "127.0.0.2:8080", "/health"))
}

func TestRouting_MethodConstraint(t *testing.T) {
	p := testProxy(t)
	post := p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods[HTTP](http.MethodPost))
	any := p.MustAdd("api.stripe.com/v1/charges", noopHandler)

	assert.Equal(t, post, match(t, p, http.MethodPost, "https", "api.stripe.com:443", "/v1/charges"))
	assert.Equal(t, any, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
}

func TestRouting_TrailingSlash(t *testing.T) {
	t.Run("exact by default", func(t *testing.T) {
		p := testProxy(t)
		p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))
		assert.Zero(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges/"))
	})

	t.Run("relaxed", func(t *testing.T) {
		p := testProxy(t, WithDefaultTrailingSlash(RelaxedSlash))
		p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))
		assert.NotZero(t, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges/"))
	})
}

func TestRouting_RejectsConnect(t *testing.T) {
	p := testProxy(t)
	_, err := p.Add("api.stripe.com/", noopHandler, WithMethods[HTTP](http.MethodConnect))
	require.ErrorIs(t, err, ErrInvalidMatcher)
	assert.Contains(t, err.Error(), "establishes a connection")
}

func TestRouting_ConflictDetection(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))

	_, err := p.Add("api.stripe.com/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))
	var conflict *EntryConflictError
	require.ErrorAs(t, err, &conflict)

	// Differing by a matcher is not a conflict: the matchers tell the two interceptors apart.
	_, err = p.Add("api.stripe.com/v1/charges", noopHandler, WithScheme[HTTP]("https"), WithMethods[HTTP](http.MethodGet))
	require.NoError(t, err)
}

func countAuthorities(p *Proxy) int {
	n := 0
	for range p.Iter().Admissions() {
		n++
	}
	return n
}

func TestRouting_PortDiscriminatesTwoInterceptors(t *testing.T) {
	p := testProxy(t)

	api := p.MustAdd("localhost:8080/api", noopHandler, WithMethods[HTTP](http.MethodGet))
	ui := p.MustAdd("localhost:3000/api", noopHandler, WithMethods[HTTP](http.MethodGet))
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

	deleted, err := p.Delete[HTTP]("localhost:8080/api", WithMethods[HTTP](http.MethodGet))
	require.NoError(t, err)
	assert.Equal(t, api, deleted)
	assert.Equal(t, ui, match(t, p, http.MethodGet, "http", "localhost:3000", "/api"))
	assert.Equal(t, false, p.Admits(target("localhost:8080"), KindHTTP))
}

func TestRouting_PortOutranksTheRest(t *testing.T) {
	p := testProxy(t)

	beta, err := MatchHeader("X-Channel", "beta")
	require.NoError(t, err)

	// Registered least specific first, so only the ordering can put them back in order.
	any := p.MustAdd("localhost/api", noopHandler)
	header := p.MustAdd("localhost/api", noopHandler, WithRequestMatchers[HTTP](beta))
	get := p.MustAdd("localhost/api", noopHandler, WithMethods[HTTP](http.MethodGet))
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

func TestRouting_InterceptorMutationDuringTraffic(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin %s", r.URL.Path)
	}))
	defer origin.Close()

	p, authority, client := interceptingProxy(t, origin)

	var served atomic.Int64
	p.MustAdd(authority+"/stable", func(c *HTTPCtx) (*http.Response, error) {
		served.Add(1)
		return Text(http.StatusOK, "stable"), nil
	}, WithMethods[HTTP](http.MethodGet))

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// A writer churning the tree: interceptors come and go for the whole run.
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}

			pattern := fmt.Sprintf("%s/churn/%d", authority, i%16)
			ic, err := p.Add(pattern, func(c *HTTPCtx) (*http.Response, error) {
				return Text(http.StatusOK, "churn"), nil
			}, WithMethods[HTTP](http.MethodGet))
			if err != nil {
				continue
			}
			// The matchers identify an entry, methods included, so a delete names the same
			// ones the add did.
			if _, err := p.Delete[HTTP](ic.Pattern(), WithMethods[HTTP](http.MethodGet)); err != nil {
				t.Errorf("delete %s: %v", pattern, err)
				return
			}
		}
	})

	// Readers hammering an interceptor the writer never touches.
	const readers = 8
	for range readers {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}

				resp, err := client.Get(origin.URL + "/stable")
				if err != nil {
					t.Errorf("get: %v", err)
					return
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if string(body) != "stable" {
					t.Errorf("body = %q, want stable", body)
					return
				}
			}
		})
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	assert.Positive(t, served.Load(), "no request was served")
	assert.Equal(t, true, p.Admits(target(authority), KindHTTP), "the authority the stable interceptor implies must have survived the churn")
}

func TestRouting_AuthorityMutationDuringTraffic(t *testing.T) {
	p := testProxy(t)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			pattern := fmt.Sprintf("churn-%d.example.test", i%32)
			if _, err := p.Add[TCP](pattern, relayStream); err != nil {
				continue
			}
			if _, err := p.Delete[TCP](pattern); err != nil {
				t.Errorf("delete tunnel %s: %v", pattern, err)
				return
			}
		}
	})

	p.MustAdd("stable.example.test/*{any}", noopHandler)

	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if !p.Admits(target("stable.example.test:443"), KindHTTP) {
					t.Error("stable authority is not admitted")
					return
				}
				// Named by nothing, so it stays refused however the entry set churns.
				if p.Admits(target("other.example.test:443"), KindHTTP) {
					t.Error("unnamed authority is admitted")
					return
				}
			}
		})
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func benchProxy(b *testing.B, patterns ...string) *Proxy {
	b.Helper()
	ca, err := GenerateCA()
	if err != nil {
		b.Fatal(err)
	}
	p, err := New(WithCA(ca))
	if err != nil {
		b.Fatal(err)
	}
	for _, pattern := range patterns {
		if _, err := p.Add(pattern, noopHandler, WithMethods[HTTP](http.MethodGet)); err != nil {
			b.Fatalf("register %s: %v", pattern, err)
		}
	}
	return p
}

func BenchmarkLookup(b *testing.B) {
	cases := []struct {
		name    string
		pattern string
		host    string
		path    string
	}{
		{name: "static", pattern: "api.stripe.com/v1/charges", host: "api.stripe.com", path: "/v1/charges"},
		{name: "param", pattern: "api.stripe.com/v1/{id}/refunds", host: "api.stripe.com", path: "/v1/ch_1234567890/refunds"},
		{name: "wildcard path", pattern: "api.stripe.com/files/+{path}", host: "api.stripe.com", path: "/files/a/b/c/d"},
		{name: "wildcard host", pattern: "+{sub}.stripe.com/v1/charges", host: "eu.west.stripe.com", path: "/v1/charges"},
		{name: "any authority", pattern: "+{any}/v1/charges", host: "anything.example.test", path: "/v1/charges"},
		{name: "exact address", pattern: "10.1.2.3/v1/charges", host: "10.1.2.3", path: "/v1/charges"},
		{name: "range", pattern: "[10.0.0.0/8]/v1/charges", host: "10.1.2.3", path: "/v1/charges"},
		{name: "range v6", pattern: "[fd00::/8]/v1/charges", host: "fd12:3456::1", path: "/v1/charges"},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			p := benchProxy(b, tc.pattern)
			tree := p.getTree()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)

			c := tree.pool.Get().(*routeCtx)
			defer tree.pool.Put(c)
			c.reset(nil, req, "https", tc.host, "443")

			b.ReportAllocs()
			for b.Loop() {
				*c.params = (*c.params)[:0]
				if _, n := tree.lookup(tc.host, tc.path, c, false); n == nil {
					b.Fatal("no match")
				}
			}
		})
	}
}

func BenchmarkLookupDeepTree(b *testing.B) {
	patterns := []string{
		"api.stripe.com/v1/charges",
		"api.stripe.com/v1/charges/{id}",
		"api.stripe.com/v1/charges/{id}/capture",
		"api.stripe.com/v1/charges/{id}/refunds",
		"api.stripe.com/v1/customers",
		"api.stripe.com/v1/customers/{id}",
		"api.stripe.com/v1/customers/{id}/sources/{source}",
		"api.stripe.com/v1/payment_intents",
		"api.stripe.com/v1/payment_intents/{id}",
		"api.stripe.com/v1/subscriptions/{id}/items/{item}",
		"+{sub}.stripe.com/v1/files/+{path}",
		"files.stripe.com/v1/files/{id}",
		"connect.stripe.com/oauth/token",
		"api.internal.corp/health",
		"+{sub}.internal.corp/metrics",
	}
	p := benchProxy(b, patterns...)
	tree := p.getTree()

	const host = "api.stripe.com"
	const path = "/v1/subscriptions/sub_123/items/si_456"
	req := httptest.NewRequest(http.MethodGet, path, nil)

	c := tree.pool.Get().(*routeCtx)
	defer tree.pool.Put(c)
	c.reset(nil, req, "https", host, "443")

	b.ReportAllocs()
	for b.Loop() {
		*c.params = (*c.params)[:0]
		if _, n := tree.lookup(host, path, c, false); n == nil {
			b.Fatal("no match")
		}
	}
}

func BenchmarkLookupUnnarrowed(b *testing.B) {
	cases := []struct {
		name    string
		pattern string
		host    string
		path    string
	}{
		{name: "static", pattern: "api.stripe.com/v1/charges", host: "api.stripe.com", path: "/v1/charges"},
		{name: "param", pattern: "api.stripe.com/v1/{id}/refunds", host: "api.stripe.com", path: "/v1/ch_1234567890/refunds"},
		{name: "any authority", pattern: "+{any}/v1/charges", host: "anything.example.test", path: "/v1/charges"},
		{name: "range", pattern: "[10.0.0.0/8]/v1/charges", host: "10.1.2.3", path: "/v1/charges"},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			ca, err := GenerateCA()
			if err != nil {
				b.Fatal(err)
			}
			p, err := New(WithCA(ca))
			if err != nil {
				b.Fatal(err)
			}
			if _, err := p.Add(tc.pattern, noopHandler); err != nil {
				b.Fatalf("register %s: %v", tc.pattern, err)
			}

			tree := p.getTree()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)

			c := tree.pool.Get().(*routeCtx)
			defer tree.pool.Put(c)
			c.reset(nil, req, "https", tc.host, "443")

			b.ReportAllocs()
			for b.Loop() {
				if _, n := tree.lookup(tc.host, tc.path, c, false); n == nil {
					b.Fatal("no match")
				}
			}
		})
	}
}

func BenchmarkAddDelete(b *testing.B) {
	cases := []struct {
		name string
		base string
	}{
		{name: "fresh authority"},
		{name: "admitted authority", base: "api.stripe.com/v1/other"},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			var patterns []string
			if tc.base != "" {
				patterns = append(patterns, tc.base)
			}
			p := benchProxy(b, patterns...)

			b.ReportAllocs()
			for b.Loop() {
				if _, err := p.Add("api.stripe.com/v1/charges", noopHandler); err != nil {
					b.Fatal(err)
				}
				if _, err := p.Delete[HTTP]("api.stripe.com/v1/charges"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
