// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

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
		if _, err := p.AddInterceptor([]string{http.MethodGet}, pattern, noopHandler); err != nil {
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

			c := tree.pool.Get().(*Context)
			defer tree.pool.Put(c)
			c.reset(nil, req, "https", tc.host, "443")

			b.ReportAllocs()
			for b.Loop() {
				*c.params = (*c.params)[:0]
				if _, n := tree.lookup(http.MethodGet, tc.host, tc.path, c, false); n == nil {
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

	c := tree.pool.Get().(*Context)
	defer tree.pool.Put(c)
	c.reset(nil, req, "https", host, "443")

	b.ReportAllocs()
	for b.Loop() {
		*c.params = (*c.params)[:0]
		if _, n := tree.lookup(http.MethodGet, host, path, c, false); n == nil {
			b.Fatal("no match")
		}
	}
}

func BenchmarkActionFor(b *testing.B) {
	cases := []struct {
		name        string
		authorities []string
		host        string
	}{
		{name: "hit static", authorities: []string{"api.stripe.com"}, host: "api.stripe.com"},
		{name: "hit wildcard", authorities: []string{"+{sub}.stripe.com"}, host: "eu.west.stripe.com"},
		{name: "miss", authorities: []string{"api.stripe.com"}, host: "example.test"},
		{name: "hit address", authorities: []string{"10.1.2.3"}, host: "10.1.2.3"},
		{name: "hit range", authorities: []string{"[10.0.0.0/8]"}, host: "10.9.9.9"},
		{name: "miss address", authorities: []string{"[10.0.0.0/8]"}, host: "11.0.0.1"},
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
			for _, authority := range tc.authorities {
				if _, err := p.AddInterceptor(nil, authority+"/*{any}", noopHandler); err != nil {
					b.Fatalf("intercept %s: %v", authority, err)
				}
			}
			t := Target{Scheme: "https", Host: tc.host, Port: "443"}

			b.ReportAllocs()
			for b.Loop() {
				p.ActionFor(t)
			}
		})
	}
}

func BenchmarkLeafCached(b *testing.B) {
	ca, err := GenerateCA()
	if err != nil {
		b.Fatal(err)
	}
	if _, err := ca.Leaf("api.stripe.com"); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := ca.Leaf("api.stripe.com"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLeafMint(b *testing.B) {
	ca, err := GenerateCA()
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	i := 0
	for b.Loop() {
		i++
		// An authority never seen before, so every iteration signs a certificate rather
		// than reading one back out of the cache.
		if _, err := ca.Leaf("host-" + strconv.Itoa(i) + ".example.test"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStripHopByHop(b *testing.B) {
	// The common case: an ordinary request with nothing connection-scoped to remove, where
	// the header map is left untouched and can be reused across iterations.
	b.Run("nothing to strip", func(b *testing.B) {
		h := http.Header{
			"Accept":          {"*/*"},
			"User-Agent":      {"edge-bench"},
			"Accept-Encoding": {"gzip, deflate, br"},
			"Authorization":   {"Bearer token"},
		}
		b.ReportAllocs()
		for b.Loop() {
			stripHopByHop(h)
		}
	})

	// The case that does work. The clone is inside the loop because the strip is
	// destructive, so its cost is part of what is measured.
	b.Run("with hop by hop", func(b *testing.B) {
		base := http.Header{
			"Connection":       {"Keep-Alive, X-Custom"},
			"Proxy-Connection": {"keep-alive"},
			"Keep-Alive":       {"timeout=5"},
			"X-Custom":         {"value"},
			"Accept":           {"*/*"},
			"User-Agent":       {"edge-bench"},
		}
		b.ReportAllocs()
		for b.Loop() {
			stripHopByHop(base.Clone())
		}
	})
}

func BenchmarkRoutingPath(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/v1/charges/ch_123/refunds?limit=10", nil)

	b.ReportAllocs()
	for b.Loop() {
		if routingPath(req) == "" {
			b.Fatal("empty routing path")
		}
	}
}
