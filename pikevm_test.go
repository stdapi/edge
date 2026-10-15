// Copyright 2026 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPikeVM_Lookup(t *testing.T) {
	cases := []struct {
		name     string
		patterns []string
		failing  []string
		relaxed  bool
		host     string
		path     string
		want     string
		params   []string
	}{
		{
			name:     "infix match",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/y"},
			path:     "/a/x/B/x/c/y",
			want:     "/+{a}/x/+{b:[a-z/]+}/y",
			params:   []string{"a/x/B", "c"},
		},
		{
			name:     "param after infix",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/{p}/z"},
			path:     "/a/x/b/x/C/x/c/dd/z",
			want:     "/+{a}/x/+{b:[a-z/]+}/{p}/z",
			params:   []string{"a/x/b/x/C", "c", "dd"},
		},
		{
			name:     "suffix without regexp after infix",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/y/+{c}"},
			path:     "/a/x/B/x/c/y/d",
			want:     "/+{a}/x/+{b:[a-z/]+}/y/+{c}",
			params:   []string{"a/x/B", "c", "d"},
		},
		{
			name:     "suffix regexp sibling",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/y", "/+{a}/x/+{c:[a-z/]+}"},
			path:     "/a/x/B/x/c/d",
			want:     "/+{a}/x/+{c:[a-z/]+}",
			params:   []string{"a/x/B", "c/d"},
		},
		{
			name:     "empty optional catch-all",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/y/*{c}"},
			path:     "/a/x/B/x/c/y/",
			want:     "/+{a}/x/+{b:[a-z/]+}/y/*{c}",
			params:   []string{"a/x/B", "c", ""},
		},
		{
			name:     "slash candidate adding a slash to a static key",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/y/"},
			relaxed:  true,
			path:     "/a/x/B/x/c/y",
			want:     "/+{a}/x/+{b:[a-z/]+}/y/",
			params:   []string{"a/x/B", "c"},
		},
		{
			name:     "slash candidate adding a slash node",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/y/", "/+{a}/x/+{b:[a-z/]+}/yz"},
			relaxed:  true,
			path:     "/a/x/B/x/c/y",
			want:     "/+{a}/x/+{b:[a-z/]+}/y/",
			params:   []string{"a/x/B", "c"},
		},
		{
			name:     "slash candidate removing a slash node",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/y", "/+{a}/x/+{b:[a-z/]+}/y/z", "/+{a}/x/+{b:[a-z/]+}/y/w"},
			relaxed:  true,
			path:     "/a/x/B/x/c/y/",
			want:     "/+{a}/x/+{b:[a-z/]+}/y",
			params:   []string{"a/x/B", "c"},
		},
		{
			name:     "slash candidate removing a slash before the next wildcard",
			patterns: []string{"/+{a}/x+{b:[a-z/]+}/y", "/+{a}/x", "/+{a}/x+{c:[/a-z]+}"},
			relaxed:  true,
			path:     "/a/x/B/x/",
			want:     "/+{a}/x",
			params:   []string{"a/x/B"},
		},
		{
			name:     "suffix before a slash candidate removing a slash",
			patterns: []string{"/+{a}/x+{c:[/a-z]+}", "/+{a}/x", "/+{a}/x+{b:[a-z/]+}/y"},
			relaxed:  true,
			path:     "/a/x/B/x/",
			want:     "/+{a}/x+{c:[/a-z]+}",
			params:   []string{"a/x/B", "/"},
		},
		{
			name:     "infix slash candidate",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/", "/+{a}/x/+{c:[0-9/]+}"},
			relaxed:  true,
			path:     "/a/x/B/x/c",
			want:     "/+{a}/x/+{b:[a-z/]+}/",
			params:   []string{"a/x/B", "c"},
		},
		{
			name:     "suffix before an infix slash candidate",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/", "/+{a}/x/+{c:[a-z/]+}"},
			relaxed:  true,
			path:     "/a/x/B/x/c",
			want:     "/+{a}/x/+{c:[a-z/]+}",
			params:   []string{"a/x/B", "c"},
		},
		{
			name:     "walk resumes below the vm",
			patterns: []string{"/s/+{a}/x/+{b:[a-z/]+}/y", "/{p}/+{w}"},
			path:     "/s/a/x/B/x/c/Z",
			want:     "/{p}/+{w}",
			params:   []string{"s", "a/x/B/x/c/Z"},
		},
		{
			name:     "slash candidate in place of a param",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/y{p}", "/+{a}/x/+{b:[a-z/]+}/y"},
			relaxed:  true,
			path:     "/a/x/B/x/c/y/",
			want:     "/+{a}/x/+{b:[a-z/]+}/y",
			params:   []string{"a/x/B", "c"},
		},
		{
			name:     "slash candidate between wildcards",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/y+{c}/z", "/+{a}/x/+{b:[a-z/]+}/y+{d}/w", "/+{a}/x/+{b:[a-z/]+}/y"},
			relaxed:  true,
			path:     "/a/x/B/x/c/y/",
			want:     "/+{a}/x/+{b:[a-z/]+}/y",
			params:   []string{"a/x/B", "c"},
		},
		{
			name:     "non ascii path",
			patterns: []string{"/+{a}/x/+{b:[^/]+}/y"},
			path:     "/a/x/B/x/é\xff€/y",
			want:     "/+{a}/x/+{b:[^/]+}/y",
			params:   []string{"a/x/B", "é\xff€"},
		},
		{
			name:     "invalid utf8 in a regexp capture",
			patterns: []string{"/+{a}/x/+{b:[a-zé]+}/y", "/+{a}/x/{p}/y"},
			path:     "/a/x/B/x/é\xe9/y",
			want:     "/+{a}/x/{p}/y",
			params:   []string{"a/x/B", "é\xe9"},
		},
		{
			name:     "outermost infix with a regexp",
			patterns: []string{"/+{a:[a-zB/]+}/x/+{b:[a-z/]+}/y"},
			path:     "/a/x/B/x/c/y",
			want:     "/+{a:[a-zB/]+}/x/+{b:[a-z/]+}/y",
			params:   []string{"a/x/B", "c"},
		},
		{
			name:     "regexp suffix next to the outermost infix",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/y", "/+{s:[a-zB/]+}"},
			path:     "/a/x/B/x/c/z",
			want:     "/+{s:[a-zB/]+}",
			params:   []string{"a/x/B/x/c/z"},
		},
		{
			name:     "regexp with closures followed at each step",
			patterns: []string{"/+{a}/x/+{b:(?:[a-z€/]?){20}}/y"},
			path:     "/a/x/B/x/c€d/y",
			want:     "/+{a}/x/+{b:(?:[a-z€/]?){20}}/y",
			params:   []string{"a/x/B", "c€d"},
		},
		{
			name:     "no match",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/y", "/+{a}/x/{p}/z"},
			path:     "/a/x/B/x//z",
		},
		{
			name:     "infix without regexp with a slash candidate adding a slash",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/k/+{c}/y/"},
			relaxed:  true,
			path:     "/a/x/B/x/c/k/d/y",
			want:     "/+{a}/x/+{b:[a-z/]+}/k/+{c}/y/",
			params:   []string{"a/x/B", "c", "d"},
		},
		{
			name:     "infix without regexp started twice at a position",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/k/+{c}/y"},
			path:     "/a/x/B/x/c/k/k/d/y",
			want:     "/+{a}/x/+{b:[a-z/]+}/k/+{c}/y",
			params:   []string{"a/x/B", "c", "k/d"},
		},
		{
			name:     "regexp capture not matched at the end of the path",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+z}/y"},
			path:     "/a/x/B/x/c/d",
		},
		{
			name:     "empty segment on a param",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/y/{p}"},
			path:     "/a/x/B/x/c/y//",
		},
		{
			name:     "suffix with a failing matcher",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/y"},
			failing:  []string{"/+{a}/x/+{c:[a-z/]+}"},
			path:     "/a/x/B/x/c/d",
		},
		{
			name:     "slash candidate with a failing matcher",
			patterns: []string{"/+{a}/x/+{b:[a-z/]+}/y/z"},
			failing:  []string{"/+{a}/x/+{b:[a-z/]+}/y"},
			relaxed:  true,
			path:     "/a/x/B/x/c/y/",
		},
		{
			name:     "infix slash candidate with a failing matcher",
			patterns: []string{"/+{a}/x/+{c:[0-9/]+}"},
			failing:  []string{"/+{a}/x/+{b:[a-z/]+}/"},
			relaxed:  true,
			path:     "/a/x/B/x/c",
		},
		{
			name:     "entry with another port",
			patterns: []string{"a.test:8443/+{a}/x/+{b:[a-z/]+}/y", "/+{a}/x/+{b:[a-z/]+}/{p}"},
			path:     "/a/x/b/x/C/x/c/y",
			want:     "/+{a}/x/+{b:[a-z/]+}/{p}",
			params:   []string{"a/x/b/x/C", "c", "y"},
		},
		{
			name:     "address range",
			patterns: []string{"[10.0.0.0/8]/+{a}/x/+{b:[a-z/]+}/y"},
			host:     "10.1.2.3",
			path:     "/a/x/B/x/c/y",
			want:     "[10.0.0.0/8]/+{a}/x/+{b:[a-z/]+}/y",
			params:   []string{"a/x/B", "c"},
		},
		{
			name:     "address range near miss",
			patterns: []string{"[10.0.0.0/8]/+{a}/x/+{b:[a-z/]+}/y"},
			host:     "10.1.2.3",
			path:     "/a/x/B/x/c/Z",
		},
		{
			name:     "hostname regexp with closures followed at each step",
			patterns: []string{"+{a}.x.+{b:(?:[a-z.]?){18}}.com/"},
			host:     "a.x.b.x.c.9.x.b.c.com",
			path:     "/",
			want:     "+{a}.x.+{b:(?:[a-z.]?){18}}.com/",
			params:   []string{"a.x.b.x.c.9", "b.c"},
		},
		{
			name:     "hostname infix",
			patterns: []string{"+{a}.x.+{b:(?:[a-z]+\\.)*[a-z]+}.com/p"},
			host:     "A.X.b.X.c9.X.C.COM",
			path:     "/p",
			want:     "+{a}.x.+{b:(?:[a-z]+\\.)*[a-z]+}.com/p",
			params:   []string{"A.X.b.X.c9", "C"},
		},
		{
			name:     "hostname non ascii",
			patterns: []string{"+{a}.x.+{b:[a-zé.]+}.com/"},
			host:     "a.x.é.x.\xff.x.é.com",
			path:     "/",
			want:     "+{a}.x.+{b:[a-zé.]+}.com/",
			params:   []string{"a.x.é.x.\xff", "é"},
		},
		{
			name:     "hostname suffix with a path vm",
			patterns: []string{"+{a}.x.+{b:[a-z]+}/+{c}/x/+{d:[a-z/]+}/y"},
			host:     "a.x.9.x.b",
			path:     "/a/x/B/x/c/y",
			want:     "+{a}.x.+{b:[a-z]+}/+{c}/x/+{d:[a-z/]+}/y",
			params:   []string{"a.x.9", "b", "a/x/B", "c"},
		},
		{
			name:     "hostname path lookup fails",
			patterns: []string{"+{a}.x.+{b:[a-z]+}/foo", "/bar"},
			host:     "a.x.9.x.b",
			path:     "/bar",
			want:     "/bar",
			params:   []string{"a.x.9.x.b"},
		},
		{
			name:     "hostname path lookup matched again",
			patterns: []string{"+{a}.x.+{b:c|x\\.x\\.c\\.y}.y.+{s}/"},
			host:     "q.x.x.x.Z.x.x.x.c.y.y.w",
			path:     "/",
			want:     "+{a}.x.+{b:c|x\\.x\\.c\\.y}.y.+{s}/",
			params:   []string{"q.x.x.x.Z", "x.x.c.y", "w"},
		},
		{
			name:     "hostname param",
			patterns: []string{"+{a}.x.+{b:[a-z.]+}.{p}.com/"},
			host:     "a.x.b.x.9.x.c.dd.com",
			path:     "/",
			want:     "+{a}.x.+{b:[a-z.]+}.{p}.com/",
			params:   []string{"a.x.b.x.9", "c", "dd"},
		},
		{
			name:     "hostname suffix path lookup fails",
			patterns: []string{"+{a}.x.+{b:[a-z.]+}.k.+{s}/foo", "/bar"},
			host:     "a.x.b.x.c.k.d",
			path:     "/bar",
			want:     "/bar",
			params:   []string{"a.x.b.x.c.k.d"},
		},
		{
			name:     "hostname consumed before the path",
			patterns: []string{"+{a}.x.+{b:[a-z.]+}.comy/", "+{a}.x.+{b:[a-z.]+}.comz/", "/p"},
			host:     "a.x.b.x.c.com",
			path:     "/p",
			want:     "/p",
			params:   []string{"a.x.b.x.c.com"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Every pattern has a host. A path pattern goes on a.test, or on every host when the
			// request has one.
			place := func(pattern string) string {
				if tc.host != "" && strings.HasPrefix(pattern, "/") {
					return "+{any}" + pattern
				}
				return onHost(pattern)
			}
			p := testProxy(t, WithRegexpParam(true), WithRelaxedTrailingSlash[HTTP](tc.relaxed))
			for _, pattern := range tc.patterns {
				p.MustAdd(place(pattern), noopHandler)
			}
			for _, pattern := range tc.failing {
				p.MustAdd(place(pattern), noopHandler, WithRequestMatchers[HTTP](countingMatcher{calls: new(int)}))
			}
			for _, lazy := range []bool{false, true} {
				c, e := freshLookup(p, tc.host, tc.path, lazy, 0)
				if tc.want == "" {
					assert.Nil(t, e)
					continue
				}
				require.NotNil(t, e)
				assert.Equal(t, place(tc.want), e.pattern.str)
				if lazy {
					assert.Empty(t, *c.params)
				} else {
					assert.Equal(t, tc.params, *c.params)
				}
			}
		})
	}
}

func TestPikeVM_LookupRefinedKinds(t *testing.T) {
	const pattern = "a.test/+{a}/x/+{b:[a-z/]+}/y"
	p := testProxy(t, WithRegexpParam(true))
	p.MustAdd(pattern, noopHandler)
	p.MustAdd[WebSocket](pattern, func(*WebSocketCtx) error { return nil })
	p.MustAdd[GRPC](pattern, func(*GRPCCtx) error { return nil })

	cases := []struct {
		name   string
		header http.Header
		want   Kind
	}{
		{name: "http", header: http.Header{}, want: KindHTTP},
		{name: "websocket", header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}}, want: KindWebSocket},
		{name: "grpc", header: http.Header{"Content-Type": {"application/grpc"}}, want: KindGRPC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := p.getTree()
			for path, match := range map[string]bool{"/a/x/B/x/c/y": true, "/a/x/B/x/c/Z": false} {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.Header = tc.header
				c := tree.allocateContext()
				c.reset(nil, req, "https", "a.test", "443")
				idx, n := lookupTarget(tree.patterns, tree.addrs, "a.test", path, c, false, 0)
				assert.NotNil(t, c.lookup.pathPikeVM, path)
				if !match {
					assert.Nil(t, n, path)
					continue
				}
				require.NotNil(t, n, path)
				assert.Equal(t, tc.want, n.entries[idx].kind)
				assert.Equal(t, []string{"a/x/B", "c"}, *c.params)
			}
		})
	}
}

func TestPikeVM_LookupMatcher(t *testing.T) {
	var calls int
	p := testProxy(t, WithRegexpParam(true))
	p.MustAdd("a.test/+{a}/x/+{b:[a-z/]+}/y", noopHandler, WithRequestMatchers[HTTP](countingMatcher{calls: &calls}))
	p.MustAdd("a.test/+{a}/x/+{b:[a-z/]+}/{p}", noopHandler)
	c, e := freshLookup(p, "", "/a/x/b/x/C/x/c/y", false, 0)
	require.NotNil(t, e)
	assert.Equal(t, "a.test/+{a}/x/+{b:[a-z/]+}/{p}", e.pattern.str)
	assert.Equal(t, []string{"a/x/b/x/C", "c", "y"}, *c.params)
	assert.NotNil(t, c.lookup.pathPikeVM)
	assert.Positive(t, calls)
}

func TestPikeVM_LookupAfterACommit(t *testing.T) {
	p := testProxy(t, WithRegexpParam(true))
	p.MustAdd("a.test/+{a}/x/+{b:[a-z/]+}/y", noopHandler)
	_, e := freshLookup(p, "", "/a/x/B/x/c/z", false, 0)
	assert.Nil(t, e)

	require.NoError(t, p.Updates(func(txn *Txn) error {
		if _, err := txn.Add("a.test/+{a}/x/+{b:[a-z/]+}/w", noopHandler); err != nil {
			return err
		}
		_, err := txn.Add("a.test/+{a}/x/+{b:[a-z/]+}/z", noopHandler)
		return err
	}))

	_, e = freshLookup(p, "", "/a/x/B/x/c/z", false, 0)
	require.NotNil(t, e)
	assert.Equal(t, "a.test/+{a}/x/+{b:[a-z/]+}/z", e.pattern.str)
}

func TestPikeVM_LookupDuringWrites(t *testing.T) {
	p := testProxy(t, WithRegexpParam(true))
	path, host := "/+{a}/x/+{b:[a-z/]+}/", "+{h}.x.+{i:(?:[a-z]+\\.)*[a-z]+}.com"
	p.MustAdd("a.test"+path+"y", noopHandler)
	p.MustAdd(host+path+"y", noopHandler)
	p.MustAdd[TCP](host, noopStream)
	nearPath, nearHost, hitHost := strings.Repeat("/a/x", 50)+"/Z", strings.Repeat("a.x.", 10)+"org", "a.x.b.x.c.com"

	lookup := func(host, path string) *entry {
		tree := p.getTree()
		c := tree.pool.Get().(*routeCtx)
		defer tree.pool.Put(c)
		c.reset(nil, httptest.NewRequest(http.MethodGet, path, nil), "https", host, "443")
		return tree.route(c, false)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				for _, h := range []string{hitHost, "a.test"} {
					assert.Nil(t, lookup(h, nearPath))
					assert.NotNil(t, lookup(h, "/a/x/B/x/c/y"))
				}
				assert.Nil(t, lookup(nearHost, "/a/x/B/x/c/y"))
				assert.False(t, p.Admits(Target{Scheme: "https", Host: nearHost, Port: "443"}, KindTCP))
				assert.True(t, p.Admits(Target{Scheme: "https", Host: hitHost, Port: "443"}, KindTCP))
			}
		})
	}
	for g := range 2 {
		wg.Go(func() {
			for i := range 100 {
				leaf := fmt.Sprintf("w%d_%d", g, i)
				for _, pattern := range []string{"a.test" + path + leaf, host + path + leaf} {
					_, err := p.Add(pattern, noopHandler)
					assert.NoError(t, err)
				}
				if e := lookup(hitHost, "/a/x/B/x/c/"+leaf); assert.NotNil(t, e) {
					assert.Equal(t, host+path+leaf, e.pattern.str)
				}
				if i > 0 {
					prev := fmt.Sprintf("w%d_%d", g, i-1)
					for _, pattern := range []string{"a.test" + path + prev, host + path + prev} {
						_, err := p.Delete[HTTP](pattern)
						assert.NoError(t, err)
					}
				}
			}
		})
	}
	wg.Wait()
}
