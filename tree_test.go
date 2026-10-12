// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stdapi/edge/internal/iterutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type lookupCase struct {
	name     string
	patterns []string
	host     string
	path     string
	want     string
	relaxed  bool // the match exists only under RelaxedSlash
	params   []Param
}

func lookupOn(p *Proxy, host, path string, req *http.Request, lazy bool) (*entry, []Param) {
	tree := p.getTree()
	c := tree.pool.Get().(*routeCtx)
	defer tree.pool.Put(c)
	c.reset(nil, req, "https", host, "443")
	idx, n := tree.lookup(host, path, c, lazy)
	if n == nil {
		return nil, nil
	}
	c.entry = n.entries[idx]
	return c.entry, c.capturedParams()
}

func patternOf(e *entry) string {
	if e == nil {
		return ""
	}
	return e.pattern.str
}

func routingProxy(t *testing.T, slash TrailingSlashOption, patterns ...string) *Proxy {
	t.Helper()
	p := testProxy(t, WithRegexpParam(true), WithDefaultTrailingSlash(slash))
	for _, pattern := range patterns {
		_, err := p.Add(pattern, noopHandler)
		require.NoError(t, err)
	}
	return p
}

// runLookup checks every case under slash, and under RelaxedSlash checks that ExactSlash finds
// the same entry unless the case is relaxed. A lazy walk must find the same entry and capture nothing.
func runLookup(t *testing.T, slash TrailingSlashOption, cases []lookupCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := routingProxy(t, slash, tc.patterns...)
			e, params := lookupOn(p, tc.host, tc.path, httptest.NewRequest(http.MethodGet, "/", nil), false)
			assert.Equal(t, tc.want, patternOf(e))
			assert.Equal(t, tc.params, params)

			e, params = lookupOn(p, tc.host, tc.path, httptest.NewRequest(http.MethodGet, "/", nil), true)
			assert.Equal(t, tc.want, patternOf(e), "lazy")
			assert.Empty(t, params, "lazy")

			if slash == ExactSlash {
				return
			}
			p = routingProxy(t, ExactSlash, tc.patterns...)
			e, _ = lookupOn(p, tc.host, tc.path, httptest.NewRequest(http.MethodGet, "/", nil), false)
			if tc.relaxed {
				assert.NotEqual(t, tc.want, patternOf(e), "exact slash")
			} else {
				assert.Equal(t, tc.want, patternOf(e), "exact slash")
			}
		})
	}
}

func onPathHost(cases []lookupCase) []lookupCase {
	const host = "a.test"
	out := make([]lookupCase, len(cases))
	for i, tc := range cases {
		tc.host = host
		tc.patterns = make([]string, len(cases[i].patterns))
		for j, pattern := range cases[i].patterns {
			tc.patterns[j] = host + pattern
		}
		if tc.want != "" {
			tc.want = host + tc.want
		}
		out[i] = tc
	}
	return out
}

func TestRouting_Hostname(t *testing.T) {
	runLookup(t, RelaxedSlash, []lookupCase{
		{
			name:     "static hostname with complex overlapping pattern with static priority",
			patterns: []string{"example.com/foo/bar/baz/{$1}/jo", "example.com/foo/+{any}/baz/{$1}/jo", "example.com/foo/{ps}/baz/{$1}/jo"},
			host:     "example.com",
			path:     "/foo/bar/baz/1/jo",
			want:     "example.com/foo/bar/baz/{$1}/jo",
			params:   []Param{{Key: "$1", Value: "1"}},
		},
		{
			name:     "infix hostname wildcard with consecutive capturing single dot",
			patterns: []string{"a.+{any}.com/bar"},
			host:     "a...com",
			path:     "/bar",
			want:     "a.+{any}.com/bar",
			params:   []Param{{Key: "any", Value: "."}},
		},
		{
			name:     "suffix hostname wildcard with hostname ending with single dot",
			patterns: []string{"+{any}/bar"},
			host:     "a.com.",
			path:     "/bar",
			want:     "+{any}/bar",
			params:   []Param{{Key: "any", Value: "a.com"}},
		},
		{
			name:     "static hostname with complex overlapping pattern with static priority and regexp",
			patterns: []string{"example.com/foo/bar/baz/{$1:[0-9]}/jo", "example.com/foo/+{any:.*}/baz/{$1:.*}/jo", "example.com/foo/{ps:.*}/baz/{$1:.*}/jo"},
			host:     "example.com",
			path:     "/foo/bar/baz/1/jo",
			want:     "example.com/foo/bar/baz/{$1:[0-9]}/jo",
			params:   []Param{{Key: "$1", Value: "1"}},
		},
		{
			name:     "static hostname with complex overlapping pattern with param priority",
			patterns: []string{"example.com/foo/bar/baz/{$1}/jo", "example.com/foo/+{any}/baz/{$1}/jo", "example.com/foo/{ps}/baz/{$1}/jo"},
			host:     "example.com",
			path:     "/foo/bam/baz/1/jo",
			want:     "example.com/foo/{ps}/baz/{$1}/jo",
			params:   []Param{{Key: "ps", Value: "bam"}, {Key: "$1", Value: "1"}},
		},
		{
			name:     "static hostname with complex overlapping pattern with param priority and regexp",
			patterns: []string{"example.com/foo/bar/baz/{$1:[0-9]}/jo", "example.com/foo/+{any:.*}/baz/{$1:.*}/jo", "example.com/foo/{ps:.*}/baz/{$1:.*}/jo"},
			host:     "example.com",
			path:     "/foo/bam/baz/1/jo",
			want:     "example.com/foo/{ps:.*}/baz/{$1:.*}/jo",
			params:   []Param{{Key: "ps", Value: "bam"}, {Key: "$1", Value: "1"}},
		},
		{
			name:     "wildcard hostname with complex overlapping pattern with static priority",
			patterns: []string{"example.com/foo/bar/baz/{$1}/jo", "{any}.com/foo/+{any}/baz/{$1}/jo", "example.{tld}/foo/{ps}/baz/{$1}/jo"},
			host:     "example.com",
			path:     "/foo/bar/baz/1/jo",
			want:     "example.com/foo/bar/baz/{$1}/jo",
			params:   []Param{{Key: "$1", Value: "1"}},
		},
		{
			name:     "wildcard hostname with complex overlapping pattern with static priority and regexp",
			patterns: []string{"example.com/foo/bar/baz/{$1}/jo", "{any:.*}.com/foo/+{any}/baz/{$1}/jo", "example.{tld}/foo/{ps}/baz/{$1}/jo"},
			host:     "example.com",
			path:     "/foo/bar/baz/1/jo",
			want:     "example.com/foo/bar/baz/{$1}/jo",
			params:   []Param{{Key: "$1", Value: "1"}},
		},
		{
			name:     "wildcard hostname with complex overlapping pattern with static priority (case-insensitive)",
			patterns: []string{"example.com/foo/bar/baz/{$1}/jo", "{any}.com/foo/+{any}/baz/{$1}/jo", "example.{tld}/foo/{ps}/baz/{$1}/jo"},
			host:     "EXAMPLE.COM",
			path:     "/foo/bar/baz/1/jo",
			want:     "example.com/foo/bar/baz/{$1}/jo",
			params:   []Param{{Key: "$1", Value: "1"}},
		},
		{
			name:     "wildcard hostname with complex overlapping pattern with param priority",
			patterns: []string{"{sub}.com/foo/bar/baz/{$1}/jo", "example.{tld}/foo/+{any}/baz/{$1}/jo", "example.com/foo/{ps}/baz/{$1}/jo"},
			host:     "example.com",
			path:     "/foo/bam/baz/1/jo",
			want:     "example.com/foo/{ps}/baz/{$1}/jo",
			params:   []Param{{Key: "ps", Value: "bam"}, {Key: "$1", Value: "1"}},
		},
		{
			name:     "hostname not matching fallback to param",
			patterns: []string{"{a}/foo", "fooxyz/foo", "foobar/foo"},
			host:     "foo",
			path:     "/foo",
			want:     "{a}/foo",
			params:   []Param{{Key: "a", Value: "foo"}},
		},
		{
			name:     "hostname not matching fallback to param with regexp",
			patterns: []string{"{a:.*}/foo", "fooxyz/foo", "foobar/foo"},
			host:     "foo",
			path:     "/foo",
			want:     "{a:.*}/foo",
			params:   []Param{{Key: "a", Value: "foo"}},
		},
		{
			name:     "static priority in hostname with one param",
			patterns: []string{"{a}.{b}.{c}/foo", "{a}.{b}.c/foo", "{a}.b.c/foo"},
			host:     "foo.b.c",
			path:     "/foo",
			want:     "{a}.b.c/foo",
			params:   []Param{{Key: "a", Value: "foo"}},
		},
		{
			name:     "static priority in hostname with regexp",
			patterns: []string{"{a:foo}.{b}.{c}/foo", "{a:foo}.{b}.c/foo", "{a:foo}.b.c/foo"},
			host:     "foo.b.c",
			path:     "/foo",
			want:     "{a:foo}.b.c/foo",
			params:   []Param{{Key: "a", Value: "foo"}},
		},
		{
			name:     "static priority in hostname (case-insensitive)",
			patterns: []string{"{a}.{b}.{c}/foo", "{a}.{b}.c/foo", "{a}.b.c/foo"},
			host:     "FOO.B.C",
			path:     "/foo",
			want:     "{a}.b.c/foo",
			params:   []Param{{Key: "a", Value: "FOO"}},
		},
		{
			name:     "static priority in hostname (case-insensitive) with regexp",
			patterns: []string{"{a:[A-z]+}.{b}.{c}/foo", "{a:[A-z]+}.{b}.c/foo", "{a:[A-z]+}.b.c/foo"},
			host:     "FOO.B.C",
			path:     "/foo",
			want:     "{a:[A-z]+}.b.c/foo",
			params:   []Param{{Key: "a", Value: "FOO"}},
		},
		{
			name:     "regexp hostname params match all cases with static label priority",
			patterns: []string{"{a:[a-z]+}.b.c/foo", "{a:[A-Z]+}.{b:[A-Z]+}.{c:[A-Z]+}/foo", "{a:[A-Z]+}.{b:[a-z]+}.c/foo"},
			host:     "FOO.B.C",
			path:     "/foo",
			want:     "{a:[a-z]+}.b.c/foo",
			params:   []Param{{Key: "a", Value: "FOO"}},
		},
		{
			name:     "static priority in hostname with two params",
			patterns: []string{"{a}.{b}.{c}/foo", "{a}.{b}.c/foo", "{a}.b.c/foo"},
			host:     "foo.bar.c",
			path:     "/foo",
			want:     "{a}.{b}.c/foo",
			params:   []Param{{Key: "a", Value: "foo"}, {Key: "b", Value: "bar"}},
		},
		{
			name:     "static priority in hostname with three params",
			patterns: []string{"{a}.{b}.{c}/foo", "{a}.{b}.c/foo", "{a}.b.c/foo"},
			host:     "foo.bar.baz",
			path:     "/foo",
			want:     "{a}.{b}.{c}/foo",
			params:   []Param{{Key: "a", Value: "foo"}, {Key: "b", Value: "bar"}, {Key: "c", Value: "baz"}},
		},
		{
			name:     "fallback to any host",
			patterns: []string{"{a}.{b}.{c}/foo", "{a}.{b}.c/foo", "{a}.b.c/foo", "+{any}/foo/bar"},
			host:     "foo.bar.baz",
			path:     "/foo/bar",
			want:     "+{any}/foo/bar",
			params:   []Param{{Key: "any", Value: "foo.bar.baz"}},
		},
		{
			name:     "regexp priority",
			patterns: []string{"{a:.*}.{b}.{c}/foo", "{a:[A-z]+}.{b}.c/foo", "{a:a}.b.c/foo", "+{any}/foo/bar"},
			host:     "a.b.c",
			path:     "/foo",
			want:     "{a:.*}.{b}.{c}/foo",
			params:   []Param{{Key: "a", Value: "a"}, {Key: "b", Value: "b"}, {Key: "c", Value: "c"}},
		},
		{
			name:     "regexp priority but backtrack to most specific",
			patterns: []string{"{a:.*}.{b}.{c}/foo/x", "{a:[A-z]+}.{b}.c/foo", "{a:a}.b.c/foo", "+{any}/foo/bar"},
			host:     "a.b.c",
			path:     "/foo",
			want:     "{a:[A-z]+}.{b}.c/foo",
			params:   []Param{{Key: "a", Value: "a"}, {Key: "b", Value: "b"}},
		},
		{
			name:     "regexp priority with relaxed match",
			patterns: []string{"{a:.*}.{b}.{c}/foo", "{a:[a-z]+}.{b}.c/foo", "{a:a}.b.c/foo", "+{any}/foo/bar"},
			host:     "A.b.c",
			path:     "/foo/",
			want:     "{a:.*}.{b}.{c}/foo",
			relaxed:  true,
			params:   []Param{{Key: "a", Value: "A"}, {Key: "b", Value: "b"}, {Key: "c", Value: "c"}},
		},
		{
			name:     "regexp priority then next static",
			patterns: []string{"{a:.*}.{b}.{c}/foo", "{a:.*}.{b}.c/foo", "{a:.*}.b.c/foo", "+{any}/foo/bar"},
			host:     "a.b.c",
			path:     "/foo",
			want:     "{a:.*}.b.c/foo",
			params:   []Param{{Key: "a", Value: "a"}},
		},
		{
			name:     "regexp priority then param then next static",
			patterns: []string{"{a:.*}.{b}.{c}/foo", "{a:.*}.{b}.c/foo", "{a:.*}.b.c/foo", "+{any}/foo/bar"},
			host:     "a.x.c",
			path:     "/foo",
			want:     "{a:.*}.{b}.c/foo",
			params:   []Param{{Key: "a", Value: "a"}, {Key: "b", Value: "x"}},
		},
		{
			name:     "regexp priority with backtrack to most specific",
			patterns: []string{"{a:.*}.{b}.{c}/foo", "{a:[A-z]+}.{b}.c/foo", "{a:a}.b.c/{bar}", "+{any}/foo/bar"},
			host:     "a.b.c",
			path:     "/bar",
			want:     "{a:a}.b.c/{bar}",
			params:   []Param{{Key: "a", Value: "a"}, {Key: "bar", Value: "bar"}},
		},
		{
			name:     "regexp priority with backtrack to any host",
			patterns: []string{"{a:.*}.{b}.{c}/foo", "{a:[A-z]+}.{b}.c/foo", "{a:a}.b.c/{bar}", "+{any}/foo/bar"},
			host:     "a.b.c",
			path:     "/foo/bar",
			want:     "+{any}/foo/bar",
			params:   []Param{{Key: "any", Value: "a.b.c"}},
		},
		{
			name:     "fallback to any host (case-insensitive)",
			patterns: []string{"{a}.{b}.{c}/foo", "{a}.{b}.c/foo", "{a}.b.c/foo", "+{any}/foo/bar"},
			host:     "FOO.BAR.BAZ",
			path:     "/foo/bar",
			want:     "+{any}/foo/bar",
			params:   []Param{{Key: "any", Value: "FOO.BAR.BAZ"}},
		},
		{
			name:     "fallback to any host with param",
			patterns: []string{"{a}.{b}.{c}/{d}", "{a}.{b}.c/{d}", "{a}.b.c/{d}", "+{any}/{a}/bar"},
			host:     "foo.bar.baz",
			path:     "/foo/bar",
			want:     "+{any}/{a}/bar",
			params:   []Param{{Key: "any", Value: "foo.bar.baz"}, {Key: "a", Value: "foo"}},
		},
		{
			name:     "fallback to relaxed match with hostname priority",
			patterns: []string{"{a}.{b}.{c}/{d}", "{a}.{b}.c/{d}", "{a}.b.c/{path}/bar/", "+{any}/{a}/bar/"},
			host:     "foo.b.c",
			path:     "/john/bar",
			want:     "{a}.b.c/{path}/bar/",
			relaxed:  true,
			params:   []Param{{Key: "a", Value: "foo"}, {Key: "path", Value: "john"}},
		},
		{
			name:     "path priority with no hostname match",
			patterns: []string{"{a}.{b}.{c}/{d}", "{a}.{b}.c/{d}", "{a}.b.c/{path}/bar/x", "+{any}/{a}/bar"},
			host:     "foo.b.c",
			path:     "/john/bar",
			want:     "+{any}/{a}/bar",
			params:   []Param{{Key: "any", Value: "foo.b.c"}, {Key: "a", Value: "john"}},
		},
		{
			name:     "fallback to most specific hostname with path param and regexp",
			patterns: []string{"{a:.*}.{b:.*}.{c}/{d}", "{a:foo}.{b}.c/{d}", "{a:[A-z]+}.b.c/{path}/bar/", "+{any}/{a}/bar/"},
			host:     "foo.b.c",
			path:     "/john/bar",
			want:     "{a:[A-z]+}.b.c/{path}/bar/",
			relaxed:  true,
			params:   []Param{{Key: "a", Value: "foo"}, {Key: "path", Value: "john"}},
		},
		{
			name:     "fallback to most specific hostname with path param and regexp beside a shorter any host pattern",
			patterns: []string{"{a:.*}.{b:.*}.{c}/{d}", "{a:foo}.{b}.c/{d}", "{a:[A-z]+}.b.c/{path}/bar/", "+{any}/{a}/ba"},
			host:     "foo.b.c",
			path:     "/john/bar",
			want:     "{a:[A-z]+}.b.c/{path}/bar/",
			relaxed:  true,
			params:   []Param{{Key: "a", Value: "foo"}, {Key: "path", Value: "john"}},
		},
		{
			name:     "fallback to most specific path with path param and regexp",
			patterns: []string{"{a:.*}.{b:.*}.{c}/{d}", "{a:foo}.{b}.c/{d}", "{a:[A-z]+}.b.c/{path}/bar/x", "+{any}/{a}/bar"},
			host:     "foo.b.c",
			path:     "/john/bar",
			want:     "+{any}/{a}/bar",
			params:   []Param{{Key: "any", Value: "foo.b.c"}, {Key: "a", Value: "john"}},
		},
		{
			name:     "fallback to most specific hostname with path param and regexp beside a regexp any host pattern",
			patterns: []string{"{a:.*}.{b:.*}.{c}/{d}", "{a:foo}.{b}.c/{d}", "{a:[A-z]+}.b.c/{path}/bar/", "+{any}/{a:^$}/bar"},
			host:     "foo.b.c",
			path:     "/john/bar",
			want:     "{a:[A-z]+}.b.c/{path}/bar/",
			relaxed:  true,
			params:   []Param{{Key: "a", Value: "foo"}, {Key: "path", Value: "john"}},
		},
		{
			name:     "fallback to any host with param after regexp hostnames",
			patterns: []string{"{a:.*}.{b:.*}.{c}/{d}", "{a:foo}.{b}.c/{d}", "{a:[A-z]+}.b.c/{path}/bar/joh", "+{any}/{a}/bar"},
			host:     "foo.b.c",
			path:     "/john/bar",
			want:     "+{any}/{a}/bar",
			params:   []Param{{Key: "any", Value: "foo.b.c"}, {Key: "a", Value: "john"}},
		},
		{
			name:     "fallback to relaxed match with hostname priority (case-insensitive)",
			patterns: []string{"{a}.{b}.{c}/{d}", "{a}.{b}.c/{d}", "{a}.b.c/{path}/bar/", "+{any}/{a}/barr"},
			host:     "FOO.B.C",
			path:     "/john/bar",
			want:     "{a}.b.c/{path}/bar/",
			relaxed:  true,
			params:   []Param{{Key: "a", Value: "FOO"}, {Key: "path", Value: "john"}},
		},
		{
			name:     "simple hostname suffix wildcard",
			patterns: []string{"+{any}/bar"},
			host:     "foo.com",
			path:     "/bar",
			want:     "+{any}/bar",
			params:   []Param{{Key: "any", Value: "foo.com"}},
		},
		{
			name:     "simple hostname suffix wildcard with regexp",
			patterns: []string{"+{any:[A-Z.]+}/bar"},
			host:     "FOO.COM",
			path:     "/bar",
			want:     "+{any:[A-Z.]+}/bar",
			params:   []Param{{Key: "any", Value: "FOO.COM"}},
		},
		{
			name:     "simple prefix wildcard",
			patterns: []string{"+{any}.com/bar"},
			host:     "a.b.com",
			path:     "/bar",
			want:     "+{any}.com/bar",
			params:   []Param{{Key: "any", Value: "a.b"}},
		},
		{
			name:     "simple prefix wildcard overlap static",
			patterns: []string{"a.b.com/bar", "+{any}.com/bar"},
			host:     "a.b.com",
			path:     "/bar",
			want:     "a.b.com/bar",
		},
		{
			name:     "simple prefix wildcard overlap static with fallback",
			patterns: []string{"a.b.com/barr", "+{any}.com/bar"},
			host:     "a.b.com",
			path:     "/bar",
			want:     "+{any}.com/bar",
			params:   []Param{{Key: "any", Value: "a.b"}},
		},
		{
			name:     "simple prefix wildcard with regexp",
			patterns: []string{"+{any:[A-Z.]+}.com/bar"},
			host:     "A.B.com",
			path:     "/bar",
			want:     "+{any:[A-Z.]+}.com/bar",
			params:   []Param{{Key: "any", Value: "A.B"}},
		},
		{
			name:     "simple infix wildcard",
			patterns: []string{"example.+{any}.com/bar"},
			host:     "example.foo.bar.com",
			path:     "/bar",
			want:     "example.+{any}.com/bar",
			params:   []Param{{Key: "any", Value: "foo.bar"}},
		},
		{
			name:     "simple infix wildcard with regexp",
			patterns: []string{"example.+{any:[A-Z.]+}.com/bar"},
			host:     "example.FOO.BAR.com",
			path:     "/bar",
			want:     "example.+{any:[A-Z.]+}.com/bar",
			params:   []Param{{Key: "any", Value: "FOO.BAR"}},
		},
		{
			name:     "prefix wildcard with params",
			patterns: []string{"+{any}.{tld}/bar"},
			host:     "a.b.com",
			path:     "/bar",
			want:     "+{any}.{tld}/bar",
			params:   []Param{{Key: "any", Value: "a.b"}, {Key: "tld", Value: "com"}},
		},
		{
			name:     "infix wildcard with params",
			patterns: []string{"{first}.+{any}.{tld}/bar"},
			host:     "foo.s1.s2.s3.com",
			path:     "/bar",
			want:     "{first}.+{any}.{tld}/bar",
			params:   []Param{{Key: "first", Value: "foo"}, {Key: "any", Value: "s1.s2.s3"}, {Key: "tld", Value: "com"}},
		},
		{
			name:     "suffix wildcard with params",
			patterns: []string{"{first}.{second}.+{any}/bar"},
			host:     "first.second.third.com",
			path:     "/bar",
			want:     "{first}.{second}.+{any}/bar",
			params:   []Param{{Key: "first", Value: "first"}, {Key: "second", Value: "second"}, {Key: "any", Value: "third.com"}},
		},
		{
			name:     "priority to params",
			patterns: []string{"+{any}.b.com/bar", "{ps}.b.com/bar"},
			host:     "a.b.com",
			path:     "/bar",
			want:     "{ps}.b.com/bar",
			params:   []Param{{Key: "ps", Value: "a"}},
		},
		{
			name:     "fallback to catch-all with leading dot",
			patterns: []string{"+{any}/bar", "{ps}/bar"},
			host:     ".com",
			path:     "/bar",
			want:     "+{any}/bar",
			params:   []Param{{Key: "any", Value: ".com"}},
		},
		{
			name:     "eval param with wildcard fallback",
			patterns: []string{"+{any}.b.com/bar", "{ps}.b.com/bar"},
			host:     "foo.b.b.com",
			path:     "/bar",
			want:     "+{any}.b.com/bar",
			params:   []Param{{Key: "any", Value: "foo.b"}},
		},
		{
			name:     "priority to infix wildcard",
			patterns: []string{"a.+{any}.com/bar", "a.+{any}/bar"},
			host:     "a.bar.baz.com",
			path:     "/bar",
			want:     "a.+{any}.com/bar",
			params:   []Param{{Key: "any", Value: "bar.baz"}},
		},
		{
			name:     "eval infix with suffix fallback",
			patterns: []string{"a.+{any}.com/bar", "a.+{any}/bar"},
			host:     "a.bar.baz.ch",
			path:     "/bar",
			want:     "a.+{any}/bar",
			params:   []Param{{Key: "any", Value: "bar.baz.ch"}},
		},
		{
			name:     "priority to regexp wildcard",
			patterns: []string{"a.+{3}.com/bar", "a.+{1:[A-z.]+}.com/bar", "a.+{2:[0-9.]+}.com/bar"},
			host:     "a.b.c.com",
			path:     "/bar",
			want:     "a.+{1:[A-z.]+}.com/bar",
			params:   []Param{{Key: "1", Value: "b.c"}},
		},
		{
			name:     "priority to next regexp wildcard",
			patterns: []string{"a.+{3}.com/bar", "a.+{1:[A-z.]+}.com/bar", "a.+{2:[0-9.]+}.com/bar"},
			host:     "a.1.2.com",
			path:     "/bar",
			want:     "a.+{2:[0-9.]+}.com/bar",
			params:   []Param{{Key: "2", Value: "1.2"}},
		},
		{
			name:     "fallback to non-regexp infix wildcard",
			patterns: []string{"a.+{3}.com/bar", "a.+{1:[A-z.]+}.com/bar", "a.+{2:[0-9.]+}.com/bar"},
			host:     "a.b.2.com",
			path:     "/bar",
			want:     "a.+{3}.com/bar",
			params:   []Param{{Key: "3", Value: "b.2"}},
		},
		{
			name:     "fallback to relaxed match with hostname priority and prefix wildcard",
			patterns: []string{"+{a}.{b}.{c}/{d}", "+{a}.{b}.c/{d}", "+{a}.b.c/{path}/bar/", "+{any}/{a}/barr"},
			host:     "foo.b.c",
			path:     "/john/bar",
			want:     "+{a}.b.c/{path}/bar/",
			relaxed:  true,
			params:   []Param{{Key: "a", Value: "foo"}, {Key: "path", Value: "john"}},
		},
		{
			name:     "fallback to path priority with prefix wildcard",
			patterns: []string{"+{a}.{b}.{c}/{d}", "+{a}.{b}.c/{d}", "+{a}.b.c/{path}/bar/x", "+{any}/{path}/bar"},
			host:     "foo.b.c",
			path:     "/john/bar",
			want:     "+{any}/{path}/bar",
			params:   []Param{{Key: "any", Value: "foo.b.c"}, {Key: "path", Value: "john"}},
		},
		{
			name:     "fallback to most specific hostname with path param, wildcard and regexp",
			patterns: []string{"{a:.*}.{b:.*}.+{c:nomatch}/john/bar", "+{a:nomatch}.{b}.c/{d}", "+{a:[A-z]+}.b.c/{path}/bar/", "+{any}/{a:^$}/bar"},
			host:     "foo.b.c",
			path:     "/john/bar",
			want:     "+{a:[A-z]+}.b.c/{path}/bar/",
			relaxed:  true,
			params:   []Param{{Key: "a", Value: "foo"}, {Key: "path", Value: "john"}},
		},
		{
			name:     "fallback to most specific hostname with wildcard and regexp priority",
			patterns: []string{"{a:.*}.{b:.*}.+{c:nomatch}/john/bar", "+{a:foo}.{b}.c/{d}/bar", "+{a:[A-z]+}.b.c/{path}/bar/", "+{any}/{a:^$}/bar"},
			host:     "foo.b.c",
			path:     "/john/bar",
			want:     "+{a:foo}.{b}.c/{d}/bar",
			params:   []Param{{Key: "a", Value: "foo"}, {Key: "b", Value: "b"}, {Key: "d", Value: "john"}},
		},
		{
			name:     "direct to most specific with wildcard and regexp",
			patterns: []string{"{a:.*}.{b:.*}.+{c:.*}/john/bar", "+{a:foo}.{b}.c/{d}/bar", "+{a:[A-z]+}.b.c/{path}/bar/", "+{any}/{a:^$}/bar"},
			host:     "foo.b.c.com",
			path:     "/john/bar",
			want:     "{a:.*}.{b:.*}.+{c:.*}/john/bar",
			params:   []Param{{Key: "a", Value: "foo"}, {Key: "b", Value: "b"}, {Key: "c", Value: "c.com"}},
		},
		{
			name:     "fallback to plain param after regexp param subtree dead end",
			patterns: []string{"{p:[a-z]+}.x.example.com/", "{p}.y.example.com/"},
			host:     "abc.y.example.com",
			path:     "/",
			want:     "{p}.y.example.com/",
			params:   []Param{{Key: "p", Value: "abc"}},
		},
		{
			name:     "fallback to param hostname when static hostname path does not match",
			patterns: []string{"foo.example.com/y", "{p}.example.com/x"},
			host:     "foo.example.com",
			path:     "/x",
			want:     "{p}.example.com/x",
			params:   []Param{{Key: "p", Value: "foo"}},
		},
		{
			name:     "suffix hostname wildcard does not capture path bytes on path fallback",
			patterns: []string{"+{x}/foo"},
			host:     "zzz",
			path:     "/bar/foo",
		},
		{
			name:     "suffix hostname wildcard does not capture path bytes with empty host",
			patterns: []string{"+{x}/foo"},
			host:     "",
			path:     "/bar/foo",
		},
		{
			name:     "boundary hostname wildcard does not capture path bytes",
			patterns: []string{"example.com/p", "example.com+{y}/q"},
			host:     "example.com",
			path:     "/zzz/q",
		},
		{
			name:     "root hostname param does not capture asterisk form target",
			patterns: []string{"{tld}/"},
			host:     "zzz",
			path:     "*",
		},
		{
			name:     "path fallback to any host pattern with hostname wildcard sibling",
			patterns: []string{"+{x}/foo", "+{any}/bar"},
			host:     "zzz",
			path:     "/bar",
			want:     "+{any}/bar",
			params:   []Param{{Key: "any", Value: "zzz"}},
		},
		{
			name:     "boundary hostname static path with hostname wildcard sibling",
			patterns: []string{"example.com/p", "example.com+{y}/q"},
			host:     "example.com",
			path:     "/p",
			want:     "example.com/p",
		},
		{
			name:     "suffix hostname wildcard extending static hostname",
			patterns: []string{"example.com/p", "example.com+{y}/q"},
			host:     "example.comfoo",
			path:     "/q",
			want:     "example.com+{y}/q",
			params:   []Param{{Key: "y", Value: "foo"}},
		},
		{
			name:     "fallback to next suffix hostname wildcard when path subtree does not match",
			patterns: []string{"a.+{x:[b.]+}/foo", "a.+{y}/bar"},
			host:     "a.b.b",
			path:     "/bar",
			want:     "a.+{y}/bar",
			params:   []Param{{Key: "y", Value: "b.b"}},
		},
		{
			name:     "regexp suffix hostname wildcard priority when path subtree matches",
			patterns: []string{"a.+{x:[b.]+}/foo", "a.+{y}/foo"},
			host:     "a.b.b",
			path:     "/foo",
			want:     "a.+{x:[b.]+}/foo",
			params:   []Param{{Key: "x", Value: "b.b"}},
		},
		{
			name:     "regexp hostname param matches case-insensitively",
			patterns: []string{"{a:[a-z]+}.example.com/"},
			host:     "FOO.example.com",
			path:     "/",
			want:     "{a:[a-z]+}.example.com/",
			params:   []Param{{Key: "a", Value: "FOO"}},
		},
		{
			name:     "regexp hostname wildcard matches case-insensitively",
			patterns: []string{"+{sub:[a-z.]+}.example.com/"},
			host:     "A.B.example.com",
			path:     "/",
			want:     "+{sub:[a-z.]+}.example.com/",
			params:   []Param{{Key: "sub", Value: "A.B"}},
		},
		{
			name:     "no match when no suffix hostname wildcard path subtree matches",
			patterns: []string{"a.+{x:[b.]+}/foo", "a.+{y}/bar"},
			host:     "a.b.b",
			path:     "/nope",
		},
	})
}

func TestRouting_Overlapping(t *testing.T) {
	runLookup(t, ExactSlash, onPathHost([]lookupCase{
		{
			name:     "basic test most specific",
			patterns: []string{"/products/{id}", "/products/new"},
			path:     "/products/new",
			want:     "/products/new",
		},
		{
			name:     "basic test most specific with regexp param",
			patterns: []string{"/products/{id:[0-9]+}", "/products/new"},
			path:     "/products/new",
			want:     "/products/new",
		},
		{
			name:     "basic test less specific",
			patterns: []string{"/products/{id}", "/products/new"},
			path:     "/products/123",
			want:     "/products/{id}",
			params:   []Param{{Key: "id", Value: "123"}},
		},
		{
			name:     "basic test less specific with regexp priority",
			patterns: []string{"/products/{name}", "/products/{id:[0-9]+}", "/products/new"},
			path:     "/products/123",
			want:     "/products/{id:[0-9]+}",
			params:   []Param{{Key: "id", Value: "123"}},
		},
		{
			name:     "basic test less specific with regexp and less specific",
			patterns: []string{"/products/{name}", "/products/{id:[0-9]+}", "/products/new"},
			path:     "/products/abc",
			want:     "/products/{name}",
			params:   []Param{{Key: "name", Value: "abc"}},
		},
		{
			name:     "ieof+backtrack to {id} wildcard while deleting {a}",
			patterns: []string{"/{base}/val1/{id}", "/{base}/val1/123/{a}/bar", "/{base}/val1/{id}/new/{name}", "/{base}/val2"},
			path:     "/base/val1/123/new/barr",
			want:     "/{base}/val1/{id}/new/{name}",
			params:   []Param{{Key: "base", Value: "base"}, {Key: "id", Value: "123"}, {Key: "name", Value: "barr"}},
		},
		{
			name:     "backtrack to {id} wildcard while deleting {a} with regexp constraint",
			patterns: []string{"/{base}/val1/{id:[0-9]+}", "/{base}/val1/123/{a:[A-z]+}/{id:[0-9]+}", "/{base}/val1/{id:[0-9]+}/new/{name:[A-z]+}", "/{base}/val2"},
			path:     "/base/val1/123/new/barr",
			want:     "/{base}/val1/{id:[0-9]+}/new/{name:[A-z]+}",
			params:   []Param{{Key: "base", Value: "base"}, {Key: "id", Value: "123"}, {Key: "name", Value: "barr"}},
		},
		{
			name:     "kme+backtrack to {id} wildcard while deleting {a}",
			patterns: []string{"/{base}/val1/{id}", "/{base}/val1/123/{a}/bar", "/{base}/val1/{id}/new/{name}", "/{base}/val2"},
			path:     "/base/val1/123/new/ba",
			want:     "/{base}/val1/{id}/new/{name}",
			params:   []Param{{Key: "base", Value: "base"}, {Key: "id", Value: "123"}, {Key: "name", Value: "ba"}},
		},
		{
			name:     "kme+backtrack to {id} wildcard while deleting {a} with regexp constraint",
			patterns: []string{"/{base}/val1/{id:[0-9]+}", "/{base}/val1/123/{a:[A-z]+}/bar", "/{base}/val1/{id:[0-9]+}/new/{name:[A-z]+}", "/{base}/val2"},
			path:     "/base/val1/123/new/ba",
			want:     "/{base}/val1/{id:[0-9]+}/new/{name:[A-z]+}",
			params:   []Param{{Key: "base", Value: "base"}, {Key: "id", Value: "123"}, {Key: "name", Value: "ba"}},
		},
		{
			name:     "ime+backtrack to {id} wildcard while deleting {a}",
			patterns: []string{"/{base}/val1/{id}", "/{base}/val1/123/{a}/bar", "/{base}/val1/{id}/new/{name}", "/{base}/val2"},
			path:     "/base/val1/123/new/bx",
			want:     "/{base}/val1/{id}/new/{name}",
			params:   []Param{{Key: "base", Value: "base"}, {Key: "id", Value: "123"}, {Key: "name", Value: "bx"}},
		},
		{
			name:     "ime+backtrack to {id} wildcard while deleting {a} with regex constraint",
			patterns: []string{"/{base}/val1/{id:[0-9]+}", "/{base}/val1/123/{a:[A-z]+}/bar", "/{base}/val1/{id:[0-9]+}/new/{name:[A-z]+}", "/{base}/val2"},
			path:     "/base/val1/123/new/bx",
			want:     "/{base}/val1/{id:[0-9]+}/new/{name:[A-z]+}",
			params:   []Param{{Key: "base", Value: "base"}, {Key: "id", Value: "123"}, {Key: "name", Value: "bx"}},
		},
		{
			name:     "backtrack to catch while deleting {a}, {id} and {name}",
			patterns: []string{"/{base}/val1/{id}", "/{base}/val1/123/{a}/barr", "/{base}/val1/{id}/new/{name}/y", "/{base}/val+{all}"},
			path:     "/base/val1/123/new/bar/",
			want:     "/{base}/val+{all}",
			params:   []Param{{Key: "base", Value: "base"}, {Key: "all", Value: "1/123/new/bar/"}},
		},
		{
			name:     "backtrack to catch while deleting {a}, {id} and {name} with regexp constraint",
			patterns: []string{"/{base}/val1/{id:[0-9]+}", "/{base}/val1/123/{a:[A-z]+}/barr", "/{base}/val1/{id:[0-9]+}/new/{name:ba}", "/{base}/val+{all}"},
			path:     "/base/val1/123/new/bar/",
			want:     "/{base}/val+{all}",
			params:   []Param{{Key: "base", Value: "base"}, {Key: "all", Value: "1/123/new/bar/"}},
		},
		{
			name:     "notleaf+backtrack to catch while deleting {a}, {id}",
			patterns: []string{"/{base}/val1/123/{a}/baz", "/{base}/val1/123/{a}/bar", "/{base}/val1/{id}/new/{name}", "/{base}/val+{all}"},
			path:     "/base/val1/123/new",
			want:     "/{base}/val+{all}",
			params:   []Param{{Key: "base", Value: "base"}, {Key: "all", Value: "1/123/new"}},
		},
		{
			name:     "multi node most specific",
			patterns: []string{"/foo/{ab}", "/foo/{ab}/{bc}", "/foo/{ab}/{bc}/{de}", "/foo/{ab}/{bc}/{de}/bar", "/foo/{ab}/{bc}/{de}/{fg}"},
			path:     "/foo/1/2/3/bar",
			want:     "/foo/{ab}/{bc}/{de}/bar",
			params:   []Param{{Key: "ab", Value: "1"}, {Key: "bc", Value: "2"}, {Key: "de", Value: "3"}},
		},
		{
			name:     "multi node most specific with regexp",
			patterns: []string{"/foo/{ab:[0-9]+}", "/foo/{ab:[0-9]}/{bc:[0-9]+}", "/foo/{ab:.*}/{bc:[0-9]}/{de:[0-9]+}", "/foo/{ab:1}/{bc:2}/{de:3}/bar", "/foo/{ab}/{bc}/{de}/{fg}"},
			path:     "/foo/1/2/3/bar",
			want:     "/foo/{ab:1}/{bc:2}/{de:3}/bar",
			params:   []Param{{Key: "ab", Value: "1"}, {Key: "bc", Value: "2"}, {Key: "de", Value: "3"}},
		},
		{
			name:     "multi node most specific with multi name",
			patterns: []string{"/foo/{aa}", "/foo/{bb}/{cc}", "/foo/{dd}/{ee}/{ff}", "/foo/{gg}/{hh}/{ii}/bar", "/foo/{jj}/{kk}/{ll}/{mm}"},
			path:     "/foo/1/2/3/bar",
			want:     "/foo/{gg}/{hh}/{ii}/bar",
			params:   []Param{{Key: "gg", Value: "1"}, {Key: "hh", Value: "2"}, {Key: "ii", Value: "3"}},
		},
		{
			name:     "multi node most specific with regexp and multi name",
			patterns: []string{"/foo/{aa:[0-9]+}", "/foo/{bb:[0-9]}/{cc:[0-9]+}", "/foo/{dd:.*}/{ee:[0-9]}/{ff:[0-9]+}", "/foo/{gg:1}/{hh:2}/{ii:3}/bar", "/foo/{jj}/{kk}/{ll}/{mm}"},
			path:     "/foo/1/2/3/bar",
			want:     "/foo/{gg:1}/{hh:2}/{ii:3}/bar",
			params:   []Param{{Key: "gg", Value: "1"}, {Key: "hh", Value: "2"}, {Key: "ii", Value: "3"}},
		},
		{
			name:     "multi node less specific",
			patterns: []string{"/foo/{ab}", "/foo/{ab}/{bc}", "/foo/{ab}/{bc}/{de}", "/foo/{ab}/{bc}/{de}/bar", "/foo/{ab}/{bc}/{de}/{fg}"},
			path:     "/foo/1/2/3/john",
			want:     "/foo/{ab}/{bc}/{de}/{fg}",
			params:   []Param{{Key: "ab", Value: "1"}, {Key: "bc", Value: "2"}, {Key: "de", Value: "3"}, {Key: "fg", Value: "john"}},
		},
		{
			name:     "multi node less specific with regexp",
			patterns: []string{"/foo/{ab:[0-9]+}", "/foo/{ab:[0-9]}/{bc:[0-9]+}", "/foo/{ab:.*}/{bc:[0-9]}/{de:[0-9]+}", "/foo/{ab:1}/{bc:2}/{de:3}/bar", "/foo/{ab}/{bc}/{de}/{fg}"},
			path:     "/foo/1/2/3/john",
			want:     "/foo/{ab}/{bc}/{de}/{fg}",
			params:   []Param{{Key: "ab", Value: "1"}, {Key: "bc", Value: "2"}, {Key: "de", Value: "3"}, {Key: "fg", Value: "john"}},
		},
		{
			name:     "multi node less specific with multi name",
			patterns: []string{"/foo/{aa}", "/foo/{bb}/{cc}", "/foo/{dd}/{ee}/{ff}", "/foo/{gg}/{hh}/{ii}/bar", "/foo/{jj}/{kk}/{ll}/{mm}"},
			path:     "/foo/1/2/3/john",
			want:     "/foo/{jj}/{kk}/{ll}/{mm}",
			params:   []Param{{Key: "jj", Value: "1"}, {Key: "kk", Value: "2"}, {Key: "ll", Value: "3"}, {Key: "mm", Value: "john"}},
		},
		{
			name:     "backtrack on empty mid key parameter",
			patterns: []string{"/foo/abc{id}/bar", "/foo/{name}/bar"},
			path:     "/foo/abc/bar",
			want:     "/foo/{name}/bar",
			params:   []Param{{Key: "name", Value: "abc"}},
		},
		{
			name:     "backtrack on empty mid key parameter with regexp",
			patterns: []string{"/foo/abc{id:.*}/bar", "/foo/{name:.*}/bar"},
			path:     "/foo/abc/bar",
			want:     "/foo/{name:.*}/bar",
			params:   []Param{{Key: "name", Value: "abc"}},
		},
		{
			name:     "most specific param between catch all",
			patterns: []string{"/foo/{id}", "/foo/a+{args}", "/foo+{args}"},
			path:     "/foo/123",
			want:     "/foo/{id}",
			params:   []Param{{Key: "id", Value: "123"}},
		},
		{
			name:     "most specific param between catch all with regexp",
			patterns: []string{"/foo/{id:.*}", "/foo/a+{args:.*}", "/foo+{args:.*}"},
			path:     "/foo/123",
			want:     "/foo/{id:.*}",
			params:   []Param{{Key: "id", Value: "123"}},
		},
		{
			name:     "most specific catch all with param",
			patterns: []string{"/foo/{id}", "/foo/a+{args}", "/foo+{args}"},
			path:     "/foo/abc",
			want:     "/foo/a+{args}",
			params:   []Param{{Key: "args", Value: "bc"}},
		},
		{
			name:     "most specific catch all with param and regexp",
			patterns: []string{"/foo/{id:.*}", "/foo/a+{args:.*}", "/foo+{args:.*}"},
			path:     "/foo/abc",
			want:     "/foo/a+{args:.*}",
			params:   []Param{{Key: "args", Value: "bc"}},
		},
		{
			name:     "param priority over catch-all",
			patterns: []string{"/foo/{id}", "/foo/+{args}"},
			path:     "/foo/abc",
			want:     "/foo/{id}",
			params:   []Param{{Key: "id", Value: "abc"}},
		},
		{
			name:     "static priority over param and catch-all",
			patterns: []string{"/foo/abc", "/foo/{id}", "/foo/+{args}"},
			path:     "/foo/abc",
			want:     "/foo/abc",
		},
		{
			name:     "no match static with param fallback",
			patterns: []string{"/foo/abc", "/foo/{id}", "/foo/+{args}"},
			path:     "/foo/abd",
			want:     "/foo/{id}",
			params:   []Param{{Key: "id", Value: "abd"}},
		},
		{
			name:     "no match static with catch all fallback",
			patterns: []string{"/foo/abc", "/foo/{id}", "/foo/+{args}"},
			path:     "/foo/abc/foo",
			want:     "/foo/+{args}",
			params:   []Param{{Key: "args", Value: "abc/foo"}},
		},
		{
			name:     "most specific catch all with static",
			patterns: []string{"/foo/{id}/abc", "/foo/{id}/+{args}", "/foo/+{args}"},
			path:     "/foo/bar/abd",
			want:     "/foo/{id}/+{args}",
			params:   []Param{{Key: "id", Value: "bar"}, {Key: "args", Value: "abd"}},
		},
		{
			name:     "most specific catch all with static and param",
			patterns: []string{"/foo/{id_1}/abc", "/foo/{id_1}/{id_2}", "/foo/{id_1}/+{args}", "/foo/+{args}"},
			path:     "/foo/bar/abc/def",
			want:     "/foo/{id_1}/+{args}",
			params:   []Param{{Key: "id_1", Value: "bar"}, {Key: "args", Value: "abc/def"}},
		},
		{
			name:     "backtrack to most specific param with 2 skipped catch all",
			patterns: []string{"/foo/{id_1}/abc", "/foo/{id_1}/+{args}", "/foo/{id_1}/{id_2}", "/foo/+{args}"},
			path:     "/foo/bar/def",
			want:     "/foo/{id_1}/{id_2}",
			params:   []Param{{Key: "id_1", Value: "bar"}, {Key: "id_2", Value: "def"}},
		},
		{
			name:     "backtrack to most specific catch-all with an exact match",
			patterns: []string{"/foo/{id_1}/abc", "/foo/{id_1}/+{args}", "/foo/{id_1}/{id_2}", "/foo/+{args}"},
			path:     "/foo/bar/x/y/z",
			want:     "/foo/{id_1}/+{args}",
			params:   []Param{{Key: "id_1", Value: "bar"}, {Key: "args", Value: "x/y/z"}},
		},
		{
			name:     "backtrack to the first catch-all on a trailing slash",
			patterns: []string{"/foo/{id_1}/abc", "/foo/{id_1}/+{args}", "/foo/{id_1}/{id_2}", "/foo/+{args}"},
			path:     "/foo/bar/",
			want:     "/foo/+{args}",
			params:   []Param{{Key: "args", Value: "bar/"}},
		},
		{
			name:     "param at index 1 with 2 nodes",
			patterns: []string{"/foo/{bar}", "/foo/[bar]"},
			path:     "/foo/[barr]",
			want:     "/foo/{bar}",
			params:   []Param{{Key: "bar", Value: "[barr]"}},
		},
		{
			name:     "param at index 1 with 3 nodes",
			patterns: []string{"/foo/{bar}", "/foo/[bar]", "/foo/]bar]"},
			path:     "/foo/]barr]",
			want:     "/foo/{bar}",
			params:   []Param{{Key: "bar", Value: "]barr]"}},
		},
		{
			name:     "param at index 0 with 3 nodes",
			patterns: []string{"/foo/{bar}", "/foo/~bar~", "/foo/]bar]"},
			path:     "/foo/~barr~",
			want:     "/foo/{bar}",
			params:   []Param{{Key: "bar", Value: "~barr~"}},
		},
		{
			name:     "regexp param priority in register order",
			patterns: []string{"/foo/{fallback}", "/foo/{a:[0-9]+}", "/foo/{b:[0-9-A-z]+}", "/foo/{c:[0-9-A-Z]+}"},
			path:     "/foo/123",
			want:     "/foo/{a:[0-9]+}",
			params:   []Param{{Key: "a", Value: "123"}},
		},
		{
			name:     "regexp param priority in register order, with last match",
			patterns: []string{"/foo/{fallback}", "/foo/{a:[0-9]+}", "/foo/{b:[0-9-A-Z]+}", "/foo/{c:[0-9-A-z]+}"},
			path:     "/foo/abc",
			want:     "/foo/{c:[0-9-A-z]+}",
			params:   []Param{{Key: "c", Value: "abc"}},
		},
		{
			name:     "regexp param priority with fallback",
			patterns: []string{"/foo/{fallback}", "/foo/{a:[0-9]+}", "/foo/{b:[0-9-A-Z]+}", "/foo/{c:[0-9-A-z]+}"},
			path:     "/foo/*",
			want:     "/foo/{fallback}",
			params:   []Param{{Key: "fallback", Value: "*"}},
		},
		{
			name:     "regexp wildcard priority in register order",
			patterns: []string{"/foo/+{fallback}", "/foo/+{a:[0-9]+}", "/foo/+{b:[0-9-A-z]+}", "/foo/+{c:[0-9-A-Z]+}"},
			path:     "/foo/123",
			want:     "/foo/+{a:[0-9]+}",
			params:   []Param{{Key: "a", Value: "123"}},
		},
		{
			name:     "regexp wildcard priority in register order, with last match",
			patterns: []string{"/foo/+{fallback}", "/foo/+{a:[0-9]+}", "/foo/+{b:[0-9-A-Z]+}", "/foo/+{c:[0-9-A-z]+}"},
			path:     "/foo/abc",
			want:     "/foo/+{c:[0-9-A-z]+}",
			params:   []Param{{Key: "c", Value: "abc"}},
		},
		{
			name:     "regexp wildcard priority with fallback",
			patterns: []string{"/foo/+{fallback}", "/foo/+{a:[0-9]+}", "/foo/+{b:[0-9-A-Z]+}", "/foo/+{c:[0-9-A-z]+}"},
			path:     "/foo/*",
			want:     "/foo/+{fallback}",
			params:   []Param{{Key: "fallback", Value: "*"}},
		},
		{
			name:     "regexp infix wildcard priority with fallback",
			patterns: []string{"/foo/+{fallback}/bar", "/foo/+{a:[0-9]+}/bar", "/foo/+{b:[0-9-A-Z]+}/bar", "/foo/+{c:[0-9-A-z]+}/bar"},
			path:     "/foo/a/b/c/bar",
			want:     "/foo/+{fallback}/bar",
			params:   []Param{{Key: "fallback", Value: "a/b/c"}},
		},
		{
			name:     "mixing all together 1",
			patterns: []string{"/foo/+{fallback}/bar/+{ab:[0-9]+}", "/foo/+{a:.*}/bar/{b:[A-z]+}", "/foo/+{b}/bar/{foo}", "/foo/+{c:[0-9/]+}/bar/foo"},
			path:     "/foo/1/2/3/bar/foo",
			want:     "/foo/+{a:.*}/bar/{b:[A-z]+}",
			params:   []Param{{Key: "a", Value: "1/2/3"}, {Key: "b", Value: "foo"}},
		},
		{
			name:     "mixing all together 2",
			patterns: []string{"/foo/+{fallback}/bar/+{ab:[0-9]+}", "/foo/+{a:.*}/bar/{b:[A-z]+}", "/foo/+{b}/bar/{foo}", "/foo/+{c:[0-9/]+}/bar/foo"},
			path:     "/foo/1/2/3/bar/foo123",
			want:     "/foo/+{b}/bar/{foo}",
			params:   []Param{{Key: "b", Value: "1/2/3"}, {Key: "foo", Value: "foo123"}},
		},
		{
			name:     "mixing all together 4",
			patterns: []string{"/foo/+{fallback}/bar/+{ab:[A-z0-9/]+}", "/foo/+{a:.*}/bar/{b:[A-z]+}", "/foo/+{b}/bar/{foo}", "/foo/+{c:[0-9/]+}/bar/foo"},
			path:     "/foo/1/2/3/bar/foo/1/2/3",
			want:     "/foo/+{fallback}/bar/+{ab:[A-z0-9/]+}",
			params:   []Param{{Key: "fallback", Value: "1/2/3"}, {Key: "ab", Value: "foo/1/2/3"}},
		},
		{
			name:     "exhausting infix with suffix fallback at first position",
			patterns: []string{"/+{args:.*}", "/+{a:a}/b/c", "/+{b:b}/b/c"},
			path:     "/aa/b/c",
			want:     "/+{args:.*}",
			params:   []Param{{Key: "args", Value: "aa/b/c"}},
		},
		{
			name:     "exhausting infix with suffix fallback at last position",
			patterns: []string{"/+{a:a}/b/c", "/+{b:b}/b/c", "/+{args}"},
			path:     "/aa/b/c",
			want:     "/+{args}",
			params:   []Param{{Key: "args", Value: "aa/b/c"}},
		},
		{
			name:     "suffix regex catch-all capture includes the trailing slash",
			patterns: []string{"/+{w:[a-z/]+}"},
			path:     "/abc/",
			want:     "/+{w:[a-z/]+}",
			params:   []Param{{Key: "w", Value: "abc/"}},
		},
	}))
}

func TestRouting_InfixWildcard(t *testing.T) {
	runLookup(t, ExactSlash, onPathHost([]lookupCase{
		{
			name:     "simple infix wildcard",
			patterns: []string{"/foo/+{args}/bar"},
			path:     "/foo/a/bar",
			want:     "/foo/+{args}/bar",
			params:   []Param{{Key: "args", Value: "a"}},
		},
		{
			name:     "simple infix wildcard with regexp",
			patterns: []string{"/foo/+{args:a}/bar"},
			path:     "/foo/a/bar",
			want:     "/foo/+{args:a}/bar",
			params:   []Param{{Key: "args", Value: "a"}},
		},
		{
			name:     "simple infix wildcard capture slash",
			patterns: []string{"/foo/+{args}/bar"},
			path:     "/foo///bar",
			want:     "/foo/+{args}/bar",
			params:   []Param{{Key: "args", Value: "/"}},
		},
		{
			name:     "simple infix wildcard capture slash with regexp",
			patterns: []string{"/foo/+{args:/}/bar"},
			path:     "/foo///bar",
			want:     "/foo/+{args:/}/bar",
			params:   []Param{{Key: "args", Value: "/"}},
		},
		{
			name:     "simple infix wildcard capture anything not empty",
			patterns: []string{"/foo/+{args}/bar"},
			path:     "/foo//a//bar",
			want:     "/foo/+{args}/bar",
			params:   []Param{{Key: "args", Value: "/a/"}},
		},
		{
			name:     "simple infix wildcard capture anything not empty with regexp",
			patterns: []string{"/foo/+{args:/a/}/bar"},
			path:     "/foo//a//bar",
			want:     "/foo/+{args:/a/}/bar",
			params:   []Param{{Key: "args", Value: "/a/"}},
		},
		{
			name:     "static with infix wildcard child",
			patterns: []string{"/foo/", "/foo/+{args}/baz"},
			path:     "/foo/bar/baz",
			want:     "/foo/+{args}/baz",
			params:   []Param{{Key: "args", Value: "bar"}},
		},
		{
			name:     "static with infix wildcard regexp child",
			patterns: []string{"/foo/", "/foo/+{args:[A-z]+}/baz"},
			path:     "/foo/bar/baz",
			want:     "/foo/+{args:[A-z]+}/baz",
			params:   []Param{{Key: "args", Value: "bar"}},
		},
		{
			name:     "static with 2 infix wildcard and regexp child",
			patterns: []string{"/foo/", "/foo/+{args}/baz", "/foo/+{args:[A-z]+}/baz"},
			path:     "/foo/bar/baz",
			want:     "/foo/+{args:[A-z]+}/baz",
			params:   []Param{{Key: "args", Value: "bar"}},
		},
		{
			name:     "static with infix wildcard child capture slash",
			patterns: []string{"/foo/", "/foo/+{args}/baz"},
			path:     "/foo///baz",
			want:     "/foo/+{args}/baz",
			params:   []Param{{Key: "args", Value: "/"}},
		},
		{
			name:     "static with infix wildcard regexp child capture slash after fallback",
			patterns: []string{"/foo/", "/foo/+{args}/baz", "/foo/+{args:a}/baz"},
			path:     "/foo///baz",
			want:     "/foo/+{args}/baz",
			params:   []Param{{Key: "args", Value: "/"}},
		},
		{
			name:     "simple infix wildcard with pattern character",
			patterns: []string{"/foo/+{args}/bar"},
			path:     "/foo/+{args}/bar",
			want:     "/foo/+{args}/bar",
			params:   []Param{{Key: "args", Value: "+{args}"}},
		},
		{
			name:     "simple infix wildcard regexp with pattern character",
			patterns: []string{"/foo/+{args:.*}/bar"},
			path:     "/foo/+{args:.*}/bar",
			want:     "/foo/+{args:.*}/bar",
			params:   []Param{{Key: "args", Value: "+{args:.*}"}},
		},
		{
			name:     "simple infix wildcard with multi segment and pattern character",
			patterns: []string{"/foo/+{args}/bar"},
			path:     "/foo/+{args}/b/c/bar",
			want:     "/foo/+{args}/bar",
			params:   []Param{{Key: "args", Value: "+{args}/b/c"}},
		},
		{
			name:     "simple infix wildcard regexp with multi segment and pattern character",
			patterns: []string{"/foo/+{args:.*}/bar"},
			path:     "/foo/+{args:.*}/b/c/bar",
			want:     "/foo/+{args:.*}/bar",
			params:   []Param{{Key: "args", Value: "+{args:.*}/b/c"}},
		},
		{
			name:     "simple infix inflight wildcard",
			patterns: []string{"/foo/z+{args}/bar"},
			path:     "/foo/za/bar",
			want:     "/foo/z+{args}/bar",
			params:   []Param{{Key: "args", Value: "a"}},
		},
		{
			name:     "simple infix regexp inflight wildcard",
			patterns: []string{"/foo/z+{args:a}/bar"},
			path:     "/foo/za/bar",
			want:     "/foo/z+{args:a}/bar",
			params:   []Param{{Key: "args", Value: "a"}},
		},
		{
			name:     "simple infix inflight wildcard capture slash",
			patterns: []string{"/foo/z+{args}/bar"},
			path:     "/foo/z//bar",
			want:     "/foo/z+{args}/bar",
			params:   []Param{{Key: "args", Value: "/"}},
		},
		{
			name:     "simple infix regexp inflight wildcard capture slash",
			patterns: []string{"/foo/z+{args:/}/bar"},
			path:     "/foo/z//bar",
			want:     "/foo/z+{args:/}/bar",
			params:   []Param{{Key: "args", Value: "/"}},
		},
		{
			name:     "simple infix inflight wildcard with pattern character",
			patterns: []string{"/foo/z+{args}/bar"},
			path:     "/foo/z+{args}/bar",
			want:     "/foo/z+{args}/bar",
			params:   []Param{{Key: "args", Value: "+{args}"}},
		},
		{
			name:     "simple infix regexp inflight wildcard with pattern character",
			patterns: []string{"/foo/z+{args:.*}/bar"},
			path:     "/foo/z+{args:.*}/bar",
			want:     "/foo/z+{args:.*}/bar",
			params:   []Param{{Key: "args", Value: "+{args:.*}"}},
		},
		{
			name:     "simple infix inflight wildcard with multi segment",
			patterns: []string{"/foo/z+{args}/bar"},
			path:     "/foo/za/b/c/bar",
			want:     "/foo/z+{args}/bar",
			params:   []Param{{Key: "args", Value: "a/b/c"}},
		},
		{
			name:     "simple infix inflight wildcard regexp with multi segment",
			patterns: []string{"/foo/z+{args:[A-z/]+}/bar"},
			path:     "/foo/za/b/c/bar",
			want:     "/foo/z+{args:[A-z/]+}/bar",
			params:   []Param{{Key: "args", Value: "a/b/c"}},
		},
		{
			name:     "simple infix inflight wildcard literal regexp with multi segment",
			patterns: []string{"/foo/z+{args:a/b/c}/bar"},
			path:     "/foo/za/b/c/bar",
			want:     "/foo/z+{args:a/b/c}/bar",
			params:   []Param{{Key: "args", Value: "a/b/c"}},
		},
		{
			name:     "simple infix inflight wildcard with multi slash",
			patterns: []string{"/foo/z+{args}/bar"},
			path:     "/foo/z////bar",
			want:     "/foo/z+{args}/bar",
			params:   []Param{{Key: "args", Value: "///"}},
		},
		{
			name:     "simple infix inflight wildcard regexp with multi slash",
			patterns: []string{"/foo/z+{args:///}/bar"},
			path:     "/foo/z////bar",
			want:     "/foo/z+{args:///}/bar",
			params:   []Param{{Key: "args", Value: "///"}},
		},
		{
			name:     "simple infix inflight wildcard with multi segment and pattern character",
			patterns: []string{"/foo/z+{args}/bar"},
			path:     "/foo/z+{args}/b/c/bar",
			want:     "/foo/z+{args}/bar",
			params:   []Param{{Key: "args", Value: "+{args}/b/c"}},
		},
		{
			name:     "simple infix inflight wildcard regexp with multi segment and pattern character",
			patterns: []string{"/foo/z+{args:.*}/bar"},
			path:     "/foo/z+{args}/b/c/bar",
			want:     "/foo/z+{args:.*}/bar",
			params:   []Param{{Key: "args", Value: "+{args}/b/c"}},
		},
		{
			name:     "simple infix inflight wildcard long",
			patterns: []string{"/foo/xyz+{args}/bar"},
			path:     "/foo/xyza/bar",
			want:     "/foo/xyz+{args}/bar",
			params:   []Param{{Key: "args", Value: "a"}},
		},
		{
			name:     "simple infix inflight wildcard with multi segment long",
			patterns: []string{"/foo/xyz+{args}/bar"},
			path:     "/foo/xyza/b/c/bar",
			want:     "/foo/xyz+{args}/bar",
			params:   []Param{{Key: "args", Value: "a/b/c"}},
		},
		{
			name:     "overlapping infix and suffix wildcard match infix",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar"},
			path:     "/foo/a/b/c/bar",
			want:     "/foo/+{args}/bar",
			params:   []Param{{Key: "args", Value: "a/b/c"}},
		},
		{
			name:     "overlapping infix and suffix regexp wildcard match infix",
			patterns: []string{"/foo/+{args:.*}", "/foo/+{args:.*}/bar"},
			path:     "/foo/a/b/c/bar",
			want:     "/foo/+{args:.*}/bar",
			params:   []Param{{Key: "args", Value: "a/b/c"}},
		},
		{
			name:     "overlapping infix and suffix wildcard match infix with slash",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar"},
			path:     "/foo///bar",
			want:     "/foo/+{args}/bar",
			params:   []Param{{Key: "args", Value: "/"}},
		},
		{
			name:     "overlapping infix and suffix regexp wildcard match infix with slash",
			patterns: []string{"/foo/+{args:/}", "/foo/+{args:/}/bar"},
			path:     "/foo///bar",
			want:     "/foo/+{args:/}/bar",
			params:   []Param{{Key: "args", Value: "/"}},
		},
		{
			name:     "overlapping infix and suffix wildcard match suffix",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar"},
			path:     "/foo/a/b/c/baz",
			want:     "/foo/+{args}",
			params:   []Param{{Key: "args", Value: "a/b/c/baz"}},
		},
		{
			name:     "overlapping infix and suffix regexp wildcard match suffix",
			patterns: []string{"/foo/+{args:.*}", "/foo/+{args:.*}/bar"},
			path:     "/foo/a/b/c/baz",
			want:     "/foo/+{args:.*}",
			params:   []Param{{Key: "args", Value: "a/b/c/baz"}},
		},
		{
			name:     "overlapping infix and suffix wildcard match suffix with empty slash",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar"},
			path:     "/foo///baz",
			want:     "/foo/+{args}",
			params:   []Param{{Key: "args", Value: "//baz"}},
		},
		{
			name:     "overlapping infix and suffix regexp wildcard match suffix with empty slash",
			patterns: []string{"/foo/+{args:.*}", "/foo/+{args:.*}/bar"},
			path:     "/foo///baz",
			want:     "/foo/+{args:.*}",
			params:   []Param{{Key: "args", Value: "//baz"}},
		},
		{
			name:     "overlapping infix and suffix wildcard match suffix with a prefix of the infix tail",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar"},
			path:     "/foo/a/b/c/barito",
			want:     "/foo/+{args}",
			params:   []Param{{Key: "args", Value: "a/b/c/barito"}},
		},
		{
			name:     "overlapping infix suffix wildcard and param match infix",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar", "/foo/{ps}/bar"},
			path:     "/foo/a/b/c/bar",
			want:     "/foo/+{args}/bar",
			params:   []Param{{Key: "args", Value: "a/b/c"}},
		},
		{
			name:     "overlapping infix suffix wildcard and param match infix with empty slash",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar", "/foo/{ps}/bar"},
			path:     "/foo///bar",
			want:     "/foo/+{args}/bar",
			params:   []Param{{Key: "args", Value: "/"}},
		},
		{
			name:     "overlapping infix suffix wildcard and param match suffix",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar", "/foo/{ps}/bar"},
			path:     "/foo/a/b/c/bili",
			want:     "/foo/+{args}",
			params:   []Param{{Key: "args", Value: "a/b/c/bili"}},
		},
		{
			name:     "overlapping infix suffix wildcard and suffix param match infix",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar", "/foo/{ps}"},
			path:     "/foo/a/bar",
			want:     "/foo/+{args}/bar",
			params:   []Param{{Key: "args", Value: "a"}},
		},
		{
			name:     "overlapping infix suffix wildcard and param match param",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar", "/foo/{ps}/bar"},
			path:     "/foo/a/bar",
			want:     "/foo/{ps}/bar",
			params:   []Param{{Key: "ps", Value: "a"}},
		},
		{
			name:     "overlapping infix suffix wildcard and suffix param match suffix",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar", "/foo/{ps}"},
			path:     "/foo/a/bili",
			want:     "/foo/+{args}",
			params:   []Param{{Key: "args", Value: "a/bili"}},
		},
		{
			name:     "overlapping infix suffix wildcard and suffix param match param",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar", "/foo/{ps}"},
			path:     "/foo/a",
			want:     "/foo/{ps}",
			params:   []Param{{Key: "ps", Value: "a"}},
		},
		{
			name:     "overlapping infix suffix wildcard and param match param with trailing slash",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar", "/foo/{ps}/"},
			path:     "/foo/a/",
			want:     "/foo/{ps}/",
			params:   []Param{{Key: "ps", Value: "a"}},
		},
		{
			name:     "overlapping infix suffix wildcard and param match suffix on one segment",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar", "/foo/{ps}/y"},
			path:     "/foo/a",
			want:     "/foo/+{args}",
			params:   []Param{{Key: "args", Value: "a"}},
		},
		{
			name:     "overlapping infix suffix wildcard and param match suffix without trailing slash",
			patterns: []string{"/foo/+{args}", "/foo/+{args}/bar", "/foo/{ps}/y"},
			path:     "/foo/a/",
			want:     "/foo/+{args}",
			params:   []Param{{Key: "args", Value: "a/"}},
		},
		{
			name:     "overlapping infix inflight suffix wildcard and param match param",
			patterns: []string{"/foo/123+{args}", "/foo/123+{args}/bar", "/foo/123{ps}/bar"},
			path:     "/foo/123a/bar",
			want:     "/foo/123{ps}/bar",
			params:   []Param{{Key: "ps", Value: "a"}},
		},
		{
			name:     "overlapping infix inflight suffix wildcard and param match suffix",
			patterns: []string{"/foo/123+{args}", "/foo/123+{args}/bar", "/foo/123{ps}"},
			path:     "/foo/123a/bili",
			want:     "/foo/123+{args}",
			params:   []Param{{Key: "args", Value: "a/bili"}},
		},
		{
			name:     "overlapping infix inflight suffix wildcard and suffix param match param",
			patterns: []string{"/foo/123+{args}", "/foo/123+{args}/bar", "/foo/123{ps}"},
			path:     "/foo/123a",
			want:     "/foo/123{ps}",
			params:   []Param{{Key: "ps", Value: "a"}},
		},
		{
			name:     "infix segment followed by param",
			patterns: []string{"/foo/+{a}/{b}"},
			path:     "/foo/a/b/c/d",
			want:     "/foo/+{a}/{b}",
			params:   []Param{{Key: "a", Value: "a/b/c"}, {Key: "b", Value: "d"}},
		},
		{
			name:     "infix segment followed by two params",
			patterns: []string{"/foo/+{a}/{b}/{c}"},
			path:     "/foo/a/b/c/d",
			want:     "/foo/+{a}/{b}/{c}",
			params:   []Param{{Key: "a", Value: "a/b"}, {Key: "b", Value: "c"}, {Key: "c", Value: "d"}},
		},
		{
			name:     "infix segment followed by one param and one wildcard",
			patterns: []string{"/foo/+{a}/{b}/+{c}"},
			path:     "/foo/a/b/c/d",
			want:     "/foo/+{a}/{b}/+{c}",
			params:   []Param{{Key: "a", Value: "a"}, {Key: "b", Value: "b"}, {Key: "c", Value: "c/d"}},
		},
		{
			name:     "param followed by suffix wildcard",
			patterns: []string{"/foo/{a}/+{b}"},
			path:     "/foo/a/b/c/d",
			want:     "/foo/{a}/+{b}",
			params:   []Param{{Key: "a", Value: "a"}, {Key: "b", Value: "b/c/d"}},
		},
		{
			name:     "infix inflight segment followed by param",
			patterns: []string{"/foo/123+{a}/{b}"},
			path:     "/foo/123a/b/c/d",
			want:     "/foo/123+{a}/{b}",
			params:   []Param{{Key: "a", Value: "a/b/c"}, {Key: "b", Value: "d"}},
		},
		{
			name:     "inflight param followed by suffix wildcard",
			patterns: []string{"/foo/123{a}/+{b}"},
			path:     "/foo/123a/b/c/d",
			want:     "/foo/123{a}/+{b}",
			params:   []Param{{Key: "a", Value: "a"}, {Key: "b", Value: "b/c/d"}},
		},
		{
			name:     "multi infix segment simple",
			patterns: []string{"/foo/+{$1}/bar/+{$2}/baz"},
			path:     "/foo/a/bar/b/c/d/baz",
			want:     "/foo/+{$1}/bar/+{$2}/baz",
			params:   []Param{{Key: "$1", Value: "a"}, {Key: "$2", Value: "b/c/d"}},
		},
		{
			name:     "multi inflight segment simple",
			patterns: []string{"/foo/123+{$1}/bar/456+{$2}/baz"},
			path:     "/foo/123a/bar/456b/c/d/baz",
			want:     "/foo/123+{$1}/bar/456+{$2}/baz",
			params:   []Param{{Key: "$1", Value: "a"}, {Key: "$2", Value: "b/c/d"}},
		},
		{
			name:     "static priority",
			patterns: []string{"/foo/bar/baz", "/foo/{ps}/baz", "/foo/+{any}/baz"},
			path:     "/foo/bar/baz",
			want:     "/foo/bar/baz",
		},
		{
			name:     "param priority",
			patterns: []string{"/foo/bar/baz", "/foo/{ps}/baz", "/foo/+{any}/baz"},
			path:     "/foo/buzz/baz",
			want:     "/foo/{ps}/baz",
			params:   []Param{{Key: "ps", Value: "buzz"}},
		},
		{
			name:     "fallback catch all",
			patterns: []string{"/foo/bar/baz", "/foo/{ps}/baz", "/foo/+{any}/baz"},
			path:     "/foo/a/b/baz",
			want:     "/foo/+{any}/baz",
			params:   []Param{{Key: "any", Value: "a/b"}},
		},
		{
			name:     "complex overlapping pattern with static priority",
			patterns: []string{"/foo/bar/baz/{$1}/jo", "/foo/+{any}/baz/{$1}/jo", "/foo/{ps}/baz/{$1}/jo"},
			path:     "/foo/bar/baz/1/jo",
			want:     "/foo/bar/baz/{$1}/jo",
			params:   []Param{{Key: "$1", Value: "1"}},
		},
		{
			name:     "complex overlapping pattern with param priority",
			patterns: []string{"/foo/bar/baz/{$1}/jo", "/foo/+{any}/baz/{$1}/jo", "/foo/{ps}/baz/{$1}/jo"},
			path:     "/foo/bam/baz/1/jo",
			want:     "/foo/{ps}/baz/{$1}/jo",
			params:   []Param{{Key: "ps", Value: "bam"}, {Key: "$1", Value: "1"}},
		},
		{
			name:     "complex overlapping pattern with catch all fallback",
			patterns: []string{"/foo/bar/baz/{$1}/jo", "/foo/+{any}/baz/{$1}/jo", "/foo/{ps}/baz/{$1}/jo"},
			path:     "/foo/a/b/c/baz/1/jo",
			want:     "/foo/+{any}/baz/{$1}/jo",
			params:   []Param{{Key: "any", Value: "a/b/c"}, {Key: "$1", Value: "1"}},
		},
		{
			name:     "complex overlapping pattern with catch all fallback on distinct tails",
			patterns: []string{"/foo/bar/baz/{$1}/jo", "/foo/+{any}/baz/{$1}/john", "/foo/{ps}/baz/{$1}/johnny"},
			path:     "/foo/a/baz/1/john",
			want:     "/foo/+{any}/baz/{$1}/john",
			params:   []Param{{Key: "any", Value: "a"}, {Key: "$1", Value: "1"}},
		},
		{
			name:     "overlapping static and infix",
			patterns: []string{"/foo/+{any}/baz", "/foo/a/b/baz"},
			path:     "/foo/a/b/baz",
			want:     "/foo/a/b/baz",
		},
		{
			name:     "overlapping static and infix with catch all fallback",
			patterns: []string{"/foo/+{any}/baz", "/foo/a/b/baz"},
			path:     "/foo/a/b/c/baz",
			want:     "/foo/+{any}/baz",
			params:   []Param{{Key: "any", Value: "a/b/c"}},
		},
		{
			name:     "infix wildcard with trailing slash",
			patterns: []string{"/foo/+{any}/"},
			path:     "/foo/a/b/c/",
			want:     "/foo/+{any}/",
			params:   []Param{{Key: "any", Value: "a/b/c"}},
		},
		{
			name:     "overlapping static and infix with most specific",
			patterns: []string{"/foo/+{any}/{a}/ddd/", "/foo/+{any}/bbb/{d}/e"},
			path:     "/foo/a/b/c/bbb/ddd/",
			want:     "/foo/+{any}/{a}/ddd/",
			params:   []Param{{Key: "any", Value: "a/b/c"}, {Key: "a", Value: "bbb"}},
		},
		{
			name:     "suffix wildcard captures the trailing slash beside infix siblings",
			patterns: []string{"/foo/+{any}", "/foo/+{any}/b/", "/foo/+{any}/c/"},
			path:     "/foo/x/y/z/",
			want:     "/foo/+{any}",
			params:   []Param{{Key: "any", Value: "x/y/z/"}},
		},
		{
			name:     "infix wildcard with trailing slash most specific",
			patterns: []string{"/foo/+{any}", "/foo/+{any}/"},
			path:     "/foo/x/y/z/",
			want:     "/foo/+{any}/",
			params:   []Param{{Key: "any", Value: "x/y/z"}},
		},
		{
			name:     "infix wildcard with trailing with direct match most specific",
			patterns: []string{"/foo/+{any}", "/foo/+{any}/"},
			path:     "/foo/x/y/z",
			want:     "/foo/+{any}",
			params:   []Param{{Key: "any", Value: "x/y/z"}},
		},
		{
			name:     "infix regexp wildcard with trailing slash most specific",
			patterns: []string{"/foo/+{any:.*}", "/foo/+{any:.*}/"},
			path:     "/foo/x/y/z/",
			want:     "/foo/+{any:.*}/",
			params:   []Param{{Key: "any", Value: "x/y/z"}},
		},
		{
			name:     "infix regexp wildcard with direct match",
			patterns: []string{"/foo/+{any:.*}", "/foo/+{any:.*}/"},
			path:     "/foo/x/y/z",
			want:     "/foo/+{any:.*}",
			params:   []Param{{Key: "any", Value: "x/y/z"}},
		},
		{
			name:     "infix wildcard with fallback to suffix",
			patterns: []string{"/foo/+{any}", "/foo/+{any}/x"},
			path:     "/foo/x/y/z",
			want:     "/foo/+{any}",
			params:   []Param{{Key: "any", Value: "x/y/z"}},
		},
		{
			name:     "infix regexp wildcard with fallback to suffix",
			patterns: []string{"/foo/+{any:.*}", "/foo/+{any:[A-z]}/"},
			path:     "/foo/x/y/z",
			want:     "/foo/+{any:.*}",
			params:   []Param{{Key: "any", Value: "x/y/z"}},
		},
	}))
}

func TestRouting_TrailingSlash(t *testing.T) {
	runLookup(t, RelaxedSlash, onPathHost([]lookupCase{
		{
			name:     "infix wildcard with trailing slash and added slash",
			patterns: []string{"/foo/+{any}/"},
			path:     "/foo/a/b/c",
			want:     "/foo/+{any}/",
			relaxed:  true,
			params:   []Param{{Key: "any", Value: "a/b/c"}},
		},
		{
			name:     "infix wildcard with trailing slash and added slash and empty slash",
			patterns: []string{"/foo/+{any}/"},
			path:     "/foo//a",
			want:     "/foo/+{any}/",
			relaxed:  true,
			params:   []Param{{Key: "any", Value: "/a"}},
		},
		{
			name:     "infix wildcard with relaxed match and skipped node match",
			patterns: []string{"/foo/+{any}/", "/{x}/a/b/c"},
			path:     "/foo/a/b/c",
			want:     "/foo/+{any}/",
			relaxed:  true,
			params:   []Param{{Key: "any", Value: "a/b/c"}},
		},
		{
			name:     "infix wildcard with relaxed match but skipped node does not match",
			patterns: []string{"/foo/+{any}/", "/{x}/a/b/x"},
			path:     "/foo/a/b/c",
			want:     "/foo/+{any}/",
			relaxed:  true,
			params:   []Param{{Key: "any", Value: "a/b/c"}},
		},
		{
			name:     "infix wildcard with trailing slash and added slash beside static siblings",
			patterns: []string{"/foo/+{any}/", "/foo/+{any}/abc", "/foo/+{any}/bcd"},
			path:     "/foo/a/b/c/abd",
			want:     "/foo/+{any}/",
			relaxed:  true,
			params:   []Param{{Key: "any", Value: "a/b/c/abd"}},
		},
		{
			name:     "infix wildcard with sub-node added slash fallback",
			patterns: []string{"/foo/+{any}/{a}/ddd/", "/foo/+{any}/bbb/{d}/foo"},
			path:     "/foo/a/b/c/bbb/ddd",
			want:     "/foo/+{any}/{a}/ddd/",
			relaxed:  true,
			params:   []Param{{Key: "any", Value: "a/b/c"}, {Key: "a", Value: "bbb"}},
		},
		{
			name:     "infix wildcard with more specific relaxed match",
			patterns: []string{"/foo/+{any}/c/bbb/", "/foo/+{any}/bbb"},
			path:     "/foo/a/b/c/bbb",
			want:     "/foo/+{any}/c/bbb/",
			relaxed:  true,
			params:   []Param{{Key: "any", Value: "a/b"}},
		},
		{
			name:     "infix wildcard with more specific relaxed match but regexp does not pass",
			patterns: []string{"/foo/+{any:bar}/c/bbb/", "/foo/+{any}/bbb"},
			path:     "/foo/a/b/c/bbb",
			want:     "/foo/+{any}/bbb",
			params:   []Param{{Key: "any", Value: "a/b/c"}},
		},
		{
			name:     "infix wildcard with more specific relaxed match (multi depth)",
			patterns: []string{"/foo/+{any}/b/c/bbb/", "/foo/+{any}/c/bbb/", "/foo/+{any}/bbb"},
			path:     "/foo/a/b/c/bbb",
			want:     "/foo/+{any}/b/c/bbb/",
			relaxed:  true,
			params:   []Param{{Key: "any", Value: "a"}},
		},
		{
			name:     "infix wildcard with sub-node relaxed match at depth 1 and 2 but fallback first relaxed match",
			patterns: []string{"/foo/+{any}/b/c/bbb/", "/foo/+{any}/c/bbb/", "/foo/+{any}/bbx"},
			path:     "/foo/a/b/c/bbb",
			want:     "/foo/+{any}/b/c/bbb/",
			relaxed:  true,
			params:   []Param{{Key: "any", Value: "a"}},
		},
		{
			name:     "infix wildcard with sub-node relaxed match at depth 1 and 2 beside a slash sibling",
			patterns: []string{"/foo/+{any}/", "/foo/+{any}/b/c/bbb/", "/foo/+{any}/c/bbb/", "/foo/+{any}/bbx"},
			path:     "/foo/a/b/c/bbb",
			want:     "/foo/+{any}/b/c/bbb/",
			relaxed:  true,
			params:   []Param{{Key: "any", Value: "a"}},
		},
		{
			name:     "infix wildcard with depth 0 relaxed match and sub-node relaxed match at depth 1 fallback first relaxed match",
			patterns: []string{"/foo/a/b/c/bbb/", "/foo/+{any}/c/bbb/", "/foo/+{any}/bbx"},
			path:     "/foo/a/b/c/bbb",
			want:     "/foo/a/b/c/bbb/",
			relaxed:  true,
		},
		{
			name:     "infix wildcard with depth 0 param relaxed match and sub-node relaxed match at depth 1 fallback first relaxed match",
			patterns: []string{"/foo/{first}/b/c/bbb/", "/foo/+{any}/c/bbb/", "/foo/+{any}/bbx"},
			path:     "/foo/a/b/c/bbb",
			want:     "/foo/{first}/b/c/bbb/",
			relaxed:  true,
			params:   []Param{{Key: "first", Value: "a"}},
		},
		{
			name:     "infix wildcard with trailing slash and suffix regexp catch-all",
			patterns: []string{"/foo/+{any:[A-z]+}", "/foo/+{any}/"},
			path:     "/foo/a/b/c",
			want:     "/foo/+{any}/",
			relaxed:  true,
			params:   []Param{{Key: "any", Value: "a/b/c"}},
		},
		{
			name:     "multi infix with most specific and match",
			patterns: []string{"/foo/+{any1}/b/c/+{any2}/d/", "/foo/+{any1}/c/+{any2}/d"},
			path:     "/foo/a/b/c/x/y/z/d",
			want:     "/foo/+{any1}/b/c/+{any2}/d/",
			relaxed:  true,
			params:   []Param{{Key: "any1", Value: "a"}, {Key: "any2", Value: "x/y/z"}},
		},
		{
			name:     "multi infix wildcard with sub-node relaxed match at depth 1 and fallback first",
			patterns: []string{"/foo/+{any1}/b/c/+{any2}/d/", "/foo/+{any1}/c/+{any2}/x"},
			path:     "/foo/a/b/c/x/y/z/d",
			want:     "/foo/+{any1}/b/c/+{any2}/d/",
			relaxed:  true,
			params:   []Param{{Key: "any1", Value: "a"}, {Key: "any2", Value: "x/y/z"}},
		},
		{
			name:     "multi infix wildcard with sub-node relaxed match and skipped nodes at depth 1 and fallback first",
			patterns: []string{"/foo/+{any1}/b/c/+{any2}/{a}/", "/foo/+{any1}/b/c/+{any2}/d{a}/", "/foo/+{any1}/b/c/+{any2}/dd/", "/foo/+{any1}/c/+{any2}/x"},
			path:     "/foo/a/b/c/x/y/z/dd",
			want:     "/foo/+{any1}/b/c/+{any2}/dd/",
			relaxed:  true,
			params:   []Param{{Key: "any1", Value: "a"}, {Key: "any2", Value: "x/y/z"}},
		},
		{
			name:     "multi infix wildcard with sub-node relaxed match and skipped nodes at depth 1 and direct match",
			patterns: []string{"/foo/+{any1}/b/c/+{any2}/{a}/", "/foo/+{any1}/b/c/+{any2}/d{a}/", "/foo/+{any1}/b/c/+{any2}/dd/", "/foo/+{any1}/c/+{any2}/x"},
			path:     "/foo/a/b/c/x/y/z/xd/",
			want:     "/foo/+{any1}/b/c/+{any2}/{a}/",
			params:   []Param{{Key: "any1", Value: "a"}, {Key: "any2", Value: "x/y/z"}, {Key: "a", Value: "xd"}},
		},
		{
			name:     "multi infix wildcard with most specific relaxed match match",
			patterns: []string{"/foo/+{any1}/b/c/+{any2}/{a}/", "/foo/+{any1}/b/c/+{any2}/d{a}/", "/foo/+{any1}/b/c/+{any2}/dd/", "/foo/+{any1}/c/+{any2}/x", "/{a}/+{any1}/c/x/y/z/dd"},
			path:     "/foo/a/b/c/x/y/z/dd",
			want:     "/foo/+{any1}/b/c/+{any2}/dd/",
			relaxed:  true,
			params:   []Param{{Key: "any1", Value: "a"}, {Key: "any2", Value: "x/y/z"}},
		},
		{
			name:     "match mid edge",
			patterns: []string{"/foo/bar/"},
			path:     "/foo/bar",
			want:     "/foo/bar/",
			relaxed:  true,
		},
		{
			name:     "incomplete match end of edge",
			patterns: []string{"/foo/bar"},
			path:     "/foo/bar/",
			want:     "/foo/bar",
			relaxed:  true,
		},
		{
			name:     "match mid edge with child node",
			patterns: []string{"/users/", "/users/{id}"},
			path:     "/users",
			want:     "/users/",
			relaxed:  true,
		},
		{
			name:     "match mid edge in child node",
			patterns: []string{"/users", "/users/{id}"},
			path:     "/users/",
			want:     "/users",
			relaxed:  true,
		},
		{
			name:     "match mid edge in child node with parent not leaf",
			patterns: []string{"/test/x", "/tests/"},
			path:     "/test/",
		},
		{
			name:     "match mid edge in child node with invalid remaining prefix",
			patterns: []string{"/users/{id}"},
			path:     "/users/",
		},
		{
			name:     "match mid edge with child node with invalid remaining suffix",
			patterns: []string{"/users/{id}"},
			path:     "/users",
		},
		{
			name:     "match mid edge with trailing slash and more characters after",
			patterns: []string{"/foo/bar/buzz"},
			path:     "/foo/bar",
		},
		{
			name:     "match mid edge with trailing slash and more characters before",
			patterns: []string{"/foo/barr/"},
			path:     "/foo/bar",
		},
		{
			name:     "incomplete match end of edge with trailing slash and more characters after",
			patterns: []string{"/foo/bar"},
			path:     "/foo/bar/buzz",
		},
		{
			name:     "incomplete match end of edge with trailing slash and more characters before",
			patterns: []string{"/foo/bar"},
			path:     "/foo/barr/",
		},
		{
			name:     "no relaxed match on pattern ending with double slash",
			patterns: []string{"/foo//"},
			path:     "/foo/",
		},
		{
			name:     "no relaxed match on pattern ending with triple slash",
			patterns: []string{"/foo///"},
			path:     "/foo//",
		},
		{
			name:     "no relaxed match on pattern ending with double slash and sibling",
			patterns: []string{"/foo//", "/foo/bar"},
			path:     "/foo/",
		},
		{
			name:     "no relaxed match on request ending with double slash and standalone slash node",
			patterns: []string{"/foo/", "/foo//bar", "/foo//qux"},
			path:     "/foo//",
		},
		{
			name:     "no relaxed match on request ending with double slash",
			patterns: []string{"/foo/"},
			path:     "/foo//",
		},
		{
			name:     "match with empty catch all behind a split static node",
			patterns: []string{"/foo/*{a}", "/foobar"},
			path:     "/foo",
			want:     "/foo/*{a}",
			relaxed:  true,
			params:   []Param{{Key: "a", Value: ""}},
		},
		{
			name:     "match mid edge on pattern with infix double slash",
			patterns: []string{"/foo//bar/"},
			path:     "/foo//bar",
			want:     "/foo//bar/",
			relaxed:  true,
		},
		{
			name:     "incomplete match end of edge on pattern with infix double slash",
			patterns: []string{"/foo//bar"},
			path:     "/foo//bar/",
			want:     "/foo//bar",
			relaxed:  true,
		},
		{
			name:     "relaxed match on static pattern wins over direct match on lower priority param pattern",
			patterns: []string{"/foo", "/{a}/"},
			path:     "/foo/",
			want:     "/foo",
			relaxed:  true,
		},
		{
			name:     "relaxed match on static pattern wins over direct match on lower priority param pattern reversed",
			patterns: []string{"/foo/", "/{a}"},
			path:     "/foo",
			want:     "/foo/",
			relaxed:  true,
		},
		{
			name:     "match infix wildcard with added trailing slash",
			patterns: []string{"/+{a}/"},
			path:     "/x/y",
			want:     "/+{a}/",
			relaxed:  true,
			params:   []Param{{Key: "a", Value: "x/y"}},
		},
		{
			name:     "no relaxed match when a suffix catch-all direct matches",
			patterns: []string{"/+{a}/", "/+{a}"},
			path:     "/x/y",
			want:     "/+{a}",
			params:   []Param{{Key: "a", Value: "x/y"}},
		},
		{
			name:     "match regex param with extra trailing slash",
			patterns: []string{"/{p:[a-z]+}"},
			path:     "/abc/",
			want:     "/{p:[a-z]+}",
			relaxed:  true,
			params:   []Param{{Key: "p", Value: "abc"}},
		},
		{
			name:     "no relaxed match for suffix regex catch-all rejecting the full capture",
			patterns: []string{"/+{w:[a-z]+}"},
			path:     "/abc/",
		},
		{
			name:     "no relaxed match when a suffix regex catch-all direct matches",
			patterns: []string{"/+{w:[a-z/]+}", "/+{w:[a-z/]+}/x"},
			path:     "/abc/",
			want:     "/+{w:[a-z/]+}",
			params:   []Param{{Key: "w", Value: "abc/"}},
		},
		{
			name:     "no relaxed match for suffix regex catch-all rejecting the full capture with sibling",
			patterns: []string{"/+{w:[a-z]+}", "/+{w:[a-z]+}/x"},
			path:     "/abc/",
		},
		{
			name:     "no relaxed match on slash node when parent suffix regex catch-all direct matches",
			patterns: []string{"/+{w:[a-z/]+}", "/+{w:[a-z/]+}/x", "/+{w:[a-z/]+}/y"},
			path:     "/abc/",
			want:     "/+{w:[a-z/]+}",
			params:   []Param{{Key: "w", Value: "abc/"}},
		},
		{
			name:     "no relaxed match on slash node when parent suffix catch-all direct matches",
			patterns: []string{"/+{a}", "/+{a}/x", "/+{a}/y"},
			path:     "/abc/",
			want:     "/+{a}",
			params:   []Param{{Key: "a", Value: "abc/"}},
		},
		{
			name:     "current not a leaf with extra trailing slash",
			patterns: []string{"/foo", "/foo/x/", "/foo/z/"},
			path:     "/foo/",
			want:     "/foo",
			relaxed:  true,
		},
		{
			name:     "current not a leaf with extra trailing slash and static children",
			patterns: []string{"/foo", "/foo/bar", "/foo/baz"},
			path:     "/foo/",
			want:     "/foo",
			relaxed:  true,
		},
		{
			name:     "current not a leaf without extra trailing slash",
			patterns: []string{"/foo/", "/foobar"},
			path:     "/foo",
			want:     "/foo/",
			relaxed:  true,
		},
		{
			name:     "current not a leaf without extra trailing slash and child not a leaf",
			patterns: []string{"/foo/kam", "/foobar", "/foo/bar"},
			path:     "/foo",
		},
		{
			name:     "current not a leaf without extra trailing slash but current not matched completely",
			patterns: []string{"/foo/", "/foobar"},
			path:     "/fo",
		},
		{
			name:     "current not a leaf without extra trailing slash and child has more than a slash",
			patterns: []string{"/foo/b", "/foobar"},
			path:     "/a/foo",
		},
		{
			name:     "current not a leaf and path does not end with trailing slash",
			patterns: []string{"/foo", "/foo/x/", "/foo/z/"},
			path:     "/foo/c",
		},
		{
			name:     "current not a leaf and path ends with extra character and trailing slash",
			patterns: []string{"/foo", "/foo/x/", "/foo/z/"},
			path:     "/foo/c/",
		},
		{
			name:     "current not a leaf and path ends with trailing slash but last is not a leaf",
			patterns: []string{"/foo/a/a", "/foo/a/b", "/foo/c/"},
			path:     "/foo/a/",
		},
		{
			name:     "mid edge key without extra trailing slash",
			patterns: []string{"/foo/bar/baz", "/foo/bar"},
			path:     "/foo/bar/",
			want:     "/foo/bar",
			relaxed:  true,
		},
		{
			name:     "incomplete match end of edge with trailing slash request not cleaned",
			patterns: []string{"/foo", "/foo/", "/foo/x/", "/foo/z/"},
			path:     "/foo///",
		},
		{
			name:     "root pattern does not match a double slash",
			patterns: []string{"/"},
			path:     "//",
		},
		{
			name:     "current not a leaf, with leave on incomplete to end of edge",
			patterns: []string{"/{a}", "/foo/{b}", "/foo/{b}/x/", "/foo/{b}/y/"},
			path:     "/foo/bar/",
			want:     "/foo/{b}",
			relaxed:  true,
			params:   []Param{{Key: "b", Value: "bar"}},
		},
		{
			name:     "current not a leaf, with leave on end mid-edge",
			patterns: []string{"/{a}/x", "/foo/{b}", "/foo/{b}/x/", "/foo/{b}/y/"},
			path:     "/foo/bar/",
			want:     "/foo/{b}",
			relaxed:  true,
			params:   []Param{{Key: "b", Value: "bar"}},
		},
		{
			name:     "current not a leaf, with leave on end mid-edge behind a deeper param sibling",
			patterns: []string{"/{a}/{b}/e", "/foo/{b}", "/foo/{b}/x/", "/foo/{b}/y/"},
			path:     "/foo/bar/",
			want:     "/foo/{b}",
			relaxed:  true,
			params:   []Param{{Key: "b", Value: "bar"}},
		},
		{
			name:     "current not a leaf, with leave on not a leaf",
			patterns: []string{"/{a}/{b}/e", "/{a}/{b}/d", "/foo/{b}", "/foo/{b}/x/", "/foo/{b}/y/"},
			path:     "/foo/bar/",
			want:     "/foo/{b}",
			relaxed:  true,
			params:   []Param{{Key: "b", Value: "bar"}},
		},
		{
			name:     "current not a leaf, with most specific relaxed match",
			patterns: []string{"/a/foo/", "/a/foobar", "/{a}/foo"},
			path:     "/a/foo",
			want:     "/a/foo/",
			relaxed:  true,
		},
		{
			name:     "current not a leaf, with child slash match",
			patterns: []string{"/{x}/foo/", "/{x}/foobar", "/a/fo"},
			path:     "/a/foo",
			want:     "/{x}/foo/",
			relaxed:  true,
			params:   []Param{{Key: "x", Value: "a"}},
		},
		{
			name:     "current not a leaf, with child slash match and backtrack",
			patterns: []string{"/{param}/b/foo/", "/{param}/b/foobar", "/{param}/{b}/fo"},
			path:     "/a/b/foo",
			want:     "/{param}/b/foo/",
			relaxed:  true,
			params:   []Param{{Key: "param", Value: "a"}},
		},
		{
			name:     "mid edge key, add an extra trailing slash",
			patterns: []string{"/{a}", "/foo/{b}/"},
			path:     "/foo/bar",
			want:     "/foo/{b}/",
			relaxed:  true,
			params:   []Param{{Key: "b", Value: "bar"}},
		},
		{
			name:     "mid edge key, remove an extra trailing slash",
			patterns: []string{"/{a}", "/foo/{b}/baz", "/foo/{b}"},
			path:     "/foo/bar/",
			want:     "/foo/{b}",
			relaxed:  true,
			params:   []Param{{Key: "b", Value: "bar"}},
		},
		{
			name:     "incomplete match end of edge, remove extra trailing slash",
			patterns: []string{"/{a}", "/foo/{b}"},
			path:     "/foo/bar/",
			want:     "/foo/{b}",
			relaxed:  true,
			params:   []Param{{Key: "b", Value: "bar"}},
		},
		{
			name:     "current not a leaf, should empty params",
			patterns: []string{"/{a}", "/foo", "/foo/x/", "/foo/y/"},
			path:     "/foo/",
			want:     "/foo",
			relaxed:  true,
		},
		{
			name:     "relaxed match with empty catch all",
			patterns: []string{"/a/foo/*{any}", "/{a}/foo/y", "/{a}/foo/b"},
			path:     "/a/foo",
			want:     "/a/foo/*{any}",
			relaxed:  true,
			params:   []Param{{Key: "any", Value: ""}},
		},
		{
			name:     "relaxed match with empty catch all behind a split static node",
			patterns: []string{"/a/foo/*{any}", "/a/foobar", "/{a}/foo/y", "/{a}/foo/b"},
			path:     "/a/foo",
			want:     "/a/foo/*{any}",
			relaxed:  true,
			params:   []Param{{Key: "any", Value: ""}},
		},
		{
			name:     "relaxed match with empty catch all and param before",
			patterns: []string{"/{a}/foo/*{any}", "/{a}/foo/y", "/{a}/foo/b"},
			path:     "/a/foo",
			want:     "/{a}/foo/*{any}",
			relaxed:  true,
			params:   []Param{{Key: "a", Value: "a"}, {Key: "any", Value: ""}},
		},
		{
			name:     "relaxed match with infix wildcard",
			patterns: []string{"/+{args}/"},
			path:     "/a/b/c",
			want:     "/+{args}/",
			relaxed:  true,
			params:   []Param{{Key: "args", Value: "a/b/c"}},
		},
		{
			name:     "relaxed match with infix wildcard after param backtrack",
			patterns: []string{"/+{args}/", "/{a}/b"},
			path:     "/x/c",
			want:     "/+{args}/",
			relaxed:  true,
			params:   []Param{{Key: "args", Value: "x/c"}},
		},
	}))
}

func TestRouting_NoMatch(t *testing.T) {
	runLookup(t, ExactSlash, onPathHost([]lookupCase{
		{
			name:     "infix wildcard",
			patterns: []string{"/foo/+{args}/bar"},
			path:     "/foo/bar",
		},
		{
			name:     "infix wildcard regexp",
			patterns: []string{"/foo/+{args:$^}/bar"},
			path:     "/foo/bar",
		},
		{
			name:     "infix wildcard with children",
			patterns: []string{"/foo/+{args}/bar", "/foo/+{args}/caz"},
			path:     "/foo/bar",
		},
		{
			name:     "infix wildcard with children regexp",
			patterns: []string{"/foo/+{args:$^}/bar", "/foo/+{args:$^}/caz"},
			path:     "/foo/bar",
		},
		{
			name:     "infix wildcard with static edge",
			patterns: []string{"/foo/+{args}/bar", "/foo/baz"},
			path:     "/foo/bar",
		},
		{
			name:     "infix wildcard with static edge regexp",
			patterns: []string{"/foo/+{args:$^}/bar", "/foo/baz"},
			path:     "/foo/bar",
		},
		{
			name:     "infix wildcard and suffix wildcard",
			patterns: []string{"/foo/+{args}/bar", "/foo/+{args}"},
			path:     "/foo/",
		},
		{
			name:     "infix wildcard and suffix wildcard regexp",
			patterns: []string{"/foo/+{args:$^}/bar", "/foo/+{args:$^}"},
			path:     "/foo/",
		},
		{
			name:     "infix inflight wildcard",
			patterns: []string{"/foo/abc+{args}/bar"},
			path:     "/foo/abc/bar",
		},
		{
			name:     "infix inflight wildcard regexp",
			patterns: []string{"/foo/abc+{args:$^}/bar"},
			path:     "/foo/abc/bar",
		},
		{
			name:     "infix inflight wildcard with children",
			patterns: []string{"/foo/abc+{args}/bar", "/foo/abc+{args}/caz"},
			path:     "/foo/abc/bar",
		},
		{
			name:     "infix inflight wildcard with children regexp",
			patterns: []string{"/foo/abc+{args:$^}/bar", "/foo/abc+{args:$^}/caz"},
			path:     "/foo/abc/bar",
		},
		{
			name:     "infix inflight wildcard with static edge",
			patterns: []string{"/foo/abc+{args}/bar", "/foo/abc/baz"},
			path:     "/foo/abc/bar",
		},
		{
			name:     "infix inflight wildcard with static edge regexp",
			patterns: []string{"/foo/abc+{args:$^}/bar", "/foo/abc/baz"},
			path:     "/foo/abc/bar",
		},
		{
			name:     "infix inflight wildcard and suffix wildcard",
			patterns: []string{"/foo/abc+{args}/bar", "/foo/abc+{args}"},
			path:     "/foo/abc",
		},
		{
			name:     "infix inflight wildcard and suffix wildcard regexp",
			patterns: []string{"/foo/abc+{args:$^}/bar", "/foo/abc+{args:$^}"},
			path:     "/foo/abc",
		},
		{
			name:     "suffix wildcard wildcard with param edge",
			patterns: []string{"/foo/+{args}", "/foo/{param}"},
			path:     "/foo/",
		},
		{
			name:     "suffix wildcard wildcard with param edge regexp",
			patterns: []string{"/foo/+{args:$^}", "/foo/{param:$^}"},
			path:     "/foo/",
		},
		{
			name:     "suffix inflight wildcard wildcard with param edge",
			patterns: []string{"/foo/abc+{args}", "/foo/abc{param}"},
			path:     "/foo/abc",
		},
		{
			name:     "suffix inflight wildcard wildcard with param edge regexp",
			patterns: []string{"/foo/abc+{args:$^}", "/foo/abc{param:$^}"},
			path:     "/foo/abc",
		},
		{
			name:     "infix wildcard wildcard with param edge",
			patterns: []string{"/foo/+{args}/bar", "/foo/{param}/bar"},
			path:     "/foo/bar",
		},
		{
			name:     "infix wildcard wildcard with param edge regexp",
			patterns: []string{"/foo/+{args:$^}/bar", "/foo/{param:$^}/bar"},
			path:     "/foo/bar",
		},
		{
			name:     "infix inflight wildcard wildcard with param edge",
			patterns: []string{"/foo/abc+{args}/bar", "/foo/abc{param}/bar"},
			path:     "/foo/abc/bar",
		},
		{
			name:     "infix inflight wildcard wildcard with param edge regexp",
			patterns: []string{"/foo/abc+{args:$^}/bar", "/foo/abc{param:$^}/bar"},
			path:     "/foo/abc/bar",
		},
		{
			name:     "infix wildcard wildcard with trailing slash",
			patterns: []string{"/foo/+{args}/"},
			path:     "/foo//",
		},
		{
			name:     "infix wildcard wildcard with trailing slash regexp",
			patterns: []string{"/foo/+{args:$^}/"},
			path:     "/foo//",
		},
		{
			name:     "infix inflight wildcard wildcard with trailing slash",
			patterns: []string{"/foo/abc+{args}/"},
			path:     "/foo/abc/",
		},
		{
			name:     "infix inflight wildcard wildcard with trailing slash regexp",
			patterns: []string{"/foo/abc+{args:$^}/"},
			path:     "/foo/abc/",
		},
		{
			name:     "empty segment",
			patterns: []string{"/cmd/{tool}/{sub}"},
			path:     "/cmd//sub",
		},
		{
			name:     "empty segment regexp",
			patterns: []string{"/cmd/{tool:bar}/{sub}"},
			path:     "/cmd//sub",
		},
		{
			name:     "empty inflight end of pattern",
			patterns: []string{"/command/exec:{tool}"},
			path:     "/command/exec:",
		},
		{
			name:     "empty inflight end of pattern regexp",
			patterns: []string{"/command/exec:{tool:bar}"},
			path:     "/command/exec:",
		},
		{
			name:     "empty inflight segment",
			patterns: []string{"/command/exec:{tool}/id"},
			path:     "/command/exec:/id",
		},
		{
			name:     "empty inflight segment regexp",
			patterns: []string{"/command/exec:{tool:bar}/id"},
			path:     "/command/exec:/id",
		},
	}))
}

func TestRouting_Matchers(t *testing.T) {
	type registration struct {
		pattern  string
		matchers []RequestMatcher
		priority uint
	}

	cases := []struct {
		name     string
		entries  []registration
		host     string
		target   string
		want     string
		relaxed  bool
		matchers int
		params   []Param
	}{
		{
			name: "relaxed match on hostname pattern after failing every query matcher",
			entries: []registration{
				{pattern: "example.com/foo/bar/"},
				{pattern: "+{any}/foo/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}}},
			},
			host:    "example.com",
			target:  "/foo/bar",
			want:    "example.com/foo/bar/",
			relaxed: true,
		},
		{
			name: "relaxed match on hostname pattern with matcher after failing every query matcher",
			entries: []registration{
				{pattern: "example.com/foo/bar/", matchers: []RequestMatcher{QueryMatcher{"c", "d"}}},
				{pattern: "+{any}/foo/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}},
			},
			host:     "example.com",
			target:   "/foo/bar?c=d",
			want:     "example.com/foo/bar/",
			relaxed:  true,
			matchers: 1,
		},
		{
			name: "relaxed match on hostname pattern after failing one query matcher",
			entries: []registration{
				{pattern: "example.com/foo/bar/"},
				{pattern: "+{any}/foo/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}},
			},
			host:    "example.com",
			target:  "/foo/bar?a=b",
			want:    "example.com/foo/bar/",
			relaxed: true,
		},
		{
			name: "relaxed match on catch-all with matcher after failing every query matcher",
			entries: []registration{
				{pattern: "a.test/foo/+{any}/", matchers: []RequestMatcher{QueryMatcher{"c", "d"}}},
				{pattern: "a.test/foo/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}},
			},
			host:     "a.test",
			target:   "/foo/bar?c=d",
			want:     "a.test/foo/+{any}/",
			relaxed:  true,
			matchers: 1,
			params:   []Param{{Key: "any", Value: "bar"}},
		},
		{
			name: "fallback on catch-all with matcher after failing every query matcher",
			entries: []registration{
				{pattern: "a.test/foo/+{any}", matchers: []RequestMatcher{QueryMatcher{"c", "d"}}},
				{pattern: "a.test/foo/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}},
			},
			host:     "a.test",
			target:   "/foo/bar?c=d",
			want:     "a.test/foo/+{any}",
			matchers: 1,
			params:   []Param{{Key: "any", Value: "bar"}},
		},
		{
			name: "fallback on param with matcher after failing every query matcher",
			entries: []registration{
				{pattern: "a.test/foo/{name}", matchers: []RequestMatcher{QueryMatcher{"c", "d"}}},
				{pattern: "a.test/foo/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}},
			},
			host:     "a.test",
			target:   "/foo/bar?c=d",
			want:     "a.test/foo/{name}",
			matchers: 1,
			params:   []Param{{Key: "name", Value: "bar"}},
		},
		{
			name: "fallback on catch-all with matchers after failing every query matcher",
			entries: []registration{
				{pattern: "a.test/foo/{name}/baz", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}},
				{pattern: "a.test/foo/{id}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}},
				{pattern: "a.test/foo/{id}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"e", "f"}}},
				{pattern: "a.test/foo/+{any}", matchers: []RequestMatcher{QueryMatcher{"a", "b"}}},
			},
			host:     "a.test",
			target:   "/foo/bar/baz?a=b",
			want:     "a.test/foo/+{any}",
			matchers: 1,
			params:   []Param{{Key: "any", Value: "bar/baz"}},
		},
		{
			name: "any host pattern with matchers after a hostname miss",
			entries: []registration{
				{pattern: "example.com/foo/bar/baz"},
				{pattern: "+{any}/foo/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}},
			},
			host:     "example.com",
			target:   "/foo/bar?a=b&c=d",
			want:     "+{any}/foo/bar",
			matchers: 2,
			params:   []Param{{Key: "any", Value: "example.com"}},
		},
		{
			name: "any host pattern with matchers after a hostname param backtrack",
			entries: []registration{
				{pattern: "example.com/{name}/bar/baz"},
				{pattern: "+{any}/foo/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}},
			},
			host:     "example.com",
			target:   "/foo/bar?a=b&c=d",
			want:     "+{any}/foo/bar",
			matchers: 2,
			params:   []Param{{Key: "any", Value: "example.com"}},
		},
		{
			name: "match with the same query matcher twice",
			entries: []registration{
				{pattern: "example.com/{name}/bar/baz"},
				{pattern: "+{any}/foo/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"a", "b"}}},
			},
			host:     "example.com",
			target:   "/foo/bar?a=b",
			want:     "+{any}/foo/bar",
			matchers: 2,
			params:   []Param{{Key: "any", Value: "example.com"}},
		},
		{
			name: "match many query matchers",
			entries: []registration{
				{pattern: "example.com/{name}/bar/baz"},
				{pattern: "+{any}/foo/bar", matchers: []RequestMatcher{
					QueryMatcher{"a", "b"},
					QueryMatcher{"c", "d"},
					QueryMatcher{"e", "f"},
					QueryMatcher{"g", "h"},
					QueryMatcher{"i", "j"},
					QueryMatcher{"k", "l"},
				}},
			},
			host:     "example.com",
			target:   "/foo/bar?e=f&k=l&a=b&c=d&g=h&i=j",
			want:     "+{any}/foo/bar",
			matchers: 6,
			params:   []Param{{Key: "any", Value: "example.com"}},
		},
		{
			name: "relaxed match after failing every entry of one level",
			entries: []registration{
				{pattern: "example.com/{name}/bar/"},
				{pattern: "+{any}/{id}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}}},
				{pattern: "+{any}/{id}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}},
				{pattern: "+{any}/{id}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}, QueryMatcher{"e", "f"}}},
			},
			host:    "example.com",
			target:  "/foo/bar?a=a&c=d&e=f",
			want:    "example.com/{name}/bar/",
			relaxed: true,
			params:  []Param{{Key: "name", Value: "foo"}},
		},
		{
			name: "fallback to most specific hostname with wildcard, regexp priority and matchers",
			entries: []registration{
				{pattern: "{a:.*}.{b:.*}.+{c:.*}/john/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}}},
				{pattern: "+{a:[A-z]+}.b.c/{path}/bar/", matchers: []RequestMatcher{QueryMatcher{"d", "e"}}},
				{pattern: "+{a:foo}.{b}.c/{d}/bar"},
				{pattern: "+{any}/{a:^$}/bar"},
			},
			host:   "foo.b.c",
			target: "/john/bar?b=c",
			want:   "+{a:foo}.{b}.c/{d}/bar",
			params: []Param{{Key: "a", Value: "foo"}, {Key: "b", Value: "b"}, {Key: "d", Value: "john"}},
		},
		{
			name: "match most specific hostname with wildcard, regexp priority and matchers",
			entries: []registration{
				{pattern: "{a:.*}.{b:.*}.+{c:.*}/john/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}}},
				{pattern: "+{a:foo}.{b}.c/{d}/bar/baz"},
				{pattern: "+{a:[A-z]+}.b.c/{path}/bar", matchers: []RequestMatcher{QueryMatcher{"b", "c"}}},
				{pattern: "+{any}/{a:^$}/bar"},
			},
			host:     "foo.b.c",
			target:   "/john/bar?b=c",
			want:     "+{a:[A-z]+}.b.c/{path}/bar",
			matchers: 1,
			params:   []Param{{Key: "a", Value: "foo"}, {Key: "path", Value: "john"}},
		},
		{
			name: "fallback to any host pattern with wildcard, regexp priority and matchers",
			entries: []registration{
				{pattern: "{a:.*}.{b:.*}.+{c:.*}/john/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}}},
				{pattern: "+{a:foo}.{b}.c/{d}/bar/", matchers: []RequestMatcher{QueryMatcher{"d", "f"}}},
				{pattern: "+{a:[A-z]+}.b.c/{path}/bar", matchers: []RequestMatcher{QueryMatcher{"e", "f"}}},
				{pattern: "+{any}/{a:.*}/bar"},
			},
			host:   "foo.b.c",
			target: "/john/bar?b=c",
			want:   "+{any}/{a:.*}/bar",
			params: []Param{{Key: "any", Value: "foo.b.c"}, {Key: "a", Value: "john"}},
		},
		{
			name: "most matchers first",
			entries: []registration{
				{pattern: "a.test/{name}/bar"},
				{pattern: "a.test/{name}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}}},
				{pattern: "a.test/{id}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}},
				{pattern: "a.test/{foo}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}, QueryMatcher{"e", "f"}}},
			},
			host:     "a.test",
			target:   "/john/bar?a=b&c=d&e=f",
			want:     "a.test/{foo}/bar",
			matchers: 3,
			params:   []Param{{Key: "foo", Value: "john"}},
		},
		{
			name: "second most matchers after a failing one",
			entries: []registration{
				{pattern: "a.test/{name}/bar"},
				{pattern: "a.test/{name}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}}},
				{pattern: "a.test/{id}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}},
				{pattern: "a.test/{foo}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}, QueryMatcher{"e", "f"}}},
			},
			host:     "a.test",
			target:   "/john/bar?a=b&c=d&e=g",
			want:     "a.test/{id}/bar",
			matchers: 2,
			params:   []Param{{Key: "id", Value: "john"}},
		},
		{
			name: "entry without matcher after every narrowed one fails",
			entries: []registration{
				{pattern: "a.test/{four}/bar"},
				{pattern: "a.test/{third}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}}},
				{pattern: "a.test/{second}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}},
				{pattern: "a.test/{first}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}, QueryMatcher{"e", "f"}}},
			},
			host:   "a.test",
			target: "/john/bar?a=g&c=d&e=g",
			want:   "a.test/{four}/bar",
			params: []Param{{Key: "four", Value: "john"}},
		},
		{
			name: "priority before the number of matchers",
			entries: []registration{
				{pattern: "a.test/{four}/bar"},
				{pattern: "a.test/{third}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}}, priority: 1000},
				{pattern: "a.test/{second}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}},
				{pattern: "a.test/{first}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}, QueryMatcher{"e", "f"}}},
			},
			host:     "a.test",
			target:   "/john/bar?a=b&c=d&e=f",
			want:     "a.test/{third}/bar",
			matchers: 1,
			params:   []Param{{Key: "third", Value: "john"}},
		},
		{
			name: "next priority after a failing priority entry",
			entries: []registration{
				{pattern: "a.test/{four}/bar"},
				{pattern: "a.test/{third}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "f"}}, priority: 1000},
				{pattern: "a.test/{second}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}}, priority: 500},
				{pattern: "a.test/{first}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}, QueryMatcher{"e", "f"}}},
			},
			host:     "a.test",
			target:   "/john/bar?a=b&c=d&e=f",
			want:     "a.test/{second}/bar",
			matchers: 2,
			params:   []Param{{Key: "second", Value: "john"}},
		},
		{
			name: "lowest priority after every higher one fails",
			entries: []registration{
				{pattern: "a.test/{four}/bar"},
				{pattern: "a.test/{third}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "f"}}, priority: 1000},
				{pattern: "a.test/{second}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "f"}}, priority: 500},
				{pattern: "a.test/{first}/bar", matchers: []RequestMatcher{QueryMatcher{"a", "b"}, QueryMatcher{"c", "d"}, QueryMatcher{"e", "f"}}, priority: 250},
			},
			host:     "a.test",
			target:   "/john/bar?a=b&c=d&e=f",
			want:     "a.test/{first}/bar",
			matchers: 3,
			params:   []Param{{Key: "first", Value: "john"}},
		},
		{
			name:     "matcher passes on a relaxed candidate",
			entries:  []registration{{pattern: "a.test/foo/", matchers: []RequestMatcher{QueryMatcher{"mode", "beta"}}}},
			host:     "a.test",
			target:   "/foo?mode=beta",
			want:     "a.test/foo/",
			relaxed:  true,
			matchers: 1,
		},
		{
			name:    "matcher refuses a relaxed candidate",
			entries: []registration{{pattern: "a.test/foo/", matchers: []RequestMatcher{QueryMatcher{"mode", "beta"}}}},
			host:    "a.test",
			target:  "/foo",
		},
		{
			name: "matcher refusing a relaxed candidate reopens a lower priority direct match",
			entries: []registration{
				{pattern: "a.test/foo/", matchers: []RequestMatcher{QueryMatcher{"mode", "beta"}}},
				{pattern: "a.test/{a}"},
			},
			host:   "a.test",
			target: "/foo",
			want:   "a.test/{a}",
			params: []Param{{Key: "a", Value: "foo"}},
		},
		{
			name: "relaxed candidate passing its matcher keeps priority over a direct match",
			entries: []registration{
				{pattern: "a.test/foo/", matchers: []RequestMatcher{QueryMatcher{"mode", "beta"}}},
				{pattern: "a.test/{a}"},
			},
			host:     "a.test",
			target:   "/foo?mode=beta",
			want:     "a.test/foo/",
			relaxed:  true,
			matchers: 1,
		},
		{
			name: "narrowed entry first on a shared relaxed candidate",
			entries: []registration{
				{pattern: "a.test/foo/", matchers: []RequestMatcher{QueryMatcher{"mode", "beta"}}},
				{pattern: "a.test/foo/"},
			},
			host:     "a.test",
			target:   "/foo?mode=beta",
			want:     "a.test/foo/",
			relaxed:  true,
			matchers: 1,
		},
		{
			name: "fallback entry on a shared relaxed candidate",
			entries: []registration{
				{pattern: "a.test/foo/", matchers: []RequestMatcher{QueryMatcher{"mode", "beta"}}},
				{pattern: "a.test/foo/"},
			},
			host:    "a.test",
			target:  "/foo",
			want:    "a.test/foo/",
			relaxed: true,
		},
		{
			name:     "matcher passes on an empty catch-all candidate",
			entries:  []registration{{pattern: "a.test/foo/*{x}", matchers: []RequestMatcher{QueryMatcher{"mode", "beta"}}}},
			host:     "a.test",
			target:   "/foo?mode=beta",
			want:     "a.test/foo/*{x}",
			relaxed:  true,
			matchers: 1,
			params:   []Param{{Key: "x", Value: ""}},
		},
		{
			name:    "matcher refuses an empty catch-all candidate",
			entries: []registration{{pattern: "a.test/foo/*{x}", matchers: []RequestMatcher{QueryMatcher{"mode", "beta"}}}},
			host:    "a.test",
			target:  "/foo",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, slash := range []TrailingSlashOption{RelaxedSlash, ExactSlash} {
				p := testProxy(t, WithRegexpParam(true), WithDefaultTrailingSlash(slash))
				for _, r := range tc.entries {
					var opts []EntryOption[HTTP]
					if len(r.matchers) > 0 {
						opts = append(opts, WithRequestMatchers[HTTP](r.matchers...))
					}
					if r.priority > 0 {
						opts = append(opts, WithMatchersPriority[HTTP](r.priority))
					}
					p.MustAdd(r.pattern, noopHandler, opts...)
				}

				req := httptest.NewRequest(http.MethodGet, tc.target, nil)
				e, params := lookupOn(p, tc.host, routingPath(req), req, false)
				if slash == ExactSlash {
					if tc.relaxed {
						assert.NotEqual(t, tc.want, patternOf(e), "exact slash")
					} else {
						assert.Equal(t, tc.want, patternOf(e), "exact slash")
					}
					continue
				}
				require.Equal(t, tc.want, patternOf(e))
				if e != nil {
					assert.Len(t, e.matchers, tc.matchers)
				}
				assert.Equal(t, tc.params, params)
			}
		})
	}
}

func TestRouting_Encoding(t *testing.T) {
	cases := []struct {
		name     string
		patterns []string
		target   string
		want     string
		params   []Param
	}{
		{
			name:     "encoded request matches decoded pattern",
			patterns: []string{"a.test/users/john"},
			target:   "/users/j%6Fhn",
			want:     "a.test/users/john",
		},
		{
			name:     "raw utf8 request matches encoded pattern",
			patterns: []string{"a.test/caf%C3%A9"},
			target:   "https://a.test/café",
			want:     "a.test/caf%C3%A9",
		},
		{
			name:     "param captures decoded unreserved",
			patterns: []string{"a.test/users/{id}"},
			target:   "/users/j%6Fhn",
			want:     "a.test/users/{id}",
			params:   []Param{{Key: "id", Value: "john"}},
		},
		{
			name:     "param keeps reserved encoded",
			patterns: []string{"a.test/users/{id}"},
			target:   "/users/j%C3%A9r%C3%B4me",
			want:     "a.test/users/{id}",
			params:   []Param{{Key: "id", Value: "j%C3%A9r%C3%B4me"}},
		},
		{
			name:     "lowercase hex captured as uppercase",
			patterns: []string{"a.test/users/{id}"},
			target:   "/users/a%2fb",
			want:     "a.test/users/{id}",
			params:   []Param{{Key: "id", Value: "a%2Fb"}},
		},
		{
			name:     "wildcard captures mixed decoded and encoded",
			patterns: []string{"a.test/files/+{p}"},
			target:   "/files/a%2Fb/c%61t",
			want:     "a.test/files/+{p}",
			params:   []Param{{Key: "p", Value: "a%2Fb/cat"}},
		},
		{
			name:     "wildcard keeps an encoded slash",
			patterns: []string{"a.test/+{request}"},
			target:   "/run/cmd/S123L%2FA",
			want:     "a.test/+{request}",
			params:   []Param{{Key: "request", Value: "run/cmd/S123L%2FA"}},
		},
		{
			name:     "regexp evaluates decoded segment",
			patterns: []string{"a.test/n/{d:[0-9]+}"},
			target:   "/n/%31%32",
			want:     "a.test/n/{d:[0-9]+}",
			params:   []Param{{Key: "d", Value: "12"}},
		},
		{
			name:     "encoded slash stays distinct",
			patterns: []string{"a.test/a/b"},
			target:   "/a%2Fb",
		},
		{
			name:     "literal plus matches raw plus",
			patterns: []string{"a.test/emails/a+b"},
			target:   "/emails/a+b",
			want:     "a.test/emails/a+b",
		},
		{
			name:     "encoded plus does not match literal plus",
			patterns: []string{"a.test/emails/a+b"},
			target:   "/emails/a%2Bb",
		},
		{
			name:     "encoded plus pattern matches encoded plus request",
			patterns: []string{"a.test/emails/a%2Bb"},
			target:   "/emails/a%2Bb",
			want:     "a.test/emails/a%2Bb",
		},
		{
			name:     "literal star matches raw star",
			patterns: []string{"a.test/glob/*"},
			target:   "/glob/*",
			want:     "a.test/glob/*",
		},
		{
			name:     "raw star does not match encoded star pattern",
			patterns: []string{"a.test/star/%2A"},
			target:   "/star/*",
		},
		{
			name:     "encoded brace pattern matches raw brace request",
			patterns: []string{"a.test/brace/%7Bid%7D"},
			target:   "/brace/{id}",
			want:     "a.test/brace/%7Bid%7D",
		},
		{
			name:     "encoded dot segment does not reach a static pattern",
			patterns: []string{"a.test/foo/bar"},
			target:   "/foo/%2E%2E/bar",
		},
		{
			name:     "param captures decoded dots",
			patterns: []string{"a.test/foo/bar", "a.test/foo/{x}/bar"},
			target:   "/foo/%2E%2E/bar",
			want:     "a.test/foo/{x}/bar",
			params:   []Param{{Key: "x", Value: ".."}},
		},
		{
			name:     "param captures decoded lowercase dots",
			patterns: []string{"a.test/foo/{x}/bar"},
			target:   "/foo/%2e%2e/bar",
			want:     "a.test/foo/{x}/bar",
			params:   []Param{{Key: "x", Value: ".."}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := routingProxy(t, ExactSlash, tc.patterns...)
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			e, params := lookupOn(p, "a.test", routingPath(req), req, false)
			assert.Equal(t, tc.want, patternOf(e))
			assert.Equal(t, tc.params, params)
		})
	}
}

func TestRouting_RegexpAlternationIsAnchored(t *testing.T) {
	p := routingProxy(t, ExactSlash, "a.test/role/{role:admin|user|guest}", "a.test/scope/{scope:read|write}/items")

	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/role/admin", true},
		{"/role/user", true},
		{"/role/guest", true},
		{"/role/adminBYPASS", false},
		{"/role/EVILguest", false},
		{"/role/userX", false},
		{"/role/Xuser", false},
		{"/scope/read/items", true},
		{"/scope/write/items", true},
		{"/scope/readBYPASS/items", false},
		{"/scope/EVILwrite/items", false},
	} {
		e, _ := lookupOn(p, "a.test", tc.path, httptest.NewRequest(http.MethodGet, "/", nil), false)
		assert.Equal(t, tc.want, e != nil, tc.path)
	}
}

func TestRouting_GitHubAPI(t *testing.T) {
	p := testProxy(t)
	for _, r := range githubAPI {
		p.MustAdd("api.github.test"+r.path, noopHandler, WithMethods[HTTP](r.method))
	}
	assert.Equal(t, len(githubAPI), p.Len())

	braces := regexp.MustCompile(`\+?\{([A-z_]+)\}`)
	for _, r := range githubAPI {
		var want []Param
		for _, m := range braces.FindAllStringSubmatch(r.path, -1) {
			want = append(want, Param{Key: m[1], Value: "v-" + m[1]})
		}
		target := braces.ReplaceAllString(r.path, "v-$1")

		req := httptest.NewRequest(r.method, target, nil)
		e, params := lookupOn(p, "api.github.test", routingPath(req), req, false)
		require.NotNil(t, e, "%s %s", r.method, target)
		assert.Equal(t, "api.github.test"+r.path, e.pattern.str)
		assert.Equal(t, want, params, target)

		purge := httptest.NewRequest("PURGE", target, nil)
		e, _ = lookupOn(p, "api.github.test", routingPath(purge), purge, false)
		assert.Nil(t, e, "PURGE %s", target)
	}
}

func TestRouting_WildcardHostnames(t *testing.T) {
	p := testProxy(t)
	for _, r := range wildcardHostnames {
		p.MustAdd(r.path+"/foo", noopHandler, WithMethods[HTTP](r.method))
	}
	assert.Equal(t, len(wildcardHostnames), p.Len())

	braces := regexp.MustCompile(`\{([A-z_]+)\}`)
	for _, r := range wildcardHostnames {
		for _, host := range []string{r.path, strings.ToUpper(r.path)} {
			req := httptest.NewRequest(r.method, "/foo", nil)
			e, params := lookupOn(p, host, "/foo", req, false)
			require.NotNil(t, e, "%s %s", r.method, host)
			assert.Equal(t, r.path+"/foo", e.pattern.str)

			var want []Param
			for _, m := range braces.FindAllStringSubmatchIndex(r.path, -1) {
				want = append(want, Param{Key: r.path[m[2]:m[3]], Value: host[m[0]:m[1]]})
			}
			assert.Equal(t, want, params, host)
		}
	}
}

func TestRouting_LookupAllocs(t *testing.T) {
	p := testProxy(t)
	for _, r := range githubAPI {
		p.MustAdd("api.github.test"+r.path, noopHandler, WithMethods[HTTP](r.method))
	}
	for _, r := range wildcardHostnames {
		p.MustAdd(r.path+"/foo", noopHandler, WithMethods[HTTP](r.method))
	}

	braces := regexp.MustCompile(`\+?\{[^}]+\}`)
	tree := p.getTree()
	c := tree.pool.Get().(*routeCtx)
	defer tree.pool.Put(c)

	check := func(method, host, path string) {
		t.Helper()
		c.reset(nil, httptest.NewRequest(method, path, nil), "https", host, "443")
		allocs := testing.AllocsPerRun(100, func() {
			*c.params = (*c.params)[:0]
			if _, n := tree.lookup(host, path, c, false); n == nil {
				t.Fatalf("no match for %s %s%s", method, host, path)
			}
		})
		assert.Zero(t, allocs, "%s %s%s", method, host, path)
	}
	for _, r := range githubAPI {
		check(r.method, "api.github.test", braces.ReplaceAllString(r.path, "xxx"))
	}
	for _, r := range wildcardHostnames {
		check(r.method, braces.ReplaceAllString(r.path, "xxx"), "/foo")
	}
}

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

func TestRouting_StaticPathBeatsSchemeQualifiedParam(t *testing.T) {
	p := testProxy(t)
	static := p.MustAdd("api.stripe.com/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))
	p.MustAdd("api.stripe.com/v1/{id}", noopHandler, WithScheme[HTTP]("https"), WithMethods[HTTP](http.MethodGet))

	// The scheme is a matcher rather than a tree edge precisely so it cannot promote a
	// parameter above a static segment.
	assert.Equal(t, static, match(t, p, http.MethodGet, "https", "api.stripe.com:443", "/v1/charges"))
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

func TestRouting_RejectsConnect(t *testing.T) {
	p := testProxy(t)
	_, err := p.Add("api.stripe.com/", noopHandler, WithMethods[HTTP](http.MethodConnect))
	require.ErrorIs(t, err, ErrInvalidMatcher)
	assert.Contains(t, err.Error(), "establishes a connection")
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

func TestRouting_HostnameSwitchDuringLookups(t *testing.T) {
	p := testProxy(t)
	ab, err := MatchQuery("a", "b")
	require.NoError(t, err)
	cd, err := MatchQuery("c", "d")
	require.NoError(t, err)

	family := func(txn *Txn, host string) error {
		for _, r := range githubAPI {
			name := r.method + ":" + host + r.path
			for i, m := range [][]RequestMatcher{nil, {ab}, {cd}} {
				opts := []EntryOption[HTTP]{WithMethods[HTTP](r.method), WithName[HTTP](fmt.Sprint(name, ":", i))}
				if m != nil {
					opts = append(opts, WithRequestMatchers[HTTP](m...))
				}
				if _, err := txn.Add(host+r.path, noopHandler, opts...); err != nil {
					return err
				}
			}
		}
		return nil
	}
	toggle := func(host string) error {
		return p.Updates(func(txn *Txn) error {
			if !txn.Has[HTTP](host+githubAPI[0].path, mustMethods(githubAPI[0].method)) {
				return family(txn, host)
			}
			for _, r := range githubAPI {
				for _, m := range [][]RequestMatcher{nil, {ab}, {cd}} {
					opts := []MatcherOption[HTTP]{WithMethods[HTTP](r.method)}
					if m != nil {
						opts = append(opts, WithRequestMatchers[HTTP](m...))
					}
					if _, err := txn.Delete[HTTP](host+r.path, opts...); err != nil {
						return err
					}
				}
			}
			return nil
		})
	}
	require.NoError(t, p.Updates(func(txn *Txn) error { return family(txn, "+{any}") }))

	const rounds = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range rounds {
		for _, host := range []string{"{sub}.bar.{tld}", "foo.bar.baz"} {
			wg.Go(func() {
				<-start
				if err := toggle(host); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Go(func() {
			<-start
			for _, r := range githubAPI {
				req := httptest.NewRequest(r.method, r.path, nil)
				if e, _ := lookupOn(p, "foo.bar.baz", r.path, req, false); e == nil {
					t.Errorf("%s foo.bar.baz%s: no entry", r.method, r.path)
					return
				}
			}
		})
	}
	close(start)
	wg.Wait()

	tree := p.getTree()
	assert.Equal(t, 3*len(githubAPI), tree.handlers)
	assert.Equal(t, 1, tree.admissions)
	assert.Equal(t, 3*len(githubAPI), iterutil.Len(p.Iter().Names()))
	assert.Len(t, tree.patterns.wildcards, 1)
	assert.Empty(t, tree.patterns.statics)
	assert.Empty(t, tree.patterns.params)
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

func assertEmptyTree(t *testing.T, p *Proxy) {
	t.Helper()
	tree := p.getTree()
	for _, root := range []*node{tree.patterns, tree.addrs, tree.names} {
		assert.Empty(t, root.statics)
		assert.Empty(t, root.params)
		assert.Empty(t, root.wildcards)
	}
	assert.Zero(t, tree.handlers)
	assert.Zero(t, tree.admissions)
}

func TestTree_InsertUpdateDelete(t *testing.T) {
	cases := []struct {
		name     string
		patterns []string
	}{
		{
			name:     "delete with merge",
			patterns: []string{"a.b.c/foo/bar", "a.b.c.d/foo/bar", "a.b.c{d}/foo/bar", "a.b/"},
		},
		{
			name: "delete with merge beside any host patterns",
			patterns: []string{
				"a.b.c/f",
				"a.b.c.d/foo/bar",
				"a.b.c.d/f",
				"a.b.c.d/fox",
				"a.b.c{d}/fox/bar",
				"a.e.c{d}/fox/bar",
				"+{any}/johnny",
				"+{any}/j",
				"+{any}/x",
				"a.b/",
			},
		},
		{
			name:     "delete with merge of three hostnames",
			patterns: []string{"a.b.c/foo/bar", "a.b.c.d/foo/bar", "a.b.c{d}/foo/bar"},
		},
		{
			name:     "delete with merge of two hostnames",
			patterns: []string{"a.b.c/foo/bar", "a.b.c{d}/foo/bar"},
		},
		{
			name:     "one hostname",
			patterns: []string{"a.x.x/"},
		},
		{
			name:     "two hostnames",
			patterns: []string{"a.x.x/", "a.x.y/"},
		},
		{
			name:     "hostnames prefix of one another",
			patterns: []string{"aaa/", "aaab/", "aaabc/"},
		},
		{
			name:     "delete with merge of paths and hostnames",
			patterns: []string{"a.b.c/foo/bar", "a.b.c/foo/ba", "a.b.c/foo", "a.b.c/x", "a.b.c.d/foo/bar", "a.b.c{d}/foo/bar"},
		},
		{
			name:     "mixed path wildcards",
			patterns: []string{"a.test/+{args}", "a.test/+{a}/b/+{c}/f", "a.test/+{a}/b/+{l}/g/", "a.test/+{a}/b/+{x}/e", "a.test/+{a}/b/+{c}/d/"},
		},
		{
			name:     "addresses and ranges",
			patterns: []string{"[10.0.0.0/8]/api", "[10.0.0.0/16]/api", "10.0.0.1/api", "10.0.0.1:8080/api", "[::1]/api", "[fd00::/8]/api"},
		},
		{
			name:     "ports on one hostname",
			patterns: []string{"a.test/api", "a.test:8080/api", "a.test:9090/api", "a.test:8080/api/v1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testProxy(t)
			for _, pattern := range tc.patterns {
				p.MustAdd(pattern, noopHandler, WithAnnotation[HTTP]("foo", "bar"))
			}
			for _, pattern := range tc.patterns {
				_, err := p.Update(pattern, noopHandler, WithAnnotation[HTTP]("foo", "baz"))
				require.NoError(t, err)
			}
			for i, pattern := range tc.patterns {
				deleted, err := p.Delete[HTTP](pattern)
				require.NoError(t, err)
				assert.Equal(t, pattern, deleted.Pattern())
				assert.False(t, p.Has[HTTP](pattern))
				for _, rest := range tc.patterns[i+1:] {
					e, ok := p.Lookup[HTTP](rest)
					require.True(t, ok, rest)
					assert.Equal(t, "baz", e.Annotation("foo"), rest)
				}
			}
			assertEmptyTree(t, p)

			require.NoError(t, p.Updates(func(txn *Txn) error {
				for _, pattern := range slices.Backward(tc.patterns) {
					if _, err := txn.Add(pattern, noopHandler); err != nil {
						return err
					}
				}
				for i, pattern := range slices.Backward(tc.patterns) {
					if _, err := txn.Delete[HTTP](pattern); err != nil {
						return err
					}
					for _, rest := range tc.patterns[:i] {
						assert.True(t, txn.Has[HTTP](rest), rest)
					}
				}
				return nil
			}))
			assertEmptyTree(t, p)
		})
	}
}

func TestTree_DeleteEveryPattern(t *testing.T) {
	for _, inTxn := range []bool{false, true} {
		t.Run(fmt.Sprintf("txn=%t", inTxn), func(t *testing.T) {
			p := testProxy(t)
			for _, r := range githubAPI {
				p.MustAdd("api.github.test"+r.path, noopHandler, WithMethods[HTTP](r.method))
			}
			for _, r := range wildcardHostnames {
				p.MustAdd(r.path+"/foo", noopHandler, WithMethods[HTTP](r.method))
			}

			type registered struct{ pattern, method string }
			var all []registered
			for _, r := range githubAPI {
				all = append(all, registered{"api.github.test" + r.path, r.method})
			}
			for _, r := range wildcardHostnames {
				all = append(all, registered{r.path + "/foo", r.method})
			}
			rand.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })

			del := func(txn *Txn) error {
				for _, r := range all {
					deleted, err := txn.Delete[HTTP](r.pattern, WithMethods[HTTP](r.method))
					if err != nil {
						return err
					}
					assert.Equal(t, r.pattern, deleted.Pattern())
				}
				return nil
			}
			if inTxn {
				require.NoError(t, p.Updates(del))
			} else {
				for _, r := range all {
					_, err := p.Delete[HTTP](r.pattern, WithMethods[HTTP](r.method))
					require.NoError(t, err, r.pattern)
				}
			}
			assertEmptyTree(t, p)
		})
	}
}

func TestTree_DeleteIsExact(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("a.test/foo/+{args}", noopHandler)

	_, err := p.Delete[HTTP]("a.test/foo")
	assert.ErrorIs(t, err, ErrEntryNotFound)
	_, err = p.Delete[HTTP]("a.test/foo/+{other}")
	assert.ErrorIs(t, err, ErrEntryNotFound)

	p.MustAdd("a.test/foo/{bar}", noopHandler)
	deleted, err := p.Delete[HTTP]("a.test/foo/{bar}")
	require.NoError(t, err)
	assert.Equal(t, "a.test/foo/{bar}", deleted.Pattern())
	assert.True(t, p.Has[HTTP]("a.test/foo/+{args}"))
}

func TestTree_AddConflict(t *testing.T) {
	cases := []struct {
		name      string
		patterns  []string
		insert    string
		conflicts []string
	}{
		{
			name:      "static pattern",
			patterns:  []string{"a.test/foo/bar", "a.test/foo/baz"},
			insert:    "a.test/foo/bar",
			conflicts: []string{"a.test/foo/bar"},
		},
		{
			name:      "same param",
			patterns:  []string{"a.test/foo/{foo}"},
			insert:    "a.test/foo/{foo}",
			conflicts: []string{"a.test/foo/{foo}"},
		},
		{
			name:      "same wildcard",
			patterns:  []string{"a.test/foo/+{foo}"},
			insert:    "a.test/foo/+{foo}",
			conflicts: []string{"a.test/foo/+{foo}"},
		},
		{
			name:      "param with another key",
			patterns:  []string{"a.test/foo/{foo}"},
			insert:    "a.test/foo/{bar}",
			conflicts: []string{"a.test/foo/{foo}"},
		},
		{
			name:      "wildcard with another key",
			patterns:  []string{"a.test/foo/+{foo}"},
			insert:    "a.test/foo/+{bar}",
			conflicts: []string{"a.test/foo/+{foo}"},
		},
		{
			name:      "infix param with another key",
			patterns:  []string{"a.test/{foo}/bar"},
			insert:    "a.test/{other}/bar",
			conflicts: []string{"a.test/{foo}/bar"},
		},
		{
			name:      "infix wildcard with another key",
			patterns:  []string{"a.test/+{foo}/bar"},
			insert:    "a.test/+{other}/bar",
			conflicts: []string{"a.test/+{foo}/bar"},
		},
		{
			name:      "same regexp param",
			patterns:  []string{"a.test/foo/{foo:[A-z]+}"},
			insert:    "a.test/foo/{foo:[A-z]+}",
			conflicts: []string{"a.test/foo/{foo:[A-z]+}"},
		},
		{
			name:      "regexp param with another key",
			patterns:  []string{"a.test/foo/{foo:[A-z]+}"},
			insert:    "a.test/foo/{bar:[A-z]+}",
			conflicts: []string{"a.test/foo/{foo:[A-z]+}"},
		},
		{
			name:      "same regexp wildcard",
			patterns:  []string{"a.test/foo/+{foo:[A-z]+}"},
			insert:    "a.test/foo/+{foo:[A-z]+}",
			conflicts: []string{"a.test/foo/+{foo:[A-z]+}"},
		},
		{
			name:      "regexp wildcard with another key",
			patterns:  []string{"a.test/foo/+{foo:[A-z]+}"},
			insert:    "a.test/foo/+{bar:[A-z]+}",
			conflicts: []string{"a.test/foo/+{foo:[A-z]+}"},
		},
		{
			name:      "infix regexp param with another key",
			patterns:  []string{"a.test/{foo:[A-z]+}/bar"},
			insert:    "a.test/{other:[A-z]+}/bar",
			conflicts: []string{"a.test/{foo:[A-z]+}/bar"},
		},
		{
			name:      "infix regexp wildcard with another key",
			patterns:  []string{"a.test/+{foo:[A-z]+}/bar"},
			insert:    "a.test/+{other:[A-z]+}/bar",
			conflicts: []string{"a.test/+{foo:[A-z]+}/bar"},
		},
		{
			name:      "hostname param with another key",
			patterns:  []string{"a.{b}.c/fox", "{a}.b.c/fox"},
			insert:    "a.{d}.c/fox",
			conflicts: []string{"a.{b}.c/fox"},
		},
		{
			name:      "same port",
			patterns:  []string{"a.test:8080/foo", "a.test/foo"},
			insert:    "a.test:8080/foo",
			conflicts: []string{"a.test:8080/foo"},
		},
		{
			name:      "same address",
			patterns:  []string{"10.0.0.1/foo"},
			insert:    "10.0.0.1/foo",
			conflicts: []string{"10.0.0.1/foo"},
		},
		{
			name:      "same range",
			patterns:  []string{"[10.0.0.0/8]/foo", "[10.0.0.0/16]/foo"},
			insert:    "[10.0.0.0/8]/foo",
			conflicts: []string{"[10.0.0.0/8]/foo"},
		},
		{
			name:     "another port",
			patterns: []string{"a.test:8080/foo", "a.test/foo"},
			insert:   "a.test:9090/foo",
		},
		{
			name:     "another prefix length",
			patterns: []string{"[10.0.0.0/8]/foo", "10.0.0.1/foo"},
			insert:   "[10.0.0.0/16]/foo",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := routingProxy(t, ExactSlash, tc.patterns...)
			_, err := p.Add(tc.insert, noopHandler)
			if tc.conflicts == nil {
				require.NoError(t, err)
				return
			}
			var conflict *EntryConflictError
			require.ErrorAs(t, err, &conflict)
			var got []string
			for _, e := range conflict.Conflicts {
				got = append(got, e.pattern.str)
			}
			assert.Equal(t, tc.conflicts, got)
		})
	}

	t.Run("entries differing by a matcher", func(t *testing.T) {
		p := testProxy(t)
		p.MustAdd("a.test/foo", noopHandler, WithMethods[HTTP](http.MethodGet))
		_, err := p.Add("a.test/foo", noopHandler, WithScheme[HTTP]("https"), WithMethods[HTTP](http.MethodGet))
		require.NoError(t, err)
		_, err = p.Add("a.test/foo", noopHandler, WithMethods[HTTP](http.MethodGet))
		require.ErrorAs(t, err, new(*EntryConflictError))
	})

	t.Run("entries differing by kind", func(t *testing.T) {
		p := testProxy(t)
		p.MustAdd("a.test/foo", noopHandler)
		_, err := p.Add("a.test/foo", relayFrames)
		require.NoError(t, err)
	})
}

func TestTree_OptionalCatchAllConflict(t *testing.T) {
	a, err := MatchQuery("a", "1")
	require.NoError(t, err)
	b, err := MatchQuery("b", "1")
	require.NoError(t, err)
	get := WithMethods[HTTP](http.MethodGet)
	post := WithMethods[HTTP](http.MethodPost)

	cases := []struct {
		name       string
		first      string
		firstOpts  []EntryOption[HTTP]
		second     string
		secondOpts []EntryOption[HTTP]
		conflict   bool
	}{
		{
			name:     "exact first",
			first:    "a.test/foo/",
			second:   "a.test/foo/*{x}",
			conflict: true,
		},
		{
			name:     "catch-all first",
			first:    "a.test/foo/*{x}",
			second:   "a.test/foo/",
			conflict: true,
		},
		{
			name:       "exact without matcher before a narrowed catch-all",
			first:      "a.test/foo/",
			second:     "a.test/foo/*{x}",
			secondOpts: []EntryOption[HTTP]{WithRequestMatchers[HTTP](b)},
			conflict:   true,
		},
		{
			name:      "narrowed catch-all before an exact without matcher",
			first:     "a.test/foo/*{x}",
			firstOpts: []EntryOption[HTTP]{WithRequestMatchers[HTTP](b)},
			second:    "a.test/foo/",
			conflict:  true,
		},
		{
			name:       "exact matchers included in the catch-all matchers",
			first:      "a.test/foo/",
			firstOpts:  []EntryOption[HTTP]{WithRequestMatchers[HTTP](a)},
			second:     "a.test/foo/*{x}",
			secondOpts: []EntryOption[HTTP]{WithRequestMatchers[HTTP](a, b)},
			conflict:   true,
		},
		{
			name:       "catch-all first with exact matchers included in its own",
			first:      "a.test/foo/*{x}",
			firstOpts:  []EntryOption[HTTP]{WithRequestMatchers[HTTP](b, a)},
			second:     "a.test/foo/",
			secondOpts: []EntryOption[HTTP]{WithRequestMatchers[HTTP](a)},
			conflict:   true,
		},
		{
			name:       "method included in the catch-all matchers",
			first:      "a.test/foo/",
			firstOpts:  []EntryOption[HTTP]{get},
			second:     "a.test/foo/*{x}",
			secondOpts: []EntryOption[HTTP]{get, WithRequestMatchers[HTTP](b)},
			conflict:   true,
		},
		{
			name:       "equal matchers",
			first:      "a.test/foo/",
			firstOpts:  []EntryOption[HTTP]{WithRequestMatchers[HTTP](a)},
			second:     "a.test/foo/*{x}",
			secondOpts: []EntryOption[HTTP]{WithRequestMatchers[HTTP](a)},
			conflict:   true,
		},
		{
			name:       "exact without matcher before a catch-all with a method",
			first:      "a.test/foo/",
			second:     "a.test/foo/*{x}",
			secondOpts: []EntryOption[HTTP]{get},
			conflict:   true,
		},
		{
			name:       "disjoint matchers",
			first:      "a.test/foo/",
			firstOpts:  []EntryOption[HTTP]{WithRequestMatchers[HTTP](a)},
			second:     "a.test/foo/*{x}",
			secondOpts: []EntryOption[HTTP]{WithRequestMatchers[HTTP](b)},
		},
		{
			name:       "disjoint methods",
			first:      "a.test/foo/",
			firstOpts:  []EntryOption[HTTP]{get},
			second:     "a.test/foo/*{x}",
			secondOpts: []EntryOption[HTTP]{post},
		},
		{
			name:      "exact with a method before a catch-all without matcher",
			first:     "a.test/foo/",
			firstOpts: []EntryOption[HTTP]{get},
			second:    "a.test/foo/*{x}",
		},
		{
			name:       "catch-all without matcher before an exact with a method",
			first:      "a.test/foo/*{x}",
			second:     "a.test/foo/",
			secondOpts: []EntryOption[HTTP]{get},
		},
		{
			name:   "another port",
			first:  "a.test:8080/foo/",
			second: "a.test/foo/*{x}",
		},
		{
			name:     "same port",
			first:    "a.test:8080/foo/",
			second:   "a.test:8080/foo/*{x}",
			conflict: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testProxy(t)
			p.MustAdd(tc.first, noopHandler, tc.firstOpts...)
			_, err := p.Add(tc.second, noopHandler, tc.secondOpts...)
			if tc.conflict {
				require.ErrorAs(t, err, new(*EntryConflictError))
				return
			}
			require.NoError(t, err)
		})
	}

	t.Run("another kind", func(t *testing.T) {
		p := testProxy(t)
		p.MustAdd("a.test/foo/", noopHandler)
		_, err := p.Add("a.test/foo/*{x}", relayFrames)
		require.NoError(t, err)
	})
}

func TestTree_Update(t *testing.T) {
	cases := []struct {
		name     string
		patterns []string
		update   string
		found    bool
	}{
		{
			name:     "ending static node",
			patterns: []string{"a.test/foo/", "a.test/foo/bar", "a.test/foo/baz"},
			update:   "a.test/foo/bar",
			found:    true,
		},
		{
			name:     "middle static node",
			patterns: []string{"a.test/foo/", "a.test/foo/bar", "a.test/foo/baz"},
			update:   "a.test/foo/",
			found:    true,
		},
		{
			name:     "ending param node",
			patterns: []string{"a.test/foo/", "a.test/foo/bar", "a.test/foo/{baz}"},
			update:   "a.test/foo/{baz}",
			found:    true,
		},
		{
			name:     "ending inflight param node",
			patterns: []string{"a.test/foo/", "a.test/foo/bar_xyz", "a.test/foo/bar_{baz}"},
			update:   "a.test/foo/bar_{baz}",
			found:    true,
		},
		{
			name:     "middle param node",
			patterns: []string{"a.test/foo/{bar}", "a.test/foo/{bar}/baz", "a.test/foo/{bar}/xyz"},
			update:   "a.test/foo/{bar}",
			found:    true,
		},
		{
			name:     "middle inflight param node",
			patterns: []string{"a.test/foo/id:{bar}", "a.test/foo/id:{bar}/baz", "a.test/foo/id:{bar}/xyz"},
			update:   "a.test/foo/id:{bar}",
			found:    true,
		},
		{
			name:     "catch-all node",
			patterns: []string{"a.test/foo/+{bar}", "a.test/foo", "a.test/foo/bar"},
			update:   "a.test/foo/+{bar}",
			found:    true,
		},
		{
			name:     "infix catch-all node",
			patterns: []string{"a.test/foo/+{bar}/baz", "a.test/foo", "a.test/foo/bar"},
			update:   "a.test/foo/+{bar}/baz",
			found:    true,
		},
		{
			name:     "infix inflight catch-all node",
			patterns: []string{"a.test/foo/abc+{bar}/baz", "a.test/foo", "a.test/foo/abc{bar}"},
			update:   "a.test/foo/abc+{bar}/baz",
			found:    true,
		},
		{
			name:     "param with another key",
			patterns: []string{"a.test/foo/{bar}"},
			update:   "a.test/foo/{baz}",
		},
		{
			name:     "catch-all over a param",
			patterns: []string{"a.test/foo/{bar}"},
			update:   "a.test/foo/+{baz}",
		},
		{
			name:     "node that is not a leaf",
			patterns: []string{"a.test/foo/bar/baz"},
			update:   "a.test/foo/bar",
		},
		{
			name:     "catch-all with another key",
			patterns: []string{"a.test/foo/bar", "a.test/foo/+{args}"},
			update:   "a.test/foo/+{all}",
		},
		{
			name:     "catch-all over a static",
			patterns: []string{"a.test/foo/bar", "a.test/foo/"},
			update:   "a.test/foo/+{all}",
		},
		{
			name:     "static over a catch-all",
			patterns: []string{"a.test/foo/bar", "a.test/foo/+{args}"},
			update:   "a.test/foo/",
		},
		{
			name:     "another port",
			patterns: []string{"a.test:8080/foo"},
			update:   "a.test/foo",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := routingProxy(t, ExactSlash, tc.patterns...)
			e, err := p.Update(tc.update, noopHandler, WithAnnotation[HTTP]("updated", true))
			if !tc.found {
				require.ErrorIs(t, err, ErrEntryNotFound)
				assert.Zero(t, e)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, len(tc.patterns), p.Len())
			got, ok := p.Lookup[HTTP](tc.update)
			require.True(t, ok)
			assert.Equal(t, true, got.Annotation("updated"))
		})
	}
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

// From https://github.com/julienschmidt/go-http-routing-benchmark
var githubAPI = []struct{ method, path string }{
	{"GET", "/authorizations"},
	{"GET", "/authorizations/{id}"},
	{"POST", "/authorizations"},
	{"DELETE", "/authorizations/{id}"},
	{"GET", "/applications/{client_id}/tokens/{access_token}"},
	{"DELETE", "/applications/{client_id}/tokens"},
	{"DELETE", "/applications/{client_id}/tokens/{access_token}"},
	{"GET", "/events"},
	{"GET", "/repos/{owner}/{repo}/events"},
	{"GET", "/networks/{owner}/{repo}/events"},
	{"GET", "/orgs/{org}/events"},
	{"GET", "/users/{user}/received_events"},
	{"GET", "/users/{user}/received_events/public"},
	{"GET", "/users/{user}/events"},
	{"GET", "/users/{user}/events/public"},
	{"GET", "/users/{user}/events/orgs/{org}"},
	{"GET", "/feeds"},
	{"GET", "/notifications"},
	{"GET", "/repos/{owner}/{repo}/notifications"},
	{"PUT", "/notifications"},
	{"PUT", "/repos/{owner}/{repo}/notifications"},
	{"GET", "/notifications/threads/{id}"},
	{"GET", "/notifications/threads/{id}/subscription"},
	{"PUT", "/notifications/threads/{id}/subscription"},
	{"DELETE", "/notifications/threads/{id}/subscription"},
	{"GET", "/repos/{owner}/{repo}/stargazers"},
	{"GET", "/users/{user}/starred"},
	{"GET", "/user/starred"},
	{"GET", "/user/starred/{owner}/{repo}"},
	{"PUT", "/user/starred/{owner}/{repo}"},
	{"DELETE", "/user/starred/{owner}/{repo}"},
	{"GET", "/repos/{owner}/{repo}/subscribers"},
	{"GET", "/users/{user}/subscriptions"},
	{"GET", "/user/subscriptions"},
	{"GET", "/repos/{owner}/{repo}/subscription"},
	{"PUT", "/repos/{owner}/{repo}/subscription"},
	{"DELETE", "/repos/{owner}/{repo}/subscription"},
	{"GET", "/user/subscriptions/{owner}/{repo}"},
	{"PUT", "/user/subscriptions/{owner}/{repo}"},
	{"DELETE", "/user/subscriptions/{owner}/{repo}"},
	{"GET", "/users/{user}/gists"},
	{"GET", "/gists"},
	{"GET", "/gists/{id}"},
	{"POST", "/gists"},
	{"PUT", "/gists/{id}/star"},
	{"DELETE", "/gists/{id}/star"},
	{"GET", "/gists/{id}/star"},
	{"POST", "/gists/{id}/forks"},
	{"DELETE", "/gists/{id}"},
	{"GET", "/repos/{owner}/{repo}/git/blobs/{sha}"},
	{"POST", "/repos/{owner}/{repo}/git/blobs"},
	{"GET", "/repos/{owner}/{repo}/git/commits/{sha}"},
	{"POST", "/repos/{owner}/{repo}/git/commits"},
	{"GET", "/repos/{owner}/{repo}/git/refs/+{ref}"},
	{"GET", "/repos/{owner}/{repo}/git/refs"},
	{"POST", "/repos/{owner}/{repo}/git/refs"},
	{"DELETE", "/repos/{owner}/{repo}/git/refs/+{ref}"},
	{"GET", "/repos/{owner}/{repo}/git/tags/{sha}"},
	{"POST", "/repos/{owner}/{repo}/git/tags"},
	{"GET", "/repos/{owner}/{repo}/git/trees/{sha}"},
	{"POST", "/repos/{owner}/{repo}/git/trees"},
	{"GET", "/issues"},
	{"GET", "/user/issues"},
	{"GET", "/orgs/{org}/issues"},
	{"GET", "/repos/{owner}/{repo}/issues"},
	{"GET", "/repos/{owner}/{repo}/issues/{number}"},
	{"POST", "/repos/{owner}/{repo}/issues"},
	{"GET", "/repos/{owner}/{repo}/assignees"},
	{"GET", "/repos/{owner}/{repo}/assignees/:assignee"},
	{"GET", "/repos/{owner}/{repo}/issues/{number}/comments"},
	{"POST", "/repos/{owner}/{repo}/issues/{number}/comments"},
	{"GET", "/repos/{owner}/{repo}/issues/{number}/events"},
	{"GET", "/repos/{owner}/{repo}/labels"},
	{"GET", "/repos/{owner}/{repo}/labels/{name}"},
	{"POST", "/repos/{owner}/{repo}/labels"},
	{"DELETE", "/repos/{owner}/{repo}/labels/{name}"},
	{"GET", "/repos/{owner}/{repo}/issues/{number}/labels"},
	{"POST", "/repos/{owner}/{repo}/issues/{number}/labels"},
	{"DELETE", "/repos/{owner}/{repo}/issues/{number}/labels/{name}"},
	{"PUT", "/repos/{owner}/{repo}/issues/{number}/labels"},
	{"DELETE", "/repos/{owner}/{repo}/issues/{number}/labels"},
	{"GET", "/repos/{owner}/{repo}/milestones/{number}/labels"},
	{"GET", "/repos/{owner}/{repo}/milestones"},
	{"GET", "/repos/{owner}/{repo}/milestones/{number}"},
	{"POST", "/repos/{owner}/{repo}/milestones"},
	{"DELETE", "/repos/{owner}/{repo}/milestones/{number}"},
	{"GET", "/emojis"},
	{"GET", "/gitignore/templates"},
	{"GET", "/gitignore/templates/{name}"},
	{"POST", "/markdown"},
	{"POST", "/markdown/raw"},
	{"GET", "/meta"},
	{"GET", "/rate_limit"},
	{"GET", "/users/{user}/orgs"},
	{"GET", "/user/orgs"},
	{"GET", "/orgs/{org}"},
	{"GET", "/orgs/{org}/members"},
	{"GET", "/orgs/{org}/members/{user}"},
	{"DELETE", "/orgs/{org}/members/{user}"},
	{"GET", "/orgs/{org}/public_members"},
	{"GET", "/orgs/{org}/public_members/{user}"},
	{"PUT", "/orgs/{org}/public_members/{user}"},
	{"DELETE", "/orgs/{org}/public_members/{user}"},
	{"GET", "/orgs/{org}/teams"},
	{"GET", "/teams/{id}"},
	{"POST", "/orgs/{org}/teams"},
	{"DELETE", "/teams/{id}"},
	{"GET", "/teams/{id}/members"},
	{"GET", "/teams/{id}/members/{user}"},
	{"PUT", "/teams/{id}/members/{user}"},
	{"DELETE", "/teams/{id}/members/{user}"},
	{"GET", "/teams/{id}/repos"},
	{"GET", "/teams/{id}/repos/{owner}/{repo}"},
	{"PUT", "/teams/{id}/repos/{owner}/{repo}"},
	{"DELETE", "/teams/{id}/repos/{owner}/{repo}"},
	{"GET", "/user/teams"},
	{"GET", "/repos/{owner}/{repo}/pulls"},
	{"GET", "/repos/{owner}/{repo}/pulls/{number}"},
	{"POST", "/repos/{owner}/{repo}/pulls"},
	{"GET", "/repos/{owner}/{repo}/pulls/{number}/commits"},
	{"GET", "/repos/{owner}/{repo}/pulls/{number}/files"},
	{"GET", "/repos/{owner}/{repo}/pulls/{number}/merge"},
	{"PUT", "/repos/{owner}/{repo}/pulls/{number}/merge"},
	{"GET", "/repos/{owner}/{repo}/pulls/{number}/comments"},
	{"PUT", "/repos/{owner}/{repo}/pulls/{number}/comments"},
	{"GET", "/user/repos"},
	{"GET", "/users/{user}/repos"},
	{"GET", "/orgs/{org}/repos"},
	{"GET", "/repositories"},
	{"POST", "/user/repos"},
	{"POST", "/orgs/{org}/repos"},
	{"GET", "/repos/{owner}/{repo}"},
	{"GET", "/repos/{owner}/{repo}/contributors"},
	{"GET", "/repos/{owner}/{repo}/languages"},
	{"GET", "/repos/{owner}/{repo}/teams"},
	{"GET", "/repos/{owner}/{repo}/tags"},
	{"GET", "/repos/{owner}/{repo}/branches"},
	{"GET", "/repos/{owner}/{repo}/branches/{branch}"},
	{"DELETE", "/repos/{owner}/{repo}"},
	{"GET", "/repos/{owner}/{repo}/collaborators"},
	{"GET", "/repos/{owner}/{repo}/collaborators/{user}"},
	{"PUT", "/repos/{owner}/{repo}/collaborators/{user}"},
	{"DELETE", "/repos/{owner}/{repo}/collaborators/{user}"},
	{"GET", "/repos/{owner}/{repo}/comments"},
	{"GET", "/repos/{owner}/{repo}/commits/{sha}/comments"},
	{"POST", "/repos/{owner}/{repo}/commits/{sha}/comments"},
	{"GET", "/repos/{owner}/{repo}/comments/{id}"},
	{"DELETE", "/repos/{owner}/{repo}/comments/{id}"},
	{"GET", "/repos/{owner}/{repo}/commits"},
	{"GET", "/repos/{owner}/{repo}/commits/{sha}"},
	{"GET", "/repos/{owner}/{repo}/readme"},
	{"GET", "/repos/{owner}/{repo}/contents/+{path}"},
	{"DELETE", "/repos/{owner}/{repo}/contents/+{path}"},
	{"GET", "/repos/{owner}/{repo}/keys"},
	{"GET", "/repos/{owner}/{repo}/keys/{id}"},
	{"POST", "/repos/{owner}/{repo}/keys"},
	{"DELETE", "/repos/{owner}/{repo}/keys/{id}"},
	{"GET", "/repos/{owner}/{repo}/downloads"},
	{"GET", "/repos/{owner}/{repo}/downloads/{id}"},
	{"DELETE", "/repos/{owner}/{repo}/downloads/{id}"},
	{"GET", "/repos/{owner}/{repo}/forks"},
	{"POST", "/repos/{owner}/{repo}/forks"},
	{"GET", "/repos/{owner}/{repo}/hooks"},
	{"GET", "/repos/{owner}/{repo}/hooks/{id}"},
	{"POST", "/repos/{owner}/{repo}/hooks"},
	{"POST", "/repos/{owner}/{repo}/hooks/{id}/tests"},
	{"DELETE", "/repos/{owner}/{repo}/hooks/{id}"},
	{"POST", "/repos/{owner}/{repo}/merges"},
	{"GET", "/repos/{owner}/{repo}/releases"},
	{"GET", "/repos/{owner}/{repo}/releases/{id}"},
	{"POST", "/repos/{owner}/{repo}/releases"},
	{"DELETE", "/repos/{owner}/{repo}/releases/{id}"},
	{"GET", "/repos/{owner}/{repo}/releases/{id}/assets"},
	{"GET", "/repos/{owner}/{repo}/stats/contributors"},
	{"GET", "/repos/{owner}/{repo}/stats/commit_activity"},
	{"GET", "/repos/{owner}/{repo}/stats/code_frequency"},
	{"GET", "/repos/{owner}/{repo}/stats/participation"},
	{"GET", "/repos/{owner}/{repo}/stats/punch_card"},
	{"GET", "/repos/{owner}/{repo}/statuses/{ref}"},
	{"POST", "/repos/{owner}/{repo}/statuses/{ref}"},
	{"GET", "/search/repositories"},
	{"GET", "/search/code"},
	{"GET", "/search/issues"},
	{"GET", "/search/users"},
	{"GET", "/legacy/issues/search/{owner}/{repository}/{state}/{keyword}"},
	{"GET", "/legacy/repos/search/{keyword}"},
	{"GET", "/legacy/user/search/{keyword}"},
	{"GET", "/legacy/user/email/{email}"},
	{"GET", "/users/{user}"},
	{"GET", "/user"},
	{"GET", "/users"},
	{"GET", "/user/emails"},
	{"POST", "/user/emails"},
	{"DELETE", "/user/emails"},
	{"GET", "/users/{user}/followers"},
	{"GET", "/user/followers"},
	{"GET", "/users/{user}/following"},
	{"GET", "/user/following"},
	{"GET", "/user/following/{user}"},
	{"GET", "/users/{user}/following/{target_user}"},
	{"PUT", "/user/following/{user}"},
	{"DELETE", "/user/following/{user}"},
	{"GET", "/users/{user}/keys"},
	{"GET", "/user/keys"},
	{"GET", "/user/keys/{id}"},
	{"POST", "/user/keys"},
	{"DELETE", "/user/keys/{id}"},
}

var wildcardHostnames = []struct{ method, path string }{
	{"GET", "authorizations"},
	{"GET", "authorizations.{id}"},
	{"POST", "authorizations"},
	{"DELETE", "authorizations.{id}"},
	{"GET", "applications.{client_id}.tokens.{access_token}"},
	{"DELETE", "applications.{client_id}.tokens"},
	{"DELETE", "applications.{client_id}.tokens.{access_token}"},
	{"GET", "events"},
	{"GET", "repos.{owner}.{repo}.events"},
	{"GET", "networks.{owner}.{repo}.events"},
	{"GET", "orgs.{org}.events"},
	{"GET", "users.{user}.received_events"},
	{"GET", "users.{user}.received_events.public"},
	{"GET", "users.{user}.events"},
	{"GET", "users.{user}.events.public"},
	{"GET", "users.{user}.events.orgs.{org}"},
	{"GET", "feeds"},
	{"GET", "notifications"},
	{"GET", "repos.{owner}.{repo}.notifications"},
	{"PUT", "notifications"},
	{"PUT", "repos.{owner}.{repo}.notifications"},
	{"GET", "notifications.threads.{id}"},
	{"GET", "notifications.threads.{id}.subscription"},
	{"PUT", "notifications.threads.{id}.subscription"},
	{"DELETE", "notifications.threads.{id}.subscription"},
	{"GET", "repos.{owner}.{repo}.stargazers"},
	{"GET", "users.{user}.starred"},
	{"GET", "user.starred"},
	{"GET", "user.starred.{owner}.{repo}"},
	{"PUT", "user.starred.{owner}.{repo}"},
	{"DELETE", "user.starred.{owner}.{repo}"},
	{"GET", "repos.{owner}.{repo}.subscribers"},
	{"GET", "users.{user}.subscriptions"},
	{"GET", "user.subscriptions"},
	{"GET", "repos.{owner}.{repo}.subscription"},
	{"PUT", "repos.{owner}.{repo}.subscription"},
	{"DELETE", "repos.{owner}.{repo}.subscription"},
	{"GET", "user.subscriptions.{owner}.{repo}"},
	{"PUT", "user.subscriptions.{owner}.{repo}"},
	{"DELETE", "user.subscriptions.{owner}.{repo}"},
	{"GET", "users.{user}.gists"},
	{"GET", "gists"},
	{"GET", "gists.{id}"},
	{"POST", "gists"},
	{"PUT", "gists.{id}.star"},
	{"DELETE", "gists.{id}.star"},
	{"GET", "gists.{id}.star"},
	{"POST", "gists.{id}.forks"},
	{"DELETE", "gists.{id}"},
	{"GET", "repos.{owner}.{repo}.git.blobs.{sha}"},
	{"POST", "repos.{owner}.{repo}.git.blobs"},
	{"GET", "repos.{owner}.{repo}.git.commits.{sha}"},
	{"POST", "repos.{owner}.{repo}.git.commits"},
	{"GET", "repos.{owner}.{repo}.git.refs.{ref}"},
	{"GET", "repos.{owner}.{repo}.git.refs"},
	{"POST", "repos.{owner}.{repo}.git.refs"},
	{"DELETE", "repos.{owner}.{repo}.git.refs.{ref}"},
	{"GET", "repos.{owner}.{repo}.git.tags.{sha}"},
	{"POST", "repos.{owner}.{repo}.git.tags"},
	{"GET", "repos.{owner}.{repo}.git.trees.{sha}"},
	{"POST", "repos.{owner}.{repo}.git.trees"},
	{"GET", "issues"},
	{"GET", "user.issues"},
	{"GET", "orgs.{org}.issues"},
	{"GET", "repos.{owner}.{repo}.issues"},
	{"GET", "repos.{owner}.{repo}.issues.{number}"},
	{"POST", "repos.{owner}.{repo}.issues"},
	{"GET", "repos.{owner}.{repo}.assignees"},
	{"GET", "repos.{owner}.{repo}.assignees.assignee"},
	{"GET", "repos.{owner}.{repo}.issues.{number}.comments"},
	{"POST", "repos.{owner}.{repo}.issues.{number}.comments"},
	{"GET", "repos.{owner}.{repo}.issues.{number}.events"},
	{"GET", "repos.{owner}.{repo}.labels"},
	{"GET", "repos.{owner}.{repo}.labels.{name}"},
	{"POST", "repos.{owner}.{repo}.labels"},
	{"DELETE", "repos.{owner}.{repo}.labels.{name}"},
	{"GET", "repos.{owner}.{repo}.issues.{number}.labels"},
	{"POST", "repos.{owner}.{repo}.issues.{number}.labels"},
	{"DELETE", "repos.{owner}.{repo}.issues.{number}.labels.{name}"},
	{"PUT", "repos.{owner}.{repo}.issues.{number}.labels"},
	{"DELETE", "repos.{owner}.{repo}.issues.{number}.labels"},
	{"GET", "repos.{owner}.{repo}.milestones.{number}.labels"},
	{"GET", "repos.{owner}.{repo}.milestones"},
	{"GET", "repos.{owner}.{repo}.milestones.{number}"},
	{"POST", "repos.{owner}.{repo}.milestones"},
	{"DELETE", "repos.{owner}.{repo}.milestones.{number}"},
	{"GET", "emojis"},
	{"GET", "gitignore.templates"},
	{"GET", "gitignore.templates.{name}"},
	{"POST", "markdown"},
	{"POST", "markdown.raw"},
	{"GET", "meta"},
	{"GET", "rate_limit"},
	{"GET", "users.{user}.orgs"},
	{"GET", "user.orgs"},
	{"GET", "orgs.{org}"},
	{"GET", "orgs.{org}.members"},
	{"GET", "orgs.{org}.members.{user}"},
	{"DELETE", "orgs.{org}.members.{user}"},
	{"GET", "orgs.{org}.public_members"},
	{"GET", "orgs.{org}.public_members.{user}"},
	{"PUT", "orgs.{org}.public_members.{user}"},
	{"DELETE", "orgs.{org}.public_members.{user}"},
	{"GET", "orgs.{org}.teams"},
	{"GET", "teams.{id}"},
	{"POST", "orgs.{org}.teams"},
	{"DELETE", "teams.{id}"},
	{"GET", "teams.{id}.members"},
	{"GET", "teams.{id}.members.{user}"},
	{"PUT", "teams.{id}.members.{user}"},
	{"DELETE", "teams.{id}.members.{user}"},
	{"GET", "teams.{id}.repos"},
	{"GET", "teams.{id}.repos.{owner}.{repo}"},
	{"PUT", "teams.{id}.repos.{owner}.{repo}"},
	{"DELETE", "teams.{id}.repos.{owner}.{repo}"},
	{"GET", "user.teams"},
	{"GET", "repos.{owner}.{repo}.pulls"},
	{"GET", "repos.{owner}.{repo}.pulls.{number}"},
	{"POST", "repos.{owner}.{repo}.pulls"},
	{"GET", "repos.{owner}.{repo}.pulls.{number}.commits"},
	{"GET", "repos.{owner}.{repo}.pulls.{number}.files"},
	{"GET", "repos.{owner}.{repo}.pulls.{number}.merge"},
	{"PUT", "repos.{owner}.{repo}.pulls.{number}.merge"},
	{"GET", "repos.{owner}.{repo}.pulls.{number}.comments"},
	{"PUT", "repos.{owner}.{repo}.pulls.{number}.comments"},
	{"GET", "user.repos"},
	{"GET", "users.{user}.repos"},
	{"GET", "orgs.{org}.repos"},
	{"GET", "repositories"},
	{"POST", "user.repos"},
	{"POST", "orgs.{org}.repos"},
	{"GET", "repos.{owner}.{repo}"},
	{"GET", "repos.{owner}.{repo}.contributors"},
	{"GET", "repos.{owner}.{repo}.languages"},
	{"GET", "repos.{owner}.{repo}.teams"},
	{"GET", "repos.{owner}.{repo}.tags"},
	{"GET", "repos.{owner}.{repo}.branches"},
	{"GET", "repos.{owner}.{repo}.branches.{branch}"},
	{"DELETE", "repos.{owner}.{repo}"},
	{"GET", "repos.{owner}.{repo}.collaborators"},
	{"GET", "repos.{owner}.{repo}.collaborators.{user}"},
	{"PUT", "repos.{owner}.{repo}.collaborators.{user}"},
	{"DELETE", "repos.{owner}.{repo}.collaborators.{user}"},
	{"GET", "repos.{owner}.{repo}.comments"},
	{"GET", "repos.{owner}.{repo}.commits.{sha}.comments"},
	{"POST", "repos.{owner}.{repo}.commits.{sha}.comments"},
	{"GET", "repos.{owner}.{repo}.comments.{id}"},
	{"DELETE", "repos.{owner}.{repo}.comments.{id}"},
	{"GET", "repos.{owner}.{repo}.commits"},
	{"GET", "repos.{owner}.{repo}.commits.{sha}"},
	{"GET", "repos.{owner}.{repo}.readme"},
	{"GET", "repos.{owner}.{repo}.contents.{path}"},
	{"DELETE", "repos.{owner}.{repo}.contents.{path}"},
	{"GET", "repos.{owner}.{repo}.keys"},
	{"GET", "repos.{owner}.{repo}.keys.{id}"},
	{"POST", "repos.{owner}.{repo}.keys"},
	{"DELETE", "repos.{owner}.{repo}.keys.{id}"},
	{"GET", "repos.{owner}.{repo}.downloads"},
	{"GET", "repos.{owner}.{repo}.downloads.{id}"},
	{"DELETE", "repos.{owner}.{repo}.downloads.{id}"},
	{"GET", "repos.{owner}.{repo}.forks"},
	{"POST", "repos.{owner}.{repo}.forks"},
	{"GET", "repos.{owner}.{repo}.hooks"},
	{"GET", "repos.{owner}.{repo}.hooks.{id}"},
	{"POST", "repos.{owner}.{repo}.hooks"},
	{"POST", "repos.{owner}.{repo}.hooks.{id}.tests"},
	{"DELETE", "repos.{owner}.{repo}.hooks.{id}"},
	{"POST", "repos.{owner}.{repo}.merges"},
	{"GET", "repos.{owner}.{repo}.releases"},
	{"GET", "repos.{owner}.{repo}.releases.{id}"},
	{"POST", "repos.{owner}.{repo}.releases"},
	{"DELETE", "repos.{owner}.{repo}.releases.{id}"},
	{"GET", "repos.{owner}.{repo}.releases.{id}.assets"},
	{"GET", "repos.{owner}.{repo}.stats.contributors"},
	{"GET", "repos.{owner}.{repo}.stats.commit_activity"},
	{"GET", "repos.{owner}.{repo}.stats.code_frequency"},
	{"GET", "repos.{owner}.{repo}.stats.participation"},
	{"GET", "repos.{owner}.{repo}.stats.punch_card"},
	{"GET", "repos.{owner}.{repo}.statuses.{ref}"},
	{"POST", "repos.{owner}.{repo}.statuses.{ref}"},
	{"GET", "search.repositories"},
	{"GET", "search.code"},
	{"GET", "search.issues"},
	{"GET", "search.users"},
	{"GET", "legacy.issues.search.{owner}.{repository}.{state}.{keyword}"},
	{"GET", "legacy.repos.search.{keyword}"},
	{"GET", "legacy.user.search.{keyword}"},
	{"GET", "legacy.user.email.{email}"},
	{"GET", "users.{user}"},
	{"GET", "user"},
	{"GET", "users"},
	{"GET", "user.emails"},
	{"POST", "user.emails"},
	{"DELETE", "user.emails"},
	{"GET", "users.{user}.followers"},
	{"GET", "user.followers"},
	{"GET", "users.{user}.following"},
	{"GET", "user.following"},
	{"GET", "user.following.{user}"},
	{"GET", "users.{user}.following.{target_user}"},
	{"PUT", "user.following.{user}"},
	{"DELETE", "user.following.{user}"},
	{"GET", "users.{user}.keys"},
	{"GET", "user.keys"},
	{"GET", "user.keys.{id}"},
	{"POST", "user.keys"},
	{"DELETE", "user.keys.{id}"},
}
