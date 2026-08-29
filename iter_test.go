// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net/http"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func patternsOf(seq func(func(*Route) bool)) []string {
	var out []string
	for rte := range seq {
		out = append(out, rte.Pattern())
	}
	slices.Sort(out)
	return out
}

func TestIter_All(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/charges", noopHandler)
	p.MustHandle([]string{http.MethodPost}, "api.test/v1/refunds", noopHandler)
	p.MustHandle([]string{http.MethodGet}, "files.test/v1/files/{id}", noopHandler)

	assert.Equal(t, []string{
		"api.test/v1/charges",
		"api.test/v1/refunds",
		"files.test/v1/files/{id}",
	}, patternsOf(p.Iter().All()))
}

func TestIter_Methods(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/charges", noopHandler)
	p.MustHandle([]string{http.MethodPost}, "api.test/v1/refunds", noopHandler)
	p.MustHandle(nil, "api.test/v1/any", noopHandler)

	methods := slices.Sorted(p.Iter().Methods())
	assert.Equal(t, []string{http.MethodGet, http.MethodPost}, methods,
		"a route with no method constraint contributes none")
}

func TestIter_Routes(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/charges", noopHandler)
	p.MustHandle([]string{http.MethodPost}, "api.test/v1/charges", noopHandler)
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/refunds", noopHandler)

	assert.Len(t, patternsOf(p.Iter().Routes("api.test/v1/charges")), 2)
	assert.Empty(t, patternsOf(p.Iter().Routes("api.test/v1/missing")))
}

func TestIter_RoutesReturnsEveryRouteOnAPattern(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/charges", noopHandler, WithScheme("https"))
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/charges", noopHandler)

	// Two routes on one pattern, told apart by their matchers rather than by their key.
	assert.Len(t, patternsOf(p.Iter().Routes("api.test/v1/charges")), 2)
}

func TestIter_PatternPrefix(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/charges", noopHandler)
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/refunds", noopHandler)
	p.MustHandle([]string{http.MethodGet}, "files.test/v1/files", noopHandler)

	assert.Equal(t, []string{
		"api.test/v1/charges",
		"api.test/v1/refunds",
	}, patternsOf(p.Iter().PatternPrefix("api.test/v1")))
}

func TestIter_NamePrefix(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/charges", noopHandler, WithName("stripe.charges"))
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/refunds", noopHandler, WithName("stripe.refunds"))
	p.MustHandle([]string{http.MethodGet}, "files.test/v1/files", noopHandler, WithName("files.list"))

	var names []string
	for rte := range p.Iter().NamePrefix("stripe.") {
		names = append(names, rte.Name())
	}
	slices.Sort(names)
	assert.Equal(t, []string{"stripe.charges", "stripe.refunds"}, names)
}

func TestIter_SnapshotIsStable(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/charges", noopHandler)

	it := p.Iter()
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/refunds", noopHandler)

	assert.Len(t, patternsOf(it.All()), 1, "an iterator must not observe writes made after it was taken")
	assert.Len(t, patternsOf(p.Iter().All()), 2)
}

func TestIter_Names(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/charges", noopHandler, WithName("charges"))
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/refunds", noopHandler)

	var named []string
	for rte := range p.Iter().Names() {
		named = append(named, rte.Name())
	}
	require.Equal(t, []string{"charges"}, named)
}
