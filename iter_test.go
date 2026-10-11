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

func patternsOf(seq func(func(EntryView) bool)) []string {
	var out []string
	for ic := range seq {
		out = append(out, ic.Pattern())
	}
	slices.Sort(out)
	return out
}

func TestIter_All(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))
	p.MustAdd("api.test/v1/refunds", noopHandler, WithMethods[HTTP](http.MethodPost))
	p.MustAdd("files.test/v1/files/{id}", noopHandler, WithMethods[HTTP](http.MethodGet))

	assert.Equal(t, []string{
		"api.test/v1/charges",
		"api.test/v1/refunds",
		"files.test/v1/files/{id}",
	}, patternsOf(p.Iter().All()))
}

func TestIter_AllReportsEveryKindAndNoImpliedAdmission(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.stripe.com/v1/charges/{id}", noopHandler)
	p.MustAdd[TCP]("smtp.test:465", noopStream)
	p.MustAdd[UDP]("dns.test:53", forwardDatagram)

	assert.Equal(t, []string{
		"api.stripe.com/v1/charges/{id}",
		"dns.test:53",
		"smtp.test:465",
	}, patternsOf(p.Iter().All()))

	assert.Equal(t, []string{"smtp.test:465"}, patternsOf(p.Iter().Entries("smtp.test:465")))
	assert.Empty(t, patternsOf(p.Iter().Entries("api.stripe.com")))

	assert.Equal(t, []string{
		"api.stripe.com",
		"dns.test:53",
		"smtp.test:465",
	}, patternsOf(p.Iter().Admissions()))

	implied := make(map[string]bool)
	for v := range p.Iter().Admissions() {
		implied[v.Pattern()] = v.Implied()
	}
	assert.True(t, implied["api.stripe.com"])
	assert.False(t, implied["smtp.test:465"])
	assert.False(t, implied["dns.test:53"])
}

func TestIter_Interceptors(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))
	p.MustAdd("api.test/v1/charges", noopHandler, WithMethods[HTTP](http.MethodPost))
	p.MustAdd("api.test/v1/refunds", noopHandler, WithMethods[HTTP](http.MethodGet))

	assert.Len(t, patternsOf(p.Iter().Entries("api.test/v1/charges")), 2)
	assert.Empty(t, patternsOf(p.Iter().Entries("api.test/v1/missing")))
}

func TestIter_InterceptorsReturnsEveryOneOnAPattern(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1/charges", noopHandler, WithScheme[HTTP]("https"), WithMethods[HTTP](http.MethodGet))
	p.MustAdd("api.test/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))

	// Two interceptors on one pattern, told apart by their matchers rather than by their key.
	assert.Len(t, patternsOf(p.Iter().Entries("api.test/v1/charges")), 2)
}

func TestIter_PatternPrefix(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))
	p.MustAdd("api.test/v1/refunds", noopHandler, WithMethods[HTTP](http.MethodGet))
	p.MustAdd("files.test/v1/files", noopHandler, WithMethods[HTTP](http.MethodGet))

	assert.Equal(t, []string{
		"api.test/v1/charges",
		"api.test/v1/refunds",
	}, patternsOf(p.Iter().PatternPrefix("api.test/v1")))
}

func TestIter_NamePrefix(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1/charges", noopHandler, WithName[HTTP]("stripe.charges"), WithMethods[HTTP](http.MethodGet))
	p.MustAdd("api.test/v1/refunds", noopHandler, WithName[HTTP]("stripe.refunds"), WithMethods[HTTP](http.MethodGet))
	p.MustAdd("files.test/v1/files", noopHandler, WithName[HTTP]("files.list"), WithMethods[HTTP](http.MethodGet))

	var names []string
	for ic := range p.Iter().NamePrefix("stripe.") {
		names = append(names, ic.Name())
	}
	slices.Sort(names)
	assert.Equal(t, []string{"stripe.charges", "stripe.refunds"}, names)
}

func TestIter_SnapshotIsStable(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))

	it := p.Iter()
	p.MustAdd("api.test/v1/refunds", noopHandler, WithMethods[HTTP](http.MethodGet))

	assert.Len(t, patternsOf(it.All()), 1, "an iterator must not observe writes made after it was taken")
	assert.Len(t, patternsOf(p.Iter().All()), 2)
}

func TestIter_Names(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1/charges", noopHandler, WithName[HTTP]("charges"), WithMethods[HTTP](http.MethodGet))
	p.MustAdd("api.test/v1/refunds", noopHandler, WithMethods[HTTP](http.MethodGet))

	var named []string
	for ic := range p.Iter().Names() {
		named = append(named, ic.Name())
	}
	require.Equal(t, []string{"charges"}, named)
}

func TestIter_Break(t *testing.T) {
	p := testProxy(t)
	for _, pattern := range []string{"a.test/x", "a.test/y", "b.test/x", "10.0.0.1/x", "[10.0.0.0/8]/x"} {
		p.MustAdd(pattern, noopHandler, WithName[HTTP](pattern))
		p.MustAdd(pattern, noopHandler, WithName[HTTP](pattern+" GET"), WithMethods[HTTP](http.MethodGet))
	}
	p.MustAdd[TCP]("smtp.test:25", noopStream)
	p.MustAdd[TCP]("10.0.0.2:25", noopStream)

	it := p.Iter()
	for name, seq := range map[string]func(func(EntryView) bool){
		"All":                         it.All(),
		"Admissions":                  it.Admissions(),
		"Names":                       it.Names(),
		"Entries":                     it.Entries("a.test/x"),
		"PatternPrefix":               it.PatternPrefix(""),
		"PatternPrefix of a name":     it.PatternPrefix("a.test/"),
		"PatternPrefix of an address": it.PatternPrefix("10.0.0.1"),
		"NamePrefix":                  it.NamePrefix("a.test/"),
	} {
		n := 0
		for range seq {
			n++
			break
		}
		assert.Equal(t, 1, n, name)
	}
}

func TestIter_PatternStrictPrefix(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("a.test/{a}/b/x", noopHandler)
	p.MustAdd("a.test/{a}/b/y", noopHandler)
	p.MustAdd("a.test/{other}/b/z", noopHandler)

	assert.Equal(t, []string{"a.test/{a}/b/x", "a.test/{a}/b/y"}, patternsOf(p.Iter().PatternPrefix("a.test/{a}/b")))
	assert.Empty(t, patternsOf(p.Iter().PatternPrefix("a.test/{a:")))
}

func TestIter_Empty(t *testing.T) {
	it := testProxy(t).Iter()
	for name, seq := range map[string]func(func(EntryView) bool){
		"All":                  it.All(),
		"Admissions":           it.Admissions(),
		"Names":                it.Names(),
		"Entries":              it.Entries("a.test/x"),
		"Entries of nothing":   it.Entries(""),
		"PatternPrefix":        it.PatternPrefix("a.test/"),
		"PatternPrefix of all": it.PatternPrefix(""),
		"NamePrefix":           it.NamePrefix("a"),
		"NamePrefix of all":    it.NamePrefix(""),
	} {
		assert.Empty(t, patternsOf(seq), name)
	}
}
