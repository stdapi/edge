// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"iter"
	"net/http"
	"slices"
	"strings"
)

// Route is an immutable route: a request target pattern, the methods and matchers that
// narrow it, and the handler that serves it. A Route is safe for concurrent use and is
// never mutated after registration.
type Route struct {
	hbase       HandlerFunc
	hself       HandlerFunc
	hall        HandlerFunc
	annots      map[any]any
	name        string
	methods     []string
	mws         []middleware
	params      []string
	matchers    []Matcher
	methodFast  string
	pattern     pattern
	priority    uint
	handleSlash TrailingSlashOption
	action      Action
	implicit    bool
	refs        uint32
}

// Handle calls the route handler with c, without the route middleware.
func (r *Route) Handle(c *Context) (*http.Response, error) {
	return r.hbase(c)
}

// HandleMiddleware calls the route handler with the route-specific middleware applied.
// It is not meant to be registered as another route's handler: the middleware chain would
// be applied twice. Use [Route.Handle] to reuse a handler.
func (r *Route) HandleMiddleware(c *Context, _ ...struct{}) (*http.Response, error) {
	// The variadic parameter keeps this method from having the HandlerFunc signature,
	// which would make the misuse above compile.
	return r.hself(c)
}

// Methods returns an iterator over the methods this route responds to, in lexicographical
// order. A route with no method responds to every method.
func (r *Route) Methods() iter.Seq[string] {
	return slices.Values(r.methods)
}

// Pattern returns the pattern as registered.
func (r *Route) Pattern() string { return r.pattern.str }

// Hostname returns the hostname part of the pattern, or an empty string when the route
// matches every authority.
func (r *Route) Hostname() string { return r.pattern.host }

// Path returns the path part of the pattern.
func (r *Route) Path() string { return r.pattern.path }

// Name returns the name of this route, or an empty string.
func (r *Route) Name() string { return r.name }

// Annotation returns the value associated with key on this route, or nil.
func (r *Route) Annotation(key any) any { return r.annots[key] }

// TrailingSlashOption returns the [TrailingSlashOption] configured for this route.
func (r *Route) TrailingSlashOption() TrailingSlashOption { return r.handleSlash }

// ParamsLen returns the number of parameters in this route's pattern.
func (r *Route) ParamsLen() int { return len(r.params) }

// Params returns an iterator over this route's parameter names, in pattern order.
func (r *Route) Params() iter.Seq[string] {
	return slices.Values(r.params)
}

// MatchersLen returns the number of matchers attached to this route, including the implicit
// scheme and port matchers derived from the pattern.
func (r *Route) MatchersLen() int { return len(r.matchers) }

// Matchers returns an iterator over the matchers attached to this route.
func (r *Route) Matchers() iter.Seq[Matcher] {
	return slices.Values(r.matchers)
}

// MatchersPriority returns the matcher priority of this route.
func (r *Route) MatchersPriority() uint { return r.priority }

func (r *Route) String() string {
	sb := new(strings.Builder)
	routef(sb, r, 0, true)
	return sb.String()
}

// noFastMethod and ruleLookupMethod are method values that can never appear on the wire: a
// NUL byte is not a valid HTTP token character, so validMethod rejects both and no route can
// be registered with either.
//
// noFastMethod is what a route carries when the fast path cannot serve it. Left at its zero
// value the field would be the empty string, and a lookup carrying an empty method would
// then match the route outright, skipping the matchers that narrow it. That is not a
// theoretical hole: rules have no method at all, so their lookup has nothing real to pass.
//
// ruleLookupMethod is what that rule lookup passes instead. It must differ from
// noFastMethod, or the fast path would compare the two sentinels, find them equal and claim
// a match for every rule. TestMethodSentinels holds both properties.
const (
	noFastMethod     = "\x00none"
	ruleLookupMethod = "\x00rule"
)

// match reports whether the request satisfies this route's method constraint and every
// attached matcher.
func (r *Route) match(method string, c *Context) bool {
	// Fast path: a route with exactly one method and no matcher caches it in methodFast.
	if r.methodFast == method {
		return true
	}
	return r.matchSlow(method, c)
}

// matchSlow covers what match's fast path does not: zero or many methods, and matchers.
// It is kept out of line so match stays inlinable.
//
//go:noinline
func (r *Route) matchSlow(method string, c *Context) bool {
	methods := r.methods
	switch len(methods) {
	case 0:
		// No method constraint.
	case 1:
		// Avoid the slices.Contains call for the single-method case, which the fast path
		// leaves to us when matchers are present.
		if methods[0] != method {
			return false
		}
	default:
		if !slices.Contains(methods, method) {
			return false
		}
	}
	c.matcherRoute = r
	sealed := onlyRequestContext{c}
	for _, m := range r.matchers {
		if !m.Match(sealed) {
			return false
		}
	}
	return true
}

// matchersEqual reports whether this route's matchers are equal to the provided ones.
func (r *Route) matchersEqual(matchers []Matcher) bool {
	if len(r.matchers) != len(matchers) {
		return false
	}

	// Runs in O(n²), but the matched slice is stack allocated for the sizes involved.
	// A map would cost more to populate than the quadratic scan saves.
	matched := make([]bool, len(matchers))

outer:
	for _, a := range r.matchers {
		for i, b := range matchers {
			if !matched[i] && a.Equal(b) {
				matched[i] = true
				continue outer
			}
		}
		return false
	}
	return true
}

func routef(sb *strings.Builder, route *Route, pad int, showName bool) {
	sb.WriteString(strings.Repeat(" ", pad))
	if route.action != 0 {
		sb.WriteString("rule:")
		sb.WriteString(route.action.String())
		sb.WriteString(" authority:")
		sb.WriteString(route.pattern.str)
		return
	}

	sb.WriteString("method:")
	if len(route.methods) > 0 {
		sb.WriteString(strings.Join(route.methods, ","))
	} else {
		sb.WriteString("*")
	}

	sb.WriteString(" pattern:")
	sb.WriteString(route.pattern.str)

	if route.name != "" && showName {
		sb.WriteString(" name:")
		sb.WriteString(route.name)
	}

	size := sb.Len()
	for _, matcher := range route.matchers {
		m, ok := matcher.(fmt.Stringer)
		if !ok {
			continue
		}
		if sb.Len() > size {
			sb.WriteByte(',')
		} else {
			sb.WriteString(" matchers:{")
		}
		sb.WriteString(m.String())
	}
	if sb.Len() > size {
		sb.WriteByte('}')
	}
}
