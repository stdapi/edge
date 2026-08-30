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

// Interceptor is an immutable rule: a request target pattern, the methods and matchers that
// narrow it, and the handler that serves it. A Interceptor is safe for concurrent use and is
// never mutated after registration.
type Interceptor struct {
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

// Handle calls the interceptor handler with c, without the interceptor middleware.
func (r *Interceptor) Handle(c *Context) (*http.Response, error) {
	return r.hbase(c)
}

// HandleMiddleware calls the interceptor handler with the interceptor-specific middleware applied.
// It is not meant to be registered as another interceptor's handler: the middleware chain would
// be applied twice. Use [Interceptor.Handle] to reuse a handler.
func (r *Interceptor) HandleMiddleware(c *Context, _ ...struct{}) (*http.Response, error) {
	// The variadic parameter keeps this method from having the HandlerFunc signature,
	// which would make the misuse above compile.
	return r.hself(c)
}

// Methods returns an iterator over the methods this interceptor responds to, in lexicographical
// order. An interceptor with no method responds to every method.
func (r *Interceptor) Methods() iter.Seq[string] {
	return slices.Values(r.methods)
}

// Pattern returns the pattern as registered.
func (r *Interceptor) Pattern() string { return r.pattern.str }

// Hostname returns the hostname part of the pattern, or an empty string when the interceptor
// matches every authority.
func (r *Interceptor) Hostname() string { return r.pattern.host }

// Path returns the path part of the pattern.
func (r *Interceptor) Path() string { return r.pattern.path }

// Name returns the name of this interceptor, or an empty string.
func (r *Interceptor) Name() string { return r.name }

// Annotation returns the value associated with key on this interceptor, or nil.
func (r *Interceptor) Annotation(key any) any { return r.annots[key] }

// TrailingSlashOption returns the [TrailingSlashOption] configured for this interceptor.
func (r *Interceptor) TrailingSlashOption() TrailingSlashOption { return r.handleSlash }

// ParamsLen returns the number of parameters in this interceptor's pattern.
func (r *Interceptor) ParamsLen() int { return len(r.params) }

// Params returns an iterator over this interceptor's parameter names, in pattern order.
func (r *Interceptor) Params() iter.Seq[string] {
	return slices.Values(r.params)
}

// Port returns the port this interceptor is restricted to, or an empty string when it accepts
// every port.
func (r *Interceptor) Port() string { return r.pattern.port }

// MatchersLen returns the number of matchers attached to this interceptor.
func (r *Interceptor) MatchersLen() int { return len(r.matchers) }

// Matchers returns an iterator over the matchers attached to this interceptor.
func (r *Interceptor) Matchers() iter.Seq[Matcher] {
	return slices.Values(r.matchers)
}

// MatchersPriority returns the matcher priority of this interceptor.
func (r *Interceptor) MatchersPriority() uint { return r.priority }

func (r *Interceptor) String() string {
	sb := new(strings.Builder)
	entryf(sb, r, 0, true)
	return sb.String()
}

// noFastMethod is what an interceptor carries when the method fast path cannot serve it. Left at
// its zero value the field would be the empty string, and a lookup carrying an empty method
// would then match the interceptor outright, skipping the port and the matchers that narrow it.
//
// A NUL byte is not a valid HTTP token character, so validMethod rejects this value and no
// interceptor can be registered with it. TestMethodSentinels holds both properties.
const noFastMethod = "\x00none"

// match reports whether the request satisfies this interceptor's method constraint, the port
// it names, and every attached matcher.
func (r *Interceptor) match(method string, c *Context) bool {
	// Fast path: an interceptor with exactly one method, no port and no matcher caches it in
	// methodFast.
	if r.methodFast == method {
		return true
	}
	return r.matchSlow(method, c)
}

// matchSlow covers what match's fast path does not: zero or many methods, a port, and
// matchers. It is kept out of line so match stays inlinable.
//
//go:noinline
func (r *Interceptor) matchSlow(method string, c *Context) bool {
	methods := r.methods
	switch len(methods) {
	case 0:
		// No method constraint.
	case 1:
		// Avoid the slices.Contains call for the single-method case, which the fast path
		// leaves to us when a port or a matcher narrows the interceptor.
		if methods[0] != method {
			return false
		}
	default:
		if !slices.Contains(methods, method) {
			return false
		}
	}
	if !r.acceptsPort(c) {
		return false
	}

	sealed := onlyRequestContext{c}
	for _, m := range r.matchers {
		if !m.Match(sealed) {
			return false
		}
	}
	return true
}

// acceptsPort reports whether the target port is the one this interceptor names. A pattern
// naming none accepts every port, which is why the port is kept beside the tree key rather
// than folded into it.
func (r *Interceptor) acceptsPort(c *Context) bool {
	return r.pattern.port == "" || r.pattern.port == c.port
}

// samePort reports whether two interceptors name the same port. It is part of what identifies
// an entry: two patterns differing only by their port are two entries on one node, not a
// conflict and not one another's update.
func (r *Interceptor) samePort(other *Interceptor) bool {
	return r.pattern.port == other.pattern.port
}

// matchersEqual reports whether this interceptor's matchers are equal to the provided ones.
func (r *Interceptor) matchersEqual(matchers []Matcher) bool {
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

func entryf(sb *strings.Builder, ic *Interceptor, pad int, showName bool) {
	sb.WriteString(strings.Repeat(" ", pad))
	if ic.action != 0 {
		sb.WriteString("authority:")
		sb.WriteString(ic.pattern.str)
		sb.WriteString(" action:")
		sb.WriteString(ic.action.String())
		return
	}

	sb.WriteString("method:")
	if len(ic.methods) > 0 {
		sb.WriteString(strings.Join(ic.methods, ","))
	} else {
		sb.WriteString("*")
	}

	sb.WriteString(" pattern:")
	sb.WriteString(ic.pattern.str)

	if ic.name != "" && showName {
		sb.WriteString(" name:")
		sb.WriteString(ic.name)
	}

	size := sb.Len()
	for _, matcher := range ic.matchers {
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
