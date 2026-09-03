// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"iter"
	"slices"
	"strings"
)

// entry is one registration: a kind, the pattern it matches, the matchers that narrow it,
// and the handler that serves it. It is immutable once published and safe for concurrent use.
//
// Both key spaces live in it. A per-message kind carries a path and is reached by a request
// lookup; a connection or datagram kind carries none and is reached by an admission lookup.
// An entry with no handler is the admission the per-message entries of its authority imply.
type entry struct {
	// handler is the value the caller registered, of the alias type its kind names. serve
	// carries the same handler with the middleware of its kind around it.
	handler any
	serve   any

	annots   map[any]any
	name     string
	mws      []middleware
	params   []string
	matchers []RequestMatcher

	pattern     pattern
	priority    uint
	handleSlash TrailingSlashOption
	kind        Kind
	// implied marks the admission entry derived from per-message registrations rather than
	// declared, and refs counts how many of them still need it.
	implied bool
	refs    uint32
}

// admits reports whether this entry is an admission decision rather than a handler, which is
// every entry without a path.
func (e *entry) admits() bool { return e.pattern.path == "" }

// match reports whether the unit satisfies the port this entry names, the precondition of its
// kind, and every matcher on it.
//
// Every matcher is evaluated the same way. The method is one of them and gets no shortcut of
// its own: it stopped being a predicate of the route when it became a matcher, and a fast path
// for it would be that privilege coming back through the engine.
func (e *entry) match(c *routeCtx) bool {
	// Fast path: nothing narrows this entry, so it accepts whatever reached it.
	if !e.narrowed() {
		return true
	}
	return e.matchSlow(c)
}

// matchSlow evaluates what narrows an entry: the port it names, the precondition its kind
// carries, and its matchers. It is kept out of line so match stays inlinable.
//
//go:noinline
func (e *entry) matchSlow(c *routeCtx) bool {
	if !e.acceptsPort(c) {
		return false
	}
	if !e.kindAccepts(c) {
		return false
	}
	sealed := onlyRequestContext{c}
	for _, m := range e.matchers {
		if !m.Match(sealed) {
			return false
		}
	}
	return true
}

// narrowed reports whether anything selects this entry beyond its pattern: a port, a kind
// that refines the kind it rides on, or a matcher. An entry narrowed by nothing is the
// fallback of its node.
func (e *entry) narrowed() bool {
	return e.pattern.port != "" || e.kind.refines() || len(e.matchers) > 0
}

// kindAccepts reports whether the unit being routed is what this entry's kind serves. It is
// the precondition that lets a refined kind share a key with the kind it rides on: a gRPC
// entry and an HTTP entry on one path are told apart by the request, never by the tree.
func (e *entry) kindAccepts(c *routeCtx) bool {
	switch e.kind {
	case KindGRPC:
		return isGRPCRequest(c.req)
	case KindWebSocket:
		return isWebSocketUpgrade(c.req)
	default:
		return true
	}
}

// acceptsPort reports whether the target port is the one this entry names. A pattern naming
// none accepts every port, which is why the port is kept beside the tree key rather than
// folded into it.
func (e *entry) acceptsPort(c *routeCtx) bool {
	return e.pattern.port == "" || e.pattern.port == c.port
}

// samePort reports whether two entries name the same port. It is part of what identifies an
// entry: two patterns differing only by their port are two entries on one node, not a
// conflict and not one another's update.
func (e *entry) samePort(other *entry) bool {
	return e.pattern.port == other.pattern.port
}

// matchersEqual reports whether this entry's matchers are equal to the provided ones.
func (e *entry) matchersEqual(matchers []RequestMatcher) bool {
	if len(e.matchers) != len(matchers) {
		return false
	}

	// Runs in O(n²), but the matched slice is stack allocated for the sizes involved.
	// A map would cost more to populate than the quadratic scan saves.
	matched := make([]bool, len(matchers))

outer:
	for _, a := range e.matchers {
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

func (e *entry) String() string {
	sb := new(strings.Builder)
	entryf(sb, e, 0, true)
	return sb.String()
}

// Entry is a registration as the caller can read it back. Its type parameter is the handler
// kind it was registered under, so [Entry.Handler] returns the handler with the signature it
// was given.
type Entry[H Handler] struct {
	e *entry
}

// Handler returns the handler as registered, without the middleware around it.
func (r Entry[H]) Handler() H {
	h, _ := r.e.handler.(H)
	return h
}

// Kind returns the kind of traffic this entry serves.
func (r Entry[H]) Kind() Kind { return r.e.kind }

// Pattern returns the pattern as registered.
func (r Entry[H]) Pattern() string { return r.e.pattern.str }

// Host returns the host part of the pattern as it was registered, brackets dropped: a
// hostname, an address, or a range such as "10.0.0.0/8". An IPv6 literal or a range needs its
// brackets back to appear in a pattern again; [Entry.Pattern] carries the registrable
// spelling.
func (r Entry[H]) Host() string { return r.e.pattern.host }

// Path returns the path part of the pattern, empty for a kind that routes whole connections.
func (r Entry[H]) Path() string { return r.e.pattern.path }

// Port returns the port this entry is restricted to, or an empty string when it accepts every
// port.
func (r Entry[H]) Port() string { return r.e.pattern.port }

// Name returns the name of this entry, or an empty string.
func (r Entry[H]) Name() string { return r.e.name }

// Annotation returns the value associated with key on this entry, or nil.
func (r Entry[H]) Annotation(key any) any { return r.e.annots[key] }

// ParamsLen returns the number of parameters in this entry's pattern.
func (r Entry[H]) ParamsLen() int { return len(r.e.params) }

// Params returns an iterator over this entry's parameter names, in pattern order.
func (r Entry[H]) Params() iter.Seq[string] { return slices.Values(r.e.params) }

// MatchersLen returns the number of matchers attached to this entry.
func (r Entry[H]) MatchersLen() int { return len(r.e.matchers) }

// RequestMatchers returns an iterator over the matchers attached to this entry.
func (r Entry[H]) RequestMatchers() iter.Seq[RequestMatcher] { return slices.Values(r.e.matchers) }

// MatchersPriority returns the matcher priority of this entry.
func (r Entry[H]) MatchersPriority() uint { return r.e.priority }

// TrailingSlashOption returns the [TrailingSlashOption] configured for this entry.
func (r Entry[H]) TrailingSlashOption() TrailingSlashOption { return r.e.handleSlash }

func (r Entry[H]) String() string { return r.e.String() }

// EntryView is a registration read without naming its kind, which is what an iteration over
// every kind can offer. [Proxy.Lookup] returns the typed [Entry] for one.
type EntryView struct {
	e *entry
}

// Kind returns the kind of traffic this entry serves.
func (v EntryView) Kind() Kind { return v.e.kind }

// Pattern returns the pattern as registered.
func (v EntryView) Pattern() string { return v.e.pattern.str }

// Host returns the host part of the pattern as registered, brackets dropped.
func (v EntryView) Host() string { return v.e.pattern.host }

// Path returns the path part of the pattern, empty for a kind that routes whole connections.
func (v EntryView) Path() string { return v.e.pattern.path }

// Port returns the port this entry is restricted to, or an empty string for any port.
func (v EntryView) Port() string { return v.e.pattern.port }

// Name returns the name of this entry, or an empty string.
func (v EntryView) Name() string { return v.e.name }

// Admits reports whether this entry admits an authority rather than serving traffic on it.
// An entry admitting a kind no registration named explicitly is implied by the per-message
// entries under it.
func (v EntryView) Admits() bool { return v.e.admits() }

// Implied reports whether this entry was derived from per-message registrations rather than
// declared by the caller.
func (v EntryView) Implied() bool { return v.e.implied }

// Matchers returns an iterator over the matchers attached to this entry.
func (v EntryView) RequestMatchers() iter.Seq[RequestMatcher] { return slices.Values(v.e.matchers) }

func (v EntryView) String() string { return v.e.String() }

func entryf(sb *strings.Builder, e *entry, pad int, showName bool) {
	sb.WriteString(strings.Repeat(" ", pad))
	sb.WriteString("kind:")
	sb.WriteString(e.kind.String())
	if e.handler == nil {
		sb.WriteString(" admits:")
		sb.WriteString(e.pattern.str)
		if e.implied {
			sb.WriteString(" implied")
		}
		return
	}

	sb.WriteString(" pattern:")
	sb.WriteString(e.pattern.str)

	if e.name != "" && showName {
		sb.WriteString(" name:")
		sb.WriteString(e.name)
	}

	size := sb.Len()
	for _, matcher := range e.matchers {
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
