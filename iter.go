// Copyright 2022 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"iter"
	"strings"
)

const stackSizeThreshold = 25

type stack struct {
	edges []*node
}

// Iter provide a set of range iterators for traversing registered methods, interceptors and authority entries. Iter capture a point-in-time
// snapshot of the routing tree. Therefore, all iterators returned by Iter will not observe subsequent write on the
// proxy or on the transaction from which the Iter is created.
type Iter struct {
	patterns *node
	addrs    *node
	names    *node
	methods  map[string]uint
	maxDepth int // tree or txn maxDepth
}

// Methods returns a range iterator over all HTTP methods registered in the routing tree. The iterator reflect a snapshot
// of the routing tree at the time [Iter] is created. This function is safe for concurrent use by multiple goroutine and
// while mutation on interceptors are ongoing.
func (it Iter) Methods() iter.Seq[string] {
	return func(yield func(string) bool) {
		for k := range it.methods {
			if !yield(k) {
				return
			}
		}
	}
}

// Interceptors returns a range iterator over all registered interceptors in the routing tree that exactly match the provided
// pattern. The iterator reflect a snapshot of the routing tree at the time [Iter] is created. This function is safe for
// concurrent use by multiple goroutine and while mutation on interceptors are ongoing.
func (it Iter) Interceptors(pattern string) iter.Seq[*Interceptor] {
	return func(yield func(*Interceptor) bool) {
		key, isAddr := patternKey(pattern)
		root := it.patterns
		if isAddr {
			root = it.addrs
		}
		matched := root.searchPattern(key)
		if matched == nil || !matched.isLeaf() {
			return
		}

		for _, ic := range matched.entries {
			if ic.pattern.path == "" {
				continue
			}
			if ic.pattern.str == pattern {
				if !yield(ic) {
					return
				}
			}
		}
	}
}

// NamePrefix returns a range iterator over all interceptors in the routing tree that match a given name prefix. The iterator
// reflect a snapshot of the routing tree at the time [Iter] is created. This function is safe for concurrent use by
// multiple goroutine and while mutation on interceptors are ongoing.
func (it Iter) NamePrefix(prefix string) iter.Seq[*Interceptor] {
	return func(yield func(*Interceptor) bool) {
		var stacks []stack
		if it.maxDepth < stackSizeThreshold {
			stacks = make([]stack, 0, stackSizeThreshold) // stack allocation
		} else {
			stacks = make([]stack, 0, it.maxDepth) // heap allocation
		}

		matched := it.names.searchName(prefix)
		if matched == nil {
			return
		}

		stacks = append(stacks, stack{
			edges: []*node{matched},
		})

		for len(stacks) > 0 {
			n := len(stacks)
			last := stacks[n-1]
			elem := last.edges[0]

			if len(last.edges) > 1 {
				stacks[n-1].edges = last.edges[1:]
			} else {
				stacks = stacks[:n-1]
			}

			if len(elem.statics) > 0 {
				stacks = append(stacks, stack{edges: elem.statics})
			}

			if elem.isLeaf() {
				if !yield(elem.entries[0]) {
					return
				}
			}
		}
	}
}

// PatternPrefix returns a range iterator over all interceptors in the routing tree that match a given pattern prefix.
// The iterator reflect a snapshot of the routing tree at the time [Iter] is created. This function is safe for
// concurrent use by multiple goroutine and while mutation on interceptors are ongoing.
// Note: Partial parameter syntax (e.g., /users/{name:) is not supported and will not match any interceptor.
// An interceptor on an address host is matched on its registered spelling, so a bracketed
// pattern is only reachable through a prefix that starts with '['.
func (it Iter) PatternPrefix(prefix string) iter.Seq[*Interceptor] {
	return it.patternPrefix(prefix, false)
}

// patternPrefix walks the trees yielding either the interceptors or the authority entries,
// never both. They share the trees but nothing else: an authority has no handler to call and
// no method to report, so handing one to a caller asking for interceptors would be a trap.
//
// The address root is walked whole rather than guided, its keys are encoded and a textual
// prefix cannot steer the descent, so the registered spelling is filtered instead.
func (it Iter) patternPrefix(prefix string, authorities bool) iter.Seq[*Interceptor] {
	return func(yield func(*Interceptor) bool) {
		if !it.walkPatterns(it.patterns.searchPattern(prefix), prefix, authorities, false, yield) {
			return
		}
		it.walkPatterns(it.addrs, prefix, authorities, true, yield)
	}
}

// walkPatterns yields the matching entries under start and reports whether the walk ran to
// completion rather than being stopped by its consumer. With filterAll set, every entry is
// held to the string prefix, which is what the address root does instead of a guided descent.
func (it Iter) walkPatterns(start *node, prefix string, authorities, filterAll bool, yield func(*Interceptor) bool) bool {
	if start == nil {
		return true
	}

	var stacks []stack
	if it.maxDepth < stackSizeThreshold {
		stacks = make([]stack, 0, stackSizeThreshold) // stack allocation
	} else {
		stacks = make([]stack, 0, it.maxDepth) // heap allocation
	}

	stacks = append(stacks, stack{
		edges: []*node{start},
	})

	for len(stacks) > 0 {
		n := len(stacks)
		last := stacks[n-1]
		elem := last.edges[0]

		if len(last.edges) > 1 {
			stacks[n-1].edges = last.edges[1:]
		} else {
			stacks = stacks[:n-1]
		}

		if len(elem.statics) > 0 {
			stacks = append(stacks, stack{edges: elem.statics})
		}
		if len(elem.params) > 0 {
			stacks = append(stacks, stack{edges: elem.params})
		}
		if len(elem.wildcards) > 0 {
			stacks = append(stacks, stack{edges: elem.wildcards})
		}

		if elem.isLeaf() {
			for _, ic := range elem.entries {
				if (ic.pattern.path == "") != authorities {
					continue
				}
				if (filterAll || len(ic.params) > 0) && !strings.HasPrefix(ic.pattern.str, prefix) {
					continue
				}

				if !yield(ic) {
					return false
				}
			}
		}
	}
	return true
}

// Authorities returns a range iterator over the authority entries registered in the routing
// tree, the ones implied by interceptors included. The iterator reflect a snapshot of the
// routing tree at the time [Iter] is created. This function is safe for concurrent use by
// multiple goroutine and while mutation on interceptors are ongoing.
func (it Iter) Authorities() iter.Seq[Authority] {
	return func(yield func(Authority) bool) {
		for ic := range it.patternPrefix("", true) {
			if !yield(Authority{entry: ic}) {
				return
			}
		}
	}
}

// All returns a range iterator over all interceptors registered in the routing tree. The iterator reflect a snapshot
// of the routing tree at the time [Iter] is created. This function is safe for concurrent use by multiple goroutine
// and while mutation on interceptors are ongoing. See also [Iter.PatternPrefix] as an alternative.
func (it Iter) All() iter.Seq[*Interceptor] {
	return func(yield func(*Interceptor) bool) {
		for ic := range it.PatternPrefix("") {
			if !yield(ic) {
				return
			}
		}
	}
}

// Names returns a range iterator over all interceptors registered in the routing tree with a name. The iterator reflect a snapshot
// of the routing tree at the time [Iter] is created. This function is safe for concurrent use by multiple goroutine
// and while mutation on interceptors are ongoing. See also [Iter.NamePrefix] as an alternative.
func (it Iter) Names() iter.Seq[*Interceptor] {
	return func(yield func(*Interceptor) bool) {
		for ic := range it.NamePrefix("") {
			if !yield(ic) {
				return
			}
		}
	}
}
