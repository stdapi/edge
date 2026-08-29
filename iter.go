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

// Iter provide a set of range iterators for traversing registered methods and routes. Iter capture a point-in-time
// snapshot of the routing tree. Therefore, all iterators returned by Iter will not observe subsequent write on the
// router or on the transaction from which the Iter is created.
type Iter struct {
	patterns *node
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

// Interceptors returns a range iterator over all registered interceptors in the routing tree that exactly match the provided route
// pattern. The iterator reflect a snapshot of the routing tree at the time [Iter] is created. This function is safe for
// concurrent use by multiple goroutine and while mutation on interceptors are ongoing.
func (it Iter) Interceptors(pattern string) iter.Seq[*Interceptor] {
	return func(yield func(*Interceptor) bool) {
		matched := it.patterns.searchPattern(patternKey(pattern))
		if matched == nil || !matched.isLeaf() {
			return
		}

		for _, route := range matched.entries {
			if route.pattern.str == pattern {
				if !yield(route) {
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
// Note: Partial parameter syntax (e.g., /users/{name:) is not supported and will not match any routes.
func (it Iter) PatternPrefix(prefix string) iter.Seq[*Interceptor] {
	return it.patternPrefix(prefix, false)
}

// patternPrefix walks the tree yielding either the routes or the authority entries, never
// both. They share the tree but nothing else: an authority has no handler to call and no
// method to report, so handing one to a caller asking for routes would be a trap.
func (it Iter) patternPrefix(prefix string, authorities bool) iter.Seq[*Interceptor] {
	return func(yield func(*Interceptor) bool) {
		var stacks []stack
		if it.maxDepth < stackSizeThreshold {
			stacks = make([]stack, 0, stackSizeThreshold) // stack allocation
		} else {
			stacks = make([]stack, 0, it.maxDepth) // heap allocation
		}

		matched := it.patterns.searchPattern(prefix)
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
			if len(elem.params) > 0 {
				stacks = append(stacks, stack{edges: elem.params})
			}
			if len(elem.wildcards) > 0 {
				stacks = append(stacks, stack{edges: elem.wildcards})
			}

			if elem.isLeaf() {
				for _, route := range elem.entries {
					if (route.pattern.path == "") != authorities {
						continue
					}
					if len(route.params) > 0 && !strings.HasPrefix(route.pattern.str, prefix) {
						continue
					}

					if !yield(route) {
						return
					}
				}
			}
		}
	}
}

// All returns a range iterator over all interceptors registered in the routing tree. The iterator reflect a snapshot
// of the routing tree at the time [Iter] is created. This function is safe for concurrent use by multiple goroutine
// and while mutation on interceptors are ongoing. See also [Iter.PatternPrefix] as an alternative.
func (it Iter) All() iter.Seq[*Interceptor] {
	return func(yield func(*Interceptor) bool) {
		for route := range it.PatternPrefix("") {
			if !yield(route) {
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
		for route := range it.NamePrefix("") {
			if !yield(route) {
				return
			}
		}
	}
}
