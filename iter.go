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

// Iter provides a set of range iterators for traversing the registered entries. Iter captures a point-in-time
// snapshot of the routing tree. Therefore, all iterators returned by Iter will not observe subsequent write on the
// proxy or on the transaction from which the Iter is created.
type Iter struct {
	patterns *node
	addrs    *node
	names    *node
	maxDepth int // tree or txn maxDepth
}

// Entries returns a range iterator over the entries in the routing tree that exactly match the provided
// pattern. The iterator reflect a snapshot of the routing tree at the time [Iter] is created. This function is safe for
// concurrent use by multiple goroutine and while mutation on entries are ongoing.
func (it Iter) Entries(pattern string) iter.Seq[EntryView] {
	return func(yield func(EntryView) bool) {
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
			if ic.implied {
				continue
			}
			if ic.pattern.str == pattern {
				if !yield(EntryView{e: ic}) {
					return
				}
			}
		}
	}
}

// NamePrefix returns a range iterator over all entries in the routing tree that match a given name prefix. The iterator
// reflect a snapshot of the routing tree at the time [Iter] is created. This function is safe for concurrent use by
// multiple goroutine and while mutation on entries are ongoing.
func (it Iter) NamePrefix(prefix string) iter.Seq[EntryView] {
	return views(func(yield func(*entry) bool) {
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
	})
}

// PatternPrefix returns a range iterator over all entries in the routing tree that match a given pattern prefix.
// The iterator reflect a snapshot of the routing tree at the time [Iter] is created. This function is safe for
// concurrent use by multiple goroutine and while mutation on entries are ongoing.
// Note: Partial parameter syntax (e.g., /users/{name:) is not supported and will not match any entry.
// An entry on an address host is matched on its registered spelling, so a bracketed
// pattern is only reachable through a prefix that starts with '['.
func (it Iter) PatternPrefix(prefix string) iter.Seq[EntryView] {
	return views(it.patternPrefix(prefix, false))
}

// patternPrefix walks the trees yielding either what was registered or what admits an
// authority. A registration is an entry of any kind, with a path or without, and never an
// admission another registration implied, which nobody asked for when asking for entries.
//
// The address root is walked whole rather than guided, its keys are encoded and a textual
// prefix cannot steer the descent, so the registered spelling is filtered instead.
func (it Iter) patternPrefix(prefix string, admissions bool) iter.Seq[*entry] {
	return func(yield func(*entry) bool) {
		if !it.walkPatterns(it.patterns.searchPattern(prefix), prefix, admissions, false, yield) {
			return
		}
		it.walkPatterns(it.addrs, prefix, admissions, true, yield)
	}
}

// walkPatterns yields the matching entries under start and reports whether the walk ran to
// completion rather than being stopped by its consumer. With filterAll set, every entry is
// held to the string prefix, which is what the address root does instead of a guided descent.
func (it Iter) walkPatterns(start *node, prefix string, admissions, filterAll bool, yield func(*entry) bool) bool {
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
				if (admissions && !ic.admits()) || (!admissions && ic.implied) {
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

// Admissions returns a range iterator over the entries admitting an authority, the ones
// implied by per-message entries included. The iterator reflects a snapshot of the routing
// tree at the time [Iter] is created. This function is safe for concurrent use by multiple
// goroutines and while mutations are ongoing.
func (it Iter) Admissions() iter.Seq[EntryView] {
	return views(it.patternPrefix("", true))
}

// All returns a range iterator over all entries registered in the routing tree. The iterator reflect a snapshot
// of the routing tree at the time [Iter] is created. This function is safe for concurrent use by multiple goroutine
// and while mutation on entries are ongoing. See also [Iter.PatternPrefix] as an alternative.
func (it Iter) All() iter.Seq[EntryView] {
	return it.PatternPrefix("")
}

// Names returns a range iterator over all entries registered in the routing tree with a name. The iterator reflect a snapshot
// of the routing tree at the time [Iter] is created. This function is safe for concurrent use by multiple goroutine
// and while mutation on entries are ongoing. See also [Iter.NamePrefix] as an alternative.
func (it Iter) Names() iter.Seq[EntryView] {
	return it.NamePrefix("")
}

// views adapts an internal walk to the read-only view a caller gets.
func views(seq iter.Seq[*entry]) iter.Seq[EntryView] {
	return func(yield func(EntryView) bool) {
		for e := range seq {
			if !yield(EntryView{e: e}) {
				return
			}
		}
	}
}
