package edge

import (
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/fox-toolkit/edge/internal/simplelru"
	"github.com/fox-toolkit/edge/internal/slicesutil"
)

const defaultModifiedCache = 4096

type iTree struct {
	pool         sync.Pool
	p            *Proxy
	patterns     *node
	addrs        *node
	names        *node
	methods      map[string]uint
	interceptors int
	authorities  int
	maxParams    int
	maxDepth     int
}

func (t *iTree) txn() *tXn {
	return &tXn{
		tree:         t,
		patterns:     t.patterns,
		addrs:        t.addrs,
		names:        t.names,
		methods:      t.methods,
		interceptors: t.interceptors,
		authorities:  t.authorities,
		maxParams:    t.maxParams,
		maxDepth:     t.maxDepth,
	}
}

func (t *iTree) lookup(method, host, path string, c *Context, lazy bool) (int, *node) {
	return lookupTarget(t.patterns, t.addrs, method, host, path, c, lazy, false)
}

// lookupTarget is the single entry of both lookups, the request routing and the authority
// decision. It canonicalizes the host and routes it to the root of its kind: an address
// consults addrs, a name consults patterns, and neither ever falls back to the other. Both
// entries share this so the two cannot canonicalize differently, which is an interception
// bypass: a host normalized by one and not the other gets its TLS terminated on a decision
// its requests then miss.
//
// With authority set the walks stop on the host and answer with an authority entry, and no
// method is compared because an authority carries none.
func lookupTarget(patterns, addrs *node, method, host, path string, c *Context, lazy, authority bool) (int, *node) {
	*c.skipStack = (*c.skipStack)[:0]
	// The canonical form exists only inside the lookup, like the routing path of a request.
	if len(host) > 0 && host[len(host)-1] == '.' {
		host = host[:len(host)-1]
	}
	if maybeRoutingAddr(host) {
		if addr, ok := routingAddr(host); ok {
			var buf [maxAddrKey]byte
			key := appendPrefixKey(buf[:0], netip.PrefixFrom(addr, addr.BitLen()))
			return lookupByAddr(addrs, method, key, path, c, lazy, authority)
		}
	}
	return lookupByHostname(patterns, method, host, path, c, lazy, authority)
}

func (t *iTree) allocateContext() *Context {
	return &Context{
		params:    new(make([]string, 0, t.maxParams)),
		skipStack: new(make(skipStack, 0, t.maxDepth)),
		// Read only, never reset: the context always belongs to this tree's pool.
		tree: t,
		// Read only, never reset.
		p: t.p,
	}
}

// interceptor returns the interceptor registered for the exact combination of methods, pattern and
// matchers, or nil.
func (t *iTree) interceptor(methods []string, pattern string, matchers []Matcher) *Interceptor {
	key, isAddr := patternKey(pattern)
	root := t.patterns
	if isAddr {
		root = t.addrs
	}
	matched := root.searchPattern(key)
	if matched == nil || !matched.isLeaf() {
		return nil
	}

	idx := slices.IndexFunc(matched.entries, func(r *Interceptor) bool {
		return r.pattern.path != "" && r.pattern.str == pattern &&
			slicesutil.EqualUnsorted(r.methods, methods) && r.matchersEqual(matchers)
	})
	if idx < 0 {
		return nil
	}
	return matched.entries[idx]
}

// byName returns the interceptor registered under name, or nil.
func (t *iTree) byName(name string) *Interceptor {
	matched := t.names.searchName(name)
	if matched == nil || !matched.isLeaf() {
		return nil
	}
	if matched.entries[0].name != name {
		return nil
	}
	return matched.entries[0]
}

type tXn struct {
	tree         *iTree
	writable     *simplelru.LRU[*node, struct{}]
	patterns     *node
	addrs        *node
	names        *node
	methods      map[string]uint
	interceptors int
	authorities  int
	maxParams    int
	maxDepth     int
	forked       bool
	mode         insertMode
}

func (t *tXn) commit() *iTree {
	tc := &iTree{
		patterns:     t.patterns,
		addrs:        t.addrs,
		names:        t.names,
		methods:      t.methods,
		p:            t.tree.p,
		interceptors: t.interceptors,
		authorities:  t.authorities,
		maxParams:    t.maxParams,
		maxDepth:     t.maxDepth,
	}
	tc.pool = sync.Pool{
		New: func() any {
			return tc.allocateContext()
		},
	}
	t.writable = nil
	t.forked = false
	return tc
}

// clone capture a point-in-time clone of the transaction. The cloned transaction will contain
// any uncommitted writes in the original transaction but further mutations to either will be independent and result
// in different tree on commit.
func (t *tXn) clone() *tXn {
	t.writable = nil
	t.forked = false
	tx := &tXn{
		tree:         t.tree,
		patterns:     t.patterns,
		addrs:        t.addrs,
		names:        t.names,
		methods:      t.methods,
		interceptors: t.interceptors,
		authorities:  t.authorities,
		maxParams:    t.maxParams,
		maxDepth:     t.maxDepth,
	}
	return tx
}

// rootFor returns the root ic's pattern lives under. The insert, delete and search
// machinery walks whatever root it is handed, so this is the whole of the dispatch.
func (t *tXn) rootFor(ic *Interceptor) *node {
	if ic.pattern.prefix.IsValid() {
		return t.addrs
	}
	return t.patterns
}

func (t *tXn) setRootFor(ic *Interceptor, root *node) {
	if ic.pattern.prefix.IsValid() {
		t.addrs = root
		return
	}
	t.patterns = root
}

func (t *tXn) insertName(ic *Interceptor, mode insertMode) error {
	newRoot, err := t.insertNameIn(t.names, ic.name, ic, mode)
	if err != nil {
		return err
	}
	if newRoot != nil {
		t.names = newRoot
	}
	return nil
}

func (t *tXn) insertNameIn(n *node, search string, ic *Interceptor, mode insertMode) (*node, error) {
	if len(search) == 0 {
		if n.isLeaf() && mode != modeUpdate {
			// Unlike the regular insert path, where we don't know whether an interceptor exists for the given name,
			// update mode provides a stronger guarantee: the caller has already verified that old.name == new.name
			// before invoking insert. This precondition eliminates the need to check for update errors in cases
			// like node splitting, which the standard insert path must handle.
			return nil, &InterceptorNameConflictError{New: ic, Conflict: n.entries[0]}
		}

		nc := t.writeNode(n)
		nc.entries = []*Interceptor{ic}
		return nc, nil
	}

	idx, child := n.getStaticEdge(search[0])
	if child == nil {
		newChild := &node{
			label:   search[0],
			key:     search,
			entries: []*Interceptor{ic},
		}

		nc := t.writeNode(n)
		nc.addStaticEdge(newChild)
		return nc, nil
	}

	commonPrefix := longestPrefix(search, child.key)
	if commonPrefix == len(child.key) {
		search = search[commonPrefix:]
		newChild, err := t.insertNameIn(child, search, ic, mode)
		if err != nil {
			return nil, err
		}
		nc := t.writeNode(n)
		nc.statics[idx] = newChild
		return nc, nil
	}

	nc := t.writeNode(n)
	splitNode := &node{
		label: search[0],
		key:   search[:commonPrefix],
	}
	nc.replaceStaticEdge(splitNode)

	modChild := t.writeNode(child)
	modChild.label = modChild.key[commonPrefix]
	modChild.key = modChild.key[commonPrefix:]
	splitNode.addStaticEdge(modChild)

	search = search[commonPrefix:]
	if len(search) == 0 {
		splitNode.entries = []*Interceptor{ic}
		return nc, nil
	}

	splitNode.addStaticEdge(&node{
		label:   search[0],
		key:     search,
		entries: []*Interceptor{ic},
	})
	return nc, nil
}

func (t *tXn) deleteName(ic *Interceptor) bool {
	newRoot := t.deleteNameIn(t.names, t.names, ic.name)
	if newRoot != nil {
		t.names = newRoot
		return true
	}

	return false
}

func (t *tXn) deleteNameIn(root, n *node, search string) *node {
	if len(search) == 0 {
		if !n.isLeaf() {
			return nil
		}

		nc := t.writeNode(n)
		nc.entries = nil

		if n != root && len(nc.statics) == 1 {
			t.mergeChild(nc)
		}

		return nc
	}

	label := search[0]
	idx, child := n.getStaticEdge(label)
	if child == nil || !strings.HasPrefix(search, child.key) {
		return nil
	}

	// Consume the matched portion
	search = search[len(child.key):]

	newChild := t.deleteNameIn(root, child, search)
	if newChild == nil {
		return nil
	}

	nc := t.writeNode(n)

	if !newChild.isLeaf() && len(newChild.statics) == 0 {
		nc.delStaticEdge(label)
		if n != root && !nc.isLeaf() && len(nc.statics) == 1 {
			t.mergeChild(nc)
		}
	} else {
		nc.statics[idx] = newChild
	}

	return nc
}

// insert performs a recursive copy-on-write insertion.
func (t *tXn) insert(ic *Interceptor, mode insertMode) error {
	t.mode = mode

	newRoot, err := t.insertTokens(nil, t.rootFor(ic), ic.pattern.tokens, ic)
	if err != nil {
		return err
	}
	if newRoot != nil {
		t.setRootFor(ic, newRoot)
		t.maxDepth = max(t.maxDepth, t.computePathDepth(newRoot, ic.pattern.tokens))
		t.maxParams = max(t.maxParams, len(ic.params))
		if t.mode == modeInsert {
			if ic.pattern.path == "" {
				t.authorities++
			} else {
				t.interceptors++
			}
			if len(ic.methods) > 0 {
				if !t.forked {
					t.methods = maps.Clone(t.methods)
					t.forked = true
				}

				for _, method := range ic.methods {
					t.methods[method]++
				}
			}
		}
	}
	return nil
}

func (t *tXn) insertTokens(p, n *node, tokens []token, ic *Interceptor) (*node, error) {
	// Base case: no tokens left, attach the interceptor
	if len(tokens) == 0 {
		switch t.mode {
		case modeInsert:
			if n.isLeaf() {
				var conflicts []*Interceptor
				for _, r := range n.entries {
					if r.samePort(ic) && r.matchersEqual(ic.matchers) && slicesutil.Overlap(r.methods, ic.methods) {
						conflicts = append(conflicts, r)
					}
				}
				if len(conflicts) > 0 {
					return nil, &InterceptorConflictError{New: ic, Conflicts: conflicts}
				}
			}

			// Optional catch-all conflict detection:
			// Interceptors like /foo/ and /foo/*{any} conflict because a request to /foo/ always matches the exact interceptor,
			// making /foo/*{any} unreachable. The correct semantic is to use /foo/+{any} which doesn't capture empty segments.
			//
			// We handle both insertion orders:
			//   1. /foo/ then /foo/*{any}: check parent for existing exact match
			//   2. /foo/*{any} then /foo/: check child wildcards with catchEmpty flag
			//
			// Conflicts are method-aware: GET /foo/ and POST /foo/*{any} don't conflict since they route to different method sets.
			// A method-less exact interceptor matches every method, so it conflicts with a catch-all regardless of its methods.
			// Conflicts are matcher-aware: /foo/?x=y and /foo/*{any}?a=b don't conflict because the exact path's matcher
			// creates a gap, such as request with ?a=b (but not ?x=y) fail the exact match and fall through to the catch-empty.
			// Since pattern matching precedes matcher evaluation, a conflict occurs when the exact path has no matchers (shadows all requests
			// to that pattern) or matchers equal to the catch-empty's (both match the same request).
			var conflicts []*Interceptor
			if ic.pattern.optionalCatchAll && p != nil {
				for _, r := range p.entries {
					if r.samePort(ic) && (len(r.matchers) == 0 || r.matchersEqual(ic.matchers)) && (len(r.methods) == 0 || slicesutil.Overlap(r.methods, ic.methods)) {
						conflicts = append(conflicts, r)
					}
				}
			}
			if len(conflicts) > 0 {
				return nil, &InterceptorConflictError{New: ic, Conflicts: conflicts, isShadowed: true}
			}

			for _, wildcard := range n.wildcards {
				for _, r := range wildcard.entries {
					if r.pattern.optionalCatchAll && r.samePort(ic) && (len(ic.matchers) == 0 || ic.matchersEqual(r.matchers)) && (len(ic.methods) == 0 || slicesutil.Overlap(ic.methods, r.methods)) {
						conflicts = append(conflicts, r)
					}
				}
			}
			if len(conflicts) > 0 {
				return nil, &InterceptorConflictError{New: ic, Conflicts: conflicts, isShadowed: true}
			}

			if ic.name != "" {
				if err := t.insertName(ic, modeInsert); err != nil {
					return nil, err
				}
			}

			nc := t.writeNode(n)
			nc.addEntry(ic)
			return nc, nil
		case modeUpdate:
			idx := slices.IndexFunc(n.entries, func(r *Interceptor) bool {
				return r.pattern.str == ic.pattern.str && slices.Equal(r.methods, ic.methods) && r.matchersEqual(ic.matchers)
			})
			if idx == -1 {
				return nil, newInterceptorNotFoundError(ic)
			}

			oldIC := n.entries[idx]
			// Updating an interceptor supports mutating the handler, option, and interceptor name. Name changes require
			// extra care. If the caller updates an interceptor without providing a name, any previously registered name
			// is deleted. If the same name is provided, the interceptor for that name is updated. The most complex case
			// is when the caller wants to change the name: we must delete the old name entry and register the new one.
			// The order of operations is critical here; if any step fails (e.g., the new name collides with an
			// existing one), we must not have cloned any nodes while traversing the names tree. Therefore, we always
			// attempt the name insertion first, then update the patterns tree only on success.
			if oldIC.name != "" {
				// If the new interceptor has no name, we simply need to delete the old name (and the new one will not have
				// any name registered)
				if ic.name == "" {
					t.deleteName(n.entries[idx])
				} else if oldIC.name == ic.name {
					// If the new interceptor name is equal to the old interceptor name, we need to update the registered name with
					// the new interceptor. Since we have the guarantee that it exist at oldIC.name, this cannot fail.
					if err := t.insertName(ic, modeUpdate); err != nil {
						panic(fmt.Errorf("internal error: update name: %w", err))
					}
				} else {
					// If the new interceptor name is different from the old interceptor name, we first try to insert the new name and
					// then only on success, we can safely deregister the old name.
					if err := t.insertName(ic, modeInsert); err != nil {
						return nil, err
					}
					t.deleteName(n.entries[idx])
				}

				nc := t.writeNode(n)
				nc.replaceEntry(idx, ic)
				return nc, nil
			}

			// Last but not least, oldIC may not have any name registered, and in this case this is a simple
			// insert for this new name.
			if ic.name != "" {
				if err := t.insertName(ic, modeInsert); err != nil {
					return nil, err
				}
			}

			nc := t.writeNode(n)
			nc.replaceEntry(idx, ic)
			return nc, nil
		default:
			panic("internal error: unexpected insert mode")
		}
	}

	tk := tokens[0]
	remaining := tokens[1:]

	switch tk.typ {
	case nodeStatic:
		return t.insertStatic(p, n, tk, remaining, ic)
	case nodeParam:
		return t.insertParam(n, tk, remaining, ic)
	case nodeWildcard:
		return t.insertWildcard(n, tk, remaining, ic)
	default:
		panic("internal error: unknown token type")
	}
}

func (t *tXn) insertStatic(p, n *node, tk token, remaining []token, ic *Interceptor) (*node, error) {
	search := tk.value

	if len(search) == 0 {
		return t.insertTokens(p, n, remaining, ic)
	}

	idx, child := n.getStaticEdge(search[0])
	if child == nil {
		if t.mode == modeUpdate {
			return nil, newInterceptorNotFoundError(ic)
		}

		newChild, err := t.insertTokens(
			n,
			&node{
				label: search[0],
				key:   search,
				host:  tk.hsplit,
			},
			remaining,
			ic,
		)
		if err != nil {
			return nil, err
		}
		nc := t.writeNode(n)
		nc.addStaticEdge(newChild)
		return nc, nil
	}

	commonPrefix := longestPrefix(search, child.key)
	if commonPrefix == len(child.key) {
		search = search[commonPrefix:]
		remaining = append([]token{{typ: nodeStatic, value: search, hsplit: tk.hsplit}}, remaining...)
		// e.g. child /foo and want insert /fooo, insert "o"
		newChild, err := t.insertTokens(n, child, remaining, ic)
		if err != nil {
			return nil, err
		}
		nc := t.writeNode(n)
		nc.statics[idx] = newChild
		return nc, nil
	}

	if t.mode == modeUpdate {
		return nil, newInterceptorNotFoundError(ic)
	}

	// All following case require creating a split node.
	splitNode := &node{
		label: search[0],
		key:   search[:commonPrefix],
		host:  tk.hsplit,
	}

	search = search[commonPrefix:]
	if len(search) == 0 {
		// e.g. we have /foo and want to insert /fo,
		// we first split /foo into /fo, o and then fo <- get the new interceptor
		if len(remaining) > 0 {
			newSplitNode, err := t.insertTokens(n, splitNode, remaining, ic)
			if err != nil {
				return nil, err
			}

			nc := t.writeNode(n)
			nc.replaceStaticEdge(newSplitNode)

			// Restore the existing child node
			modChild := t.writeNode(child)
			modChild.label = modChild.key[commonPrefix]
			modChild.key = modChild.key[commonPrefix:]
			newSplitNode.addStaticEdge(modChild)

			return nc, nil
		}

		if ic.name != "" {
			if err := t.insertName(ic, modeInsert); err != nil {
				return nil, err
			}
		}

		nc := t.writeNode(n)
		nc.replaceStaticEdge(splitNode)

		modChild := t.writeNode(child)
		modChild.label = modChild.key[commonPrefix]
		modChild.key = modChild.key[commonPrefix:]
		splitNode.addStaticEdge(modChild)
		splitNode.entries = []*Interceptor{ic}
		return nc, nil
	}

	// e.g. we have /foo and want to insert /fob
	// we first have our splitNode /fo, with old child (modChild) equal o, and insert the edge b
	newChild, err := t.insertTokens(
		n,
		&node{
			label: search[0],
			key:   search,
			host:  tk.hsplit,
		},
		remaining,
		ic,
	)
	if err != nil {
		return nil, err
	}

	nc := t.writeNode(n)
	nc.replaceStaticEdge(splitNode)

	modChild := t.writeNode(child)
	modChild.label = modChild.key[commonPrefix]
	modChild.key = modChild.key[commonPrefix:]
	splitNode.addStaticEdge(modChild)
	splitNode.addStaticEdge(newChild)
	return nc, nil
}

func (t *tXn) insertParam(n *node, tk token, remaining []token, ic *Interceptor) (*node, error) {
	key := canonicalKey(tk)
	idx, child := n.getParamEdge(key)
	if child == nil {
		if t.mode == modeUpdate {
			return nil, newInterceptorNotFoundError(ic)
		}

		newChild, err := t.insertTokens(
			n,
			&node{
				key:    key,
				regexp: tk.regexp,
			},
			remaining,
			ic,
		)
		if err != nil {
			return nil, err
		}

		nc := t.writeNode(n)
		nc.addParamEdge(newChild)
		return nc, nil
	}

	newChild, err := t.insertTokens(n, child, remaining, ic)
	if err != nil {
		return nil, err
	}

	nc := t.writeNode(n)
	nc.params[idx] = newChild
	return nc, nil
}

func (t *tXn) insertWildcard(n *node, tk token, remaining []token, ic *Interceptor) (*node, error) {
	key := canonicalKey(tk)
	idx, child := n.getWildcardEdge(key)
	if child == nil {
		if t.mode == modeUpdate {
			return nil, newInterceptorNotFoundError(ic)
		}

		newChild, err := t.insertTokens(
			n,
			&node{
				key:    key,
				regexp: tk.regexp,
			},
			remaining,
			ic,
		)
		if err != nil {
			return nil, err
		}
		nc := t.writeNode(n)
		nc.addWildcardEdge(newChild)
		return nc, nil
	}

	newChild, err := t.insertTokens(n, child, remaining, ic)
	if err != nil {
		return nil, err
	}
	nc := t.writeNode(n)
	nc.wildcards[idx] = newChild
	return nc, nil
}

// delete performs a recursive copy-on-write deletion.
// searchAuthority returns the entry registered for the same authority pattern as ic,
// whatever its action, or nil. An authority carries no method, so it identifies at most one.
func (t *tXn) searchAuthority(ic *Interceptor) *Interceptor {
	matched := t.rootFor(ic).searchPattern(ic.pattern.key)
	if matched == nil || !matched.isLeaf() {
		return nil
	}
	for _, r := range matched.entries {
		if r.pattern.str == ic.pattern.str && r.matchersEqual(ic.matchers) {
			return r
		}
	}
	return nil
}

func (t *tXn) delete(ic *Interceptor) (*Interceptor, bool) {
	root := t.rootFor(ic)
	newRoot, oldIC := t.deleteTokens(root, root, ic.pattern.tokens, ic)
	if newRoot != nil {
		t.setRootFor(ic, newRoot)
		if !t.forked && len(ic.methods) > 0 {
			t.methods = maps.Clone(t.methods)
			t.forked = true
		}
	}

	if oldIC != nil {
		if ic.pattern.path == "" {
			t.authorities--
		} else {
			t.interceptors--
		}
		for _, method := range ic.methods {
			t.methods[method]--
			if n, ok := t.methods[method]; ok && n == 0 {
				delete(t.methods, method)
			}
		}
		return oldIC, true
	}

	return nil, false
}

func (t *tXn) deleteTokens(root, n *node, tokens []token, ic *Interceptor) (*node, *Interceptor) {
	if len(tokens) == 0 {
		if !n.isLeaf() {
			return nil, nil
		}

		idx := slices.IndexFunc(n.entries, func(r *Interceptor) bool {
			return r.pattern.str == ic.pattern.str && slices.Equal(r.methods, ic.methods) && r.matchersEqual(ic.matchers)
		})
		if idx == -1 {
			return nil, nil
		}

		oldIC := n.entries[idx]
		nc := t.writeNode(n)
		nc.delIC(idx)
		if oldIC.name != "" {
			t.deleteName(oldIC) // The root key always hold the http method.
		}

		if n != root &&
			!nc.isLeaf() &&
			len(nc.statics) == 1 &&
			len(nc.params) == 0 &&
			len(nc.wildcards) == 0 {
			t.mergeChild(nc)
		}

		return nc, oldIC
	}

	tk := tokens[0]
	remaining := tokens[1:]

	switch tk.typ {
	case nodeStatic:
		return t.deleteStatic(root, n, tk.value, remaining, ic)
	case nodeParam:
		return t.deleteParam(root, n, canonicalKey(tk), remaining, ic)
	case nodeWildcard:
		return t.deleteWildcard(root, n, canonicalKey(tk), remaining, ic)
	default:
		panic("internal error: unknown token type")
	}
}

func (t *tXn) deleteStatic(root, n *node, search string, remaining []token, ic *Interceptor) (*node, *Interceptor) {
	if len(search) == 0 {
		return t.deleteTokens(root, n, remaining, ic)
	}

	label := search[0]
	idx, child := n.getStaticEdge(label)
	if child == nil || !strings.HasPrefix(search, child.key) {
		return nil, nil
	}

	// Consume the matched portion
	search = search[len(child.key):]

	// Prepend remaining static portion if any
	if len(search) > 0 {
		remaining = append([]token{{typ: nodeStatic, value: search}}, remaining...)
	}

	newChild, deletedIC := t.deleteTokens(root, child, remaining, ic)
	if deletedIC == nil {
		return nil, nil
	}

	nc := t.writeNode(n)

	if !newChild.isLeaf() &&
		len(newChild.statics) == 0 &&
		len(newChild.params) == 0 &&
		len(newChild.wildcards) == 0 {
		nc.delStaticEdge(label)

		if n != root &&
			!nc.isLeaf() &&
			len(nc.statics) == 1 &&
			len(nc.params) == 0 &&
			len(nc.wildcards) == 0 {
			t.mergeChild(nc)
		}
	} else {
		nc.statics[idx] = newChild
	}

	return nc, deletedIC
}

func (t *tXn) deleteParam(root, n *node, key string, remaining []token, ic *Interceptor) (*node, *Interceptor) {
	idx, child := n.getParamEdge(key)
	if child == nil {
		return nil, nil
	}

	// Recurse into param's children
	newChild, deletedIC := t.deleteTokens(root, child, remaining, ic)
	if deletedIC == nil {
		return nil, nil
	}

	nc := t.writeNode(n)

	// If param node is now empty, remove it
	if !newChild.isLeaf() &&
		len(newChild.statics) == 0 &&
		len(newChild.params) == 0 &&
		len(newChild.wildcards) == 0 {
		nc.delParamEdge(key)

		if n != root &&
			len(nc.statics) == 1 &&
			!nc.isLeaf() &&
			len(nc.params) == 0 &&
			len(nc.wildcards) == 0 {
			t.mergeChild(nc)
		}

	} else {
		nc.params[idx] = newChild
	}

	return nc, deletedIC
}

func (t *tXn) deleteWildcard(root, n *node, key string, remaining []token, ic *Interceptor) (*node, *Interceptor) {
	idx, child := n.getWildcardEdge(key)
	if child == nil {
		return nil, nil
	}

	// Recurse into wildcard's children
	newChild, deletedIC := t.deleteTokens(root, child, remaining, ic)
	if deletedIC == nil {
		return nil, nil
	}

	nc := t.writeNode(n)

	// If wildcard node is now empty, remove it
	if !newChild.isLeaf() &&
		len(newChild.statics) == 0 &&
		len(newChild.params) == 0 &&
		len(newChild.wildcards) == 0 {
		nc.delWildcardEdge(key)

		if n != root &&
			len(nc.statics) == 1 &&
			!nc.isLeaf() &&
			len(nc.params) == 0 &&
			len(nc.wildcards) == 0 {
			t.mergeChild(nc)
		}
	} else {
		nc.wildcards[idx] = newChild
	}

	return nc, deletedIC
}

func (t *tXn) truncate() {
	t.patterns = new(node)
	t.addrs = new(node)
	t.names = new(node)
	t.methods = make(map[string]uint)
	t.maxDepth = 0
	t.maxParams = 0
	t.interceptors = 0
	t.authorities = 0
	t.writable = nil
	t.forked = true
}

func (t *tXn) computePathDepth(root *node, tokens []token) int {
	var depth int
	current := root

	if len(current.params) > 0 || len(current.wildcards) > 0 {
		depth++
	}

	for _, tk := range tokens {
		switch tk.typ {
		case nodeStatic:
			search := tk.value
			for len(search) > 0 {
				_, child := current.getStaticEdge(search[0])
				if child == nil || !strings.HasPrefix(search, child.key) {
					current = nil
					break
				}
				search = search[len(child.key):]
				current = child
				if len(current.params) > 0 || len(current.wildcards) > 0 {
					depth++
				}
			}
		case nodeParam:
			_, current = current.getParamEdge(canonicalKey(tk))
		case nodeWildcard:
			_, current = current.getWildcardEdge(canonicalKey(tk))
		}

		if current == nil {
			break
		}
	}

	return depth
}

func (t *tXn) writeNode(n *node) *node {
	if t.writable == nil {
		lru, err := simplelru.NewLRU[*node, struct{}](defaultModifiedCache, nil)
		if err != nil {
			panic(err)
		}
		t.writable = lru
	}

	if _, ok := t.writable.Get(n); ok {
		return n
	}

	nc := &node{
		label:  n.label,
		key:    n.key,
		regexp: n.regexp,
		host:   n.host,
	}

	if len(n.entries) != 0 {
		nc.entries = make([]*Interceptor, len(n.entries))
		copy(nc.entries, n.entries)
	}
	if len(n.statics) != 0 {
		nc.statics = make([]*node, len(n.statics))
		copy(nc.statics, n.statics)
	}
	if len(n.params) != 0 {
		nc.params = make([]*node, len(n.params))
		copy(nc.params, n.params)
	}
	if len(n.wildcards) != 0 {
		nc.wildcards = make([]*node, len(n.wildcards))
		copy(nc.wildcards, n.wildcards)
	}

	t.writable.Add(nc, struct{}{})
	return nc
}

// mergeChild is called to collapse the given node with its child. This is only
// called when the given node is not a leaf and has a single edge.
func (t *tXn) mergeChild(n *node) {
	child := n.statics[0]

	// A node that belong to a wildcard or param cannot be merged with a child.
	if n.label == 0x00 {
		return
	}
	// A node that belong to a host cannot be merged with a child key that start with a '/'.
	if n.host && strings.HasPrefix(child.key, "/") {
		return
	}

	// Merge nodes
	n.key = concat(n.key, child.key)

	if len(child.entries) != 0 {
		n.entries = make([]*Interceptor, len(child.entries))
		copy(n.entries, child.entries)
	}

	if len(child.statics) != 0 {
		n.statics = make([]*node, len(child.statics))
		copy(n.statics, child.statics)
	} else {
		n.statics = nil
	}

	if len(child.params) != 0 {
		n.params = make([]*node, len(child.params))
		copy(n.params, child.params)
	}

	if len(child.wildcards) != 0 {
		n.wildcards = make([]*node, len(child.wildcards))
		copy(n.wildcards, child.wildcards)
	}
}

// longestPrefix finds the length of the shared prefix of two strings
func longestPrefix(k1, k2 string) int {
	max := len(k1)
	if l := len(k2); l < max {
		max = l
	}
	var i int
	for i = 0; i < max; i++ {
		if k1[i] != k2[i] {
			break
		}
	}
	return i
}

// concat two string
func concat(a, b string) string {
	return a + b
}

// canonicalKey returns the internal key representation for a token.
// Returns the regexp pattern if present, otherwise returns a normalized
// placeholder ("?" for params, "*" for catch-alls).
func canonicalKey(tk token) string {
	if tk.regexp != nil {
		return rawExpr(tk.regexp)
	}
	switch tk.typ {
	case nodeParam:
		return "?"
	case nodeWildcard:
		return "*"
	default:
		panic("internal error: unknown token type")
	}
}

type insertMode uint8

const (
	modeInsert insertMode = iota
	modeUpdate
)

type nodeType uint8

const (
	nodeStatic nodeType = iota
	nodeParam
	nodeWildcard
)

type token struct {
	// Compiled regular expression constraint for params/wildcards, nil if none.
	regexp *regexp.Regexp
	// The literal string value of this token segment.
	value string
	// The type of this token: static, param, or wildcard.
	typ nodeType
	// True if this token is part of the hostname portion of the interceptor.
	// Nodes created from tokens with hsplit=true cannot be merged
	// during deletion to preserve the hostname/path boundary for lookupByPath optimization.
	// Only relevant for nodeStatic tokens since params and wildcards
	// are isolated in their own nodes and never merged.
	hsplit bool
}
