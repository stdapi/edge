package edge

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/stdapi/edge/internal/regprog"
	"github.com/stdapi/edge/internal/simplelru"
)

const defaultModifiedCache = 4096

type iTree struct {
	pool       sync.Pool
	p          *Proxy
	patterns   *node
	addrs      *node
	names      *node
	handlers   int
	admissions int
	maxParams  int
	maxDepth   int
}

func (t *iTree) txn() *tXn {
	return &tXn{
		tree:       t,
		patterns:   t.patterns,
		addrs:      t.addrs,
		names:      t.names,
		handlers:   t.handlers,
		admissions: t.admissions,
		maxParams:  t.maxParams,
		maxDepth:   t.maxDepth,
	}
}

func (t *iTree) lookup(host, path string, c *routeCtx, lazy bool) (int, *node) {
	return lookupTarget(t.patterns, t.addrs, host, path, c, lazy, 0)
}

// route returns the entry serving the request c was reset with. A failed walk may leave
// captures behind, and every reader bounds them on entry.params, empty for a [WithNoEntry]
// handler.
func (t *iTree) route(c *routeCtx, lazy bool) *entry {
	idx, n := t.lookup(c.host, routingPath(c.req), c, lazy)
	if n != nil {
		return n.entries[idx]
	}
	if canonicalHost(c.host) == "" {
		return nil
	}
	return t.p.cfg.noEntryFor(c)
}

// canonicalHost returns host without its root label, or an empty string for a host ending in
// an empty label or containing a slash, which no entry can admit. A hostname walk would match
// a slash against the path keys below the hostname.
func canonicalHost(host string) string {
	host = strings.TrimSuffix(host, ".")
	if strings.HasSuffix(host, ".") || strings.IndexByte(host, slashDelim) >= 0 {
		return ""
	}
	return host
}

// lookupTarget is the single entry of both lookups, the request routing and the admission
// decision. It canonicalizes the host and routes it to the root of its kind: an address
// consults addrs, a name consults patterns, and neither ever falls back to the other. Both
// entries share this so the two cannot canonicalize differently, which is a termination
// bypass: a host normalized by one and not the other gets its TLS terminated on a decision
// its requests then miss.
//
// With admit set the walks stop on the host and answer with the entry admitting that kind.
func lookupTarget(patterns, addrs *node, host, path string, c *routeCtx, lazy bool, admit Kind) (int, *node) {
	*c.skipStack = (*c.skipStack)[:0]
	if c.lookup.dirty {
		c.lookup.reset()
	}
	// The canonical form exists only inside the lookup, like the routing path of a request.
	host = canonicalHost(host)
	if maybeRoutingAddr(host) {
		if addr, ok := routingAddr(host); ok {
			var buf [maxAddrKey]byte
			key := appendPrefixKey(buf[:0], netip.PrefixFrom(addr, addr.BitLen()))
			return lookupByAddr(addrs, key, path, c, lazy, admit)
		}
	}
	return lookupByHostname(patterns, host, path, c, lazy, admit)
}

func (t *iTree) allocateContext() *routeCtx {
	c := &routeCtx{
		params:    new(make([]string, 0, t.maxParams)),
		skipStack: new(make(skipStack, 0, t.maxDepth)),
		// Read only, never reset.
		p: t.p,
	}
	c.http.r = c
	c.grpc.http = &c.http
	return c
}

// entryFor returns the entry registered for the exact combination of kind, pattern and
// matchers, or nil.
func (t *iTree) entryFor(kind Kind, pattern string, matchers []RequestMatcher) *entry {
	key, isAddr := patternKey(pattern)
	root := t.patterns
	if isAddr {
		root = t.addrs
	}
	matched := root.searchPattern(key)
	if matched == nil || !matched.isLeaf() {
		return nil
	}

	idx := slices.IndexFunc(matched.entries, func(r *entry) bool {
		return r.handler != nil && r.kind == kind && r.pattern.str == pattern &&
			r.matchersEqual(matchers)
	})
	if idx < 0 {
		return nil
	}
	return matched.entries[idx]
}

// byName returns the interceptor registered under name, or nil.
func (t *iTree) byName(name string) *entry {
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
	tree     *iTree
	writable *simplelru.LRU[*node, struct{}]
	patterns *node
	addrs    *node
	names    *node
	// pending is the admission implied by the entry being inserted or deleted, claimed by
	// the descent at the host node and settled on the unwind.
	pending    *entry
	pathTokens int
	handlers   int
	admissions int
	maxParams  int
	maxDepth   int
	mode       insertMode
}

func (t *tXn) commit() *iTree {
	tc := &iTree{
		patterns:   t.patterns,
		addrs:      t.addrs,
		names:      t.names,
		p:          t.tree.p,
		handlers:   t.handlers,
		admissions: t.admissions,
		maxParams:  t.maxParams,
		maxDepth:   t.maxDepth,
	}
	tc.pool = sync.Pool{
		New: func() any {
			return tc.allocateContext()
		},
	}
	t.writable = nil
	return tc
}

// clone capture a point-in-time clone of the transaction. The cloned transaction will contain
// any uncommitted writes in the original transaction but further mutations to either will be independent and result
// in different tree on commit.
func (t *tXn) clone() *tXn {
	t.writable = nil
	tx := &tXn{
		tree:       t.tree,
		patterns:   t.patterns,
		addrs:      t.addrs,
		names:      t.names,
		handlers:   t.handlers,
		admissions: t.admissions,
		maxParams:  t.maxParams,
		maxDepth:   t.maxDepth,
	}
	return tx
}

// snapshot returns the roots as they stand. Dropping writable makes the next write copy the
// nodes it touches, which a snapshot may still reach.
func (t *tXn) snapshot() (patterns, addrs, names *node) {
	t.writable = nil
	return t.patterns, t.addrs, t.names
}

// rootFor returns the root ic's pattern lives under. The insert, delete and search
// machinery walks whatever root it is handed, so this is the whole of the dispatch.
func (t *tXn) rootFor(ic *entry) *node {
	if ic.pattern.prefix.IsValid() {
		return t.addrs
	}
	return t.patterns
}

func (t *tXn) setRootFor(ic *entry, root *node) {
	if ic.pattern.prefix.IsValid() {
		t.addrs = root
		return
	}
	t.patterns = root
}

func (t *tXn) insertName(ic *entry, mode insertMode) error {
	newRoot, err := t.insertNameIn(t.names, ic.name, ic, mode)
	if err != nil {
		return err
	}
	if newRoot != nil {
		t.names = newRoot
	}
	return nil
}

func (t *tXn) insertNameIn(n *node, search string, ic *entry, mode insertMode) (*node, error) {
	if len(search) == 0 {
		if n.isLeaf() && mode != modeUpdate {
			// Unlike the regular insert path, where we don't know whether an interceptor exists for the given name,
			// update mode provides a stronger guarantee: the caller has already verified that old.name == new.name
			// before invoking insert. This precondition eliminates the need to check for update errors in cases
			// like node splitting, which the standard insert path must handle.
			return nil, &EntryNameConflictError{New: ic, Conflict: n.entries[0]}
		}

		nc := t.writeNode(n)
		nc.entries = []*entry{ic}
		return nc, nil
	}

	idx, child := n.getStaticEdge(search[0])
	if child == nil {
		newChild := &node{
			label:   search[0],
			key:     search,
			entries: []*entry{ic},
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
		splitNode.entries = []*entry{ic}
		return nc, nil
	}

	splitNode.addStaticEdge(&node{
		label:   search[0],
		key:     search,
		entries: []*entry{ic},
	})
	return nc, nil
}

func (t *tXn) deleteName(ic *entry) bool {
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
func (t *tXn) insert(ic *entry, mode insertMode, adm *entry) error {
	t.mode = mode
	t.pending = adm
	t.pathTokens = len(ic.pattern.tokens) - ic.pattern.pathStart

	newRoot, err := t.insertTokens(nil, t.rootFor(ic), ic.pattern.tokens, ic)
	t.pending = nil
	if err != nil {
		return err
	}
	if newRoot != nil {
		t.setRootFor(ic, newRoot)
		t.maxDepth = max(t.maxDepth, t.computePathDepth(newRoot, ic.pattern.tokens))
		t.maxParams = max(t.maxParams, len(ic.params))
		if t.mode == modeInsert {
			t.handlers++
		}
	}
	return nil
}

func (t *tXn) insertTokens(p, n *node, tokens []token, ic *entry) (*node, error) {
	// len(tokens) first drops to pathTokens on the node ending the host tokens. Applying
	// the admission on the unwind keeps every failure ahead of the first mutation.
	if t.pending != nil && len(tokens) == t.pathTokens {
		adm := t.pending
		t.pending = nil
		nc, err := t.insertTokens(p, n, tokens, ic)
		if err != nil {
			return nil, err
		}
		t.applyAdmission(nc, adm)
		return nc, nil
	}

	// Base case: no tokens left, attach the interceptor
	if len(tokens) == 0 {
		switch t.mode {
		case modeInsert:
			if n.isLeaf() {
				var conflicts []*entry
				for _, r := range n.entries {
					if r.kind == ic.kind && r.samePort(ic) && r.matchersEqual(ic.matchers) {
						conflicts = append(conflicts, r)
					}
				}
				if len(conflicts) > 0 {
					return nil, &EntryConflictError{New: ic, Conflicts: conflicts}
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
			// Conflicts are kind-aware: an HTTP entry and a gRPC entry on one pattern never shadow one
			// another, the request itself telling them apart.
			// Conflicts are matcher-aware: /foo/?x=y and /foo/*{any}?a=b don't conflict because the exact path's matcher
			// creates a gap, such as request with ?a=b (but not ?x=y) fail the exact match and fall through to the catch-empty.
			// The exact path is tried first, so it shadows the catch-empty when each of its matchers, if it has any, is also a
			// matcher of the catch-empty. Matchers are compared with Equal, so one accepting more requests than another, such as
			// GET,POST over GET, is not detected.
			var conflicts []*entry
			if ic.pattern.optionalCatchAll && p != nil {
				for _, r := range p.entries {
					if r.kind == ic.kind && r.samePort(ic) && r.matchersWithin(ic) {
						conflicts = append(conflicts, r)
					}
				}
			}
			if len(conflicts) > 0 {
				return nil, &EntryConflictError{New: ic, Conflicts: conflicts, isShadowed: true}
			}

			for _, wildcard := range n.wildcards {
				for _, r := range wildcard.entries {
					if r.pattern.optionalCatchAll && r.kind == ic.kind && r.samePort(ic) && ic.matchersWithin(r) {
						conflicts = append(conflicts, r)
					}
				}
			}
			if len(conflicts) > 0 {
				return nil, &EntryConflictError{New: ic, Conflicts: conflicts, isShadowed: true}
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
			idx := slices.IndexFunc(n.entries, func(r *entry) bool {
				return r.kind == ic.kind && r.pattern.str == ic.pattern.str && r.matchersEqual(ic.matchers)
			})
			if idx == -1 {
				return nil, newEntryNotFoundError(ic)
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

func (t *tXn) insertStatic(p, n *node, tk token, remaining []token, ic *entry) (*node, error) {
	search := tk.value

	if len(search) == 0 {
		return t.insertTokens(p, n, remaining, ic)
	}

	idx, child := n.getStaticEdge(search[0])
	if child == nil {
		if t.mode == modeUpdate {
			return nil, newEntryNotFoundError(ic)
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
		return nil, newEntryNotFoundError(ic)
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
		splitNode.entries = []*entry{ic}
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

func (t *tXn) insertParam(n *node, tk token, remaining []token, ic *entry) (*node, error) {
	key := canonicalKey(tk)
	idx, child := n.getParamEdge(key)
	if child == nil {
		if t.mode == modeUpdate {
			return nil, newEntryNotFoundError(ic)
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

// compileProg compiles the regexp of a wildcard for simulation, or returns nil without regexp.
func compileProg(re *regexp.Regexp) *regprog.Regexp {
	if re == nil {
		return nil
	}
	r, err := regprog.Compile(re)
	if err != nil {
		// The expression already compiled with regexp.
		panic(fmt.Sprintf("unreachable: %s: %v", re, err))
	}
	return r
}

func (t *tXn) insertWildcard(n *node, tk token, remaining []token, ic *entry) (*node, error) {
	key := canonicalKey(tk)
	idx, child := n.getWildcardEdge(key)
	if child == nil {
		if t.mode == modeUpdate {
			return nil, newEntryNotFoundError(ic)
		}

		newChild, err := t.insertTokens(
			n,
			&node{
				key:    key,
				regexp: tk.regexp,
				prog:   compileProg(tk.regexp),
				nested: tk.nested,
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

// applyAdmission inserts adm on the cloned host node, or bumps the count of the one already
// there through a copy, entries being immutable once published. Kind and port are the whole
// identity, a node is one host structure and parameter names are no part of it.
func (t *tXn) applyAdmission(nc *node, adm *entry) {
	for i, r := range nc.entries {
		if r.admits() && r.kind == adm.kind && r.samePort(adm) {
			next := *r
			next.refs++
			nc.entries[i] = &next
			return
		}
	}
	adm.refs = 1
	nc.addEntry(adm)
	t.admissions++
}

// releaseAdmission drops one reference on the admission the deleted entry implied, removing
// it once the last entry that needed it is gone.
func (t *tXn) releaseAdmission(nc *node, adm *entry) {
	for i, r := range nc.entries {
		if r.admits() && r.kind == adm.kind && r.samePort(adm) {
			if r.refs > 1 {
				next := *r
				next.refs--
				nc.entries[i] = &next
				return
			}
			nc.delIC(i)
			t.admissions--
			return
		}
	}
	panic("internal error: no admission on host node")
}

func (t *tXn) delete(ic *entry, adm *entry) (*entry, bool) {
	t.pending = adm
	t.pathTokens = len(ic.pattern.tokens) - ic.pattern.pathStart

	root := t.rootFor(ic)
	newRoot, oldIC := t.deleteTokens(root, root, ic.pattern.tokens, ic)
	t.pending = nil
	if newRoot != nil {
		t.setRootFor(ic, newRoot)
	}

	if oldIC != nil {
		t.handlers--
		return oldIC, true
	}

	return nil, false
}

func (t *tXn) deleteTokens(root, n *node, tokens []token, ic *entry) (*node, *entry) {
	// Counterpart of the insert claim, releasing once the deeper delete has succeeded and
	// retrying the merge the admission blocked.
	if t.pending != nil && len(tokens) == t.pathTokens {
		adm := t.pending
		t.pending = nil
		nc, deleted := t.deleteTokens(root, n, tokens, ic)
		if deleted == nil {
			return nil, nil
		}
		t.releaseAdmission(nc, adm)
		if n != root &&
			!nc.isLeaf() &&
			len(nc.statics) == 1 &&
			len(nc.params) == 0 &&
			len(nc.wildcards) == 0 {
			t.mergeChild(nc)
		}
		return nc, deleted
	}

	if len(tokens) == 0 {
		if !n.isLeaf() {
			return nil, nil
		}

		idx := slices.IndexFunc(n.entries, func(r *entry) bool {
			return r.kind == ic.kind && r.pattern.str == ic.pattern.str && r.matchersEqual(ic.matchers)
		})
		if idx == -1 {
			return nil, nil
		}

		oldIC := n.entries[idx]
		nc := t.writeNode(n)
		nc.delIC(idx)
		if oldIC.name != "" {
			t.deleteName(oldIC)
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

func (t *tXn) deleteStatic(root, n *node, search string, remaining []token, ic *entry) (*node, *entry) {
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

func (t *tXn) deleteParam(root, n *node, key string, remaining []token, ic *entry) (*node, *entry) {
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

func (t *tXn) deleteWildcard(root, n *node, key string, remaining []token, ic *entry) (*node, *entry) {
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
	t.maxDepth = 0
	t.maxParams = 0
	t.handlers = 0
	t.admissions = 0
	t.writable = nil
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
		prog:   n.prog,
		host:   n.host,
		nested: n.nested,
	}

	if len(n.entries) != 0 {
		nc.entries = make([]*entry, len(n.entries))
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
		n.entries = make([]*entry, len(child.entries))
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
	// True if a wildcard precedes this wildcard in the same part of the pattern (hostname or path).
	nested bool
	// True if this token is part of the hostname portion of the interceptor.
	// Nodes created from tokens with hsplit=true cannot be merged
	// during deletion to preserve the hostname/path boundary for lookupByPath optimization.
	// Only relevant for nodeStatic tokens since params and wildcards
	// are isolated in their own nodes and never merged.
	hsplit bool
}
