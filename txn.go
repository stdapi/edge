// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"slices"
	"strings"
)

// Txn is a read or write transaction on the routing tree.
//
// A Txn must not be used concurrently by multiple goroutines. It is however safe to run
// multiple transactions from different goroutines, each on its own Txn. Read transactions
// operate on a point-in-time snapshot and never block, while write transactions are
// serialized by the proxy. A write Txn must be finalized with [Txn.Commit] or [Txn.Abort].
// Routing never blocks, even while a write transaction is in progress.
type Txn struct {
	p       *Proxy
	rootTxn *tXn
	write   bool
}

// Add registers handler for pattern. See [Proxy.Add]. Adding on a read-only transaction
// returns [ErrReadOnlyTxn].
func (txn *Txn) Add[H Handler](pattern string, handler H, opts ...EntryOption) (Entry[H], error) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if !txn.write {
		return Entry[H]{}, ErrReadOnlyTxn
	}

	e, err := newEntry(txn.p, pattern, handler, opts...)
	if err != nil {
		return Entry[H]{}, err
	}

	// The entry goes in first. Admitting an authority for an entry that then fails to insert
	// leaves an admission nothing needs and nothing can withdraw, since a delete has no entry
	// to release it from.
	if err = txn.rootTxn.insert(e, modeInsert); err != nil {
		return Entry[H]{}, err
	}
	if err = txn.admit(e); err != nil {
		if _, ok := txn.rootTxn.delete(e); !ok {
			return Entry[H]{}, fmt.Errorf("internal error: entry %s vanished while unwinding: %w",
				e.pattern.str, err)
		}
		return Entry[H]{}, err
	}
	return Entry[H]{e: e}, nil
}

// Update overrides the handler and options of an existing entry. See [Proxy.Update].
// Updating on a read-only transaction returns [ErrReadOnlyTxn].
func (txn *Txn) Update[H Handler](pattern string, handler H, opts ...EntryOption) (Entry[H], error) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if !txn.write {
		return Entry[H]{}, ErrReadOnlyTxn
	}

	e, err := newEntry(txn.p, pattern, handler, opts...)
	if err != nil {
		return Entry[H]{}, err
	}
	if err = txn.rootTxn.insert(e, modeUpdate); err != nil {
		return Entry[H]{}, err
	}
	return Entry[H]{e: e}, nil
}

// Delete removes the entry registered for the given kind, pattern and matchers. See
// [Proxy.Delete]. Deleting on a read-only transaction returns [ErrReadOnlyTxn].
func (txn *Txn) Delete[H Handler](pattern string, opts ...MatcherOption) (Entry[H], error) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if !txn.write {
		return Entry[H]{}, ErrReadOnlyTxn
	}

	kind := kindOf[H]()
	pat, _, err := txn.p.parsePattern(pattern, kind)
	if err != nil {
		return Entry[H]{}, err
	}

	e := &entry{pattern: pat, kind: kind}
	for _, opt := range opts {
		if err = opt.applyMatcher(sealedOption{proxy: txn.p, entry: e}); err != nil {
			return Entry[H]{}, err
		}
	}
	if len(e.matchers) > txn.p.cfg.maxMatchers {
		return Entry[H]{}, fmt.Errorf("%w: %w", ErrInvalidEntry, ErrTooManyMatchers)
	}

	deleted, ok := txn.rootTxn.delete(e)
	if !ok {
		return Entry[H]{}, newEntryNotFoundError(e)
	}
	txn.release(deleted)

	return Entry[H]{e: deleted}, nil
}

// Has reports whether an entry is registered for the given kind, pattern and matchers.
func (txn *Txn) Has[H Handler](pattern string, matchers ...Matcher) bool {
	_, ok := txn.Lookup[H](pattern, matchers...)
	return ok
}

// Lookup returns the entry registered for the given kind, pattern and matchers.
func (txn *Txn) Lookup[H Handler](pattern string, matchers ...Matcher) (Entry[H], bool) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}

	kind := kindOf[H]()
	key, isAddr := patternKey(pattern)
	root := txn.rootTxn.patterns
	if isAddr {
		root = txn.rootTxn.addrs
	}
	matched := root.searchPattern(key)
	if matched == nil || !matched.isLeaf() {
		return Entry[H]{}, false
	}

	idx := slices.IndexFunc(matched.entries, func(r *entry) bool {
		return r.handler != nil && r.kind == kind && r.pattern.str == pattern &&
			r.matchersEqual(matchers)
	})
	if idx < 0 {
		return Entry[H]{}, false
	}
	return Entry[H]{e: matched.entries[idx]}, true
}

// Named returns the entry registered under name for the given kind.
func (txn *Txn) Named[H Handler](name string) (Entry[H], bool) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}

	matched := txn.rootTxn.names.searchName(name)
	if matched == nil || !matched.isLeaf() || matched.entries[0].name != name {
		return Entry[H]{}, false
	}
	e := matched.entries[0]
	if e.kind != kindOf[H]() {
		return Entry[H]{}, false
	}
	return Entry[H]{e: e}, true
}

// Truncate empties the tree, removing the entries and the admissions they imply together.
// Truncating on a read-only transaction returns [ErrReadOnlyTxn].
func (txn *Txn) Truncate() error {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if !txn.write {
		return ErrReadOnlyTxn
	}
	txn.rootTxn.truncate()
	return nil
}

// Len returns the number of registered entries.
func (txn *Txn) Len() int {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	return txn.rootTxn.handlers
}

// Admits reports whether a connection to target carrying kind's traffic is admitted, resolved
// on the tree this transaction sees rather than on the published one. A write transaction can
// therefore check the effect of a change before it commits. See [Proxy.Admits].
func (txn *Txn) Admits(target Target, kind Kind) bool {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}

	t := txn.rootTxn
	// The context comes from the pool of the tree the transaction forked from. Its
	// capacities are a sizing hint that the lookup grows when it has to, and nothing on the
	// admission path reads the tree the context was allocated for.
	pool := &t.tree.pool
	c := pool.Get().(*routeCtx)
	defer pool.Put(c)

	return resolveAdmission(t.patterns, t.addrs, t.handlers+t.admissions, c, target, kind) != nil
}

// Commit finalizes the transaction. This is a noop for read transactions, already aborted or
// committed transactions.
func (txn *Txn) Commit() {
	// Noop for a read transaction
	if !txn.write {
		return
	}

	// Check if already aborted or committed
	if txn.rootTxn == nil {
		return
	}

	txn.p.tree.Store(txn.rootTxn.commit())

	// Clear the txn
	txn.rootTxn = nil
	txn.p.mu.Unlock()
}

// Abort cancels the transaction. This is a noop for read transactions, already aborted or
// committed transactions.
func (txn *Txn) Abort() {
	if !txn.write {
		return
	}
	if txn.rootTxn == nil {
		return
	}

	txn.rootTxn = nil
	txn.p.mu.Unlock()
}

// Snapshot returns a point in time snapshot of the current state of the transaction. It
// contains any uncommitted writes, and further mutations to either are independent.
func (txn *Txn) Snapshot() *Txn {
	if txn.rootTxn == nil {
		return nil
	}

	return &Txn{
		p:       txn.p,
		rootTxn: txn.rootTxn.clone(),
	}
}

// admit registers the admission a per-message entry implies, or bumps the reference count of
// the one already there. An entry that routes whole connections is its own admission and
// needs none.
func (txn *Txn) admit(e *entry) error {
	if !e.kind.perMessage() {
		return txn.requireCA(e)
	}

	adm, err := txn.p.newAdmission(admissionPattern(e.pattern), e.kind.admittedAs())
	if err != nil {
		return err
	}
	if err = txn.requireCA(adm); err != nil {
		return err
	}

	t := txn.rootTxn
	existing := t.searchAdmission(adm)
	if existing == nil {
		adm.refs = 1
		return t.insert(adm, modeInsert)
	}
	return replaceRefs(t, existing, existing.refs+1)
}

// release drops one reference on the admission a deleted entry implied, removing it once the
// last entry that needed it is gone.
func (txn *Txn) release(e *entry) {
	if !e.kind.perMessage() {
		return
	}

	adm, err := txn.p.newAdmission(admissionPattern(e.pattern), e.kind.admittedAs())
	if err != nil {
		return
	}

	t := txn.rootTxn
	existing := t.searchAdmission(adm)
	if existing == nil {
		return
	}
	if existing.refs > 1 {
		_ = replaceRefs(t, existing, existing.refs-1)
		return
	}
	t.delete(existing)
}

// requireCA refuses a registration the proxy could not serve. QUIC is always TLS, and the HTTP
// kind is in practice, so an entry of either kind registered without a certificate authority
// would admit connections nothing can answer.
//
// A stream or a datagram is not necessarily encrypted, so those are left to fail at the
// handshake that actually needs a certificate, if one ever comes.
func (txn *Txn) requireCA(e *entry) error {
	if txn.p.cfg.ca != nil || (e.kind != KindHTTP && e.kind != KindQUIC) {
		return nil
	}
	return fmt.Errorf("%w: %s admits %s, which carries TLS",
		ErrNoCertificateAuthority, e.kind, e.pattern.str)
}

// replaceRefs swaps an entry for a copy holding a different reference count. Entries are
// immutable once published, so the count cannot be bumped in place.
func replaceRefs(t *tXn, existing *entry, refs uint32) error {
	next := *existing
	next.refs = refs
	if _, ok := t.delete(existing); !ok {
		return fmt.Errorf("internal error: admission %s vanished during refcount update", existing.pattern.str)
	}
	return t.insert(&next, modeInsert)
}

// newAdmission builds the entry admitting one authority for one kind. It carries no
// handler and no matcher: nothing has been read off the connection at the point it is
// consulted.
func (p *Proxy) newAdmission(pattern string, kind Kind) (*entry, error) {
	pat, paramsCnt, err := p.parseAuthorityPattern(pattern)
	if err != nil {
		return nil, err
	}

	e := &entry{pattern: pat, kind: kind, implied: true}
	e.params = make([]string, 0, paramsCnt)
	for _, tk := range pat.tokens {
		if tk.typ != nodeStatic {
			e.params = append(e.params, tk.value)
		}
	}
	return e, nil
}

// admissionPattern spells the authority pattern naming pat's host and port. Only an address
// host is ever bracketed, a range for its '/' as an IPv6 literal is for its colons. A name is
// left alone, the colon of a regexp constraint lives inside braces and the parser reads it
// back there.
//
// An entry restricted to one port implies an admission restricted to the same one:
// terminating TLS on a port no entry can serve would be visible to the client for nothing.
func admissionPattern(pat pattern) string {
	host := pat.host
	if pat.prefix.IsValid() && strings.ContainsAny(host, ":/") {
		host = "[" + host + "]"
	}
	if pat.port == "" {
		return host
	}
	return host + ":" + pat.port
}
