// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"slices"
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
func (txn *Txn) Add[H Handler](pattern string, handler H, opts ...EntryOption[H]) (Entry[H], error) {
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

	adm, err := txn.admissionFor(e)
	if err != nil {
		return Entry[H]{}, err
	}
	// One descent lands the entry and its admission, so a failed Add leaves neither.
	if err = txn.rootTxn.insert(e, modeInsert, adm); err != nil {
		return Entry[H]{}, err
	}
	return Entry[H]{e: e}, nil
}

// Update overrides the handler and options of an existing entry. See [Proxy.Update].
// Updating on a read-only transaction returns [ErrReadOnlyTxn].
func (txn *Txn) Update[H Handler](pattern string, handler H, opts ...EntryOption[H]) (Entry[H], error) {
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
	if err = txn.rootTxn.insert(e, modeUpdate, nil); err != nil {
		return Entry[H]{}, err
	}
	return Entry[H]{e: e}, nil
}

// Delete removes the entry registered for the given kind, pattern and matchers. See
// [Proxy.Delete]. Deleting on a read-only transaction returns [ErrReadOnlyTxn].
func (txn *Txn) Delete[H Handler](pattern string, opts ...MatcherOption[H]) (Entry[H], error) {
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

	var adm *entry
	if kind.requiresPath() {
		adm = impliedAdmission(e)
	}
	deleted, ok := txn.rootTxn.delete(e, adm)
	if !ok {
		return Entry[H]{}, newEntryNotFoundError(e)
	}

	return Entry[H]{e: deleted}, nil
}

// Has reports whether an entry is registered for the given kind, pattern and matchers.
func (txn *Txn) Has[H Handler](pattern string, matchers ...RequestMatcher) bool {
	_, ok := txn.Lookup[H](pattern, matchers...)
	return ok
}

// Lookup returns the entry registered for the given kind, pattern and matchers.
func (txn *Txn) Lookup[H Handler](pattern string, matchers ...RequestMatcher) (Entry[H], bool) {
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

	return resolveAdmission(t.patterns, t.addrs, t.handlers+t.admissions, c, target, kind, false) != nil
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

// admissionFor returns the admission e implies, nil for a kind that is its own. Running
// requireCA here keeps every refusal ahead of the first mutation.
func (txn *Txn) admissionFor(e *entry) (*entry, error) {
	if !e.kind.requiresPath() {
		return nil, txn.requireCA(e)
	}
	adm := impliedAdmission(e)
	if err := txn.requireCA(adm); err != nil {
		return nil, err
	}
	return adm, nil
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

// impliedAdmission slices the admission out of the parsed pattern, so nothing is reparsed
// and nothing can fail. An entry restricted to one port implies an admission restricted to
// the same one, terminating TLS on a port no entry serves would be visible for nothing.
func impliedAdmission(e *entry) *entry {
	pat := e.pattern
	hostTokens := pat.tokens[:pat.pathStart:pat.pathStart]
	adm := &entry{
		pattern: pattern{
			str:       pat.str[:len(pat.str)-len(pat.path)],
			key:       pat.key[:len(pat.key)-len(pat.path)],
			host:      pat.host,
			port:      pat.port,
			prefix:    pat.prefix,
			tokens:    hostTokens,
			pathStart: len(hostTokens),
		},
		kind:    e.kind.admittedAs(),
		implied: true,
	}
	for _, tk := range hostTokens {
		if tk.typ != nodeStatic {
			adm.params = append(adm.params, tk.value)
		}
	}
	return adm
}
