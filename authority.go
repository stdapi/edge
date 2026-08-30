// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"iter"
)

// Authority is what the proxy does with connections to one authority: relay them, terminate
// their TLS, or refuse them. Entries share the tree with the interceptors and are evaluated
// most specific first, a static authority beating a parameter, which beats a wildcard.
//
// An authority named by neither an interceptor nor a tunnel is refused.
//
//	edge.WithIntercept("+{sub}.stripe.com")   // every subdomain
//	edge.WithTunnel("checkout.stripe.com")    // except this one, static wins
type Authority struct {
	entry *Interceptor
}

// Pattern returns the authority pattern as registered.
func (r Authority) Pattern() string { return r.entry.pattern.str }

// Host returns the hostname pattern of the authority entry.
func (r Authority) Host() string { return r.entry.pattern.host }

// Port returns the port the authority entry is restricted to, or an empty string for any port.
func (r Authority) Port() string { return r.entry.pattern.port }

// Action returns what the authority entry does with a matching connection.
func (r Authority) Action() Action { return r.entry.action }

// Implicit reports whether the authority entry was derived from a registered interceptor
// rather than declared with [Proxy.AddTunnel].
func (r Authority) Implicit() bool { return r.entry.implicit }

func (r Authority) String() string { return r.entry.String() }

// AddTunnel marks the given authorities for end to end tunneling. The connection is relayed
// byte for byte, so the client's TLS stays intact and no interceptor is ever consulted.
//
// It fails with [ErrAuthorityConflict] when interceptors are registered under the same
// authority pattern: tunneling it would leave them unreachable.
func (p *Proxy) AddTunnel(patterns ...string) error {
	return p.addAuthorities(Tunnel, patterns, false)
}

// DeleteTunnel removes the tunnel registered for the given authority pattern and returns it.
// It fails with [ErrTunnelNotFound] when none is registered.
func (p *Proxy) DeleteTunnel(pattern string) (Authority, error) {
	txn := p.Txn(true)
	defer txn.Abort()
	tn, err := txn.DeleteTunnel(pattern)
	if err != nil {
		return Authority{}, err
	}
	txn.Commit()
	return tn, nil
}

// AddTunnel marks the given authorities for end to end tunneling. See [Proxy.AddTunnel].
// Adding a tunnel on a read-only transaction returns [ErrReadOnlyTxn].
func (txn *Txn) AddTunnel(patterns ...string) error {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if !txn.write {
		return ErrReadOnlyTxn
	}

	for _, pattern := range patterns {
		ic, err := txn.p.newAuthority(pattern, Tunnel, false)
		if err != nil {
			return err
		}
		if err := insertAuthority(txn.rootTxn, ic); err != nil {
			return err
		}
	}
	return nil
}

// DeleteTunnel removes the tunnel registered for the given authority pattern and returns it.
// See [Proxy.DeleteTunnel]. Deleting on a read-only transaction returns [ErrReadOnlyTxn].
func (txn *Txn) DeleteTunnel(pattern string) (Authority, error) {
	if txn.rootTxn == nil {
		panic(ErrSettledTxn)
	}
	if !txn.write {
		return Authority{}, ErrReadOnlyTxn
	}

	ic, err := txn.p.newAuthority(pattern, Tunnel, false)
	if err != nil {
		return Authority{}, err
	}

	deleted, ok := txn.rootTxn.delete(ic)
	if !ok {
		return Authority{}, fmt.Errorf("%w: no tunnel registered for %q", ErrTunnelNotFound, pattern)
	}
	if deleted.refs > 0 {
		// Interceptors still need this authority intercepted. Removing the caller's
		// declaration hands it back to them rather than leaving them unreachable.
		implied := *deleted
		implied.action = Intercept
		implied.implicit = true
		if err := txn.rootTxn.insert(&implied, modeInsert); err != nil {
			return Authority{}, fmt.Errorf("internal error: restoring the implied authority for %q: %w",
				deleted.pattern.str, err)
		}
	}
	return Authority{entry: deleted}, nil
}

// Authorities returns an iterator over a point-in-time snapshot of what decides the
// connections, the entries implied by interceptors included.
func (p *Proxy) Authorities() iter.Seq[Authority] {
	tree := p.getTree()
	it := Iter{patterns: tree.patterns, names: tree.names, methods: tree.methods, maxDepth: tree.maxDepth}
	return func(yield func(Authority) bool) {
		for ic := range it.patternPrefix("", true) {
			if !yield(Authority{entry: ic}) {
				return
			}
		}
	}
}

// Decide reports what the proxy does with a connection to target. It is the same lookup the
// proxy runs on CONNECT, on a transparent TLS handshake and on a plaintext request, and is
// exported so a caller can reason about a configuration without opening a connection.
func (p *Proxy) Decide(target Target) Action {
	tree := p.getTree()
	c := tree.pool.Get().(*Context)
	defer tree.pool.Put(c)
	return tree.decide(c, target)
}

func (t *iTree) decide(c *Context, target Target) Action {
	if t.authorities == 0 {
		return Reject
	}

	scheme := target.Scheme
	port := target.Port
	if scheme == "" {
		scheme = schemeForPort(port)
	}
	if port == "" {
		port = defaultPort(scheme)
	}
	c.resetForAuthority(nil, scheme, target.Host, port)

	idx, n := t.lookupAuthority(target.Host, c)
	if n == nil {
		return Reject
	}
	return n.entries[idx].action
}

func (p *Proxy) addAuthorities(action Action, patterns []string, implicit bool) error {
	if len(patterns) == 0 {
		return nil
	}

	if action == Intercept && p.cfg.ca == nil {
		return fmt.Errorf("%w: intercepting %s requires one", ErrNoCertificateAuthority, patterns[0])
	}

	rules := make([]*Interceptor, 0, len(patterns))
	for _, pattern := range patterns {
		ic, err := p.newAuthority(pattern, action, implicit)
		if err != nil {
			return err
		}
		rules = append(rules, ic)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	txn := p.getTree().txn()
	for _, ic := range rules {
		if err := insertAuthority(txn, ic); err != nil {
			return err
		}
	}
	p.tree.Store(txn.commit())
	return nil
}

// insertAuthority adds an authority entry, replacing an implied one registered for the same
// authority. The same authority declared twice is a configuration error, so the
// conflict is reported rather than silently resolved.
func insertAuthority(txn *tXn, ic *Interceptor) error {
	existing := txn.searchAuthority(ic)
	switch {
	case existing == nil:
		return txn.insert(ic, modeInsert)
	case existing.implicit && !ic.implicit:
		// The entry sitting there was derived from interceptors. Taking it over is only sound if
		// the explicit declaration keeps intercepting them; anything else would leave those
		// interceptors registered and unreachable, which is the failure this rejects.
		if ic.action != Intercept && existing.refs > 0 {
			return fmt.Errorf("%w: %d interceptor(s) intercept %s, so it cannot be set to %s",
				ErrAuthorityConflict, existing.refs, existing.pattern.str, ic.action)
		}
		if _, ok := txn.delete(existing); !ok {
			return fmt.Errorf("internal error: authority %q vanished during replace", existing.pattern.str)
		}
		// The count travels with the decision, so deleting the explicit rule later can hand
		// the authority back to the interceptors that still need it.
		ic.refs = existing.refs
		return txn.insert(ic, modeInsert)
	case ic.implicit:
		// An interceptor never overrides an authority entry that is already there.
		return nil
	default:
		return &InterceptorConflictError{New: ic, Conflicts: []*Interceptor{existing}}
	}
}

func (p *Proxy) newAuthority(pattern string, action Action, implicit bool) (*Interceptor, error) {
	pat, paramsCnt, err := p.parseAuthorityPattern(pattern)
	if err != nil {
		return nil, err
	}

	ic := &Interceptor{
		pattern:    pat,
		action:     action,
		implicit:   implicit,
		methodFast: noFastMethod,
	}

	ic.params = make([]string, 0, paramsCnt)
	for _, tk := range pat.tokens {
		if tk.typ != nodeStatic {
			ic.params = append(ic.params, tk.value)
		}
	}

	return ic, nil
}

// impliedAuthorityFor returns the authority entry an interceptor implies. The hostname is
// what it derives it from, and the parser makes that hostname mandatory, so there is no case
// where an interceptor implies nothing: an empty one would fail here as an invalid authority
// rather than quietly arming none.
//
// An interceptor restricted to one port implies an entry restricted to the same one:
// interception terminates TLS, and doing that on a port no interceptor can serve would be
// visible to the client for nothing.
func (p *Proxy) impliedAuthorityFor(ic *Interceptor) (*Interceptor, error) {
	return p.newAuthority(joinHostPort(ic.pattern.host, ic.pattern.port), Intercept, true)
}
