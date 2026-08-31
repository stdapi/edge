// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"strings"
)

// Authority is what the proxy does with connections to one authority: relay them, terminate
// their TLS, or refuse them. Entries share the trees with the interceptors and are evaluated
// most specific first. Among hostnames a static authority beats a parameter, which beats a
// wildcard. Among addresses the longest registered prefix wins, and an exact address is the
// longest of all. A host is a hostname or an address, never both, so the two kinds of entry
// never compete for one connection.
//
// An authority named by neither an interceptor nor a tunnel is refused.
//
//	p.AddInterceptor(nil, "+{sub}.stripe.com/*{rest}", h) // every subdomain, implicitly
//	p.AddTunnel("checkout.stripe.com")                    // except this one, static wins
//	p.AddTunnel("[10.0.0.0/8]")                           // a range of addresses
//	p.AddInterceptor(nil, "10.1.2.3/*{rest}", h)          // except this one, /32 wins
type Authority struct {
	entry *Interceptor
}

// Pattern returns the authority pattern as registered.
func (r Authority) Pattern() string { return r.entry.pattern.str }

// Host returns the host of the authority pattern as registered, brackets dropped: a
// hostname, an address, or a range such as "10.0.0.0/8". [Authority.Pattern] carries the
// registrable spelling.
func (r Authority) Host() string { return r.entry.pattern.host }

// Port returns the port the authority entry is restricted to, or an empty string for any port.
func (r Authority) Port() string { return r.entry.pattern.port }

// Action returns what the authority entry does with a matching connection.
func (r Authority) Action() Action { return r.entry.action }

// Implicit reports whether the authority entry was derived from a registered interceptor
// rather than declared with [Proxy.AddTunnel].
func (r Authority) Implicit() bool { return r.entry.implicit }

func (r Authority) String() string { return r.entry.String() }

// MustAddTunnel marks the given authority for end to end tunneling and panics on error. It is
// a convenience wrapper for [Proxy.AddTunnel].
func (p *Proxy) MustAddTunnel(pattern string) Authority {
	tn, err := p.AddTunnel(pattern)
	if err != nil {
		panic(err)
	}
	return tn
}

// AddTunnel marks the given authority for end to end tunneling. The connection is relayed
// byte for byte, so the client's TLS stays intact and no interceptor is ever consulted.
//
// The pattern is a host with an optional port: a hostname, possibly parameterized, an
// address literal, or a bracketed address range such as "[10.0.0.0/8]" or "[fd00::/8]".
//
// If an error occurs, it returns one of the following:
//   - [*PatternError]: the pattern syntax is invalid.
//   - [*InterceptorConflictError]: the authority is already declared.
//   - [ErrAuthorityConflict]: interceptors are registered under the same authority pattern,
//     so tunneling it would leave them unreachable.
func (p *Proxy) AddTunnel(pattern string) (Authority, error) {
	txn := p.Txn(true)
	defer txn.Abort()
	tn, err := txn.AddTunnel(pattern)
	if err != nil {
		return Authority{}, err
	}
	txn.Commit()
	return tn, nil
}

// DeleteTunnel removes the tunnel registered for the given authority pattern and returns it.
// It fails with [ErrTunnelNotFound] when none is registered.
//
// The connections already relaying under it are left untouched. See [Proxy.Sessions] to close
// them.
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

// AddTunnel marks the given authority for end to end tunneling. See [Proxy.AddTunnel].
// Adding a tunnel on a read-only transaction returns [ErrReadOnlyTxn].
func (txn *Txn) AddTunnel(pattern string) (Authority, error) {
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
	if err := insertAuthority(txn.rootTxn, ic); err != nil {
		return Authority{}, err
	}
	return Authority{entry: ic}, nil
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

// ActionFor reports what the proxy does with a connection to target. It is the same lookup the
// proxy runs on CONNECT, on a transparent TLS handshake and on a plaintext request, and is
// exported so a caller can reason about a configuration without opening a connection.
func (p *Proxy) ActionFor(target Target) Action {
	tree := p.getTree()
	c := tree.pool.Get().(*Context)
	defer tree.pool.Put(c)
	return tree.actionFor(c, target)
}

func (t *iTree) actionFor(c *Context, target Target) Action {
	return resolveAction(t.patterns, t.addrs, t.authorities, c, target)
}

// resolveAction walks the authority entries under the given roots and returns what the
// matching one says to do. A transaction and the published tree share the node structure
// under different roots, so the roots are passed in rather than read off a receiver.
func resolveAction(patterns, addrs *node, authorities int, c *Context, target Target) Action {
	if authorities == 0 {
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

	idx, n := lookupTarget(patterns, addrs, "", target.Host, "", c, true, true)
	if n == nil {
		return Reject
	}
	return n.entries[idx].action
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
	return p.newAuthority(authorityPattern(ic.pattern), Intercept, true)
}

// authorityPattern spells the authority pattern naming pat's host and port. Only an address
// host is ever bracketed, a range for its '/' as an IPv6 literal is for its colons. A name
// is left alone, the colon of a regexp constraint lives inside braces and the parser reads
// it back there.
func authorityPattern(pat pattern) string {
	host := pat.host
	if pat.prefix.IsValid() && strings.ContainsAny(host, ":/") {
		host = "[" + host + "]"
	}
	if pat.port == "" {
		return host
	}
	return host + ":" + pat.port
}
