// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"iter"
)

// Rule decides what the proxy does with connections to an authority. Rules live in their own
// radix tree and are evaluated most specific first: a static authority beats a parameter,
// which beats a wildcard.
//
//	edge.WithIntercept("+{sub}.stripe.com")   // every subdomain
//	edge.WithTunnel("checkout.stripe.com")    // except this one, static wins
type Rule struct {
	route *Route
}

// Pattern returns the authority pattern as registered.
func (r Rule) Pattern() string { return r.route.pattern.str }

// Host returns the hostname pattern of the rule.
func (r Rule) Host() string { return r.route.pattern.host }

// Port returns the port the rule is restricted to, or an empty string for any port.
func (r Rule) Port() string { return r.route.pattern.port }

// Action returns what the rule does with a matching connection.
func (r Rule) Action() Action { return r.route.action }

// Implicit reports whether the rule was derived from a registered route rather than declared
// with [WithIntercept], [WithTunnel] or [WithReject].
func (r Rule) Implicit() bool { return r.route.implicit }

func (r Rule) String() string { return r.route.String() }

// Intercept marks the given authorities for interception at runtime. It replaces any implicit
// rule registered for the same authority pattern.
func (p *Proxy) Intercept(patterns ...string) error {
	return p.addRules(Intercept, patterns, false)
}

// Tunnel marks the given authorities for end to end tunneling at runtime.
func (p *Proxy) Tunnel(patterns ...string) error {
	return p.addRules(Tunnel, patterns, false)
}

// Reject refuses connections to the given authorities at runtime.
func (p *Proxy) Reject(patterns ...string) error {
	return p.addRules(Reject, patterns, false)
}

// DeleteRule removes the rule registered for the given authority pattern and returns it.
func (p *Proxy) DeleteRule(pattern string) (Rule, error) {
	rte, err := p.newRule(pattern, Tunnel, false)
	if err != nil {
		return Rule{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	txn := p.getRules().txn()
	deleted, ok := txn.delete(rte)
	if !ok {
		return Rule{}, fmt.Errorf("%w: no rule registered for %q", ErrRuleNotFound, pattern)
	}
	p.rules.Store(txn.commit())
	return Rule{route: deleted}, nil
}

// Rules returns an iterator over a point-in-time snapshot of the rule set, implicit rules
// included.
func (p *Proxy) Rules() iter.Seq[Rule] {
	tree := p.getRules()
	it := Iter{patterns: tree.patterns, names: tree.names, methods: tree.methods, maxDepth: tree.maxDepth}
	return func(yield func(Rule) bool) {
		for rte := range it.All() {
			if !yield(Rule{route: rte}) {
				return
			}
		}
	}
}

// Decide reports what the proxy does with a connection to target. It is the same lookup the
// proxy runs on CONNECT, on a transparent TLS handshake and on a plaintext request, and is
// exported so a caller can reason about a configuration without opening a connection.
func (p *Proxy) Decide(target Target) Action {
	tree := p.getRules()
	if tree.size == 0 {
		return p.cfg.defaultAction
	}

	c := tree.pool.Get().(*Context)
	defer tree.pool.Put(c)

	scheme := target.Scheme
	port := target.Port
	if scheme == "" {
		scheme = schemeForPort(port)
	}
	if port == "" {
		port = defaultPort(scheme)
	}
	c.resetForRule(nil, scheme, target.Host, port)

	idx, n, _ := tree.lookup(ruleLookupMethod, target.Host, "/", c, true)
	if n == nil {
		return p.cfg.defaultAction
	}
	return n.routes[idx].action
}

// applyRuleOptions registers the rules collected from the proxy options, in declaration order.
func (p *Proxy) applyRuleOptions() error {
	for _, spec := range p.cfg.rules {
		if err := p.addRules(spec.action, spec.patterns, false); err != nil {
			return err
		}
	}
	return nil
}

func (p *Proxy) addRules(action Action, patterns []string, implicit bool) error {
	if len(patterns) == 0 {
		return nil
	}

	if action == Intercept && p.cfg.ca == nil {
		return fmt.Errorf("%w: intercepting %s requires one, configure it with WithCA", ErrNoCertificateAuthority, patterns[0])
	}

	rules := make([]*Route, 0, len(patterns))
	for _, pattern := range patterns {
		rte, err := p.newRule(pattern, action, implicit)
		if err != nil {
			return err
		}
		rules = append(rules, rte)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	txn := p.getRules().txn()
	for _, rte := range rules {
		if err := insertRule(txn, rte); err != nil {
			return err
		}
	}
	p.rules.Store(txn.commit())
	return nil
}

// insertRule adds a rule, replacing an implicit rule registered for the same authority. An
// explicit rule declared twice for the same authority is a configuration error, so the
// conflict is reported rather than silently resolved.
func insertRule(txn *tXn, rte *Route) error {
	existing := txn.findRule(rte)
	switch {
	case existing == nil:
		return txn.insert(rte, modeInsert)
	case existing.implicit && !rte.implicit:
		// An explicit declaration always wins over one derived from a route.
		if _, ok := txn.delete(existing); !ok {
			return fmt.Errorf("internal error: rule %q vanished during replace", existing.pattern.str)
		}
		return txn.insert(rte, modeInsert)
	case rte.implicit:
		// A route never overrides a rule that is already there.
		return nil
	default:
		return &RouteConflictError{New: rte, Conflicts: []*Route{existing}}
	}
}

func (p *Proxy) newRule(pattern string, action Action, implicit bool) (*Route, error) {
	pat, paramsCnt, err := p.parseAuthorityPattern(pattern)
	if err != nil {
		return nil, err
	}

	rte := &Route{
		pattern:    pat,
		action:     action,
		implicit:   implicit,
		methodFast: noFastMethod,
	}

	rte.params = make([]string, 0, paramsCnt)
	for _, tk := range pat.tokens {
		if tk.typ != nodeStatic {
			rte.params = append(rte.params, tk.value)
		}
	}

	if pat.port != "" {
		rte.matchers = append(rte.matchers, PortMatcher{port: pat.port})
	}
	rte.priority = uint(len(rte.matchers))

	return rte, nil
}

// implicitRuleFor returns the interception rule a route implies, or nil when the route names
// no authority. A route with no authority matches every host, and turning that into a rule
// would silently intercept the whole world, so it does not create one.
//
// A route restricted to one port implies a rule restricted to the same one: interception
// terminates TLS, and doing that on a port no route can serve would be visible to the client
// for nothing.
func (p *Proxy) implicitRuleFor(route *Route) (*Route, error) {
	if route.pattern.host == "" {
		return nil, nil
	}
	return p.newRule(joinHostPort(route.pattern.host, routePort(route)), Intercept, true)
}

// routePort returns the port a route restricts itself to, or an empty string when it accepts
// any. A route says so with [WithPort], which attaches a [PortMatcher].
func routePort(route *Route) string {
	for _, m := range route.matchers {
		if pm, ok := m.(PortMatcher); ok {
			return pm.port
		}
	}
	return ""
}
