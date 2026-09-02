// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

// Admits reports whether the proxy admits a connection to target carrying the traffic of the
// given kind. It is the same lookup the proxy runs when a connection arrives, exported so a
// caller can reason about a configuration. [Session.Stale] reports the connections that would
// be served differently now.
//
// The kind is what the traffic itself named, which is why a session reports it. An authority
// admitted for one kind is not admitted for another: a QUIC entry does not admit HTTP/3, and an
// HTTP entry does not admit a raw stream. A kind that refines another is admitted by what
// carries it, so a WebSocket connection and a gRPC call both ask about HTTP.
func (p *Proxy) Admits(target Target, kind Kind) bool {
	return p.admission(target, kind) != nil
}

// stale replays the decision taken when s arrived on the tree as it stands, on one snapshot,
// and reports whether it differs. It compares the kind first, then the entry for a connection
// whose handler owns it.
func (p *Proxy) stale(s *Session) bool {
	tree := p.getTree()
	c := tree.pool.Get().(*routeCtx)
	defer tree.pool.Put(c)

	kinds := s.servableAs
	if len(kinds) == 0 {
		kinds = []Kind{s.kind}
	}
	var now *entry
	for _, k := range kinds {
		if now = tree.admission(c, s.target, k); now != nil {
			if k != s.kind {
				return true
			}
			break
		}
	}
	if now == nil {
		return true
	}

	decided := s.entry.Load()
	if decided == nil {
		return false
	}
	if s.kind != KindWebSocket {
		return now != decided
	}
	// A WebSocket session was decided by the request lookup on its upgrade, on the path and
	// the matchers, and that is the lookup to replay.
	r := s.upgrade
	c.reset(s, r, s.target.Scheme, s.target.Host, s.target.Port)
	c.identity = s.identity
	idx, n := tree.lookup(s.target.Host, routingPath(r), c, true)
	return n == nil || n.entries[idx] != decided
}

func (p *Proxy) admission(target Target, kind Kind) *entry {
	tree := p.getTree()
	c := tree.pool.Get().(*routeCtx)
	defer tree.pool.Put(c)
	return tree.admission(c, target, kind)
}

func (t *iTree) admission(c *routeCtx, target Target, kind Kind) *entry {
	return resolveAdmission(t.patterns, t.addrs, t.handlers+t.admissions, c, target, kind, false)
}

// resolveAdmission walks the admission entries under the given roots and returns the one that
// admits kind on target, or nil. A transaction and the published tree share the node
// structure under different roots, so the roots are passed in rather than read off a receiver.
// With capture set the walk records what the pattern's parameters matched, which only a
// caller about to hand the entry to a handler pays for.
func resolveAdmission(patterns, addrs *node, total int, c *routeCtx, target Target, kind Kind, capture bool) *entry {
	if total == 0 || kind == 0 {
		return nil
	}
	// A refinement is admitted by what carries it: a WebSocket connection and a gRPC call are
	// HTTP traffic, and the entry admitting the authority is the HTTP one they implied. The
	// mapping lives here so no caller can reach the walk without it.
	kind = kind.admittedAs()

	scheme := target.Scheme
	port := target.Port
	if scheme == "" {
		scheme = schemeForPort(port)
	}
	if port == "" {
		port = defaultPort(scheme)
	}
	c.resetForAdmission(nil, scheme, target.Host, port)

	idx, n := lookupTarget(patterns, addrs, target.Host, "", c, !capture, kind)
	if n == nil {
		return nil
	}
	return n.entries[idx]
}

// admitWith resolves the entry admitting kind on target and copies out the parameters its
// pattern captured, which a handler serving a whole connection keeps for longer than the
// pooled state of the lookup lives.
func (p *Proxy) admitWith(target Target, kind Kind) (*entry, []Param) {
	return p.admitInto(target, kind, nil)
}

// admitInto is [Proxy.admitWith] writing the parameters into buf, reused across the datagrams
// of one flow so routing one allocates nothing. The parameters it returns are only valid until
// the next call with the same buffer.
func (p *Proxy) admitInto(target Target, kind Kind, buf []Param) (*entry, []Param) {
	tree := p.getTree()
	c := tree.pool.Get().(*routeCtx)
	defer tree.pool.Put(c)

	e := resolveAdmission(tree.patterns, tree.addrs, tree.handlers+tree.admissions, c, target, kind, true)
	if e == nil {
		return nil, buf[:0]
	}
	c.entry = e
	return e, c.appendParams(buf)
}

// admitsAny reports whether any of the given kinds is admitted on target. It answers the
// question a connection raises before it has said what it carries: an authority nothing admits
// at all is refused there and then, rather than after a handshake that could never be served.
func (p *Proxy) admitsAny(target Target, kinds ...Kind) bool {
	return p.firstAdmitted(target, kinds...) != 0
}

func (p *Proxy) firstAdmitted(target Target, kinds ...Kind) Kind {
	tree := p.getTree()
	c := tree.pool.Get().(*routeCtx)
	defer tree.pool.Put(c)

	for _, k := range kinds {
		if tree.admission(c, target, k) != nil {
			return k
		}
	}
	return 0
}

// firstAdmittedWith is [Proxy.firstAdmitted] with the entry and its captured parameters. Every
// kind is read on one tree snapshot, an entry committing in between cannot split the decision.
func (p *Proxy) firstAdmittedWith(target Target, kinds []Kind) (Kind, *entry, []Param) {
	tree := p.getTree()
	c := tree.pool.Get().(*routeCtx)
	defer tree.pool.Put(c)

	for _, k := range kinds {
		e := resolveAdmission(tree.patterns, tree.addrs, tree.handlers+tree.admissions, c, target, k, true)
		if e != nil {
			c.entry = e
			return k, e, c.appendParams(nil)
		}
	}
	return 0, nil, nil
}

// admitsAny is [Proxy.admitsAny] on one tree snapshot and one borrowed context, for a caller
// already holding both.
func (t *iTree) admitsAny(c *routeCtx, target Target, kinds []Kind) bool {
	for _, k := range kinds {
		if t.admission(c, target, k) != nil {
			return true
		}
	}
	return false
}
