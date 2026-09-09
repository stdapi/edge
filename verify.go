// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"
)

type verifiedHost struct {
	target  Target
	host    string
	refused bool
}

// nameVerifyTimeout bounds the resolver lookup a transparent connection waits on.
const nameVerifyTimeout = 5 * time.Second

// NameVerification is the mode [WithNameVerification] applies to the server name of a
// transparent connection.
type NameVerification uint8

const (
	// VerifyOff trusts the server name as the client sent it. The default.
	VerifyOff NameVerification = iota
	// VerifyLoose treats a name that is unconfirmed or matches no rule as if the client
	// had sent none, so the connection is matched on its destination alone. A name no
	// rule matches is not resolved.
	VerifyLoose
	// VerifyReject refuses the connection when the server name is not confirmed.
	VerifyReject

	verifySentinel
)

// NameResolver resolves a hostname to its addresses. *net.Resolver implements it.
type NameResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

var (
	errNameMismatch   = fmt.Errorf("%w, the server name does not resolve to the destination", ErrConnectionRejected)
	errNameUnresolved = fmt.Errorf("%w, the server name cannot be resolved", ErrConnectionRejected)
)

// nameVerdict is what verification concluded about the server name. Refusals are already
// folded into the admission answer.
type nameVerdict uint8

const (
	// nameTrusted covers a confirmed name and every connection with nothing to verify.
	nameTrusted nameVerdict = iota
	nameDropped
	nameMismatch
	nameUnresolved
)

// targetForTransparent answers which target a transparent connection is matched on, and
// whether anything admits it at all. named reports that the host came from the ClientHello
// rather than the destination.
//
// The kinds are the kinds the connection could still turn out to be. Nothing has been
// negotiated yet, so admission here only asks whether the authority is known at all; the
// kind is checked again once the traffic has named it.
func (p *Proxy) targetForTransparent(ctx context.Context, target Target, origin netip.AddrPort, named bool, kinds ...Kind) (Target, bool, nameVerdict) {
	mode := p.cfg.verifyNames
	if mode == VerifyOff || !named || !origin.IsValid() {
		// Without a destination on record the upstream dial resolves the name itself, so
		// there is no client-chosen address the name could disagree with.
		return target, p.admitsAny(target, kinds...), nameTrusted
	}

	// The target the same connection without a server name would have produced.
	nameless := target
	nameless.Host = origin.Addr().Unmap().String()

	// One snapshot for both lookups, so an entry committing in between cannot split them
	// across two trees.
	tree := p.getTree()
	c := tree.pool.Get().(*routeCtx)
	admitted := tree.admitsAny(c, target, kinds)
	fallback := false
	if mode == VerifyLoose {
		fallback = tree.admitsAny(c, nameless, kinds)
	}
	tree.pool.Put(c)

	if !admitted {
		if !fallback {
			// Refused confirmed or not, so the name is not resolved. A client spraying
			// names gets no lookups of its choosing out of the proxy.
			return target, false, nameTrusted
		}
		// A name no entry matches is dropped unresolved, since resolution could not make
		// it match one.
		return nameless, true, nameDropped
	}

	verdict := p.nameResolvesTo(ctx, target.Host, origin)
	if verdict == nameTrusted {
		return target, true, nameTrusted
	}
	if mode == VerifyReject {
		return target, false, verdict
	}
	return nameless, fallback, nameDropped
}

// nameResolvesTo reports whether name resolves to the address of origin: nameTrusted when it
// does, nameUnresolved when the lookup fails, nameMismatch otherwise.
func (p *Proxy) nameResolvesTo(ctx context.Context, name string, origin netip.AddrPort) nameVerdict {
	rctx, cancel := context.WithTimeout(ctx, nameVerifyTimeout)
	defer cancel()
	addrs, err := p.cfg.resolver.LookupNetIP(rctx, "ip", name)
	if err != nil {
		p.cfg.logger.Debug("edge: server name cannot be resolved",
			slog.String("name", name), slog.String("error", err.Error()))
		return nameUnresolved
	}
	want := origin.Addr().Unmap()
	if slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Unmap() == want }) {
		return nameTrusted
	}
	p.cfg.logger.Debug("edge: server name does not resolve to the destination",
		slog.String("name", name), slog.String("destination", origin.String()))
	return nameMismatch
}

// verifyRequestHost checks the authority of a plaintext request against the destination its
// connection fixed, the way placeTLS checks a server name, and returns the target it is routed
// on. The kinds decide whether a name is resolved at all, and the decision is kept on the
// session per Host, refusals included.
func (p *Proxy) verifyRequestHost(ctx context.Context, sess *Session, target Target, kinds ...Kind) (Target, bool) {
	if p.cfg.verifyNames == VerifyOff || !sess.upstream.IsValid() {
		return target, true
	}
	if _, err := netip.ParseAddr(target.Host); err == nil {
		return target, true
	}
	if v := sess.verified.Load(); v != nil && v.host == target.Host && v.target.Port == target.Port {
		return v.target, !v.refused
	}
	verified, _, verdict := p.targetForTransparent(ctx, target, sess.upstream, true, kinds...)
	refused := verdict == nameMismatch || verdict == nameUnresolved
	sess.verified.Store(&verifiedHost{host: target.Host, target: verified, refused: refused})
	return verified, !refused
}
