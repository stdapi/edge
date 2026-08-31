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
// folded into the action.
type nameVerdict uint8

const (
	// nameTrusted covers a confirmed name and every connection with nothing to verify.
	nameTrusted nameVerdict = iota
	nameDropped
	nameMismatch
	nameUnresolved
)

// actionForTransparent answers the action of a transparent connection and the target it
// was matched on. named reports that the host came from the ClientHello rather than the
// destination.
func (p *Proxy) actionForTransparent(ctx context.Context, target Target, origin netip.AddrPort, named bool) (Action, Target, nameVerdict) {
	mode := p.cfg.verifyNames
	if mode == VerifyOff || !named || !origin.IsValid() {
		// Without a destination on record the upstream dial resolves the name itself, so
		// there is no client-chosen address the name could disagree with.
		return p.ActionFor(target), target, nameTrusted
	}

	// The target the same connection without a server name would have produced.
	nameless := target
	nameless.Host = origin.Addr().Unmap().String()

	// One snapshot for both lookups, so a rule committing in between cannot split them
	// across two trees.
	tree := p.getTree()
	c := tree.pool.Get().(*Context)
	action := tree.actionFor(c, target)
	fallback := Reject
	if mode == VerifyLoose {
		fallback = tree.actionFor(c, nameless)
	}
	tree.pool.Put(c)

	if action == Reject {
		if fallback == Reject {
			// Refused confirmed or not, so the name is not resolved. A client spraying
			// names gets no lookups of its choosing out of the proxy.
			return Reject, target, nameTrusted
		}
		// A name no rule matches is dropped unresolved, since resolution could not make
		// it match one.
		return fallback, nameless, nameDropped
	}

	rctx, cancel := context.WithTimeout(ctx, nameVerifyTimeout)
	defer cancel()
	addrs, err := p.cfg.resolver.LookupNetIP(rctx, "ip", target.Host)
	if err != nil {
		p.cfg.logger.Debug("edge: server name cannot be resolved",
			slog.String("name", target.Host), slog.String("error", err.Error()))
		if mode == VerifyReject {
			return Reject, target, nameUnresolved
		}
		return fallback, nameless, nameDropped
	}

	want := origin.Addr().Unmap()
	if slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Unmap() == want }) {
		return action, target, nameTrusted
	}
	if mode == VerifyReject {
		return Reject, target, nameMismatch
	}
	p.cfg.logger.Debug("edge: server name does not resolve to the destination",
		slog.String("name", target.Host), slog.String("destination", origin.String()))
	return fallback, nameless, nameDropped
}
