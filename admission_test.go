// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func target(authority string) Target {
	host, port := splitHostPort(authority)
	return Target{Scheme: schemeForPort(port), Host: host, Port: port}.normalized()
}

// Nothing crosses a proxy that was not told about it. An authority no entry names is a hole in
// the setup, and the caller finds out at once rather than having the traffic pass unobserved.
func TestAdmission_DefaultIsReject(t *testing.T) {
	p := testProxy(t)
	assert.False(t, p.Admits(target("example.com:443"), KindHTTP))
	assert.False(t, p.Admits(target("example.com:443"), KindTCP))
	assert.False(t, p.Admits(target("10.0.0.1:443"), KindUDP))
}

// A per-message entry names the authority it serves, so registering one admits it. There is no
// separate verb for that: naming the authority is what admitting it means.
func TestAdmission_EntryAdmitsItsAuthority(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1/*{rest}", noopHandler)

	assert.True(t, p.Admits(target("api.test:443"), KindHTTP))
	assert.False(t, p.Admits(target("other.test:443"), KindHTTP))
	assert.Equal(t, 1, admissionsLen(p))
}

// The kinds partition the traffic, so two of them share an authority without competing. It is
// the traffic that picks which one serves a connection, never the tree.
func TestAdmission_KindsCoexistOnOneAuthority(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1", noopHandler)
	p.MustAdd[TCP]("api.test", noopStream)

	assert.True(t, p.Admits(target("api.test:443"), KindHTTP))
	assert.True(t, p.Admits(target("api.test:443"), KindTCP))
	assert.False(t, p.Admits(target("api.test:443"), KindQUIC))
}

// An authority admitted for one kind is not admitted for another. A QUIC entry does not admit
// HTTP/3, whose requests are routed one by one, and an HTTP entry does not admit a raw stream.
func TestAdmission_IsPerKind(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[QUIC]("game.test:443", func(*QUICCtx) error { return nil })

	assert.True(t, p.Admits(target("game.test:443"), KindQUIC))
	assert.False(t, p.Admits(target("game.test:443"), KindHTTP))
}

// The flagship shape: watch a whole zone, except the one host served another way. A static
// authority is more precise than a wildcard, so it decides first.
func TestAdmission_StaticBeatsWildcard(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("+{any}/*{rest}", noopHandler)
	p.MustAdd[TCP]("checkout.stripe.com", noopStream)

	assert.True(t, p.Admits(target("api.stripe.com:443"), KindHTTP))
	assert.True(t, p.Admits(target("checkout.stripe.com:443"), KindTCP))
	// The wildcard is a name pattern and still admits HTTP on the static host: the two
	// entries are on different kinds and neither hides the other.
	assert.True(t, p.Admits(target("checkout.stripe.com:443"), KindHTTP))
}

// Terminating TLS on a port no entry can serve would be visible to the client for nothing, so
// an entry scoped to a port admits only that port.
func TestAdmission_PortScoped(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test:8443/v1", noopHandler)

	assert.True(t, p.Admits(target("api.test:8443"), KindHTTP))
	assert.False(t, p.Admits(target("api.test:443"), KindHTTP))
}

// A pattern for a kind that routes whole connections carries no path and no scheme: the
// decision is taken before anything has revealed what the connection carries.
func TestAdmission_RejectsSchemeAndPath(t *testing.T) {
	p := testProxy(t)

	_, err := p.Add[TCP]("https://api.test", noopStream)
	require.Error(t, err)

	_, err = p.Add[TCP]("api.test/v1", noopStream)
	require.Error(t, err)
}

// The same kind twice on one authority contradicts itself, and is reported rather than
// silently resolved.
func TestAdmission_DuplicateKindConflicts(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[TCP]("api.test", noopStream)

	_, err := p.Add[TCP]("api.test", noopStream)
	var ce *EntryConflictError
	require.ErrorAs(t, err, &ce)
}

// The admission a per-message entry implies lives exactly as long as the entries needing it.
func TestAdmission_ImpliedEntryIsReferenceCounted(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/a", noopHandler)
	p.MustAdd("api.test/b", noopHandler)
	assert.Equal(t, 1, admissionsLen(p))

	_, err := p.Delete[HTTP]("api.test/a")
	require.NoError(t, err)
	assert.True(t, p.Admits(target("api.test:443"), KindHTTP))

	_, err = p.Delete[HTTP]("api.test/b")
	require.NoError(t, err)
	assert.False(t, p.Admits(target("api.test:443"), KindHTTP))
	assert.Equal(t, 0, admissionsLen(p))
}

// A gRPC or WebSocket entry rides on HTTP, so it admits the HTTP kind and shares the
// admission with the plain HTTP entries of the same authority.
func TestAdmission_RefinedKindsAdmitTheirFamily(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/billing.v1.Billing/Charge", func(*GRPCCtx) error { return nil })

	assert.True(t, p.Admits(target("api.test:443"), KindHTTP))
	assert.False(t, p.Admits(target("api.test:443"), KindTCP))
	assert.Equal(t, 1, admissionsLen(p))

	p.MustAdd("api.test/ws", func(*WebSocketCtx) error { return nil })
	assert.Equal(t, 1, admissionsLen(p), "one kind, one admission")
}

// Everything the proxy admits is terminated, and terminating TLS needs a leaf certificate, so
// a registration without a certificate authority is refused rather than left unserveable.
func TestAdmission_TerminationRequiresCA(t *testing.T) {
	p, err := New()
	require.NoError(t, err)

	_, err = p.Add("api.test/v1", noopHandler)
	require.ErrorIs(t, err, ErrNoCertificateAuthority)

	_, err = p.Add[QUIC]("api.test:443", func(*QUICCtx) error { return nil })
	require.ErrorIs(t, err, ErrNoCertificateAuthority)

	// A stream may well be in the clear, and a datagram carries no handshake at all, so
	// neither is refused for want of a certificate it may never need.
	_, err = p.Add[TCP]("api.test", noopStream)
	require.NoError(t, err)
	_, err = p.Add[UDP]("[0.0.0.0/0]:53", func(*DatagramCtx) error { return nil })
	require.NoError(t, err)
}

// Truncate drops the entries and the admissions they imply together.
func TestAdmission_TruncateDropsEverything(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1", noopHandler)
	p.MustAdd[TCP]("smtp.test:465", noopStream)

	require.NoError(t, p.Updates(func(txn *Txn) error { return txn.Truncate() }))

	assert.Equal(t, 0, p.Len())
	assert.Equal(t, 0, admissionsLen(p))
	assert.False(t, p.Admits(target("api.test:443"), KindHTTP))
}

// The point of one tree: swapping an authority from one kind to another takes one
// transaction, so no connection ever observes the half-applied state.
func TestAdmission_SwapKindsAtomically(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/*{rest}", noopHandler)

	require.NoError(t, p.Updates(func(txn *Txn) error {
		if _, err := txn.Delete[HTTP]("api.test/*{rest}"); err != nil {
			return err
		}
		_, err := txn.Add[TCP]("api.test", noopStream)
		return err
	}))

	assert.False(t, p.Admits(target("api.test:443"), KindHTTP))
	assert.True(t, p.Admits(target("api.test:443"), KindTCP))
}

// A transaction that fails leaves nothing behind.
func TestAdmission_FailedTxnAbortsCleanly(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/*{rest}", noopHandler)

	err := p.Updates(func(txn *Txn) error {
		if _, err := txn.Add[TCP]("api.test", noopStream); err != nil {
			return err
		}
		_, err := txn.Add[TCP]("api.test", noopStream)
		return err
	})
	require.Error(t, err)

	assert.True(t, p.Admits(target("api.test:443"), KindHTTP))
	assert.False(t, p.Admits(target("api.test:443"), KindTCP))
}

// The admissions are readable, and an implied one says so.
func TestAdmission_IterationReportsImplied(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1", noopHandler)
	p.MustAdd[TCP]("smtp.test:465", noopStream)

	var implied, declared []string
	for v := range p.Iter().Admissions() {
		if v.Implied() {
			implied = append(implied, v.Pattern())
			continue
		}
		declared = append(declared, v.Pattern())
	}
	assert.Equal(t, []string{"api.test"}, implied)
	assert.Equal(t, []string{"smtp.test:465"}, declared)
}

// A request the tree no longer covers is refused on the connection it arrives on, without
// waiting for the client to open another one.
func TestAdmission_DeleteAppliesToTheNextRequest(t *testing.T) {
	p := testProxy(t)
	e := p.MustAdd("api.test/v1", noopHandler)
	require.Equal(t, "api.test/v1", e.Pattern())

	assert.NotZero(t, lookupHTTP(p, "api.test/v1"))
	_, err := p.Delete[HTTP]("api.test/v1")
	require.NoError(t, err)
	assert.Zero(t, lookupHTTP(p, "api.test/v1"))
	assert.False(t, p.Admits(target("api.test:443"), KindHTTP))
}

// An entry that fails to insert must leave no admission behind. One bumped for an entry that
// never landed outlives it and nothing can withdraw it, since a delete has no entry to release
// it from.
func TestAdmission_FailedAddLeavesNoAdmission(t *testing.T) {
	p := testProxy(t)

	err := p.Updates(func(txn *Txn) error {
		if _, aerr := txn.Add("leak.test/v1", noopHandler); aerr != nil {
			return aerr
		}
		// The same kind, pattern and matchers: a conflict, refused.
		_, aerr := txn.Add("leak.test/v1", noopHandler)
		require.Error(t, aerr)
		return nil
	})
	require.NoError(t, err)

	_, err = p.Delete[HTTP]("leak.test/v1")
	require.NoError(t, err)

	assert.False(t, p.Admits(target("leak.test:443"), KindHTTP),
		"the refused registration left an admission behind")
	assert.Equal(t, 0, admissionsLen(p))
}

// A transaction answers the same admission question the proxy does, or previewing a change is
// worthless.
func TestAdmission_TxnAgreesWithTheProxy(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/svc/Method", func(*GRPCCtx) error { return nil })

	tgt := target("api.test:443")
	for _, kind := range []Kind{KindHTTP, KindGRPC, KindWebSocket, KindTCP, KindQUIC, KindUDP} {
		want := p.Admits(tgt, kind)
		require.NoError(t, p.View(func(txn *Txn) error {
			assert.Equal(t, want, txn.Admits(tgt, kind), kind.String())
			return nil
		}))
	}
}

// forgedMatcher writes a matcher onto an entry of any kind, which the exported constructors
// refuse at compile time. Outside the package the same reach comes from embedding an
// EntryOption of one kind in a struct promoting forKind of another.
func forgedMatcher[H Handler](m RequestMatcher) EntryOption[H] {
	return option[H](func(s sealedOption) error {
		s.entry.matchers = append(s.entry.matchers, m)
		return nil
	})
}

// A matcher on an entry keyed on an authority alone is never evaluated, so accepting one would
// write a policy narrower than the one enforced. WithRequestMatchers is declared on PathKeyed
// and the compiler refuses it there, so what registration has to catch is an option that
// reached the entry another way, which embedding an interface makes possible.
func TestAdmission_MatchersAreRefusedOnConnectionKinds(t *testing.T) {
	p := testProxy(t)

	beta, err := MatchHeader("X-Channel", "beta")
	require.NoError(t, err)

	_, err = p.Add[TCP]("db.test:5432", noopStream, forgedMatcher[TCP](beta))
	require.ErrorIs(t, err, ErrInvalidConfig)

	_, err = p.Add[UDP]("[0.0.0.0/0]:53", forwardDatagram, forgedMatcher[UDP](beta))
	require.ErrorIs(t, err, ErrInvalidConfig)

	_, err = p.Add[QUIC]("game.test:443", func(*QUICCtx) error { return nil }, forgedMatcher[QUIC](beta))
	require.ErrorIs(t, err, ErrInvalidConfig)

	// On a kind keyed on a path the same matcher is exactly what narrows an entry.
	_, err = p.Add("api.test/v1", noopHandler, WithRequestMatchers[HTTP](beta))
	require.NoError(t, err)
}

// Releasing the last admission of a host node retries the merge its presence blocked.
func TestAdmission_ReleaseRestoresTheMerge(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/x", noopHandler)
	p.MustAdd("api.testers/y", noopHandler)

	_, err := p.Delete[HTTP]("api.test/x")
	require.NoError(t, err)
	assert.False(t, p.Admits(target("api.test:443"), KindHTTP))
	assert.True(t, p.Admits(target("api.testers:443"), KindHTTP))
	assert.NotZero(t, lookupHTTP(p, "api.testers/y"))

	p.MustAdd("api.test/x", noopHandler)
	assert.True(t, p.Admits(target("api.test:443"), KindHTTP))
	assert.Equal(t, 2, admissionsLen(p))
}

// Two ports on one authority are two admissions on one node, and deleting the entries of one
// must not release the other's.
func TestAdmission_PortsAreCountedApart(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test:8443/x", noopHandler)
	p.MustAdd("api.test:9443/x", noopHandler)
	assert.Equal(t, 2, admissionsLen(p))

	_, err := p.Delete[HTTP]("api.test:8443/x")
	require.NoError(t, err)
	assert.False(t, p.Admits(target("api.test:8443"), KindHTTP))
	assert.True(t, p.Admits(target("api.test:9443"), KindHTTP))
}

// The admission of a wildcard host lives on the wildcard node.
func TestAdmission_WildcardHostIsReferenceCounted(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("+{any}/a", noopHandler)
	p.MustAdd("+{any}/b", noopHandler)
	assert.Equal(t, 1, admissionsLen(p))

	_, err := p.Delete[HTTP]("+{any}/a")
	require.NoError(t, err)
	assert.True(t, p.Admits(target("whatever.test:443"), KindHTTP))

	_, err = p.Delete[HTTP]("+{any}/b")
	require.NoError(t, err)
	assert.False(t, p.Admits(target("whatever.test:443"), KindHTTP))
	assert.Equal(t, 0, admissionsLen(p))
}

// Parameter names are no part of identity, here as in the rest of the router. Two hosts of
// one structure conflict only where their entries do, and share the one admission.
func TestAdmission_ParamNamesShareOneAdmission(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("{sub}.api.test/a", noopHandler)
	p.MustAdd("{other}.api.test/b", noopHandler)
	assert.Equal(t, 1, admissionsLen(p))
	assert.True(t, p.Admits(target("eu.api.test:443"), KindHTTP))

	_, err := p.Add("{third}.api.test/a", noopHandler)
	var ce *EntryConflictError
	require.ErrorAs(t, err, &ce)

	_, err = p.Delete[HTTP]("{sub}.api.test/a")
	require.NoError(t, err)
	assert.True(t, p.Admits(target("eu.api.test:443"), KindHTTP))

	_, err = p.Delete[HTTP]("{other}.api.test/b")
	require.NoError(t, err)
	assert.False(t, p.Admits(target("eu.api.test:443"), KindHTTP))
	assert.Equal(t, 0, admissionsLen(p))
}

// The same accounting through the address root, where the host key is encoded prefix bits.
func TestAdmission_AddressHostIsReferenceCounted(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("10.0.0.1/a", noopHandler)
	p.MustAdd("10.0.0.1/b", noopHandler)
	p.MustAdd("[10.0.0.0/8]/c", noopHandler)
	assert.Equal(t, 2, admissionsLen(p))

	_, err := p.Delete[HTTP]("10.0.0.1/a")
	require.NoError(t, err)
	assert.True(t, p.Admits(target("10.0.0.1:443"), KindHTTP))

	_, err = p.Delete[HTTP]("10.0.0.1/b")
	require.NoError(t, err)
	// The exact address is gone, the range admission still covers it.
	assert.True(t, p.Admits(target("10.0.0.1:443"), KindHTTP))
	assert.Zero(t, lookupHTTP(p, "10.0.0.1/a"))

	_, err = p.Delete[HTTP]("[10.0.0.0/8]/c")
	require.NoError(t, err)
	assert.False(t, p.Admits(target("10.0.0.1:443"), KindHTTP))
	assert.Equal(t, 0, admissionsLen(p))
}

// An entry admitting a whole connection captures what its parameters matched, for the handler
// that then serves the connection. The plain admission answer skips the captures.
func TestAdmission_AdmitWithCapturesParameters(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	p.MustAdd[TCP]("{sub}.corp.test:443", relayStream)

	e, params := p.admitWith(Target{Scheme: "https", Host: "mail.corp.test", Port: "443"}, KindTCP)
	require.NotNil(t, e)
	assert.Equal(t, []Param{{Key: "sub", Value: "mail"}}, params)
	assert.True(t, p.Admits(Target{Scheme: "https", Host: "mail.corp.test", Port: "443"}, KindTCP))
}

func TestAdmission_FirstAdmittedWithPicksTheFinestKind(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	target := Target{Scheme: "https", Host: "api.test", Port: "443"}
	kinds := []Kind{KindHTTP, KindTCP}

	kind, e, _ := p.firstAdmittedWith(target, kinds)
	assert.Equal(t, Kind(0), kind)
	assert.Nil(t, e)

	p.MustAdd[TCP]("{name}.test", relayStream)
	kind, e, params := p.firstAdmittedWith(target, kinds)
	assert.Equal(t, KindTCP, kind)
	require.NotNil(t, e)
	assert.Equal(t, []Param{{Key: "name", Value: "api"}}, params)

	p.MustAdd("{name}.test/+{any}", forwardHandler)
	kind, _, params = p.firstAdmittedWith(target, kinds)
	assert.Equal(t, KindHTTP, kind)
	assert.Equal(t, []Param{{Key: "name", Value: "api"}}, params)
}
