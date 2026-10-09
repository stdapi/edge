// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func target(authority string) Target {
	host, port := splitHostPort(authority)
	return Target{Scheme: schemeForPort(port), Host: host, Port: port}.normalized()
}

func TestAdmission_DefaultIsReject(t *testing.T) {
	p := testProxy(t)
	assert.False(t, p.Admits(target("example.com:443"), KindHTTP))
	assert.False(t, p.Admits(target("example.com:443"), KindTCP))
	assert.False(t, p.Admits(target("10.0.0.1:443"), KindUDP))
}

func TestAdmission_EntryAdmitsItsAuthority(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1/*{rest}", noopHandler)

	assert.True(t, p.Admits(target("api.test:443"), KindHTTP))
	assert.False(t, p.Admits(target("other.test:443"), KindHTTP))
	assert.Equal(t, 1, admissionsLen(p))
}

func TestAdmission_KindsCoexistOnOneAuthority(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1", noopHandler)
	p.MustAdd[TCP]("api.test", noopStream)

	assert.True(t, p.Admits(target("api.test:443"), KindHTTP))
	assert.True(t, p.Admits(target("api.test:443"), KindTCP))
	assert.False(t, p.Admits(target("api.test:443"), KindQUIC))
}

func TestAdmission_IsPerKind(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[QUIC]("game.test:443", func(*QUICCtx) error { return nil })

	assert.True(t, p.Admits(target("game.test:443"), KindQUIC))
	assert.False(t, p.Admits(target("game.test:443"), KindHTTP))
}

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

func TestAdmission_PortScoped(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test:8443/v1", noopHandler)

	assert.True(t, p.Admits(target("api.test:8443"), KindHTTP))
	assert.False(t, p.Admits(target("api.test:443"), KindHTTP))
}

func TestAdmission_RejectsSchemeAndPath(t *testing.T) {
	p := testProxy(t)

	_, err := p.Add[TCP]("https://api.test", noopStream)
	require.Error(t, err)

	_, err = p.Add[TCP]("api.test/v1", noopStream)
	require.Error(t, err)
}

func TestAdmission_DuplicateKindConflicts(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[TCP]("api.test", noopStream)

	_, err := p.Add[TCP]("api.test", noopStream)
	var ce *EntryConflictError
	require.ErrorAs(t, err, &ce)
}

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

func TestAdmission_RefinedKindsAdmitTheirFamily(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/billing.v1.Billing/Charge", func(*GRPCCtx) error { return nil })

	assert.True(t, p.Admits(target("api.test:443"), KindHTTP))
	assert.False(t, p.Admits(target("api.test:443"), KindTCP))
	assert.Equal(t, 1, admissionsLen(p))

	p.MustAdd("api.test/ws", func(*WebSocketCtx) error { return nil })
	assert.Equal(t, 1, admissionsLen(p), "one kind, one admission")
}

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

func TestAdmission_TruncateDropsEverything(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1", noopHandler)
	p.MustAdd[TCP]("smtp.test:465", noopStream)

	require.NoError(t, p.Updates(func(txn *Txn) error { return txn.Truncate() }))

	assert.Equal(t, 0, p.Len())
	assert.Equal(t, 0, admissionsLen(p))
	assert.False(t, p.Admits(target("api.test:443"), KindHTTP))
}

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

func TestAdmission_NoEntryAdmitsEveryHostAndStaysOutOfTheTree(t *testing.T) {
	p := testProxy(t, WithNoEntry(forwardHandler), WithNoEntry(relayStream), WithNoEntry(relayQUIC), WithNoEntry(forwardDatagram))

	for _, host := range []string{"api.test", "api.test.", "127.0.0.1", "[::1]"} {
		for _, kind := range []Kind{KindHTTP, KindGRPC, KindWebSocket, KindTCP, KindQUIC, KindUDP} {
			assert.True(t, p.Admits(Target{Host: host, Port: "443"}, kind), "%s %s", host, kind)
		}
	}
	assert.False(t, p.Admits(Target{Host: "", Port: "443"}, KindHTTP))
	assert.False(t, p.Admits(Target{Host: ".", Port: "443"}, KindHTTP))
	assert.False(t, p.Admits(Target{Host: "api.test", Port: "443"}, Kind(0)))
	assert.False(t, p.Admits(Target{Host: "api.test", Port: "443"}, KindUDP+1))

	txn := p.Txn(true)
	defer txn.Abort()
	assert.True(t, txn.Admits(Target{Host: "api.test", Port: "443"}, KindTCP))
	_, err := txn.Add[TCP]("api.test", relayStream)
	require.NoError(t, err)
	assert.True(t, txn.Admits(Target{Host: "api.test", Port: "443"}, KindTCP))
	assert.Equal(t, 1, txn.Len())

	assert.Equal(t, 0, p.Len())
	assert.Zero(t, admissionsLen(p))
	assert.False(t, p.Has[HTTP]("+{any}/*{any}"))
}

func TestAdmission_NoEntryGRPCAloneAdmitsHTTPWithoutServingIt(t *testing.T) {
	p := testProxy(t, WithNoEntry(func(c *GRPCCtx) error { return c.Forward() }))
	assert.True(t, p.Admits(Target{Host: "api.test", Port: "443"}, KindHTTP))
	assert.False(t, p.Admits(Target{Host: "api.test", Port: "443"}, KindTCP))

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(origin.Close)
	p.cfg.transport.RootCAs = originPool(t, origin)

	client := proxyClient(startProxy(t, p), p.cfg.ca.CertPool())
	resp, err := client.Get(origin.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func BenchmarkAdmits(b *testing.B) {
	cases := []struct {
		name        string
		authorities []string
		host        string
	}{
		{name: "hit static", authorities: []string{"api.stripe.com"}, host: "api.stripe.com"},
		{name: "hit wildcard", authorities: []string{"+{sub}.stripe.com"}, host: "eu.west.stripe.com"},
		{name: "miss", authorities: []string{"api.stripe.com"}, host: "example.test"},
		{name: "hit address", authorities: []string{"10.1.2.3"}, host: "10.1.2.3"},
		{name: "hit range", authorities: []string{"[10.0.0.0/8]"}, host: "10.9.9.9"},
		{name: "miss address", authorities: []string{"[10.0.0.0/8]"}, host: "11.0.0.1"},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			ca, err := GenerateCA()
			if err != nil {
				b.Fatal(err)
			}
			p, err := New(WithCA(ca))
			if err != nil {
				b.Fatal(err)
			}
			for _, authority := range tc.authorities {
				if _, err := p.Add(authority+"/*{any}", noopHandler); err != nil {
					b.Fatalf("intercept %s: %v", authority, err)
				}
			}
			t := Target{Scheme: "https", Host: tc.host, Port: "443"}

			b.ReportAllocs()
			for b.Loop() {
				p.Admits(t, KindHTTP)
			}
		})
	}
}
