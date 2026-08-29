// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func target(authority string) Target {
	host, port := splitHostPort(authority)
	return Target{Host: host, Port: port}
}

func TestRules_DefaultIsTunnel(t *testing.T) {
	p := testProxy(t)
	assert.Equal(t, Tunnel, p.Decide(target("anything.test:443")))
}

func TestRules_ExplicitIntercept(t *testing.T) {
	p := testProxy(t, WithIntercept("api.stripe.com"))
	assert.Equal(t, Intercept, p.Decide(target("api.stripe.com:443")))
	assert.Equal(t, Tunnel, p.Decide(target("files.stripe.com:443")))
}

func TestRules_StaticBeatsWildcard(t *testing.T) {
	p := testProxy(t,
		WithIntercept("+{sub}.stripe.com"),
		WithTunnel("checkout.stripe.com"),
	)

	assert.Equal(t, Intercept, p.Decide(target("api.stripe.com:443")))
	assert.Equal(t, Intercept, p.Decide(target("a.b.stripe.com:443")))
	assert.Equal(t, Tunnel, p.Decide(target("checkout.stripe.com:443")))
}

func TestRules_PortScoped(t *testing.T) {
	p := testProxy(t, WithIntercept("localhost:8080"))
	assert.Equal(t, Intercept, p.Decide(target("localhost:8080")))
	assert.Equal(t, Tunnel, p.Decide(target("localhost:9090")))
}

func TestRules_RejectsScheme(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)

	_, err = New(WithCA(ca), WithIntercept("https://api.stripe.com"))
	var pe *PatternError
	require.ErrorAs(t, err, &pe)
	assert.Contains(t, pe.Error(), "scheme is not known")
}

func TestRules_RejectsPath(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)

	_, err = New(WithCA(ca), WithIntercept("api.stripe.com/v1"))
	var pe *PatternError
	require.ErrorAs(t, err, &pe)
	assert.Contains(t, pe.Error(), "must not carry a path")
}

func TestRules_RouteImpliesIntercept(t *testing.T) {
	p := testProxy(t)
	assert.Equal(t, Tunnel, p.Decide(target("api.stripe.com:443")))

	p.MustHandle([]string{http.MethodPost}, "api.stripe.com/v1/charges", noopHandler)
	assert.Equal(t, Intercept, p.Decide(target("api.stripe.com:443")))

	rules := collectRules(p)
	require.Len(t, rules, 1)
	assert.True(t, rules[0].Implicit())
	assert.Equal(t, "api.stripe.com", rules[0].Pattern())
}

func TestRules_RoutePortScopesTheImpliedRule(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "localhost/api", noopHandler, WithPort("8080"))

	assert.Equal(t, Intercept, p.Decide(target("localhost:8080")))
	assert.Equal(t, Tunnel, p.Decide(target("localhost:9090")))
}

func TestRules_ExplicitTunnelWinsOverImpliedIntercept(t *testing.T) {
	p := testProxy(t, WithTunnel("api.stripe.com"))
	p.MustHandle([]string{http.MethodPost}, "api.stripe.com/v1/charges", noopHandler)

	// The route wanted interception but the operator said otherwise for that authority.
	assert.Equal(t, Tunnel, p.Decide(target("api.stripe.com:443")))
	require.Len(t, collectRules(p), 1)
	assert.False(t, collectRules(p)[0].Implicit())
}

func TestRules_ExplicitReplacesImplied(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodPost}, "api.stripe.com/v1/charges", noopHandler)
	require.Equal(t, Intercept, p.Decide(target("api.stripe.com:443")))

	require.NoError(t, p.Tunnel("api.stripe.com"))
	assert.Equal(t, Tunnel, p.Decide(target("api.stripe.com:443")))

	rules := collectRules(p)
	require.Len(t, rules, 1)
	assert.False(t, rules[0].Implicit())
}

func TestRules_ImpliedRuleIsReferenceCounted(t *testing.T) {
	p := testProxy(t)
	one := p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
	two := p.MustHandle([]string{http.MethodPost}, "api.stripe.com/v1/refunds", noopHandler)
	require.Len(t, collectRules(p), 1)

	_, err := p.DeleteRoute(one)
	require.NoError(t, err)
	assert.Equal(t, Intercept, p.Decide(target("api.stripe.com:443")), "one route still needs it")

	_, err = p.DeleteRoute(two)
	require.NoError(t, err)
	assert.Equal(t, Tunnel, p.Decide(target("api.stripe.com:443")), "no route needs it any more")
	assert.Empty(t, collectRules(p))
}

func TestRules_DuplicateExplicitRuleConflicts(t *testing.T) {
	p := testProxy(t, WithIntercept("api.stripe.com"))
	err := p.Tunnel("api.stripe.com")

	var conflict *RouteConflictError
	require.ErrorAs(t, err, &conflict)
}

func TestRules_Reject(t *testing.T) {
	p := testProxy(t, WithReject("telemetry.example.test"))
	assert.Equal(t, Reject, p.Decide(target("telemetry.example.test:443")))
}

func TestRules_DeleteRule(t *testing.T) {
	p := testProxy(t, WithIntercept("api.stripe.com"))

	rule, err := p.DeleteRule("api.stripe.com")
	require.NoError(t, err)
	assert.Equal(t, Intercept, rule.Action())
	assert.Equal(t, Tunnel, p.Decide(target("api.stripe.com:443")))

	_, err = p.DeleteRule("api.stripe.com")
	require.ErrorIs(t, err, ErrRuleNotFound)
}

func TestRules_InterceptRequiresCA(t *testing.T) {
	p, err := New()
	require.NoError(t, err, "a proxy that only tunnels needs no CA")

	err = p.Intercept("api.stripe.com")
	require.ErrorIs(t, err, ErrNoCertificateAuthority)

	_, err = p.Handle([]string{http.MethodGet}, "api.stripe.com/v1", noopHandler)
	require.ErrorIs(t, err, ErrNoCertificateAuthority)

	// A route that names no authority implies no interception, so it needs no CA.
	_, err = p.Handle([]string{http.MethodGet}, "/v1", noopHandler)
	require.NoError(t, err)
}

func TestRules_DefaultInterceptRequiresCA(t *testing.T) {
	_, err := New(WithDefaultAction(Intercept))
	require.ErrorIs(t, err, ErrNoCertificateAuthority)
}

func TestRules_TruncateDropsImpliedRules(t *testing.T) {
	p := testProxy(t, WithIntercept("kept.example.test"))
	p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
	require.Len(t, collectRules(p), 2)

	require.NoError(t, p.Updates(func(txn *Txn) error { return txn.Truncate() }))

	rules := collectRules(p)
	require.Len(t, rules, 1)
	assert.Equal(t, "kept.example.test", rules[0].Pattern())
}

func collectRules(p *Proxy) []Rule {
	var out []Rule
	for r := range p.Rules() {
		out = append(out, r)
	}
	return out
}
