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

func collectAuthorities(p *Proxy) []Authority {
	var out []Authority
	for a := range p.Authorities() {
		out = append(out, a)
	}
	return out
}

// Nothing crosses a proxy that was not told about it. An authority named by no tunnel and no
// interceptor is a hole in the setup, and the caller finds out at once rather than having
// the traffic relayed unobserved.
func TestAuthority_DefaultIsReject(t *testing.T) {
	p := testProxy(t)
	assert.Equal(t, Reject, p.Decide(target("anything.test:443")))
	assert.Empty(t, collectAuthorities(p))
}

// An interceptor names the authority it intercepts, so registering one arms it. There is no
// separate verb for that: naming the authority is what admitting it means.
func TestAuthority_InterceptorArmsItsAuthority(t *testing.T) {
	p := testProxy(t)
	require.Equal(t, Reject, p.Decide(target("api.stripe.com:443")))

	p.MustAddInterceptor([]string{http.MethodPost}, "api.stripe.com/v1/charges", noopHandler)

	assert.Equal(t, Intercept, p.Decide(target("api.stripe.com:443")))
	assert.Equal(t, Reject, p.Decide(target("files.stripe.com:443")), "only the one named")

	authorities := collectAuthorities(p)
	require.Len(t, authorities, 1)
	assert.Equal(t, "api.stripe.com", authorities[0].Pattern())
	assert.Equal(t, Intercept, authorities[0].Action())
	assert.True(t, authorities[0].Implicit(), "derived from the interceptor, not declared")
}

func TestAuthority_AddTunnel(t *testing.T) {
	p := testProxy(t)
	require.NoError(t, p.AddTunnel("checkout.stripe.com"))

	assert.Equal(t, Tunnel, p.Decide(target("checkout.stripe.com:443")))
	assert.Equal(t, Reject, p.Decide(target("api.stripe.com:443")))

	authorities := collectAuthorities(p)
	require.Len(t, authorities, 1)
	assert.False(t, authorities[0].Implicit(), "declared, not derived")

	assert.Equal(t, "checkout.stripe.com", authorities[0].Pattern())
	assert.Equal(t, Tunnel, authorities[0].Action())
}

// The flagship shape: watch a whole zone, except the one host that must stay end to end.
// A static authority is more precise than a wildcard, so it decides first.
func TestAuthority_StaticBeatsWildcard(t *testing.T) {
	p := testProxy(t)
	p.MustAddInterceptor(nil, "+{sub}.stripe.com/*{any}", DefaultNoInterceptorHandler)
	require.NoError(t, p.AddTunnel("checkout.stripe.com"))

	assert.Equal(t, Intercept, p.Decide(target("api.stripe.com:443")))
	assert.Equal(t, Intercept, p.Decide(target("a.b.stripe.com:443")))
	assert.Equal(t, Tunnel, p.Decide(target("checkout.stripe.com:443")))
	assert.Equal(t, Reject, p.Decide(target("example.test:443")))
}

// Terminating TLS on a port no interceptor can serve would be visible to the client for
// nothing, so an interceptor scoped to a port arms only that port.
func TestAuthority_PortScoped(t *testing.T) {
	p := testProxy(t)
	p.MustAddInterceptor([]string{http.MethodGet}, "localhost:8080/api", noopHandler)

	assert.Equal(t, Intercept, p.Decide(target("localhost:8080")))
	assert.Equal(t, Reject, p.Decide(target("localhost:9090")))

	require.NoError(t, p.AddTunnel("localhost:9090"))
	assert.Equal(t, Tunnel, p.Decide(target("localhost:9090")))
	assert.Equal(t, Intercept, p.Decide(target("localhost:8080")), "the interceptor keeps its port")
}

func TestAuthority_RejectsSchemeAndPath(t *testing.T) {
	p := testProxy(t)

	for _, tc := range []struct{ pattern, hint string }{
		{"https://api.stripe.com", "no scheme is known"},
		{"api.stripe.com/v1", "must not carry a path"},
	} {
		err := p.AddTunnel(tc.pattern)
		var pe *PatternError
		require.ErrorAs(t, err, &pe, tc.pattern)
		assert.Contains(t, pe.Error(), tc.hint, tc.pattern)
	}
}

// An interceptor registered under a tunneled authority can never run: the connection is
// relayed byte for byte and no request is ever parsed. Accepting it would leave the caller
// with a handler that is silently dead, so it is refused instead.
func TestAuthority_InterceptorUnderATunnelIsRefused(t *testing.T) {
	p := testProxy(t)
	require.NoError(t, p.AddTunnel("api.stripe.com"))

	_, err := p.AddInterceptor([]string{http.MethodPost}, "api.stripe.com/v1/charges", noopHandler)
	require.ErrorIs(t, err, ErrAuthorityConflict)
	assert.Contains(t, err.Error(), "would never run")

	assert.Equal(t, Tunnel, p.Decide(target("api.stripe.com:443")))
	assert.Zero(t, p.InterceptorsLen(), "the refused interceptor must not be registered")
}

// The same conflict from the other side: tunneling an authority interceptors depend on would
// strand them, so it is refused rather than resolved in silence.
func TestAuthority_TunnelingAnInterceptedAuthorityIsRefused(t *testing.T) {
	p := testProxy(t)
	p.MustAddInterceptor([]string{http.MethodPost}, "api.stripe.com/v1/charges", noopHandler)
	require.Equal(t, Intercept, p.Decide(target("api.stripe.com:443")))

	err := p.AddTunnel("api.stripe.com")
	require.ErrorIs(t, err, ErrAuthorityConflict)
	assert.Contains(t, err.Error(), "1 interceptor(s) intercept")

	assert.Equal(t, Intercept, p.Decide(target("api.stripe.com:443")), "the interceptors keep it")
}

// Nothing but precision arbitrates between a tunnel and an interception. On the very same
// authority they contradict each other, which the conflict above rejects; on patterns of
// different precision they coexist, which is the case above this one.
func TestAuthority_DuplicateTunnelConflicts(t *testing.T) {
	p := testProxy(t)
	require.NoError(t, p.AddTunnel("api.stripe.com"))

	err := p.AddTunnel("api.stripe.com")
	var conflict *InterceptorConflictError
	require.ErrorAs(t, err, &conflict)
}

// The authority an interceptor implies lives exactly as long as the interceptors needing it.
func TestAuthority_ImpliedEntryIsReferenceCounted(t *testing.T) {
	p := testProxy(t)
	one := p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
	two := p.MustAddInterceptor([]string{http.MethodPost}, "api.stripe.com/v1/refunds", noopHandler)
	require.Len(t, collectAuthorities(p), 1)

	_, err := p.removeInterceptor(one)
	require.NoError(t, err)
	assert.Equal(t, Intercept, p.Decide(target("api.stripe.com:443")), "one still needs it")

	_, err = p.removeInterceptor(two)
	require.NoError(t, err)
	assert.Equal(t, Reject, p.Decide(target("api.stripe.com:443")), "none needs it any more")
	assert.Empty(t, collectAuthorities(p))
}

func TestAuthority_DeleteTunnel(t *testing.T) {
	p := testProxy(t)
	require.NoError(t, p.AddTunnel("checkout.stripe.com"))

	tn, err := p.DeleteTunnel("checkout.stripe.com")
	require.NoError(t, err)
	assert.Equal(t, "checkout.stripe.com", tn.Pattern())
	assert.Equal(t, Reject, p.Decide(target("checkout.stripe.com:443")))

	_, err = p.DeleteTunnel("checkout.stripe.com")
	require.ErrorIs(t, err, ErrTunnelNotFound)
}

func TestAuthority_InterceptionRequiresCA(t *testing.T) {
	p, err := New()
	require.NoError(t, err, "a proxy that only tunnels never mints a certificate")

	require.NoError(t, p.AddTunnel("api.stripe.com"), "tunneling needs no authority")

	_, err = p.AddInterceptor([]string{http.MethodGet}, "files.stripe.com/v1", noopHandler)
	require.ErrorIs(t, err, ErrNoCertificateAuthority)
}

func TestAuthority_TruncateDropsEverything(t *testing.T) {
	p := testProxy(t)
	require.NoError(t, p.AddTunnel("kept.example.test"))
	p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/charges", noopHandler)
	require.Len(t, collectAuthorities(p), 2)
	require.Equal(t, 1, p.InterceptorsLen())
	require.Equal(t, 2, p.AuthoritiesLen(), "the declared tunnel plus the one the interceptor implies")

	require.NoError(t, p.Updates(func(txn *Txn) error { return txn.Truncate() }))

	// Interceptors and authorities share one tree, so truncating it leaves nothing behind.
	assert.Empty(t, collectAuthorities(p))
	assert.Zero(t, p.InterceptorsLen())
	assert.Zero(t, p.AuthoritiesLen())
}

// The point of putting both in one tree: swapping an authority from intercepted to tunneled
// takes one transaction, so no connection ever observes the half-applied state where the
// interceptors are gone and the tunnel is not there yet.
func TestAuthority_SwapInterceptionForATunnelAtomically(t *testing.T) {
	p := testProxy(t)
	p.MustAddInterceptor([]string{http.MethodPost}, "api.stripe.com/v1/charges", noopHandler)
	require.Equal(t, Intercept, p.Decide(target("api.stripe.com:443")))

	err := p.Updates(func(txn *Txn) error {
		if _, err := txn.DeleteInterceptor([]string{http.MethodPost}, "api.stripe.com/v1/charges"); err != nil {
			return err
		}
		return txn.AddTunnel("api.stripe.com")
	})
	require.NoError(t, err)

	assert.Equal(t, Tunnel, p.Decide(target("api.stripe.com:443")))
	assert.Zero(t, p.InterceptorsLen())
}

// The same swap in the wrong order is refused, and the transaction leaves nothing behind.
func TestAuthority_SwapInTheWrongOrderAbortsCleanly(t *testing.T) {
	p := testProxy(t)
	p.MustAddInterceptor([]string{http.MethodPost}, "api.stripe.com/v1/charges", noopHandler)

	err := p.Updates(func(txn *Txn) error {
		if err := txn.AddTunnel("api.stripe.com"); err != nil {
			return err
		}
		_, err := txn.DeleteInterceptor([]string{http.MethodPost}, "api.stripe.com/v1/charges")
		return err
	})
	require.ErrorIs(t, err, ErrAuthorityConflict)

	assert.Equal(t, Intercept, p.Decide(target("api.stripe.com:443")), "nothing was applied")
	assert.Equal(t, 1, p.InterceptorsLen())
}

func TestAuthority_TunnelOnAReadOnlyTxn(t *testing.T) {
	p := testProxy(t)
	require.NoError(t, p.View(func(txn *Txn) error {
		assert.ErrorIs(t, txn.AddTunnel("api.stripe.com"), ErrReadOnlyTxn)
		_, err := txn.DeleteTunnel("api.stripe.com")
		assert.ErrorIs(t, err, ErrReadOnlyTxn)
		return nil
	}))
}
