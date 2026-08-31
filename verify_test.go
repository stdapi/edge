// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeResolver answers from a fixed map, standing in for the DNS behind name verification.
type fakeResolver struct {
	addrs map[string][]netip.Addr
	err   error
	calls atomic.Int32
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	r.calls.Add(1)
	if r.err != nil {
		return nil, r.err
	}
	return r.addrs[host], nil
}

func addrsOf(s ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(s))
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func TestNameVerification_DecideTransparent(t *testing.T) {
	liar := netip.MustParseAddrPort("6.6.6.6:443")

	cases := []struct {
		name        string
		mode        NameVerification
		tunnels     []string
		resolved    map[string][]netip.Addr
		resolveErr  error
		host        string
		named       bool
		origin      netip.AddrPort
		wantAction  Action
		wantHost    string
		wantVerdict nameVerdict
		wantCalls   int32
	}{
		{
			name: "off trusts the name and never resolves", mode: VerifyOff,
			tunnels: []string{"allowed.test"}, host: "allowed.test", named: true, origin: liar,
			wantAction: Tunnel, wantHost: "allowed.test", wantVerdict: nameTrusted, wantCalls: 0,
		},
		{
			name: "loose keeps a confirmed name", mode: VerifyLoose,
			tunnels:  []string{"allowed.test"},
			resolved: map[string][]netip.Addr{"allowed.test": addrsOf("6.6.6.6")},
			host:     "allowed.test", named: true, origin: liar,
			wantAction: Tunnel, wantHost: "allowed.test", wantVerdict: nameTrusted, wantCalls: 1,
		},
		{
			name: "loose without a destination rule rejects the liar", mode: VerifyLoose,
			tunnels:  []string{"allowed.test"},
			resolved: map[string][]netip.Addr{"allowed.test": addrsOf("9.9.9.9")},
			host:     "allowed.test", named: true, origin: liar,
			wantAction: Reject, wantHost: "6.6.6.6", wantVerdict: nameDropped, wantCalls: 1,
		},
		{
			name: "loose with a destination rule admits the flow on it", mode: VerifyLoose,
			tunnels:  []string{"allowed.test", "6.6.6.6:443"},
			resolved: map[string][]netip.Addr{"allowed.test": addrsOf("9.9.9.9")},
			host:     "allowed.test", named: true, origin: liar,
			wantAction: Tunnel, wantHost: "6.6.6.6", wantVerdict: nameDropped, wantCalls: 1,
		},
		{
			name: "strict rejects a mismatch", mode: VerifyReject,
			tunnels:  []string{"allowed.test"},
			resolved: map[string][]netip.Addr{"allowed.test": addrsOf("9.9.9.9")},
			host:     "allowed.test", named: true, origin: liar,
			wantAction: Reject, wantHost: "allowed.test", wantVerdict: nameMismatch, wantCalls: 1,
		},
		{
			name: "strict rejects a name that does not resolve", mode: VerifyReject,
			tunnels:    []string{"allowed.test"},
			resolveErr: errors.New("no such host"),
			host:       "allowed.test", named: true, origin: liar,
			wantAction: Reject, wantHost: "allowed.test", wantVerdict: nameUnresolved, wantCalls: 1,
		},
		{
			name: "loose falls back to the destination when resolution fails", mode: VerifyLoose,
			tunnels:    []string{"allowed.test", "6.6.6.6:443"},
			resolveErr: errors.New("no such host"),
			host:       "allowed.test", named: true, origin: liar,
			wantAction: Tunnel, wantHost: "6.6.6.6", wantVerdict: nameDropped, wantCalls: 1,
		},
		{
			name: "a name refused either way is not resolved", mode: VerifyLoose,
			host: "junk.test", named: true, origin: liar,
			wantAction: Reject, wantHost: "junk.test", wantVerdict: nameTrusted, wantCalls: 0,
		},
		{
			name: "strict never falls back, so a rejected name skips resolution", mode: VerifyReject,
			tunnels: []string{"6.6.6.6:443"}, host: "junk.test", named: true, origin: liar,
			wantAction: Reject, wantHost: "junk.test", wantVerdict: nameTrusted, wantCalls: 0,
		},
		{
			name: "loose drops a name no rule matches without a lookup", mode: VerifyLoose,
			tunnels: []string{"6.6.6.6:443"}, host: "junk.test", named: true, origin: liar,
			wantAction: Tunnel, wantHost: "6.6.6.6", wantVerdict: nameDropped, wantCalls: 0,
		},
		{
			name: "a rule-less name is dropped unresolved even when it would confirm", mode: VerifyLoose,
			tunnels:  []string{"6.6.6.6:443"},
			resolved: map[string][]netip.Addr{"junk.test": addrsOf("6.6.6.6")},
			host:     "junk.test", named: true, origin: liar,
			wantAction: Tunnel, wantHost: "6.6.6.6", wantVerdict: nameDropped, wantCalls: 0,
		},
		{
			name: "a host that is not a client name is not checked", mode: VerifyReject,
			tunnels: []string{"allowed.test"}, host: "allowed.test", named: false, origin: liar,
			wantAction: Tunnel, wantHost: "allowed.test", wantVerdict: nameTrusted, wantCalls: 0,
		},
		{
			name: "no destination on record means nothing to verify", mode: VerifyReject,
			tunnels: []string{"allowed.test"}, host: "allowed.test", named: true,
			wantAction: Tunnel, wantHost: "allowed.test", wantVerdict: nameTrusted, wantCalls: 0,
		},
		{
			name: "a v4-mapped resolver answer confirms a v4 destination", mode: VerifyReject,
			tunnels:  []string{"allowed.test"},
			resolved: map[string][]netip.Addr{"allowed.test": addrsOf("::ffff:6.6.6.6")},
			host:     "allowed.test", named: true, origin: liar,
			wantAction: Tunnel, wantHost: "allowed.test", wantVerdict: nameTrusted, wantCalls: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeResolver{addrs: tc.resolved, err: tc.resolveErr}
			p, err := New(WithNameVerification(tc.mode), WithNameResolver(r))
			require.NoError(t, err)
			for _, pattern := range tc.tunnels {
				p.MustAddTunnel(pattern)
			}

			target := Target{Scheme: "https", Host: tc.host, Port: "443"}
			action, matched, verdict := p.actionForTransparent(t.Context(), target, tc.origin, tc.named)
			assert.Equal(t, tc.wantAction, action)
			assert.Equal(t, tc.wantHost, matched.Host)
			assert.Equal(t, tc.wantVerdict, verdict)
			assert.Equal(t, tc.wantCalls, r.calls.Load())
		})
	}
}

func TestNameVerification_OptionValidation(t *testing.T) {
	_, err := New(WithNameVerification(verifySentinel))
	require.ErrorIs(t, err, ErrInvalidConfig)
	_, err = New(WithNameResolver(nil))
	require.ErrorIs(t, err, ErrInvalidConfig)
}

// countingOrigin accepts connections, counts them and holds them open until the test ends.
// Whether the proxy dialed it is the observable difference between a relayed liar and a
// refused one.
func countingOrigin(t *testing.T) (netip.AddrPort, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})

	dials := new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String()), dials
}

// lyingHandshake sends a TLS ClientHello with name toward the proxy from the background.
// The origin never speaks TLS back, so the handshake cannot complete and the dial counter
// is what tells the outcomes apart.
func lyingHandshake(t *testing.T, proxyAddr, name string) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         name,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	go func() { _ = tlsConn.Handshake() }()
}

func TestTransparent_NameVerificationStopsALyingServerName(t *testing.T) {
	t.Run("off relays the liar to its destination", func(t *testing.T) {
		origin, dials := countingOrigin(t)
		p, err := New()
		require.NoError(t, err)
		p.MustAddTunnel("allowed.test")

		addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) { return origin, nil })
		lyingHandshake(t, addr, "allowed.test")

		assert.Eventually(t, func() bool { return dials.Load() == 1 }, 3*time.Second, 10*time.Millisecond,
			"without verification the permitted name reaches the client's own destination")
	})

	t.Run("strict refuses the liar before any dial", func(t *testing.T) {
		origin, dials := countingOrigin(t)
		r := &fakeResolver{addrs: map[string][]netip.Addr{"allowed.test": addrsOf("9.9.9.9")}}
		p, err := New(WithNameVerification(VerifyReject), WithNameResolver(r))
		require.NoError(t, err)
		p.MustAddTunnel("allowed.test")

		addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) { return origin, nil })
		lyingHandshake(t, addr, "allowed.test")

		time.Sleep(300 * time.Millisecond)
		assert.Equal(t, int32(0), dials.Load(), "a refused connection must not reach the origin")
		assert.Equal(t, int32(1), r.calls.Load())
	})

	t.Run("loose without a destination rule refuses the liar", func(t *testing.T) {
		origin, dials := countingOrigin(t)
		r := &fakeResolver{addrs: map[string][]netip.Addr{"allowed.test": addrsOf("9.9.9.9")}}
		p, err := New(WithNameVerification(VerifyLoose), WithNameResolver(r))
		require.NoError(t, err)
		p.MustAddTunnel("allowed.test")

		addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) { return origin, nil })
		lyingHandshake(t, addr, "allowed.test")

		time.Sleep(300 * time.Millisecond)
		assert.Equal(t, int32(0), dials.Load())
	})

	t.Run("loose admits the flow through a rule on the destination", func(t *testing.T) {
		origin, dials := countingOrigin(t)
		r := &fakeResolver{addrs: map[string][]netip.Addr{"allowed.test": addrsOf("9.9.9.9")}}
		p, err := New(WithNameVerification(VerifyLoose), WithNameResolver(r))
		require.NoError(t, err)
		p.MustAddTunnel("allowed.test")
		p.MustAddTunnel(origin.String())

		addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) { return origin, nil })
		lyingHandshake(t, addr, "allowed.test")

		assert.Eventually(t, func() bool { return dials.Load() == 1 }, 3*time.Second, 10*time.Millisecond)
		sessions := waitForSessions(t, p, 1)
		assert.Equal(t, origin.Addr().String(), sessions[0].Target().Host,
			"a dropped name leaves the destination as the session target, not the unproven name")
		assert.Equal(t, Tunnel, sessions[0].Action())
	})
}

func TestTransparent_NameVerificationConfirmedNameTunnels(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunneled")
	}))
	defer origin.Close()
	originURL, _ := url.Parse(origin.URL)
	originAddr := netip.MustParseAddrPort(originURL.Host)

	r := &fakeResolver{addrs: map[string][]netip.Addr{"example.com": {originAddr.Addr()}}}
	p, err := New(WithNameVerification(VerifyReject), WithNameResolver(r))
	require.NoError(t, err)
	p.MustAddTunnel("example.com")

	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) { return originAddr, nil })

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: pinnedDialer(addr),
			TLSClientConfig: &tls.Config{
				RootCAs:    originPool(t, origin),
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	resp, err := client.Get("https://example.com/")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "tunneled", string(body))
	assert.Equal(t, int32(1), r.calls.Load())
}

func TestQUIC_NameVerificationRejectsALyingServerName(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	r := &fakeResolver{addrs: map[string][]netip.Addr{h3Authority: addrsOf("9.9.9.9")}}
	p, err := New(WithNameVerification(VerifyReject), WithNameResolver(r))
	require.NoError(t, err)
	p.MustAddTunnel(h3Authority)

	proxyAddr := startQUICRedirected(t, p, origin)

	clientPC, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	ctr := &quic.Transport{Conn: clientPC}
	defer func() { _ = ctr.Close(); _ = clientPC.Close() }()

	_, err = ctr.Dial(t.Context(), net.UDPAddrFromAddrPort(proxyAddr), &tls.Config{
		ServerName: h3Authority,
		RootCAs:    poolOf(originCA),
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{HandshakeIdleTimeout: 1500 * time.Millisecond})
	require.Error(t, err, "a refused connection gets silence, so the handshake must time out")
	assert.Equal(t, int32(1), r.calls.Load())
}

func TestQUIC_NameVerificationLooseFallsBackToTheDestination(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	r := &fakeResolver{addrs: map[string][]netip.Addr{h3Authority: addrsOf("9.9.9.9")}}
	p, err := New(WithNameVerification(VerifyLoose), WithNameResolver(r))
	require.NoError(t, err)
	p.MustAddTunnel(origin.String())

	proxyAddr := startQUICRedirected(t, p, origin)

	clientPC, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	ctr := &quic.Transport{Conn: clientPC}
	defer func() { _ = ctr.Close(); _ = clientPC.Close() }()

	conn := dialSharedQUIC(t, ctr, proxyAddr, h3Authority, poolOf(originCA))
	h3tr := &http3.Transport{}
	defer func() { _ = h3tr.Close() }()
	cc := h3tr.NewClientConn(conn)
	assert.Contains(t, h3Get(t, cc, h3Authority, proxyAddr.Port()), "host="+h3Authority)

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, origin.Addr().String(), sessions[0].Target().Host)
	assert.Equal(t, Tunnel, sessions[0].Action())
}

// The mitm handshake refines an explicit CONNECT target with the handshake's server name.
// On a session with a dropped name it would put the unproven name back.
func TestTransparent_NameVerificationInterceptionKeepsTheDroppedTarget(t *testing.T) {
	origin, dials := countingOrigin(t)
	ca, err := GenerateCA()
	require.NoError(t, err)

	r := &fakeResolver{addrs: map[string][]netip.Addr{"allowed.test": addrsOf("9.9.9.9")}}
	p, err := New(WithCA(ca), WithNameVerification(VerifyLoose), WithNameResolver(r))
	require.NoError(t, err)
	p.MustAddInterceptor(nil, fmt.Sprintf("%s:%d/+{any}", origin.Addr(), origin.Port()),
		func(c *Context) (*http.Response, error) {
			return Text(http.StatusOK, "intercepted"), nil
		})

	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) { return origin, nil })

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "allowed.test",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	require.NoError(t, tlsConn.Handshake(), "the dropped name is intercepted through the rule on its destination")

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, origin.Addr().String(), sessions[0].Target().Host,
		"the handshake must not put the unproven name back on the session")
	assert.Equal(t, Intercept, sessions[0].Action())
	assert.Equal(t, int32(0), dials.Load(), "nothing forwarded, nothing dialed")
}

// deadlineResolver records whether the lookup context is bounded.
type deadlineResolver struct {
	sawDeadline atomic.Bool
}

func (r *deadlineResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	_, ok := ctx.Deadline()
	r.sawDeadline.Store(ok)
	return nil, errors.New("no such host")
}

func TestNameVerification_ResolutionCarriesADeadline(t *testing.T) {
	r := new(deadlineResolver)
	p, err := New(WithNameVerification(VerifyReject), WithNameResolver(r))
	require.NoError(t, err)
	p.MustAddTunnel("allowed.test")

	target := Target{Scheme: "https", Host: "allowed.test", Port: "443"}
	action, _, verdict := p.actionForTransparent(t.Context(), target, netip.MustParseAddrPort("6.6.6.6:443"), true)
	assert.Equal(t, Reject, action)
	assert.Equal(t, nameUnresolved, verdict)
	assert.True(t, r.sawDeadline.Load(), "a resolver without a deadline could stall the connection forever")
}
