// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const h3Authority = "h3.example.test"

// h3Origin starts an HTTP/3 origin holding a certificate for h3Authority signed by ca, and
// returns its address.
func h3Origin(t *testing.T, ca *CA) netip.AddrPort {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Origin-Proto", r.Proto)
			fmt.Fprintf(w, "origin method=%s path=%s proto=%s host=%s", r.Method, r.URL.Path, r.Proto, r.Host)
		}),
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{selfSignedFor(t, ca, h3Authority)},
			MinVersion:   tls.VersionTLS13,
		}),
		QUICConfig: &quic.Config{},
	}

	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = pc.Close()
	})

	addr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	require.NoError(t, err)
	return addr
}

// startQUIC starts p on a loopback UDP port and returns it.
func startQUIC(t *testing.T, p *Proxy) netip.AddrPort {
	t.Helper()
	return serveQUIC(t, p, func(pc net.PacketConn) net.PacketConn { return pc })
}

// startQUICRedirected starts p on a loopback UDP port whose datagrams all report origin as
// the address they were headed to, standing in for the redirect that would have sent them.
func startQUICRedirected(t *testing.T, p *Proxy, origin netip.AddrPort) netip.AddrPort {
	t.Helper()
	return serveQUIC(t, p, func(pc net.PacketConn) net.PacketConn {
		return fixedOriginPacketConn{PacketConn: pc, origin: origin}
	})
}

func serveQUIC(t *testing.T, p *Proxy, wrap func(net.PacketConn) net.PacketConn) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() { _ = p.ServeQUIC(wrap(pc)) }()
	t.Cleanup(func() { _ = p.Close() })

	addr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	require.NoError(t, err)
	return addr
}

type fixedOriginPacketConn struct {
	net.PacketConn
	origin netip.AddrPort
}

func (c fixedOriginPacketConn) OriginalDestination(net.Addr) (netip.AddrPort, error) {
	return c.origin, nil
}

func caFileOf(t *testing.T, ca *CA, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, ca.CertificatePEM(), 0o600))
	return path
}

func poolOf(ca *CA) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	return pool
}

func TestQUIC_InterceptWithCurl(t *testing.T) {
	requireCurl(t)

	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)

	tr := DefaultTransport()
	tr.AllowHTTP3 = true
	tr.RootCAs = poolOf(originCA)

	p, err := New(WithCA(proxyCA), WithTransport(tr))
	require.NoError(t, err)

	seen := new(recorder)
	p.MustAddInterceptor(nil, h3Authority+"/+{any}", func(c *Context) (*http.Response, error) {
		seen.add(c.Protocol().String() + " " + c.Request().URL.Path)
		return c.Forward()
	})

	proxyAddr := startQUICRedirected(t, p, origin)
	port := fmt.Sprint(proxyAddr.Port())

	res := runCurl(t,
		"--http3-only",
		"--resolve", h3Authority+":"+port+":127.0.0.1",
		"--cacert", caFileOf(t, proxyCA, "proxy.pem"),
		fmt.Sprintf("https://%s:%s/echo", h3Authority, port),
	)

	require.Equal(t, "200", res.status, "body %q", res.body)
	assert.Equal(t, "3", res.version, "curl must have used HTTP/3")
	assert.Contains(t, res.body, "proto=HTTP/3.0", "the origin must have been reached over HTTP/3 too")
	assert.Contains(t, res.body, "path=/echo")
	require.Equal(t, []string{"HTTP/3.0 /echo"}, seen.all())
}

func TestQUIC_TunnelWithCurl(t *testing.T) {
	requireCurl(t)

	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)

	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	require.NoError(t, p.AddTunnel(h3Authority))

	// On every other authority: the tunnel is the more precise entry and decides first.
	// An interceptor on the tunneled authority itself is refused, since it could never run.
	handlerRan := new(atomic.Bool)
	p.MustAddInterceptor(nil, "+{any}/+{rest}", func(c *Context) (*http.Response, error) {
		handlerRan.Store(true)
		return c.Forward()
	})

	proxyAddr := startQUICRedirected(t, p, origin)
	port := fmt.Sprint(proxyAddr.Port())

	// Only the origin CA is trusted. A relayed handshake reaches the origin certificate, an
	// intercepted one would present the proxy's and fail.
	res := runCurl(t,
		"--http3-only",
		"--resolve", h3Authority+":"+port+":127.0.0.1",
		"--cacert", caFileOf(t, originCA, "origin.pem"),
		fmt.Sprintf("https://%s:%s/echo", h3Authority, port),
	)

	require.Equal(t, "200", res.status, "body %q", res.body)
	assert.Equal(t, "3", res.version)
	assert.Contains(t, res.body, "proto=HTTP/3.0")
	assert.False(t, handlerRan.Load(), "no handler may run on a relayed connection")
}

func TestQUIC_HandlerCanShortCircuit(t *testing.T) {
	requireCurl(t)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)

	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)

	p.MustAddInterceptor([]string{http.MethodGet}, h3Authority+"/blocked", func(c *Context) (*http.Response, error) {
		return Text(http.StatusForbidden, "blocked by edge over "+c.Protocol().String()), nil
	})

	proxyAddr := startQUIC(t, p)
	port := fmt.Sprint(proxyAddr.Port())

	res := runCurl(t,
		"--http3-only",
		"--resolve", h3Authority+":"+port+":127.0.0.1",
		"--cacert", caFileOf(t, proxyCA, "proxy.pem"),
		fmt.Sprintf("https://%s:%s/blocked", h3Authority, port),
	)

	assert.Equal(t, "403", res.status)
	assert.Equal(t, "3", res.version)
	assert.Contains(t, res.body, "blocked by edge over HTTP/3.0")
}

func TestQUIC_RejectDropsTheConnection(t *testing.T) {
	proxyCA, err := GenerateCA()
	require.NoError(t, err)

	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)

	proxyAddr := startQUIC(t, p)

	pc, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()

	ctx := t.Context()
	_, err = quic.Dial(ctx,
		pc,
		net.UDPAddrFromAddrPort(proxyAddr),
		&tls.Config{ServerName: h3Authority, RootCAs: poolOf(proxyCA), NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
		&quic.Config{HandshakeIdleTimeout: 2 * time.Second},
	)
	require.Error(t, err, "a rejected authority must never complete a handshake")
}

// dialQUICTo returns an HTTP/3 transport reaching addr whatever the URL says, so a test can
// use the authority the proxy sniffs without it having to resolve.
func dialQUICTo(addr netip.AddrPort, roots *x509.CertPool) *http3.Transport {
	return &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		// A short idle timeout so a connection the proxy cut does not hold the test open.
		QUICConfig: &quic.Config{MaxIdleTimeout: time.Second},
		Dial: func(ctx context.Context, _ string, cfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			pc, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			conn, err := quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(addr), cfg, qcfg)
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
			return conn, nil
		},
	}
}

// A tunneled QUIC peer is decided once, when its ClientHello is read, and never again, so it
// needs a session of its own for a sweep to reach it.
func TestQUIC_TunnelSessionIsListedAndClosed(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	require.NoError(t, p.AddTunnel(h3Authority))

	proxyAddr := startQUICRedirected(t, p, origin)

	tr := dialQUICTo(proxyAddr, poolOf(originCA))
	defer func() { _ = tr.Close() }()

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/echo", h3Authority, proxyAddr.Port()), nil)
	require.NoError(t, err)

	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	// End to end, the origin answered its own certificate and the proxy only moved datagrams.
	assert.Contains(t, string(body), "path=/echo")

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, Tunnel, sessions[0].Action())
	assert.Equal(t, h3Authority, sessions[0].Target().Host)
	assert.Equal(t, HTTP3, sessions[0].Protocol())

	require.NoError(t, sessions[0].Close())
	assert.Empty(t, slices.Collect(p.Sessions()), "closing removes the peer under the demux lock")
}

// The proxy terminated the connection of an intercepted QUIC peer, so closing its session goes
// through CloseWithError rather than leaving the client to time out. What the client
// then observes is not asserted, an http3.Transport is free to redial on its own.
func TestQUIC_InterceptedSessionIsListedAndClosed(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)

	upstream := DefaultTransport()
	upstream.AllowHTTP3 = true
	upstream.RootCAs = poolOf(originCA)

	p, err := New(WithCA(proxyCA), WithTransport(upstream))
	require.NoError(t, err)
	p.MustAddInterceptor(nil, h3Authority+"/+{any}", func(c *Context) (*http.Response, error) {
		return c.Forward()
	})

	proxyAddr := startQUICRedirected(t, p, origin)

	tr := dialQUICTo(proxyAddr, poolOf(proxyCA))
	defer func() { _ = tr.Close() }()

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/echo", h3Authority, proxyAddr.Port()), nil)
	require.NoError(t, err)

	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "path=/echo")

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, Intercept, sessions[0].Action())
	assert.Equal(t, h3Authority, sessions[0].Target().Host)
	assert.NotNil(t, sessions[0].TLS(), "the handshake the proxy terminated is recorded")

	require.NoError(t, sessions[0].Close())
	assert.Empty(t, slices.Collect(p.Sessions()))
}

// A handler waiting on the session context has to be released when the session ends. A QUIC
// peer owns its own, since nothing upstream of it cancels one.
func TestQUIC_SessionContextEndsWithTheSession(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	require.NoError(t, p.AddTunnel(h3Authority))

	proxyAddr := startQUICRedirected(t, p, origin)
	tr := dialQUICTo(proxyAddr, poolOf(originCA))
	defer func() { _ = tr.Close() }()

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/echo", h3Authority, proxyAddr.Port()), nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	sess := waitForSessions(t, p, 1)[0]
	sessCtx := sess.Context()
	select {
	case <-sessCtx.Done():
		t.Fatal("the context fired while the session was alive")
	default:
	}

	require.NoError(t, sess.Close())
	select {
	case <-sessCtx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("closing the session did not end its context")
	}
}

// The session context of an intercepted QUIC peer follows the connection. A client that
// closes it and leaves ends the context right away, not two minutes later when the idle
// sweep gets to the peer.
func TestQUIC_SessionContextEndsWhenTheClientLeaves(t *testing.T) {
	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddInterceptor(nil, h3Authority+"/", func(c *Context) (*http.Response, error) {
		return Text(http.StatusOK, "ok"), nil
	})

	proxyAddr := startQUIC(t, p)
	tr := dialQUICTo(proxyAddr, poolOf(proxyCA))

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/", h3Authority, proxyAddr.Port()), nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	sessCtx := waitForSessions(t, p, 1)[0].Context()
	select {
	case <-sessCtx.Done():
		t.Fatal("the context fired while the connection was alive")
	default:
	}

	require.NoError(t, tr.Close())
	select {
	case <-sessCtx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the client leaving did not end the session context")
	}
}
