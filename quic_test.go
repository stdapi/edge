// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
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
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() { _ = p.ServeQUIC(pc) }()
	t.Cleanup(func() { _ = p.Close() })

	addr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	require.NoError(t, err)
	return addr
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

	p, err := New(
		WithCA(proxyCA),
		WithTransport(tr),
		// Standing in for the redirect that would send the client's datagrams here.
		WithPacketOriginalDestination(func(net.Addr, net.Addr) (netip.AddrPort, error) {
			return origin, nil
		}),
	)
	require.NoError(t, err)

	seen := new(recorder)
	p.MustAddInterceptor(nil, h3Authority+"/+{any}", func(c *Context) (*http.Response, error) {
		seen.add(c.Protocol().String() + " " + c.Request().URL.Path)
		return c.Forward()
	})

	proxyAddr := startQUIC(t, p)
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

	p, err := New(
		WithCA(proxyCA),
		WithPacketOriginalDestination(func(net.Addr, net.Addr) (netip.AddrPort, error) {
			return origin, nil
		}),
	)
	require.NoError(t, err)
	require.NoError(t, p.AddTunnel(h3Authority))

	// On every other authority: the tunnel is the more precise entry and decides first.
	// An interceptor on the tunneled authority itself is refused, since it could never run.
	handlerRan := new(atomic.Bool)
	p.MustAddInterceptor(nil, "+{any}/+{rest}", func(c *Context) (*http.Response, error) {
		handlerRan.Store(true)
		return c.Forward()
	})

	proxyAddr := startQUIC(t, p)
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
