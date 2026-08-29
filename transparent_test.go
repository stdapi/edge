// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startTransparent starts p on a loopback port in transparent mode.
func startTransparent(t *testing.T, p *Proxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.ServeTransparent(ln) }()
	t.Cleanup(func() { _ = p.Close() })
	return ln.Addr().String()
}

// pinnedDialer sends every upstream connection to addr, standing in for the DNS the client
// would have resolved before its traffic was redirected.
func pinnedDialer(addr string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	}
}

func TestTransparent_TLSInterceptRoutesOnServerName(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin got host=%s path=%s", r.Host, r.URL.Path)
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)
	// The test origin holds a certificate for example.com, not for the name the redirect
	// pretends to reach.
	tr.InsecureSkipVerify = true

	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)

	var seenTarget Target
	p.MustAddInterceptor([]string{http.MethodGet}, "api.example.test/v1/charges", func(c *Context) (*http.Response, error) {
		seenTarget = Target{Scheme: c.Scheme(), Host: c.Host(), Port: c.Port()}
		return c.Forward()
	})

	addr := startTransparent(t, p)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// The redirect is simulated by dialing the proxy while asking for the origin,
			// which is exactly what the client sees behind a real one.
			DialContext:     pinnedDialer(addr),
			TLSClientConfig: &tls.Config{RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12},
		},
	}

	resp, err := client.Get("https://api.example.test/v1/charges")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "host=api.example.test")
	assert.Contains(t, string(body), "path=/v1/charges")

	assert.Equal(t, "https", seenTarget.Scheme)
	assert.Equal(t, "api.example.test", seenTarget.Host)
	assert.Equal(t, "443", seenTarget.Port)
}

func TestTransparent_TLSTunnelLeavesTheHandshakeAlone(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunneled")
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)

	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	// The authority comes from the ClientHello, so it is the name the client asked for,
	// not the address the upstream transport is pinned to.
	require.NoError(t, p.AddTunnel("example.com"))

	addr := startTransparent(t, p)

	// Trusting only the origin: an interception here would present the proxy CA and fail.
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
}

func TestTransparent_PlaintextRoutesOnHostHeader(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin got host=%s", r.Host)
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)

	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)

	var seen Target
	p.MustAddInterceptor([]string{http.MethodGet}, "api.example.test/ping", func(c *Context) (*http.Response, error) {
		seen = Target{Scheme: c.Scheme(), Host: c.Host(), Port: c.Port()}
		return c.Forward()
	})

	addr := startTransparent(t, p)

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: pinnedDialer(addr)},
	}

	resp, err := client.Get("http://api.example.test/ping")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "host=api.example.test")
	assert.Equal(t, "http", seen.Scheme)
	assert.Equal(t, "api.example.test", seen.Host)
}

func TestTransparent_PeekClientHelloDoesNotConsume(t *testing.T) {
	ca, _ := GenerateCA()
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	p.MustAddInterceptor(nil, "peek.example.test/", func(c *Context) (*http.Response, error) {
		hello := c.Session().ClientHello()
		require.NotNil(t, hello)
		return Text(http.StatusOK, "sni="+hello.ServerName), nil
	})

	addr := startTransparent(t, p)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:     pinnedDialer(addr),
			TLSClientConfig: &tls.Config{RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12},
		},
	}

	// The handshake only completes if the bytes read to find the server name were left in
	// place for the TLS server that follows.
	resp, err := client.Get("https://peek.example.test/")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "sni=peek.example.test", string(body))
}

func TestTransparent_RejectClosesTheConnection(t *testing.T) {
	ca, _ := GenerateCA()
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	addr := startTransparent(t, p)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: "blocked.example.test",
		RootCAs:    ca.CertPool(),
		MinVersion: tls.VersionTLS12,
	})
	require.Error(t, tlsConn.Handshake(), "a rejected authority must not get a handshake")
}

func TestTransparent_TLSWithoutServerNameNeedsTheOriginalDestination(t *testing.T) {
	ca, _ := GenerateCA()
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	addr := startTransparent(t, p)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Go omits SNI for an IP literal, which leaves the proxy with nothing to place the
	// connection by. Without an original destination resolver it can only give up.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "127.0.0.1",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	require.Error(t, tlsConn.Handshake())
}

func TestTransparent_OriginalDestinationPlacesTheConnection(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "reached by address")
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	originAddr, err := netip.ParseAddrPort(originURL.Host)
	require.NoError(t, err)

	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(
		WithCA(ca),
		WithTransport(tr),
		// Standing in for SO_ORIGINAL_DST or a pf lookup, which need a real redirect.
		WithOriginalDestination(func(net.Conn) (netip.AddrPort, error) { return originAddr, nil }),
	)
	require.NoError(t, err)
	require.NoError(t, p.AddTunnel(originURL.Host))

	addr := startTransparent(t, p)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// No SNI, and the authority is only tunneled: the connection is relayed to the address
	// the client was headed to, so the origin certificate reaches the client untouched.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "127.0.0.1",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	require.NoError(t, tlsConn.Handshake())

	_, err = fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", originURL.Host)
	require.NoError(t, err)

	out, err := io.ReadAll(tlsConn)
	require.NoError(t, err)
	assert.Contains(t, string(out), "reached by address")
}
