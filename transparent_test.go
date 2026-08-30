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
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
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

// originListener makes every accepted connection report what origin answers, standing in for
// the SO_ORIGINAL_DST or pf lookup a real redirect would answer.
type originListener struct {
	net.Listener
	origin func(net.Conn) (netip.AddrPort, error)
}

func (l originListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// A pointer, since the proxy tracks connections in a map and this one holds a func.
	return &originConn{Conn: c, origin: l.origin}, nil
}

type originConn struct {
	net.Conn
	origin func(net.Conn) (netip.AddrPort, error)
}

func (c *originConn) OriginalDestination() (netip.AddrPort, error) { return c.origin(c.Conn) }

// startTransparentRedirected starts p on a loopback port whose connections report where they
// were headed.
func startTransparentRedirected(t *testing.T, p *Proxy, origin func(net.Conn) (netip.AddrPort, error)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.ServeTransparent(originListener{Listener: ln, origin: origin}) }()
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

	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	require.NoError(t, p.AddTunnel(originURL.Host))

	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
		return originAddr, nil
	})

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

// A transparent listener carries many authorities, so each request is decided on its own.
func TestTransparent_PlaintextRejectsAnUnnamedAuthority(t *testing.T) {
	reached := new(atomic.Bool)
	origin := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached.Store(true)
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()

	p, err := New(WithCA(ca))
	require.NoError(t, err)
	require.Equal(t, Reject, p.Decide(Target{Scheme: "http", Host: "127.0.0.1", Port: originURL.Port()}))

	addr := startTransparent(t, p)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: pinnedDialer(addr)}}

	resp, err := client.Get("http://" + originURL.Host + "/probe")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.False(t, reached.Load(), "a rejected authority must not be forwarded to")
}

func TestTransparent_PlaintextRelaysATunneledAuthority(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin reached")
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()

	p, err := New(WithCA(ca))
	require.NoError(t, err)
	require.NoError(t, p.AddTunnel(originURL.Host))

	// A tunneled authority stays unobserved even when it arrives as a plain request the
	// proxy had to parse to place it at all.
	observed := new(atomic.Bool)
	p.MustAddInterceptor(nil, "+{any}/+{rest}", func(c *Context) (*http.Response, error) {
		observed.Store(true)
		return c.Forward()
	})

	addr := startTransparent(t, p)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: pinnedDialer(addr)}}

	resp, err := client.Get("http://" + originURL.Host + "/probe")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "origin reached", string(body))
	assert.False(t, observed.Load(), "no handler may observe a tunneled authority")
}

func TestTransparent_PlaintextServesH2C(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin reached")
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()

	p, err := New(WithCA(ca))
	require.NoError(t, err)

	var seen, session atomic.Value
	p.MustAddInterceptor(nil, "+{any}/+{rest}", func(c *Context) (*http.Response, error) {
		seen.Store(c.Protocol())
		session.Store(c.Session().Protocol())
		return c.Forward()
	})

	addr := startTransparent(t, p)
	// A redirected client may speak HTTP/2 over plaintext, with the connection preface
	// instead of ALPN.
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}

	resp, err := client.Get("http://" + originURL.Host + "/probe")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "origin reached", string(body))
	assert.Equal(t, 2, resp.ProtoMajor)
	assert.Equal(t, HTTP2, seen.Load())
	assert.Equal(t, HTTP2, session.Load(), "the session must report the protocol the preface settled")
}

func TestTransparent_SessionReportsTheRedirect(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin reached")
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)
	tr.InsecureSkipVerify = true

	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)

	transparent := new(atomic.Bool)
	p.MustAddInterceptor(nil, "api.example.test/+{rest}", func(c *Context) (*http.Response, error) {
		transparent.Store(c.Session().Transparent())
		return c.Forward()
	})

	addr := startTransparent(t, p)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext:     pinnedDialer(addr),
		TLSClientConfig: &tls.Config{RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12},
	}}

	resp, err := client.Get("https://api.example.test/probe")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.True(t, transparent.Load(), "a redirected TLS connection is a transparent one")
}

// A lookup on a connection that was not redirected answers with the listener's own address.
// Taking it at face value would send the proxy back into its own socket.
func TestTransparent_OriginalDestinationPointingAtTheListenerIsIgnored(t *testing.T) {
	ca, _ := GenerateCA()

	p, err := New(WithCA(ca))
	require.NoError(t, err)

	var listenerAddr atomic.Value
	addr := startTransparentRedirected(t, p, func(c net.Conn) (netip.AddrPort, error) {
		listenerAddr.Store(c.LocalAddr().String())
		return addrPort(c.LocalAddr()), nil
	})

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// No server name and no usable original destination leaves nothing to place the
	// connection by.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "127.0.0.1",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	require.Error(t, tlsConn.Handshake())
	assert.Equal(t, addr, listenerAddr.Load(), "the resolver must have been consulted")
}

func TestTransparent_PacketConnAnswersOnlyForTheDatagramItRead(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()

	wrapped, err := TransparentPacketConn(pc)
	if err != nil {
		t.Skipf("transparent datagrams unavailable here: %v", err)
	}
	defer func() { _ = wrapped.Close() }()
	resolve := wrapped.(PacketOriginalDestination)

	client, err := net.Dial("udp", wrapped.LocalAddr().String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	_, err = client.Write([]byte("datagram"))
	require.NoError(t, err)

	buf := make([]byte, 64)
	require.NoError(t, wrapped.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, from, err := wrapped.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "datagram", string(buf[:n]))
	assert.Equal(t, client.LocalAddr().String(), from.String())

	// Nothing redirected this datagram, so what the platform reports for the peer that sent
	// it is the listener's own address at best. What has to hold is that any other peer is
	// answered with nothing rather than with an address that was never its own.
	other := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:1"))
	dst, err := resolve.OriginalDestination(other)
	require.NoError(t, err)
	assert.False(t, dst.IsValid())
}

// A redirected plaintext connection resolves to the address it was headed to, never to an
// authority. Deciding it at connection level would refuse it, since no entry matches the
// origin by its address, so each request is decided on its own Host header instead.
func TestTransparent_PlaintextWithOriginalDestination(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin got host=%s", r.Host)
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	originAddr, err := netip.ParseAddrPort(originURL.Host)
	require.NoError(t, err)

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)

	p := testProxy(t, WithTransport(tr))
	p.MustAddInterceptor([]string{http.MethodGet}, "api.example.test/ping", func(c *Context) (*http.Response, error) {
		return c.Forward()
	})

	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
		return originAddr, nil
	})

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: pinnedDialer(addr)},
	}

	resp, err := client.Get("http://api.example.test/ping")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "origin got host=api.example.test", string(body))

	assert.Empty(t, slices.Collect(p.Sessions()), "a connection decided per request is not reported")
}
