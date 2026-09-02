// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
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
	p.MustAdd("api.example.test/v1/charges", func(c *HTTPCtx) (*http.Response, error) {
		seenTarget = Target{Scheme: c.Scheme(), Host: c.Host(), Port: c.Port()}
		return c.Forward()
	}, WithMethods(http.MethodGet))

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

func TestTransparent_TLSStreamIsPlacedByItsServerName(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunneled")
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	// The authority comes from the ClientHello, so it is the name the client asked for,
	// not the address the upstream transport is pinned to.
	p.MustAdd[TCP]("example.com", relayStream)

	addr := startTransparent(t, p)

	// Terminated like everything else, so the certificate the client checks is the proxy's.
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: pinnedDialer(addr),
			TLSClientConfig: &tls.Config{
				RootCAs:    ca.CertPool(),
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	resp, err := client.Get("https://example.com/")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "tunneled", string(body))

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, KindTCP, sessions[0].Kind())
	assert.Zero(t, sessions[0].Protocol(), "a stream carries no HTTP version")
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
	p.MustAdd("api.example.test/ping", func(c *HTTPCtx) (*http.Response, error) {
		seen = Target{Scheme: c.Scheme(), Host: c.Host(), Port: c.Port()}
		return c.Forward()
	}, WithMethods(http.MethodGet))

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

	p.MustAdd("peek.example.test/", func(c *HTTPCtx) (*http.Response, error) {
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
	p.MustAdd[TCP](originURL.Host, relayStream)

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
	require.Equal(t, false, p.Admits(Target{Scheme: "http", Host: "127.0.0.1", Port: originURL.Port()}, KindHTTP))

	addr := startTransparent(t, p)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: pinnedDialer(addr)}}

	resp, err := client.Get("http://" + originURL.Host + "/probe")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.False(t, reached.Load(), "a rejected authority must not be forwarded to")
}

// A redirected plaintext connection the platform reports no destination for has no authority
// of its own: each request names one, and each is routed on its own. Nothing can serve it as a
// stream, since by the time an authority is known the bytes have been parsed.
func TestTransparent_PlaintextWithoutADestinationRoutesPerRequest(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin reached")
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()

	p, err := New(WithCA(ca))
	require.NoError(t, err)

	observed := new(atomic.Bool)
	p.MustAdd("[0.0.0.0/0]/+{rest}", func(c *HTTPCtx) (*http.Response, error) {
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
	assert.True(t, observed.Load(), "the request is routed on the authority its Host names")

	// An authority nothing names is refused on the request rather than on the connection.
	resp2, err := client.Get("http://never-named.test/probe")
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
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
	// The redirected target is an address, which the name wildcard does not cover.
	p.MustAdd("[0.0.0.0/0]/+{rest}", func(c *HTTPCtx) (*http.Response, error) {
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
	p.MustAdd("api.example.test/+{rest}", func(c *HTTPCtx) (*http.Response, error) {
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
	p.MustAdd("api.example.test/ping", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	}, WithMethods(http.MethodGet))

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

// tcpEchoOrigin starts a TCP echo server and returns its address.
func tcpEchoOrigin(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	addr, err := netip.ParseAddrPort(ln.Addr().String())
	require.NoError(t, err)
	return addr
}

func TestTransparent_RawTCPTunnelByDestination(t *testing.T) {
	origin := tcpEchoOrigin(t)

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd[TCP](origin.String(), relayStream)

	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
		return origin, nil
	})

	client, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	payload := []byte{0x00, 0x2a, 'r', 'a', 'w', '-', 'd', 'n', 's'}
	_, err = client.Write(payload)
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n])

	sessions := waitForSessions(t, p, 1)
	sess := sessions[0]
	assert.Equal(t, KindTCP, sess.Kind())
	assert.Equal(t, KindTCP, sess.Kind())
	assert.Equal(t, origin.Addr().String(), sess.Target().Host)
	assert.Equal(t, fmt.Sprint(origin.Port()), sess.Target().Port)
	assert.Equal(t, origin, sess.Upstream())
	assert.True(t, sess.Transparent())
	assert.Nil(t, sess.ClientHello())

	require.NoError(t, sess.Close())
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, err = client.Read(buf)
	require.Error(t, err, "closing the session cuts the connection")
}

// A connection that is neither TLS nor claimed by a tunnel keeps today's path: parsed as a
// plaintext request, which these bytes are not, so it is closed.
func TestTransparent_RawTCPRejectedWithoutTunnel(t *testing.T) {
	origin := tcpEchoOrigin(t)

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
		return origin, nil
	})

	client, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	_, err = client.Write([]byte{0x00, 0x2a, 'n', 'o', 'p', 'e'})
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
	buf := make([]byte, 512)
	for {
		if _, err = client.Read(buf); err != nil {
			break
		}
	}
	require.Error(t, err)
	assert.Empty(t, slices.Collect(p.Sessions()))
}

// A tunnel entry says to leave the connection alone, so bytes that would parse as HTTP go
// through untouched rather than being intercepted on their Host header.
func TestTransparent_StreamEntryWinsOverHTTPParsing(t *testing.T) {
	origin := tcpEchoOrigin(t)

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd[TCP](origin.String(), relayStream)

	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
		return origin, nil
	})

	client, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	request := "GET /secret HTTP/1.1\r\nHost: never-consulted.test\r\n\r\n"
	_, err = client.Write([]byte(request))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	buf := make([]byte, len(request))
	_, err = io.ReadFull(client, buf)
	require.NoError(t, err)
	assert.Equal(t, request, string(buf), "the origin must receive the request byte for byte")
}

func TestDivertedOrigin(t *testing.T) {
	ap := netip.MustParseAddrPort
	tests := []struct {
		name     string
		local    netip.AddrPort
		listener netip.AddrPort
		want     netip.AddrPort
		diverted bool
	}{
		{"another port settles it", ap("203.0.113.9:5301"), ap("0.0.0.0:7778"), ap("203.0.113.9:5301"), true},
		{"listener port on a wildcard bind reads as direct", ap("127.0.0.1:7778"), ap("0.0.0.0:7778"), netip.AddrPort{}, false},
		{"the listener address itself is direct", ap("10.0.0.1:7778"), ap("10.0.0.1:7778"), netip.AddrPort{}, false},
		{"listener port on a specific bind still discriminates", ap("203.0.113.9:7778"), ap("10.0.0.1:7778"), ap("203.0.113.9:7778"), true},
		{"a mapped local address is unmapped", ap("[::ffff:203.0.113.9]:5301"), ap("0.0.0.0:7778"), ap("203.0.113.9:5301"), true},
		{"invalid local", netip.AddrPort{}, ap("0.0.0.0:7778"), netip.AddrPort{}, false},
		{"invalid listener", ap("203.0.113.9:5301"), netip.AddrPort{}, netip.AddrPort{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, diverted := divertedOrigin(tc.local, tc.listener)
			assert.Equal(t, tc.diverted, diverted)
			assert.Equal(t, tc.want, got)
		})
	}
}

// divertedListener stands in for a TPROXY diverted TCP listener: the conntrack lookup has
// nothing to answer and the accepted socket reports the destination itself.
type divertedListener struct {
	net.Listener
	origin netip.AddrPort
}

func (l divertedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &divertedConn{Conn: c, origin: l.origin}, nil
}

type divertedConn struct {
	net.Conn
	origin netip.AddrPort
}

func (c *divertedConn) OriginalDestination() (netip.AddrPort, error) {
	return netip.AddrPort{}, fmt.Errorf("no conntrack entry")
}

func (c *divertedConn) divertedTo() (netip.AddrPort, bool) { return c.origin, true }

func TestTransparent_TProxyTCPPlacesByTheSocketAddress(t *testing.T) {
	origin := tcpEchoOrigin(t)

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd[TCP](origin.String(), relayStream)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.ServeTransparent(divertedListener{Listener: ln, origin: origin}) }()
	t.Cleanup(func() { _ = p.Close() })

	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	payload := []byte{0x00, 0x2a, 'v', 'i', 'a', '-', 't', 'p', 'r', 'o', 'x', 'y'}
	_, err = client.Write(payload)
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n])

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, KindTCP, sessions[0].Kind())
	assert.Equal(t, KindTCP, sessions[0].Kind())
	assert.Equal(t, origin, sessions[0].Upstream())
}

// A stream entry naming a destination serves it even when a request entry admits the same
// destination for HTTP. What the connection is comes from its bytes, and the kinds are tried
// most refined first against the destination, not one against the other by hand.
func TestTransparent_StreamAndHTTPOnOneDestination(t *testing.T) {
	origin := tcpEchoOrigin(t)

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	// Portless, so it admits every port of that address, including the stream entry's.
	p.MustAdd(origin.Addr().String()+"/*{any}", noopHandler)
	p.MustAdd[TCP](origin.String(), relayStream)

	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
		return origin, nil
	})

	client, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	payload := []byte{0x00, 0x2a, 'n', 'o', 't', '-', 'h', 't', 't', 'p'}
	_, err = client.Write(payload)
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n], "the stream entry serves it, HTTP being admitted changes nothing")

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, KindTCP, sessions[0].Kind())
}

type countingListener struct {
	net.Listener
	accepted atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return c, err
}

// Under plaintext no certificate ties a pooled connection to its name, so the pool is keyed on
// the destination. A client headed to one origin never uses the connection another client
// opened to a different one, and two clients headed to the same origin share it.
func TestTransparent_PlainPoolIsKeyedOnTheDestination(t *testing.T) {
	var toA countingListener
	a, b := twoOriginsOnOnePort(t, func(ln net.Listener, id string) {
		if id == "A" {
			toA.Listener = ln
			ln = &toA
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, id)
		})}
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { _ = srv.Close() })
	})

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd("example.test/", forwardHandler)

	var headedTo atomic.Value
	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
		return headedTo.Load().(netip.AddrPort), nil
	})
	get := func(origin netip.AddrPort) string {
		headedTo.Store(origin)
		conn, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		_, err = fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
		require.NoError(t, err)
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return string(body)
	}

	assert.Equal(t, "B", get(b))
	assert.Equal(t, "A", get(a), "the client was headed to A")
	// The first connection to A goes back to its pool once its response is done, which the
	// transport does just after the proxy has written the body.
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, "A", get(a))
	assert.EqualValues(t, 1, toA.accepted.Load(), "two clients headed to A share one upstream connection")
}
