// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

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
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
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

func (c *originConn) CloseWrite() error { return closeWrite(c.Conn) }

func (c *originConn) Abort() { abort(c.Conn) }

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

const (
	viaRedirected   = "redirected"
	viaUnredirected = "unredirected"
	viaServeConn    = "serveconn"
)

// unroutedDestination is the destination of a redirected connection nothing dials.
var unroutedDestination = netip.MustParseAddrPort("192.0.2.1:80")

type wrapListener struct {
	net.Listener
	wrap func(net.Conn) net.Conn
}

func (l wrapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.wrap(c), nil
}

// octetConn returns at most one octet per read, as TCP may deliver them.
type octetConn struct{ net.Conn }

func (c octetConn) Read(b []byte) (int, error) { return c.Conn.Read(b[:min(len(b), 1)]) }

func asOctets(c net.Conn) net.Conn { return octetConn{c} }

// dialTransparentFront serves p on a redirected, unredirected or ServeConn front and returns a
// connection to it. The proxy reads and writes through wrap.
func dialTransparentFront(t *testing.T, front string, p *Proxy, wrap func(net.Conn) net.Conn) net.Conn {
	t.Helper()
	if front == viaServeConn {
		client, server := net.Pipe()
		go func() { _ = p.ServeConn(wrap(server)) }()
		return client
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	l := wrapListener{Listener: ln, wrap: wrap}
	switch front {
	case viaRedirected:
		go func() {
			_ = p.ServeTransparent(originListener{Listener: l, origin: func(net.Conn) (netip.AddrPort, error) {
				return unroutedDestination, nil
			}})
		}()
	case viaUnredirected:
		go func() { _ = p.ServeTransparent(l) }()
	default:
		t.Fatalf("unknown front %q", front)
	}
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	return c
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
	}, WithMethods[HTTP](http.MethodGet))

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
	}, WithMethods[HTTP](http.MethodGet))

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

func TestTransparent_ClientHelloParseReturnsTheAlert(t *testing.T) {
	hello, alert := clientHelloFromRecords(plainClientHello(t, "allowed.test"))
	require.NotNil(t, hello)
	assert.Equal(t, "allowed.test", hello.ServerName)
	assert.Zero(t, alert)

	hello, alert = clientHelloFromRecords(helloWithECH(t, []byte{0x02}))
	assert.Nil(t, hello)
	assert.Equal(t, byte(47), alert, "an undefined ECHClientHelloType")

	hello, alert = clientHelloFromRecords(helloWithECH(t, []byte{0x00}))
	assert.Nil(t, hello)
	assert.Equal(t, byte(50), alert, "an outer encrypted_client_hello cut short")

	hello, alert = clientHelloFromRecords([]byte{0x16, 0x03, 0x01, 0x00})
	assert.Nil(t, hello)
	assert.Zero(t, alert, "records cut short")
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
	assert.ErrorContains(t, tlsConn.Handshake(), "unrecognized name", "a rejected authority must not get a handshake")
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
	assert.ErrorContains(t, tlsConn.Handshake(), "missing extension")
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
	assert.ErrorContains(t, tlsConn.Handshake(), "missing extension")
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
	}, WithMethods[HTTP](http.MethodGet))

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

	sessions := slices.Collect(p.Sessions())
	require.Len(t, sessions, 1, "a connection decided on the authority of its first request is reported")
	assert.Equal(t, KindHTTP, sessions[0].Kind())
	assert.Equal(t, "api.example.test", sessions[0].Target().Host)
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

func TestTransparent_StreamEntryOnTheAuthorityWinsOverHTTPParsing(t *testing.T) {
	origin := tcpEchoOrigin(t)

	send := func(t *testing.T, p *Proxy, request string) string {
		t.Helper()
		addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
			return origin, nil
		})
		client, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		defer func() { _ = client.Close() }()
		_, err = client.Write([]byte(request))
		require.NoError(t, err)
		require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
		buf := make([]byte, len(request))
		n, _ := io.ReadFull(client, buf)
		return string(buf[:n])
	}

	t.Run("on the name", func(t *testing.T) {
		p := testProxy(t)
		p.MustAdd[TCP]("bytes.test", relayStream)
		request := "GET /secret HTTP/1.1\r\nHost: bytes.test\r\n\r\n"
		assert.Equal(t, request, send(t, p, request), "the origin must receive the request byte for byte")
	})

	t.Run("on the destination, for a request whose Host is the destination", func(t *testing.T) {
		p := testProxy(t)
		p.MustAdd[TCP](origin.String(), relayStream)
		request := "GET /secret HTTP/1.1\r\nHost: " + origin.String() + "\r\n\r\n"
		assert.Equal(t, request, send(t, p, request))
	})

	t.Run("on the destination, a request whose Host is a hostname is refused", func(t *testing.T) {
		p := testProxy(t)
		p.MustAdd[TCP](origin.String(), relayStream)
		request := "GET /secret HTTP/1.1\r\nHost: some.test\r\n\r\n"
		assert.True(t, strings.HasPrefix(send(t, p, request), "HTTP/1.1 403 "), "a request with a hostname is not admitted by an entry on an address")
	})
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

func TestTransparent_PlaintextIsDecidedOnItsFirstAuthority(t *testing.T) {
	type counters struct {
		served, streamed atomic.Int32
		servableAs       chan []Kind
	}
	setup := func(t *testing.T, streamEntry bool) (*Proxy, string, netip.AddrPort, *counters) {
		t.Helper()
		origin := h2cOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "origin got host=%s proto=%d", r.Host, r.ProtoMajor)
		}))
		originURL, err := url.Parse(origin.URL)
		require.NoError(t, err)
		originAddr, err := netip.ParseAddrPort(originURL.Host)
		require.NoError(t, err)

		tr := DefaultTransport()
		tr.DialContext = pinnedDialer(originURL.Host)
		p := testProxy(t, WithTransport(tr))

		n := &counters{servableAs: make(chan []Kind, 1)}
		p.MustAdd("api.example.test/ping", func(c *HTTPCtx) (*http.Response, error) {
			n.served.Add(1)
			select {
			case n.servableAs <- c.Session().ServableAs():
			default:
			}
			return c.Forward()
		})
		if streamEntry {
			p.MustAdd[TCP]("[0.0.0.0/0]", func(c *TCPCtx) error {
				n.streamed.Add(1)
				return c.Relay()
			})
		}
		addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
			return originAddr, nil
		})
		return p, addr, originAddr, n
	}
	body := func(t *testing.T, resp *http.Response) string {
		t.Helper()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return string(b)
	}
	h2cClient := func(addr string) *http.Client {
		return &http.Client{Timeout: 10 * time.Second, Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		}}
	}

	t.Run("HTTP/1.1 goes to the entry on its name", func(t *testing.T) {
		p, addr, _, n := setup(t, true)
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: pinnedDialer(addr)}}
		resp, err := client.Get("http://api.example.test/ping")
		require.NoError(t, err)
		assert.Equal(t, "origin got host=api.example.test proto=1", body(t, resp))
		assert.EqualValues(t, 1, n.served.Load())
		assert.Zero(t, n.streamed.Load(), "the stream entry on the address does not receive a connection routed on a hostname")

		sessions := slices.Collect(p.Sessions())
		require.Len(t, sessions, 1)
		assert.Equal(t, KindHTTP, sessions[0].Kind())
		assert.Equal(t, "api.example.test", sessions[0].Target().Host)
		assert.False(t, sessions[0].Stale())
	})

	t.Run("h2c goes to the stream entry on its destination", func(t *testing.T) {
		p, addr, originAddr, n := setup(t, true)
		resp, err := h2cClient(addr).Get("http://api.example.test/ping")
		require.NoError(t, err)
		assert.Equal(t, "origin got host=api.example.test proto=2", body(t, resp))
		assert.Zero(t, n.served.Load())
		assert.EqualValues(t, 1, n.streamed.Load(), "the preface has no authority, the destination decided")

		sessions := slices.Collect(p.Sessions())
		require.Len(t, sessions, 1)
		assert.Equal(t, KindTCP, sessions[0].Kind())
		assert.Equal(t, originAddr.Addr().String(), sessions[0].Target().Host)
	})

	t.Run("h2c with nothing on its destination is routed request by request", func(t *testing.T) {
		p, addr, _, n := setup(t, false)
		resp, err := h2cClient(addr).Get("http://api.example.test/ping")
		require.NoError(t, err)
		assert.Equal(t, "origin got host=api.example.test proto=2", body(t, resp))
		assert.EqualValues(t, 1, n.served.Load())
		assert.Equal(t, []Kind{KindHTTP, KindTCP}, <-n.servableAs, "the first bytes fixed the kinds, whatever decided the connection")
		assert.Empty(t, slices.Collect(p.Sessions()), "nothing decided the connection, so nothing reports it")
	})
}

func TestTransparent_PlaintextConnectIsRefused(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin reached")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	originAddr, err := netip.ParseAddrPort(originURL.Host)
	require.NoError(t, err)

	p := testProxy(t)
	p.MustAdd("api.example.test/probe", forwardHandler)
	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
		return originAddr, nil
	})
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	_, err = fmt.Fprint(conn, "CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode)
}

func TestTransparent_PlaintextGRPCIsDecidedOnItsDestination(t *testing.T) {
	setup := func(t *testing.T, streamEntry bool) (*http.Client, *atomic.Int32, *atomic.Int32, *atomic.Int32) {
		t.Helper()
		reached := new(atomic.Int32)
		origin := h2cOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached.Add(1)
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status")
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Grpc-Status", "0")
		}))
		originURL, err := url.Parse(origin.URL)
		require.NoError(t, err)
		originAddr, err := netip.ParseAddrPort(originURL.Host)
		require.NoError(t, err)

		p := testProxy(t)
		called, streamed := new(atomic.Int32), new(atomic.Int32)
		p.MustAdd("api.example.test/billing.v1.Billing/Charge", func(c *GRPCCtx) error {
			called.Add(1)
			return c.Fail(CodeUnavailable, "held by the proxy")
		})
		if streamEntry {
			p.MustAdd[TCP]("[0.0.0.0/0]", func(c *TCPCtx) error {
				streamed.Add(1)
				return c.Relay()
			})
		}
		addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
			return originAddr, nil
		})
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		}}
		return client, reached, called, streamed
	}
	call := func(t *testing.T, client *http.Client) (code, msg string) {
		t.Helper()
		resp := grpcDo(t, client, "http://api.example.test/billing.v1.Billing/Charge", []byte{0, 0, 0, 0, 0})
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return grpcStatus(resp)
	}

	t.Run("a stream entry on the destination takes the connection", func(t *testing.T) {
		client, reached, called, streamed := setup(t, true)
		code, _ := call(t, client)
		assert.Equal(t, "0", code, "the origin answered through the stream handler")
		assert.EqualValues(t, 1, reached.Load())
		assert.EqualValues(t, 1, streamed.Load())
		assert.Zero(t, called.Load())
	})

	t.Run("with nothing on the destination the entry on the method serves the call", func(t *testing.T) {
		client, reached, called, streamed := setup(t, false)
		code, msg := call(t, client)
		assert.Equal(t, "14", code)
		assert.Equal(t, "held by the proxy", msg)
		assert.Zero(t, reached.Load())
		assert.EqualValues(t, 1, called.Load())
		assert.Zero(t, streamed.Load())
	})
}

func TestTransparent_PlaintextAuthorityIsVerified(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin reached")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	originAddr, err := netip.ParseAddrPort(originURL.Host)
	require.NoError(t, err)

	run := func(t *testing.T, mode NameVerification, resolvesTo string) (int, string, int32, int32, int) {
		t.Helper()
		tr := DefaultTransport()
		tr.DialContext = pinnedDialer(originURL.Host)
		resolver := &fakeResolver{addrs: map[string][]netip.Addr{"api.example.test": addrsOf(resolvesTo)}}
		p := testProxy(t, WithTransport(tr), WithNameVerification(mode), WithNameResolver(resolver))

		var served, streamed atomic.Int32
		p.MustAdd("api.example.test/probe", func(c *HTTPCtx) (*http.Response, error) {
			served.Add(1)
			return c.Forward()
		})
		p.MustAdd[TCP]("[0.0.0.0/0]", func(c *TCPCtx) error {
			streamed.Add(1)
			return c.Relay()
		})
		addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
			return originAddr, nil
		})
		client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: pinnedDialer(addr), DisableKeepAlives: true}}
		resp, err := client.Get("http://api.example.test/probe")
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp.StatusCode, string(body), served.Load(), streamed.Load(), len(slices.Collect(p.Sessions()))
	}

	t.Run("confirmed under VerifyReject", func(t *testing.T) {
		status, body, served, streamed, _ := run(t, VerifyReject, "127.0.0.1")
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "origin reached", body)
		assert.EqualValues(t, 1, served)
		assert.Zero(t, streamed)
	})

	t.Run("refused under VerifyReject", func(t *testing.T) {
		status, _, served, streamed, sessions := run(t, VerifyReject, "10.0.0.1")
		assert.Equal(t, http.StatusForbidden, status)
		assert.Zero(t, served)
		assert.Zero(t, streamed, "a refused name is not handed to whatever admits the destination")
		assert.Zero(t, sessions)
	})

	t.Run("dropped under VerifyLoose", func(t *testing.T) {
		status, body, served, streamed, _ := run(t, VerifyLoose, "10.0.0.1")
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, "origin reached", body)
		assert.Zero(t, served)
		assert.EqualValues(t, 1, streamed, "the name dropped, the destination decided")
	})
}

func TestTransparent_PlaintextAuthorityPeekIsBounded(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin reached")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	originAddr, err := netip.ParseAddrPort(originURL.Host)
	require.NoError(t, err)

	setup := func(t *testing.T, opts ...ProxyOption) (net.Conn, *bufio.Reader, *atomic.Int32) {
		t.Helper()
		p := testProxy(t, opts...)
		byAddress := new(atomic.Int32)
		p.MustAdd("[0.0.0.0/0]/+{rest}", func(c *HTTPCtx) (*http.Response, error) {
			byAddress.Add(1)
			return c.Forward()
		})
		addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
			return originAddr, nil
		})
		conn, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		return conn, bufio.NewReader(conn), byAddress
	}

	t.Run("a header block past the limit", func(t *testing.T) {
		conn, br, byAddress := setup(t, WithMaxHeaderBytes(1024))
		_, err := fmt.Fprintf(conn, "GET /probe HTTP/1.1\r\n%sHost: api.example.test\r\n\r\n", strings.Repeat("X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n", 300))
		require.NoError(t, err)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusRequestHeaderFieldsTooLarge, resp.StatusCode)
		assert.Zero(t, byAddress.Load())
	})

	t.Run("a client that stalls in its headers", func(t *testing.T) {
		const timeout = 500 * time.Millisecond
		conn, br, _ := setup(t, WithReadHeaderTimeout(timeout))
		start := time.Now()
		_, err := fmt.Fprint(conn, "GET /probe HTTP/1.1\r\nX-A: a\r\n")
		require.NoError(t, err)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusRequestTimeout, resp.StatusCode)
		assert.Less(t, time.Since(start), 2*timeout-100*time.Millisecond, "one header timeout in all")
	})
}

func TestTransparent_PlaintextPortStaysTheDestinations(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin reached")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	originAddr, err := netip.ParseAddrPort(originURL.Host)
	require.NoError(t, err)

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)
	p := testProxy(t, WithTransport(tr))
	ports := make(chan string, 2)
	p.MustAdd("b.test/probe", func(c *HTTPCtx) (*http.Response, error) {
		ports <- c.Port()
		return c.Forward()
	})
	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
		return originAddr, nil
	})

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	br := bufio.NewReader(conn)
	for _, host := range []string{"b.test:8443", "b.test"} {
		_, err = fmt.Fprintf(conn, "GET /probe HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		require.NoError(t, err)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}
	assert.Equal(t, "8443", <-ports)
	assert.Equal(t, originURL.Port(), <-ports)

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, "b.test", sessions[0].Target().Host)
	assert.Equal(t, originURL.Port(), sessions[0].Target().Port)
}

func TestTransparent_StreamNothingAdmitsIsReset(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[TCP]("other.test", noopStream)
	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
		return netip.MustParseAddrPort("192.0.2.1:25"), nil
	})
	c, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Write([]byte{0x00, 0x01, 0x02, 0x03})
	require.NoError(t, err)
	assert.Equal(t, "RST", peerEnd(c, 3*time.Second))
}

func TestTransparent_SilentConnectionIsServedAsAStream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		t.Cleanup(func() { _ = c.Close() })
		_, _ = io.WriteString(c, "220 banner\r\n")
	}()
	dest := netip.MustParseAddrPort(ln.Addr().String())
	p := testProxy(t, WithSniffTimeout(300*time.Millisecond))
	p.MustAdd[TCP](ln.Addr().String(), relayStream)
	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) { return dest, nil })

	client, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	line, err := bufio.NewReader(client).ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "220 banner\r\n", line)
}

func TestTransparent_StalledClientHelloIsReset(t *testing.T) {
	p := testProxy(t, WithReadHeaderTimeout(300*time.Millisecond))
	p.MustAdd[TCP]("a.test", relayStream)
	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
		return netip.MustParseAddrPort("127.0.0.1:443"), nil
	})
	client, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer client.Close()
	// A record header announcing more than is sent.
	_, err = client.Write([]byte{0x16, 0x03, 0x01, 0x01, 0x00, 0x01})
	require.NoError(t, err)
	assert.Equal(t, "RST", peerEnd(client, 3*time.Second))
}

func TestTransparent_ServeConnReturnsErrProxyClosedAfterACut(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	running := make(chan struct{})
	p.MustAdd[TCP]("svc.test", func(c *TCPCtx) error {
		close(running)
		<-c.Context().Done()
		return c.Context().Err()
	})
	cl, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer cl.Close()
	served := make(chan error, 1)
	go func() {
		sc, aerr := cl.Accept()
		if aerr == nil {
			served <- p.ServeConn(sc)
		}
	}()
	conn, err := net.Dial("tcp", cl.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	tc := tls.Client(conn, &tls.Config{ServerName: "svc.test", RootCAs: ca.CertPool(), NextProtos: []string{"x-test"}})
	require.NoError(t, tc.Handshake())
	<-running
	require.NoError(t, p.Close())
	select {
	case err := <-served:
		require.ErrorIs(t, err, ErrProxyClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeConn did not return")
	}
}

func TestTransparent_ServeConnReturnsNilForANormalCause(t *testing.T) {
	serveConn := func(t *testing.T, p *Proxy) (net.Conn, <-chan error) {
		cl, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = cl.Close() })
		served := make(chan error, 1)
		go func() {
			if sc, aerr := cl.Accept(); aerr == nil {
				served <- p.ServeConn(sc)
			}
		}()
		conn, err := net.Dial("tcp", cl.Addr().String())
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		return conn, served
	}
	wait := func(t *testing.T, served <-chan error) error {
		select {
		case err := <-served:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("ServeConn did not return")
			return nil
		}
	}

	t.Run("session close", func(t *testing.T) {
		ca, err := GenerateCA()
		require.NoError(t, err)
		p, err := New(WithCA(ca))
		require.NoError(t, err)
		t.Cleanup(func() { _ = p.Close() })
		running := make(chan struct{})
		p.MustAdd[TCP]("svc.test", func(c *TCPCtx) error {
			close(running)
			<-c.Context().Done()
			return c.Context().Err()
		})
		conn, served := serveConn(t, p)
		tc := tls.Client(conn, &tls.Config{ServerName: "svc.test", RootCAs: ca.CertPool(), NextProtos: []string{"x-test"}})
		require.NoError(t, tc.Handshake())
		<-running
		require.NoError(t, waitForSessions(t, p, 1)[0].Close())
		require.NoError(t, wait(t, served), "ServeConn returned an error after Session.Close")
	})
	t.Run("refusal", func(t *testing.T) {
		p := testProxy(t)
		t.Cleanup(func() { _ = p.Close() })
		conn, served := serveConn(t, p)
		_, err := conn.Write([]byte{0})
		require.NoError(t, err)
		require.NoError(t, wait(t, served), "ServeConn returned an error after a refusal")
	})
}

func TestTransparent_ServeConnReportsAPeerReset(t *testing.T) {
	for name, first := range map[string][]byte{
		"before the first byte":  nil,
		"inside the ClientHello": {0x16, 0x03, 0x01, 0x01, 0x00, 0x01},
	} {
		t.Run(name, func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			p, err := New(WithCA(ca), WithSniffTimeout(2*time.Second))
			require.NoError(t, err)
			t.Cleanup(func() { _ = p.Close() })
			p.MustAdd("reset.test/", okHandler)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			client, err := net.Dial("tcp", ln.Addr().String())
			require.NoError(t, err)
			server, err := ln.Accept()
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() { done <- p.ServeConn(server) }()
			if first != nil {
				_, err = client.Write(first)
				require.NoError(t, err)
				time.Sleep(100 * time.Millisecond)
			}
			require.NoError(t, client.(*net.TCPConn).SetLinger(0))
			require.NoError(t, client.Close())
			select {
			case err := <-done:
				require.Error(t, err, "ServeConn hid the peer reset that ended its connection")
			case <-time.After(3 * time.Second):
				t.Fatal("ServeConn did not return")
			}
		})
	}
}

func TestServeConn_ReturnsTheFailureOfASessionServedAsHTTP(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run("read header timeout "+strconv.FormatBool(timeout), func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			opts := []ProxyOption{WithCA(ca)}
			if timeout {
				opts = append(opts, WithReadHeaderTimeout(300*time.Millisecond))
			}
			p, err := New(opts...)
			require.NoError(t, err)
			t.Cleanup(func() { _ = p.Close() })
			p.MustAdd("svc.test/", okHandler)
			conn, server := tcpPair(t)
			served := make(chan error, 1)
			go func() { served <- p.ServeConn(server) }()
			tc := tls.Client(conn, &tls.Config{ServerName: "svc.test", RootCAs: poolOf(ca), NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
			require.NoError(t, tc.Handshake())
			if timeout {
				_, err = tc.Write([]byte("GET / HTTP/1.1\r\n"))
				require.NoError(t, err)
			} else {
				_, err = tc.Write([]byte("GET / HTTP/1.1\r\nHost: svc.test\r\n\r\n"))
				require.NoError(t, err)
				resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.NoError(t, conn.SetLinger(0))
				require.NoError(t, conn.Close())
			}
			select {
			case err := <-served:
				if timeout {
					require.True(t, isTimeout(err), "%v", err)
				} else {
					require.ErrorIs(t, err, syscall.ECONNRESET)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("ServeConn did not return")
			}
		})
	}
}

func TestServeConn_ResetDuringTheNormalEndOfADrainIsNoFailure(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	p.MustAdd("svc.test/", okHandler)
	conn, server := tcpPair(t)
	served := make(chan error, 1)
	go func() { served <- p.ServeConn(server) }()
	tc := tls.Client(conn, &tls.Config{ServerName: "svc.test", RootCAs: poolOf(ca), NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	require.NoError(t, tc.Handshake())
	time.Sleep(100 * time.Millisecond)
	shut := make(chan error, 1)
	go func() { shut <- p.Shutdown(context.Background()) }()
	// The drain ends the connection, which began no request, normally, and the client resets
	// it during the read that follows its close_notify.
	_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = tc.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
	require.NoError(t, conn.SetLinger(0))
	require.NoError(t, conn.Close())
	select {
	case err := <-served:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeConn did not return")
	}
	require.NoError(t, <-shut)
}
