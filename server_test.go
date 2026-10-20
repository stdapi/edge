// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/iotest"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// startQUICFront serves p as an explicit proxy over HTTP/3 on a loopback UDP port, with a
// certificate for 127.0.0.1 minted by ca, and returns the address and the channel ServeQUIC
// reports on.
func startQUICFront(t *testing.T, p *Proxy, ca *CA) (netip.AddrPort, <-chan error) {
	t.Helper()
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		served <- p.ServeQUIC(pc, *cert)
		close(done)
	}()
	t.Cleanup(func() {
		_ = p.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("ServeQUIC did not return after Close")
		}
		select {
		case err := <-served:
			assert.True(t, errors.Is(err, ErrProxyClosed), "%v", err)
		default:
		}
		_ = pc.Close()
	})
	return netip.MustParseAddrPort(pc.LocalAddr().String()), served
}

// loopbackUDP opens the client socket of a QUIC test. A dual-stack socket, what quic.DialAddr
// opens, loses datagrams on macOS loopback under load and the handshake waits out its timeout.
func loopbackUDP() (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

// dialQUICFront opens a QUIC connection to the proxy front at addr, trusting ca.
func dialQUICFront(t *testing.T, addr netip.AddrPort, ca *CA) *quic.Conn {
	t.Helper()
	pc, err := loopbackUDP()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(addr), &tls.Config{
		RootCAs:    poolOf(ca),
		ServerName: "127.0.0.1",
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		_ = pc.Close()
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.CloseWithError(0, "")
		_ = pc.Close()
	})
	return conn
}

// streamConn adapts an HTTP/3 request stream to a net.Conn, for a TLS client to run inside a
// CONNECT carried on it.
type streamConn struct {
	*http3.RequestStream
}

func (streamConn) LocalAddr() net.Addr  { return emptyAddr{} }
func (streamConn) RemoteAddr() net.Addr { return emptyAddr{} }

func TestServeQUIC_AbsoluteRequest(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin proto=%s host=%s path=%s", r.Proto, r.Host, r.URL.Path)
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)

	var seen atomic.Uint32
	p.MustAdd(originHost(originURL)+"/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		seen.Store(uint32(c.Protocol()))
		return c.Forward()
	})
	front, served := startQUICFront(t, p, ca)

	h3 := &http3.Transport{
		Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			return dialQUICFront(t, front, ca), nil
		},
	}
	defer func() { _ = h3.Close() }()

	req, err := http.NewRequest(http.MethodGet, origin.URL+"/hello", nil)
	require.NoError(t, err)
	resp, err := h3.RoundTrip(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "origin proto=HTTP/1.1 host="+originURL.Host+" path=/hello", string(body))
	assert.Equal(t, HTTP3, Protocol(seen.Load()), "the request reached the proxy over HTTP/3")
	assert.Empty(t, waitForSessions(t, p, 0), "a front connection is addressed to the proxy itself")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, p.Shutdown(ctx))
	select {
	case err := <-served:
		assert.True(t, errors.Is(err, ErrProxyClosed), "%v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeQUIC did not return after Shutdown")
	}
}

func TestServeQUIC_ConnectStream(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin host=%s", r.Host)
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd(originHost(originURL)+"/*{any}", forwardHandler)
	front, _ := startQUICFront(t, p, ca)

	h3 := &http3.Transport{}
	defer func() { _ = h3.Close() }()
	cc := h3.NewClientConn(dialQUICFront(t, front, ca))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rstr, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodConnect, "https://"+originURL.Host, nil)
	require.NoError(t, err)
	require.NoError(t, rstr.SendRequestHeader(req))
	resp, err := rstr.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "the proxy accepts the CONNECT stream")

	tunnel := tls.Client(streamConn{rstr}, &tls.Config{
		RootCAs:    ca.CertPool(),
		ServerName: originURL.Hostname(),
		MinVersion: tls.VersionTLS12,
	})
	inner := http.Client{Transport: &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return tunnel, nil },
	}}
	got, err := inner.Get(origin.URL + "/foo")
	require.NoError(t, err)
	body, _ := io.ReadAll(got.Body)
	_ = got.Body.Close()
	assert.Equal(t, "origin host="+originURL.Host, string(body))

	sess := waitForSessions(t, p, 1)[0]
	assert.Equal(t, KindHTTP, sess.Kind())
	assert.Equal(t, HTTP11, sess.Protocol(), "the tunnel carries HTTP/1.1 inside, whatever the stream that opened it")
	assert.Equal(t, originURL.Hostname(), sess.Target().Host)
	assert.Equal(t, netip.MustParseAddrPort(originURL.Host), sess.Upstream())
	_ = tunnel.Close()
	waitForSessions(t, p, 0)
}

func TestProxyTarget_PortIsCanonical(t *testing.T) {
	u, err := url.Parse("http://example.test:0080/x")
	require.NoError(t, err)
	target, err := proxyTarget(&http.Request{URL: u, Host: u.Host, ProtoMajor: 1}, "")
	require.NoError(t, err)
	assert.Equal(t, "80", target.Port)

	target, err = proxyTarget(&http.Request{URL: &url.URL{Path: "/x"}, Host: "example.test:08080", ProtoMajor: 2}, "http")
	require.NoError(t, err)
	assert.Equal(t, "8080", target.Port)

	_, err = proxyTarget(&http.Request{URL: &url.URL{Path: "/x"}, Host: "example.test:70000", ProtoMajor: 2}, "http")
	require.Error(t, err)
}

func TestProxyTarget_RootDotIsDropped(t *testing.T) {
	u, err := url.Parse("http://example.test./x")
	require.NoError(t, err)
	target, err := proxyTarget(&http.Request{URL: u, Host: u.Host, ProtoMajor: 1}, "")
	require.NoError(t, err)
	assert.Equal(t, "example.test", target.Host)
	assert.Equal(t, "example.test.", u.Host)

	target, err = proxyTarget(&http.Request{URL: &url.URL{Path: "/x"}, Host: "127.0.0.1.:8443", ProtoMajor: 2}, "https")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", target.Host)
}

func TestProxyTarget_MalformedAuthorityIsRefused(t *testing.T) {
	_, err := proxyTarget(&http.Request{URL: &url.URL{Path: "/x"}, Host: "origin.test:80:80", ProtoMajor: 2}, "http")
	require.Error(t, err)
	_, err = proxyTarget(&http.Request{URL: &url.URL{Scheme: "http", Host: "[origin.test]", Path: "/x"}, ProtoMajor: 1}, "")
	require.Error(t, err)
}

func TestValidRequestTarget(t *testing.T) {
	for _, tc := range []struct {
		method, target string
		want           bool
	}{
		{http.MethodGet, "/x", true},
		{http.MethodGet, "http://origin.test/x", true},
		{http.MethodGet, "HTTPS://origin.test", true},
		{http.MethodOptions, "*", true},
		{http.MethodConnect, "origin.test:443", true},
		{http.MethodGet, "*", false},
		{http.MethodGet, "origin.test:80", false},
		{http.MethodGet, "ftp://origin.test/x", false},
		{http.MethodGet, "http:///x", false},
		{http.MethodGet, "http:x", false},
	} {
		r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(tc.method + " " + tc.target + " HTTP/1.1\r\nHost: origin.test\r\n\r\n")))
		require.NoError(t, err, tc.target)
		assert.Equal(t, tc.want, validRequestTarget(r), "%s %s", tc.method, tc.target)
	}
}

func TestLifecycle_ShutdownStopsAccepting(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd(originHost(originURL)+"/*{any}", forwardHandler)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	served := make(chan error, 1)
	go func() { served <- p.Serve(ln) }()

	addr := ln.Addr().String()
	client := proxyClient(addr, ca.CertPool())

	resp, err := client.Get(origin.URL + "/")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, "ok", string(body))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, p.Shutdown(ctx))

	select {
	case err := <-served:
		assert.ErrorIs(t, err, ErrProxyClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}

	_, err = net.DialTimeout("tcp", addr, time.Second)
	assert.Error(t, err, "the listener must be closed")

	// Serving again after a shutdown is refused rather than silently starting a second life.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln2.Close() }()
	assert.ErrorIs(t, p.Serve(ln2), ErrProxyClosed)
}

func TestLifecycle_RejectOnExplicitProxy(t *testing.T) {
	ca, _ := GenerateCA()
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	// Nothing names this authority, so it is refused: rejection is the default, not an authority entry.

	addr := startProxy(t, p)
	client := proxyClient(addr, ca.CertPool())

	t.Run("connect", func(t *testing.T) {
		_, err := client.Get("https://blocked.example.test/")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Forbidden", "a rejected CONNECT must be refused, not tunneled")
	})

	t.Run("absolute target", func(t *testing.T) {
		resp, err := client.Get("http://blocked.example.test/")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

func TestLifecycle_OriginFormRequestIsRefused(t *testing.T) {
	ca, _ := GenerateCA()
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	addr := startProxy(t, p)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// A client that was never configured to use a proxy sends an origin-form target. There
	// is no authority in it to proxy to.
	_, err = fmt.Fprint(conn, "GET /v1/charges HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusText(http.StatusBadRequest)+"\n", string(body), "the client learns the status and nothing else")
}

func TestLifecycle_AmbiguousLengthIsNormalized(t *testing.T) {
	originSeen := new(recorder)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originSeen.add(r.Method + " " + r.URL.Path)
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	proxySeen := new(recorder)
	p.MustAdd(originHost(originURL)+"/+{any}", func(c *HTTPCtx) (*http.Response, error) {
		proxySeen.add(c.Method() + " " + c.RoutingPath())
		return c.Forward()
	})
	p.MustAdd(originHost(originURL)+"/", func(c *HTTPCtx) (*http.Response, error) {
		proxySeen.add(c.Method() + " " + c.RoutingPath())
		return c.Forward()
	})

	addr := startProxy(t, p)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	smuggled := "POST http://" + originURL.Host + "/ HTTP/1.1\r\n" +
		"Host: " + originURL.Host + "\r\n" +
		"Content-Length: 6\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"0\r\n\r\n" +
		"GET http://" + originURL.Host + "/smuggled HTTP/1.1\r\n" +
		"Host: " + originURL.Host + "\r\n\r\n"

	_, err = conn.Write([]byte(smuggled))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	br := bufio.NewReader(conn)
	for range 2 {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			break
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	// The trailing bytes are a second pipelined request, not payload the origin will read as
	// part of the first. Whatever reached the origin went through a handler first.
	assert.Equal(t, proxySeen.all(), originSeen.all(),
		"the origin must have seen exactly the requests the proxy routed")
	assert.NotContains(t, strings.Join(originSeen.all(), " "), "POST /smuggled",
		"the framing must not have been resolved differently on the two sides")
}

func TestLifecycle_NoCASevesWhatNeedsNoCertificate(t *testing.T) {
	p, err := New()
	require.NoError(t, err)
	require.Nil(t, p.cfg.ca)

	_, err = p.Add[TCP]("plain.test:25", relayStream)
	require.NoError(t, err)
	_, err = p.Add[UDP]("[0.0.0.0/0]:53", func(*DatagramCtx) error { return nil })
	require.NoError(t, err)

	_, err = p.Add("api.test/v1", noopHandler)
	require.ErrorIs(t, err, ErrNoCertificateAuthority)
	_, err = p.Add[QUIC]("api.test:443", func(*QUICCtx) error { return nil })
	require.ErrorIs(t, err, ErrNoCertificateAuthority)
}

func TestLifecycle_ShutdownClosesTheTransparentListener(t *testing.T) {
	p := testProxy(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()

	served := make(chan error, 1)
	go func() { served <- p.ServeTransparent(ln) }()

	// Wait on the registration itself. A successful dial would only prove the listen backlog
	// exists, which it does before ServeTransparent runs at all.
	require.Eventually(t, func() bool {
		p.srv.mu.Lock()
		defer p.srv.mu.Unlock()
		return len(p.srv.listeners) == 1
	}, 3*time.Second, 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, p.Shutdown(ctx))

	select {
	case err := <-served:
		assert.ErrorIs(t, err, ErrProxyClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeTransparent did not return after Shutdown")
	}

	_, err = net.DialTimeout("tcp", addr, time.Second)
	assert.Error(t, err, "the listener must be closed")
}

// blockingHandler signals that a request reached it, then holds it until release closes.
func blockingHandler(started chan<- struct{}, release <-chan struct{}) HTTP {
	return func(c *HTTPCtx) (*http.Response, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return Text(http.StatusOK, "drained over "+c.Protocol().String()), nil
	}
}

type drainResult struct {
	body string
	err  error
}

// assertShutdownDrains runs get in the background, waits until its request is blocked inside
// the handler, begins a graceful Shutdown, checks that it neither returns early nor cuts the
// request, then releases the handler and returns the body the client got.
func assertShutdownDrains(t *testing.T, p *Proxy, started <-chan struct{}, release chan<- struct{}, get func() (string, error)) string {
	t.Helper()

	got := make(chan drainResult, 1)
	go func() {
		body, err := get()
		got <- drainResult{body: body, err: err}
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the handler")
	}

	shutdownErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		shutdownErr <- p.Shutdown(ctx)
	}()

	select {
	case err := <-shutdownErr:
		t.Fatalf("Shutdown returned while a request was in flight: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)

	var r drainResult
	select {
	case r = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the in-flight request never completed")
	}
	require.NoError(t, r.err, "a graceful shutdown must not cut a request in flight")

	select {
	case err := <-shutdownErr:
		require.NoError(t, err, "a drain finished before the deadline reports no error")
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after the drain")
	}
	return r.body
}

func getBody(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func TestLifecycle_ShutdownDrainsInterceptedHTTP1(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	p.MustAdd("example.test/", blockingHandler(started, release))

	addr := startProxy(t, p)
	client := proxyClient(addr, ca.CertPool())

	body := assertShutdownDrains(t, p, started, release, func() (string, error) {
		return getBody(client, "https://example.test/")
	})
	assert.Equal(t, "drained over HTTP/1.1", body)
}

func TestLifecycle_ShutdownDrainsInterceptedHTTP2(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	p.MustAdd("example.test/", blockingHandler(started, release))

	addr := startProxy(t, p)
	client := h2Client(addr, ca.CertPool())

	body := assertShutdownDrains(t, p, started, release, func() (string, error) {
		return getBody(client, "https://example.test/")
	})
	assert.Equal(t, "drained over HTTP/2.0", body)
}

func TestLifecycle_ShutdownSendsGoAwayOnAnInterceptedHTTP2Connection(t *testing.T) {
	p, ca := newTLSProxy(t)
	conn := connectRaw(t, startProxy(t, p), tlsName+":443")
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	tc := tls.Client(conn, &tls.Config{ServerName: tlsName, RootCAs: ca.CertPool(), NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	require.NoError(t, tc.Handshake())
	_, err := io.WriteString(tc, http2.ClientPreface)
	require.NoError(t, err)
	fr := http2.NewFramer(tc, tc)
	require.NoError(t, fr.WriteSettings())
	f, err := fr.ReadFrame()
	require.NoError(t, err)
	require.IsType(t, &http2.SettingsFrame{}, f)

	go func() { _ = p.Shutdown(t.Context()) }()
	for {
		f, err := fr.ReadFrame()
		require.NoError(t, err, "the connection ended without a GOAWAY")
		if g, ok := f.(*http2.GoAwayFrame); ok {
			assert.Equal(t, http2.ErrCodeNo, g.ErrCode)
			return
		}
	}
}

func TestLifecycle_ShutdownDrainsInterceptedHTTP3(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	p.MustAdd(h3Authority+"/", blockingHandler(started, release))

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- p.ServeTransparentUDP(pc) }()
	t.Cleanup(func() { _ = p.Close() })

	proxyAddr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	require.NoError(t, err)

	// dialQUICTo carries a deliberately short idle timeout; a request parked in the handler
	// needs one that outlives the drain.
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: poolOf(ca), MinVersion: tls.VersionTLS13},
		QUICConfig:      &quic.Config{MaxIdleTimeout: 10 * time.Second},
		Dial: func(ctx context.Context, _ string, cfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			udp, err := loopbackUDP()
			if err != nil {
				return nil, err
			}
			conn, err := quic.Dial(ctx, udp, net.UDPAddrFromAddrPort(proxyAddr), cfg, qcfg)
			if err != nil {
				_ = udp.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	defer func() { _ = tr.Close() }()

	body := assertShutdownDrains(t, p, started, release, func() (string, error) {
		req, err := http.NewRequest(http.MethodGet,
			fmt.Sprintf("https://%s:%d/", h3Authority, proxyAddr.Port()), nil)
		if err != nil {
			return "", err
		}
		resp, err := tr.RoundTrip(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	})
	assert.Equal(t, "drained over HTTP/3.0", body)

	select {
	case err := <-served:
		assert.True(t, errors.Is(err, ErrProxyClosed), "%v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeTransparentUDP did not return after Shutdown")
	}
}

func TestLifecycle_ShutdownStopsQUIC(t *testing.T) {
	p := testProxy(t)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- p.ServeTransparentUDP(pc) }()

	require.Eventually(t, func() bool {
		p.srv.mu.Lock()
		defer p.srv.mu.Unlock()
		return len(p.srv.quics) == 1
	}, 3*time.Second, 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, p.Shutdown(ctx))

	select {
	case err := <-served:
		assert.True(t, errors.Is(err, ErrProxyClosed), "%v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeTransparentUDP did not return after Shutdown")
	}

	pc2, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = pc2.Close() }()
	err = p.ServeTransparentUDP(pc2)
	assert.True(t, errors.Is(err, ErrProxyClosed), "%v", err)
	_, err = pc2.WriteTo([]byte("x"), pc2.LocalAddr())
	assert.ErrorIs(t, err, net.ErrClosed, "a refused ServeTransparentUDP closes pc")
}

func TestLifecycle_ShutdownDeadlineBoundsAStuckHandler(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	p.MustAdd("example.test/", blockingHandler(started, release))

	addr := startProxy(t, p)
	client := proxyClient(addr, ca.CertPool())

	got := make(chan error, 1)
	go func() {
		_, gerr := getBody(client, "https://example.test/")
		got <- gerr
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the handler")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = p.Shutdown(ctx)
	elapsed := time.Since(start)

	assert.True(t, errors.Is(err, context.DeadlineExceeded), "%v", err)
	assert.Less(t, elapsed, 3*time.Second, "the deadline must bound Shutdown, not the handler")

	select {
	case cerr := <-got:
		assert.Error(t, cerr, "the request must have been cut at the deadline")
	case <-time.After(5 * time.Second):
		t.Fatal("the client request never returned after the cut")
	}
	close(release)
}

func TestLifecycle_ShutdownDeadlineBoundsAStuckHTTP3Handler(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	p.MustAdd(h3Authority+"/", blockingHandler(started, release))

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- p.ServeTransparentUDP(pc) }()
	t.Cleanup(func() { _ = p.Close() })
	// Registered after Close, so the handler is released before Close waits for it.
	releaseHandler := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseHandler)

	proxyAddr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	require.NoError(t, err)

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: poolOf(ca), MinVersion: tls.VersionTLS13},
		QUICConfig:      &quic.Config{MaxIdleTimeout: 10 * time.Second},
		Dial: func(ctx context.Context, _ string, cfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			udp, err := loopbackUDP()
			if err != nil {
				return nil, err
			}
			conn, err := quic.Dial(ctx, udp, net.UDPAddrFromAddrPort(proxyAddr), cfg, qcfg)
			if err != nil {
				_ = udp.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	defer func() { _ = tr.Close() }()

	got := make(chan error, 1)
	go func() {
		req, rerr := http.NewRequest(http.MethodGet,
			fmt.Sprintf("https://%s:%d/", h3Authority, proxyAddr.Port()), nil)
		if rerr != nil {
			got <- rerr
			return
		}
		resp, rerr := tr.RoundTrip(req)
		if rerr == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		got <- rerr
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the handler")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = p.Shutdown(ctx)
	elapsed := time.Since(start)

	assert.True(t, errors.Is(err, context.DeadlineExceeded), "%v", err)
	assert.Less(t, elapsed, 3*time.Second, "the deadline must bound Shutdown, not the handler")
	select {
	case err := <-served:
		assert.True(t, errors.Is(err, ErrProxyClosed), "%v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeTransparentUDP did not return after the deadline")
	}

	// Releasing the handler lets everything the deadline left behind unwind.
	releaseHandler()
	select {
	case <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("the client request never returned after the release")
	}
}

func TestLifecycle_ShutdownDrainsTheHTTP3Front(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	p.MustAdd(h3Authority+"/", blockingHandler(started, release))
	front, served := startQUICFront(t, p, ca)
	// Registered after the front, so the handler is released before Close waits on it.
	releaseHandler := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseHandler)

	conn := dialQUICFront(t, front, ca)
	tr := &http3.Transport{}
	defer func() { _ = tr.Close() }()
	cc := tr.NewClientConn(conn)

	got := make(chan drainResult, 1)
	go func() {
		req, rerr := http.NewRequest(http.MethodGet, "https://"+h3Authority+"/", nil)
		if rerr != nil {
			got <- drainResult{err: rerr}
			return
		}
		resp, rerr := cc.RoundTrip(req)
		if rerr != nil {
			got <- drainResult{err: rerr}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, rerr := io.ReadAll(resp.Body)
		got <- drainResult{body: string(b), err: rerr}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the handler")
	}

	shutdownErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		shutdownErr <- p.Shutdown(ctx)
	}()
	select {
	case err := <-shutdownErr:
		t.Fatalf("Shutdown returned while a request was in flight: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	pc, err := loopbackUDP()
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(front), &tls.Config{
		RootCAs:    poolOf(ca),
		ServerName: "127.0.0.1",
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{HandshakeIdleTimeout: 500 * time.Millisecond})
	require.Error(t, err, "a handshake during the drain is not accepted")
	select {
	case <-served:
		t.Fatal("ServeQUIC returned before Shutdown did")
	default:
	}

	releaseHandler()
	var r drainResult
	select {
	case r = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the in-flight request never completed")
	}
	require.NoError(t, r.err, "a graceful shutdown must not cut a request in flight")
	assert.Equal(t, "drained over HTTP/3.0", r.body)
	select {
	case err := <-shutdownErr:
		require.NoError(t, err, "a drain finished before the deadline reports no error")
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after the drain")
	}
	select {
	case err := <-served:
		assert.True(t, errors.Is(err, ErrProxyClosed), "%v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeQUIC did not return after Shutdown")
	}
}

// lateCtx is a context whose cancellation reaches the contexts derived from it only once
// propagate is called.
type lateCtx struct {
	context.Context
	done       chan struct{}
	registered chan struct{}
	funcs      []func()
	mu         sync.Mutex
}

func newLateCtx() *lateCtx {
	return &lateCtx{Context: context.Background(), done: make(chan struct{}), registered: make(chan struct{}, 1)}
}

func (c *lateCtx) Done() <-chan struct{} { return c.done }

func (c *lateCtx) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func (c *lateCtx) AfterFunc(f func()) func() bool {
	c.mu.Lock()
	c.funcs = append(c.funcs, f)
	c.mu.Unlock()
	select {
	case c.registered <- struct{}{}:
	default:
	}
	return func() bool { return true }
}

func (c *lateCtx) propagate() {
	c.mu.Lock()
	funcs := c.funcs
	c.mu.Unlock()
	for _, f := range funcs {
		f()
	}
}

func TestLifecycle_ShutdownDeadlineCutsWhenTheCancellationLags(t *testing.T) {
	p, _, resp := openH2Connect(t, sinkOrigin(t))

	ctx := newLateCtx()
	shutdown := make(chan error, 1)
	go func() { shutdown <- p.Shutdown(ctx) }()
	select {
	case <-ctx.registered:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown never watched its context")
	}
	close(ctx.done)
	select {
	case err := <-shutdown:
		assert.True(t, errors.Is(err, context.DeadlineExceeded), "%v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after the deadline")
	}
	ctx.propagate()
	assertStreamReset(t, resp)
}

func TestLifecycle_ShutdownDeadlineCutsTheHTTP3Front(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	p.MustAdd(h3Authority+"/", blockingHandler(started, release))
	front, served := startQUICFront(t, p, ca)
	// Registered after the front, so the handler is released before Close waits on it.
	releaseHandler := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseHandler)

	conn := dialQUICFront(t, front, ca)
	tr := &http3.Transport{}
	defer func() { _ = tr.Close() }()
	cc := tr.NewClientConn(conn)

	got := make(chan error, 1)
	go func() {
		req, rerr := http.NewRequest(http.MethodGet, "https://"+h3Authority+"/", nil)
		if rerr != nil {
			got <- rerr
			return
		}
		resp, rerr := cc.RoundTrip(req)
		if rerr == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		got <- rerr
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the handler")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = p.Shutdown(ctx)
	assert.True(t, errors.Is(err, context.DeadlineExceeded), "%v", err)
	assert.Less(t, time.Since(start), 3*time.Second, "the deadline must bound Shutdown, not the handler")

	select {
	case <-conn.Context().Done():
		var appErr *quic.ApplicationError
		cause := context.Cause(conn.Context())
		require.True(t, errors.As(cause, &appErr), "the close reached the client as %v", cause)
		assert.True(t, appErr.Remote, "the close comes from the proxy: %v", cause)
	case <-time.After(5 * time.Second):
		t.Fatal("the client never learned of the cut")
	}
	select {
	case err := <-served:
		assert.True(t, errors.Is(err, ErrProxyClosed), "%v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeQUIC did not return after the deadline")
	}

	releaseHandler()
	select {
	case <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("the client request never returned after the release")
	}
}

// stuckHTTP3Front serves p over HTTP/3, on the explicit front or the transparent socket,
// with a handler parked on h3Authority, sends it a request, and returns once the handler has
// it. The handler is released on cleanup.
func stuckHTTP3Front(t *testing.T, transparent bool) (*Proxy, <-chan error, *quic.Conn) {
	t.Helper()
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	p, served, conn := http3Request(t, transparent, blockingHandler(started, release), started)
	// Registered after Close, so the handler is released before Close waits for it.
	t.Cleanup(sync.OnceFunc(func() { close(release) }))
	return p, served, conn
}

// http3Request serves handler on h3Authority over HTTP/3, on the explicit front or the
// transparent socket, sends it a request, and returns once started is closed or receives.
func http3Request(t *testing.T, transparent bool, handler HTTP, started <-chan struct{}) (*Proxy, <-chan error, *quic.Conn) {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd(h3Authority+"/", handler)

	var addr netip.AddrPort
	var served <-chan error
	var conn *quic.Conn
	if transparent {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		ch := make(chan error, 1)
		go func() { ch <- p.ServeTransparentUDP(pc) }()
		t.Cleanup(func() { _ = p.Close() })
		addr, served = netip.MustParseAddrPort(pc.LocalAddr().String()), ch
	} else {
		addr, served = startQUICFront(t, p, ca)
	}

	if transparent {
		udp, err := loopbackUDP()
		require.NoError(t, err)
		t.Cleanup(func() { _ = udp.Close() })
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		conn, err = quic.Dial(ctx, udp, net.UDPAddrFromAddrPort(addr), &tls.Config{
			RootCAs:    poolOf(ca),
			ServerName: h3Authority,
			NextProtos: []string{http3.NextProtoH3},
			MinVersion: tls.VersionTLS13,
		}, &quic.Config{MaxIdleTimeout: 30 * time.Second})
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	} else {
		conn = dialQUICFront(t, addr, ca)
	}
	tr := &http3.Transport{}
	t.Cleanup(func() { _ = tr.Close() })
	cc := tr.NewClientConn(conn)
	go func() {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s:%d/", h3Authority, addr.Port()), nil)
		if err != nil {
			return
		}
		resp, err := cc.RoundTrip(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the handler")
	}
	return p, served, conn
}

// assertCutDoesNotWait runs cut, a Close or a Shutdown already past its deadline, against a
// parked HTTP/3 handler and checks that it returns at once, that the client is sent a
// CONNECTION_CLOSE, and that the socket is released before the handler ends. It returns
// what cut did.
func assertCutDoesNotWait(t *testing.T, served <-chan error, conn *quic.Conn, cut func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cut() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the cut must not wait for the handler")
	}
	select {
	case <-conn.Context().Done():
		var appErr *quic.ApplicationError
		cause := context.Cause(conn.Context())
		require.True(t, errors.As(cause, &appErr), "the close reached the client as %v", cause)
		assert.True(t, appErr.Remote, "the close comes from the proxy: %v", cause)
	case <-time.After(5 * time.Second):
		t.Fatal("the client never learned of the cut")
	}
	select {
	case err := <-served:
		assert.True(t, errors.Is(err, ErrProxyClosed), "%v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the socket was not released before the handler ended")
	}
	return err
}

func TestLifecycle_CloseDoesNotWaitForAStuckHTTP3Handler(t *testing.T) {
	p, served, conn := stuckHTTP3Front(t, false)
	require.NoError(t, assertCutDoesNotWait(t, served, conn, p.Close))

	done := make(chan error, 1)
	go func() { done <- p.Shutdown(context.Background()) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown after Close must not wait for the handler")
	}
}

func TestLifecycle_CloseDoesNotWaitForAStuckTransparentHTTP3Handler(t *testing.T) {
	p, served, conn := stuckHTTP3Front(t, true)
	require.NoError(t, assertCutDoesNotWait(t, served, conn, p.Close))
}

func TestLifecycle_ShutdownExpiredContextCutsTheHTTP3Front(t *testing.T) {
	p, served, conn := stuckHTTP3Front(t, false)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := assertCutDoesNotWait(t, served, conn, func() error { return p.Shutdown(ctx) })
	assert.True(t, errors.Is(err, context.Canceled), "%v", err)
}

func TestLifecycle_ShutdownExpiredContextCutsTheTransparentHTTP3(t *testing.T) {
	p, served, conn := stuckHTTP3Front(t, true)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := assertCutDoesNotWait(t, served, conn, func() error { return p.Shutdown(ctx) })
	assert.True(t, errors.Is(err, context.Canceled), "%v", err)
}

func TestLifecycle_CloseDoesNotWaitForAStuckDatagramHandler(t *testing.T) {
	origin := udpEchoOrigin(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	p.MustAdd[UDP](origin.String(), func(c *DatagramCtx) error {
		if !c.Inbound() {
			return c.Forward()
		}
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return c.Forward()
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- p.ServeTransparentUDP(newTProxyOriginPacketConn(pc, origin)) }()
	t.Cleanup(func() { _ = p.Close() })
	// Registered after Close, so the handler is released before Close waits for it.
	t.Cleanup(sync.OnceFunc(func() { close(release) }))

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	_, err = client.WriteTo([]byte("ping"), pc.LocalAddr())
	require.NoError(t, err)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the reply never reached the handler")
	}

	done := make(chan error, 1)
	go func() { done <- p.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Close must not wait for the handler")
	}
	select {
	case err := <-served:
		assert.True(t, errors.Is(err, ErrProxyClosed), "%v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeTransparentUDP did not return after Close")
	}
}

func TestLifecycle_ShutdownCutsTunnelsAtTheDeadline(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	originURL, _ := url.Parse(origin.URL)

	p, err := New()
	require.NoError(t, err)
	p.MustAdd[TCP](originHost(originURL), relayStream)

	addr := startProxy(t, p)

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", originURL.Host, originURL.Host)
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = p.Shutdown(ctx)
	elapsed := time.Since(start)

	assert.True(t, errors.Is(err, context.DeadlineExceeded), "%v", err)
	assert.Less(t, elapsed, 3*time.Second, "cutting the tunnel must release the wait promptly")

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = conn.Read(make([]byte, 1))
	assert.Error(t, err, "the tunnel must be cut")
}

func TestLifecycle_CloseDropsTheQueuedDatagrams(t *testing.T) {
	origin, _ := udpSinkOrigin(t)
	slow, _ := udpClient(t)
	p, err := New()
	require.NoError(t, err)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	p.MustAdd[UDP](origin.String(), func(c *DatagramCtx) error {
		mu.Lock()
		calls++
		mu.Unlock()
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return c.Forward()
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- p.ServeTransparentUDP(newTProxyOriginPacketConn(pc, origin)) }()
	proxyAddr := netip.MustParseAddrPort(pc.LocalAddr().String())

	sendTo(t, slow, proxyAddr, "0")
	waitEntered(t, entered)
	for i := 1; i <= 20; i++ {
		sendTo(t, slow, proxyAddr, fmt.Sprint(i))
	}
	time.Sleep(200 * time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- p.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Close must not wait for the parked handler")
	}
	close(release)
	select {
	case err := <-served:
		assert.True(t, errors.Is(err, ErrProxyClosed), "%v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeTransparentUDP did not return after Close")
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, calls, "nothing queued is served after Close")
}

func TestLifecycle_CloseCancelsTheResolutionInFlight(t *testing.T) {
	origin := udpEchoOrigin(t)
	p, ca, wrapper, proxyAddr, r, _ := verifiedQUICProxy(t, origin, "example.test")

	parked := dialQUICAsync(t, wrapper, origin, proxyAddr, "example.test", ca)
	waitEntered(t, r.entered)

	done := make(chan error, 1)
	go func() { done <- p.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Close must not wait for the resolution")
	}
	select {
	case err := <-r.ctxErr:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("Close must cancel the lookup")
	}
	select {
	case err := <-parked:
		assert.Error(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("the parked handshake never ended")
	}
}

func TestLifecycle_CloseEndsATunnelWaitingForSettings(t *testing.T) {
	p, ca, front, origin := masqueProxy(t)
	qc := dialQUICFront(t, front, ca)

	// No control stream, so no SETTINGS.
	var fields bytes.Buffer
	enc := qpack.NewEncoder(&fields)
	for _, f := range []qpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":protocol", Value: connectUDPUpgrade},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: front.String()},
		{Name: ":path", Value: connectUDPTargetPath(h3Authority, strconv.Itoa(int(origin.Port())))},
		{Name: "capsule-protocol", Value: "?1"},
	} {
		require.NoError(t, enc.WriteField(f))
	}
	frame := quicvarint.Append(quicvarint.Append(nil, 0x01), uint64(fields.Len()))
	str, err := qc.OpenStreamSync(t.Context())
	require.NoError(t, err)
	_, err = str.Write(append(frame, fields.Bytes()...))
	require.NoError(t, err)

	tunnel := waitForSessions(t, p, 1)[0]
	require.True(t, tunnel.Tunnel())
	require.NoError(t, tunnel.Close())

	require.NoError(t, str.SetReadDeadline(time.Now().Add(3*time.Second)))
	answer, err := io.ReadAll(str)
	require.NoError(t, err, "the stream did not end after the Close")
	typ, n, err := quicvarint.Parse(answer)
	require.NoError(t, err)
	require.Equal(t, uint64(0x01), typ, "the stream opens with a HEADERS frame")
	length, m, err := quicvarint.Parse(answer[n:])
	require.NoError(t, err)
	require.GreaterOrEqual(t, uint64(len(answer)-n-m), length)
	status, err := qpack.NewDecoder().Decode(answer[n+m : n+m+int(length)])()
	require.NoError(t, err)
	assert.Equal(t, qpack.HeaderField{Name: ":status", Value: "200"}, status)
	waitForSessions(t, p, 0)
}

func TestLifecycle_CloseEndsASOCKS5Connection(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)
	p := testProxy(t, WithTransport(tr))
	p.MustAdd("allowed.test/*{rest}", forwardHandler)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- p.ServeSOCKS5(ln) }()

	d := socksDialer(t, ln.Addr().String(), nil)
	conn, err := d.DialContext(t.Context(), "tcp", "allowed.test:80")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = fmt.Fprint(conn, "GET /probe HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	sess := waitForSessions(t, p, 1)[0]
	assert.Equal(t, "allowed.test", sess.Target().Host)
	require.NoError(t, sess.Close())
	_, err = br.ReadByte()
	assert.ErrorIs(t, err, io.EOF, "Close ends the connection the SOCKS5 CONNECT opened")
	waitForSessions(t, p, 0)

	require.NoError(t, p.Close())
	select {
	case err := <-served:
		assert.ErrorIs(t, err, ErrProxyClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeSOCKS5 did not return after Close")
	}
}

func TestServe_HTTP2ClientWithoutConnect(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	var seenScheme, seenAuthority, seenPath string
	var seenProto, seenSessProto Protocol
	p.MustAdd(originHost(originURL)+"/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		seenScheme, seenAuthority, seenPath = c.Scheme(), c.Authority(), c.RoutingPath()
		seenProto, seenSessProto = c.Protocol(), c.Session().Protocol()
		return c.Forward()
	})

	addr, pool := startProxyTLS(t, p, ca)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(&url.URL{Scheme: "https", Host: addr}),
			TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		},
	}

	resp, err := client.Get(origin.URL + "/foo")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "HTTP/2.0", resp.Proto, "the client must have reached the proxy over HTTP/2")
	assert.Equal(t, "origin", string(body))

	// :scheme is http even though the connection to the proxy carries TLS: the client asked
	// for a plain HTTP origin, and it is the target that decides the scheme, not the hop.
	assert.Equal(t, "http", seenScheme)
	assert.Equal(t, originURL.Host, seenAuthority)
	assert.Equal(t, "/foo", seenPath)
	assert.Equal(t, HTTP2, seenProto)
	// The session is built from ConnContext, before the protocol is known, so it has to be
	// recorded once a request has been read rather than assumed to be HTTP/1.1.
	assert.Equal(t, HTTP2, seenSessProto)
}

func TestServe_OriginFormIsStillRefusedOverHTTP1(t *testing.T) {
	p := testProxy(t)
	addr := startProxy(t, p)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://" + addr + "/foo")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestServe_HTTP1RefusalEndsTheConnectionAfterA400OrACONNECT(t *testing.T) {
	cases := []struct {
		name    string
		request string
		status  int
		ends    bool
	}{
		{"400", "GET /foo HTTP/1.1\r\nHost: origin.test\r\n\r\n", http.StatusBadRequest, true},
		{"refused CONNECT", "CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n", http.StatusForbidden, true},
		{"refused upgrade", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", http.StatusForbidden, true},
		{"other refusal", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n", http.StatusForbidden, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := startProxy(t, testProxy(t))
			conn, err := net.Dial("tcp", addr)
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			br := bufio.NewReader(conn)
			for range 2 {
				_, err = io.WriteString(conn, tc.request)
				require.NoError(t, err)
				resp, err := http.ReadResponse(br, nil)
				require.NoError(t, err)
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				assert.Equal(t, tc.status, resp.StatusCode)
				if tc.ends {
					assert.True(t, resp.Close, "the response does not end the connection")
					_, err = br.ReadByte()
					assert.ErrorIs(t, err, io.EOF)
					return
				}
			}
		})
	}
}

func TestServe_GRPCRefusalIsTrailersOnly(t *testing.T) {
	refuse := func(string, string) bool { return false }
	cases := []struct {
		name      string
		opts      []ProxyOption
		status    string
		challenge bool
	}{
		{name: "no entry", status: "7"},
		{name: "authentication", opts: []ProxyOption{WithProxyAuth(BasicAuth("edge", refuse))}, status: "16", challenge: true},
		{name: "authentication without a challenge", opts: []ProxyOption{WithProxyAuth(noChallengeAuth{})}, status: "7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := startProxy(t, testProxy(t, tc.opts...))
			conn, err := net.Dial("tcp", addr)
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()
			cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(conn)
			require.NoError(t, err)
			req, err := http.NewRequest(http.MethodPost, "http://origin.test/pkg.Svc/Method", strings.NewReader(string(grpcPayload("hello"))))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/grpc")
			resp, err := cc.RoundTrip(req)
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			_ = resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "application/grpc", resp.Header.Get("Content-Type"))
			assert.Empty(t, body)
			assert.Equal(t, tc.status, resp.Header.Get("Grpc-Status"))
			assert.Equal(t, tc.challenge, resp.Header.Get(HeaderProxyAuthenticate) != "")
		})
	}
}

func TestServe_RefusalLogRedactsThePassword(t *testing.T) {
	cases := []struct {
		name    string
		request string
		want    string
	}{
		{
			name:    "absolute-form",
			request: "GET http://alice:s3cret@origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n",
			want:    "request=http://alice:xxxxx@origin.test/",
		},
		{
			name:    "authority-form",
			request: "CONNECT alice:s3cret@origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n",
			want:    "request=//alice:xxxxx@origin.test:443",
		},
		{
			name:    "authority-form without userinfo",
			request: "CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n",
			want:    "request=origin.test:443",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := &syncBuffer{}
			p := testProxy(t, WithLogger(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))))
			conn, err := net.Dial("tcp", startProxy(t, p))
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()

			_, err = io.WriteString(conn, tc.request)
			require.NoError(t, err)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.NoError(t, err)
			_ = resp.Body.Close()

			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			assert.Contains(t, logs.String(), tc.want)
			assert.NotContains(t, logs.String(), "s3cret")
		})
	}
}

func TestServe_SessionTLSOnATLSFrontListener(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	var state *tls.ConnectionState
	p.MustAdd(originHost(originURL)+"/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		state = c.Session().TLS()
		return c.Forward()
	})

	addr, pool := startProxyTLS(t, p, ca)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(&url.URL{Scheme: "https", Host: addr}),
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}},
		},
	}

	resp, err := client.Get(origin.URL + "/foo")
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.NotNil(t, state)
	assert.True(t, state.HandshakeComplete)
	assert.Equal(t, "http/1.1", state.NegotiatedProtocol)
}

func TestServe_H2CClientWithoutConnect(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	p := testProxy(t)
	var seenScheme, seenAuthority, seenPath string
	var seenProto, seenSessProto Protocol
	p.MustAdd(originHost(originURL)+"/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		seenScheme, seenAuthority, seenPath = c.Scheme(), c.Authority(), c.RoutingPath()
		seenProto, seenSessProto = c.Protocol(), c.Session().Protocol()
		return c.Forward()
	})
	addr := startProxy(t, p)

	// http2.Transport has no proxy support, so the connection is opened by hand: the TCP
	// connection goes to the proxy while the request names the origin, which is exactly the
	// shape of an HTTP/2 proxy request.
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	tr := &http2.Transport{AllowHTTP: true}
	cc, err := tr.NewClientConn(conn)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, origin.URL+"/foo", nil)
	require.NoError(t, err)

	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "HTTP/2.0", resp.Proto)
	assert.Equal(t, "origin", string(body))

	assert.Equal(t, "http", seenScheme)
	assert.Equal(t, originURL.Host, seenAuthority)
	assert.Equal(t, "/foo", seenPath)
	assert.Equal(t, HTTP2, seenProto)
	assert.Equal(t, HTTP2, seenSessProto)
}

func TestLifecycle_ShutdownDrainsAnIdleConnectionInsideAnHTTP2Connect(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)
	p := testProxy(t, WithTransport(tr))
	p.MustAdd("allowed.test/*{rest}", forwardHandler)

	w, br := h2cConnect(t, startProxy(t, p), "allowed.test:80")
	_, err = io.WriteString(w, "GET /idle HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "ok", string(body))

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	assert.NoError(t, p.Shutdown(ctx), "the idle connection inside the tunnel was not drained")
}

// pipeListener accepts the ends of [net.Pipe] sent on ch. A pipe has no buffer, so a peer that
// does not read blocks every write.
type pipeListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return emptyAddr{} }

func TestLifecycle_CloseCutsTheTLSFrontConnectionsTogether(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd("idle.test/", okHandler)
	leaf, err := ca.Leaf("proxy.test")
	require.NoError(t, err)
	ln := newPipeListener()
	go func() { _ = p.ServeTLS(ln, *leaf) }()
	t.Cleanup(func() { _ = p.Close() })

	for range 3 {
		front, client := net.Pipe()
		t.Cleanup(func() { _ = client.Close() })
		ln.ch <- front
		tc := tls.Client(client, &tls.Config{ServerName: "proxy.test", RootCAs: ca.CertPool(), NextProtos: []string{"http/1.1"}})
		require.NoError(t, tc.Handshake())
		_, err = io.WriteString(tc, "GET http://idle.test/ HTTP/1.1\r\nHost: idle.test\r\n\r\n")
		require.NoError(t, err)
		resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	start := time.Now()
	require.NoError(t, p.Close())
	assert.Less(t, time.Since(start), alertWriteTimeout*3/2, "the front connections were closed one after the other")
}

func TestLifecycle_ShutdownDeadlineCutsAPlainFrontRequest(t *testing.T) {
	for _, tc := range []struct {
		client func(addr string) *http.Client
		name   string
	}{
		{func(addr string) *http.Client { return proxyClient(addr, nil) }, "h1"},
		{h2cFrontClient, "h2c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			p, err := New(WithCA(ca))
			require.NoError(t, err)
			started := make(chan struct{}, 1)
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			p.MustAdd("example.test/", blockingHandler(started, release))
			client := tc.client(startProxy(t, p))

			got := make(chan error, 1)
			go func() {
				_, gerr := getBody(client, "http://example.test/")
				got <- gerr
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("the request never reached the handler")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
			defer cancel()
			assert.ErrorIs(t, p.Shutdown(ctx), context.DeadlineExceeded)
			select {
			case gerr := <-got:
				assert.Error(t, gerr, "the request must have been cut at the deadline")
			case <-time.After(200 * time.Millisecond):
				t.Fatal("the request outlived the Shutdown that cut it")
			}
		})
	}
}

func TestLifecycle_CloseEndsAnIdleTunnelAtOnce(t *testing.T) {
	p, ca := newTLSProxy(t)
	conn := connectRaw(t, startProxy(t, p), tlsName+":443")
	tc := tls.Client(conn, &tls.Config{ServerName: tlsName, RootCAs: ca.CertPool()})
	_, err := io.WriteString(tc, "GET / HTTP/1.1\r\nHost: "+tlsName+"\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	waitForSessions(t, p, 1)
	// A client closes its connection once it reads the end of it.
	go func() {
		_, _ = io.Copy(io.Discard, tc)
		_ = tc.Close()
	}()

	start := time.Now()
	require.NoError(t, p.Close())
	assert.Less(t, time.Since(start), alertWriteTimeout/2)
}

func TestLifecycle_CloseSendsCloseNotifyOnATerminatedHTTPConnection(t *testing.T) {
	p, ca := newTLSProxy(t)
	rec := &recordingConn{Conn: connectRaw(t, startProxy(t, p), tlsName+":443")}
	tc := tls.Client(rec, &tls.Config{ServerName: tlsName, RootCAs: ca.CertPool(), MaxVersion: tls.VersionTLS12, MinVersion: tls.VersionTLS12})
	_, err := io.WriteString(tc, "GET / HTTP/1.1\r\nHost: "+tlsName+"\r\n\r\n")
	require.NoError(t, err)
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	waitForSessions(t, p, 1)

	require.NoError(t, p.Close())
	_, _ = io.ReadAll(br)
	assert.Equal(t, byte(tlsAlert), rec.lastRecord(), "the cut ended the connection without a close_notify")
}

func TestLifecycle_FrontConnectionLeavesTheRegistry(t *testing.T) {
	p, ca := newTLSProxy(t)
	p.MustAdd[TCP](tlsDB, func(c *TCPCtx) error {
		_, err := io.Copy(io.Discard, c.Client())
		return err
	})
	addr := startProxy(t, p)
	fronts := func() int {
		p.srv.mu.Lock()
		defer p.srv.mu.Unlock()
		return len(p.srv.fronts)
	}

	plain, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	_, err = io.WriteString(plain, "GET http://"+tlsName+"/ HTTP/1.1\r\nHost: "+tlsName+"\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(plain), nil)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, 1, fronts())
	require.NoError(t, plain.Close())
	assert.Eventually(t, func() bool { return fronts() == 0 }, 3*time.Second, 10*time.Millisecond, "a closed connection stayed registered")

	tunnel := connectRaw(t, addr, tlsDB+":443")
	inner := tls.Client(tunnel, &tls.Config{ServerName: tlsDB, RootCAs: ca.CertPool()})
	require.NoError(t, inner.Handshake())
	assert.Eventually(t, func() bool { return fronts() == 0 }, 3*time.Second, 10*time.Millisecond, "a hijacked connection stayed registered")
}

// silentOrigin answers no request and counts the requests its clients cancel. reached is
// closed once a request arrived.
func silentOrigin(t *testing.T) (*httptest.Server, <-chan struct{}, *atomic.Int64) {
	t.Helper()
	var canceled atomic.Int64
	reached := make(chan struct{})
	arrived := sync.OnceFunc(func() { close(reached) })
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived()
		<-r.Context().Done()
		canceled.Add(1)
	}))
	t.Cleanup(origin.Close)
	return origin, reached, &canceled
}

func TestLifecycle_CloseCutsAForwardedRequest(t *testing.T) {
	front := func(t *testing.T) (*Proxy, string, <-chan struct{}, *atomic.Int64) {
		origin, reached, canceled := silentOrigin(t)
		originURL, err := url.Parse(origin.URL)
		require.NoError(t, err)
		tr := DefaultTransport()
		tr.DialContext = pinnedDialer(originURL.Host)
		p := testProxy(t, WithTransport(tr))
		p.MustAdd("allowed.test/*{rest}", forwardHandler)
		p.MustAdd[WebSocket]("allowed.test/ws", func(*WebSocketCtx) error { return nil })
		return p, startProxy(t, p), reached, canceled
	}
	grpcCall := func(client *http.Client, target string) error {
		req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(grpcPayload("one")))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/grpc")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		_, err = io.ReadAll(resp.Body)
		return err
	}

	for _, tc := range []struct {
		run  func(t *testing.T) (p *Proxy, send func() error, reached <-chan struct{}, canceled *atomic.Int64)
		name string
	}{
		{name: "front h1", run: func(t *testing.T) (*Proxy, func() error, <-chan struct{}, *atomic.Int64) {
			p, addr, reached, canceled := front(t)
			return p, func() error {
				_, err := getBody(proxyClient(addr, nil), "http://allowed.test/")
				return err
			}, reached, canceled
		}},
		{name: "front h2c", run: func(t *testing.T) (*Proxy, func() error, <-chan struct{}, *atomic.Int64) {
			p, addr, reached, canceled := front(t)
			return p, func() error {
				_, err := getBody(h2cFrontClient(addr), "http://allowed.test/")
				return err
			}, reached, canceled
		}},
		{name: "WebSocket handshake", run: func(t *testing.T) (*Proxy, func() error, <-chan struct{}, *atomic.Int64) {
			p, addr, reached, canceled := front(t)
			return p, func() error {
				conn, err := net.Dial("tcp", addr)
				if err != nil {
					return err
				}
				defer func() { _ = conn.Close() }()
				_, err = io.WriteString(conn, "GET http://allowed.test/ws HTTP/1.1\r\nHost: allowed.test\r\n"+
					"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
				if err != nil {
					return err
				}
				_, err = http.ReadResponse(bufio.NewReader(conn), nil)
				return err
			}, reached, canceled
		}},
		{name: "terminated h1", run: func(t *testing.T) (*Proxy, func() error, <-chan struct{}, *atomic.Int64) {
			origin, reached, canceled := grpcHoldingOrigin(t, nil, false)
			p, _, client := interceptingProxy(t, origin)
			return p, func() error {
				_, err := getBody(client, origin.URL)
				return err
			}, reached, canceled
		}},
		{name: "terminated h2", run: func(t *testing.T) (*Proxy, func() error, <-chan struct{}, *atomic.Int64) {
			origin, reached, canceled := grpcHoldingOrigin(t, nil, false)
			p, host, client := grpcH2Proxy(t, origin)
			p.MustAdd(host+"/*{any}", forwardHandler)
			return p, func() error {
				_, err := getBody(client, origin.URL)
				return err
			}, reached, canceled
		}},
		{name: "gRPC h1", run: func(t *testing.T) (*Proxy, func() error, <-chan struct{}, *atomic.Int64) {
			origin, reached, canceled := grpcHoldingOrigin(t, nil, false)
			p, host, client := grpcProxy(t, origin)
			p.MustAdd(host+"/pkg.Svc/Method", func(c *GRPCCtx) error { return c.Forward() })
			return p, func() error { return grpcCall(client, origin.URL+"/pkg.Svc/Method") }, reached, canceled
		}},
		{name: "gRPC h2", run: func(t *testing.T) (*Proxy, func() error, <-chan struct{}, *atomic.Int64) {
			origin, reached, canceled := grpcHoldingOrigin(t, nil, false)
			p, host, client := grpcH2Proxy(t, origin)
			p.MustAdd(host+"/pkg.Svc/Method", func(c *GRPCCtx) error { return c.Forward() })
			return p, func() error { return grpcCall(client, origin.URL+"/pkg.Svc/Method") }, reached, canceled
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, send, reached, canceled := tc.run(t)
			got := make(chan error, 1)
			go func() { got <- send() }()
			select {
			case <-reached:
			case <-time.After(5 * time.Second):
				t.Fatal("the request never reached the origin")
			}

			start := time.Now()
			require.NoError(t, p.Close())
			assert.Less(t, time.Since(start), alertWriteTimeout/2)
			select {
			case err := <-got:
				assert.Error(t, err, "a status reached the client of a cut request")
			case <-time.After(2 * time.Second):
				t.Fatal("the client never saw the cut")
			}
			assert.Eventually(t, func() bool { return canceled.Load() == 1 }, 2*time.Second, 10*time.Millisecond, "the origin never saw the cut")
		})
	}
}

func TestLifecycle_CloseReturnsOnceTheHandlersItCutReturned(t *testing.T) {
	t.Run("request", func(t *testing.T) {
		p := testProxy(t)
		var returned atomic.Bool
		started := make(chan struct{})
		p.MustAdd("allowed.test/", func(c *HTTPCtx) (*http.Response, error) {
			close(started)
			<-c.Request().Context().Done()
			time.Sleep(100 * time.Millisecond)
			returned.Store(true)
			return nil, c.Request().Context().Err()
		})
		addr := startProxy(t, p)
		go func() { _, _ = getBody(proxyClient(addr, nil), "http://allowed.test/") }()
		<-started

		require.NoError(t, p.Close())
		assert.True(t, returned.Load())
	})
	for _, transparent := range []bool{false, true} {
		name := "HTTP/3 front request"
		if transparent {
			name = "terminated HTTP/3 request"
		}
		t.Run(name, func(t *testing.T) {
			var returned atomic.Bool
			started := make(chan struct{})
			p, _, _ := http3Request(t, transparent, func(c *HTTPCtx) (*http.Response, error) {
				close(started)
				<-c.Request().Context().Done()
				time.Sleep(100 * time.Millisecond)
				returned.Store(true)
				return nil, c.Request().Context().Err()
			}, started)

			require.NoError(t, p.Close())
			assert.True(t, returned.Load())
		})
	}
	t.Run("session", func(t *testing.T) {
		p, ca := newTLSProxy(t)
		var returned atomic.Bool
		started := make(chan struct{})
		p.MustAdd[TCP](tlsDB, func(c *TCPCtx) error {
			close(started)
			<-c.Context().Done()
			time.Sleep(100 * time.Millisecond)
			returned.Store(true)
			return nil
		})
		tc := tls.Client(connectRaw(t, startProxy(t, p), tlsDB+":443"), &tls.Config{ServerName: tlsDB, RootCAs: ca.CertPool()})
		require.NoError(t, tc.Handshake())
		_, err := tc.Write([]byte{0})
		require.NoError(t, err)
		<-started

		require.NoError(t, p.Close())
		assert.True(t, returned.Load())
	})
}

func TestLifecycle_ALaterCutReturnsOnceTheFirstHasEnded(t *testing.T) {
	p := testProxy(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	started := make(chan struct{}, 1)
	p.MustAdd("allowed.test/", blockingHandler(started, release))
	addr := startProxy(t, p)
	go func() { _, _ = getBody(proxyClient(addr, nil), "http://allowed.test/") }()
	<-started

	shutdownEnd := make(chan time.Time, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		_ = p.Shutdown(ctx)
		shutdownEnd <- time.Now()
	}()
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, p.Close())
	closeEnd := time.Now()
	ended := <-shutdownEnd
	assert.Less(t, closeEnd.Sub(ended), 100*time.Millisecond, "the concurrent Close waited bounds of its own")

	start := time.Now()
	require.NoError(t, p.Close())
	assert.Less(t, time.Since(start), 100*time.Millisecond, "a Close after the cut waited again")
}

func TestLifecycle_CloseDoesNotWaitForASessionClosedBeforeIt(t *testing.T) {
	p, ca := newTLSProxy(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	p.MustAdd[TCP](tlsDB, func(*TCPCtx) error {
		<-release
		return nil
	})
	tc := tls.Client(connectRaw(t, startProxy(t, p), tlsDB+":443"), &tls.Config{ServerName: tlsDB, RootCAs: ca.CertPool()})
	require.NoError(t, tc.Handshake())
	_, err := tc.Write([]byte{0})
	require.NoError(t, err)
	require.NoError(t, waitForSessions(t, p, 1)[0].Close())

	start := time.Now()
	require.NoError(t, p.Close())
	assert.Less(t, time.Since(start), alertWriteTimeout/2)
}

func TestLifecycle_CutAbortsAResponseReturnedAfterIt(t *testing.T) {
	for _, tc := range []struct {
		cut  func(p *Proxy)
		name string
	}{
		{func(p *Proxy) { _ = p.Close() }, "Close"},
		{func(p *Proxy) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_ = p.Shutdown(ctx)
		}, "Shutdown deadline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testProxy(t)
			started := make(chan struct{})
			p.MustAdd("allowed.test/", func(c *HTTPCtx) (*http.Response, error) {
				close(started)
				<-c.Request().Context().Done()
				time.Sleep(200 * time.Millisecond)
				return Text(http.StatusOK, "late"), nil
			})
			addr := startProxy(t, p)
			got := make(chan error, 1)
			go func() {
				_, err := getBody(proxyClient(addr, nil), "http://allowed.test/")
				got <- err
			}()
			<-started
			go tc.cut(p)
			select {
			case err := <-got:
				assert.Error(t, err, "a response returned after the cut reached the client")
			case <-time.After(5 * time.Second):
				t.Fatal("the client never saw the cut")
			}
		})
	}
}

func TestLifecycle_ShutdownReturnsOnceItsCutHasEnded(t *testing.T) {
	p, ca := newTLSProxy(t)
	var returned atomic.Bool
	started := make(chan struct{})
	p.MustAdd[TCP](tlsDB, func(c *TCPCtx) error {
		close(started)
		<-c.Context().Done()
		time.Sleep(500 * time.Millisecond)
		returned.Store(true)
		return nil
	})
	tc := tls.Client(connectRaw(t, startProxy(t, p), tlsDB+":443"), &tls.Config{ServerName: tlsDB, RootCAs: ca.CertPool()})
	require.NoError(t, tc.Handshake())
	_, err := tc.Write([]byte{0})
	require.NoError(t, err)
	<-started

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	assert.ErrorIs(t, p.Shutdown(ctx), context.DeadlineExceeded)
	assert.True(t, returned.Load())
}

func TestLifecycle_CloseRefusesConnectionsFromItsStart(t *testing.T) {
	p := testProxy(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	started := make(chan struct{}, 1)
	p.MustAdd("allowed.test/", blockingHandler(started, release))
	addr := startProxy(t, p)
	go func() { _, _ = getBody(proxyClient(addr, nil), "http://allowed.test/") }()
	<-started

	closed := make(chan struct{})
	go func() {
		_ = p.Close()
		close(closed)
	}()
	time.Sleep(200 * time.Millisecond)
	select {
	case <-closed:
		t.Fatal("Close returned before the cut waited for the request")
	default:
	}
	_, err := net.DialTimeout("tcp", addr, time.Second)
	assert.Error(t, err, "the listener accepted during the cut")
	<-closed
}

func TestLifecycle_CloseWritesTheCloseNotifyBeforeClosingTheSocket(t *testing.T) {
	p, ca := newTLSProxy(t)
	ln := newPipeListener()
	go func() { _ = p.Serve(ln) }()
	t.Cleanup(func() { _ = p.Close() })
	front, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	ln.ch <- front

	br := bufio.NewReader(client)
	_, err := io.WriteString(client, "CONNECT "+tlsName+":443 HTTP/1.1\r\nHost: "+tlsName+":443\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	rec := &recordingConn{Conn: client}
	tc := tls.Client(rec, &tls.Config{ServerName: tlsName, RootCAs: ca.CertPool(), MaxVersion: tls.VersionTLS12, MinVersion: tls.VersionTLS12})
	_, err = io.WriteString(tc, "GET / HTTP/1.1\r\nHost: "+tlsName+"\r\n\r\n")
	require.NoError(t, err)
	tbr := bufio.NewReader(tc)
	resp, err = http.ReadResponse(tbr, nil)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	waitForSessions(t, p, 1)

	go func() { _ = p.Close() }()
	// The pipe has no buffer, so the close_notify waits for this read.
	time.Sleep(300 * time.Millisecond)
	_, _ = io.ReadAll(tbr)
	assert.Equal(t, byte(tlsAlert), rec.lastRecord(), "the socket closed before the close_notify")
}

func TestLifecycle_ShutdownReturnsOnceACloseCutItsDrain(t *testing.T) {
	p, ca := newTLSProxy(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	started := make(chan struct{})
	p.MustAdd[TCP](tlsDB, func(*TCPCtx) error {
		close(started)
		<-release
		return nil
	})
	tc := tls.Client(connectRaw(t, startProxy(t, p), tlsDB+":443"), &tls.Config{ServerName: tlsDB, RootCAs: ca.CertPool()})
	require.NoError(t, tc.Handshake())
	_, err := tc.Write([]byte{0})
	require.NoError(t, err)
	<-started

	shutdown := make(chan error, 1)
	go func() { shutdown <- p.Shutdown(context.Background()) }()
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, p.Close())
	select {
	case err := <-shutdown:
		assert.ErrorIs(t, err, ErrProxyClosed)
	case <-time.After(alertWriteTimeout):
		t.Fatal("Shutdown waited for a handler that ignores its context after Close cut the drain")
	}
}

func TestLifecycle_CutGivesAResponseDelimitedByTheCloseItsFailedEnd(t *testing.T) {
	for _, tc := range []struct {
		name string
		body func(ctx context.Context) io.Reader
	}{
		{"its body ignores its context", func(context.Context) io.Reader {
			pr, pw := io.Pipe()
			go func() { _, _ = pw.Write([]byte("partial")) }()
			return pr
		}},
		{"its body fails", func(context.Context) io.Reader {
			return io.MultiReader(strings.NewReader("partial"), iotest.ErrReader(errors.New("origin reset")))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testProxy(t)
			p.MustAdd("allowed.test/", func(c *HTTPCtx) (*http.Response, error) {
				return Stream(http.StatusOK, "text/plain", tc.body(c.Request().Context()), -1), nil
			})
			conn, err := net.Dial("tcp", startProxy(t, p))
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			_, err = io.WriteString(conn, "GET http://allowed.test/ HTTP/1.0\r\nHost: allowed.test\r\n\r\n")
			require.NoError(t, err)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.NoError(t, err)
			_, err = io.ReadFull(resp.Body, make([]byte, 7))
			require.NoError(t, err)

			go func() { _ = p.Close() }()
			_, err = io.ReadAll(resp.Body)
			assert.ErrorIs(t, err, syscall.ECONNRESET, "the truncated response read as complete")
		})
	}
}

func TestLifecycle_CloseGivesATerminatedResponseDelimitedByTheCloseItsFailedEnd(t *testing.T) {
	for _, how := range []string{"Session.Close", "Proxy.Close"} {
		t.Run(how, func(t *testing.T) {
			p, ca := newTLSProxy(t)
			p.MustAdd(tlsDB+"/*{any}", func(c *HTTPCtx) (*http.Response, error) {
				pr, pw := io.Pipe()
				go func() { _, _ = pw.Write([]byte("partial")) }()
				t.Cleanup(func() { _ = pw.Close() })
				return Stream(http.StatusOK, "text/plain", pr, -1), nil
			})
			raw := connectRaw(t, startProxy(t, p), tlsDB+":443")
			rec := &recordingConn{Conn: raw}
			tc := tls.Client(rec, &tls.Config{ServerName: tlsDB, RootCAs: ca.CertPool(), NextProtos: []string{"http/1.1"}, MaxVersion: tls.VersionTLS12})
			_, err := io.WriteString(tc, "GET / HTTP/1.0\r\nHost: "+tlsDB+"\r\n\r\n")
			require.NoError(t, err)
			resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
			require.NoError(t, err)
			_, err = io.ReadFull(resp.Body, make([]byte, 7))
			require.NoError(t, err)

			if how == "Session.Close" {
				require.NoError(t, waitForSessions(t, p, 1)[0].Close())
			} else {
				require.NoError(t, p.Close())
			}
			require.NoError(t, raw.SetReadDeadline(time.Now().Add(3*time.Second)))
			_, err = io.ReadAll(resp.Body)
			assert.Error(t, err, "the truncated response read as complete")
			assert.NotEqual(t, byte(tlsAlert), rec.lastRecord(), "the cut wrote a close_notify after a truncated response")
		})
	}
}

func TestLifecycle_CloseResetsAnHTTP2RequestIgnoringItsContext(t *testing.T) {
	p := testProxy(t)
	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	p.MustAdd("allowed.test/", func(*HTTPCtx) (*http.Response, error) {
		close(started)
		<-release
		return nil, errors.New("late")
	})
	client := h2cFrontClient(startProxy(t, p))
	got := make(chan error, 1)
	go func() {
		_, err := getBody(client, "http://allowed.test/")
		got <- err
	}()
	<-started

	start := time.Now()
	go func() { _ = p.Close() }()
	err := <-got
	_, reset := errors.AsType[http2.StreamError](err)
	assert.True(t, reset, "the request got %v", err)
	assert.Less(t, time.Since(start), alertWriteTimeout/2)
}

func TestLifecycle_CutServesNoRequestReadAfterItsStart(t *testing.T) {
	p := testProxy(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	started := make(chan struct{}, 1)
	var late atomic.Bool
	p.MustAdd("allowed.test/", blockingHandler(started, release))
	p.MustAdd("late.test/", func(*HTTPCtx) (*http.Response, error) {
		late.Store(true)
		return Text(http.StatusOK, "late"), nil
	})
	addr := startProxy(t, p)
	idle, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = idle.Close() })
	go func() { _, _ = getBody(proxyClient(addr, nil), "http://allowed.test/") }()
	<-started

	go func() { _ = p.Close() }()
	// The cut waits on the blocked handler, with the idle connection still open.
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, idle.SetDeadline(time.Now().Add(3*time.Second)))
	_, err = io.WriteString(idle, "GET http://late.test/ HTTP/1.1\r\nHost: late.test\r\n\r\n")
	require.NoError(t, err)
	_, err = http.ReadResponse(bufio.NewReader(idle), nil)
	assert.Error(t, err, "a request read during the cut got a response")
	assert.False(t, late.Load(), "the handler of a request read during the cut ran")
}

func TestLifecycle_CutResetsAPendingSession(t *testing.T) {
	for _, mode := range []string{"CONNECT", "SOCKS5", "transparent"} {
		t.Run(mode, func(t *testing.T) {
			p := testProxy(t, WithSniffTimeout(10*time.Second))
			p.MustAdd[TCP]("plain.test", noopStream)
			var conn net.Conn
			switch mode {
			case "CONNECT":
				conn = connectRaw(t, startProxy(t, p), "plain.test:25")
			case "SOCKS5":
				c, err := socksDialer(t, startSOCKS5(t, p), nil).DialContext(t.Context(), "tcp", "plain.test:25")
				require.NoError(t, err)
				t.Cleanup(func() { _ = c.Close() })
				conn = c
			default:
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				go func() { _ = p.ServeTransparent(ln) }()
				c, err := net.Dial("tcp", ln.Addr().String())
				require.NoError(t, err)
				t.Cleanup(func() { _ = c.Close() })
				conn = c
				time.Sleep(50 * time.Millisecond)
			}
			assert.Empty(t, slices.Collect(p.Sessions()), "a pending session is listed")
			require.NoError(t, p.Close())
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
			_, err := conn.Read(make([]byte, 1))
			assert.ErrorIs(t, err, syscall.ECONNRESET)
		})
	}
}

func TestLifecycle_ServeConnAfterTheCutResetsItsConnection(t *testing.T) {
	p := testProxy(t)
	require.NoError(t, p.Close())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer client.Close()
	server, err := ln.Accept()
	require.NoError(t, err)
	assert.ErrorIs(t, p.ServeConn(server), ErrProxyClosed)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, err = client.Read(make([]byte, 1))
	assert.ErrorIs(t, err, syscall.ECONNRESET)
}

func TestLifecycle_CutRefusesASOCKS5RequestReadDuringIt(t *testing.T) {
	p := testProxy(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	started := make(chan struct{}, 1)
	var ran atomic.Bool
	p.MustAdd("allowed.test/", blockingHandler(started, release))
	p.MustAdd[TCP]("plain.test", func(*TCPCtx) error {
		ran.Store(true)
		return nil
	})
	addr := startProxy(t, p)
	socks, err := net.Dial("tcp", startSOCKS5(t, p))
	require.NoError(t, err)
	t.Cleanup(func() { _ = socks.Close() })
	require.NoError(t, socks.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = socks.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	method := make([]byte, 2)
	_, err = io.ReadFull(socks, method)
	require.NoError(t, err)
	go func() { _, _ = getBody(proxyClient(addr, nil), "http://allowed.test/") }()
	<-started

	go func() { _ = p.Close() }()
	// The cut waits on the blocked handler.
	time.Sleep(200 * time.Millisecond)
	_, err = socks.Write(append([]byte{0x05, 0x01, 0x00, 0x03, byte(len("plain.test"))}, "plain.test\x00\x19x"...))
	require.NoError(t, err)
	reply := make([]byte, 10)
	_, err = io.ReadFull(socks, reply)
	assert.ErrorIs(t, err, syscall.ECONNRESET, "a SOCKS5 request read during the cut got %x", reply)
	assert.False(t, ran.Load(), "the handler of a session registered during the cut ran")
}

type endlessBody struct{ pause time.Duration }

func (e endlessBody) Read(b []byte) (int, error) {
	time.Sleep(e.pause)
	n := min(len(b), 512)
	for i := range n {
		b[i] = 'x'
	}
	return n, nil
}

func TestLifecycle_CutEndsAResponseInFlightAtOnce(t *testing.T) {
	for _, proto := range []string{"h1", "h2c", "h3"} {
		for _, client := range []string{"reading", "stalled"} {
			t.Run(proto+"/"+client, func(t *testing.T) {
				ca, err := GenerateCA()
				require.NoError(t, err)
				p, err := New(WithCA(ca))
				require.NoError(t, err)
				body := endlessBody{pause: 2 * time.Millisecond}
				if client == "stalled" {
					body.pause = 0
				}
				p.MustAdd("front.example.test/", func(*HTTPCtx) (*http.Response, error) {
					return Stream(http.StatusOK, "text/plain", body, -1), nil
				})
				var resp *http.Response
				switch proto {
				case "h3":
					front, _ := startQUICFront(t, p, ca)
					req, rerr := http.NewRequest(http.MethodGet, "http://front.example.test/", nil)
					require.NoError(t, rerr)
					resp, err = h3Over(t, dialQUICFront(t, front, ca)).RoundTrip(req)
				case "h2c":
					resp, err = h2cFrontClient(startProxy(t, p)).Get("http://front.example.test/")
				default:
					resp, err = proxyClient(startProxy(t, p), nil).Get("http://front.example.test/")
				}
				require.NoError(t, err)
				defer resp.Body.Close()
				_, err = io.ReadFull(resp.Body, make([]byte, 2048))
				require.NoError(t, err)

				if client == "stalled" {
					// The flow control windows fill and the writes of the response block.
					time.Sleep(200 * time.Millisecond)
				}
				start := time.Now()
				// Close waits T at most for the client's FIN in the normal end of its connection.
				go func() { _ = p.Close() }()
				_, err = io.Copy(io.Discard, resp.Body)
				assert.Error(t, err, "the response the cut ended reads as complete")
				assert.Less(t, time.Since(start), 500*time.Millisecond, "the response in flight outlived the requests phase")
			})
		}
	}
}

func TestLifecycle_CloseSendsAGoawayFirst(t *testing.T) {
	p := testProxy(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	started := make(chan struct{}, 1)
	p.MustAdd("allowed.test/", blockingHandler(started, release))
	raw, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	_, err = raw.Write([]byte(http2.ClientPreface))
	require.NoError(t, err)
	fr := http2.NewFramer(raw, raw)
	require.NoError(t, fr.WriteSettings())
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range [][2]string{{":method", "GET"}, {":scheme", "http"}, {":authority", "allowed.test"}, {":path", "/"}} {
		require.NoError(t, enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]}))
	}
	require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: buf.Bytes(), EndHeaders: true, EndStream: true}))
	<-started

	go func() { _ = p.Close() }()
	require.NoError(t, raw.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
	for {
		f, rerr := fr.ReadFrame()
		require.NoError(t, rerr, "the connection ended with no GOAWAY")
		if _, ok := f.(*http2.GoAwayFrame); ok {
			return
		}
	}
}

func TestLifecycle_DrainLeavesTheContextOfAnAdmittedSession(t *testing.T) {
	for _, mode := range []string{"CONNECT", "transparent", "SOCKS5"} {
		t.Run(mode, func(t *testing.T) {
			p, ca := newTLSProxy(t)
			ended := make(chan struct{}, 1)
			started := make(chan struct{}, 1)
			release := make(chan struct{})
			p.MustAdd[TCP](tlsDB, func(c *TCPCtx) error {
				started <- struct{}{}
				select {
				case <-c.Context().Done():
					ended <- struct{}{}
				case <-release:
				}
				return nil
			})
			var raw net.Conn
			switch mode {
			case "CONNECT":
				raw = connectRaw(t, startProxy(t, p), tlsDB+":443")
			case "SOCKS5":
				c, err := socksDialer(t, startSOCKS5(t, p), nil).DialContext(t.Context(), "tcp", tlsDB+":443")
				require.NoError(t, err)
				t.Cleanup(func() { _ = c.Close() })
				raw = c
			default:
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				go func() { _ = p.ServeTransparent(ln) }()
				t.Cleanup(func() { _ = p.Close() })
				c, err := net.Dial("tcp", ln.Addr().String())
				require.NoError(t, err)
				t.Cleanup(func() { _ = c.Close() })
				raw = c
			}
			tc := tls.Client(raw, &tls.Config{ServerName: tlsDB, RootCAs: ca.CertPool()})
			require.NoError(t, tc.Handshake())
			_, err := tc.Write([]byte{0})
			require.NoError(t, err)
			<-started

			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			go func() { _ = p.Shutdown(ctx) }()
			select {
			case <-ended:
				t.Error("the drain ended the context of a session admitted before it")
			case <-time.After(500 * time.Millisecond):
			}
			close(release)
		})
	}
}

func TestLifecycle_DrainServesAnHTTP1RequestReadDuringIt(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("allowed.test/", okHandler)
	conn, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer conn.Close()
	// The connection is accepted before the drain and sends its request after the start.
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	go func() { _ = p.Shutdown(ctx) }()
	time.Sleep(200 * time.Millisecond)

	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	_, err = io.WriteString(conn, "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err, "the request read during the drain got no response")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, resp.Close, "the response of a request read during the drain keeps the connection")
}

func TestLifecycle_DrainRefusesAnHTTP1ConnectReadDuringIt(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[TCP]("plain.test", noopStream)
	conn, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer conn.Close()
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	go func() { _ = p.Shutdown(ctx) }()
	time.Sleep(200 * time.Millisecond)

	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	_, err = io.WriteString(conn, "CONNECT plain.test:25 HTTP/1.1\r\nHost: plain.test:25\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.True(t, resp.Close)
}

func TestLifecycle_DrainEndsAnIdleHTTP3FrontAfterItsGoaway(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd("front.example.test/", okHandler)
	front, _ := startQUICFront(t, p, ca)
	conn := dialQUICFront(t, front, ca)
	req, err := http.NewRequest(http.MethodGet, "http://front.example.test/", nil)
	require.NoError(t, err)
	resp, err := h3Over(t, conn).RoundTrip(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	start := time.Now()
	require.NoError(t, p.Shutdown(ctx))
	assert.Less(t, time.Since(start), 2*time.Second, "the drain waited for an idle HTTP/3 connection")
	select {
	case <-conn.Context().Done():
		var appErr *quic.ApplicationError
		require.ErrorAs(t, context.Cause(conn.Context()), &appErr)
		assert.EqualValues(t, http3.ErrCodeNoError, appErr.ErrorCode)
	case <-time.After(time.Second):
		t.Fatal("the idle HTTP/3 connection outlived the drain")
	}
}

func TestServe_CallerTLSListenerServesBothProtocols(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxy(t)
	p.MustAdd("allowed.test/", okHandler)
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		_ = p.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"h2", "http/1.1"}}))
	}()
	t.Cleanup(func() { _ = p.Close() })
	for _, proto := range []string{"h2", "http/1.1"} {
		t.Run(proto, func(t *testing.T) {
			tr := &http.Transport{
				Proxy:           http.ProxyURL(&url.URL{Scheme: "https", Host: ln.Addr().String()}),
				TLSClientConfig: &tls.Config{RootCAs: ca.CertPool(), NextProtos: []string{proto}},
			}
			tr.Protocols = new(http.Protocols)
			if proto == "h2" {
				tr.Protocols.SetHTTP2(true)
			} else {
				tr.Protocols.SetHTTP1(true)
			}
			t.Cleanup(tr.CloseIdleConnections)
			body, err := getBody(&http.Client{Transport: tr, Timeout: 5 * time.Second}, "http://allowed.test/")
			require.NoError(t, err)
			assert.Equal(t, "ok", body)
		})
	}
}

func TestLifecycle_DrainSendsALateHTTP2ConnectionItsGoaway(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("allowed.test/", okHandler)
	conn, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer conn.Close()
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	go func() { _ = p.Shutdown(ctx) }()
	time.Sleep(200 * time.Millisecond)

	// The preface reaches the HTTP/2 server after the drain shut it down.
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	_, err = io.WriteString(conn, http2.ClientPreface)
	require.NoError(t, err)
	fr := http2.NewFramer(conn, conn)
	require.NoError(t, fr.WriteSettings())
	for {
		f, err := fr.ReadFrame()
		require.NoError(t, err, "the late HTTP/2 connection got no GOAWAY")
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			_ = fr.WriteSettingsAck()
		}
		if _, ok := f.(*http2.GoAwayFrame); ok {
			return
		}
	}
}

func TestServe_SilentConnectionEndsAtTheReadHeaderTimeout(t *testing.T) {
	p := testProxy(t, WithReadHeaderTimeout(500*time.Millisecond))
	conn, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer conn.Close()
	start := time.Now()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, _ = conn.Read(make([]byte, 1))
	assert.Less(t, time.Since(start), 800*time.Millisecond)
}

// emfileListener fails its first Accept with EMFILE.
type emfileListener struct {
	net.Listener
	failed atomic.Bool
}

func (l *emfileListener) Accept() (net.Conn, error) {
	if !l.failed.Swap(true) {
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	}
	return l.Listener.Accept()
}

func TestServe_FrontOutlivesTheFileDescriptorLimit(t *testing.T) {
	for _, serve := range []struct {
		run   func(p *Proxy, ln net.Listener) error
		name  string
		hello string
	}{
		{(*Proxy).Serve, "explicit", "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n"},
		{(*Proxy).ServeSOCKS5, "SOCKS5", "\x05\x01\x00"},
	} {
		t.Run(serve.name, func(t *testing.T) {
			p := testProxy(t)
			p.MustAdd("allowed.test/", okHandler)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			served := make(chan error, 1)
			go func() { served <- serve.run(p, &emfileListener{Listener: ln}) }()
			t.Cleanup(func() { _ = p.Close() })
			select {
			case err := <-served:
				t.Fatalf("Serve returned on a temporary accept error: %v", err)
			case <-time.After(300 * time.Millisecond):
			}
			conn, err := net.Dial("tcp", ln.Addr().String())
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
			_, err = io.WriteString(conn, serve.hello)
			require.NoError(t, err)
			_, err = conn.Read(make([]byte, 1))
			require.NoError(t, err, "the listener no longer serves")
		})
	}
}

func TestLifecycle_DrainEndsAFrontConnectionThatSentNothing(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("allowed.test/", okHandler)
	addr := startProxy(t, p)
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	err = p.Shutdown(ctx)
	require.NoError(t, err, "an idle connection to an HTTP front ends with the drain")
}

func TestServe_CallerTLS12ListenerSendsItsCloseNotifyFirst(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("allowed.test/", okHandler)
	cert, err := p.cfg.ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln := tls.NewListener(inner, &tls.Config{Certificates: []tls.Certificate{*cert}, MaxVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	go func() { _ = p.Serve(ln) }()
	t.Cleanup(func() { _ = p.Close() })
	raw, err := net.Dial("tcp", inner.Addr().String())
	require.NoError(t, err)
	rec := &recordingConn{Conn: raw}
	conn := tls.Client(rec, &tls.Config{ServerName: "127.0.0.1", RootCAs: p.cfg.ca.CertPool(), NextProtos: []string{"http/1.1"}, MaxVersion: tls.VersionTLS12})
	require.NoError(t, conn.Handshake())
	defer conn.Close()
	_, err = io.WriteString(conn, "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	start := time.Now()
	go func() { _ = p.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
	require.Less(t, time.Since(start), 500*time.Millisecond, "the close_notify of a normal end comes first")
	assert.Equal(t, byte(tlsAlert), rec.lastRecord(), "the connection ended without a close_notify")
}

func TestLifecycle_DrainEndsATLSFrontConnectionThatBeganNoRequest(t *testing.T) {
	for _, rht := range []time.Duration{10 * time.Second, 0} {
		t.Run(rht.String(), func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			p := testProxyWithCA(t, ca, WithReadHeaderTimeout(rht))
			p.MustAdd("allowed.test/", okHandler)
			addr, pool := startProxyTLS(t, p, ca)
			conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}})
			require.NoError(t, err)
			defer conn.Close()
			time.Sleep(100 * time.Millisecond)
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			start := time.Now()
			err = p.Shutdown(ctx)
			require.NoError(t, err)
			// The drain ends it T after the start, and its normal end waits up to T for the FIN of
			// a client that reads nothing.
			require.Less(t, time.Since(start), 2*alertWriteTimeout+500*time.Millisecond)
		})
	}
}

func TestLifecycle_DrainEndsATerminatedConnectionThatBeganNoRequest(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	p.MustAdd("allowed.test/", okHandler)
	client, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer client.Close()
	_, err = io.WriteString(client, "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
	require.NoError(t, err)
	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tc := tls.Client(client, &tls.Config{RootCAs: ca.CertPool(), ServerName: "allowed.test", NextProtos: []string{"http/1.1"}})
	require.NoError(t, tc.Handshake())
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	start := time.Now()
	err = p.Shutdown(ctx)
	require.NoError(t, err)
	// T to begin a request, then the normal end, its read and discard bounded by T.
	require.Less(t, time.Since(start), 2*alertWriteTimeout+alertWriteTimeout/2)
}

func TestLifecycle_ConcurrentShutdownsReturnOnceDrained(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("allowed.test/", okHandler)
	addr := startProxy(t, p)
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	type res struct {
		err error
		d   time.Duration
	}
	out := make(chan res, 2)
	start := time.Now()
	for range 2 {
		go func() {
			err := p.Shutdown(ctx)
			out <- res{err, time.Since(start)}
		}()
	}
	for range 2 {
		r := <-out
		require.NoError(t, r.err)
		require.Less(t, r.d, 3*time.Second)
	}
}

func TestLifecycle_DrainEndsAnIdleHTTP3ConnectionAfterItsGOAWAY(t *testing.T) {
	dials := map[string]func(t *testing.T, p *Proxy, ca *CA) *quic.Conn{
		"front": func(t *testing.T, p *Proxy, ca *CA) *quic.Conn {
			front, _ := startQUICFront(t, p, ca)
			pc, err := loopbackUDP()
			require.NoError(t, err)
			t.Cleanup(func() { _ = pc.Close() })
			qc, err := quic.Dial(t.Context(), pc, net.UDPAddrFromAddrPort(front),
				&tls.Config{ServerName: "127.0.0.1", RootCAs: poolOf(ca), NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
				&quic.Config{MaxIdleTimeout: 10 * time.Second, HandshakeIdleTimeout: 3 * time.Second, EnableDatagrams: true})
			require.NoError(t, err)
			return qc
		},
		"terminated": func(t *testing.T, p *Proxy, ca *CA) *quic.Conn {
			p.MustAdd(h3Authority+"/", okHandler)
			return dialRawQUIC(t, startQUIC(t, p), ca, "h3")
		},
	}
	for name, dial := range dials {
		t.Run(name, func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			p, err := New(WithCA(ca))
			require.NoError(t, err)
			qc := dial(t, p, ca)
			t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
			hc, err := newH3Conn(qc)
			require.NoError(t, err)
			select {
			case <-hc.settings:
			case <-time.After(3 * time.Second):
				t.Fatal("no SETTINGS")
			}

			shut := make(chan error, 1)
			start := time.Now()
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()
				shut <- p.Shutdown(ctx)
			}()
			select {
			case <-hc.goaway:
			case <-time.After(3 * time.Second):
				t.Fatal("no GOAWAY")
			}
			select {
			case <-qc.Context().Done():
			case <-time.After(3 * alertWriteTimeout):
				t.Fatalf("the idle connection is still open %v after the start of the drain", time.Since(start))
			}
			assert.GreaterOrEqual(t, time.Since(start), alertWriteTimeout, "a request accepted before the GOAWAY has T to reach its handler")
			appErr, ok := errors.AsType[*quic.ApplicationError](context.Cause(qc.Context()))
			require.True(t, ok, "the connection ended with %v", context.Cause(qc.Context()))
			assert.Equal(t, quic.ApplicationErrorCode(http3.ErrCodeNoError), appErr.ErrorCode)
			assert.True(t, appErr.Remote)
			require.NoError(t, <-shut)
		})
	}
}

func TestLifecycle_DrainServesAnHTTP3RequestPastTheIdleEnd(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	resolver := &fakeResolver{addrs: map[string][]netip.Addr{h3Authority: {netip.MustParseAddr("127.0.0.1")}}}
	p, err := New(WithCA(ca), WithNameResolver(resolver))
	require.NoError(t, err)
	started := make(chan struct{})
	p.MustAdd(h3Authority+"/+{any}", func(c *HTTPCtx) (*http.Response, error) {
		close(started)
		time.Sleep(2*alertWriteTimeout + 500*time.Millisecond)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("served"))}, nil
	})
	front, _ := startQUICFront(t, p, ca)
	cc := masqueClient(t, front, ca)
	type result struct {
		body string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		body, gerr := getThrough(cc, "https://"+h3Authority+"/slow")
		done <- result{body, gerr}
	}()
	<-started
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	go func() { _ = p.Shutdown(ctx) }()
	r := <-done
	require.NoError(t, r.err)
	assert.Equal(t, "served", r.body)
}

func TestServe_CallerTLSListenerSessionContextEnds(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	got := make(chan context.Context, 1)
	p.MustAdd("svc.test/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		got <- c.Session().Context()
		return Text(200, "ok"), nil
	})
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{*cert}})) }()
	t.Cleanup(func() { _ = p.Close() })
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{ServerName: "127.0.0.1", RootCAs: ca.CertPool()})
	require.NoError(t, err)
	_, err = fmt.Fprintf(conn, "GET http://svc.test/ HTTP/1.1\r\nHost: svc.test\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	ctx := <-got
	_ = conn.Close()
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the session context outlived its connection")
	}
}

func TestServeQUIC_ConnectionReachingTheDrainedServerGetsItsGOAWAY(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	front, _ := startQUICFront(t, p, ca)
	// The shared server is shut down as the drain does, before this connection reaches it.
	require.NoError(t, p.srv.h3.Shutdown(t.Context()))

	pc, err := loopbackUDP()
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	qc, err := quic.Dial(t.Context(), pc, net.UDPAddrFromAddrPort(front),
		&tls.Config{ServerName: "127.0.0.1", RootCAs: poolOf(ca), NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
		&quic.Config{MaxIdleTimeout: 10 * time.Second, HandshakeIdleTimeout: 3 * time.Second, EnableDatagrams: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	hc, err := newH3Conn(qc)
	require.NoError(t, err)
	select {
	case <-hc.goaway:
	case <-qc.Context().Done():
		t.Fatalf("the connection ended with %v and no GOAWAY", context.Cause(qc.Context()))
	case <-time.After(3 * time.Second):
		t.Fatal("no GOAWAY")
	}
}

func TestServeQUIC_TerminatedConnectionReachingTheDrainedServerGetsItsGOAWAY(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd(h3Authority+"/", okHandler)
	addr := startQUIC(t, p)
	first := dialRawQUIC(t, addr, ca, "h3")
	_, err = newH3Conn(first)
	require.NoError(t, err)
	var d *quicDemux
	p.srv.mu.Lock()
	for q := range p.srv.quics {
		d = q
	}
	p.srv.mu.Unlock()
	require.NotNil(t, d)
	d.mu.Lock()
	h3 := d.h3
	d.mu.Unlock()
	require.NotNil(t, h3)
	// The shared server is shut down as the drain does, before the next connection reaches it.
	require.NoError(t, first.CloseWithError(0, ""))
	require.NoError(t, h3.Shutdown(t.Context()))

	qc := dialRawQUIC(t, addr, ca, "h3")
	hc, err := newH3Conn(qc)
	require.NoError(t, err)
	select {
	case <-hc.goaway:
	case <-qc.Context().Done():
		t.Fatalf("the connection ended with %v and no GOAWAY", context.Cause(qc.Context()))
	case <-time.After(3 * time.Second):
		t.Fatal("no GOAWAY")
	}
}

func TestLifecycle_HeaderTimeoutLeavesNoConnectionRecorded(t *testing.T) {
	p := testProxy(t, WithReadHeaderTimeout(200*time.Millisecond))
	p.MustAdd("allowed.test/", okHandler)
	addr := startProxy(t, p)
	for range 20 {
		c, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		defer c.Close()
	}
	time.Sleep(1500 * time.Millisecond)
	p.srv.mu.Lock()
	fronts := len(p.srv.fronts)
	p.srv.mu.Unlock()
	require.Zero(t, fronts)
	require.Zero(t, countFresh(p), "a connection the proxy ended is still recorded in fresh")
}

func TestLifecycle_DrainServesARequestWhoseHeaderStraddlesT(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("allowed.test/", okHandler)
	addr := startProxy(t, p)
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()
	_, err = io.WriteString(conn, "GET http://allowed.test/ HTTP/1.1\r\n")
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	shut := make(chan error, 1)
	go func() { shut <- p.Shutdown(ctx) }()
	time.Sleep(alertWriteTimeout + 300*time.Millisecond)
	_, err = io.WriteString(conn, "Host: allowed.test\r\n\r\n")
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err, "a request is served when its first bytes arrived before the drain")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, resp.Close)
	require.NoError(t, <-shut)
}

// countFresh counts the connections the drain would end for having read no byte.
func countFresh(p *Proxy) int {
	n := 0
	p.srv.fresh.Range(func(_, _ any) bool { n++; return true })
	return n
}

func TestLifecycle_DrainGivesAnIdleTLSConnectionItsNormalEnd(t *testing.T) {
	t.Run("front", func(t *testing.T) {
		ca, err := GenerateCA()
		require.NoError(t, err)
		p := testProxyWithCA(t, ca)
		p.MustAdd("allowed.test/", okHandler)
		addr, pool := startProxyTLS(t, p, ca)
		conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}})
		require.NoError(t, err)
		defer conn.Close()
		time.Sleep(100 * time.Millisecond)
		ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
		defer cancel()
		go func() { _ = p.Shutdown(ctx) }()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, rerr := conn.Read(make([]byte, 1))
		assert.ErrorIs(t, rerr, io.EOF, "the client reads a close_notify")
	})
	t.Run("terminated", func(t *testing.T) {
		ca, err := GenerateCA()
		require.NoError(t, err)
		p := testProxyWithCA(t, ca)
		p.MustAdd("allowed.test/", okHandler)
		client, err := net.Dial("tcp", startProxy(t, p))
		require.NoError(t, err)
		defer client.Close()
		_, err = io.WriteString(client, "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
		require.NoError(t, err)
		br := bufio.NewReader(client)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		tc := tls.Client(client, &tls.Config{RootCAs: ca.CertPool(), ServerName: "allowed.test", NextProtos: []string{"http/1.1"}})
		require.NoError(t, tc.Handshake())
		time.Sleep(100 * time.Millisecond)
		ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
		defer cancel()
		go func() { _ = p.Shutdown(ctx) }()
		_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, rerr := tc.Read(make([]byte, 1))
		assert.ErrorIs(t, rerr, io.EOF, "the client reads a close_notify")
	})
}

func TestLifecycle_DrainServesATerminatedRequestWhoseHeaderStraddlesT(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	p.MustAdd("allowed.test/", okHandler)
	client, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer client.Close()
	_, err = io.WriteString(client, "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tc := tls.Client(client, &tls.Config{RootCAs: ca.CertPool(), ServerName: "allowed.test", NextProtos: []string{"http/1.1"}})
	require.NoError(t, tc.Handshake())
	_, err = io.WriteString(tc, "GET / HTTP/1.1\r\n")
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	shut := make(chan error, 1)
	go func() { shut <- p.Shutdown(ctx) }()
	time.Sleep(alertWriteTimeout + 300*time.Millisecond)
	_, err = io.WriteString(tc, "Host: allowed.test\r\n\r\n")
	require.NoError(t, err)
	require.NoError(t, tc.SetReadDeadline(time.Now().Add(3*time.Second)))
	resp, err = http.ReadResponse(bufio.NewReader(tc), nil)
	require.NoError(t, err, "a request is served when its first bytes arrived before the drain")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, <-shut)
}

func TestLifecycle_ShutdownWaitsForAConnectionAcceptedAtItsStart(t *testing.T) {
	var once sync.Once
	started := make(chan struct{})
	acceptedHook = func() {
		once.Do(func() {
			close(started)
			time.Sleep(300 * time.Millisecond)
		})
	}
	defer func() { acceptedHook = nil }()
	p := testProxy(t)
	p.MustAdd("allowed.test/", okHandler)
	addr := startProxy(t, p)
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()
	<-started
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	start := time.Now()
	require.NoError(t, p.Shutdown(ctx))
	returned := time.Since(start)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, err = conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
	ended := time.Since(start)
	require.GreaterOrEqual(t, returned, ended-50*time.Millisecond, "Shutdown returned before the front connection ended")
}

func TestLifecycle_DrainServesAnHTTP3FrontConnectionInItsHandshake(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	p.MustAdd("allowed.test/", okHandler)
	addr, _ := startQUICFront(t, p, ca)

	udp, err := loopbackUDP()
	require.NoError(t, err)
	defer udp.Close()
	pc := &heldPC{PacketConn: udp, release: time.Now().Add(400 * time.Millisecond)}
	type result struct {
		status int
		err    error
	}
	res := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(addr), &tls.Config{
			RootCAs: poolOf(ca), ServerName: "127.0.0.1", NextProtos: []string{http3.NextProtoH3}, MinVersion: tls.VersionTLS13,
		}, &quic.Config{EnableDatagrams: true})
		if err != nil {
			res <- result{err: err}
			return
		}
		defer conn.CloseWithError(0, "")
		tr := &http3.Transport{}
		cc := tr.NewClientConn(conn)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://allowed.test/", nil)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			res <- result{err: err}
			return
		}
		_ = resp.Body.Close()
		res <- result{status: resp.StatusCode}
	}()
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	require.NoError(t, p.Shutdown(ctx))
	r := <-res
	require.NoError(t, r.err, "a front connection is served when its handshake began before the drain")
	assert.Equal(t, http.StatusOK, r.status)
}

func TestLifecycle_DrainServesAnHTTP3FrontConnectionThatReachesItsServerLate(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	p.MustAdd("allowed.test/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		d, _ := time.ParseDuration(strings.TrimPrefix(c.Request().URL.Path, "/"))
		time.Sleep(d)
		return Text(http.StatusOK, "ok"), nil
	})
	h1addr := startProxy(t, p)
	addr, _ := startQUICFront(t, p, ca)

	h1done := make(chan error, 1)
	go func() {
		resp, err := proxyClient(h1addr, nil).Get("http://allowed.test/900ms")
		if err == nil {
			_ = resp.Body.Close()
		}
		h1done <- err
	}()

	udp, err := loopbackUDP()
	require.NoError(t, err)
	defer udp.Close()
	pc := &heldPC{PacketConn: udp, release: time.Now().Add(300 * time.Millisecond)}
	type result struct {
		status int
		err    error
		at     time.Time
	}
	res := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(addr), &tls.Config{
			RootCAs: poolOf(ca), ServerName: "127.0.0.1", NextProtos: []string{http3.NextProtoH3}, MinVersion: tls.VersionTLS13,
		}, &quic.Config{EnableDatagrams: true})
		if err != nil {
			res <- result{err: err, at: time.Now()}
			return
		}
		defer conn.CloseWithError(0, "")
		cc := (&http3.Transport{}).NewClientConn(conn)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://allowed.test/1200ms", nil)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			res <- result{err: err, at: time.Now()}
			return
		}
		_, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		res <- result{status: resp.StatusCode, err: err, at: time.Now()}
	}()
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, p.Shutdown(ctx))
	require.NoError(t, <-h1done)
	r := <-res
	require.NoError(t, r.err, "an HTTP/3 connection that reached its server after the start drains")
	assert.Equal(t, http.StatusOK, r.status)
}

// heldPC delays every packet after the first until release, which stretches a handshake.
type heldPC struct {
	net.PacketConn
	n       atomic.Int32
	release time.Time
}

func (d *heldPC) WriteTo(b []byte, addr net.Addr) (int, error) {
	if d.n.Add(1) > 1 {
		if w := time.Until(d.release); w > 0 {
			time.Sleep(w)
		}
	}
	return d.PacketConn.WriteTo(b, addr)
}

func TestLifecycle_CutResetsAnHTTP3RequestNoHandlerProcessed(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	resolver := &fakeResolver{addrs: map[string][]netip.Addr{h3Authority: {netip.MustParseAddr("127.0.0.1")}}}
	p, err := New(WithCA(ca), WithNameResolver(resolver))
	require.NoError(t, err)
	p.MustAdd(h3Authority+"/+{any}", okHandler)
	front, _ := startQUICFront(t, p, ca)
	cc := masqueClient(t, front, ca)
	// A cut refuses every request read after its start.
	p.srv.requests.cutAll()
	_, err = getThrough(cc, "https://"+h3Authority+"/")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "H3_INTERNAL_ERROR", "quic-go gives a reset before the response header no other code")
}

func TestLifecycle_DrainServesTheFirstRequestOfALateHTTP2Connection(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("allowed.test/", okHandler)
	conn, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer conn.Close()
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	go func() { _ = p.Shutdown(ctx) }()
	time.Sleep(200 * time.Millisecond)

	// The preface and the first request reach the HTTP/2 server after the drain shut it down.
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	_, err = io.WriteString(conn, http2.ClientPreface)
	require.NoError(t, err)
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	require.NoError(t, fr.WriteSettings())
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodGet},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: "allowed.test"},
		{Name: ":path", Value: "/"},
	} {
		require.NoError(t, enc.WriteField(f))
	}
	require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: buf.Bytes(), EndHeaders: true, EndStream: true}))
	for {
		f, err := fr.ReadFrame()
		require.NoError(t, err, "the late HTTP/2 connection ended before its request was answered")
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.MetaHeadersFrame:
			assert.Equal(t, "200", f.PseudoValue("status"))
			return
		case *http2.GoAwayFrame:
			require.GreaterOrEqual(t, f.LastStreamID, uint32(1), "the GOAWAY refused the first request")
		}
	}
}

func TestServe_ReadHeaderTimeoutCountsFromTheAccept(t *testing.T) {
	p := testProxy(t, WithReadHeaderTimeout(500*time.Millisecond))
	p.MustAdd("allowed.test/", okHandler)
	conn, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer conn.Close()
	time.Sleep(400 * time.Millisecond)
	_, err = io.WriteString(conn, "G")
	require.NoError(t, err)
	time.Sleep(400 * time.Millisecond)
	_, _ = io.WriteString(conn, "ET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err == nil {
		assert.NotEqual(t, http.StatusOK, resp.StatusCode, "a request header of 800 ms was read under a read header timeout of 500 ms")
	}
}

func TestShutdown_DeadlineReportedWithADatagramFlow(t *testing.T) {
	lost := 0
	const runs = 12
	for range runs {
		origin := udpEchoOrigin(t)
		p, err := New()
		require.NoError(t, err)
		p.MustAdd[UDP](origin.String(), func(c *DatagramCtx) error { return c.Forward() })
		_, proxyAddr := startTProxyQUIC(t, p, origin)
		client, _ := udpClient(t)
		sendTo(t, client, proxyAddr, "x")
		_, err = readDatagram(t, client, 3*time.Second)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		err = p.Shutdown(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			lost++
			t.Logf("Shutdown returned %v after its deadline cut the drain", err)
		}
	}
	if lost > 0 {
		t.Errorf("%d of %d Shutdown calls did not report the deadline that cut them", lost, runs)
	}
}

func TestLifecycle_AdmissionDuringACutIsAFailedEnd(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	p.MustAdd[TCP]("svc.test:443", noopStream)
	inFlight := make(chan struct{})
	p.MustAdd("slow.test/", func(c *HTTPCtx) (*http.Response, error) {
		close(inFlight)
		time.Sleep(900 * time.Millisecond)
		return Text(http.StatusOK, "ok"), nil
	})
	addr := startProxy(t, p)
	conn := connectRaw(t, addr, "svc.test:443")
	go func() { _, _ = proxyClient(addr, nil).Get("http://slow.test/") }()
	<-inFlight
	closed := make(chan struct{})
	go func() { _ = p.Close(); close(closed) }()
	time.Sleep(100 * time.Millisecond)
	tc := tls.Client(conn, &tls.Config{ServerName: "svc.test", RootCAs: ca.CertPool(), NextProtos: []string{"http/1.1"}})
	require.NoError(t, tc.SetDeadline(time.Now().Add(5*time.Second)))
	herr := tc.Handshake()
	var rerr error
	if herr == nil {
		_, rerr = tc.Read(make([]byte, 1))
	}
	t.Logf("handshake %v, read %v", herr, rerr)
	<-closed
	if herr == nil && errors.Is(rerr, io.EOF) {
		t.Errorf("an admission refused by the cut ended with a close_notify, the normal end of TLS")
	}
}

func http3RequestInFlightEnd(t *testing.T, viaSession bool) error {
	ca, err := GenerateCA()
	require.NoError(t, err)
	resolver := &fakeResolver{addrs: map[string][]netip.Addr{h3Authority: {netip.MustParseAddr("127.0.0.1")}}}
	p, err := New(WithCA(ca), WithNameResolver(resolver))
	require.NoError(t, err)
	began := make(chan *Session, 1)
	p.MustAdd(h3Authority+"/+{any}", func(c *HTTPCtx) (*http.Response, error) {
		began <- c.Session()
		time.Sleep(2500 * time.Millisecond)
		return Status(http.StatusOK), nil
	})
	front, _ := startQUICFront(t, p, ca)
	cc := masqueClient(t, front, ca)
	errc := make(chan error, 1)
	go func() {
		_, err := getThrough(cc, "https://"+h3Authority+"/slow")
		errc <- err
	}()
	sess := <-began
	start := time.Now()
	if viaSession {
		go func() { _ = sess.Close() }()
	} else {
		go func() { _ = p.Close() }()
	}
	err = <-errc
	t.Logf("client error after %v: %v", time.Since(start), err)
	return err
}

func TestLifecycle_CutFailsAnHTTP3ConnectionWithARequestInFlight(t *testing.T) {
	err := http3RequestInFlightEnd(t, false)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "H3_NO_ERROR", "the connection got its normal end with a request in flight")
}

func TestLifecycle_SessionCloseFailsAnHTTP3ConnectionWithARequestInFlight(t *testing.T) {
	err := http3RequestInFlightEnd(t, true)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "H3_NO_ERROR", "the connection got its normal end with a request in flight")
}

func TestServer_ReadHeaderTimeoutFailsAFrontConnection(t *testing.T) {
	for _, sent := range []string{"", "GET http://allowed.test/ HTTP/1.1\r\n"} {
		t.Run(strconv.Quote(sent), func(t *testing.T) {
			p := testProxy(t, WithReadHeaderTimeout(300*time.Millisecond))
			p.MustAdd("allowed.test/", okHandler)
			conn, err := net.Dial("tcp", startProxy(t, p))
			require.NoError(t, err)
			defer conn.Close()
			_, _ = io.WriteString(conn, sent)
			got := peerEnd(conn, 3*time.Second)
			t.Logf("client read %s", got)
			require.Equal(t, "RST", got, "the read header timeout is a failed end, docs/lifecycle.md Timers")
		})
	}
}

func TestShutdown_ReportsACutCloseStarted(t *testing.T) {
	p := testProxy(t)
	began := make(chan struct{}, 1)
	p.MustAdd("allowed.test/", func(c *HTTPCtx) (*http.Response, error) {
		began <- struct{}{}
		time.Sleep(3 * time.Second)
		return Status(http.StatusOK), nil
	})
	conn, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer conn.Close()
	_, err = io.WriteString(conn, "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	require.NoError(t, err)
	<-began
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res := make(chan error, 1)
	go func() { res <- p.Shutdown(ctx) }()
	time.Sleep(500 * time.Millisecond)
	go func() { _ = p.Close() }()
	err = <-res
	t.Logf("Shutdown returned %v", err)
	require.ErrorIs(t, err, ErrProxyClosed, "Close started the cut")
	require.NotErrorIs(t, err, context.DeadlineExceeded, "the context did not start the cut")
}

func TestServer_LateHTTP2ServerOfAConnectionWithNoPreface(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	addr, pool := startProxyTLS(t, p, ca)
	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	res := make(chan error, 1)
	go func() { res <- p.Shutdown(ctx) }()
	time.Sleep(200 * time.Millisecond)
	tc := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", NextProtos: []string{"h2"}})
	require.NoError(t, tc.Handshake())
	require.Equal(t, "h2", tc.ConnectionState().NegotiatedProtocol)
	_ = tc.Close()
	t.Logf("Shutdown returned %v", <-res)
	time.Sleep(2 * time.Second)
	buf := make([]byte, 1<<20)
	stacks := string(buf[:runtime.Stack(buf, true)])
	n := strings.Count(stacks, "edge.(*Proxy).serveLate")
	if n > 0 {
		i := strings.Index(stacks, "edge.(*Proxy).serveLate")
		t.Logf("%s", stacks[max(0, i-1500):min(len(stacks), i+300)])
	}
	require.Zero(t, n, "a per-connection server outlived the proxy")
}

func TestLifecycle_CutWaitsForADatagramHandler(t *testing.T) {
	origin := udpEchoOrigin(t)
	p := testProxy(t)
	entered := make(chan struct{}, 1)
	var finished atomic.Bool
	p.MustAdd[UDP](origin.Addr().String(), func(c *DatagramCtx) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		time.Sleep(300 * time.Millisecond)
		finished.Store(true)
		return nil
	})
	addr := startQUICRedirected(t, p, origin)
	client, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(addr))
	require.NoError(t, err)
	defer client.Close()
	_, err = client.Write([]byte("x"))
	require.NoError(t, err)
	<-entered
	start := time.Now()
	require.NoError(t, p.Close())
	t.Logf("Close returned after %v, handler finished before: %v", time.Since(start), finished.Load())
	if !finished.Load() {
		t.Errorf("the cut returned while a datagram handler it did not wait for still ran")
	}
}

func TestLifecycle_CutSkipsARawQUICHandlerSessionCloseEnded(t *testing.T) {
	originCA, err := GenerateCA()
	require.NoError(t, err)
	origin, _ := rawQUICOrigin(t, originCA, h3Authority)
	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.RootCAs = poolOf(originCA)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	entered := make(chan struct{})
	p.MustAdd[QUIC](h3Authority, func(c *QUICCtx) error {
		close(entered)
		time.Sleep(3 * time.Second)
		return nil
	})
	dialRawQUIC(t, startQUICRedirected(t, p, origin), ca, "raw")
	<-entered
	require.NoError(t, waitForSessions(t, p, 1)[0].Close())
	start := time.Now()
	require.NoError(t, p.Close())
	t.Logf("Proxy.Close after a Session.Close returned in %v", time.Since(start))
}

func TestServer_FirstRequestBodyOutlivesTheReadHeaderTimeout(t *testing.T) {
	p := testProxy(t, WithReadHeaderTimeout(300*time.Millisecond))
	got := make(chan string, 1)
	p.MustAdd("allowed.test/", func(c *HTTPCtx) (*http.Response, error) {
		b, err := io.ReadAll(c.Request().Body)
		if err != nil {
			got <- string(b) + ": " + err.Error()
		} else {
			got <- string(b)
		}
		return Text(http.StatusOK, "done"), nil
	})
	conn, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer conn.Close()
	_, err = io.WriteString(conn, "POST http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 10\r\n\r\nhello")
	require.NoError(t, err)
	time.Sleep(700 * time.Millisecond)
	_, err = io.WriteString(conn, "world")
	require.NoError(t, err)
	require.Equal(t, "helloworld", <-got, "the read header timeout cut the body of the first request")
}

func TestServer_IdleFrontConnectionGetsItsNormalEnd(t *testing.T) {
	for _, how := range []string{"drain", "cut"} {
		t.Run(how, func(t *testing.T) {
			p := testProxy(t)
			c, err := net.Dial("tcp", startProxy(t, p))
			require.NoError(t, err)
			t.Cleanup(func() { _ = c.Close() })
			time.Sleep(100 * time.Millisecond)
			if how == "drain" {
				go func() { _ = p.Shutdown(context.Background()) }()
				time.Sleep(3 * time.Second)
			} else {
				require.NoError(t, p.Close())
				time.Sleep(2 * time.Second)
			}
			// The client reads once the proxy's end is over.
			require.Equal(t, "FIN", peerEnd(c, 2*time.Second), "a front connection that began no request got no normal end")
		})
	}
}

func TestServer_HijackedFrontStaysRegisteredUntilItsOwnerRegisters(t *testing.T) {
	p, err := New()
	require.NoError(t, err)
	s := p.srv
	count := func(g *gauge) int64 {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.n
	}
	c, peer := net.Pipe()
	defer peer.Close()
	defer c.Close()
	require.True(t, s.addFront(c))
	s.trackFront(c, http.StateHijacked)
	require.EqualValues(t, 1, count(&s.frontsLive), "the hijack took the socket off the fronts before its owner registered")
	require.True(t, s.takeFront(c, c))
	require.EqualValues(t, 0, count(&s.frontsLive))
	require.EqualValues(t, 1, count(&s.tracked))
	s.untrack(c)
}

func TestServer_ReadHeaderTimeoutFailsATLSFrontConnection(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxy(t, WithCA(ca), WithReadHeaderTimeout(300*time.Millisecond))
	p.MustAdd("allowed.test/", okHandler)
	conn := dialFront(t, startTLSFront(t, p, ca, "http/1.1"), ca, "http/1.1")
	defer conn.Close()
	_, err = io.WriteString(conn, "GET http://allowed.test/ HTTP/1.1\r\n")
	require.NoError(t, err)
	require.Equal(t, "RST", peerEnd(conn, 3*time.Second), "the read header timeout is a failed end, with no close_notify")
}

func TestShutdown_ServesTheFirstRequestOfAFrontConnectionThatReachedItsServerDuringTheDrain(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca, WithReadHeaderTimeout(6*time.Second))
	p.MustAdd("allowed.test/", okHandler)
	addr, pool := startProxyTLS(t, p, ca)
	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	time.Sleep(100 * time.Millisecond)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	}()
	// The handshake ends T/2 after the start, and the first request begins 0.7T after it,
	// past T after the start and within T of reaching the server.
	time.Sleep(alertWriteTimeout / 2)
	require.NoError(t, conn.Handshake())
	time.Sleep(alertWriteTimeout * 7 / 10)
	_, err = io.WriteString(conn, "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestShutdown_ServesAFrontRequestWhoseHeaderEndsPastTAfterItsHandshake(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca, WithReadHeaderTimeout(6*time.Second))
	p.MustAdd("allowed.test/", okHandler)
	addr, pool := startProxyTLS(t, p, ca)
	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	time.Sleep(100 * time.Millisecond)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	}()
	time.Sleep(alertWriteTimeout / 2)
	require.NoError(t, conn.Handshake())
	// The request begins 0.8T after the handshake and its header ends 1.2T after it.
	time.Sleep(alertWriteTimeout * 8 / 10)
	_, err = io.WriteString(conn, "GET http://allowed.test/ HTTP/1.1\r\n")
	require.NoError(t, err)
	time.Sleep(alertWriteTimeout * 4 / 10)
	_, err = io.WriteString(conn, "Host: allowed.test\r\n\r\n")
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err, "the request began within T of the handshake")
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestShutdown_ReadHeaderTimeoutBeforeTheEndOfTheDrainFailsAFrontConnection(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca, WithReadHeaderTimeout(time.Second))
	p.MustAdd("allowed.test/", okHandler)
	addr, pool := startProxyTLS(t, p, ca)
	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	time.Sleep(100 * time.Millisecond)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	}()
	time.Sleep(400 * time.Millisecond)
	require.NoError(t, conn.Handshake())
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	_, rerr := conn.Read(make([]byte, 1))
	require.ErrorIs(t, rerr, syscall.ECONNRESET, "the read header timeout came first, a failed end")
}

// plainFrontRequestStraddlingTheDrain sends first 0.3T after the start of a drain and rest T
// later, and requires the response of the request they make.
func plainFrontRequestStraddlingTheDrain(t *testing.T, first, rest string) {
	p := testProxy(t, WithReadHeaderTimeout(6*time.Second))
	p.MustAdd("allowed.test/", okHandler)
	conn, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer conn.Close()
	time.Sleep(100 * time.Millisecond)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	}()
	// The request begins 0.3T after the start and goes on 1.3T after it.
	time.Sleep(alertWriteTimeout * 3 / 10)
	_, err = io.WriteString(conn, first)
	require.NoError(t, err)
	time.Sleep(alertWriteTimeout)
	_, _ = io.WriteString(conn, rest)
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err, "the request began within T of the start")
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestShutdown_ServesAPlainFrontRequestWhoseFirstByteCameWithinT(t *testing.T) {
	t.Run("HTTP/1.1 request line", func(t *testing.T) {
		plainFrontRequestStraddlingTheDrain(t, "G", "ET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	})
	t.Run("first byte of the HTTP/2 preface", func(t *testing.T) {
		plainFrontRequestStraddlingTheDrain(t, "P", "OST http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 0\r\n\r\n")
	})
}

func TestShutdown_FirstByteBeforeTheDrainKeepsTheBoundOfItsHeader(t *testing.T) {
	p := testProxy(t, WithReadHeaderTimeout(6*time.Second))
	p.MustAdd("allowed.test/", okHandler)
	conn, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer conn.Close()
	time.Sleep(100 * time.Millisecond)
	// The first byte of the HTTP/2 preface arrives before the start, the rest 1.3T after it.
	_, err = io.WriteString(conn, "P")
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	}()
	time.Sleep(alertWriteTimeout * 13 / 10)
	_, err = io.WriteString(conn, "OST http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 0\r\n\r\n")
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err, "the request began before the start of the drain")
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// delayedWrites delays every write from the from-th one until the time until.
type delayedWrites struct {
	net.Conn
	until time.Time
	n     int
	from  int
}

func (c *delayedWrites) Write(b []byte) (int, error) {
	c.n++
	if c.n >= c.from {
		time.Sleep(time.Until(c.until))
	}
	return c.Conn.Write(b)
}

func TestShutdown_TLSFrontConnectionGetsItsTOnceItsHandshakeEnded(t *testing.T) {
	cases := []struct {
		name  string
		delay time.Duration
		from  int
	}{
		{name: "ClientHello after T", delay: alertWriteTimeout * 13 / 10, from: 1},
		{name: "Finished after T", delay: alertWriteTimeout * 13 / 10, from: 2},
		{name: "handshake within T", delay: alertWriteTimeout / 2, from: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			p := testProxyWithCA(t, ca, WithReadHeaderTimeout(6*time.Second))
			p.MustAdd("allowed.test/", okHandler)
			addr, pool := startProxyTLS(t, p, ca)
			raw, err := net.Dial("tcp", addr)
			require.NoError(t, err)
			defer raw.Close()
			time.Sleep(50 * time.Millisecond)
			start := time.Now().Add(100 * time.Millisecond)
			dw := &delayedWrites{Conn: raw, from: tc.from, until: start.Add(tc.delay)}
			conn := tls.Client(dw, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}})
			hs := make(chan error, 1)
			go func() { hs <- conn.Handshake() }()
			time.Sleep(time.Until(start))
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				_ = p.Shutdown(ctx)
			}()
			require.NoError(t, <-hs)
			_, err = io.WriteString(conn, "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
			require.NoError(t, err)
			_ = raw.SetReadDeadline(time.Now().Add(4 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.NoError(t, err, "the connection reached its server %v after the start", time.Since(start))
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

func TestShutdown_PartialPrefaceOfAnH2FrontConnectionGetsItsGOAWAY(t *testing.T) {
	for _, reachedAfter := range []bool{false, true} {
		t.Run("reached after the start "+strconv.FormatBool(reachedAfter), func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			p := testProxyWithCA(t, ca, WithReadHeaderTimeout(6*time.Second))
			p.MustAdd("allowed.test/", okHandler)
			addr, pool := startProxyTLS(t, p, ca)
			cfg := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}
			shutdown := func() {
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					defer cancel()
					_ = p.Shutdown(ctx)
				}()
			}
			raw, err := net.Dial("tcp", addr)
			require.NoError(t, err)
			defer raw.Close()
			if reachedAfter {
				time.Sleep(50 * time.Millisecond)
				shutdown()
				time.Sleep(300 * time.Millisecond)
			}
			conn := tls.Client(raw, cfg)
			require.NoError(t, conn.Handshake())
			require.Equal(t, "h2", conn.ConnectionState().NegotiatedProtocol)
			// Over TLS, ALPN gave h2, so a preface begins no request.
			_, err = io.WriteString(conn, h2Preface[:16])
			require.NoError(t, err)
			if !reachedAfter {
				time.Sleep(100 * time.Millisecond)
				shutdown()
			}
			start := time.Now()
			_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))
			fr := http2.NewFramer(io.Discard, conn)
			f, err := fr.ReadFrame()
			require.NoError(t, err)
			require.IsType(t, &http2.SettingsFrame{}, f)
			f, err = fr.ReadFrame()
			require.NoError(t, err)
			goAway, ok := f.(*http2.GoAwayFrame)
			require.True(t, ok, "%T", f)
			require.Equal(t, http2.ErrCodeNo, goAway.ErrCode)
			_, err = fr.ReadFrame()
			require.ErrorIs(t, err, io.EOF, "the normal end follows the GOAWAY")
			require.Less(t, time.Since(start), 3*alertWriteTimeout)
		})
	}
}

func TestShutdown_EndsAStalledTLSHandshakeAtTWithNoReadHeaderTimeout(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca, WithReadHeaderTimeout(0))
	p.MustAdd("allowed.test/", okHandler)
	addr, _ := startProxyTLS(t, p, ca)
	// A TCP connection that never sends its ClientHello.
	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer raw.Close()
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	require.NoError(t, p.Shutdown(ctx))
	// The drain ends it T after the start, and its normal end waits up to T for the FIN of a
	// client that reads nothing.
	require.Less(t, time.Since(start), 2*alertWriteTimeout+500*time.Millisecond)
	require.Equal(t, "FIN", peerEnd(raw, time.Second), "the drain gives a connection with no request its normal end")
}

// partialH2Front returns a TLS front connection that negotiated h2 and sent part of its preface.
func partialH2Front(t *testing.T, addr string, pool *x509.CertPool) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.Equal(t, "h2", conn.ConnectionState().NegotiatedProtocol)
	_, err = io.WriteString(conn, h2Preface[:16])
	require.NoError(t, err)
	return conn
}

func TestShutdown_DrainedEndOfAFrontConnectionStaysRegistered(t *testing.T) {
	for _, how := range []string{"Shutdown", "a cut during the drain"} {
		t.Run(how, func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			p := testProxyWithCA(t, ca, WithReadHeaderTimeout(6*time.Second))
			p.MustAdd("allowed.test/", okHandler)
			addr, pool := startProxyTLS(t, p, ca)
			conn := partialH2Front(t, addr, pool)
			time.Sleep(100 * time.Millisecond)
			start := time.Now()
			shut := make(chan error, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				shut <- p.Shutdown(ctx)
			}()
			_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))
			fr := http2.NewFramer(io.Discard, conn)
			_, err = fr.ReadFrame()
			require.NoError(t, err)
			f, err := fr.ReadFrame()
			require.NoError(t, err)
			require.IsType(t, &http2.GoAwayFrame{}, f)
			// It reached its server before the start, so its GOAWAY goes out at the start.
			require.Less(t, time.Since(start), alertWriteTimeout/2)
			if how == "Shutdown" {
				require.NoError(t, <-shut)
			} else {
				closing := time.Now()
				require.NoError(t, p.Close())
				// The front stage waits for the end the drain started within its T, I4.
				require.Less(t, time.Since(closing), alertWriteTimeout+500*time.Millisecond)
			}
			// Shutdown and the cut return once the end they waited for wrote its last byte.
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, err = fr.ReadFrame()
			require.ErrorIs(t, err, io.EOF)
		})
	}
}

func TestShutdown_TLSFrontConnectionRecordedAfterTheStartWithNoReadHeaderTimeout(t *testing.T) {
	var once sync.Once
	accepted := make(chan struct{})
	release := make(chan struct{})
	acceptedHook = func() {
		once.Do(func() {
			close(accepted)
			<-release
		})
	}
	defer func() { acceptedHook = nil }()
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca, WithReadHeaderTimeout(0))
	p.MustAdd("allowed.test/", okHandler)
	addr, _ := startProxyTLS(t, p, ca)
	// Accepted before the start, recorded once endWaiting ran, and silent.
	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer raw.Close()
	<-accepted
	go func() {
		for !p.srv.closing.Load() {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
		close(release)
	}()
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	require.NoError(t, p.Shutdown(ctx))
	require.Less(t, time.Since(start), 2*alertWriteTimeout+500*time.Millisecond)
}

// handshakeInReadConn is a caller's TLS connection with no HandshakeContext, which runs its
// handshake in its first read.
type handshakeInReadConn struct {
	net.Conn
	tc *tls.Conn
}

func (c handshakeInReadConn) ConnectionState() tls.ConnectionState { return c.tc.ConnectionState() }

type handshakeInReadListener struct {
	net.Listener
	cfg *tls.Config
}

func (l handshakeInReadListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc := tls.Server(c, l.cfg)
	return handshakeInReadConn{Conn: tc, tc: tc}, nil
}

func TestShutdown_DrainHoldsNoLockOnAHandshakeInItsFirstRead(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca, WithReadHeaderTimeout(0))
	p.MustAdd("allowed.test/", okHandler)
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		_ = p.Serve(handshakeInReadListener{Listener: ln, cfg: &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"h2", "http/1.1"}}})
	}()
	// A client silent in its handshake.
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer raw.Close()
	time.Sleep(200 * time.Millisecond)
	shut := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		shut <- p.Shutdown(ctx)
	}()
	time.Sleep(100 * time.Millisecond)
	locked := make(chan struct{})
	go func() {
		p.srv.mu.Lock()
		p.srv.mu.Unlock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("the drain kept the server lock while a handshake runs")
	}
	select {
	case err := <-shut:
		require.NoError(t, err)
	case <-time.After(3 * alertWriteTimeout):
		t.Fatal("Shutdown did not return")
	}
}

func TestShutdown_H2FrontConnectionThatReachedItsServerAfterTheStartKeepsItsT(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	p.MustAdd("allowed.test/", okHandler)
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	// The listener closes slowly, so endWaiting runs after the connection reached its server.
	go func() { _ = p.ServeTLS(slowCloseListener{ln}, *cert) }()
	t.Cleanup(func() { _ = p.Close() })
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer raw.Close()
	time.Sleep(100 * time.Millisecond)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	}()
	for !p.srv.closing.Load() {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	conn := tls.Client(raw, &tls.Config{RootCAs: ca.CertPool(), ServerName: "127.0.0.1", NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	require.NoError(t, conn.Handshake())
	require.Equal(t, "h2", conn.ConnectionState().NegotiatedProtocol)
	reached := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	fr := http2.NewFramer(io.Discard, conn)
	_, err = fr.ReadFrame()
	require.NoError(t, err)
	f, err := fr.ReadFrame()
	require.NoError(t, err)
	require.IsType(t, &http2.GoAwayFrame{}, f)
	require.Greater(t, time.Since(reached), alertWriteTimeout*8/10, "the GOAWAY came before T after it reached its server")
}

func TestClose_EndsAFrontConnectionItsWakeDoesNotReach(t *testing.T) {
	p := testProxy(t, WithReadHeaderTimeout(0))
	p.MustAdd("allowed.test/", okHandler)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.Serve(noDeadlineListener{ln}) }()
	t.Cleanup(func() { _ = p.Close() })
	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer c.Close()
	// The first byte of the preface, the rest never comes.
	_, err = io.WriteString(c, "P")
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	closed := make(chan struct{})
	go func() { _ = p.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * alertWriteTimeout):
		t.Fatal("Close did not return")
	}
	assert.Less(t, time.Since(start), alertWriteTimeout+500*time.Millisecond)
}

func TestClose_FrontConnectionDecidedDuringTheUnitsStageEndsWithTheCut(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	started := make(chan struct{}, 1)
	p.MustAdd("allowed.test/", blockingHandler(started, release))
	addr, pool := startProxyTLS(t, p, ca)
	busy, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}})
	require.NoError(t, err)
	defer busy.Close()
	_, err = io.WriteString(busy, "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	require.NoError(t, err)
	<-started
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
	require.NoError(t, err)
	defer conn.Close()

	closed := make(chan struct{})
	go func() { _ = p.Close(); close(closed) }()
	for !p.srv.cutting() {
		time.Sleep(time.Millisecond)
	}
	// The blocked handler keeps the units stage running while the connection shows itself HTTP/2.
	time.Sleep(50 * time.Millisecond)
	_, err = io.WriteString(conn, h2Preface)
	require.NoError(t, err)
	require.NoError(t, http2.NewFramer(conn, nil).WriteSettings())

	_ = conn.SetReadDeadline(time.Now().Add(3 * alertWriteTimeout))
	f, err := http2.NewFramer(io.Discard, conn).ReadFrame()
	require.ErrorIs(t, err, io.EOF, "the connection was served after the start of the cut: %v", f)
	assert.NotZero(t, p.srv.frontStageBy.Load(), "the connection ended before the front stage")
	<-closed
}

func TestShutdown_SecondCallKeepsTheDrainOfTheFirst(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("allowed.test/", okHandler)
	c, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer c.Close()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	shutdown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	}
	go shutdown()
	time.Sleep(alertWriteTimeout * 8 / 10)
	go shutdown()
	_ = c.SetReadDeadline(time.Now().Add(4 * alertWriteTimeout))
	_, err = c.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
	assert.Less(t, time.Since(start), alertWriteTimeout+300*time.Millisecond)
}

func TestClose_LeavesNoFrontConnectionOfAHandlerIgnoringItsCancel(t *testing.T) {
	p := testProxy(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	started := make(chan struct{}, 1)
	p.MustAdd("allowed.test/", blockingHandler(started, release))
	c, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer c.Close()
	_, err = io.WriteString(c, "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	require.NoError(t, err)
	<-started

	require.NoError(t, p.Close())
	p.srv.mu.Lock()
	fronts := len(p.srv.fronts)
	p.srv.mu.Unlock()
	assert.Zero(t, fronts)
}

func TestClose_WaitsForTheDrainedEndOfAFrontConnection(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("allowed.test/", okHandler)
	c, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer c.Close()
	time.Sleep(100 * time.Millisecond)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	}()
	_ = c.SetReadDeadline(time.Now().Add(3 * alertWriteTimeout))
	_, err = io.Copy(io.Discard, c)
	require.NoError(t, err, "the FIN of the drain")
	fin := time.Now()
	time.Sleep(100 * time.Millisecond)
	closing := time.Now()
	closed := make(chan struct{})
	go func() { _ = p.Close(); close(closed) }()
	// The end the drain began reads and discards until its deadline, T after its FIN, so what
	// the client still sends draws no reset.
	time.Sleep(50 * time.Millisecond)
	_, err = c.Write([]byte("x"))
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	_, err = c.Write([]byte("y"))
	require.NoError(t, err)
	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = c.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
	<-closed
	assert.Greater(t, time.Since(fin), alertWriteTimeout*8/10)
	assert.Less(t, time.Since(closing), alertWriteTimeout+500*time.Millisecond)
}

// noDeadlineListener accepts connections that ignore their read deadlines.
type noDeadlineListener struct{ net.Listener }

func (l noDeadlineListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return noDeadlineConn{c}, nil
}

// slowCloseListener takes 300 ms to close.
type slowCloseListener struct{ net.Listener }

func (l slowCloseListener) Close() error {
	time.Sleep(300 * time.Millisecond)
	return l.Listener.Close()
}
