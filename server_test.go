// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
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
			assert.ErrorIs(t, err, ErrProxyClosed)
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
		assert.ErrorIs(t, err, ErrProxyClosed)
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
	target, err := proxyTarget(&http.Request{URL: u, Host: u.Host, ProtoMajor: 1})
	require.NoError(t, err)
	assert.Equal(t, "80", target.Port)

	target, err = proxyTarget(&http.Request{URL: &url.URL{Path: "/x"}, Host: "example.test:08080", ProtoMajor: 2})
	require.NoError(t, err)
	assert.Equal(t, "8080", target.Port)

	_, err = proxyTarget(&http.Request{URL: &url.URL{Path: "/x"}, Host: "example.test:70000", ProtoMajor: 2})
	require.Error(t, err)
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
		assert.ErrorIs(t, err, ErrProxyClosed)
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
		assert.ErrorIs(t, err, ErrProxyClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeTransparentUDP did not return after Shutdown")
	}

	pc2, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = pc2.Close() }()
	assert.ErrorIs(t, p.ServeTransparentUDP(pc2), ErrProxyClosed)
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

	assert.ErrorIs(t, err, context.DeadlineExceeded)
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
	// Registered after Close, so the handler is released before Close waits on it.
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

	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, 3*time.Second, "the deadline must bound Shutdown, not the handler")
	select {
	case err := <-served:
		assert.ErrorIs(t, err, ErrProxyClosed)
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
		assert.ErrorIs(t, err, ErrProxyClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeQUIC did not return after Shutdown")
	}
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
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 3*time.Second, "the deadline must bound Shutdown, not the handler")

	select {
	case <-conn.Context().Done():
		var appErr *quic.ApplicationError
		cause := context.Cause(conn.Context())
		require.ErrorAs(t, cause, &appErr, "the client is told in QUIC terms: %v", cause)
		assert.True(t, appErr.Remote, "the close comes from the proxy: %v", cause)
	case <-time.After(5 * time.Second):
		t.Fatal("the client never learned of the cut")
	}
	select {
	case err := <-served:
		assert.ErrorIs(t, err, ErrProxyClosed)
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
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	p.MustAdd(h3Authority+"/", blockingHandler(started, release))

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
	// Registered after Close, so the handler is released before Close waits on it.
	t.Cleanup(sync.OnceFunc(func() { close(release) }))

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
		require.ErrorAs(t, cause, &appErr, "the client is told in QUIC terms: %v", cause)
		assert.True(t, appErr.Remote, "the close comes from the proxy: %v", cause)
	case <-time.After(5 * time.Second):
		t.Fatal("the client never learned of the cut")
	}
	select {
	case err := <-served:
		assert.ErrorIs(t, err, ErrProxyClosed)
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
	assert.ErrorIs(t, err, context.Canceled)
}

func TestLifecycle_ShutdownExpiredContextCutsTheTransparentHTTP3(t *testing.T) {
	p, served, conn := stuckHTTP3Front(t, true)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := assertCutDoesNotWait(t, served, conn, func() error { return p.Shutdown(ctx) })
	assert.ErrorIs(t, err, context.Canceled)
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
	// Registered after Close, so the handler is released before Close waits on it.
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
		assert.ErrorIs(t, err, ErrProxyClosed)
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

	assert.ErrorIs(t, err, context.DeadlineExceeded)
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
		assert.ErrorIs(t, err, ErrProxyClosed)
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
