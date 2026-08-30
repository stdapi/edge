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
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	p.MustAddInterceptor(nil, originHost(originURL)+"/*{any}", DefaultNoInterceptorHandler)

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
	assert.Contains(t, string(body), "forward proxy")
}

// TestLifecycle_AmbiguousLengthIsNormalized covers a request carrying both a Content-Length
// and a Transfer-Encoding, the classic request smuggling setup.
//
// The proxy does not forward bytes, it parses each request and writes a fresh one upstream.
// A message whose framing is ambiguous is therefore resolved once, by the proxy, and the
// origin sees exactly what the proxy saw. What matters is that nothing crosses without being
// routed: a request the proxy did not account for must not appear at the origin.
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
	p.MustAddInterceptor(nil, originHost(originURL)+"/+{any}", func(c *Context) (*http.Response, error) {
		proxySeen.add(c.Method() + " " + c.RoutingPath())
		return c.Forward()
	})
	p.MustAddInterceptor(nil, originHost(originURL)+"/", func(c *Context) (*http.Response, error) {
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

func TestLifecycle_TunnelOnlyProxyNeedsNoCA(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunneled")
	}))
	defer origin.Close()

	// A proxy that only relays never mints a certificate, so it never needs an authority.
	// It still has to be told what to relay: nothing crosses a proxy that was not asked.
	originURL, _ := url.Parse(origin.URL)
	p, err := New()
	require.NoError(t, err)
	require.Nil(t, p.cfg.ca)
	require.NoError(t, p.AddTunnel(originHost(originURL)))

	addr := startProxy(t, p)
	client := proxyClient(addr, originPool(t, origin))

	resp, err := client.Get(origin.URL + "/")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "tunneled", string(body))
}

// A listener the proxy accepts on itself is only ever closed by Shutdown or Close, so without
// that the accept loop outlives the proxy and keeps taking connections nothing will serve.
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
func blockingHandler(started chan<- struct{}, release <-chan struct{}) HandlerFunc {
	return func(c *Context) (*http.Response, error) {
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
	p.MustAddInterceptor(nil, "example.test/", blockingHandler(started, release))

	addr := startProxy(t, p)
	client := proxyClient(addr, ca.CertPool())

	body := assertShutdownDrains(t, p, started, release, func() (string, error) {
		return getBody(client, "https://example.test/")
	})
	assert.Equal(t, "drained over HTTP/1.1", body)
}

// An HTTP/2 client keeps its connection open until it is told to go away, so this drain only
// converges if the shutdown reaches the connection with a GOAWAY.
func TestLifecycle_ShutdownDrainsInterceptedHTTP2(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	p.MustAddInterceptor(nil, "example.test/", blockingHandler(started, release))

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
	p.MustAddInterceptor(nil, h3Authority+"/", blockingHandler(started, release))

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- p.ServeQUIC(pc) }()
	t.Cleanup(func() { _ = p.Close() })

	proxyAddr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	require.NoError(t, err)

	// dialQUICTo carries a deliberately short idle timeout; a request parked in the handler
	// needs one that outlives the drain.
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: poolOf(ca), MinVersion: tls.VersionTLS13},
		QUICConfig:      &quic.Config{MaxIdleTimeout: 10 * time.Second},
		Dial: func(ctx context.Context, _ string, cfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			udp, err := net.ListenUDP("udp", nil)
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
		t.Fatal("ServeQUIC did not return after Shutdown")
	}
}

// A graceful shutdown that has nothing to drain still has to stop the QUIC side: the read
// loop, the HTTP/3 server and the relays are not tied to a listener http.Server closes.
func TestLifecycle_ShutdownStopsQUIC(t *testing.T) {
	p := testProxy(t)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- p.ServeQUIC(pc) }()

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
		t.Fatal("ServeQUIC did not return after Shutdown")
	}

	pc2, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = pc2.Close() }()
	assert.ErrorIs(t, p.ServeQUIC(pc2), ErrProxyClosed)
}

// A handler that ignores its cancellation cannot hold Shutdown past its deadline. The cut
// only closes sockets and no close can force a handler to return, so the deadline has to
// bound Shutdown itself; what the handler still holds unwinds behind it.
func TestLifecycle_ShutdownDeadlineBoundsAStuckHandler(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	p.MustAddInterceptor(nil, "example.test/", blockingHandler(started, release))

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

// The HTTP/3 shape of the same guarantee: quic-go's own graceful close waits on its
// handlers, so a stuck one wedges the drain goroutine, and only Shutdown racing its
// deadline keeps the caller out of that wait.
func TestLifecycle_ShutdownDeadlineBoundsAStuckHTTP3Handler(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	p.MustAddInterceptor(nil, h3Authority+"/", blockingHandler(started, release))

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- p.ServeQUIC(pc) }()
	t.Cleanup(func() { _ = p.Close() })

	proxyAddr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	require.NoError(t, err)

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: poolOf(ca), MinVersion: tls.VersionTLS13},
		QUICConfig:      &quic.Config{MaxIdleTimeout: 10 * time.Second},
		Dial: func(ctx context.Context, _ string, cfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			udp, err := net.ListenUDP("udp", nil)
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

	// Releasing the handler lets everything the deadline left behind unwind.
	close(release)
	select {
	case <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("the client request never returned after the release")
	}
	select {
	case err := <-served:
		assert.ErrorIs(t, err, ErrProxyClosed)
	case <-time.After(10 * time.Second):
		t.Fatal("ServeQUIC did not return after the release")
	}
}

// A tunnel never drains on its own: the proxy cannot see the end of what it relays. The
// deadline is what cuts it, and the cut has to release Shutdown promptly, upstream included.
func TestLifecycle_ShutdownCutsTunnelsAtTheDeadline(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()
	originURL, _ := url.Parse(origin.URL)

	p, err := New()
	require.NoError(t, err)
	require.NoError(t, p.AddTunnel(originHost(originURL)))

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
