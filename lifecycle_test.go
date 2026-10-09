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
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
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

// A proxy with no certificate authority still serves what needs no certificate. Registering a
// kind that always carries TLS is refused up front, and a stream that turns out to be TLS
// fails at the handshake rather than at registration: a stream may well be in the clear.
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

// An HTTP/2 client keeps its connection open until it is told to go away, so this drain only
// converges if the shutdown reaches the connection with a GOAWAY.
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

// A graceful shutdown that has nothing to drain still has to stop the QUIC side: the read
// loop, the HTTP/3 server and the relays are not tied to a listener http.Server closes.
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

// The HTTP/3 front drains like the TCP one: the request in flight completes, no connection is
// accepted meanwhile, and the socket is released once Shutdown has returned.
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

// The deadline cuts the HTTP/3 front like everything else. Shutdown returns, the client is
// sent a CONNECTION_CLOSE, and the socket is released before the handler ends.
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

// Close returns once everything is closed. A handler that ignores its cut ends behind it,
// on the HTTP/3 front as on the TCP one, and a Shutdown coming after has nothing to drain.
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

// A Shutdown whose context is already done is a cut, and the HTTP/3 front releases its
// socket the way it does at a live deadline.
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

// A datagram handler parked on the reply of its origin runs off the read loop, and Close
// returns without it.
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

// A tunnel never drains on its own: the proxy cannot see the end of what it relays. The
// deadline is what cuts it, and the cut has to release Shutdown promptly, upstream included.
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

// Close returns while datagrams wait behind a parked handler, and none of them is served after.
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

// Close returns while a resolution is in flight, and the lookup sees its context canceled.
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

// Closing a CONNECT-UDP tunnel whose HTTP/3 client has not sent its SETTINGS answers 200 and
// ends the stream, as a Close of any other tunnel does.
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
