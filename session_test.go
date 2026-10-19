// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// waitForSessions polls until the proxy reports want sessions. A session is registered by the
// goroutine serving its connection, so it appears shortly after the client's request returns
// rather than at the same instant.
func waitForSessions(t *testing.T, p *Proxy, want int) []*Session {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var got []*Session
	for time.Now().Before(deadline) {
		got = slices.Collect(p.Sessions())
		if len(got) == want {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected %d session(s), got %d", want, len(got))
	return nil
}

// tunneledOrigin starts a TLS origin the proxy is told to tunnel, and returns a client
// reaching it through the proxy along with the origin URL.
// streamedOrigin arms p with a stream entry for a TLS origin and returns a client that trusts
// the proxy. The connection is terminated like every other, so the certificate the client
// checks is the one the proxy minted, and the proxy is the one that has to trust the origin.
func streamedOrigin(t *testing.T, p *Proxy, ca *CA) (*http.Client, *url.URL, *x509.CertPool) {
	t.Helper()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	t.Cleanup(origin.Close)

	u, err := url.Parse(origin.URL)
	require.NoError(t, err)
	p.cfg.transport.RootCAs = originPool(t, origin)
	p.MustAdd[TCP](originHost(u), relayStream)

	pool := ca.CertPool()
	return proxyClient(startProxy(t, p), pool), u, pool
}

func TestSession_StreamIsListedAndClosed(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	client, originURL, _ := streamedOrigin(t, p, ca)

	resp, gerr := client.Get(originURL.String())
	require.NoError(t, gerr)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	// The transport keeps the connection open, so the session outlives the request.
	sessions := waitForSessions(t, p, 1)
	sess := sessions[0]
	assert.Equal(t, KindTCP, sess.Kind())
	assert.Equal(t, originHost(originURL), sess.Target().Host)
	assert.NotZero(t, sess.ID())

	require.NoError(t, sess.Close())
	assert.NoError(t, sess.Close(), "Close is idempotent")

	// The serving goroutine unwinds and unregisters the session it owned.
	waitForSessions(t, p, 0)
}

func TestSession_SweepAfterDeleteStream(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	client, originURL, _ := streamedOrigin(t, p, ca)

	resp, gerr := client.Get(originURL.String())
	require.NoError(t, gerr)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	waitForSessions(t, p, 1)

	_, err = p.Delete[TCP](originHost(originURL))
	require.NoError(t, err)

	var closed int
	for s := range p.Sessions() {
		if s.Stale() {
			require.NoError(t, s.Close())
			closed++
		}
	}
	assert.Equal(t, 1, closed, "the orphaned stream is swept")

	// The client reconnects and is refused at the CONNECT, which is what the delete asked for.
	_, err = client.Get(originURL.String())
	require.Error(t, err)
}

func TestSession_StaleWhenAFinerKindIsAdmitted(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	client, originURL, _ := streamedOrigin(t, p, ca)

	resp, gerr := client.Get(originURL.String())
	require.NoError(t, gerr)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	sess := waitForSessions(t, p, 1)[0]
	require.Equal(t, KindTCP, sess.Kind())
	assert.Equal(t, []Kind{KindHTTP, KindTCP}, sess.ServableAs(),
		"the traffic said HTTP, the tree had no entry for it")
	assert.False(t, sess.Stale(), "nothing finer is admitted yet")

	p.MustAdd(originHost(originURL)+"/*{rest}", forwardHandler)
	assert.True(t, sess.Stale(), "an HTTP entry now serves the traffic of this connection")

	var closed int
	for s := range p.Sessions() {
		if s.Stale() {
			require.NoError(t, s.Close())
			closed++
		}
	}
	assert.Equal(t, 1, closed)
	waitForSessions(t, p, 0)

	// The client comes back and is decided on the entries as they stand.
	resp, gerr = client.Get(originURL.String())
	require.NoError(t, gerr)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, KindHTTP, waitForSessions(t, p, 1)[0].Kind())
}

func TestSession_StaleFollowsTheEntry(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	p.cfg.transport.RootCAs = originPool(t, origin)

	_, port := splitHostPort(originURL.Host)
	catchAll, specific := "[127.0.0.0/8]:"+port, originHost(originURL)+":"+port
	p.MustAdd[TCP](catchAll, relayStream)
	client := proxyClient(startProxy(t, p), ca.CertPool())

	resp, err := client.Get(originURL.String())
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	sess := waitForSessions(t, p, 1)[0]
	require.Equal(t, KindTCP, sess.Kind())
	assert.False(t, sess.Stale(), "decided on the only entry there is")

	p.MustAdd[TCP](specific, relayStream)
	assert.True(t, sess.Stale(), "a more specific entry would serve it now")

	_, err = p.Delete[TCP](specific)
	require.NoError(t, err)
	assert.False(t, sess.Stale(), "back on the entry it was decided on")

	_, err = p.Update[TCP](catchAll, relayStream)
	require.NoError(t, err)
	assert.True(t, sess.Stale(), "the entry serving it was replaced")

	_, err = p.Delete[TCP](catchAll)
	require.NoError(t, err)
	assert.True(t, sess.Stale(), "nothing admits it any more")
}

func TestSession_StaleWebSocket(t *testing.T) {
	origin, originURL := wsOrigin(t, nil)
	p := testProxy(t)
	relayFrames := func(c *WebSocketCtx) error { return c.Relay() }
	catchAll, specific := originHost(originURL)+"/+{any}", originHost(originURL)+"/ws"
	p.MustAdd(catchAll, relayFrames)

	resp := wsUpgrade(t, startProxy(t, p), origin, "")
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	sess := waitForSessions(t, p, 1)[0]
	require.Equal(t, KindWebSocket, sess.Kind())
	assert.False(t, sess.Stale())

	p.MustAdd(specific, relayFrames)
	assert.True(t, sess.Stale(), "a more specific entry would serve the upgrade now")

	_, err := p.Delete[WebSocket](specific)
	require.NoError(t, err)
	assert.False(t, sess.Stale())

	_, err = p.Update[WebSocket](catchAll, relayFrames)
	require.NoError(t, err)
	assert.True(t, sess.Stale(), "the entry serving it was replaced")

	_, err = p.Delete[WebSocket](catchAll)
	require.NoError(t, err)
	assert.True(t, sess.Stale(), "nothing admits it any more")
}

func TestSession_WebSocketEndsAtCloseWithoutWaitingForItsHandler(t *testing.T) {
	origin, originURL := wsOrigin(t, nil)
	p := testProxy(t)
	handlerCtx, release := make(chan context.Context, 1), make(chan struct{})
	p.MustAdd(originHost(originURL)+"/ws", func(c *WebSocketCtx) error {
		handlerCtx <- c.Context()
		<-release
		return nil
	})
	resp := wsUpgrade(t, startProxy(t, p), origin, "")
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	t.Cleanup(func() { close(release) })
	ctx := <-handlerCtx

	sess := waitForSessions(t, p, 1)[0]
	require.NoError(t, sess.Close())
	assertSessionEnded(t, p, sess)
	assert.Error(t, ctx.Err(), "the context of the handler is live")
}

func TestSession_CloseSendsTheWebSocketClientGoingAway(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	client, p := wsThroughProxy(t, func(*WebSocketCtx) error {
		<-release
		return nil
	})
	sess := waitForSessions(t, p, 1)[0]
	require.NoError(t, sess.Close())
	frames := client.wantEnd()
	require.Len(t, frames, 1)
	assert.Equal(t, byte(0x88), frames[0].head)
	assert.Equal(t, closePayload(1001, ""), frames[0].payload)
}

func TestSession_WebSocketHandlerReturningNilSendsANormalClose(t *testing.T) {
	client, _ := wsThroughProxy(t, func(*WebSocketCtx) error { return nil })
	frames := client.wantEnd()
	require.Len(t, frames, 1)
	assert.Equal(t, byte(0x88), frames[0].head)
	assert.Equal(t, closePayload(1000, ""), frames[0].payload)
}

// wsThroughProxy upgrades a client to a WebSocket served by h through a proxy, and returns
// the client past the 101.
func wsThroughProxy(t *testing.T, h WebSocket) (*wsEnd, *Proxy) {
	t.Helper()
	origin, originURL := wsOrigin(t, nil)
	p := testProxy(t)
	p.MustAdd(originHost(originURL)+"/ws", h)
	raw, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	_, err = fmt.Fprintf(raw, "GET %s/ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", origin.URL, originURL.Host)
	require.NoError(t, err)
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	return &wsEnd{t: t, conn: raw, br: br, client: true}, p
}

func TestSession_FrontIsNeverStale(t *testing.T) {
	p := testProxy(t)
	stale := make(chan bool, 1)
	p.MustAdd("example.test/", func(c *HTTPCtx) (*http.Response, error) {
		stale <- c.Session().Stale()
		return Text(http.StatusOK, "ok"), nil
	})
	client := proxyClient(startProxy(t, p), nil)

	resp, err := client.Get("http://example.test/")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	assert.False(t, <-stale)
}

func TestSession_StaleUnderConcurrentChanges(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	client, originURL, _ := streamedOrigin(t, p, ca)
	specific := originHost(originURL)

	deadline := time.Now().Add(300 * time.Millisecond)
	var wg sync.WaitGroup
	wg.Go(func() {
		for time.Now().Before(deadline) {
			_, _ = p.Add[TCP]("[127.0.0.0/8]", relayStream)
			_, _ = p.Update[TCP](specific, relayStream)
			_, _ = p.Delete[TCP]("[127.0.0.0/8]")
		}
	})
	wg.Go(func() {
		for time.Now().Before(deadline) {
			for s := range p.Sessions() {
				_ = s.Stale()
			}
		}
	})
	wg.Go(func() {
		for time.Now().Before(deadline) {
			resp, gerr := client.Get(originURL.String())
			if gerr != nil {
				client.CloseIdleConnections()
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	})
	wg.Wait()
}

func TestSession_PlaintextTunnelOverTLSFront(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	origin, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		for {
			c, aerr := origin.Accept()
			if aerr != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	p.MustAdd[TCP](origin.Addr().String(), relayStream)

	proxyCert := selfSignedFor(t, ca, "localhost")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.ServeTLS(ln, proxyCert) }()
	t.Cleanup(func() { _ = p.Close() })

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName: "localhost",
		RootCAs:    poolOf(ca),
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS13,
	})
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.Equal(t, "http/1.1", conn.ConnectionState().NegotiatedProtocol,
		"the front handshake must have an ALPN for the leak to be observable")

	authority := origin.Addr().String()
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, line, "200")
	for line != "\r\n" {
		line, err = br.ReadString('\n')
		require.NoError(t, err)
	}

	_, err = conn.Write([]byte("hello\n"))
	require.NoError(t, err)
	echo, err := br.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "hello\n", echo)

	sess := waitForSessions(t, p, 1)[0]
	assert.Equal(t, KindTCP, sess.Kind())
	assert.Nil(t, sess.TLS(), "the front handshake belongs to the proxy, the tunnel has none")
	assert.Empty(t, sess.ALPN())
	assert.Equal(t, conn.LocalAddr().String(), sess.RemoteAddr().String())
}

func TestSession_InterceptedIsListedAndClosed(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()

	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)
	p := testProxy(t, WithTransport(tr))
	p.MustAdd(originHost(originURL)+"/*{rest}", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	})

	client := proxyClient(startProxy(t, p), p.cfg.ca.CertPool())
	resp, err := client.Get(originURL.String())
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, KindHTTP, sessions[0].Kind())
	assert.Equal(t, originHost(originURL), sessions[0].Target().Host)
	assert.NotNil(t, sessions[0].TLS(), "the handshake with the client is recorded")

	require.NoError(t, sessions[0].Close())
	waitForSessions(t, p, 0)
}

func TestSession_FrontConnectionsAreNotListed(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()

	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	p := testProxy(t)
	p.MustAdd(originHost(originURL)+"/*{rest}", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	})

	client := proxyClient(startProxy(t, p), nil)
	resp, err := client.Get(originURL.String())
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	assert.Empty(t, slices.Collect(p.Sessions()),
		"a plain proxy request opens no connection the proxy decides on its own")
}

func TestSession_CloseUnderTraffic(t *testing.T) {
	// The race detector checks this test.
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	client, originURL, _ := streamedOrigin(t, p, ca)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			resp, err := client.Get(originURL.String())
			if err != nil {
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	})

	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			for s := range p.Sessions() {
				_ = s.Close()
			}
		}
	})

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}

func TestSession_AdmitAfterChange(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, p *Proxy)
	}{
		{"the entry deleted", func(t *testing.T, p *Proxy) {
			_, err := p.Delete[TCP]("+{any}")
			require.NoError(t, err)
		}},
		{"a more specific entry", func(_ *testing.T, p *Proxy) {
			p.MustAdd[TCP]("example.test", relayStream)
		}},
		{"the serving entry updated", func(t *testing.T, p *Proxy) {
			_, err := p.Update[TCP]("+{any}", relayStream)
			require.NoError(t, err)
		}},
		{"a finer kind admitted", func(_ *testing.T, p *Proxy) {
			p.MustAdd("example.test/", forwardHandler)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testProxy(t)
			p.MustAdd[TCP]("+{any}", relayStream)
			target := Target{Scheme: "https", Host: "example.test", Port: "443"}
			decide := func() *Session {
				kind, e, _ := p.firstAdmittedWith(target, []Kind{KindHTTP, KindTCP})
				require.Equal(t, KindTCP, kind)
				ctx, cancel := context.WithCancel(t.Context())
				sess := newSession(p, ctx, nil, target, kind, 0)
				sess.cancel = cancel
				sess.servableAs = []Kind{KindHTTP, KindTCP}
				sess.entry.Store(e)
				return sess
			}

			admitted := decide()
			require.NoError(t, p.srv.admitSession(admitted, nil))
			require.Len(t, slices.Collect(p.Sessions()), 1)
			p.srv.untrackSession(admitted)

			late := decide()
			tc.change(t, p)
			assert.Error(t, p.srv.admitSession(late, nil), "decided before the change, registered after it")
			assert.Empty(t, slices.Collect(p.Sessions()), "a refused connection is not reported")
		})
	}
}

// frontSessionContext runs one plain proxied request through client, captures the session
// context the handler saw, and asserts it ends when the client's connection does.
func frontSessionContext(t *testing.T, p *Proxy, client *http.Client) {
	t.Helper()

	ctxCh := make(chan context.Context, 1)
	p.MustAdd("example.test/", func(c *HTTPCtx) (*http.Response, error) {
		select {
		case ctxCh <- c.Session().Context():
		default:
		}
		return Text(http.StatusOK, "ok"), nil
	})

	resp, err := client.Get("http://example.test/")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	sessCtx := <-ctxCh
	select {
	case <-sessCtx.Done():
		t.Fatal("the context fired while the connection was alive")
	default:
	}

	client.CloseIdleConnections()
	select {
	case <-sessCtx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("closing the connection did not end the session context")
	}
}

func TestSession_FrontContextEndsWithTheConnection(t *testing.T) {
	p := testProxy(t)
	frontSessionContext(t, p, proxyClient(startProxy(t, p), nil))
}

func TestSession_FrontContextEndsWithTheConnectionOverTLS(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)

	addr, pool := startProxyTLS(t, p, ca)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(&url.URL{Scheme: "https", Host: addr}),
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	frontSessionContext(t, p, client)
}

func FuzzSplitHostPort(f *testing.F) {
	seeds := []string{
		"api.stripe.com:443",
		"api.stripe.com",
		"[::1]:8080",
		"[::1]",
		"::1",
		"",
		":",
		":443",
		"a:b:c",
		"[",
		"]",
		"[]:1",
		"origin.test:80:80",
		"[::1]x",
		"[fe80::1%25en0]:80",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, authority string) {
		host, port := splitHostPort(authority)

		// Splitting and rejoining is idempotent. A malformed authority has no canonical
		// form to round-trip to, but once the pair has been through joinHostPort it must
		// survive every further pass: targets are split and rejoined all along the path a
		// request takes.
		joined := joinHostPort(host, port)
		host2, port2 := splitHostPort(joined)
		if host2 != host || port2 != port {
			t.Fatalf("split(%q) = (%q, %q), then split(join(...)) = (%q, %q)", authority, host, port, host2, port2)
		}

		host, port, ok := splitAuthority(authority)
		if !ok {
			return
		}
		if _, err := netip.ParseAddr(host); strings.Contains(host, ":") && err != nil {
			t.Fatalf("splitAuthority(%q) returned the host %q", authority, host)
		}
		if host2, port2, ok := splitAuthority(joinHostPort(host, port)); !ok || host2 != host || port2 != port {
			t.Fatalf("splitAuthority(%q) = (%q, %q), then splitAuthority(join(...)) = (%q, %q, %v)", authority, host, port, host2, port2, ok)
		}
	})
}

func TestCanonicalPort(t *testing.T) {
	for in, want := range map[string]struct {
		port string
		ok   bool
	}{
		"":            {"", true},
		"443":         {"443", true},
		"0443":        {"443", true},
		"00000000443": {"443", true},
		"65535":       {"65535", true},
		"65536":       {"", false},
		"123456":      {"", false},
		"0":           {"", false},
		"000":         {"", false},
		"4a3":         {"", false},
		"-1":          {"", false},
	} {
		got, ok := canonicalPort(in)
		assert.Equal(t, want.ok, ok, in)
		assert.Equal(t, want.port, got, in)
	}
}

func TestSplitAuthority(t *testing.T) {
	for _, tc := range []struct {
		authority, host, port string
	}{
		{"", "", ""},
		{"origin.test", "origin.test", ""},
		{"origin.test:", "origin.test", ""},
		{"origin.test:0443", "origin.test", "443"},
		{"127.0.0.1:80", "127.0.0.1", "80"},
		{"[::1]", "::1", ""},
		{"[::1]:", "::1", ""},
		{"[::1]:8080", "::1", "8080"},
		{"[fe80::1%25en0]:80", "fe80::1%25en0", "80"},
		{"[::ffff:127.0.0.1]:80", "::ffff:127.0.0.1", "80"},
		{"a-b_c~d.test", "a-b_c~d.test", ""},
		{"!$&'()*+,;=.test:80", "!$&'()*+,;=.test", "80"},
		{"a%41%c3%A9.test", "a%41%c3%A9.test", ""},
	} {
		host, port, ok := splitAuthority(tc.authority)
		assert.True(t, ok, tc.authority)
		assert.Equal(t, tc.host, host, tc.authority)
		assert.Equal(t, tc.port, port, tc.authority)
	}
	for _, authority := range []string{
		"origin.test:80:80", "::1", "::1:80", "[::1", "[::1]x", "[::1]:80:80", "[::1]]:80", "[origin.test]",
		"[127.0.0.1]:80", "origin.test]", "origin.test[", "user@origin.test", "origin.test/x", "origin.test?",
		"origin.test#", "origin .test", "origin\x00.test", "origin.test:8o", "origin.test:65536",
		"ori\"gin.test", "ori<gin>.test", "ori\\gin.test", "ori^gin.test", "ori`gin.test", "ori{gin}.test",
		"ori|gin.test", "origin.test\x7f", "origin.test\x80", "caf\xc3\xa9.test", "a%4.test", "a%zz.test",
		"a%.test", "a.test%", "a.test%4", "a.test%4:80",
	} {
		_, _, ok := splitAuthority(authority)
		assert.False(t, ok, authority)
	}
}

// wsOrigin answers every request with a 101 and keeps the connection open. before runs while
// the proxy waits on that answer.
func wsOrigin(t *testing.T, before func()) (*httptest.Server, *url.URL) {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if before != nil {
			before()
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("origin hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		_, _ = io.Copy(io.Discard, brw)
	}))
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	return origin, originURL
}

// wsUpgrade sends an upgrade request for /ws through the proxy and returns the answer.
func wsUpgrade(t *testing.T, proxyAddr string, origin *httptest.Server, extraHeaders string) *http.Response {
	t.Helper()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	raw, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	_, err = fmt.Fprintf(raw, "GET %s/ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
		extraHeaders+"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		origin.URL, originURL.Host)
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(raw), nil)
	require.NoError(t, err)
	return resp
}

func TestSession_StaleReadsACopyOfTheUpgrade(t *testing.T) {
	origin, originURL := wsOrigin(t, nil)
	p := testProxy(t)
	done := make(chan struct{})
	started := make(chan struct{})
	p.MustAdd(originHost(originURL)+"/ws", func(c *WebSocketCtx) error {
		close(started)
		for i := 0; ; i++ {
			select {
			case <-done:
				return nil
			default:
			}
			c.Request().Header.Set("X-Churn", strconv.Itoa(i))
		}
	})
	resp := wsUpgrade(t, startProxy(t, p), origin, "")
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	<-started

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		for s := range p.Sessions() {
			assert.False(t, s.Stale())
		}
	}
	close(done)
}

func TestSession_UpgradeRefusedAfterAChangeInTheWindow(t *testing.T) {
	p := testProxy(t)
	relayFrames := func(c *WebSocketCtx) error { return c.Relay() }
	var originURL *url.URL
	origin, originURL := wsOrigin(t, func() {
		tenant, err := MatchHeader("X-Tenant", "acme")
		require.NoError(t, err)
		p.MustAdd(originHost(originURL)+"/ws", relayFrames, WithRequestMatchers[WebSocket](tenant))
	})
	p.MustAdd(originHost(originURL)+"/ws", relayFrames)

	resp := wsUpgrade(t, startProxy(t, p), origin, "X-Tenant: acme\r\n")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, http.StatusText(http.StatusForbidden)+"\n", string(body))
	assert.Empty(t, slices.Collect(p.Sessions()), "a refused upgrade is not reported")
}

func TestSession_StaleLeavesTheNoEntryHandler(t *testing.T) {
	p := testProxy(t, WithNoEntry(relayStream))
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	p.cfg.transport.RootCAs = originPool(t, origin)

	client := proxyClient(startProxy(t, p), p.cfg.ca.CertPool())
	resp, err := client.Get(origin.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	sess := waitForSessions(t, p, 1)[0]
	require.Equal(t, KindTCP, sess.Kind())
	assert.False(t, sess.Stale())

	_, port := splitHostPort(originURL.Host)
	p.MustAdd[TCP](originHost(originURL)+":"+port, relayStream)
	assert.True(t, sess.Stale())
}

func TestSession_StaleWebSocketLeavesTheNoEntryHandler(t *testing.T) {
	origin, originURL := wsOrigin(t, nil)
	p := testProxy(t, WithNoEntry(forwardHandler), WithNoEntry(func(c *WebSocketCtx) error { return c.Relay() }))

	resp := wsUpgrade(t, startProxy(t, p), origin, "")
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	sess := waitForSessions(t, p, 1)[0]
	require.Equal(t, KindWebSocket, sess.Kind())
	assert.False(t, sess.Stale())

	p.MustAdd(originHost(originURL)+"/ws", func(c *WebSocketCtx) error { return c.Relay() })
	assert.True(t, sess.Stale())
}

// assertSessionEnded checks that sess is over as soon as the call that ended it returns,
// whatever its handler is still doing.
func assertSessionEnded(t *testing.T, p *Proxy, sess *Session) {
	t.Helper()
	assert.Error(t, sess.Context().Err(), "the context of the ended session is live")
	assert.False(t, slices.Contains(slices.Collect(p.Sessions()), sess), "the ended session is listed")
}

// parkedStream is a TCP handler that ignores its context and its connections until release
// closes.
func parkedStream(started chan<- struct{}, release <-chan struct{}) TCP {
	return func(*TCPCtx) error {
		close(started)
		<-release
		return nil
	}
}

func TestSession_AdmissionRefusedOnceEnded(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(p *Proxy, sess *Session)
	}{
		{"SessionClose", func(_ *Proxy, sess *Session) { _ = sess.Close() }},
		{"ProxyClose", func(p *Proxy, _ *Session) { _ = p.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testProxy(t)
			p.MustAdd[TCP]("example.test", relayStream)
			ctx, cancel := context.WithCancel(t.Context())
			sess := newSession(p, ctx, nil, Target{Scheme: "https", Host: "example.test", Port: "443"}, KindTCP, 0)
			sess.cancel = cancel
			sess.closer = noEnd{}

			tc.end(p, sess)
			assert.Error(t, p.srv.admitSession(sess, nil), "a session decided before the end is registered after it")
			assert.Empty(t, slices.Collect(p.Sessions()))
		})
	}
}

func TestSession_EndsAtTheCutWithoutWaitingForItsHandler(t *testing.T) {
	fronts := []struct {
		name string
		open func(t *testing.T, h TCP) *Proxy
	}{
		{"h1", func(t *testing.T, h TCP) *Proxy {
			origin := sinkOrigin(t)
			p := testProxy(t)
			p.MustAdd[TCP](origin.Addr().String(), h)
			conn, err := net.Dial("tcp", startProxy(t, p))
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %[1]s\r\n\r\nx", origin.Addr())
			require.NoError(t, err)
			return p
		}},
		{"h2", func(t *testing.T, h TCP) *Proxy {
			p, _, _ := openH2ConnectTo(t, sinkOrigin(t), h)
			return p
		}},
		{"h3", func(t *testing.T, h TCP) *Proxy {
			p, rstr := openH3ConnectTo(t, sinkOrigin(t), h)
			_, err := rstr.Write([]byte("x"))
			require.NoError(t, err)
			return p
		}},
		{"transparent", func(t *testing.T, h TCP) *Proxy {
			origin := netip.MustParseAddrPort(sinkOrigin(t).Addr().String())
			p := testProxy(t)
			p.MustAdd[TCP](origin.String(), h)
			addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) { return origin, nil })
			conn, err := net.Dial("tcp", addr)
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			_, err = conn.Write([]byte("x"))
			require.NoError(t, err)
			return p
		}},
		{"socks5", func(t *testing.T, h TCP) *Proxy {
			origin := netip.MustParseAddrPort(sinkOrigin(t).Addr().String())
			p := testProxy(t)
			p.MustAdd[TCP](origin.String(), h)
			w := socksConnect(t, startSOCKS5(t, p), socksAddrBytes(origin))
			w.readReply()
			w.write([]byte("x"))
			return p
		}},
	}
	cuts := []struct {
		name string
		cut  func(p *Proxy, sess *Session) error
	}{
		{"SessionClose", func(_ *Proxy, sess *Session) error { return sess.Close() }},
		{"ProxyClose", func(p *Proxy, _ *Session) error { return p.Close() }},
	}
	for _, front := range fronts {
		for _, cut := range cuts {
			t.Run(front.name+"/"+cut.name, func(t *testing.T) {
				started, release := make(chan struct{}), make(chan struct{})
				p := front.open(t, parkedStream(started, release))
				t.Cleanup(func() { close(release) })
				<-started
				sess := waitForSessions(t, p, 1)[0]

				done := make(chan error, 1)
				go func() { done <- cut.cut(p, sess) }()
				select {
				case err := <-done:
					require.NoError(t, err)
				case <-time.After(3 * time.Second):
					t.Fatal("the cut waited for the handler")
				}
				assertSessionEnded(t, p, sess)
			})
		}
	}
}

func TestSession_CloseOnAFrontSessionEndsTheConnection(t *testing.T) {
	for _, proto := range []string{"h1", "h2c"} {
		t.Run(proto, func(t *testing.T) {
			p := testProxy(t)
			closed := make(chan error, 1)
			p.MustAdd("allowed.test/", func(c *HTTPCtx) (*http.Response, error) {
				closed <- c.Session().Close()
				return Text(http.StatusOK, "ok"), nil
			})
			addr := startProxy(t, p)
			var client *http.Client
			if proto == "h1" {
				client = proxyClient(addr, nil)
			} else {
				client = h2cFrontClient(addr)
			}
			var conns atomic.Int32
			trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
				if !info.Reused {
					conns.Add(1)
				}
			}}
			for range 2 {
				req, err := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), http.MethodGet, "http://allowed.test/", nil)
				require.NoError(t, err)
				resp, err := client.Do(req)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
				require.NoError(t, <-closed)
			}
			assert.EqualValues(t, 2, conns.Load(), "the front connection served a request after Close on its session")
		})
	}
}

func TestSession_CloseOnAnHTTP3FrontSessionEndsTheConnection(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	got := make(chan *Session, 1)
	p.MustAdd("front.example.test/", func(c *HTTPCtx) (*http.Response, error) {
		got <- c.Session()
		return Text(http.StatusOK, "ok"), nil
	})
	front, _ := startQUICFront(t, p, ca)
	conn := dialQUICFront(t, front, ca)
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	req, err := http.NewRequest(http.MethodGet, "http://front.example.test/", nil)
	require.NoError(t, err)
	resp, err := h3Over(t, conn).RoundTrip(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	require.NoError(t, (<-got).Close())
	select {
	case <-conn.Context().Done():
		var appErr *quic.ApplicationError
		require.ErrorAs(t, context.Cause(conn.Context()), &appErr)
		assert.EqualValues(t, http3.ErrCodeNoError, appErr.ErrorCode)
	case <-time.After(2 * time.Second):
		t.Fatal("Close on the session left the HTTP/3 front connection open")
	}
}

func TestSession_CloseOfAnHTTPConnectionEndsItNormally(t *testing.T) {
	for _, front := range []string{"explicit", "serveconn"} {
		t.Run(front, func(t *testing.T) {
			p := testProxy(t)
			entered := make(chan *Session, 1)
			p.MustAdd("ws.example.test/x", func(c *HTTPCtx) (*http.Response, error) {
				entered <- c.Session()
				<-c.Request().Context().Done()
				return nil, c.Request().Context().Err()
			})
			var conn net.Conn
			var err error
			target := "/x"
			if front == "explicit" {
				conn, err = net.Dial("tcp", startProxy(t, p))
				target = "http://ws.example.test/x"
			} else {
				cl, lerr := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, lerr)
				defer cl.Close()
				go func() {
					sc, aerr := cl.Accept()
					if aerr == nil {
						_ = p.ServeConn(sc)
					}
				}()
				conn, err = net.Dial("tcp", cl.Addr().String())
			}
			require.NoError(t, err)
			defer conn.Close()
			_, err = fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: ws.example.test\r\nContent-Length: 100000\r\n\r\n", target)
			require.NoError(t, err)
			_, err = conn.Write(make([]byte, 50000))
			require.NoError(t, err)
			sess := <-entered
			time.Sleep(50 * time.Millisecond)
			require.NoError(t, sess.Close())
			assert.Equal(t, "FIN", peerEnd(conn, 3*time.Second))
		})
	}
}

func TestSession_CloseEndsTheContextOfAFrontSession(t *testing.T) {
	for _, mode := range []string{"plaintext", "caller TLS listener"} {
		t.Run(mode, func(t *testing.T) {
			p := testProxy(t)
			done := make(chan bool, 1)
			p.MustAdd("allowed.test/", func(c *HTTPCtx) (*http.Response, error) {
				s := c.Session()
				_ = s.Close()
				select {
				case <-s.Context().Done():
					done <- true
				case <-time.After(500 * time.Millisecond):
					done <- false
				}
				return Text(http.StatusOK, "ok"), nil
			})
			inner, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			var ln net.Listener = inner
			if mode != "plaintext" {
				cert, cerr := p.cfg.ca.Leaf("127.0.0.1")
				require.NoError(t, cerr)
				ln = tls.NewListener(inner, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}})
			}
			go func() { _ = p.Serve(ln) }()
			t.Cleanup(func() { _ = p.Close() })
			var conn net.Conn
			if mode == "plaintext" {
				conn, err = net.Dial("tcp", inner.Addr().String())
			} else {
				conn, err = tls.Dial("tcp", inner.Addr().String(), &tls.Config{ServerName: "127.0.0.1", RootCAs: p.cfg.ca.CertPool(), NextProtos: []string{"http/1.1"}})
			}
			require.NoError(t, err)
			defer conn.Close()
			_, err = io.WriteString(conn, "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
			require.NoError(t, err)
			require.True(t, <-done, "the context of a session is done once Close returned")
		})
	}
}

// closeDeadlines records the deadline of its close and blocks the close until it.
type closeDeadlines chan time.Time

func (c closeDeadlines) endBy(_ cause, deadline time.Time) error {
	c <- deadline
	time.Sleep(time.Until(deadline))
	return nil
}

func TestSession_CloseSharesItsDeadlineWithWhatItCarries(t *testing.T) {
	p := testProxy(t)
	got := make(closeDeadlines, 2)
	front := newSession(p, t.Context(), nil, Target{}, KindHTTP, HTTP2)
	front.cancel = func() {}
	require.True(t, p.srv.registerSession(front, got))
	inner := newSession(p, t.Context(), nil, Target{Host: "inner.test", Port: "443"}, KindTCP, HTTP2)
	inner.cancel = func() {}
	inner.carrier = front
	require.True(t, p.srv.registerSession(inner, got))

	start := time.Now()
	require.NoError(t, front.Close())
	assert.Less(t, time.Since(start), alertWriteTimeout*3/2, "the carrier's own legs got a deadline of their own")
	assert.Equal(t, <-got, <-got)
}

func TestSession_CloseCancelsATerminatedHTTP1Request(t *testing.T) {
	for _, req := range []string{
		"POST / HTTP/1.1\r\nHost: api.test\r\nContent-Length: 100\r\n\r\n0123456789",
		"GET / HTTP/1.1\r\nHost: api.test\r\n\r\n",
	} {
		t.Run(req[:4], func(t *testing.T) { closeTerminatedHTTP1Request(t, req) })
	}
}

func closeTerminatedHTTP1Request(t *testing.T, raw string) {
	p, ca := newTLSProxy(t)
	started := make(chan *HTTPCtx, 1)
	ended := make(chan time.Duration, 1)
	p.MustAdd("api.test/", func(c *HTTPCtx) (*http.Response, error) {
		started <- c
		begin := time.Now()
		select {
		case <-c.Request().Context().Done():
			ended <- time.Since(begin)
		case <-time.After(4 * time.Second):
			ended <- -1
		}
		return nil, errors.New("done")
	})
	tc := tls.Client(connectRaw(t, startProxy(t, p), "api.test:443"), &tls.Config{ServerName: "api.test", RootCAs: ca.CertPool()})
	require.NoError(t, tc.Handshake())
	_, err := tc.Write([]byte(raw))
	require.NoError(t, err)
	c := <-started
	start := time.Now()
	require.NoError(t, c.Session().Close())
	t.Logf("Session.Close returned in %v", time.Since(start))
	d := <-ended
	if d < 0 {
		t.Fatal("Session.Close of the session served as HTTP left the request context running")
	}
	t.Logf("request context ended %v after Session.Close", d)
}

func TestSession_CloseCancelsAFrontRequest(t *testing.T) {
	p := testProxy(t)
	started := make(chan *HTTPCtx, 1)
	ended := make(chan time.Duration, 1)
	p.MustAdd("api.test/", func(c *HTTPCtx) (*http.Response, error) {
		started <- c
		begin := time.Now()
		select {
		case <-c.Request().Context().Done():
			ended <- time.Since(begin)
		case <-time.After(4 * time.Second):
			ended <- -1
		}
		return nil, errors.New("done")
	})
	c, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Write([]byte("POST http://api.test/ HTTP/1.1\r\nHost: api.test\r\nContent-Length: 100\r\n\r\n0123456789"))
	require.NoError(t, err)
	hc := <-started
	require.NoError(t, hc.Session().Close())
	if d := <-ended; d < 0 {
		t.Fatal("Session.Close of the front connection left the request context running")
	} else {
		t.Logf("ended after %v", d)
	}
}

func TestSession_CloseCancelsATerminatedHTTP2Request(t *testing.T) {
	p, ca := newTLSProxy(t)
	started := make(chan *HTTPCtx, 1)
	ended := make(chan time.Duration, 1)
	p.MustAdd("api.test/", func(c *HTTPCtx) (*http.Response, error) {
		started <- c
		begin := time.Now()
		select {
		case <-c.Request().Context().Done():
			ended <- time.Since(begin)
		case <-time.After(4 * time.Second):
			ended <- -1
		}
		return nil, errors.New("done")
	})
	tc := tls.Client(connectRaw(t, startProxy(t, p), "api.test:443"), &tls.Config{ServerName: "api.test", RootCAs: ca.CertPool(), NextProtos: []string{"h2"}})
	require.NoError(t, tc.Handshake())
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(tc)
	require.NoError(t, err)
	pr, pw := io.Pipe()
	defer pw.Close()
	go func() { _, _ = pw.Write([]byte("0123456789")) }()
	req, _ := http.NewRequest(http.MethodPost, "https://api.test/", pr)
	req.ContentLength = 100
	go func() { _, _ = cc.RoundTrip(req) }()
	hc := <-started
	require.NoError(t, hc.Session().Close())
	if d := <-ended; d < 0 {
		t.Fatal("Session.Close of the session served as HTTP/2 left the request context running")
	} else {
		t.Logf("ended after %v", d)
	}
}

func TestSession_FrontCloseEndsAWebSocketInsideAStream(t *testing.T) {
	_, originURL := wsOrigin(t, nil)
	p := testProxy(t)
	wsSess := make(chan *Session, 1)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	p.MustAdd(originHost(originURL)+"/ws", func(c *WebSocketCtx) error {
		wsSess <- c.Session()
		<-release
		return nil
	})
	front := make(chan *Session, 1)
	p.MustAdd("front.test/", func(c *HTTPCtx) (*http.Response, error) {
		front <- c.Session()
		return Text(http.StatusOK, "ok"), nil
	})
	addr := startProxy(t, p)
	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	require.NoError(t, err)
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	req, err := http.NewRequest(http.MethodConnect, "http://"+originURL.Host, pr)
	require.NoError(t, err)
	req.Host = originURL.Host
	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = fmt.Fprintf(pw, "GET /ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", originURL.Host)
	require.NoError(t, err)
	br := bufio.NewReader(resp.Body)
	up, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, up.StatusCode)
	w := <-wsSess

	freq, err := http.NewRequest(http.MethodGet, "http://front.test/", nil)
	require.NoError(t, err)
	fresp, err := cc.RoundTrip(freq)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, fresp.Body)
	f := <-front

	start := time.Now()
	require.NoError(t, f.Close())
	t.Logf("front Close took %v", time.Since(start))
	listed := slices.Contains(slices.Collect(p.Sessions()), w)
	t.Logf("after the front Close: websocket ctx err %v, listed %v", w.Context().Err(), listed)
	if w.Context().Err() == nil || listed {
		t.Errorf("the WebSocket session the front connection carries outlives its Close: ctx %v, listed %v", w.Context().Err(), listed)
	}
}

func TestSession_FrontCloseResetsACarriedStreamWithAHandlerReturningOnItsContext(t *testing.T) {
	for _, mode := range []string{"returns-on-context", "parked"} {
		t.Run(mode, func(t *testing.T) {
			p := testProxy(t)
			started := make(chan struct{})
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			originAddr, originConns := oneConnOrigin(t)
			p.MustAdd[TCP]("svc.test:9", func(c *TCPCtx) error {
				if _, err := c.DialTo(c.Context(), originAddr); err != nil {
					return err
				}
				close(started)
				if mode == "parked" {
					<-release
					return nil
				}
				<-c.Context().Done()
				return nil
			})
			front := make(chan *Session, 1)
			p.MustAdd("front.test/", func(c *HTTPCtx) (*http.Response, error) {
				front <- c.Session()
				return Text(http.StatusOK, "ok"), nil
			})
			raw, err := net.Dial("tcp", startProxy(t, p))
			require.NoError(t, err)
			t.Cleanup(func() { _ = raw.Close() })
			cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
			require.NoError(t, err)
			pr, pw := io.Pipe()
			t.Cleanup(func() { _ = pw.Close() })
			req, err := http.NewRequest(http.MethodConnect, "http://svc.test:9", pr)
			require.NoError(t, err)
			req.Host = "svc.test:9"
			resp, err := cc.RoundTrip(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			_, err = pw.Write([]byte{0})
			require.NoError(t, err)
			<-started
			freq, err := http.NewRequest(http.MethodGet, "http://front.test/", nil)
			require.NoError(t, err)
			fresp, err := cc.RoundTrip(freq)
			require.NoError(t, err)
			_, _ = io.Copy(io.Discard, fresp.Body)
			f := <-front
			require.NoError(t, f.Close())
			_, rerr := io.ReadAll(resp.Body)
			t.Logf("the client read the end of the stream as %v", rerr)
			end := peerEnd(<-originConns, 3*time.Second)
			t.Logf("the origin read %s", end)
			if rerr == nil || end != "RST" {
				t.Errorf("a leg of the carried byte stream ended cleanly on the Close of its front connection: client %v, origin %s", rerr, end)
			}
		})
	}
}

func TestSession_CloseResetsAnHTTP3FrontRequest(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	got := make(chan *Session, 1)
	returned := make(chan error, 1)
	p.MustAdd("front.example.test/", func(c *HTTPCtx) (*http.Response, error) {
		got <- c.Session()
		select {
		case <-c.Request().Context().Done():
			returned <- context.Cause(c.Request().Context())
		case <-time.After(3 * time.Second):
			returned <- errors.New("request context never ended")
		}
		return nil, c.Request().Context().Err()
	})
	front, _ := startQUICFront(t, p, ca)
	conn := dialQUICFront(t, front, ca)
	req, err := http.NewRequest(http.MethodGet, "http://front.example.test/", nil)
	require.NoError(t, err)
	rt := make(chan error, 1)
	go func() {
		resp, err := h3Over(t, conn).RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		rt <- err
	}()
	sess := <-got
	start := time.Now()
	require.NoError(t, sess.Close())
	assert.Less(t, time.Since(start), alertWriteTimeout, "Session.Close waited past its deadline")
	var connErr error
	select {
	case <-conn.Context().Done():
		connErr = context.Cause(conn.Context())
	case <-time.After(3 * time.Second):
		t.Fatal("connection not closed")
	}
	assert.Error(t, <-returned, "the handler's request context outlived Session.Close")
	assertH3RequestReset(t, <-rt)
	appErr, ok := errors.AsType[*quic.ApplicationError](connErr)
	require.True(t, ok, "the connection ended with %v", connErr)
	assert.Equal(t, quic.ApplicationErrorCode(http3.ErrCodeNoError), appErr.ErrorCode, "the connection did not get its normal end once its request ended")
}

func assertH3RequestReset(t *testing.T, err error) {
	t.Helper()
	h3e, ok := errors.AsType[*http3.Error](err)
	require.True(t, ok, "the request ended with %v", err)
	assert.Contains(t, []http3.ErrCode{http3.ErrCodeRequestCanceled, http3.ErrCodeInternalError}, h3e.ErrorCode, "the request in flight did not get its failed end")
}

func TestSession_CloseResetsATerminatedHTTP3Request(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)
	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	got := make(chan *Session, 1)
	returned := make(chan error, 1)
	p.MustAdd(h3Authority+"/+{any}", func(c *HTTPCtx) (*http.Response, error) {
		got <- c.Session()
		select {
		case <-c.Request().Context().Done():
			returned <- context.Cause(c.Request().Context())
		case <-time.After(3 * time.Second):
			returned <- errors.New("request context never ended")
		}
		return nil, c.Request().Context().Err()
	})
	proxyAddr := startQUICRedirected(t, p, origin)
	tr := dialQUICTo(proxyAddr, poolOf(proxyCA))
	defer func() { _ = tr.Close() }()
	req, err := http.NewRequest(http.MethodGet, "https://"+h3Authority+"/echo", nil)
	require.NoError(t, err)
	rt := make(chan error, 1)
	go func() {
		resp, err := tr.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		rt <- err
	}()
	sess := <-got
	start := time.Now()
	require.NoError(t, sess.Close())
	assert.Less(t, time.Since(start), alertWriteTimeout, "Session.Close waited past its deadline")
	assert.Error(t, <-returned, "the handler's request context outlived Session.Close")
	assertH3RequestReset(t, <-rt)
}

func TestSession_CloseUnderARelayGivesTheClientNoCloseNotify(t *testing.T) {
	originCA, err := GenerateCA()
	require.NoError(t, err)
	leaf, err := originCA.Leaf("origin.test")
	require.NoError(t, err)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*leaf}, NextProtos: []string{"x-test"}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		t.Cleanup(func() { _ = c.Close() })
		if _, rerr := c.Read(make([]byte, 1)); rerr != nil {
			return
		}
		_, _ = c.Write(make([]byte, 400<<10))
		_, _ = io.Copy(io.Discard, c)
	}()

	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	p.cfg.transport.RootCAs = originCA.CertPool()
	p.MustAdd[TCP]("origin.test", func(c *TCPCtx) error { return c.Relay() })
	p.MustAdd[TCP](ln.Addr().String(), func(c *TCPCtx) error { return c.Relay() })
	addr := startProxy(t, p)

	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
		})
	}}
	raw, err := d.Dial("tcp", addr)
	require.NoError(t, err)
	defer raw.Close()
	_, err = fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr(), ln.Addr())
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(raw), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tc := tls.Client(raw, &tls.Config{RootCAs: ca.CertPool(), ServerName: "origin.test", NextProtos: []string{"x-test"}})
	require.NoError(t, tc.Handshake())
	_, err = tc.Write([]byte{0})
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)

	sess := waitForSessions(t, p, 1)[0]
	closed := make(chan struct{})
	go func() { _ = sess.Close(); close(closed) }()
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, tc.SetReadDeadline(time.Now().Add(3*time.Second)))
	n, err := io.Copy(io.Discard, tc)
	t.Logf("client read %d bytes, then %v", n, err)
	<-closed
	require.Error(t, err, "the client read a close_notify after Session.Close of a byte stream")
	require.False(t, errors.Is(err, os.ErrDeadlineExceeded), "the client read no end of a byte stream Session.Close ended")
}

func TestSession_CloseOfAFreshTerminatedHTTPSession(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	p.MustAdd("allowed.test/", noopHandler)
	client := connectRaw(t, startProxy(t, p), "allowed.test:443")
	tc := tls.Client(client, &tls.Config{RootCAs: ca.CertPool(), ServerName: "allowed.test", NextProtos: []string{"http/1.1"}})
	require.NoError(t, tc.Handshake())
	require.NoError(t, waitForSessions(t, p, 1)[0].Close())
	require.NoError(t, tc.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, err = tc.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF, "a terminated connection Session.Close ended before its first request got no close_notify")
}
