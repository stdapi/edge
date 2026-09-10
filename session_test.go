// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// Registering an entry at a more specific kind never moves a connection already open. Stale
// reports it, since the traffic allowed that kind from the start and the entries admit it now.
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

// A connection keeps the entry it was decided on, and Stale reports when the entries as they
// stand would pick another one, whether a more specific entry appeared, that entry went away
// again, or the one serving it was replaced.
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

// A WebSocket session keeps the entry that served its upgrade. Stale replays the request
// lookup, so an entry that would now serve the upgrade first makes it stale.
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

// A connection served request by request has no decision of its own to go stale.
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

// Stale reads a session while the entries change under it, and while the connection it
// describes is being decided and registered.
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

// A tunnel opened over a TLS front carries its own traffic, so a plaintext tunnel reports no
// TLS state and no ALPN even though the connection to the proxy negotiated both.
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

// A connection a client opens to the proxy itself addresses the proxy, not an authority, so it
// has no decision of its own and is not reported.
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

// Closing while traffic flows must not race the goroutines serving it.
func TestSession_CloseUnderTraffic(t *testing.T) {
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

// admitSession is what leaves no window between a commit and a sweep. A connection decided
// before the commit and registered after it replays its decision and is refused.
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
				sess := newSession(p, context.Background(), nil, target, kind, 0)
				sess.servableAs = []Kind{KindHTTP, KindTCP}
				sess.entry.Store(e)
				return sess
			}

			admitted := decide()
			require.True(t, p.srv.admitSession(admitted))
			require.Len(t, slices.Collect(p.Sessions()), 1)
			p.srv.trackSession(admitted, false)

			late := decide()
			tc.change(t, p)
			assert.False(t, p.srv.admitSession(late), "decided before the change, registered after it")
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

// The proxy-facing session of an explicit connection ends with the connection. A plain
// proxied request is served under it, so a handler waiting on Session.Context is released
// when the client goes away.
func TestSession_FrontContextEndsWithTheConnection(t *testing.T) {
	p := testProxy(t)
	frontSessionContext(t, p, proxyClient(startProxy(t, p), nil))
}

// The same contract when the proxy itself is reached over TLS.
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

// FuzzSplitHostPort checks the authority splitter against its inverse. Everything the proxy
// routes on goes through it, including hostile authorities off the wire.
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

// A WebSocket handler owns the upgrade request it is handed, so Stale replays a copy while
// the handler writes to the original.
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

// An entry committed while the origin answers the upgrade makes the decision stale before the
// session is registered, so the client is refused and reads the status alone.
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
