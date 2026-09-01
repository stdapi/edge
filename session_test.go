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
		if !p.Admits(s.Target(), s.Kind()) {
			require.NoError(t, s.Close())
			closed++
		}
	}
	assert.Equal(t, 1, closed, "the orphaned stream is swept")

	// The client reconnects and is refused at the CONNECT, which is what the delete asked for.
	_, err = client.Get(originURL.String())
	require.Error(t, err)
}

// Registering a more specific entry never moves a connection already open. ServableAs records
// what the traffic allows, so the sweep can find the connections such an entry would serve
// and end them.
func TestSession_ServableAsSweepsRefinableStream(t *testing.T) {
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

	sweep := func() int {
		closed := 0
		for s := range p.Sessions() {
			for _, kind := range s.ServableAs() {
				if kind == s.Kind() {
					break
				}
				if p.Admits(s.Target(), kind) {
					_ = s.Close()
					closed++
					break
				}
			}
		}
		return closed
	}
	assert.Zero(t, sweep(), "nothing finer is admitted yet")

	p.MustAdd(originHost(originURL)+"/*{rest}", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	})
	assert.Equal(t, 1, sweep(), "an HTTP entry now serves what this connection carries")
	waitForSessions(t, p, 0)
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

// admitSession is what leaves no window between a delete and a sweep. A connection registered
// after the delete committed reads the tree again and refuses itself.
func TestSession_AdmitAfterDelete(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[TCP]("example.test", relayStream)
	target := Target{Scheme: "https", Host: "example.test", Port: "443"}

	admitted := newSession(context.Background(), nil, target, KindTCP, 0)
	require.True(t, p.srv.admitSession(admitted))
	require.Len(t, slices.Collect(p.Sessions()), 1)
	p.srv.trackSession(admitted, false)

	_, err := p.Delete[TCP]("example.test")
	require.NoError(t, err)

	refused := newSession(context.Background(), nil, target, KindTCP, 0)
	assert.False(t, p.srv.admitSession(refused))
	assert.Empty(t, slices.Collect(p.Sessions()), "a refused connection is not reported")
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
