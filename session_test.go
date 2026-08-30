// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
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
func tunneledOrigin(t *testing.T, p *Proxy) (*http.Client, *url.URL, *x509.CertPool) {
	t.Helper()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	t.Cleanup(origin.Close)

	u, err := url.Parse(origin.URL)
	require.NoError(t, err)
	require.NoError(t, p.AddTunnel(originHost(u)))

	pool := originPool(t, origin)
	return proxyClient(startProxy(t, p), pool), u, pool
}

func TestSession_TunnelIsListedAndClosed(t *testing.T) {
	p := testProxy(t)
	client, originURL, _ := tunneledOrigin(t, p)

	resp, err := client.Get(originURL.String())
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	// The transport keeps the CONNECT tunnel open, so the session outlives the request.
	sessions := waitForSessions(t, p, 1)
	sess := sessions[0]
	assert.Equal(t, Tunnel, sess.Action())
	assert.Equal(t, originHost(originURL), sess.Target().Host)
	assert.NotZero(t, sess.ID())

	require.NoError(t, sess.Close())
	assert.NoError(t, sess.Close(), "Close is idempotent")

	// The serving goroutine unwinds and unregisters the session it owned.
	waitForSessions(t, p, 0)
}

func TestSession_SweepAfterDeleteTunnel(t *testing.T) {
	p := testProxy(t)
	client, originURL, _ := tunneledOrigin(t, p)

	resp, err := client.Get(originURL.String())
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	waitForSessions(t, p, 1)

	_, err = p.DeleteTunnel(originHost(originURL))
	require.NoError(t, err)

	var closed int
	for s := range p.Sessions() {
		if p.Decide(s.Target()) == Reject {
			require.NoError(t, s.Close())
			closed++
		}
	}
	assert.Equal(t, 1, closed, "the orphaned tunnel is swept")

	// The client reconnects and is refused at the CONNECT, which is what the delete asked for.
	_, err = client.Get(originURL.String())
	require.Error(t, err)
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
	p.MustAddInterceptor(nil, originHost(originURL)+"/*{rest}", func(c *Context) (*http.Response, error) {
		return c.Forward()
	})

	client := proxyClient(startProxy(t, p), p.cfg.ca.CertPool())
	resp, err := client.Get(originURL.String())
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, Intercept, sessions[0].Action())
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
	p.MustAddInterceptor(nil, originHost(originURL)+"/*{rest}", func(c *Context) (*http.Response, error) {
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
	p := testProxy(t)
	client, originURL, _ := tunneledOrigin(t, p)

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
	require.NoError(t, p.AddTunnel("example.test"))
	target := Target{Scheme: "https", Host: "example.test", Port: "443"}

	admitted := newSession(context.Background(), nil, target, Tunnel, HTTP11)
	require.True(t, p.srv.admitSession(admitted))
	require.Len(t, slices.Collect(p.Sessions()), 1)
	p.srv.trackSession(admitted, false)

	_, err := p.DeleteTunnel("example.test")
	require.NoError(t, err)

	refused := newSession(context.Background(), nil, target, Tunnel, HTTP11)
	assert.False(t, p.srv.admitSession(refused))
	assert.Empty(t, slices.Collect(p.Sessions()), "a refused connection is not reported")
}
