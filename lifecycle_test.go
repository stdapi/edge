// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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

	p, err := New(WithCA(ca), WithIntercept(originHost(originURL)), WithTransport(tr))
	require.NoError(t, err)

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
	p, err := New(WithCA(ca), WithReject("blocked.example.test"))
	require.NoError(t, err)

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
	p, err := New(WithCA(ca), WithIntercept(originHost(originURL)))
	require.NoError(t, err)

	proxySeen := new(recorder)
	p.MustHandle(nil, originHost(originURL)+"/+{any}", func(c *Context) (*http.Response, error) {
		proxySeen.add(c.Method() + " " + c.RoutingPath())
		return c.Forward()
	})
	p.MustHandle(nil, originHost(originURL)+"/", func(c *Context) (*http.Response, error) {
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
	p, err := New()
	require.NoError(t, err)
	require.Nil(t, p.Config().CA())

	addr := startProxy(t, p)
	client := proxyClient(addr, originPool(t, origin))

	resp, err := client.Get(origin.URL + "/")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "tunneled", string(body))
}
