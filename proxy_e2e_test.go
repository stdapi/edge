// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// originHost returns the hostname of a test server, without its port. An interceptor pattern is a
// hostname and a path, so the port never appears in one.
func originHost(u *url.URL) string {
	host, _ := splitHostPort(u.Host)
	return host
}

// originPool returns a pool trusting the certificate of an httptest TLS server.
func originPool(t *testing.T, srv *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

// startProxy starts p on a loopback port and returns its address.
func startProxy(t *testing.T, p *Proxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = p.Serve(ln) }()
	t.Cleanup(func() { _ = p.Close() })
	return ln.Addr().String()
}

// proxyClient returns a client that reaches origins through addr and trusts trust.
func proxyClient(addr string, trust *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
			TLSClientConfig: &tls.Config{RootCAs: trust, MinVersion: tls.VersionTLS12},
		},
	}
}

func TestProxy_InterceptHTTPS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "yes")
		fmt.Fprintf(w, "origin saw %s %s idem=%s", r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"))
	}))
	defer origin.Close()

	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatalf("parse origin url: %v", err)
	}

	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	var seenPattern string
	p.MustAddInterceptor([]string{http.MethodGet}, originHost(originURL)+"/v1/charges", func(c *Context) (*http.Response, error) {
		seenPattern = c.Pattern()
		c.Request().Header.Set("Idempotency-Key", "abc-123")

		resp, err := c.Forward()
		if err != nil {
			return nil, err
		}
		body, err := ReadBody(resp, 0)
		if err != nil {
			return nil, err
		}
		return Rewrite(resp, []byte(string(body)+" | patched")), nil
	})

	addr := startProxy(t, p)
	client := proxyClient(addr, ca.CertPool())

	resp, err := client.Get(origin.URL + "/v1/charges")
	if err != nil {
		t.Fatalf("get through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	want := "origin saw GET /v1/charges idem=abc-123 | patched"
	if string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
	if got := resp.Header.Get("X-Origin"); got != "yes" {
		t.Fatalf("X-Origin = %q, want yes", got)
	}
	if seenPattern != originHost(originURL)+"/v1/charges" {
		t.Fatalf("pattern = %q", seenPattern)
	}
	if resp.ContentLength != int64(len(want)) {
		t.Fatalf("ContentLength = %d, want %d", resp.ContentLength, len(want))
	}
}

func TestProxy_ShortCircuit(t *testing.T) {
	var originHits int
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		fmt.Fprint(w, "should not be reached")
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	p.MustAddInterceptor([]string{http.MethodPost}, originHost(originURL)+"/v1/charges", func(c *Context) (*http.Response, error) {
		if c.Request().Header.Get("Idempotency-Key") == "" {
			return Text(http.StatusBadRequest, "missing idempotency key"), nil
		}
		return c.Forward()
	})

	addr := startProxy(t, p)
	client := proxyClient(addr, ca.CertPool())

	resp, err := client.Post(origin.URL+"/v1/charges", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "missing idempotency key" {
		t.Fatalf("body = %q", body)
	}
	if originHits != 0 {
		t.Fatalf("origin was reached %d times, want 0", originHits)
	}
}

func TestProxy_TunnelKeepsOriginCertificate(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunneled")
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()

	p, err := New(WithCA(ca))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if err := p.AddTunnel(originHost(originURL)); err != nil {
		t.Fatalf("tunnel %s: %v", originHost(originURL), err)
	}

	// Registered on every other authority: the tunnel names a static host, so it is the
	// more precise of the two and wins. Putting this interceptor on the tunneled authority is
	// refused outright, since it could never run.
	var handlerRan bool
	p.MustAddInterceptor([]string{http.MethodGet}, "+{any}/", func(c *Context) (*http.Response, error) {
		handlerRan = true
		return c.Forward()
	})

	addr := startProxy(t, p)

	// The client trusts only the origin, not the proxy CA: if the proxy had intercepted,
	// the handshake would fail on an unknown authority.
	client := proxyClient(addr, originPool(t, origin))

	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("get through tunnel: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "tunneled" {
		t.Fatalf("body = %q, want tunneled", body)
	}
	if handlerRan {
		t.Fatal("handler ran on a tunneled connection")
	}
}

func TestProxy_PlainHTTPAbsoluteTarget(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "plain %s", r.URL.Path)
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()

	p, err := New(WithCA(ca))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	p.MustAddInterceptor([]string{http.MethodGet}, originHost(originURL)+"/hello", func(c *Context) (*http.Response, error) {
		if c.Scheme() != "http" {
			return nil, fmt.Errorf("scheme = %q, want http", c.Scheme())
		}
		resp, err := c.Forward()
		if err != nil {
			return nil, err
		}
		body, _ := ReadBody(resp, 0)
		return Rewrite(resp, []byte(strings.ToUpper(string(body)))), nil
	})

	addr := startProxy(t, p)
	client := proxyClient(addr, nil)

	resp, err := client.Get(origin.URL + "/hello")
	if err != nil {
		t.Fatalf("get through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "PLAIN /HELLO" {
		t.Fatalf("body = %q, want PLAIN /HELLO", body)
	}
}
