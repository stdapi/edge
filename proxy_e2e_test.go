// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	p.MustAdd(originHost(originURL)+"/v1/charges", func(c *HTTPCtx) (*http.Response, error) {
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
	}, WithMethods[HTTP](http.MethodGet))

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
	p.MustAdd(originHost(originURL)+"/v1/charges", func(c *HTTPCtx) (*http.Response, error) {
		if c.Request().Header.Get("Idempotency-Key") == "" {
			return Text(http.StatusBadRequest, "missing idempotency key"), nil
		}
		return c.Forward()
	}, WithMethods[HTTP](http.MethodPost))

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

func TestProxy_StreamEntryTerminatesAndReoriginates(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "streamed")
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
	if _, err := p.Add[TCP](originHost(originURL), relayStream); err != nil {
		t.Fatalf("stream entry %s: %v", originHost(originURL), err)
	}

	// A request-level catch-all on every other authority. The stream entry names a static
	// host, so on that host the HTTP kind has nothing registered and the connection is
	// served as the byte stream the entry asked for.
	var handlerRan bool
	p.MustAdd("+{any}/", func(c *HTTPCtx) (*http.Response, error) {
		handlerRan = true
		return c.Forward()
	}, WithMethods[HTTP](http.MethodGet))

	addr := startProxy(t, p)

	// Everything admitted is terminated, so the certificate the client checks is the proxy's
	// and the proxy is the one that has to trust the origin.
	client := proxyClient(addr, ca.CertPool())

	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("get through the stream entry: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "streamed" {
		t.Fatalf("body = %q, want streamed", body)
	}
	if handlerRan {
		t.Fatal("a request handler ran on a connection served as a stream")
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

	p.MustAdd(originHost(originURL)+"/hello", func(c *HTTPCtx) (*http.Response, error) {
		if c.Scheme() != "http" {
			return nil, fmt.Errorf("scheme = %q, want http", c.Scheme())
		}
		resp, err := c.Forward()
		if err != nil {
			return nil, err
		}
		body, _ := ReadBody(resp, 0)
		return Rewrite(resp, []byte(strings.ToUpper(string(body)))), nil
	}, WithMethods[HTTP](http.MethodGet))

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

// A wrapper a tunnel is handed must keep the half-close reachable.
var (
	_ closeWriter = (*peekConn)(nil)
	_ closeWriter = transparentConn{}
)

// A client still uploading when the origin is done sending gets the rest of it through.
func TestProxy_TunnelRelaysTheHalfClose(t *testing.T) {
	const head, rest = "head", "the rest of the upload"

	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = originLn.Close() }()

	received := make(chan string, 1)
	go func() {
		conn, aerr := originLn.Accept()
		if aerr != nil {
			received <- "accept: " + aerr.Error()
			return
		}
		defer func() { _ = conn.Close() }()

		first := make([]byte, len(head))
		if _, rerr := io.ReadFull(conn, first); rerr != nil {
			received <- "read: " + rerr.Error()
			return
		}
		// Done sending while the client is still uploading.
		_ = conn.(*net.TCPConn).CloseWrite()

		tail, _ := io.ReadAll(conn)
		received <- string(first) + string(tail)
	}()

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd[TCP](originLn.Addr().String(), relayStream)

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.Serve(proxyLn) }()
	t.Cleanup(func() { _ = p.Close() })

	client, err := net.Dial("tcp", proxyLn.Addr().String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	require.NoError(t, client.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", originLn.Addr(), originLn.Addr())
	require.NoError(t, err)

	br := bufio.NewReader(client)
	established, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, established.StatusCode)

	_, err = client.Write([]byte(head))
	require.NoError(t, err)

	// Reading to EOF is what says the origin's half-close reached the client.
	_, err = io.ReadAll(br)
	require.NoError(t, err)

	_, err = client.Write([]byte(rest))
	require.NoError(t, err)
	require.NoError(t, client.(*net.TCPConn).CloseWrite())

	assert.Equal(t, head+rest, <-received)
}
