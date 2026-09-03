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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func h2Client(addr string, trust *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
			TLSClientConfig:   &tls.Config{RootCAs: trust, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		},
	}
}

func TestProxy_InterceptHTTP2(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin proto %s", r.Proto)
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	var clientProto, clientALPN string
	p.MustAdd(originHost(originURL)+"/h2", func(c *HTTPCtx) (*http.Response, error) {
		clientProto = c.Protocol().String()
		if st := c.Request().TLS; st != nil {
			clientALPN = st.NegotiatedProtocol
		}
		return c.Forward()
	}, WithMethods[HTTP](http.MethodGet))

	addr := startProxy(t, p)
	client := h2Client(addr, ca.CertPool())

	resp, err := client.Get(origin.URL + "/h2")
	if err != nil {
		t.Fatalf("get through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "origin proto HTTP/2.0" {
		t.Fatalf("body = %q, want origin proto HTTP/2.0", body)
	}
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("client saw %s, want HTTP/2.0", resp.Proto)
	}
	if clientProto != "HTTP/2.0" {
		t.Fatalf("handler saw protocol %q, want HTTP/2.0", clientProto)
	}
	if clientALPN != "h2" {
		t.Fatalf("negotiated ALPN = %q, want h2", clientALPN)
	}
}

func TestProxy_ALPNMirrorsClientOffer(t *testing.T) {
	cases := []struct {
		name       string
		offer      []string
		negotiated string
	}{
		{name: "http/1.1 only", offer: []string{"http/1.1"}, negotiated: "http/1.1"},
		{name: "h2 preferred", offer: []string{"h2", "http/1.1"}, negotiated: "h2"},
		{name: "http/1.1 preferred", offer: []string{"http/1.1", "h2"}, negotiated: "http/1.1"},
		// A client offering only http/1.1 among what it wants still lands on HTTP.
		{name: "http/1.1 behind another", offer: []string{"spdy/3", "http/1.1"}, negotiated: "http/1.1"},
		{name: "no offer", offer: nil, negotiated: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, _ := GenerateCA()
			p, err := New(WithCA(ca))
			if err != nil {
				t.Fatalf("new proxy: %v", err)
			}

			var negotiated string
			p.MustAdd("example.test/", func(c *HTTPCtx) (*http.Response, error) {
				negotiated = c.Request().TLS.NegotiatedProtocol
				return Text(http.StatusOK, "ok"), nil
			})

			addr := startProxy(t, p)

			// The proxy must answer with what the client offered, never with what it would
			// have preferred: an app that speaks only HTTP/1.1 must not end up on h2.
			tr := &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
				TLSClientConfig: &tls.Config{
					RootCAs:    ca.CertPool(),
					MinVersion: tls.VersionTLS12,
					NextProtos: tc.offer,
				},
				TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
			}
			if slices.Contains(tc.offer, "h2") {
				if err := http2.ConfigureTransport(tr); err != nil {
					t.Fatalf("configure h2: %v", err)
				}
				tr.TLSClientConfig.NextProtos = tc.offer
			}
			client := &http.Client{Timeout: 10 * time.Second, Transport: tr}

			resp, err := client.Get("https://example.test/")
			if err != nil {
				t.Fatalf("get through proxy: %v", err)
			}
			_ = resp.Body.Close()

			if negotiated != tc.negotiated {
				t.Fatalf("negotiated ALPN = %q, want %q", negotiated, tc.negotiated)
			}
		})
	}
}

func TestProxy_StreamsWithoutBuffering(t *testing.T) {
	release := make(chan struct{})
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		fmt.Fprint(w, "data: first\n\n")
		_ = rc.Flush()
		<-release
		fmt.Fprint(w, "data: second\n\n")
		_ = rc.Flush()
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
	p.MustAdd(originHost(originURL)+"/events", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	}, WithMethods[HTTP](http.MethodGet))

	addr := startProxy(t, p)
	client := proxyClient(addr, ca.CertPool())

	resp, err := client.Get(origin.URL + "/events")
	if err != nil {
		t.Fatalf("get events: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read first event: %v", err)
	}
	// Reaching this before the origin has written the second event proves the proxy is not
	// waiting for the body to end before relaying it.
	if strings.TrimSpace(line) != "data: first" {
		t.Fatalf("first event = %q", line)
	}

	close(release)
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "data: second") {
		t.Fatalf("second event missing from %q", rest)
	}
}

func TestProxy_ForwardsTrailers(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Checksum")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "payload")
		w.Header().Set("X-Checksum", "deadbeef")
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
	p.MustAdd(originHost(originURL)+"/*{any}", forwardHandler)

	addr := startProxy(t, p)
	client := proxyClient(addr, ca.CertPool())

	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "payload" {
		t.Fatalf("body = %q", body)
	}
	if got := resp.Trailer.Get("X-Checksum"); got != "deadbeef" {
		t.Fatalf("trailer X-Checksum = %q, want deadbeef", got)
	}
}

// A gRPC client announces trailer support and speaks HTTP/2, where "trailers" is the only
// value TE may carry. The announcement must survive the hop the proxy adds, or an origin that
// enforces it refuses the call.
func TestProxy_AnnouncesTETrailersOverHTTP2(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "te=%s proto=%s", r.Header.Get("Te"), r.Proto)
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	p.MustAdd(originHost(originURL)+"/*{any}", forwardHandler)

	addr := startProxy(t, p)
	client := h2Client(addr, ca.CertPool())

	req, err := http.NewRequest(http.MethodGet, origin.URL+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("TE", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "te=trailers proto=HTTP/2.0" {
		t.Fatalf("origin saw %q, want te=trailers proto=HTTP/2.0", body)
	}
}

// startProxyTLS serves p as an explicit proxy reached over TLS, offering h2 in ALPN, and
// returns its address with a pool that trusts it.
func startProxyTLS(t *testing.T, p *Proxy, ca *CA) (string, *x509.CertPool) {
	t.Helper()

	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() { _ = p.ServeTLS(ln, *cert) }()
	t.Cleanup(func() { _ = p.Close() })

	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	return ln.Addr().String(), pool
}

// An HTTP/2 client reaches a plain HTTP origin without CONNECT. HTTP/2 has no absolute-form
// request target, so the authority arrives in :authority rather than in the URL, and reading
// only the URL refused every such request.
func TestProto_HTTP2ClientWithoutConnect(t *testing.T) {
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

// An origin-form target still means the client is not configured to use a proxy, but only
// HTTP/1.1 can say so: in HTTP/2 the two are written the same way.
func TestProto_OriginFormIsStillRefusedOverHTTP1(t *testing.T) {
	p := testProxy(t)
	addr := startProxy(t, p)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://" + addr + "/foo")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// The session is created from ConnContext, which http.Server calls before the handshake, so
// the TLS state has to be read when it is asked for rather than when the session is built.
func TestProto_SessionTLSOnATLSFrontListener(t *testing.T) {
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

// The same request over h2c, the other way an HTTP/2 client reaches the proxy. There is no
// TLS to read the scheme from, so the target is http, which is what such a client asks for.
func TestProto_H2CClientWithoutConnect(t *testing.T) {
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

// tunnelConn adapts the two halves of an HTTP/2 CONNECT stream to a net.Conn, so a TLS
// client can run inside a tunnel opened over h2c.
type tunnelConn struct {
	r io.ReadCloser
	w io.WriteCloser
}

func (c *tunnelConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *tunnelConn) Write(b []byte) (int, error) { return c.w.Write(b) }
func (c *tunnelConn) Close() error {
	_ = c.w.Close()
	return c.r.Close()
}
func (c *tunnelConn) LocalAddr() net.Addr              { return dummyTunnelAddr{} }
func (c *tunnelConn) RemoteAddr() net.Addr             { return dummyTunnelAddr{} }
func (c *tunnelConn) SetDeadline(time.Time) error      { return nil }
func (c *tunnelConn) SetReadDeadline(time.Time) error  { return nil }
func (c *tunnelConn) SetWriteDeadline(time.Time) error { return nil }

type dummyTunnelAddr struct{}

func (dummyTunnelAddr) Network() string { return "tunnel" }
func (dummyTunnelAddr) String() string  { return "tunnel" }

// A CONNECT carried on an h2c stream. The tunnel is the stream rather than the whole
// connection, which is the path connectStream serves.
func TestProto_H2CConnect(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin")
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

	var seenProto Protocol
	var seenAuthority string
	p.MustAdd(originHost(originURL)+"/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		seenProto, seenAuthority = c.Protocol(), c.Authority()
		return c.Forward()
	})
	addr := startProxy(t, p)

	// h2c to the proxy, opened by hand since http2.Transport has no proxy support.
	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	require.NoError(t, err)

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, "https://"+originURL.Host, pr)
	require.NoError(t, err)

	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "the proxy must accept the CONNECT stream")

	// The tunnel now carries the client's own TLS, which the proxy terminates with its CA.
	tunnel := tls.Client(&tunnelConn{r: resp.Body, w: pw}, &tls.Config{
		RootCAs:    ca.CertPool(),
		ServerName: originURL.Hostname(),
		MinVersion: tls.VersionTLS12,
	})
	defer func() { _ = tunnel.Close() }()

	// The tunnel is already handshaken, so it is handed over as the TLS connection itself.
	inner := http.Client{Transport: &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return tunnel, nil },
	}}
	got, err := inner.Get(origin.URL + "/foo")
	require.NoError(t, err)
	body, _ := io.ReadAll(got.Body)
	_ = got.Body.Close()

	assert.Equal(t, "origin", string(body))
	assert.Equal(t, originURL.Host, seenAuthority)
	// The tunnel carries HTTP/1.1 inside, whatever the stream that opened it was.
	assert.Equal(t, HTTP11, seenProto)
}

// A client offering no HTTP protocol is not asking for HTTP, so an HTTP entry does not serve
// it. What it offered is echoed back, the way an origin supporting everything would, and the
// connection is refused unless something admits it as a stream.
func TestProxy_NonHTTPALPNIsNotHTTP(t *testing.T) {
	ca, _ := GenerateCA()
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd("example.test/", noopHandler)
	addr := startProxy(t, p)

	dial := func() (*tls.Conn, error) {
		raw, derr := net.Dial("tcp", addr)
		if derr != nil {
			return nil, derr
		}
		if _, werr := raw.Write([]byte("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")); werr != nil {
			return nil, werr
		}
		br := bufio.NewReader(raw)
		if _, rerr := http.ReadResponse(br, nil); rerr != nil {
			return nil, rerr
		}
		tc := tls.Client(raw, &tls.Config{
			RootCAs:    ca.CertPool(),
			ServerName: "example.test",
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"spdy/3"},
		})
		return tc, tc.Handshake()
	}

	// ALPN is settled inside the handshake, so a connection refused for what it turned out to
	// be is refused just after it, not before: the handshake completes and nothing follows.
	refused, err := dial()
	require.NoError(t, err)
	require.NoError(t, refused.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = refused.Read(make([]byte, 1))
	assert.Error(t, err, "nothing admits a spdy stream on this authority")
	_ = refused.Close()

	// With a stream entry the same connection is served, and the protocol the client asked
	// for is the one it gets.
	p.MustAdd[TCP]("example.test:443", func(c *TCPCtx) error {
		assert.Equal(t, "spdy/3", c.ALPN())
		_, _ = c.Client().Write([]byte("hello"))
		return nil
	})

	tc, err := dial()
	require.NoError(t, err)
	defer func() { _ = tc.Close() }()
	assert.Equal(t, "spdy/3", tc.ConnectionState().NegotiatedProtocol)

	buf := make([]byte, 5)
	_, err = io.ReadFull(tc, buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf))
}
