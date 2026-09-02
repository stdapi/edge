// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// interceptingProxy wires an origin behind a proxy that intercepts it, and returns the
// proxy, the origin hostname and a client pointed at the proxy.
func interceptingProxy(t *testing.T, origin *httptest.Server, opts ...ProxyOption) (*Proxy, string, *http.Client) {
	t.Helper()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)

	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	host := originHost(originURL)
	all := append([]ProxyOption{WithCA(ca), WithTransport(tr)}, opts...)
	p, err := New(all...)
	require.NoError(t, err)

	// Observing an authority without changing anything is a catch-all that forwards. It is
	// what arms the interception: nothing crosses a proxy that was not asked for it.
	p.MustAdd(host+"/*{any}", forwardHandler)

	addr := startProxy(t, p)
	return p, host, proxyClient(addr, ca.CertPool())
}

func TestSemantics_HeadHasNoBody(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5")
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("hello"))
		}
	}))
	defer origin.Close()

	_, _, client := interceptingProxy(t, origin)

	resp, err := client.Head(origin.URL + "/")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Empty(t, body)
	assert.Equal(t, "5", resp.Header.Get("Content-Length"))
}

func TestSemantics_NoContentAndNotModified(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/204":
			w.WriteHeader(http.StatusNoContent)
		case "/304":
			w.WriteHeader(http.StatusNotModified)
		}
	}))
	defer origin.Close()

	_, _, client := interceptingProxy(t, origin)

	for _, path := range []string{"/204", "/304"} {
		resp, err := client.Get(origin.URL + path)
		require.NoError(t, err, path)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Empty(t, body, path)
	}
}

func TestSemantics_RequestBodyStreams(t *testing.T) {
	const size = 4 << 20

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "received %d", n)
	}))
	defer origin.Close()

	_, _, client := interceptingProxy(t, origin)

	body := bytes.Repeat([]byte("x"), size)
	resp, err := client.Post(origin.URL+"/upload", "application/octet-stream", bytes.NewReader(body))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	got, _ := io.ReadAll(resp.Body)
	assert.Equal(t, fmt.Sprintf("received %d", size), string(got))
}

func TestSemantics_ContentEncodingIsNotTouched(t *testing.T) {
	var payload bytes.Buffer
	zw := gzip.NewWriter(&payload)
	_, _ = zw.Write([]byte("compressed payload"))
	require.NoError(t, zw.Close())

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			http.Error(w, "proxy dropped or rewrote Accept-Encoding", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(payload.Bytes())
	}))
	defer origin.Close()

	_, _, client := interceptingProxy(t, origin)

	req, err := http.NewRequest(http.MethodGet, origin.URL+"/gz", nil)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// The client asked for gzip, so it must get gzip: a proxy that decompresses on the way
	// through changes what the application under test observes.
	assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
	raw, _ := io.ReadAll(resp.Body)
	assert.Equal(t, payload.Bytes(), raw)
}

func TestSemantics_HopByHopHeadersAreStripped(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var leaked []string
		for _, h := range []string{"Proxy-Connection", "Keep-Alive", "X-Hop", "Connection"} {
			if r.Header.Get(h) != "" {
				leaked = append(leaked, h)
			}
		}
		fmt.Fprintf(w, "leaked=%s", strings.Join(leaked, ","))
	}))
	defer origin.Close()

	_, _, client := interceptingProxy(t, origin)

	req, _ := http.NewRequest(http.MethodGet, origin.URL+"/", nil)
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "timeout=5")
	// A header named in Connection is hop-by-hop by declaration and must go too.
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "secret")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "leaked=", string(body))
}

func TestSemantics_TETrailersIsAnnouncedForTheProxy(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "te=%s", strings.Join(r.Header.Values("Te"), "|"))
	}))
	defer origin.Close()

	_, _, client := interceptingProxy(t, origin)

	cases := []struct {
		name string
		conn string
		want string
		sent []string
	}{
		{name: "nothing announced", want: "te="},
		{name: "trailers", sent: []string{"trailers"}, want: "te=trailers"},
		{name: "transfer coding only", sent: []string{"gzip"}, want: "te="},
		{name: "trailers among codings", sent: []string{"gzip", "trailers"}, want: "te=trailers"},
		{name: "listed in connection", sent: []string{"trailers"}, conn: "TE", want: "te=trailers"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, origin.URL+"/", nil)
			require.NoError(t, err)
			for _, v := range tc.sent {
				req.Header.Add("TE", v)
			}
			if tc.conn != "" {
				req.Header.Set("Connection", tc.conn)
			}

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			body, _ := io.ReadAll(resp.Body)
			// TE stops at the first hop, so the proxy makes the announcement for itself
			// rather than relaying the client's. A transfer coding it does not implement is
			// not announced at all.
			assert.Equal(t, tc.want, string(body))
		})
	}
}

func TestSemantics_HandlerPanicBecomesAnError(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()

	p, authority, client := interceptingProxy(t, origin)
	p.MustAdd(authority+"/boom", func(c *HTTPCtx) (*http.Response, error) {
		panic("handler exploded")
	}, WithMethods(http.MethodGet))
	p.MustAdd(authority+"/fine", func(c *HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, "still alive"), nil
	}, WithMethods(http.MethodGet))

	resp, err := client.Get(origin.URL + "/boom")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode,
		"a panic is a failure of the proxy, not an answer from the upstream")
	assert.Equal(t, http.StatusText(http.StatusInternalServerError), string(body), "the client learns the status and nothing else")

	// The connection must survive: an application under test should not see a transport
	// failure because a handler had a bug.
	resp, err = client.Get(origin.URL + "/fine")
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, "still alive", string(body))
}

// A panic reaches the error handler as a [PanicError] carrying what recover returned and the
// stack, so a replacement decides both the status and what is logged.
func TestSemantics_PanicReachesTheErrorHandler(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	sentinel := errors.New("boom")

	var got *PanicError
	p, authority, client := interceptingProxy(t, origin, WithErrorHandler(func(c *HTTPCtx, err error) *http.Response {
		got, _ = errors.AsType[*PanicError](err)
		return Status(http.StatusTeapot)
	}))
	p.MustAdd(authority+"/boom", func(c *HTTPCtx) (*http.Response, error) {
		panic(sentinel)
	}, WithMethods(http.MethodGet))

	resp, err := client.Get(origin.URL + "/boom")
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusTeapot, resp.StatusCode)
	require.NotZero(t, got)
	assert.Equal(t, sentinel, got.Value)
	assert.ErrorIs(t, got, sentinel, "a panic carrying an error stays reachable through Unwrap")
	assert.Contains(t, got.Stack, "TestSemantics_PanicReachesTheErrorHandler",
		"the first frame captured must be the one that panicked")
}

func TestSemantics_ErrorHandler(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	sentinel := errors.New("upstream refused")

	p, authority, client := interceptingProxy(t, origin, WithErrorHandler(func(c *HTTPCtx, err error) *http.Response {
		if errors.Is(err, sentinel) {
			return Text(http.StatusServiceUnavailable, "handled: "+err.Error())
		}
		return Status(http.StatusBadGateway)
	}))
	p.MustAdd(authority+"/fail", func(c *HTTPCtx) (*http.Response, error) {
		return nil, sentinel
	}, WithMethods(http.MethodGet))

	resp, err := client.Get(origin.URL + "/fail")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "handled: upstream refused", string(body))
}

func TestSemantics_MiddlewareOrder(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	var order []string
	record := func(name string) Middleware[HTTP] {
		return func(next HTTP) HTTP {
			return func(c *HTTPCtx) (*http.Response, error) {
				order = append(order, "→"+name)
				resp, err := next(c)
				order = append(order, "←"+name)
				return resp, err
			}
		}
	}

	p, authority, client := interceptingProxy(t, origin, WithMiddleware(record("outer"), record("inner")))
	p.MustAdd(authority+"/x", func(c *HTTPCtx) (*http.Response, error) {
		order = append(order, "handler")
		return Status(http.StatusOK), nil
	}, WithMiddleware(record("interceptor")), WithMethods(http.MethodGet))

	resp, err := client.Get(origin.URL + "/x")
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, []string{"→outer", "→inner", "→interceptor", "handler", "←interceptor", "←inner", "←outer"}, order)
}

func TestSemantics_NoInterceptorForwardsUnchanged(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin got %s", r.URL.Path)
	}))
	defer origin.Close()

	p, authority, client := interceptingProxy(t, origin)
	p.MustAdd(authority+"/known", func(c *HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, "handled"), nil
	}, WithMethods(http.MethodGet))

	resp, err := client.Get(origin.URL + "/unknown")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "origin got /unknown", string(body))
}

// The proxy matches on the canonical form of the path and forwards the one the client sent.
// The two differ only by the normalizations RFC 3986 declares equivalent, and the target that
// reaches the origin is the wire target byte for byte.
func TestSemantics_RawPathIsPreserved(t *testing.T) {
	var seen string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.RequestURI
		fmt.Fprint(w, "ok")
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

	var routed string
	p.MustAdd(originHost(originURL)+"/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		routed = c.RoutingPath()
		return c.Forward()
	}, WithMethods(http.MethodGet))
	client := proxyClient(startProxy(t, p), ca.CertPool())

	cases := []struct{ wire, wantRouted string }{
		{"/v1/charges", "/v1/charges"},
		// %2F stays encoded on the wire and is never matched as a path separator.
		{"/files/a%2Fb?q=1%2B2", "/files/a%2Fb"},
		{"/v1%2fcharges", "/v1%2Fcharges"},
		// An escaped unreserved character is decoded for matching, not on the wire.
		{"/v1/%63harges", "/v1/charges"},
		{"/v1/%2e%2e/charges", "/v1/../charges"},
		// Nothing collapses a dot segment or a double slash, in either direction.
		{"//v1/./sub/../charges", "//v1/./sub/../charges"},
		{"/v1/charges;x=1", "/v1/charges;x=1"},
	}

	for _, tc := range cases {
		seen, routed = "", ""
		resp, err := client.Get(origin.URL + tc.wire)
		require.NoError(t, err, tc.wire)
		_ = resp.Body.Close()

		assert.Equal(t, tc.wire, seen, "the request target must reach the origin byte for byte")
		assert.Equal(t, tc.wantRouted, routed, "routing form of %q", tc.wire)
	}
}

// A connection admitted for one authority does not admit the ones its Host header can name.
func TestSemantics_HostHeaderCannotReachAnUnnamedAuthority(t *testing.T) {
	reached := new(atomic.Bool)
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached.Store(true)
	}))
	defer other.Close()

	otherURL, err := url.Parse(other.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd("allowed.example.test/+{rest}", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	})
	require.Equal(t, false, p.Admits(Target{Scheme: "http", Host: "127.0.0.1", Port: otherURL.Port()}, KindHTTP))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.Serve(ln) }()
	t.Cleanup(func() { _ = p.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = fmt.Fprint(conn, "CONNECT allowed.example.test:80 HTTP/1.1\r\nHost: allowed.example.test:80\r\n\r\n")
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	established, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, established.StatusCode)

	_, err = fmt.Fprintf(conn, "GET /probe HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", otherURL.Host)
	require.NoError(t, err)

	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.False(t, reached.Load())
}
