// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
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
	"golang.org/x/net/http2/hpack"
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
	}, WithMethods[HTTP](http.MethodGet))
	p.MustAdd(authority+"/fine", func(c *HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, "still alive"), nil
	}, WithMethods[HTTP](http.MethodGet))

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
	}, WithMethods[HTTP](http.MethodGet))

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
	}, WithMethods[HTTP](http.MethodGet))

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
	}, WithMiddleware(record("interceptor")), WithMethods[HTTP](http.MethodGet))

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
	}, WithMethods[HTTP](http.MethodGet))

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
	}, WithMethods[HTTP](http.MethodGet))
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

// A proxy conformance case is one requirement HTTP places on a proxy, checked with a raw
// client in front of edge and a raw origin behind it. A case that cannot apply states the
// reason instead of a scenario.
type proxyConformanceCase struct {
	// id is the section of the source, "rfc9110/7.6.1/1".
	id string
	// name states what the client or the origin sends.
	name string
	// req is the requirement in the words of the RFC.
	req string
	// skip gives the reason the case does not apply, or where edge departs from it.
	skip string
	run  func(t *testing.T)
}

func TestConformanceProxy(t *testing.T) {
	for _, tc := range proxyConformance {
		t.Run(tc.id+" "+tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}
			t.Parallel()
			tc.run(t)
		})
	}
}

// wire reads HTTP/1.1 messages off a connection and keeps every byte it read, so a message is
// checked as it crossed the wire.
type wire struct {
	net.Conn
	br  *bufio.Reader
	rec bytes.Buffer
}

func newWire(c net.Conn) *wire {
	w := &wire{Conn: c}
	w.br = bufio.NewReader(io.TeeReader(c, &w.rec))
	return w
}

func dialWire(t *testing.T, addr string) *wire {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second)))
	return newWire(c)
}

func (w *wire) consumed() int { return w.rec.Len() - w.br.Buffered() }

func (w *wire) headFrom(start int) string {
	raw := w.rec.Bytes()[start:]
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return string(raw[:i+4])
	}
	return string(raw)
}

func (w *wire) send(t *testing.T, s string) {
	t.Helper()
	_, err := io.WriteString(w.Conn, s)
	require.NoError(t, err)
}

type wireRequest struct {
	req  *http.Request
	head string
	body []byte
}

func (w *wire) readRequest() (wireRequest, error) {
	start := w.consumed()
	req, err := http.ReadRequest(w.br)
	if err != nil {
		return wireRequest{}, err
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return wireRequest{}, err
	}
	return wireRequest{head: w.headFrom(start), req: req, body: body}, nil
}

type wireResponse struct {
	resp *http.Response
	err  error
	head string
	body []byte
}

func (w *wire) readResponse(t *testing.T, method string) wireResponse {
	t.Helper()
	start := w.consumed()
	resp, err := http.ReadResponse(w.br, &http.Request{Method: method})
	require.NoError(t, err)
	body, berr := io.ReadAll(resp.Body)
	return wireResponse{head: w.headFrom(start), resp: resp, body: body, err: berr}
}

// readHead reads a header section and nothing past it, for an answer to CONNECT whose
// framing fields the client must ignore.
func (w *wire) readHead(t *testing.T) string {
	t.Helper()
	start := w.consumed()
	for {
		line, err := w.br.ReadString('\n')
		require.NoError(t, err)
		if line == "\r\n" {
			return w.headFrom(start)
		}
	}
}

func (w *wire) wantClosed(t *testing.T) {
	t.Helper()
	require.NoError(t, w.SetReadDeadline(time.Now().Add(3*time.Second)))
	rest, err := io.ReadAll(w.br)
	require.NoError(t, err, "the connection must be closed")
	require.Empty(t, string(rest))
}

func fieldValues(head, name string) []string {
	lines := strings.Split(strings.TrimSuffix(head, "\r\n\r\n"), "\r\n")
	var out []string
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(k, name) {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}

func startLine(head string) string {
	line, _, _ := strings.Cut(head, "\r\n")
	return line
}

func headStatus(t *testing.T, head string) int {
	t.Helper()
	_, rest, _ := strings.Cut(startLine(head), " ")
	code, _, _ := strings.Cut(rest, " ")
	n, err := strconv.Atoi(code)
	require.NoError(t, err, head)
	return n
}

type rawOrigin struct {
	got      chan wireRequest
	notes    chan string
	ends     chan struct{}
	addr     string
	n        atomic.Int32
	accepted atomic.Int32
}

func newRawOrigin(t *testing.T, serve func(o *rawOrigin, w *wire)) *rawOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	o := &rawOrigin{
		addr:  ln.Addr().String(),
		got:   make(chan wireRequest, 16),
		notes: make(chan string, 16),
		ends:  make(chan struct{}, 16),
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			o.accepted.Add(1)
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func() {
				defer func() {
					_ = c.Close()
					select {
					case o.ends <- struct{}{}:
					default:
					}
				}()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				serve(o, newWire(c))
			}()
		}
	}()
	return o
}

func (o *rawOrigin) next(t *testing.T) wireRequest {
	t.Helper()
	select {
	case r := <-o.got:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("the origin received no request")
		return wireRequest{}
	}
}

func (o *rawOrigin) none(t *testing.T) {
	t.Helper()
	select {
	case r := <-o.got:
		t.Fatalf("the origin received %q", r.head)
	case <-time.After(300 * time.Millisecond):
	}
}

func (o *rawOrigin) note(s string) { o.notes <- s }

func (o *rawOrigin) nextNote(t *testing.T) string {
	t.Helper()
	select {
	case s := <-o.notes:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("the origin recorded nothing")
		return ""
	}
}

func (o *rawOrigin) ended(t *testing.T) {
	t.Helper()
	select {
	case <-o.ends:
	case <-time.After(3 * time.Second):
		t.Fatal("the connection to the origin is still open")
	}
}

// n counts the requests across connections, from zero.
func replyEach(reply func(n int, r wireRequest) string) func(*rawOrigin, *wire) {
	return func(o *rawOrigin, w *wire) {
		for {
			r, err := w.readRequest()
			if err != nil {
				return
			}
			o.got <- r
			if _, err := io.WriteString(w, reply(int(o.n.Add(1))-1, r)); err != nil {
				return
			}
		}
	}
}

func always(reply string) func(*rawOrigin, *wire) {
	return replyEach(func(int, wireRequest) string { return reply })
}

const okReply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

type proxyBench struct {
	p      *Proxy
	origin *rawOrigin
	addr   string
}

func newProxyBench(t *testing.T, serve func(*rawOrigin, *wire)) *proxyBench {
	t.Helper()
	o := newRawOrigin(t, serve)
	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(o.addr)
	p := testProxy(t, WithTransport(tr))
	p.MustAdd("origin.test/*{any}", forwardHandler)
	return &proxyBench{p: p, origin: o, addr: startProxy(t, p)}
}

func (b *proxyBench) dial(t *testing.T) *wire { return dialWire(t, b.addr) }

func (b *proxyBench) exchange(t *testing.T, method, raw string) wireResponse {
	t.Helper()
	w := b.dial(t)
	w.send(t, raw)
	return w.readResponse(t, method)
}

func (b *proxyBench) forwarded(t *testing.T, method, raw string) (wireRequest, wireResponse) {
	t.Helper()
	resp := b.exchange(t, method, raw)
	return b.origin.next(t), resp
}

func (b *proxyBench) connect(t *testing.T) *wire {
	t.Helper()
	w := b.dial(t)
	w.send(t, "CONNECT origin.test:80 HTTP/1.1\r\nHost: origin.test:80\r\n\r\n")
	require.Equal(t, http.StatusOK, headStatus(t, w.readHead(t)))
	return w
}

type h2Wire struct {
	fr  *http2.Framer
	enc *hpack.Encoder
	buf bytes.Buffer
}

func dialH2(t *testing.T, addr string) *h2Wire {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = io.WriteString(c, http2.ClientPreface)
	require.NoError(t, err)
	h := &h2Wire{fr: http2.NewFramer(c, c)}
	h.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	h.enc = hpack.NewEncoder(&h.buf)
	require.NoError(t, h.fr.WriteSettings())
	return h
}

func hf(name, value string) hpack.HeaderField { return hpack.HeaderField{Name: name, Value: value} }

func (h *h2Wire) headers(t *testing.T, id uint32, end bool, fields ...hpack.HeaderField) {
	t.Helper()
	h.buf.Reset()
	for _, f := range fields {
		require.NoError(t, h.enc.WriteField(f))
	}
	require.NoError(t, h.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: h.buf.Bytes(), EndHeaders: true, EndStream: end,
	}))
}

// The payload of a DATA frame is copied, the framer reuses its buffer.
func (h *h2Wire) next(t *testing.T, id uint32) any {
	t.Helper()
	for {
		f, err := h.fr.ReadFrame()
		require.NoError(t, err)
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				require.NoError(t, h.fr.WriteSettingsAck())
			}
			continue
		case *http2.PingFrame:
			if !f.IsAck() {
				require.NoError(t, h.fr.WritePing(true, f.Data))
			}
			continue
		case *http2.WindowUpdateFrame:
			continue
		case *http2.GoAwayFrame:
			t.Fatalf("GOAWAY %v", f.ErrCode)
		case *http2.DataFrame:
			if f.StreamID == id {
				return &h2Data{data: bytes.Clone(f.Data()), end: f.StreamEnded()}
			}
			continue
		}
		if f.Header().StreamID == id {
			return f
		}
	}
}

type h2Data struct {
	data []byte
	end  bool
}

type h2Reply struct {
	fields []hpack.HeaderField
	body   []byte
	rst    http2.ErrCode
	reset  bool
}

func (h *h2Wire) reply(t *testing.T, id uint32) h2Reply {
	t.Helper()
	var r h2Reply
	for {
		switch f := h.next(t, id).(type) {
		case *http2.MetaHeadersFrame:
			if r.fields == nil {
				r.fields = f.Fields
			}
			if f.StreamEnded() {
				return r
			}
		case *h2Data:
			r.body = append(r.body, f.data...)
			if f.end {
				return r
			}
		case *http2.RSTStreamFrame:
			r.rst, r.reset = f.ErrCode, true
			return r
		}
	}
}

func h2Field(fields []hpack.HeaderField, name string) (string, bool) {
	for _, f := range fields {
		if f.Name == name {
			return f.Value, true
		}
	}
	return "", false
}

func (h *h2Wire) h2Connect(t *testing.T) []hpack.HeaderField {
	t.Helper()
	h.headers(t, 1, false, hf(":method", "CONNECT"), hf(":authority", "origin.test:80"))
	f, ok := h.next(t, 1).(*http2.MetaHeadersFrame)
	require.True(t, ok, "the answer to CONNECT starts with HEADERS")
	status, _ := h2Field(f.Fields, ":status")
	require.Equal(t, "200", status)
	return f.Fields
}

func drainOrigin(last string) func(*rawOrigin, *wire) {
	return func(o *rawOrigin, w *wire) {
		b, _ := io.ReadAll(w.br)
		o.note(string(b))
		_, _ = io.WriteString(w, last)
	}
}

var proxyConformance = []proxyConformanceCase{
	// RFC 9110 section 6.5, trailer fields.
	{
		id: "rfc9110/6.5.1/1", name: "a chunked response with a trailer field",
		req: "A recipient MUST NOT merge a trailer field into a header section unless the recipient understands the corresponding header field definition and that definition explicitly permits and defines how trailer field values can be safely merged.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 200 OK\r\nTrailer: X-Check\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Check: sum\r\n\r\n"))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTE: trailers\r\n\r\n")
			require.NoError(t, got.err)
			assert.Equal(t, "ok", string(got.body))
			assert.Empty(t, fieldValues(got.head, "X-Check"), "a trailer field is not a header field")
			assert.Equal(t, "sum", got.resp.Trailer.Get("X-Check"))
		},
	},
	{
		id: "rfc9110/6.5.1/2", name: "a chunked request with a trailer field",
		req: "A recipient MUST NOT merge a trailer field into a header section unless the recipient understands the corresponding header field definition and that definition explicitly permits and defines how trailer field values can be safely merged.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTrailer: X-Check\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-Check: sum\r\n\r\n")
			assert.Equal(t, "hi", string(got.body))
			assert.Empty(t, fieldValues(got.head, "X-Check"), "a trailer field is not a header field")
		},
	},
	{
		id: "rfc9110/6.5.1/3", name: "a request without TE",
		req: "The presence of the keyword \"trailers\" in the TE header field (Section 10.1.4) of a request indicates that the client is willing to accept trailer fields, on behalf of itself and any downstream clients.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.Empty(t, fieldValues(got.head, "TE"), "no client promised to accept trailers")
		},
	},

	// RFC 9110 section 7, routing.
	{
		id: "rfc9110/7.1/1", name: "GET with an authority-form target",
		req: "These forms MUST NOT be used with other methods.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got := b.exchange(t, "GET", "GET origin.test:80 HTTP/1.1\r\nHost: origin.test:80\r\n\r\n")
			assert.Equal(t, http.StatusForbidden, got.resp.StatusCode)
			b.origin.none(t)
		},
	},
	{
		id: "rfc9110/7.6/1", name: "an unregistered method, field and status code",
		req: "Intermediaries are expected to forward messages even when protocol elements are not recognized (e.g., new methods, status codes, or field names) since that preserves extensibility for downstream recipients.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 299 Unregistered\r\nX-Unknown-Reply: r\r\nContent-Length: 2\r\n\r\nok"))
			got, resp := b.forwarded(t, "FROB", "FROB http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\nX-Unknown-Field: f\r\n\r\n")
			assert.Equal(t, "FROB /x HTTP/1.1", startLine(got.head))
			assert.Equal(t, []string{"f"}, fieldValues(got.head, "X-Unknown-Field"))
			assert.Equal(t, 299, resp.resp.StatusCode)
			assert.Equal(t, []string{"r"}, fieldValues(resp.head, "X-Unknown-Reply"))
		},
	},
	{
		id: "rfc9110/7.6/2", name: "a request whose target is the proxy itself",
		req: "An intermediary MUST NOT forward a message to itself unless it is protected from an infinite request loop.",
		run: func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			counted := &countingListener{Listener: ln}
			p := testProxy(t)
			p.MustAdd("127.0.0.1/*{any}", forwardHandler)
			go func() { _ = p.Serve(counted) }()
			t.Cleanup(func() { _ = p.Close() })

			addr := ln.Addr().String()
			w := dialWire(t, addr)
			w.send(t, "GET http://"+addr+"/loop HTTP/1.1\r\nHost: "+addr+"\r\n\r\n")
			got := w.readResponse(t, "GET")
			assert.NotEqual(t, http.StatusOK, got.resp.StatusCode)
			assert.LessOrEqual(t, counted.accepted.Load(), int32(2), "the request came back to the proxy more than once")
		},
	},
	{
		id: "rfc9110/7.6.1/1", name: "a request listing fields in Connection",
		req: "Intermediaries MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header or trailer field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself (or replace it with the intermediary's own control options for the forwarded message).",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n"+
				"Connection: X-Hop-A, keep-alive\r\nconnection: x-hop-b\r\nX-HOP-A: 1\r\nx-hop-b: 2\r\nX-End: 3\r\n\r\n")
			assert.Empty(t, fieldValues(got.head, "Connection"))
			assert.Empty(t, fieldValues(got.head, "X-Hop-A"))
			assert.Empty(t, fieldValues(got.head, "X-Hop-B"))
			assert.Equal(t, []string{"3"}, fieldValues(got.head, "X-End"))
		},
	},
	{
		id: "rfc9110/7.6.1/2", name: "a response listing fields in Connection",
		req: "Intermediaries MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header or trailer field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself (or replace it with the intermediary's own control options for the forwarded message).",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 200 OK\r\nConnection: X-Hop\r\nX-Hop: 1\r\nX-End: 2\r\nContent-Length: 2\r\n\r\nok"))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.Empty(t, fieldValues(got.head, "Connection"))
			assert.Empty(t, fieldValues(got.head, "X-Hop"))
			assert.Equal(t, []string{"2"}, fieldValues(got.head, "X-End"))
		},
	},
	{
		id: "rfc9110/7.6.1/3", name: "a response trailer field listed in Connection",
		req: "Intermediaries MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header or trailer field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself (or replace it with the intermediary's own control options for the forwarded message).",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 200 OK\r\nConnection: X-Hop\r\nTrailer: X-Hop, X-Check\r\nTransfer-Encoding: chunked\r\n\r\n"+
				"2\r\nok\r\n0\r\nX-Hop: secret\r\nX-Check: sum\r\n\r\n"))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTE: trailers\r\n\r\n")
			require.NoError(t, got.err)
			assert.Equal(t, "sum", got.resp.Trailer.Get("X-Check"))
			assert.Empty(t, got.resp.Trailer.Values("X-Hop"))
		},
	},
	{
		id: "rfc9110/7.6.1/4", name: "a request trailer field listed in Connection",
		req: "Intermediaries MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header or trailer field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself (or replace it with the intermediary's own control options for the forwarded message).",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nConnection: X-Hop\r\n"+
				"Trailer: X-Hop\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-Hop: secret\r\n\r\n")
			assert.Empty(t, fieldValues(got.head, "X-Hop"))
			assert.Empty(t, got.req.Trailer.Values("X-Hop"))
		},
	},
	{
		id: "rfc9110/7.6.1/5", name: "a request with Proxy-Connection, Keep-Alive, TE and Upgrade",
		req: "Furthermore, intermediaries SHOULD remove or replace fields that are known to require removal before forwarding, whether or not they appear as a connection-option, after applying those fields' semantics.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n"+
				"Proxy-Connection: keep-alive\r\nKeep-Alive: timeout=5\r\nTE: gzip\r\nUpgrade: h2c\r\n\r\n")
			for _, name := range []string{"Proxy-Connection", "Keep-Alive", "TE", "Upgrade", "Connection"} {
				assert.Empty(t, fieldValues(got.head, name), name)
			}
		},
	},
	{
		id: "rfc9110/7.6.1/6", name: "a response with Proxy-Connection, Keep-Alive and Upgrade",
		req: "Furthermore, intermediaries SHOULD remove or replace fields that are known to require removal before forwarding, whether or not they appear as a connection-option, after applying those fields' semantics.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 200 OK\r\nProxy-Connection: keep-alive\r\nKeep-Alive: timeout=5\r\nUpgrade: h2c\r\nContent-Length: 2\r\n\r\nok"))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			for _, name := range []string{"Proxy-Connection", "Keep-Alive", "Upgrade"} {
				assert.Empty(t, fieldValues(got.head, name), name)
			}
		},
	},
	{
		id: "rfc9110/7.6.2/1", name: "TRACE with Max-Forwards 0",
		req: "If the received value is zero (0), the intermediary MUST NOT forward the request; instead, the intermediary MUST respond as the final recipient.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got := b.exchange(t, "TRACE", "TRACE http://origin.test/t HTTP/1.1\r\nHost: origin.test\r\nMax-Forwards: 0\r\n\r\n")
			assert.NotZero(t, got.resp.StatusCode)
			b.origin.none(t)
		},
	},
	{
		id: "rfc9110/7.6.2/2", name: "OPTIONS with Max-Forwards 5",
		req: "If the received Max-Forwards value is greater than zero, the intermediary MUST generate an updated Max-Forwards field in the forwarded message with a field value that is the lesser of a) the received value decremented by one (1) or b) the recipient's maximum supported value for Max-Forwards.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "OPTIONS", "OPTIONS http://origin.test/o HTTP/1.1\r\nHost: origin.test\r\nMax-Forwards: 5\r\n\r\n")
			assert.Equal(t, []string{"4"}, fieldValues(got.head, "Max-Forwards"))
		},
	},
	{
		id: "rfc9110/7.6.3/1", name: "Via on a forwarded message",
		req:  "A proxy MUST send an appropriate Via header field, as described below, in each message that it forwards.",
		skip: "Edge adds nothing to a forwarded message, no Via and no X-Forwarded-For, so the application under test cannot detect a proxy in front of it, as CLAUDE.md states.",
	},
	{
		id: "rfc9110/7.7/1", name: "an absolute-form target with a fully qualified domain name",
		req: "A proxy MUST NOT change the host name if the target URI contains a fully qualified domain name.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "GET", "GET http://Origin.Test.:8080/x HTTP/1.1\r\nHost: Origin.Test.:8080\r\n\r\n")
			assert.Equal(t, []string{"Origin.Test.:8080"}, fieldValues(got.head, "Host"))
		},
	},
	{
		id: "rfc9110/7.7/2", name: "a path and a query the origin may not normalize",
		req: "A proxy MUST NOT modify the \"absolute-path\" and \"query\" parts of the received target URI when forwarding it to the next inbound server except as required by that forwarding protocol.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			const target = "/a/%7Euser/./b/../c//d%2Fe;p=1?q=%2F&x=a+b&&y=%7e"
			got, _ := b.forwarded(t, "GET", "GET http://origin.test"+target+" HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.Equal(t, "GET "+target+" HTTP/1.1", startLine(got.head))
		},
	},
	{
		id: "rfc9110/7.7/3", name: "an absolute-form target with an empty path",
		req: "For example, a proxy forwarding a request to an origin server via HTTP/1.1 will replace an empty path with \"/\" (Section 3.2.1 of [HTTP/1.1]) or \"*\" (Section 3.2.4 of [HTTP/1.1]), depending on the request method.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "GET", "GET http://origin.test HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.Equal(t, "GET / HTTP/1.1", startLine(got.head))
		},
	},
	{
		id: "rfc9110/7.7/4", name: "a response with the no-transform directive",
		req: "A proxy MUST NOT transform the content (Section 6.4) of a response message that contains a no-transform cache directive (Section 5.2.2.6 of [CACHING]).",
		run: func(t *testing.T) {
			var gz bytes.Buffer
			zw := gzip.NewWriter(&gz)
			_, _ = zw.Write([]byte("compressed content"))
			require.NoError(t, zw.Close())
			b := newProxyBench(t, always(fmt.Sprintf("HTTP/1.1 200 OK\r\nCache-Control: no-transform\r\nContent-Encoding: gzip\r\n"+
				"Content-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", gz.Len(), gz.Bytes())))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nAccept-Encoding: gzip\r\n\r\n")
			require.NoError(t, got.err)
			assert.Equal(t, gz.Bytes(), got.body)
			assert.Equal(t, []string{"gzip"}, fieldValues(got.head, "Content-Encoding"))
		},
	},
	{
		id: "rfc9110/7.7/5", name: "a response describing its representation and its origin",
		req: "A proxy SHOULD NOT modify header fields that provide information about the endpoints of the communication chain, the resource state, or the selected representation (other than the content) unless the field's definition specifically allows such modification or the modification is deemed necessary for privacy or security.",
		run: func(t *testing.T) {
			const date = "Mon, 05 Oct 2026 10:00:00 GMT"
			b := newProxyBench(t, always("HTTP/1.1 200 OK\r\nServer: origin/1\r\nDate: "+date+"\r\nETag: \"v1\"\r\n"+
				"Last-Modified: "+date+"\r\nContent-Length: 15\r\n\r\n<html>hi</html>"))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.Equal(t, []string{"origin/1"}, fieldValues(got.head, "Server"))
			assert.Equal(t, []string{date}, fieldValues(got.head, "Date"))
			assert.Equal(t, []string{`"v1"`}, fieldValues(got.head, "ETag"))
			assert.Equal(t, []string{date}, fieldValues(got.head, "Last-Modified"))
			assert.Empty(t, fieldValues(got.head, "Content-Type"), "the origin declared no media type")
		},
	},

	// RFC 9110 section 7.8, Upgrade.
	{
		id: "rfc9110/7.8/1", name: "an HTTP/1.0 request asking for an upgrade",
		req: "A server that receives an Upgrade header field in an HTTP/1.0 request MUST ignore that Upgrade field.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.0\r\nHost: origin.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			assert.Empty(t, fieldValues(got.head, "Upgrade"))
		},
	},
	{
		id: "rfc9110/7.8/2", name: "an upgrade answered with 101",
		req: "A sender of Upgrade MUST also send an \"Upgrade\" connection option in the Connection header field (Section 7.6.1) to inform intermediaries not to forward this field.",
		run: func(t *testing.T) {
			b := newProxyBench(t, func(o *rawOrigin, w *wire) {
				r, err := w.readRequest()
				if err != nil {
					return
				}
				o.got <- r
				_, _ = io.WriteString(w, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo/1\r\n\r\n")
				_, _ = io.Copy(w, w.br)
			})
			b.p.MustAdd("origin.test", relayStream)

			w := b.dial(t)
			w.send(t, "GET http://origin.test/up HTTP/1.1\r\nHost: origin.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: echo/1\r\n\r\n")
			head := w.readHead(t)
			require.Equal(t, http.StatusSwitchingProtocols, headStatus(t, head))
			assert.Equal(t, []string{"echo/1"}, fieldValues(head, "Upgrade"))
			assert.True(t, headerListContains(http.Header{"Connection": fieldValues(head, "Connection")}, "Connection", "upgrade"))

			got := b.origin.next(t)
			assert.Equal(t, []string{"echo/1"}, fieldValues(got.head, "Upgrade"))
			assert.True(t, headerListContains(http.Header{"Connection": fieldValues(got.head, "Connection")}, "Connection", "upgrade"))

			w.send(t, "ping")
			echo := make([]byte, 4)
			_, err := io.ReadFull(w.br, echo)
			require.NoError(t, err)
			assert.Equal(t, "ping", string(echo))
		},
	},

	// RFC 9110 section 9.3.6, CONNECT.
	{
		id: "rfc9110/9.3.6/1", name: "data on an established tunnel",
		req:  "The CONNECT method requests that the recipient establish a tunnel to the destination origin server identified by the request target and, if successful, thereafter restrict its behavior to blind forwarding of data, in both directions, until the tunnel is closed.",
		skip: "Edge terminates everything it admits and relays nothing it cannot observe, as CLAUDE.md states, so a tunnel is served by the entry that admits its traffic.",
	},
	{
		id: "rfc9110/9.3.6/2", name: "CONNECT to an invalid port",
		req: "A server MUST reject a CONNECT request that targets an empty or invalid port number, typically by responding with a 400 (Bad Request) status code.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			b.p.MustAdd("origin.test", relayStream)
			for _, target := range []string{"origin.test:0", "origin.test:65536", "origin.test:http"} {
				w := b.dial(t)
				w.send(t, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
				assert.Equal(t, http.StatusBadRequest, headStatus(t, w.readHead(t)), target)
			}
			assert.Zero(t, b.origin.accepted.Load())
		},
	},
	{
		id: "rfc9110/9.3.6/3", name: "CONNECT to an empty port",
		req:  "A server MUST reject a CONNECT request that targets an empty or invalid port number, typically by responding with a 400 (Bad Request) status code.",
		skip: "Edge reads a CONNECT target without a port as port 443 on purpose, targetFromConnect in connect.go states it, and a target ending in a colon takes the same path.",
	},
	{
		id: "rfc9110/9.3.6/4", name: "the 2xx answer to CONNECT over HTTP/1.1",
		req: "A server MUST NOT send any Transfer-Encoding or Content-Length header fields in a 2xx (Successful) response to CONNECT.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			w := b.dial(t)
			w.send(t, "CONNECT origin.test:80 HTTP/1.1\r\nHost: origin.test:80\r\n\r\n")
			head := w.readHead(t)
			require.Equal(t, http.StatusOK, headStatus(t, head))
			assert.Empty(t, fieldValues(head, "Content-Length"))
			assert.Empty(t, fieldValues(head, "Transfer-Encoding"))
		},
	},
	{
		id: "rfc9110/9.3.6/5", name: "CONNECT declaring content, tunnel bytes right behind it",
		req: "A CONNECT request message does not have content.  The interpretation of data sent after the header section of the CONNECT request message is specific to the version of HTTP in use.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			const inner = "GET /early HTTP/1.1\r\nHost: origin.test\r\n\r\n"
			w := b.dial(t)
			w.send(t, fmt.Sprintf("CONNECT origin.test:80 HTTP/1.1\r\nHost: origin.test:80\r\nContent-Length: %d\r\n\r\n%s", len(inner), inner))
			require.Equal(t, http.StatusOK, headStatus(t, w.readHead(t)))
			got := w.readResponse(t, "GET")
			assert.Equal(t, "ok", string(got.body))
			assert.Equal(t, "GET /early HTTP/1.1", startLine(b.origin.next(t).head))
		},
	},
	{
		id: "rfc9110/9.3.6/6", name: "each side of a tunnel closing after its last bytes",
		req: "A tunnel is closed when a tunnel intermediary detects that either side has closed its connection: the intermediary MUST attempt to send any outstanding data that came from the closed side to the other side, close both connections, and then discard any remaining data left undelivered.",
		run: func(t *testing.T) {
			b := newProxyBench(t, drainOrigin("last words"))
			b.p.MustAdd("origin.test", relayStream)
			w := b.connect(t)
			w.send(t, "\x01ping")
			require.NoError(t, w.Conn.(*net.TCPConn).CloseWrite())
			assert.Equal(t, "\x01ping", b.origin.nextNote(t))
			rest, err := io.ReadAll(w.br)
			require.NoError(t, err)
			assert.Equal(t, "last words", string(rest))
		},
	},
	{
		id: "rfc9110/9.3.6/7", name: "CONNECT to an authority no entry admits",
		req: "Proxies that support CONNECT SHOULD restrict its use to a limited set of known ports or a configurable list of safe request targets.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			w := b.dial(t)
			w.send(t, "CONNECT elsewhere.test:25 HTTP/1.1\r\nHost: elsewhere.test:25\r\n\r\n")
			assert.Equal(t, http.StatusForbidden, headStatus(t, w.readHead(t)))
			assert.Zero(t, b.origin.accepted.Load())
		},
	},
	{
		id: "rfc9110/9.3.7/1", name: "OPTIONS without Max-Forwards",
		req: "A proxy MUST NOT generate a Max-Forwards header field while forwarding a request unless that request was received with a Max-Forwards field.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "OPTIONS", "OPTIONS http://origin.test/o HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.Empty(t, fieldValues(got.head, "Max-Forwards"))
		},
	},

	// RFC 9110 section 10.1.1 and 15.2, Expect and 1xx.
	{
		id: "rfc9110/10.1.1/1", name: "a request expecting 100-continue",
		req: "Upon receiving an HTTP/1.1 (or later) request that has a method, target URI, and complete header section that contains a 100-continue expectation and indicates a request content will follow, a proxy MUST either: * send an immediate response with a final status code, if that status can be determined by examining just the method, target URI, and header fields, or * forward the request toward the origin server by sending a corresponding request-line and header section to the next inbound server.",
		run: func(t *testing.T) {
			b := newProxyBench(t, func(o *rawOrigin, w *wire) {
				req, err := http.ReadRequest(w.br)
				if err != nil {
					return
				}
				o.got <- wireRequest{head: w.headFrom(0), req: req}
				_, _ = io.WriteString(w, "HTTP/1.1 100 Continue\r\n\r\n")
				body, _ := io.ReadAll(req.Body)
				o.note(string(body))
				_, _ = io.WriteString(w, okReply)
			})
			w := b.dial(t)
			w.send(t, "PUT http://origin.test/up HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n")
			got := b.origin.next(t)
			assert.Equal(t, []string{"100-continue"}, fieldValues(got.head, "Expect"))
			assert.Equal(t, http.StatusContinue, w.readResponse(t, "PUT").resp.StatusCode)
			w.send(t, "hello")
			assert.Equal(t, http.StatusOK, w.readResponse(t, "PUT").resp.StatusCode)
			assert.Equal(t, "hello", b.origin.nextNote(t))
		},
	},
	{
		id: "rfc9110/10.1.4/1", name: "a request announcing trailers in TE",
		req: "A sender of TE MUST also send a \"TE\" connection option within the Connection header field (Section 7.6.1) to inform intermediaries not to forward this field.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTE: trailers\r\nConnection: TE\r\n\r\n")
			require.Equal(t, []string{"trailers"}, fieldValues(got.head, "TE"))
			assert.True(t, headerListContains(http.Header{"Connection": fieldValues(got.head, "Connection")}, "Connection", "te"))
		},
	},
	{
		id: "rfc9110/12.5.5/1", name: "Vary on a forwarded response",
		req:  "A proxy MUST NOT generate \"*\" in a Vary field value.",
		skip: "Vary governs what a cache may reuse, and edge stores no response and generates no Vary of its own.",
	},
	{
		id: "rfc9110/15.2/1", name: "a 103 from the origin before its final answer",
		req: "A proxy MUST forward 1xx responses unless the proxy itself requested the generation of the 1xx response.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n"+okReply))
			w := b.dial(t)
			w.send(t, "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			early := w.readResponse(t, "GET")
			assert.Equal(t, http.StatusEarlyHints, early.resp.StatusCode)
			assert.Equal(t, []string{"</s.css>; rel=preload"}, fieldValues(early.head, "Link"))
		},
	},
	{
		id: "rfc9110/15.2/2", name: "a 1xx answer to an HTTP/1.0 client",
		req: "Since HTTP/1.0 did not define any 1xx status codes, a server MUST NOT send a 1xx response to an HTTP/1.0 client.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n"+okReply))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.0\r\nHost: origin.test\r\n\r\n")
			assert.Equal(t, http.StatusOK, got.resp.StatusCode)
		},
	},
	{
		id: "rfc9110/15.2/3", name: "a 103 from the origin to an HTTP/2 client",
		req: "A proxy MUST forward 1xx responses unless the proxy itself requested the generation of the 1xx response.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n"+okReply))
			h := dialH2(t, b.addr)
			h.headers(t, 1, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"))
			early, ok := h.next(t, 1).(*http2.MetaHeadersFrame)
			require.True(t, ok, "the answer starts with HEADERS")
			status, _ := h2Field(early.Fields, ":status")
			assert.Equal(t, "103", status)
			link, _ := h2Field(early.Fields, "link")
			assert.Equal(t, "</s.css>; rel=preload", link)
			got := h.reply(t, 1)
			status, _ = h2Field(got.fields, ":status")
			assert.Equal(t, "200", status)
			_, ok = h2Field(got.fields, "link")
			assert.False(t, ok, "the final answer kept a field of the 103")
			assert.Equal(t, "ok", string(got.body))
		},
	},
	{
		id: "rfc9110/15.2/4", name: "a 103 from the origin to a request expecting 100-continue",
		req: "A proxy MUST forward 1xx responses unless the proxy itself requested the generation of the 1xx response.",
		run: func(t *testing.T) {
			b := newProxyBench(t, func(o *rawOrigin, w *wire) {
				for {
					req, err := http.ReadRequest(w.br)
					if err != nil {
						return
					}
					_, _ = io.WriteString(w, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n")
					_, _ = io.ReadAll(req.Body)
					if _, err := io.WriteString(w, okReply); err != nil {
						return
					}
				}
			})
			// The server writes its 100 from the goroutine reading the body, so a 103 written
			// alongside it is a data race the race detector reports within a few exchanges.
			for range 5 {
				w := b.dial(t)
				w.send(t, "POST http://origin.test/up HTTP/1.1\r\nHost: origin.test\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello")
				var codes []int
				for {
					got := w.readResponse(t, "POST")
					codes = append(codes, got.resp.StatusCode)
					if got.resp.StatusCode == http.StatusEarlyHints {
						assert.Equal(t, []string{"</s.css>; rel=preload"}, fieldValues(got.head, "Link"))
					}
					if got.resp.StatusCode >= http.StatusOK {
						break
					}
				}
				assert.Equal(t, []int{http.StatusContinue, http.StatusEarlyHints, http.StatusOK}, codes)
				_ = w.Close()
			}
		},
	},

	// RFC 9112 section 3.2, the request target.
	{
		id: "rfc9112/3.2/1", name: "a request with two Host field lines",
		req: "A server MUST respond with a 400 (Bad Request) status code to any HTTP/1.1 request message that lacks a Host header field and to any request message that contains more than one Host header field line or a Host header field with an invalid field value.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got := b.exchange(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nHost: other.test\r\n\r\n")
			assert.Equal(t, http.StatusBadRequest, got.resp.StatusCode)
			b.origin.none(t)
		},
	},
	{
		id: "rfc9112/3.2/2", name: "an absolute-form target with userinfo",
		req: "If the target URI includes an authority component, then a client MUST send a field value for Host that is identical to that authority component, excluding any userinfo subcomponent and its \"@\" delimiter (Section 4.2 of [HTTP]).",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "GET", "GET http://user:secret@origin.test:8080/x HTTP/1.1\r\nHost: origin.test:8080\r\n\r\n")
			assert.Equal(t, []string{"origin.test:8080"}, fieldValues(got.head, "Host"))
			assert.NotContains(t, got.head, "secret")
		},
	},
	{
		id: "rfc9112/3.2.2/1", name: "an absolute-form target with a Host that disagrees",
		req: "A proxy that forwards such a request MUST generate a new Host field value based on the received request-target rather than forward the received Host field value.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "GET", "GET http://origin.test/abs HTTP/1.1\r\nHost: other.test\r\n\r\n")
			assert.Equal(t, []string{"origin.test"}, fieldValues(got.head, "Host"))
		},
	},
	{
		id: "rfc9112/3.2.4/1", name: "OPTIONS with an absolute-form target and an empty path",
		req: "If a proxy receives an OPTIONS request with an absolute-form of request-target in which the URI has an empty path and no query component, then the last proxy on the request chain MUST send a request-target of \"*\" when it forwards the request to the indicated origin server.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "OPTIONS", "OPTIONS http://origin.test:8001 HTTP/1.1\r\nHost: origin.test:8001\r\n\r\n")
			assert.Equal(t, "OPTIONS * HTTP/1.1", startLine(got.head))
			assert.Equal(t, []string{"origin.test:8001"}, fieldValues(got.head, "Host"))
		},
	},

	// RFC 9112 section 6, the message body.
	{
		id: "rfc9112/6.1/1", name: "a chunked request",
		req: "A sender MUST NOT apply the chunked transfer coding more than once to a message body (i.e., chunking an already chunked message is not allowed).",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")
			assert.Equal(t, "abcde", string(got.body))
		},
	},
	{
		id: "rfc9112/6.1/2", name: "a chunked response",
		req: "A sender MUST NOT apply the chunked transfer coding more than once to a message body (i.e., chunking an already chunked message is not allowed).",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			require.NoError(t, got.err)
			assert.Equal(t, "abcde", string(got.body))
		},
	},
	{
		id: "rfc9112/6.1/3", name: "a request with a transfer coding the proxy does not implement",
		req: "A server that receives a request message with a transfer coding it does not understand SHOULD respond with 501 (Not Implemented).",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got := b.exchange(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n")
			assert.Equal(t, http.StatusNotImplemented, got.resp.StatusCode)
			b.origin.none(t)
		},
	},
	{
		id: "rfc9112/6.1/4", name: "a 204 from the origin declaring a transfer coding",
		req: "A server MUST NOT send a Transfer-Encoding header field in any response with a status code of 1xx (Informational) or 204 (No Content).",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n"))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.Equal(t, http.StatusNoContent, got.resp.StatusCode)
			assert.Empty(t, fieldValues(got.head, "Transfer-Encoding"))
		},
	},
	{
		id: "rfc9112/6.1/5", name: "a chunked origin response to an HTTP/1.0 client",
		req: "A server MUST NOT send a response containing Transfer-Encoding unless the corresponding request indicates HTTP/1.1 (or later minor revisions).",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.0\r\nHost: origin.test\r\n\r\n")
			require.NoError(t, got.err)
			assert.Empty(t, fieldValues(got.head, "Transfer-Encoding"))
			assert.Equal(t, "hello", string(got.body))
		},
	},
	{
		id: "rfc9112/6.1/6", name: "a request with Transfer-Encoding and Content-Length",
		req:  "Regardless, the server MUST close the connection after responding to such a request to avoid the potential attacks.",
		skip: "net/http drops the Content-Length of a request that also has Transfer-Encoding and keeps the connection open, before edge gets the request.",
	},
	{
		id: "rfc9112/6.1/7", name: "an HTTP/1.0 request with Transfer-Encoding",
		req:  "A server or client that receives an HTTP/1.0 message containing a Transfer-Encoding header field MUST treat the message as if the framing is faulty, even if a Content-Length is present, and close the connection after processing the message.",
		skip: "net/http ignores Transfer-Encoding on an HTTP/1.0 request and frames it by its Content-Length, before edge gets the request.",
	},
	{
		id: "rfc9112/6.3/1", name: "a 304 declaring a Content-Length",
		req: "Any response to a HEAD request and any response with a 1xx (Informational), 204 (No Content), or 304 (Not Modified) status code is always terminated by the first empty line after the header fields, regardless of the header fields present in the message, and thus cannot contain a message body or trailer section.",
		run: func(t *testing.T) {
			b := newProxyBench(t, replyEach(func(n int, _ wireRequest) string {
				if n == 0 {
					return "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nContent-Length: 10\r\n\r\n"
				}
				return okReply
			}))
			w := b.dial(t)
			w.send(t, "GET http://origin.test/a HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.Equal(t, http.StatusNotModified, w.readResponse(t, "GET").resp.StatusCode)
			w.send(t, "GET http://origin.test/b HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			got := w.readResponse(t, "GET")
			assert.Equal(t, "ok", string(got.body))
		},
	},
	{
		id: "rfc9112/6.3/2", name: "a request with Transfer-Encoding and Content-Length",
		req: "An intermediary that chooses to forward the message MUST first remove the received Content-Length field and process the Transfer-Encoding (as described below) prior to forwarding the message downstream.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n")
			assert.NotEqual(t, []string{"4"}, fieldValues(got.head, "Content-Length"))
			assert.Equal(t, "hi", string(got.body))
		},
	},
	{
		id: "rfc9112/6.3/3", name: "a response with Transfer-Encoding and Content-Length",
		req: "An intermediary that chooses to forward the message MUST first remove the received Content-Length field and process the Transfer-Encoding (as described below) prior to forwarding the message downstream.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			require.NoError(t, got.err)
			assert.Empty(t, fieldValues(got.head, "Content-Length"))
			assert.Equal(t, "ok", string(got.body))
		},
	},
	{
		id: "rfc9112/6.3/4", name: "a request whose final transfer coding is not chunked",
		req:  "If a Transfer-Encoding header field is present in a request and the chunked transfer coding is not the final encoding, the message body length cannot be determined reliably; the server MUST respond with the 400 (Bad Request) status code and then close the connection.",
		skip: "net/http answers a request whose final transfer coding is not chunked with a 501 before edge gets the request.",
	},
	{
		id: "rfc9112/6.3/5", name: "a response with an invalid Content-Length",
		req: "If it is in a response message received by a proxy, the proxy MUST close the connection to the server, discard the received response, and send a 502 (Bad Gateway) response to the client.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 200 OK\r\nContent-Length: 2, 3\r\n\r\nok"))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.Equal(t, http.StatusBadGateway, got.resp.StatusCode)
			assert.NotEqual(t, "ok", string(got.body))
			b.origin.ended(t)
		},
	},
	{
		id: "rfc9112/6.3/6", name: "a request with an invalid Content-Length",
		req: "If the unrecoverable error is in a request message, the server MUST respond with a 400 (Bad Request) status code and then close the connection.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			w := b.dial(t)
			w.send(t, "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 1x\r\n\r\nx")
			assert.Equal(t, http.StatusBadRequest, w.readResponse(t, "POST").resp.StatusCode)
			w.wantClosed(t)
			b.origin.none(t)
		},
	},
	{
		id: "rfc9112/6.3/7", name: "a response shorter than its Content-Length",
		req: "If the sender closes the connection or the recipient times out before the indicated number of octets are received, the recipient MUST consider the message to be incomplete and close the connection.",
		run: func(t *testing.T) {
			b := newProxyBench(t, func(o *rawOrigin, w *wire) {
				if r, err := w.readRequest(); err == nil {
					o.got <- r
					_, _ = io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")
				}
			})
			_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.ErrorIs(t, got.err, io.ErrUnexpectedEOF)
			assert.Equal(t, "short", string(got.body))
		},
	},
	{
		id: "rfc9112/6.3/8", name: "a response delimited by the close of the connection",
		req: "Otherwise, this is a response message without a declared message body length, so the message body length is determined by the number of octets received prior to the server closing the connection.",
		run: func(t *testing.T) {
			b := newProxyBench(t, func(o *rawOrigin, w *wire) {
				if r, err := w.readRequest(); err == nil {
					o.got <- r
					_, _ = io.WriteString(w, "HTTP/1.1 200 OK\r\n\r\nall of it")
				}
			})
			_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			require.NoError(t, got.err)
			assert.Equal(t, "all of it", string(got.body))
		},
	},
	{
		id: "rfc9112/6.3/9", name: "a forged response behind the end of a response",
		req: "A client MUST NOT process, cache, or forward such extra data as a separate response, since such behavior would be vulnerable to cache poisoning.",
		run: func(t *testing.T) {
			b := newProxyBench(t, replyEach(func(n int, _ wireRequest) string {
				if n == 0 {
					return "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirstHTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nforged"
				}
				return "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond"
			}))
			w := b.dial(t)
			w.send(t, "GET http://origin.test/1 HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.Equal(t, "first", string(w.readResponse(t, "GET").body))
			w.send(t, "GET http://origin.test/2 HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.Equal(t, "second", string(w.readResponse(t, "GET").body))
		},
	},

	// RFC 9112 section 7.1, chunked.
	{
		id: "rfc9112/7.1/1", name: "a chunk size past 64 bits",
		req: "Therefore, recipients MUST anticipate potentially large hexadecimal numerals and prevent parsing errors due to integer conversion overflows or precision loss due to integer representation.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got := b.exchange(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n\r\n1fffffffffffffffff\r\nhi\r\n0\r\n\r\n")
			assert.GreaterOrEqual(t, got.resp.StatusCode, 400)
			b.origin.none(t)
		},
	},
	{
		id: "rfc9112/7.1.1/1", name: "chunk extensions",
		req: "A recipient MUST ignore unrecognized chunk extensions.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			got, _ := b.forwarded(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n\r\n"+
				"2;ext=1\r\nhi\r\n3;q=\"a b\"\r\nyou\r\n0;last\r\n\r\n")
			assert.Equal(t, "hiyou", string(got.body))
		},
	},

	// RFC 9112 section 9.6, tear-down.
	{
		id: "rfc9112/9.6/1", name: "a request with close and one pipelined behind it",
		req: "A server that receives a \"close\" connection option MUST initiate closure of the connection (see below) after it sends the final response to the request that contained the \"close\" connection option.  The server SHOULD send a \"close\" connection option in its final response on that connection.  The server MUST NOT process any further requests received on that connection.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			w := b.dial(t)
			w.send(t, "GET http://origin.test/a HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n"+
				"GET http://origin.test/b HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			got := w.readResponse(t, "GET")
			assert.Equal(t, "ok", string(got.body))
			assert.True(t, got.resp.Close)
			w.wantClosed(t)
			assert.Equal(t, "GET /a HTTP/1.1", startLine(b.origin.next(t).head))
			b.origin.none(t)
		},
	},

	// RFC 9113, the HTTP/2 front.
	{
		id: "rfc9113/8.2.2/1", name: "an HTTP/1.1 response with connection-specific fields to an HTTP/2 client",
		req: "An intermediary transforming an HTTP/1.x message to HTTP/2 MUST remove connection-specific header fields as discussed in Section 7.6.1 of [HTTP], or their messages will be treated by other HTTP/2 endpoints as malformed (Section 8.1.1).",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 200 OK\r\nConnection: X-Hop\r\nX-Hop: 1\r\nKeep-Alive: timeout=5\r\n"+
				"Proxy-Connection: keep-alive\r\nUpgrade: h2c\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"))
			h := dialH2(t, b.addr)
			h.headers(t, 1, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"))
			got := h.reply(t, 1)
			require.False(t, got.reset, "stream reset with %v", got.rst)
			assert.Equal(t, "ok", string(got.body))
			for _, name := range []string{"connection", "x-hop", "keep-alive", "proxy-connection", "upgrade", "transfer-encoding"} {
				_, ok := h2Field(got.fields, name)
				assert.False(t, ok, name)
			}
		},
	},
	{
		id: "rfc9113/8.3.1/1", name: "a request whose Host differs from :authority",
		req: "The recipient of an HTTP/2 request MUST NOT use the Host header field to determine the target URI if \":authority\" is present.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			b.p.MustAdd("other.test/*{any}", func(*HTTPCtx) (*http.Response, error) {
				return Text(http.StatusOK, "other"), nil
			})
			h := dialH2(t, b.addr)
			h.headers(t, 1, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"),
				hf("host", "other.test"))
			got := h.reply(t, 1)
			assert.Equal(t, "ok", string(got.body))
		},
	},
	{
		id: "rfc9113/8.3.1/2", name: "a request forwarded over HTTP/1.1",
		req: "An intermediary that needs to generate a Host header field (which might be necessary to construct an HTTP/1.1 request) MUST use the value from the \":authority\" pseudo-header field as the value of the Host field, unless the intermediary also changes the request target.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			h := dialH2(t, b.addr)
			h.headers(t, 1, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test:8080"), hf(":path", "/x"))
			h.reply(t, 1)
			got := b.origin.next(t)
			assert.Equal(t, "GET /x HTTP/1.1", startLine(got.head))
			assert.Equal(t, []string{"origin.test:8080"}, fieldValues(got.head, "Host"))
		},
	},
	{
		id: "rfc9113/8.5/1", name: "CONNECT on a stream, a request inside",
		req: "Once this connection is successfully established, the proxy sends a HEADERS frame containing a 2xx-series status code to the client, as defined in Section 9.3.6 of [HTTP].",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			h := dialH2(t, b.addr)
			fields := h.h2Connect(t)
			_, ok := h2Field(fields, "content-length")
			assert.False(t, ok, "a 2xx answer to CONNECT has no content-length")

			require.NoError(t, h.fr.WriteData(1, false, []byte("GET /in HTTP/1.1\r\nHost: origin.test\r\n\r\n")))
			var data []byte
			for !bytes.HasSuffix(data, []byte("\r\n\r\nok")) {
				f, ok := h.next(t, 1).(*h2Data)
				require.True(t, ok, "only DATA follows the 2xx on a CONNECT stream")
				data = append(data, f.data...)
			}
			resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "GET /in HTTP/1.1", startLine(b.origin.next(t).head))
		},
	},
	{
		id: "rfc9113/8.5/2", name: "END_STREAM from the client on a stream tunnel",
		req: "A proxy that receives a DATA frame with the END_STREAM flag set sends the attached data with the FIN bit set on the last TCP segment.",
		run: func(t *testing.T) {
			b := newProxyBench(t, drainOrigin("pong"))
			b.p.MustAdd("origin.test", relayStream)
			h := dialH2(t, b.addr)
			h.h2Connect(t)
			require.NoError(t, h.fr.WriteData(1, true, []byte("\x01ping")))
			assert.Equal(t, "\x01ping", b.origin.nextNote(t))
			got := h.reply(t, 1)
			require.False(t, got.reset, "stream reset with %v", got.rst)
			assert.Equal(t, "pong", string(got.body))
		},
	},
	{
		id: "rfc9113/8.5/3", name: "FIN from the origin while the client is still sending",
		req:  "A proxy that receives a TCP segment with the FIN bit set sends a DATA frame with the END_STREAM flag set.",
		skip: "net/http offers a handler no way to end its half of a stream while it keeps reading the other, and edge leaves h2Stream.CloseWrite a no-op on purpose, conn.go states it.",
	},
	{
		id: "rfc9113/8.5/4", name: "a TCP reset from the origin",
		req: "A proxy treats any error in the TCP connection, which includes receiving a TCP segment with the RST bit set, as a stream error (Section 5.4.2) of type CONNECT_ERROR.",
		run: func(t *testing.T) {
			b := newProxyBench(t, func(o *rawOrigin, w *wire) {
				buf := make([]byte, 5)
				if _, err := io.ReadFull(w.br, buf); err != nil {
					return
				}
				o.note(string(buf))
				_ = w.Conn.(*net.TCPConn).SetLinger(0)
			})
			b.p.MustAdd("origin.test", relayStream)
			h := dialH2(t, b.addr)
			h.h2Connect(t)
			require.NoError(t, h.fr.WriteData(1, false, []byte("\x01ping")))
			assert.Equal(t, "\x01ping", b.origin.nextNote(t))
			got := h.reply(t, 1)
			require.True(t, got.reset, "the stream ended with END_STREAM")
			// net/http resets the stream of an aborted handler with INTERNAL_ERROR and cannot
			// send CONNECT_ERROR.
			assert.Contains(t, []http2.ErrCode{http2.ErrCodeConnect, http2.ErrCodeInternal}, got.rst)
		},
	},
	{
		id: "rfc9113/8.5/5", name: "RST_STREAM from the client on a stream tunnel",
		req: "Correspondingly, a proxy MUST send a TCP segment with the RST bit set if it detects an error with the stream or the HTTP/2 connection.",
		run: func(t *testing.T) {
			b := newProxyBench(t, func(o *rawOrigin, w *wire) {
				buf := make([]byte, 5)
				if _, err := io.ReadFull(w.br, buf); err != nil {
					return
				}
				o.note(string(buf))
				_, err := w.br.ReadByte()
				o.note(fmt.Sprint(errors.Is(err, syscall.ECONNRESET)))
			})
			b.p.MustAdd("origin.test", relayStream)
			h := dialH2(t, b.addr)
			h.h2Connect(t)
			require.NoError(t, h.fr.WriteData(1, false, []byte("\x01ping")))
			assert.Equal(t, "\x01ping", b.origin.nextNote(t))
			require.NoError(t, h.fr.WriteRSTStream(1, http2.ErrCodeCancel))
			assert.Equal(t, "true", b.origin.nextNote(t), "the origin read a FIN where a reset was due")
		},
	},
	{
		id: "rfc9113/8.5/6", name: "HEADERS on a stream tunnel",
		req:  "Frame types other than DATA or stream management frames (RST_STREAM, WINDOW_UPDATE, and PRIORITY) MUST NOT be sent on a connected stream and MUST be treated as a stream error (Section 5.4.2) if received.",
		skip: "net/http reads a HEADERS frame on a CONNECT stream as its trailer section and ends the request body cleanly, before edge gets the frame.",
	},
}

func TestSemantics_NoUserAgentIsAdded(t *testing.T) {
	b := newProxyBench(t, always(okReply))
	got, _ := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	assert.NotContains(t, strings.ToLower(got.head), "user-agent")

	got, _ = b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nUser-Agent: curl/8.0\r\n\r\n")
	assert.Contains(t, got.head, "User-Agent: curl/8.0\r\n")
}

// An origin that fails in the middle of a body leaves the client with a failed read, where a
// clean end would read as a complete body.
func TestSemantics_CutBodyIsNotEndedCleanly(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "partial")
		_ = http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	}))
	defer origin.Close()

	_, _, client := interceptingProxy(t, origin)

	resp, err := client.Get(origin.URL + "/")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	assert.Equal(t, "partial", string(body))
	assert.Error(t, err, "the body read as complete")
}

func TestSemantics_EarlyHintsReachAnHTTP3Client(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</s.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()
	p, _, _ := interceptingProxy(t, origin)
	ca, err := GenerateCA()
	require.NoError(t, err)
	front, _ := startQUICFront(t, p, ca)
	h3 := &http3.Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			return dialQUICFront(t, front, ca), nil
		},
	}
	defer func() { _ = h3.Close() }()

	var codes []int
	var links []string
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
		codes = append(codes, code)
		links = append(links, h.Get("Link"))
		return nil
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace),
		http.MethodGet, origin.URL+"/", nil)
	require.NoError(t, err)
	resp, err := h3.RoundTrip(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	assert.Equal(t, []int{http.StatusEarlyHints}, codes)
	assert.Equal(t, []string{"</s.css>; rel=preload"}, links)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Values("Link"), "the final answer kept a field of the 103")
	assert.Equal(t, "ok", string(body))
}

// RFC 9114 4.4, a TCP reset from the origin of a CONNECT ends the stream with H3_CONNECT_ERROR.
func TestSemantics_OriginResetEndsAnHTTP3ConnectWithConnectError(t *testing.T) {
	b := newProxyBench(t, func(o *rawOrigin, w *wire) {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(w.br, buf); err != nil {
			return
		}
		o.note(string(buf))
		_ = w.Conn.(*net.TCPConn).SetLinger(0)
	})
	b.p.MustAdd("origin.test", relayStream)
	ca, err := GenerateCA()
	require.NoError(t, err)
	front, _ := startQUICFront(t, b.p, ca)
	tr := &http3.Transport{}
	defer func() { _ = tr.Close() }()
	cc := tr.NewClientConn(dialQUICFront(t, front, ca))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	str, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodConnect, "https://origin.test:80", nil)
	require.NoError(t, err)
	require.NoError(t, str.SendRequestHeader(req))
	resp, err := str.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = str.Write([]byte("\x01ping"))
	require.NoError(t, err)
	assert.Equal(t, "\x01ping", b.origin.nextNote(t))

	require.NoError(t, str.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = io.Copy(io.Discard, str)
	h3err, ok := errors.AsType[*http3.Error](err)
	require.True(t, ok, "the stream ended with %v", err)
	assert.Equal(t, http3.ErrCodeConnectError, h3err.ErrorCode)

	require.Eventually(t, func() bool {
		_, err = str.Write([]byte("x"))
		return err != nil
	}, 5*time.Second, 10*time.Millisecond)
	stopped, ok := errors.AsType[*quic.StreamError](err)
	require.True(t, ok, "the write ended with %v", err)
	assert.Equal(t, quic.StreamErrorCode(http3.ErrCodeConnectError), stopped.ErrorCode)
}

// An asterisk-form OPTIONS is routed on its path, and no entry for a path matches it, over
// HTTP/3 and through a tunnel.
func TestSemantics_AsteriskFormNeverReachesAnAdmission(t *testing.T) {
	b := newProxyBench(t, always(okReply))
	b.p.MustAdd("origin.test", relayStream)
	ca, err := GenerateCA()
	require.NoError(t, err)
	front, _ := startQUICFront(t, b.p, ca)
	h3 := &http3.Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			return dialQUICFront(t, front, ca), nil
		},
	}
	defer func() { _ = h3.Close() }()

	resp, err := h3.RoundTrip(&http.Request{
		Method: http.MethodOptions,
		URL:    &url.URL{Scheme: "https", Host: "origin.test", Path: "*"},
		Header: http.Header{},
	})
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	w := b.connect(t)
	w.send(t, "OPTIONS * HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	got := w.readResponse(t, http.MethodOptions)
	assert.Equal(t, http.StatusForbidden, got.resp.StatusCode, "net/http answered OPTIONS * in the tunnel itself")
	b.origin.none(t)
}

// An OPTIONS with an empty path is about the server itself, so it reaches the origin as "*"
// whatever version the proxy uses upstream.
func TestSemantics_OptionsWithAnEmptyPathOverEveryVersion(t *testing.T) {
	asServer := func(c *HTTPCtx) (*http.Response, error) {
		r := c.Request().Clone(c.Request().Context())
		r.Method = http.MethodOptions
		r.URL.Path, r.URL.RawPath = "", ""
		return c.ForwardRequest(r)
	}

	t.Run("HTTP/2", func(t *testing.T) {
		origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s %s %s", r.Method, r.RequestURI, r.Proto)
		}))
		origin.Config.DisableGeneralOptionsHandler = true
		origin.EnableHTTP2 = true
		origin.StartTLS()
		defer origin.Close()

		p, host, client := interceptingProxy(t, origin)
		p.MustAdd(host+"/options", asServer)
		client.Transport.(*http.Transport).ForceAttemptHTTP2 = true

		resp, err := client.Get(origin.URL + "/options")
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		assert.Equal(t, "OPTIONS * HTTP/2.0", string(body))
	})

	t.Run("HTTP/1.1 to another proxy", func(t *testing.T) {
		o := newRawOrigin(t, always(okReply))
		tr := DefaultTransport()
		tr.DialContext = pinnedDialer(o.addr)
		tr.Proxy = func(*http.Request) (*url.URL, error) { return &url.URL{Scheme: "http", Host: "next.test:3128"}, nil }
		p := testProxy(t, WithTransport(tr))
		p.MustAdd("origin.test/*{any}", forwardHandler)
		w := dialWire(t, startProxy(t, p))
		w.send(t, "OPTIONS http://origin.test HTTP/1.1\r\nHost: origin.test\r\n\r\n")
		w.readResponse(t, "OPTIONS")
		assert.Equal(t, "OPTIONS http://origin.test HTTP/1.1", startLine(o.next(t).head), "only the last proxy sends *")
	})

	t.Run("HTTP/3", func(t *testing.T) {
		originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
		require.NoError(t, err)
		origin := h3Origin(t, originCA)
		proxyCA, err := GenerateCA()
		require.NoError(t, err)
		upstream := DefaultTransport()
		upstream.AllowHTTP3 = true
		upstream.RootCAs = poolOf(originCA)
		p, err := New(WithCA(proxyCA), WithTransport(upstream))
		require.NoError(t, err)
		p.MustAdd(h3Authority+"/options", asServer)

		tr := dialQUICTo(startQUICRedirected(t, p, origin), poolOf(proxyCA))
		defer func() { _ = tr.Close() }()
		req, err := http.NewRequest(http.MethodGet, "https://"+h3Authority+"/options", nil)
		require.NoError(t, err)
		resp, err := tr.RoundTrip(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		assert.Contains(t, string(body), "origin method=OPTIONS path=* proto=HTTP/3")
	})
}
