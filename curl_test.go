// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// curlBin is the Homebrew curl, which unlike the one shipped with macOS speaks HTTP/3 and
// reports the negotiated version. Conformance is checked against it rather than against a Go
// client, because a Go client shares its HTTP implementation with the proxy and would agree
// with it on anything both get wrong.
const curlBin = "curl3"

func requireCurl(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath(curlBin)
	if err != nil && !requireTools() {
		path, err = exec.LookPath("curl")
	}
	if err != nil {
		skipWithoutTool(t, "no curl on PATH: %v", err)
	}
	return path
}

func requireCurlHTTP3(t *testing.T) {
	t.Helper()
	out, err := exec.Command(requireCurl(t), "--version").Output()
	if err != nil || !slices.Contains(strings.Fields(string(out)), "HTTP3") {
		skipWithoutTool(t, "the curl on PATH has no HTTP/3")
	}
}

// writeCAFile writes the CA certificate where curl can read it.
func writeCAFile(t *testing.T, ca *CA) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, ca.CertificatePEM(), 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	return path
}

type curlResult struct {
	body    string
	version string
	status  string
}

func runCurl(t *testing.T, args ...string) curlResult {
	t.Helper()
	bin := requireCurl(t)

	full := append([]string{
		"--silent", "--show-error",
		"--write-out", "\nEDGE_VERSION=%{http_version} EDGE_STATUS=%{http_code}",
		"--max-time", "20",
	}, args...)

	cmd := exec.Command(bin, full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("curl %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}

	text := string(out)
	idx := strings.LastIndex(text, "\nEDGE_VERSION=")
	if idx < 0 {
		t.Fatalf("curl output has no status line:\n%s", text)
	}
	tail := text[idx+1:]
	res := curlResult{body: text[:idx]}
	for field := range strings.FieldsSeq(tail) {
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch k {
		case "EDGE_VERSION":
			res.version = v
		case "EDGE_STATUS":
			res.status = v
		}
	}
	return res
}

// curlOrigin starts a TLS origin serving both HTTP/1.1 and HTTP/2.
func curlOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/echo":
			w.Header().Set("X-Origin-Proto", r.Proto)
			fmt.Fprintf(w, "method=%s path=%s proto=%s ua=%s", r.Method, r.URL.RequestURI(), r.Proto, r.Header.Get("User-Agent"))
		case "/chunked":
			w.Header().Set("Content-Type", "text/plain")
			rc := http.NewResponseController(w)
			for i := range 3 {
				fmt.Fprintf(w, "chunk-%d\n", i)
				_ = rc.Flush()
			}
		default:
			http.NotFound(w, r)
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestCurl_ThroughInterceptingProxy(t *testing.T) {
	origin := curlOrigin(t)
	originURL, _ := url.Parse(origin.URL)

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

	seen := new(recorder)
	p.MustAdd(originHost(originURL)+"/+{any}", func(c *HTTPCtx) (*http.Response, error) {
		seen.add(c.Protocol().String() + " " + c.Request().URL.RequestURI())
		return c.Forward()
	})

	addr := startProxy(t, p)
	caFile := writeCAFile(t, ca)

	cases := []struct {
		name        string
		flag        string
		wantVersion string
		wantProto   string
	}{
		{name: "http/1.1", flag: "--http1.1", wantVersion: "1.1", wantProto: "HTTP/1.1"},
		{name: "http/2", flag: "--http2", wantVersion: "2", wantProto: "HTTP/2.0"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runCurl(t,
				tc.flag,
				"--proxy", "http://"+addr,
				"--cacert", caFile,
				origin.URL+"/echo",
			)
			if res.status != "200" {
				t.Fatalf("status = %s, body %q", res.status, res.body)
			}
			if res.version != tc.wantVersion {
				t.Fatalf("negotiated version = %s, want %s", res.version, tc.wantVersion)
			}
			if !strings.Contains(res.body, "proto="+tc.wantProto) {
				t.Fatalf("origin proto not %s in %q", tc.wantProto, res.body)
			}
			if !strings.Contains(res.body, "path=/echo") {
				t.Fatalf("path not preserved in %q", res.body)
			}
		})
	}
}

func TestCurl_H2CThroughInterceptingProxy(t *testing.T) {
	origin := h2cOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "method=%s path=%s proto=%s", r.Method, r.URL.RequestURI(), r.Proto)
	}))
	originURL, _ := url.Parse(origin.URL)

	p := testProxy(t)

	seen := new(recorder)
	p.MustAdd(originHost(originURL)+"/+{any}", func(c *HTTPCtx) (*http.Response, error) {
		seen.add(c.Protocol().String() + " " + c.Request().URL.RequestURI())
		return c.Forward()
	})

	addr := startProxy(t, p)

	res := runCurl(t,
		"--proxytunnel",
		"--http2-prior-knowledge",
		"--proxy", "http://"+addr,
		origin.URL+"/echo",
	)
	if res.status != "200" {
		t.Fatalf("status = %s, body %q", res.status, res.body)
	}
	if res.version != "2" {
		t.Fatalf("negotiated version = %s, want 2", res.version)
	}
	if !strings.Contains(res.body, "proto=HTTP/2.0") {
		t.Fatalf("origin proto not HTTP/2.0 in %q", res.body)
	}
	if !strings.Contains(res.body, "path=/echo") {
		t.Fatalf("path not preserved in %q", res.body)
	}
	if got := seen.all(); !slices.Contains(got, "HTTP/2.0 /echo") {
		t.Fatalf("interceptor saw %v, want HTTP/2.0 /echo", got)
	}
}

func TestCurl_Stream(t *testing.T) {
	origin := curlOrigin(t)
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

	// A request-level catch-all on every other authority. On the static host it names, the
	// HTTP kind has nothing registered, so the connection falls to the stream entry.
	routed := new(atomic.Bool)
	p.MustAdd("+{any}/+{rest}", func(c *HTTPCtx) (*http.Response, error) {
		routed.Store(true)
		return c.Forward()
	})

	addr := startProxy(t, p)

	// Everything admitted is terminated, so curl checks the certificate the proxy minted and
	// the proxy is the one that trusts the origin.
	originCA := filepath.Join(t.TempDir(), "proxy.pem")
	if err := os.WriteFile(originCA, ca.CertificatePEM(), 0o600); err != nil {
		t.Fatalf("write proxy CA: %v", err)
	}

	cases := []struct {
		flag        string
		wantVersion string
		wantProto   string
	}{
		{flag: "--http1.1", wantVersion: "1.1", wantProto: "HTTP/1.1"},
		{flag: "--http2", wantVersion: "2", wantProto: "HTTP/2.0"},
	}

	for _, tc := range cases {
		t.Run(strings.TrimPrefix(tc.flag, "--"), func(t *testing.T) {
			res := runCurl(t,
				tc.flag,
				"--proxy", "http://"+addr,
				"--cacert", originCA,
				origin.URL+"/echo",
			)
			if res.status != "200" {
				t.Fatalf("status = %s, body %q", res.status, res.body)
			}
			if res.version != tc.wantVersion {
				t.Fatalf("negotiated version = %s, want %s", res.version, tc.wantVersion)
			}
			if !strings.Contains(res.body, "proto="+tc.wantProto) {
				t.Fatalf("expected an end to end %s tunnel, got %q", tc.wantProto, res.body)
			}
			if routed.Load() {
				t.Fatal("a handler ran on a tunneled connection")
			}
		})
	}
}

func TestCurl_ChunkedResponse(t *testing.T) {
	origin := curlOrigin(t)
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
	caFile := writeCAFile(t, ca)

	res := runCurl(t,
		"--http1.1",
		"--proxy", "http://"+addr,
		"--cacert", caFile,
		origin.URL+"/chunked",
	)
	if res.status != "200" {
		t.Fatalf("status = %s", res.status)
	}
	for i := range 3 {
		if !strings.Contains(res.body, fmt.Sprintf("chunk-%d", i)) {
			t.Fatalf("chunk %d missing from %q", i, res.body)
		}
	}
}

// requireCurlFlag skips the test when the curl on PATH does not list flag in its help.
func requireCurlFlag(t *testing.T, flag string) {
	t.Helper()
	out, err := exec.Command(requireCurl(t), "--help", "all").Output()
	if err != nil || !strings.Contains(string(out), " "+flag+" ") {
		skipWithoutTool(t, "curl on PATH has no %s", flag)
	}
}

// protoAuth admits every request and records its method and the protocol of the proxy
// connection.
type protoAuth struct{ seen recorder }

func (a *protoAuth) Authenticate(r *http.Request) (string, bool) {
	a.seen.add(r.Method + " " + protoOfRequest(r).String())
	return "", true
}

func (a *protoAuth) Challenges(*http.Request) []string { return nil }

func TestCurl_OverHTTPSProxy(t *testing.T) {
	origin := curlOrigin(t)
	originURL, _ := url.Parse(origin.URL)

	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	auth := new(protoAuth)
	p, err := New(WithCA(ca), WithTransport(tr), WithProxyAuth(auth))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	seen := new(recorder)
	p.MustAdd(originHost(originURL)+"/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		seen.add(c.Protocol().String() + " " + c.Request().URL.RequestURI())
		return c.Forward()
	})

	// The proxy port itself is TLS, so curl reaches it with an HTTPS proxy URL. The
	// certificate authenticating the proxy is minted by the same CA curl already trusts.
	proxyCert := selfSignedFor(t, ca, "localhost")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = p.ServeTLS(ln, proxyCert) }()
	t.Cleanup(func() { _ = p.Close() })

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	caFile := writeCAFile(t, ca)

	cases := []struct {
		name    string
		flags   []string
		front   Protocol
		inner   Protocol
		version string
	}{
		{name: "h1 to proxy, h1 to origin", flags: []string{"--http1.1"}, front: HTTP11, inner: HTTP11, version: "1.1"},
		{name: "h1 to proxy, h2 to origin", flags: []string{"--http2"}, front: HTTP11, inner: HTTP2, version: "2"},
		// --proxy-http2 makes curl negotiate h2 with the proxy, so the tunnel is an HTTP/2
		// CONNECT stream.
		{name: "h2 to proxy, h1 to origin", flags: []string{"--proxy-http2", "--http1.1"}, front: HTTP2, inner: HTTP11, version: "1.1"},
		{name: "h2 to proxy, h2 to origin", flags: []string{"--proxy-http2", "--http2"}, front: HTTP2, inner: HTTP2, version: "2"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.front == HTTP2 {
				requireCurlFlag(t, "--proxy-http2")
			}
			fronts, handled := len(auth.seen.all()), len(seen.all())
			args := append(slices.Clone(tc.flags),
				"--proxy", "https://localhost:"+port,
				"--proxy-cacert", caFile,
				"--cacert", caFile,
				"--resolve", "localhost:"+port+":127.0.0.1",
				origin.URL+"/echo",
			)
			res := runCurl(t, args...)
			if res.status != "200" {
				t.Fatalf("status = %s, body %q", res.status, res.body)
			}
			if !strings.Contains(res.body, "path=/echo") {
				t.Fatalf("unexpected body %q", res.body)
			}
			assert.Equal(t, tc.version, res.version)
			assert.Equal(t, []string{"CONNECT " + tc.front.String()}, auth.seen.all()[fronts:])
			assert.Equal(t, []string{tc.inner.String() + " /echo"}, seen.all()[handled:])
		})
	}
}

func TestCurl_PlainHTTPOverHTTPSProxy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s", r.URL.Path)
	}))
	t.Cleanup(origin.Close)
	originURL, _ := url.Parse(origin.URL)

	ca, _ := GenerateCA()
	auth := new(protoAuth)
	p, err := New(WithCA(ca), WithProxyAuth(auth))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	seen := new(recorder)
	p.MustAdd(originHost(originURL)+"/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		seen.add(c.Session().Protocol().String() + " " + c.Request().URL.RequestURI())
		return c.Forward()
	})

	proxyCert := selfSignedFor(t, ca, "localhost")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = p.ServeTLS(ln, proxyCert) }()
	t.Cleanup(func() { _ = p.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	caFile := writeCAFile(t, ca)

	cases := []struct {
		flag    string
		front   Protocol
		version string
	}{
		{flag: "--http1.1", front: HTTP11, version: "1.1"},
		{flag: "--proxy-http2", front: HTTP2, version: "2"},
	}
	for _, tc := range cases {
		t.Run(tc.flag, func(t *testing.T) {
			if tc.front == HTTP2 {
				requireCurlFlag(t, "--proxy-http2")
			}
			fronts, handled := len(auth.seen.all()), len(seen.all())
			res := runCurl(t,
				tc.flag,
				"--proxy", "https://localhost:"+port,
				"--proxy-cacert", caFile,
				"--resolve", "localhost:"+port+":127.0.0.1",
				origin.URL+"/plain",
			)
			if res.status != "200" || res.body != "path=/plain" {
				t.Fatalf("status = %s, body %q", res.status, res.body)
			}
			assert.Equal(t, tc.version, res.version)
			assert.Equal(t, []string{"GET " + tc.front.String()}, auth.seen.all()[fronts:])
			assert.Equal(t, []string{tc.front.String() + " /plain"}, seen.all()[handled:])
		})
	}
}

func TestCurl_ProxyAuth(t *testing.T) {
	origin := curlOrigin(t)
	originURL, _ := url.Parse(origin.URL)

	ca, _ := GenerateCA()
	p, err := New(WithCA(ca), WithProxyAuth(BasicAuth("edge", func(user, pass string) bool {
		return user == "alice" && pass == "secret"
	})))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	// The handler answers locally, so the origin is never reached and curl only has to trust
	// the proxy CA.
	p.MustAdd(originHost(originURL)+"/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, "identity="+c.Identity()), nil
	})

	addr := startProxy(t, p)
	caFile := writeCAFile(t, ca)

	t.Run("connect with credentials", func(t *testing.T) {
		res := runCurl(t,
			"--proxy", "http://"+addr,
			"--proxy-user", "alice:secret",
			"--cacert", caFile,
			origin.URL+"/echo",
		)
		if res.status != "200" {
			t.Fatalf("status = %s, body %q", res.status, res.body)
		}
		if !strings.Contains(res.body, "identity=alice") {
			t.Fatalf("handler saw %q, want the authenticated identity", res.body)
		}
	})

	// --proxy-anyauth makes curl wait for the challenge and pick a scheme from it, which is
	// the exchange a preemptive client skips.
	t.Run("connect answering the challenge", func(t *testing.T) {
		res := runCurl(t,
			"--proxy", "http://"+addr,
			"--proxy-anyauth",
			"--proxy-user", "alice:secret",
			"--cacert", caFile,
			origin.URL+"/echo",
		)
		if res.status != "200" {
			t.Fatalf("status = %s, body %q", res.status, res.body)
		}
	})

	// A plaintext target is not a CONNECT, so the refusal comes back as an ordinary response
	// curl reports rather than a failed tunnel.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	t.Cleanup(plain.Close)

	t.Run("refused without credentials", func(t *testing.T) {
		res := runCurl(t, "--proxy", "http://"+addr, plain.URL+"/echo")
		if res.status != "407" {
			t.Fatalf("status = %s, want 407, body %q", res.status, res.body)
		}
	})

	t.Run("refused with wrong credentials", func(t *testing.T) {
		res := runCurl(t, "--proxy", "http://"+addr, "--proxy-user", "alice:wrong", plain.URL+"/echo")
		if res.status != "407" {
			t.Fatalf("status = %s, want 407, body %q", res.status, res.body)
		}
	})
}

func TestCurl_ThroughSOCKS5(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	origin := namedOrigin(t, ca, "example.test")
	_, port, _ := net.SplitHostPort(origin.Host)

	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	tr.DialContext = pinnedDialer(origin.Host)
	p, err := New(WithCA(ca), WithTransport(tr), WithProxyAuth(BasicAuth("edge", func(user, pass string) bool {
		return user == "alice" && pass == "secret"
	})))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	p.MustAdd("example.test/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, "identity="+c.Identity()+" authority="+c.Authority()), nil
	})
	p.MustAdd[TCP]("[127.0.0.0/8]", relayStream)

	addr := startSOCKS5(t, p)
	caFile := writeCAFile(t, ca)
	target := "https://example.test:" + port + "/echo"

	cases := []struct {
		name  string
		flags []string
	}{
		{name: "the proxy resolves", flags: []string{"--socks5-hostname", addr}},
		{name: "curl resolves", flags: []string{"--socks5", addr, "--resolve", "example.test:" + port + ":127.0.0.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runCurl(t, append(tc.flags, "--proxy-user", "alice:secret", "--cacert", caFile, target)...)
			if res.status != "200" {
				t.Fatalf("status = %s, body %q", res.status, res.body)
			}
			want := "identity=alice authority=example.test:" + port
			if res.body != want {
				t.Fatalf("handler saw %q, want %q", res.body, want)
			}
		})
	}

	t.Run("wrong credentials", func(t *testing.T) {
		bin := requireCurl(t)
		out, err := exec.Command(bin, "--silent", "--show-error", "--max-time", "10",
			"--socks5-hostname", addr, "--proxy-user", "alice:wrong", "--cacert", caFile, target).CombinedOutput()
		if err == nil {
			t.Fatalf("curl succeeded with wrong credentials: %s", out)
		}
		if !strings.Contains(string(out), "rejected by the SOCKS5 server") {
			t.Fatalf("curl failed for another reason: %s", out)
		}
	})
}

func TestCurl_InterceptHTTP3(t *testing.T) {
	requireCurlHTTP3(t)

	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)

	tr := DefaultTransport()
	tr.AllowHTTP3 = true
	tr.RootCAs = poolOf(originCA)

	p, err := New(WithCA(proxyCA), WithTransport(tr))
	require.NoError(t, err)

	seen := new(recorder)
	p.MustAdd(h3Authority+"/+{any}", func(c *HTTPCtx) (*http.Response, error) {
		seen.add(c.Protocol().String() + " " + c.Request().URL.Path)
		return c.Forward()
	})

	proxyAddr := startQUICRedirected(t, p, origin)
	port := fmt.Sprint(proxyAddr.Port())

	res := runCurl(t,
		"--http3-only",
		"--resolve", h3Authority+":"+port+":127.0.0.1",
		"--cacert", writeCAFile(t, proxyCA),
		fmt.Sprintf("https://%s:%s/echo", h3Authority, port),
	)

	require.Equal(t, "200", res.status, "body %q", res.body)
	assert.Equal(t, "3", res.version, "curl must have used HTTP/3")
	assert.Contains(t, res.body, "proto=HTTP/3.0", "the origin must have been reached over HTTP/3 too")
	assert.Contains(t, res.body, "path=/echo")
	require.Equal(t, []string{"HTTP/3.0 /echo"}, seen.all())
}

func TestCurl_HTTP3HandlerCanShortCircuit(t *testing.T) {
	requireCurlHTTP3(t)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)

	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)

	p.MustAdd(h3Authority+"/blocked", func(c *HTTPCtx) (*http.Response, error) {
		return Text(http.StatusForbidden, "blocked by edge over "+c.Protocol().String()), nil
	}, WithMethods[HTTP](http.MethodGet))

	proxyAddr := startQUIC(t, p)
	port := fmt.Sprint(proxyAddr.Port())

	res := runCurl(t,
		"--http3-only",
		"--resolve", h3Authority+":"+port+":127.0.0.1",
		"--cacert", writeCAFile(t, proxyCA),
		fmt.Sprintf("https://%s:%s/blocked", h3Authority, port),
	)

	assert.Equal(t, "403", res.status)
	assert.Equal(t, "3", res.version)
	assert.Contains(t, res.body, "blocked by edge over HTTP/3.0")
}

func TestCurl_GRPCOverHTTP3(t *testing.T) {
	requireCurlHTTP3(t)

	ca, err := GenerateCA()
	require.NoError(t, err)
	seen := new(recorder)
	origin := httptest.NewUnstartedServer(grpcEchoHandler(seen))
	origin.EnableHTTP2 = true
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedFor(t, ca, "origin.test")}}
	origin.StartTLS()
	t.Cleanup(origin.Close)

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(origin.Listener.Addr().String())
	tr.RootCAs = poolOf(ca)
	p := testProxyWithCA(t, ca, WithTransport(tr))
	p.MustAdd("origin.test/pkg.Svc/Method", forwardCall)
	port := fmt.Sprint(startQUICRedirected(t, p, netip.MustParseAddrPort("127.0.0.1:443")).Port())

	dir := t.TempDir()
	payload := filepath.Join(dir, "payload")
	require.NoError(t, os.WriteFile(payload, grpcPayload("hello"), 0o600))
	headers := filepath.Join(dir, "headers")
	res := runCurl(t,
		"--http3-only",
		"--resolve", "origin.test:"+port+":127.0.0.1",
		"--cacert", writeCAFile(t, ca),
		"-H", "Content-Type: application/grpc",
		"-H", "TE: trailers",
		"--data-binary", "@"+payload,
		"--dump-header", headers,
		"https://origin.test:"+port+"/pkg.Svc/Method",
	)
	dump, err := os.ReadFile(headers)
	require.NoError(t, err)
	_, trailers, ok := strings.Cut(string(dump), "\r\n\r\n")
	require.True(t, ok, "no header block in %q", dump)

	require.Equal(t, "200", res.status, "body %q", res.body)
	assert.Equal(t, "3", res.version)
	assert.Equal(t, string(grpcPayload("hello")), res.body)
	assert.Contains(t, strings.ToLower(trailers), "grpc-status: 0", "headers and trailers %q", dump)
	assert.Equal(t, []string{"HTTP/2.0"}, seen.all())
}
