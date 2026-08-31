// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// curlBin is the Homebrew curl, which unlike the one shipped with macOS speaks HTTP/3 and
// reports the negotiated version. Conformance is checked against it rather than against a Go
// client, because a Go client shares its HTTP implementation with the proxy and would agree
// with it on anything both get wrong.
const curlBin = "curl3"

func requireCurl(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath(curlBin)
	if err != nil {
		path, err = exec.LookPath("curl")
		if err != nil {
			t.Skipf("no curl on PATH: %v", err)
		}
	}
	return path
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

// conformanceOrigin starts a TLS origin serving both HTTP/1.1 and HTTP/2.
func conformanceOrigin(t *testing.T) *httptest.Server {
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

func TestConformance_CurlThroughInterceptingProxy(t *testing.T) {
	origin := conformanceOrigin(t)
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
	p.MustAddInterceptor(nil, originHost(originURL)+"/+{any}", func(c *Context) (*http.Response, error) {
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

// An h2c client inside a CONNECT tunnel: curl opens the tunnel to a plaintext port and
// starts HTTP/2 with prior knowledge, no upgrade and no TLS, so the proxy has nothing but
// the connection preface to detect it by. The origin answers over HTTP/1.1: h2 upstream is
// only reachable through ALPN, so the mirrored version stops at what the origin can do.
func TestConformance_CurlH2CThroughInterceptingProxy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "method=%s path=%s proto=%s", r.Method, r.URL.RequestURI(), r.Proto)
	}))
	defer origin.Close()
	originURL, _ := url.Parse(origin.URL)

	p := testProxy(t)

	seen := new(recorder)
	p.MustAddInterceptor(nil, originHost(originURL)+"/+{any}", func(c *Context) (*http.Response, error) {
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
	if !strings.Contains(res.body, "proto=HTTP/1.1") {
		t.Fatalf("origin proto not HTTP/1.1 in %q", res.body)
	}
	if !strings.Contains(res.body, "path=/echo") {
		t.Fatalf("path not preserved in %q", res.body)
	}
	if got := seen.all(); !slices.Contains(got, "HTTP/2.0 /echo") {
		t.Fatalf("interceptor saw %v, want HTTP/2.0 /echo", got)
	}
}

func TestConformance_CurlTunnel(t *testing.T) {
	origin := conformanceOrigin(t)
	originURL, _ := url.Parse(origin.URL)

	ca, _ := GenerateCA()
	p, err := New(WithCA(ca))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if _, err := p.AddTunnel(originHost(originURL)); err != nil {
		t.Fatalf("tunnel %s: %v", originHost(originURL), err)
	}

	// A catch-all on every other authority. The tunnel is registered on a static host, so
	// it is the more precise of the two and decides first. Registering this interceptor on the
	// tunneled authority itself would be refused, which is the point of the authority entry: an interceptor
	// that could never run is a mistake, not a silent no-op.
	routed := new(atomic.Bool)
	p.MustAddInterceptor(nil, "+{any}/+{rest}", func(c *Context) (*http.Response, error) {
		routed.Store(true)
		return c.Forward()
	})

	addr := startProxy(t, p)

	// curl is told to trust the origin and nothing else. An interception would present a
	// certificate minted by the proxy CA, which is not in this file, and the handshake
	// would fail before any request went out.
	originCA := filepath.Join(t.TempDir(), "origin.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})
	if err := os.WriteFile(originCA, pemBytes, 0o600); err != nil {
		t.Fatalf("write origin CA: %v", err)
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

func TestConformance_CurlChunkedResponse(t *testing.T) {
	origin := conformanceOrigin(t)
	originURL, _ := url.Parse(origin.URL)

	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	p.MustAddInterceptor(nil, originHost(originURL)+"/*{any}", DefaultNoInterceptorHandler)
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

func TestConformance_CurlOverHTTPSProxy(t *testing.T) {
	origin := conformanceOrigin(t)
	originURL, _ := url.Parse(origin.URL)

	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	p.MustAddInterceptor(nil, originHost(originURL)+"/*{any}", DefaultNoInterceptorHandler)

	// The proxy port itself speaks TLS, so curl reaches it with an HTTPS proxy URL. The
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
		name  string
		flags []string
	}{
		{name: "h1 to proxy, h1 to origin", flags: []string{"--http1.1"}},
		{name: "h1 to proxy, h2 to origin", flags: []string{"--http2"}},
		// --proxy-http2 makes curl speak HTTP/2 to the proxy itself, so the tunnel is an
		// HTTP/2 CONNECT stream rather than a hijacked HTTP/1.1 connection.
		{name: "h2 to proxy, h1 to origin", flags: []string{"--proxy-http2", "--http1.1"}},
		{name: "h2 to proxy, h2 to origin", flags: []string{"--proxy-http2", "--http2"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
		})
	}
}

// selfSignedFor mints a server certificate for host signed by ca, for the proxy's own port.
func selfSignedFor(t *testing.T, ca *CA, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Certificate(), key.Public(), ca.key)
	if err != nil {
		t.Fatalf("sign proxy certificate: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der, ca.Certificate().Raw}, PrivateKey: key, Leaf: leaf}
}

// recorder collects what handlers observed. A test driven by curl gets its result through
// another process, so nothing orders the handler goroutine against the test goroutine and
// the collection has to carry its own lock.
type recorder struct {
	mu      sync.Mutex
	entries []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, s)
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.entries)
}

// TestConformance_CurlProxyAuth drives the proxy authentication with curl rather than a Go
// client. Go's transport sends Basic preemptively from the proxy URL and never answers a
// challenge, so it is the one client that would never exercise the 407.
func TestConformance_CurlProxyAuth(t *testing.T) {
	origin := conformanceOrigin(t)
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
	p.MustAddInterceptor(nil, originHost(originURL)+"/*{any}", func(c *Context) (*http.Response, error) {
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
