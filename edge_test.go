// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func FuzzRoundTripRegistration(f *testing.F) {
	seeds := []string{
		"api.stripe.com/v1/charges",
		"127.0.0.1/health",
		"+{sub}.corp.internal/health",
		"/v1/charges",
		"[10.0.0.0/8]/api",
		"[fd00::/8]/v1/{id}",
		"[::1]/8/metrics",
		"10.0.0.1/32",
		"[::/0]/+{rest}",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		p := mustFuzzProxy(t)

		ic, err := p.Add(raw, noopHandler, WithMethods[HTTP](http.MethodGet))
		if err != nil {
			return
		}

		found := lookupHTTP(p, raw, mustMethods(http.MethodGet))
		if found == (Entry[HTTP]{}) {
			t.Fatalf("entry registered as %q cannot be found again", raw)
		}
		if found != ic {
			t.Fatalf("Lookup returned a different entry for %q", raw)
		}

		deleted, err := p.Delete[HTTP](raw, WithMethods[HTTP](http.MethodGet))
		if err != nil {
			t.Fatalf("delete %q: %v", raw, err)
		}
		if deleted != ic {
			t.Fatalf("Delete returned a different interceptor for %q", raw)
		}
		if p.Len() != 0 {
			t.Fatalf("tree still holds %d interceptors after deleting %q", p.Len(), raw)
		}
	})
}

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
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Certificate(), key.Public(), ca.key)
	if err != nil {
		t.Fatalf("sign proxy certificate: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der, ca.Certificate().Raw}, PrivateKey: key, Leaf: leaf}
}

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

func namedHTTP(p *Proxy, name string) Entry[HTTP] {
	e, _ := p.Named[HTTP](name)
	return e
}

func lookupHTTP(p *Proxy, pattern string, matchers ...RequestMatcher) Entry[HTTP] {
	e, _ := p.Lookup[HTTP](pattern, matchers...)
	return e
}

func lookupTCP(p *Proxy, pattern string) Entry[TCP] {
	e, _ := p.Lookup[TCP](pattern)
	return e
}

func admissionsLen(p *Proxy) int {
	return len(slices.Collect(p.Iter().Admissions()))
}

func mustMethods(methods ...string) RequestMatcher {
	m, err := MatchMethods(methods...)
	if err != nil {
		panic(err)
	}
	return m
}

func collectAuthorities(p *Proxy) []EntryView {
	var out []EntryView
	for v := range p.Iter().Admissions() {
		out = append(out, v)
	}
	return out
}

func forwardHandler(c *HTTPCtx) (*http.Response, error) { return c.Forward() }

func relayStream(c *TCPCtx) error { return c.Relay() }

func forwardDatagram(d *DatagramCtx) error { return d.Forward() }

func relayQUIC(c *QUICCtx) error { return c.Relay() }

func testProxyWithCA(t *testing.T, ca *CA, opts ...ProxyOption) *Proxy {
	t.Helper()
	p, err := New(append([]ProxyOption{WithCA(ca)}, opts...)...)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	return p
}

func mustFuzzProxy(tb testing.TB) *Proxy {
	tb.Helper()
	ca, err := GenerateCA()
	if err != nil {
		tb.Fatal(err)
	}
	p, err := New(WithCA(ca), WithRegexpParam(true))
	if err != nil {
		tb.Fatal(err)
	}
	return p
}

func h2cOrigin(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	origin := httptest.NewUnstartedServer(h)
	origin.Config.Protocols = new(http.Protocols)
	origin.Config.Protocols.SetHTTP1(true)
	origin.Config.Protocols.SetUnencryptedHTTP2(true)
	origin.Start()
	t.Cleanup(origin.Close)
	return origin
}

func h2cTunnelClient(t *testing.T, addr, authority string) *http.Client {
	t.Helper()
	raw := connectRaw(t, addr, authority)
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Protocols:   protocols,
			DialContext: func(context.Context, string, string) (net.Conn, error) { return raw, nil },
		},
	}
}

func originHost(u *url.URL) string {
	host, _ := splitHostPort(u.Host)
	return host
}

func originPool(t *testing.T, srv *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

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

func proxyClient(addr string, trust *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
			TLSClientConfig: &tls.Config{RootCAs: trust, MinVersion: tls.VersionTLS12},
		},
	}
}

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

	p.MustAdd(host+"/*{any}", forwardHandler)

	addr := startProxy(t, p)
	return p, host, proxyClient(addr, ca.CertPool())
}

func testProxy(t *testing.T, opts ...ProxyOption) *Proxy {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(append([]ProxyOption{WithCA(ca)}, opts...)...)
	require.NoError(t, err)
	return p
}

func noopHandler(*HTTPCtx) (*http.Response, error) { return Status(http.StatusOK), nil }

func match(t *testing.T, p *Proxy, method, scheme, authority, path string) Entry[HTTP] {
	t.Helper()
	return matchRequest(t, p, scheme, authority, httptest.NewRequest(method, path, nil))
}

func matchRequest(t *testing.T, p *Proxy, scheme, authority string, req *http.Request) Entry[HTTP] {
	t.Helper()
	host, port := splitHostPort(authority)
	target := Target{Scheme: scheme, Host: host, Port: port}.normalized()

	tree := p.getTree()
	c := tree.pool.Get().(*routeCtx)
	defer tree.pool.Put(c)
	c.reset(nil, req, target.Scheme, target.Host, target.Port)

	idx, n := tree.lookup(target.Host, routingPath(req), c, false)
	if n == nil {
		return Entry[HTTP]{}
	}
	return Entry[HTTP]{e: n.entries[idx]}
}

func noopStream(*TCPCtx) error { return nil }

// A conformanceCase is a requirement of a specification and the test that checks it.
type conformanceCase struct {
	run  func(t *testing.T)
	id   string // source and section, such as "rfc9110/7.6.1/1"
	name string // what the peers send
	req  string // the requirement, quoted from the source
	skip string // why the case does not apply, or how edge departs from it
}

func runConformance(t *testing.T, cases []conformanceCase) {
	for _, tc := range cases {
		t.Run(tc.id+" "+tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}
			t.Parallel()
			tc.run(t)
		})
	}
}

func okHandler(*HTTPCtx) (*http.Response, error) { return Text(http.StatusOK, "ok"), nil }

// recordLogger returns a logger and a channel closed once the logger handles a record whose
// message or attributes contain substr.
func recordLogger(substr string) (*slog.Logger, <-chan struct{}) {
	h := &recordHandler{substr: substr, seen: make(chan struct{}), once: new(sync.Once)}
	return slog.New(h), h.seen
}

type recordHandler struct {
	seen   chan struct{}
	once   *sync.Once
	substr string
}

func (*recordHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	text := r.Message
	r.Attrs(func(a slog.Attr) bool {
		text += " " + a.String()
		return true
	})
	if strings.Contains(text, h.substr) {
		h.once.Do(func() { close(h.seen) })
	}
	return nil
}

func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *recordHandler) WithGroup(string) slog.Handler { return h }
