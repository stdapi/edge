// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func FuzzRoundTripRegistration(f *testing.F) {
	for _, s := range []string{
		"api.stripe.com/v1/charges",
		"127.0.0.1/health",
		"+{sub}.corp.internal/health",
		"/v1/charges",
		"[10.0.0.0/8]/api",
		"[fd00::/8]/v1/{id}",
		"[::1]/8/metrics",
		"10.0.0.1/32",
		"[::/0]/+{rest}",
		"a.test/users/{id}\na.test/users/{id}/posts\na.test/users/{id}/posts/{pid}",
		"a.test/files/+{path}\na.test/files/list",
		"a.test/assets/+{path}/thumbnail\na.test/assets/+{path}/preview",
		"a.test/users/{id}\na.test/users/{id}/*{trail}",
		"a.test/{a}\na.test/{b}\na.test/{c}",
		"a.test/{id:[0-9]+}\na.test/{id:[a-z]+}\na.test/{name}",
		"example.com/users\nexample.com/admin\n#example.com\n#example.com:443",
		"{sub}.example.com/\n{sub}.example.com/users\n#{x}.example.com",
		"+{sub}.example.com/\n+{sub}.example.com/posts/{id}\n#+{s}.example.com",
		"api.+{tenant}.example.com/users\n_srv.example.com/",
		"a.test/foo//bar\na.test/foo//\na.test/foo/",
		"example.com/\nexample.com//\nexample.com/foo",
		"[10.0.0.0/8]/api\n[10.0.0.0/16]/api\n#[10.0.0.0/8]\n10.0.0.1/x",
		"example.com:8080/x\nexample.com:9090/x\n#example.com:8080",
		"a.test/emails/a+b\na.test/glob/*\na.test/a+{x}",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		p := mustFuzzProxy(t)

		type registered struct {
			pattern string
			http    Entry[HTTP]
			tcp     Entry[TCP]
		}
		var added []registered
		require.NoError(t, p.Updates(func(txn *Txn) error {
			for pattern := range strings.SplitSeq(input, "\n") {
				if authority, ok := strings.CutPrefix(pattern, "#"); ok {
					if e, err := txn.Add[TCP](authority, noopStream); err == nil {
						added = append(added, registered{pattern: authority, tcp: e})
					}
					continue
				}
				if e, err := txn.Add(pattern, noopHandler, WithName[HTTP](pattern), WithMethods[HTTP](http.MethodGet)); err == nil {
					added = append(added, registered{pattern: pattern, http: e})
				}
			}
			return nil
		}))
		if p.Len() != len(added) {
			t.Fatalf("Len is %d after %d registrations", p.Len(), len(added))
		}

		for _, r := range added {
			if r.tcp != (Entry[TCP]{}) {
				if got, _ := p.Lookup[TCP](r.pattern); got != r.tcp {
					t.Fatalf("authority %q cannot be found again", r.pattern)
				}
				continue
			}
			if got, _ := p.Lookup[HTTP](r.pattern, mustMethods(http.MethodGet)); got != r.http {
				t.Fatalf("entry %q cannot be found again", r.pattern)
			}
			if got, _ := p.Named[HTTP](r.pattern); got != r.http {
				t.Fatalf("entry %q cannot be found again by name", r.pattern)
			}
		}

		require.NoError(t, p.Updates(func(txn *Txn) error {
			for _, r := range slices.Backward(added) {
				if r.tcp != (Entry[TCP]{}) {
					deleted, err := txn.Delete[TCP](r.pattern)
					if err != nil || deleted != r.tcp {
						t.Fatalf("delete authority %q: %v", r.pattern, err)
					}
					continue
				}
				deleted, err := txn.Delete[HTTP](r.pattern, WithMethods[HTTP](http.MethodGet))
				if err != nil || deleted != r.http {
					t.Fatalf("delete %q: %v", r.pattern, err)
				}
			}
			return nil
		}))
		tree := p.getTree()
		for _, root := range []*node{tree.patterns, tree.addrs, tree.names} {
			if len(root.statics)+len(root.params)+len(root.wildcards) != 0 {
				t.Fatalf("tree not empty after deleting every entry:\n%s", root)
			}
		}
		if tree.handlers != 0 || tree.admissions != 0 {
			t.Fatalf("tree has %d entries and %d admissions left after deleting every entry", tree.handlers, tree.admissions)
		}
	})
}

func TestProxy_Has(t *testing.T) {
	p := testProxy(t, WithRegexpParam(true))
	for _, pattern := range []string{
		"a.test/foo/bar",
		"a.test/welcome/{name}",
		"a.test/welcome/+{name}",
		"a.test/welcome/{name}/ch",
		"a.test/welcome/+{name}/fr",
		"a.test/welcome/{name:[A-z]+}",
		"a.test/welcome/+{name:[A-z]+}",
		"a.test/welcome/{name:[A-z]+}/ch",
		"a.test/welcome/+{name:[A-z]+}/fr",
		"a.test/users/uid_{id}",
		"a.test/users/uid_{id}/ch",
		"a.test/users/uid_{id:[A-z]+}",
		"a.test/users/uid_{id:[A-z]+}/ch",
		"a.test/john/doe/",
		"a.test/foo/*{name}",
		"a.test/foo/uid_*{id}",
		"a.test/a%2Fb",
		"a.test/glob/*0{id}",
		"a.test/glob/+a{id}",
		"a.test:8080/port",
		"{sub}.a.test/host",
		"[10.0.0.0/8]/range",
	} {
		p.MustAdd(pattern, noopHandler)
	}

	for _, tc := range []struct {
		pattern string
		want    bool
	}{
		{"a.test/foo/bar", true},
		{"a.test/john/doe/", true},
		{"a.test/foo/bar/", false},
		{"a.test/john/doe", false},
		{"a.test/welcome/{name}", true},
		{"a.test/welcome/{name:[A-z]+}", true},
		{"a.test/welcome/+{name}", true},
		{"a.test/welcome/+{name:[A-z]+}", true},
		{"a.test/welcome/{name}/ch", true},
		{"a.test/welcome/{name:[A-z]+}/ch", true},
		{"a.test/welcome/+{name}/fr", true},
		{"a.test/welcome/+{name:[A-z]+}/fr", true},
		{"a.test/welcome/fox", false},
		{"a.test/welcome/{other}", false},
		{"a.test/users/uid_{id}", true},
		{"a.test/users/uid_{id:[A-z]+}", true},
		{"a.test/users/uid_{id}/ch", true},
		{"a.test/users/uid_{id:[A-z]+}/ch", true},
		{"a.test/users/uid_123", false},
		{"a.test/a%2Fb", true},
		{"a.test/a%2fb", false},
		{"a.test/a%2%46b", false},
		{"a.test/glob/*0{id}", true},
		{"a.test/glob/*1{id}", false},
		{"a.test/glob/+a{id}", true},
		{"a.test/glob/+b{id}", false},
		{"a.test:8080/port", true},
		{"a.test/port", false},
		{"a.test:9090/port", false},
		{"{sub}.a.test/host", true},
		{"{other}.a.test/host", false},
		{"b.a.test/host", false},
		{"[10.0.0.0/8]/range", true},
		{"10.0.0.1/range", false},
		{"[10.0.0.0/16]/range", false},
	} {
		assert.Equal(t, tc.want, p.Has[HTTP](tc.pattern), tc.pattern)
	}
	assert.False(t, p.Has[WebSocket]("a.test/foo/bar"), "another kind")
}

func TestProxy_HasWithMatchers(t *testing.T) {
	p := testProxy(t, WithRegexpParam(true))
	v1, err := MatchQuery("version", "v1")
	require.NoError(t, err)
	v2, err := MatchQuery("version", "v2")
	require.NoError(t, err)
	key, err := MatchHeader("X-Api-Key", "secret")
	require.NoError(t, err)

	require.NoError(t, p.Updates(func(txn *Txn) error {
		for _, r := range []struct {
			pattern  string
			matchers []RequestMatcher
		}{
			{"a.test/api/users", nil},
			{"a.test/api/users", []RequestMatcher{v1}},
			{"a.test/api/users", []RequestMatcher{v2}},
			{"a.test/api/users", []RequestMatcher{v1, key}},
			{"a.test/api/users/{id}", nil},
			{"a.test/api/users/{id}", []RequestMatcher{v1}},
			{"a.test/files/+{path}", nil},
			{"a.test/files/+{path}", []RequestMatcher{v1}},
			{"a.test/items/{id:[0-9]+}", nil},
			{"a.test/items/{id:[0-9]+}", []RequestMatcher{v1}},
			{"a.test/org/{org}/repo/{repo:[a-z]+}", []RequestMatcher{v1}},
		} {
			var opts []EntryOption[HTTP]
			if r.matchers != nil {
				opts = append(opts, WithRequestMatchers[HTTP](r.matchers...))
			}
			if _, err := txn.Add(r.pattern, noopHandler, opts...); err != nil {
				return err
			}
		}
		return nil
	}))

	cases := []struct {
		name     string
		pattern  string
		matchers []RequestMatcher
		want     bool
	}{
		{"static without matcher", "a.test/api/users", nil, true},
		{"static with its matcher", "a.test/api/users", []RequestMatcher{v1}, true},
		{"static with another value", "a.test/api/users", []RequestMatcher{v2}, true},
		{"static with two matchers", "a.test/api/users", []RequestMatcher{v1, key}, true},
		{"static with two matchers in another order", "a.test/api/users", []RequestMatcher{key, v1}, true},
		{"static with a matcher not registered alone", "a.test/api/users", []RequestMatcher{key}, false},
		{"static with matchers never registered together", "a.test/api/users", []RequestMatcher{v1, v2}, false},
		{"static with a method it does not have", "a.test/api/users", []RequestMatcher{mustMethods(http.MethodGet)}, false},
		{"param without matcher", "a.test/api/users/{id}", nil, true},
		{"param with its matcher", "a.test/api/users/{id}", []RequestMatcher{v1}, true},
		{"param with another matcher", "a.test/api/users/{id}", []RequestMatcher{v2}, false},
		{"wildcard without matcher", "a.test/files/+{path}", nil, true},
		{"wildcard with its matcher", "a.test/files/+{path}", []RequestMatcher{v1}, true},
		{"regexp without matcher", "a.test/items/{id:[0-9]+}", nil, true},
		{"regexp with its matcher", "a.test/items/{id:[0-9]+}", []RequestMatcher{v1}, true},
		{"param and regexp with its matcher", "a.test/org/{org}/repo/{repo:[a-z]+}", []RequestMatcher{v1}, true},
		{"param and regexp without matcher", "a.test/org/{org}/repo/{repo:[a-z]+}", nil, false},
		{"param with another key", "a.test/api/users/{name}", nil, false},
		{"param with another key and its matcher", "a.test/api/users/{name}", []RequestMatcher{v1}, false},
		{"regexp with another key", "a.test/items/{num:[0-9]+}", nil, false},
		{"regexp with another key and its matcher", "a.test/items/{num:[0-9]+}", []RequestMatcher{v1}, false},
	}

	for _, tc := range cases {
		assert.Equal(t, tc.want, p.Has[HTTP](tc.pattern, tc.matchers...), tc.name)
	}
	require.NoError(t, p.View(func(txn *Txn) error {
		for _, tc := range cases {
			assert.Equal(t, tc.want, txn.Has[HTTP](tc.pattern, tc.matchers...), tc.name)
		}
		return nil
	}))
}

func TestProxy_LookupAndNamed(t *testing.T) {
	p := testProxy(t)
	for _, r := range githubAPI {
		p.MustAdd("api.github.test"+r.path, noopHandler, WithMethods[HTTP](r.method), WithName[HTTP](r.method+" "+r.path))
	}

	for _, r := range githubAPI {
		e, ok := p.Lookup[HTTP]("api.github.test"+r.path, mustMethods(r.method))
		require.True(t, ok, r.path)
		assert.Equal(t, "api.github.test"+r.path, e.Pattern())

		named, ok := p.Named[HTTP](r.method + " " + r.path)
		require.True(t, ok, r.path)
		assert.Equal(t, e, named)

		_, ok = p.Lookup[HTTP]("api.github.test"+r.path, mustMethods("PURGE"))
		assert.False(t, ok, r.path)
		_, ok = p.Lookup[HTTP]("api.github.test" + r.path)
		assert.False(t, ok, r.path)
	}
}

func TestProxy_DeleteErrors(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("a.test/foo/bar", noopHandler, WithMethods[HTTP](http.MethodGet))
	p.MustAdd[TCP]("smtp.test:25", noopStream)

	_, err := p.Delete[HTTP]("a.test/{")
	assert.ErrorAs(t, err, new(*PatternError), "invalid pattern")
	_, err = p.Delete[HTTP]("a.test/users/j%6Fhn")
	assert.ErrorAs(t, err, new(*PatternError), "non-canonical pattern")
	_, err = p.Delete[HTTP]("a.test/foo/bar/", WithMethods[HTTP](http.MethodGet))
	assert.ErrorIs(t, err, ErrEntryNotFound, "trailing slash")
	_, err = p.Delete[HTTP]("a.test/foo/bar", WithMethods[HTTP](http.MethodTrace))
	assert.ErrorIs(t, err, ErrEntryNotFound, "another method")
	_, err = p.Delete[HTTP]("a.test/foo/bar")
	assert.ErrorIs(t, err, ErrEntryNotFound, "without its method")
	_, err = p.Delete[WebSocket]("a.test/foo/bar")
	assert.ErrorIs(t, err, ErrEntryNotFound, "another kind")
	_, err = p.Delete[TCP]("smtp.test:26")
	assert.ErrorIs(t, err, ErrEntryNotFound, "another port")
	_, err = p.Delete[UDP]("smtp.test:25")
	assert.ErrorIs(t, err, ErrEntryNotFound, "another connection kind")
	assert.Equal(t, 2, p.Len())
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

func h2cOnlyOrigin(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	origin := httptest.NewUnstartedServer(h)
	origin.Config.Protocols = new(http.Protocols)
	origin.Config.Protocols.SetUnencryptedHTTP2(true)
	origin.Start()
	t.Cleanup(origin.Close)
	return origin
}

// h2cFrontClient sends each request to the proxy at addr over unencrypted HTTP/2, with no
// CONNECT.
func h2cFrontClient(addr string) *http.Client {
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Protocols: protocols,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
	}
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
