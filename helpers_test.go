package edge

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

// namedHTTP returns the HTTP entry registered under name, or the zero value.
func namedHTTP(p *Proxy, name string) Entry[HTTP] {
	e, _ := p.Named[HTTP](name)
	return e
}

// lookupHTTP returns the HTTP entry registered for pattern and matchers, or the zero value.
func lookupHTTP(p *Proxy, pattern string, matchers ...RequestMatcher) Entry[HTTP] {
	e, _ := p.Lookup[HTTP](pattern, matchers...)
	return e
}

// lookupTCP returns the TCP entry registered for pattern, or the zero value.
func lookupTCP(p *Proxy, pattern string) Entry[TCP] {
	e, _ := p.Lookup[TCP](pattern)
	return e
}

// admissionsLen counts the entries admitting an authority, declared and implied alike.
func admissionsLen(p *Proxy) int {
	return len(slices.Collect(p.Iter().Admissions()))
}

// mustMethods builds a method matcher for a test that used to pass a method set.
func mustMethods(methods ...string) RequestMatcher {
	m, err := MatchMethods(methods...)
	if err != nil {
		panic(err)
	}
	return m
}

// collectAuthorities lists the entries admitting an authority.
func collectAuthorities(p *Proxy) []EntryView {
	var out []EntryView
	for v := range p.Iter().Admissions() {
		out = append(out, v)
	}
	return out
}

// forwardHandler is the visible catch-all: what used to be a hidden default is now a route.
func forwardHandler(c *HTTPCtx) (*http.Response, error) { return c.Forward() }

// relayStream carries a byte stream to its origin, which is what an entry has to do for the
// traffic to reach the far side at all.
func relayStream(c *TCPCtx) error { return c.Relay() }

// forwardDatagram passes a datagram on unchanged, which is what a flow has to do for the
// traffic to reach the far side at all.
func forwardDatagram(d *DatagramCtx) error { return d.Forward() }

// relayQUIC carries a terminated QUIC connection to its origin, stream by stream.
func relayQUIC(c *QUICCtx) error { return c.Relay() }

// testProxyWithCA is testProxy for a test that needs the CA back, to trust the certificates
// the proxy mints.
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

// h2cOrigin starts a plaintext origin speaking HTTP/1.1 and HTTP/2 with prior knowledge.
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

// h2cTunnelClient opens a CONNECT tunnel to authority through the proxy at addr and speaks
// HTTP/2 with prior knowledge inside it.
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
