package edge

import (
	"net/http"
	"slices"
	"testing"
)

// namedHTTP returns the HTTP entry registered under name, or the zero value.
func namedHTTP(p *Proxy, name string) Entry[HTTP] {
	e, _ := p.Named[HTTP](name)
	return e
}

// lookupHTTP returns the HTTP entry registered for pattern and matchers, or the zero value.
func lookupHTTP(p *Proxy, pattern string, matchers ...Matcher) Entry[HTTP] {
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
func mustMethods(methods ...string) Matcher {
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
