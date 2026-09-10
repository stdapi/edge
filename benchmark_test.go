// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
)

func benchProxy(b *testing.B, patterns ...string) *Proxy {
	b.Helper()
	ca, err := GenerateCA()
	if err != nil {
		b.Fatal(err)
	}
	p, err := New(WithCA(ca))
	if err != nil {
		b.Fatal(err)
	}
	for _, pattern := range patterns {
		if _, err := p.Add(pattern, noopHandler, WithMethods[HTTP](http.MethodGet)); err != nil {
			b.Fatalf("register %s: %v", pattern, err)
		}
	}
	return p
}

func BenchmarkLookup(b *testing.B) {
	cases := []struct {
		name    string
		pattern string
		host    string
		path    string
	}{
		{name: "static", pattern: "api.stripe.com/v1/charges", host: "api.stripe.com", path: "/v1/charges"},
		{name: "param", pattern: "api.stripe.com/v1/{id}/refunds", host: "api.stripe.com", path: "/v1/ch_1234567890/refunds"},
		{name: "wildcard path", pattern: "api.stripe.com/files/+{path}", host: "api.stripe.com", path: "/files/a/b/c/d"},
		{name: "wildcard host", pattern: "+{sub}.stripe.com/v1/charges", host: "eu.west.stripe.com", path: "/v1/charges"},
		{name: "any authority", pattern: "+{any}/v1/charges", host: "anything.example.test", path: "/v1/charges"},
		{name: "exact address", pattern: "10.1.2.3/v1/charges", host: "10.1.2.3", path: "/v1/charges"},
		{name: "range", pattern: "[10.0.0.0/8]/v1/charges", host: "10.1.2.3", path: "/v1/charges"},
		{name: "range v6", pattern: "[fd00::/8]/v1/charges", host: "fd12:3456::1", path: "/v1/charges"},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			p := benchProxy(b, tc.pattern)
			tree := p.getTree()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)

			c := tree.pool.Get().(*routeCtx)
			defer tree.pool.Put(c)
			c.reset(nil, req, "https", tc.host, "443")

			b.ReportAllocs()
			for b.Loop() {
				*c.params = (*c.params)[:0]
				if _, n := tree.lookup(tc.host, tc.path, c, false); n == nil {
					b.Fatal("no match")
				}
			}
		})
	}
}

func BenchmarkLookupDeepTree(b *testing.B) {
	patterns := []string{
		"api.stripe.com/v1/charges",
		"api.stripe.com/v1/charges/{id}",
		"api.stripe.com/v1/charges/{id}/capture",
		"api.stripe.com/v1/charges/{id}/refunds",
		"api.stripe.com/v1/customers",
		"api.stripe.com/v1/customers/{id}",
		"api.stripe.com/v1/customers/{id}/sources/{source}",
		"api.stripe.com/v1/payment_intents",
		"api.stripe.com/v1/payment_intents/{id}",
		"api.stripe.com/v1/subscriptions/{id}/items/{item}",
		"+{sub}.stripe.com/v1/files/+{path}",
		"files.stripe.com/v1/files/{id}",
		"connect.stripe.com/oauth/token",
		"api.internal.corp/health",
		"+{sub}.internal.corp/metrics",
	}
	p := benchProxy(b, patterns...)
	tree := p.getTree()

	const host = "api.stripe.com"
	const path = "/v1/subscriptions/sub_123/items/si_456"
	req := httptest.NewRequest(http.MethodGet, path, nil)

	c := tree.pool.Get().(*routeCtx)
	defer tree.pool.Put(c)
	c.reset(nil, req, "https", host, "443")

	b.ReportAllocs()
	for b.Loop() {
		*c.params = (*c.params)[:0]
		if _, n := tree.lookup(host, path, c, false); n == nil {
			b.Fatal("no match")
		}
	}
}

func BenchmarkAdmits(b *testing.B) {
	cases := []struct {
		name        string
		authorities []string
		host        string
	}{
		{name: "hit static", authorities: []string{"api.stripe.com"}, host: "api.stripe.com"},
		{name: "hit wildcard", authorities: []string{"+{sub}.stripe.com"}, host: "eu.west.stripe.com"},
		{name: "miss", authorities: []string{"api.stripe.com"}, host: "example.test"},
		{name: "hit address", authorities: []string{"10.1.2.3"}, host: "10.1.2.3"},
		{name: "hit range", authorities: []string{"[10.0.0.0/8]"}, host: "10.9.9.9"},
		{name: "miss address", authorities: []string{"[10.0.0.0/8]"}, host: "11.0.0.1"},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			ca, err := GenerateCA()
			if err != nil {
				b.Fatal(err)
			}
			p, err := New(WithCA(ca))
			if err != nil {
				b.Fatal(err)
			}
			for _, authority := range tc.authorities {
				if _, err := p.Add(authority+"/*{any}", noopHandler); err != nil {
					b.Fatalf("intercept %s: %v", authority, err)
				}
			}
			t := Target{Scheme: "https", Host: tc.host, Port: "443"}

			b.ReportAllocs()
			for b.Loop() {
				p.Admits(t, KindHTTP)
			}
		})
	}
}

func BenchmarkLeafCached(b *testing.B) {
	ca, err := GenerateCA()
	if err != nil {
		b.Fatal(err)
	}
	if _, err := ca.Leaf("api.stripe.com"); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := ca.Leaf("api.stripe.com"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLeafMint(b *testing.B) {
	ca, err := GenerateCA()
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	i := 0
	for b.Loop() {
		i++
		// An authority never seen before, so every iteration signs a certificate rather
		// than reading one back out of the cache.
		if _, err := ca.Leaf("host-" + strconv.Itoa(i) + ".example.test"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStripHopByHop(b *testing.B) {
	// The common case: an ordinary request with nothing connection-scoped to remove, where
	// the header map is left untouched and can be reused across iterations.
	b.Run("nothing to strip", func(b *testing.B) {
		h := http.Header{
			"Accept":          {"*/*"},
			"User-Agent":      {"edge-bench"},
			"Accept-Encoding": {"gzip, deflate, br"},
			"Authorization":   {"Bearer token"},
		}
		b.ReportAllocs()
		for b.Loop() {
			stripHopByHop(h)
		}
	})

	// The case that does work. The clone is inside the loop because the strip is
	// destructive, so its cost is part of what is measured.
	b.Run("with hop by hop", func(b *testing.B) {
		base := http.Header{
			"Connection":       {"Keep-Alive, X-Custom"},
			"Proxy-Connection": {"keep-alive"},
			"Keep-Alive":       {"timeout=5"},
			"X-Custom":         {"value"},
			"Accept":           {"*/*"},
			"User-Agent":       {"edge-bench"},
		}
		b.ReportAllocs()
		for b.Loop() {
			stripHopByHop(base.Clone())
		}
	})
}

func BenchmarkRoutingPath(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/v1/charges/ch_123/refunds?limit=10", nil)

	b.ReportAllocs()
	for b.Loop() {
		if routingPath(req) == "" {
			b.Fatal("empty routing path")
		}
	}
}

// BenchmarkLookupUnnarrowed is BenchmarkLookup on entries nothing narrows, the shape the fast
// path in match answers. Comparing the two says what a matcher costs, and what skipping the
// matcher loop entirely buys.
func BenchmarkLookupUnnarrowed(b *testing.B) {
	cases := []struct {
		name    string
		pattern string
		host    string
		path    string
	}{
		{name: "static", pattern: "api.stripe.com/v1/charges", host: "api.stripe.com", path: "/v1/charges"},
		{name: "param", pattern: "api.stripe.com/v1/{id}/refunds", host: "api.stripe.com", path: "/v1/ch_1234567890/refunds"},
		{name: "any authority", pattern: "+{any}/v1/charges", host: "anything.example.test", path: "/v1/charges"},
		{name: "range", pattern: "[10.0.0.0/8]/v1/charges", host: "10.1.2.3", path: "/v1/charges"},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			ca, err := GenerateCA()
			if err != nil {
				b.Fatal(err)
			}
			p, err := New(WithCA(ca))
			if err != nil {
				b.Fatal(err)
			}
			if _, err := p.Add(tc.pattern, noopHandler); err != nil {
				b.Fatalf("register %s: %v", tc.pattern, err)
			}

			tree := p.getTree()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)

			c := tree.pool.Get().(*routeCtx)
			defer tree.pool.Put(c)
			c.reset(nil, req, "https", tc.host, "443")

			b.ReportAllocs()
			for b.Loop() {
				if _, n := tree.lookup(tc.host, tc.path, c, false); n == nil {
					b.Fatal("no match")
				}
			}
		})
	}
}

func BenchmarkAddDelete(b *testing.B) {
	cases := []struct {
		name string
		base string
	}{
		{name: "fresh authority"},
		{name: "admitted authority", base: "api.stripe.com/v1/other"},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			var patterns []string
			if tc.base != "" {
				patterns = append(patterns, tc.base)
			}
			p := benchProxy(b, patterns...)

			b.ReportAllocs()
			for b.Loop() {
				if _, err := p.Add("api.stripe.com/v1/charges", noopHandler); err != nil {
					b.Fatal(err)
				}
				if _, err := p.Delete[HTTP]("api.stripe.com/v1/charges"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDatagramAdmission measures what routing one datagram costs. It is walked per
// datagram, like every other unit, so this is the price of the model rather than of a cache.
func BenchmarkDatagramAdmission(b *testing.B) {
	p, err := New()
	if err != nil {
		b.Fatal(err)
	}
	if _, err := p.Add("[0.0.0.0/0]:53", func(*DatagramCtx) error { return nil }); err != nil {
		b.Fatal(err)
	}
	target := Target{Scheme: "http", Host: "10.1.2.3", Port: "53"}

	b.ReportAllocs()
	for b.Loop() {
		if e, _ := p.admitWith(target, KindUDP); e == nil {
			b.Fatal("no entry")
		}
	}
}

// BenchmarkDatagramOutbound measures one outbound datagram from the socket's read loop to the
// handler of its flow, the queue hand-off included.
func BenchmarkDatagramOutbound(b *testing.B) {
	p, err := New()
	if err != nil {
		b.Fatal(err)
	}
	served := make(chan struct{}, 1)
	if _, err := p.Add("[0.0.0.0/0]", func(c *DatagramCtx) error {
		served <- struct{}{}
		return c.Drop()
	}); err != nil {
		b.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	d, err := newQUICDemux(p, fixedOriginPacketConn{pc, netip.MustParseAddrPort("127.0.0.1:4433")})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(d.close)

	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	pkt := make([]byte, 1200)
	d.dispatch(client, pkt, false)
	<-served

	b.ReportAllocs()
	for b.Loop() {
		d.dispatch(client, pkt, false)
		<-served
	}
}

// BenchmarkDatagramAdmissionCaptured is the same walk on a hostname target whose entry
// captures a parameter, with the buffer a flow keeps across its datagrams.
func BenchmarkDatagramAdmissionCaptured(b *testing.B) {
	p, err := New()
	if err != nil {
		b.Fatal(err)
	}
	if _, err := p.Add("{name}.udp.test:53", func(*DatagramCtx) error { return nil }); err != nil {
		b.Fatal(err)
	}
	target := Target{Scheme: "http", Host: "echo.udp.test", Port: "53"}

	var buf []Param
	b.ReportAllocs()
	for b.Loop() {
		var e *entry
		if e, buf = p.admitInto(target, KindUDP, buf); e == nil || len(buf) != 1 {
			b.Fatal("no entry or no capture")
		}
	}
}

func tunnelBench(b *testing.B) (*quicDemux, *connectUDPTunnel, *demuxPacketConn, []byte) {
	b.Helper()
	ca, err := GenerateCA()
	if err != nil {
		b.Fatal(err)
	}
	p, err := New(WithCA(ca))
	if err != nil {
		b.Fatal(err)
	}
	d, err := newQUICDemux(p, newTunnelPacketConn())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = p.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)
	target := Target{Scheme: "https", Host: "bench.test", Port: "443"}
	sess := newSession(p, ctx, nil, target, KindHTTP, HTTP3)
	sess.remoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}
	origin := netip.MustParseAddrPort("127.0.0.1:443")
	tun := newConnectUDPTunnel(d, sess, &contextFraming{target: target, upstream: origin}, cancel)
	if !d.publishTunnel(tun) {
		b.Fatal("publish")
	}
	dpc := newDemuxPacketConn(nil, 64)
	it := &quicIntercept{conn: dpc}
	dcid := "ABCDEFGH"
	d.mu.Lock()
	flow := d.flows[tun.key]
	flow.conns[dcid] = &quicConn{odcid: dcid, state: connTerminated, stack: it}
	d.mu.Unlock()

	pkt := make([]byte, 1200)
	pkt[0] = 0xC3
	pkt[4] = 1
	pkt[5] = 8
	copy(pkt[6:], dcid)
	pkt[14] = 0
	return d, tun, dpc, pkt
}

// One inner packet of a tunnel, from dispatch to the read the stack's QUIC transport does.
func BenchmarkTunnelInbound(b *testing.B) {
	d, tun, dpc, pkt := tunnelBench(b)
	buf := make([]byte, maxUDPPayload)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		d.dispatch(tun.addr, pkt, true)
		if _, _, err := dpc.ReadFrom(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// One packet the stack writes back into the tunnel, queued for the sender.
func BenchmarkTunnelOutbound(b *testing.B) {
	_, tun, _, pkt := tunnelBench(b)
	origin := netip.MustParseAddrPort("127.0.0.1:443")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		tun.send(origin, pkt)
		out := <-tun.sendCh
		putTunnelBuf(out)
	}
}
