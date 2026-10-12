// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

func TestForward_407FromTheProxyIsBadGateway(t *testing.T) {
	b := newUpstreamBench(t, nil, upstreamH1("", "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"upstream\"\r\nContent-Length: 0\r\n\r\n"))
	got := b.exchange(t, "GET", "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	assert.Equal(t, http.StatusBadGateway, got.resp.StatusCode)
	assert.Empty(t, fieldValues(got.head, "Proxy-Authenticate"))
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

func TestForward_HTTP3ResponseHeaderTimeoutCancelsTheRequest(t *testing.T) {
	tr := DefaultTransport()
	tr.ResponseHeaderTimeout = 100 * time.Millisecond
	b := newH3OriginBenchWith(t, tr, func(o *rawOrigin, _ *h3Conn, s *h3Stream) {
		s.message(false)
		<-s.Context().Done()
		code, _ := h3ResetCode(context.Cause(s.Context()))
		o.note(code.String())
	})
	got := b.dialH3Front(t).roundTrip(t, h3Request("GET", "origin.test", "/"))
	require.NoError(t, got.err)
	assert.Equal(t, "502", got.status())
	assert.Equal(t, http3.ErrCodeRequestCanceled.String(), b.origin.nextNote(t))
}

func TestForward_HTTP3ResponseHeaderTimeoutSparesALateBody(t *testing.T) {
	tr := DefaultTransport()
	tr.ResponseHeaderTimeout = 100 * time.Millisecond
	b := newH3OriginBenchWith(t, tr, func(_ *rawOrigin, _ *h3Conn, s *h3Stream) {
		s.message(false)
		if _, err := s.Write(h3Headers([]hpack.HeaderField{hf(":status", "200"), hf("content-length", "4")})); err != nil {
			return
		}
		<-time.After(3 * tr.ResponseHeaderTimeout)
		if _, err := s.Write(h3Data("late")); err == nil {
			_ = s.Close()
		}
	})
	got := b.dialH3Front(t).roundTrip(t, h3Request("GET", "origin.test", "/"))
	require.NoError(t, got.err)
	assert.Equal(t, "200", got.status())
	assert.Equal(t, "late", string(got.body))
}

func TestForward_HTTP3ResponseHeaderTimeoutStartsOnceTheRequestIsSent(t *testing.T) {
	tr := DefaultTransport()
	tr.ResponseHeaderTimeout = 100 * time.Millisecond
	b := newH3OriginBenchWith(t, tr, func(_ *rawOrigin, _ *h3Conn, s *h3Stream) {
		if m := s.message(false); m.err != nil || string(m.body) != "slow" {
			return
		}
		if _, err := s.Write(slices.Concat(h3Headers([]hpack.HeaderField{hf(":status", "200")}), h3Data("ok"))); err == nil {
			_ = s.Close()
		}
	})
	s := b.dialH3Front(t).open(t, h3Request("POST", "origin.test", "/", hf("content-length", "4")))
	<-time.After(3 * tr.ResponseHeaderTimeout)
	s.send(t, h3Data("slow"))
	closeRequest(t, s.Stream)
	got := s.message(true)
	require.NoError(t, got.err)
	assert.Equal(t, "200", got.status())
	assert.Equal(t, "ok", string(got.body))
}

func TestGatedConn_AwaitRead(t *testing.T) {
	waiting := func(t *testing.T, g *gatedConn, done <-chan struct{}) <-chan struct{} {
		t.Helper()
		returned := make(chan struct{})
		go func() {
			g.awaitRead(done)
			close(returned)
		}()
		require.Eventually(t, func() bool { return g.waiter.Load() != nil }, 5*time.Second, time.Millisecond)
		return returned
	}
	cases := []struct {
		name string
		end  func(t *testing.T, g *gatedConn, done chan struct{})
	}{
		{"a read", func(_ *testing.T, g *gatedConn, _ chan struct{}) {
			go func() { _, _ = g.Read(make([]byte, 1)) }()
		}},
		{"a close", func(t *testing.T, g *gatedConn, _ chan struct{}) {
			require.NoError(t, g.Close())
		}},
		{"done", func(_ *testing.T, _ *gatedConn, done chan struct{}) {
			close(done)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, peer := net.Pipe()
			t.Cleanup(func() {
				_ = c.Close()
				_ = peer.Close()
			})
			g := &gatedConn{Conn: c}
			done := make(chan struct{})
			returned := waiting(t, g, done)
			tc.end(t, g, done)
			select {
			case <-returned:
			case <-time.After(5 * time.Second):
				t.Fatal("awaitRead did not return")
			}
			assert.Nil(t, g.waiter.Load())
		})
	}
	t.Run("a read in progress", func(t *testing.T) {
		c, peer := net.Pipe()
		t.Cleanup(func() {
			_ = c.Close()
			_ = peer.Close()
		})
		g := &gatedConn{Conn: c}
		go func() { _, _ = g.Read(make([]byte, 1)) }()
		require.Eventually(t, g.reading.Load, 5*time.Second, time.Millisecond)
		g.awaitRead(nil)
		assert.Nil(t, g.waiter.Load())
	})
	t.Run("a closed connection", func(t *testing.T) {
		c, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		g := &gatedConn{Conn: c}
		require.NoError(t, g.Close())
		g.awaitRead(nil)
		assert.Nil(t, g.waiter.Load())
	})
}

func TestGateReuse(t *testing.T) {
	gated := func(t *testing.T) (*gatedConn, net.Conn) {
		t.Helper()
		c, peer := net.Pipe()
		t.Cleanup(func() {
			_ = c.Close()
			_ = peer.Close()
		})
		return &gatedConn{Conn: c}, peer
	}
	overTLS := func(t *testing.T, g *gatedConn, peer net.Conn, alpn string) *tls.Conn {
		t.Helper()
		ca, err := GenerateCA()
		require.NoError(t, err)
		cert, err := ca.Leaf("origin.test")
		require.NoError(t, err)
		require.NoError(t, peer.SetDeadline(time.Now().Add(5*time.Second)))
		require.NoError(t, g.SetDeadline(time.Now().Add(5*time.Second)))
		srv := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{alpn}})
		go func() { _ = srv.Handshake() }()
		tc := tls.Client(g, &tls.Config{ServerName: "origin.test", RootCAs: poolOf(ca), NextProtos: []string{alpn}})
		require.NoError(t, tc.Handshake())
		require.Equal(t, alpn, tc.ConnectionState().NegotiatedProtocol)
		return tc
	}
	returns := func(t *testing.T, info httptrace.GotConnInfo) {
		t.Helper()
		returned := make(chan struct{})
		go func() {
			gateReuse(info, nil)
			close(returned)
		}()
		select {
		case <-returned:
		case <-time.After(5 * time.Second):
			t.Fatal("gateReuse waited")
		}
	}
	waitsForRead := func(t *testing.T, g *gatedConn, info httptrace.GotConnInfo, read func()) {
		t.Helper()
		returned := make(chan struct{})
		go func() {
			gateReuse(info, nil)
			close(returned)
		}()
		require.Eventually(t, func() bool { return g.waiter.Load() != nil }, 5*time.Second, time.Millisecond)
		go read()
		select {
		case <-returned:
		case <-time.After(5 * time.Second):
			t.Fatal("gateReuse did not return on a read")
		}
	}

	t.Run("a new connection", func(t *testing.T) {
		g, _ := gated(t)
		returns(t, httptrace.GotConnInfo{Conn: g})
	})
	t.Run("a connection no pool dialed", func(t *testing.T) {
		c, peer := net.Pipe()
		t.Cleanup(func() {
			_ = c.Close()
			_ = peer.Close()
		})
		returns(t, httptrace.GotConnInfo{Conn: c, Reused: true})
	})
	t.Run("plaintext", func(t *testing.T) {
		g, _ := gated(t)
		waitsForRead(t, g, httptrace.GotConnInfo{Conn: g, Reused: true}, func() { _, _ = g.Read(make([]byte, 1)) })
	})
	t.Run("h1 over TLS", func(t *testing.T) {
		g, peer := gated(t)
		tc := overTLS(t, g, peer, "http/1.1")
		waitsForRead(t, g, httptrace.GotConnInfo{Conn: tc, Reused: true}, func() { _, _ = tc.Read(make([]byte, 1)) })
		assert.EqualValues(t, alpnH1, g.alpn.Load())
	})
	t.Run("h2 over TLS", func(t *testing.T) {
		g, peer := gated(t)
		tc := overTLS(t, g, peer, "h2")
		returns(t, httptrace.GotConnInfo{Conn: tc, Reused: true})
		assert.EqualValues(t, alpnH2, g.alpn.Load())
		returns(t, httptrace.GotConnInfo{Conn: tc, Reused: true})
	})
}

func TestTailBody(t *testing.T) {
	readers := map[string]func(io.Reader) ([]byte, error){
		"copy": func(r io.Reader) ([]byte, error) {
			var out bytes.Buffer
			_, err := io.CopyBuffer(&out, struct{ io.Reader }{r}, make([]byte, 32<<10))
			return out.Bytes(), err
		},
		"ReadAll": io.ReadAll,
	}
	for _, size := range []int{4097, 8200, 10000, 36864, 40000, 45000, 73728} {
		for name, read := range readers {
			t.Run(fmt.Sprintf("%d/%s", size, name), func(t *testing.T) {
				past := "HTTP/1.1 200 OK\r\n"
				br := bufio.NewReaderSize(strings.NewReader(strings.Repeat("a", size)+past), h1ReadBuffer)
				body := &tailBody{ReadCloser: io.NopCloser(io.LimitReader(br, int64(size))), remaining: int64(size)}
				got, err := read(body)
				require.NoError(t, err)
				assert.Len(t, got, size)
				assert.Equal(t, len(past), br.Buffered())
			})
		}
	}
}
