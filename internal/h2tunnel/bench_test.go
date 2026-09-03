// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package h2tunnel

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// echoH2C serves CONNECT over unencrypted HTTP/2 by echoing the stream, so the peer's TLS
// stays out of the measurement.
func echoH2C(b *testing.B) net.Addr {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "not a CONNECT", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		buf := make([]byte, 64<<10)
		for {
			n, rerr := r.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				_ = rc.Flush()
			}
			if rerr != nil {
				return
			}
		}
	})}
	srv.Protocols = new(http.Protocols)
	srv.Protocols.SetUnencryptedHTTP2(true)
	go func() { _ = srv.Serve(ln) }()
	b.Cleanup(func() { _ = srv.Close() })
	return ln.Addr()
}

func benchConn(b *testing.B, addr net.Addr) *Conn {
	b.Helper()
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		b.Fatal(err)
	}
	c, err := Client(nc, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = c.Close() })
	return c
}

func benchStream(b *testing.B, c *Conn) *Stream {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, resp, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	if err != nil {
		b.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		b.Fatalf("status %d", resp.StatusCode)
	}
	return s
}

// One stream, large writes, the echo drained as it comes.
func BenchmarkStreamThroughput(b *testing.B) {
	addr := echoH2C(b)
	c := benchConn(b, addr)
	s := benchStream(b, c)
	const chunk = 64 << 10
	payload := make([]byte, chunk)
	drained := make(chan struct{})
	go func() {
		_, _ = io.CopyN(io.Discard, s, int64(chunk)*int64(b.N))
		close(drained)
	}()
	b.SetBytes(chunk)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := s.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	<-drained
}

// One stream, a datagram-sized write and its echo, one after the other.
func BenchmarkDatagramRoundTrip(b *testing.B) {
	addr := echoH2C(b)
	c := benchConn(b, addr)
	s := benchStream(b, c)
	const size = 1200
	payload := make([]byte, size)
	buf := make([]byte, size)
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := s.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(s, buf); err != nil {
			b.Fatal(err)
		}
	}
}

// Datagram round trips on many streams at once, one per goroutine.
func BenchmarkParallelStreams(b *testing.B) {
	addr := echoH2C(b)
	c := benchConn(b, addr)
	const size = 1200
	b.SetBytes(size)
	b.ReportAllocs()
	b.SetParallelism(4)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		s := benchStream(b, c)
		payload := make([]byte, size)
		buf := make([]byte, size)
		for pb.Next() {
			if _, err := s.Write(payload); err != nil {
				b.Error(err)
				return
			}
			if _, err := io.ReadFull(s, buf); err != nil {
				b.Error(err)
				return
			}
		}
		_ = s.Close()
	})
}

// A stream opened and closed per operation.
func BenchmarkOpenClose(b *testing.B) {
	addr := echoH2C(b)
	c := benchConn(b, addr)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		s := benchStream(b, c)
		_ = s.Close()
	}
}

// echoTLS is echoH2C over TLS, the transport the proxy's own HTTP/2 is used with.
func echoTLS(b *testing.B) (net.Addr, *tls.Config) {
	b.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		buf := make([]byte, 64<<10)
		for {
			n, rerr := r.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				_ = rc.Flush()
			}
			if rerr != nil {
				return
			}
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	b.Cleanup(srv.Close)
	cfg := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	cfg.NextProtos = []string{"h2"}
	return srv.Listener.Addr(), cfg
}

func benchTLSConn(b *testing.B) *Conn {
	b.Helper()
	addr, cfg := echoTLS(b)
	tc, err := tls.Dial("tcp", addr.String(), cfg)
	if err != nil {
		b.Fatal(err)
	}
	c, err := Client(tc, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = c.Close() })
	return c
}

func BenchmarkStreamThroughputTLS(b *testing.B) {
	c := benchTLSConn(b)
	s := benchStream(b, c)
	const chunk = 64 << 10
	payload := make([]byte, chunk)
	drained := make(chan struct{})
	go func() {
		_, _ = io.CopyN(io.Discard, s, int64(chunk)*int64(b.N))
		close(drained)
	}()
	b.SetBytes(chunk)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := s.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	<-drained
}

func BenchmarkDatagramRoundTripTLS(b *testing.B) {
	c := benchTLSConn(b)
	s := benchStream(b, c)
	const size = 1200
	payload := make([]byte, size)
	buf := make([]byte, size)
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := s.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(s, buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParallelStreamsTLS(b *testing.B) {
	c := benchTLSConn(b)
	const size = 1200
	b.SetBytes(size)
	b.ReportAllocs()
	b.SetParallelism(4)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		s := benchStream(b, c)
		payload := make([]byte, size)
		buf := make([]byte, size)
		for pb.Next() {
			if _, err := s.Write(payload); err != nil {
				b.Error(err)
				return
			}
			if _, err := io.ReadFull(s, buf); err != nil {
				b.Error(err)
				return
			}
		}
		_ = s.Close()
	})
}
