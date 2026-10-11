// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSniff_ShortFirstWriteDecidesWithoutWaiting(t *testing.T) {
	cases := []struct {
		name  string
		write string
		want  bool
		waits bool
	}{
		{name: "redis ping", write: "PING\r\n", want: false},
		{name: "request line", write: "GET / HTTP/1.1\r\n", want: true},
		{name: "h2 preface", write: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", want: true},
		{name: "binary", write: "\x00\x01\x02", want: false},
		{name: "undecided prefix waits", write: "GET /", want: false, waits: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			go func() { _, _ = client.Write([]byte(tc.write)) }()

			pc := newPeekConn(server, nil, defaultPeekSize)
			_, err := pc.Peek(1)
			require.NoError(t, err)

			start := time.Now()
			got := sniffStreamCandidates(pc, 300*time.Millisecond)
			elapsed := time.Since(start)
			if tc.want {
				assert.Equal(t, []Kind{KindHTTP, KindTCP}, got)
			} else {
				assert.Equal(t, []Kind{KindTCP}, got)
			}
			if tc.waits {
				assert.GreaterOrEqual(t, elapsed, 300*time.Millisecond, "a prefix that may still be HTTP waits for more")
			} else {
				assert.Less(t, elapsed, 200*time.Millisecond, "decided on the bytes at hand")
			}
		})
	}
}

func TestPeekAuthority(t *testing.T) {
	cases := []struct {
		name  string
		write string
		want  string
		limit int
	}{
		{name: "host header", write: "GET /x HTTP/1.1\r\nHost: api.test\r\n\r\n", want: "api.test"},
		{name: "host with port and whitespace", write: "GET /x HTTP/1.1\r\nhost: \t api.test:8080 \r\n\r\n", want: "api.test:8080"},
		{name: "host after other headers", write: "GET /x HTTP/1.1\r\nAccept: */*\r\nX-Trace: a:b\r\nHost: api.test\r\n\r\n", want: "api.test"},
		{name: "LF line terminators", write: "GET /x HTTP/1.1\nHost: api.test\n\n", want: "api.test"},
		{name: "absolute form wins over host", write: "GET http://user:pw@api.test:8080/x?y=z HTTP/1.1\r\nHost: other.test\r\n\r\n", want: "api.test:8080"},
		{name: "absolute form without a path", write: "GET HTTPS://api.test HTTP/1.1\r\n\r\n", want: "api.test"},
		{name: "absolute form ipv6", write: "GET http://[::1]:8080/x HTTP/1.1\r\n\r\n", want: "[::1]:8080"},
		{name: "connect", write: "CONNECT api.test:443 HTTP/1.1\r\nHost: api.test:443\r\n\r\n", want: "api.test:443"},
		{name: "asterisk form", write: "OPTIONS * HTTP/1.1\r\nHost: api.test\r\n\r\n", want: "api.test"},
		{name: "no host", write: "GET /x HTTP/1.0\r\n\r\n", want: ""},
		{name: "empty host", write: "GET /x HTTP/1.1\r\nHost:\r\n\r\n", want: ""},
		{name: "malformed header line", write: "GET /x HTTP/1.1\r\nnot a header\r\nHost: api.test\r\n\r\n", want: ""},
		{name: "obsolete line folding", write: "GET /x HTTP/1.1\r\nX-A: a\r\n b\r\nHost: api.test\r\n\r\n", want: "api.test"},
		{name: "absolute form without a host falls back to the header", write: "GET x:// HTTP/1.1\r\nHost: api.test\r\n\r\n", want: "api.test"},
		{name: "host past the limit", write: "GET /x HTTP/1.1\r\n" + strings.Repeat("X-Pad: aaaaaaaaaaaa\r\n", 40) + "Host: api.test\r\n\r\n", want: "", limit: 512},
		{name: "headers never complete", write: "GET /x HTTP/1.1\r\nX-A: a\r\n", want: ""},
		// The preface, an empty SETTINGS and a request all at once, more than a client waiting
		// on the server's SETTINGS ever sends before it has them.
		{name: "h2c preface has no authority", write: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x05\x01\x05\x00\x00\x00\x01\x82\x86\x84\x41", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			go func() {
				_, _ = client.Write([]byte(tc.write))
				_ = client.Close()
			}()

			const max = 64 << 10
			pc := newPeekConn(server, nil, max)
			require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))
			require.True(t, looksLikeHTTPRequestLine(pc), "every case opens with a request line")

			limit := tc.limit
			if limit == 0 {
				limit = max
			}
			got, _ := peekAuthority(pc, limit)
			assert.Equal(t, tc.want, got)

			// The peek leaves every byte for whatever serves the connection next.
			rest, err := io.ReadAll(pc)
			require.NoError(t, err)
			assert.Equal(t, tc.write, string(rest))
		})
	}
}

// bytesConn serves the same bytes on every reset, for a benchmark that needs no peer.
type bytesConn struct {
	net.Conn
	r bytes.Reader
}

func (c *bytesConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func BenchmarkPeekAuthority(b *testing.B) {
	cases := []struct {
		name  string
		write string
	}{
		{name: "host first", write: "GET /v1/charges/ch_123 HTTP/1.1\r\nHost: api.example.test\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\n\r\n"},
		{name: "host last", write: "GET /v1/charges/ch_123 HTTP/1.1\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\nAccept-Encoding: gzip, br\r\nAuthorization: Bearer sk_test_4eC39HqLyjWDarjtT1zdp7dc\r\nHost: api.example.test\r\n\r\n"},
	}
	for _, bc := range cases {
		b.Run(bc.name, func(b *testing.B) {
			data := []byte(bc.write)
			conn := new(bytesConn)
			b.ReportAllocs()
			for b.Loop() {
				conn.r.Reset(data)
				pc := newPeekConn(conn, nil, 64<<10)
				if _, err := pc.Peek(1); err != nil {
					b.Fatal(err)
				}
				if got, _ := peekAuthority(pc, 64<<10); got != "api.example.test" {
					b.Fatal("no authority")
				}
			}
		})
	}
}

func TestSniff_NonHTTPALPNIsNotHTTP(t *testing.T) {
	ca, _ := GenerateCA()
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd("example.test/", noopHandler)
	addr := startProxy(t, p)

	dial := func() (*tls.Conn, error) {
		raw, derr := net.Dial("tcp", addr)
		if derr != nil {
			return nil, derr
		}
		if _, werr := raw.Write([]byte("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")); werr != nil {
			return nil, werr
		}
		br := bufio.NewReader(raw)
		if _, rerr := http.ReadResponse(br, nil); rerr != nil {
			return nil, rerr
		}
		tc := tls.Client(raw, &tls.Config{
			RootCAs:    ca.CertPool(),
			ServerName: "example.test",
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"spdy/3"},
		})
		return tc, tc.Handshake()
	}

	// RFC 7301 section 3.2, an offer the authority admits no kind for ends the handshake.
	_, err = dial()
	assert.ErrorContains(t, err, "no application protocol")

	// With a stream entry the same connection is served, and the protocol the client asked
	// for is the one it gets.
	p.MustAdd[TCP]("example.test:443", func(c *TCPCtx) error {
		assert.Equal(t, "spdy/3", c.ALPN())
		_, _ = c.Client().Write([]byte("hello"))
		return nil
	})

	tc, err := dial()
	require.NoError(t, err)
	defer func() { _ = tc.Close() }()
	assert.Equal(t, "spdy/3", tc.ConnectionState().NegotiatedProtocol)

	buf := make([]byte, 5)
	_, err = io.ReadFull(tc, buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf))
}
