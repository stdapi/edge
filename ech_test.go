// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// chRecorder captures what a TLS client writes, so a test can obtain a genuine
// ClientHello. Reads fail at once, ending the handshake after the first flight.
type chRecorder struct {
	buf bytes.Buffer
}

func (c *chRecorder) Read([]byte) (int, error)         { return 0, io.ErrUnexpectedEOF }
func (c *chRecorder) Write(b []byte) (int, error)      { return c.buf.Write(b) }
func (c *chRecorder) Close() error                     { return nil }
func (c *chRecorder) LocalAddr() net.Addr              { return emptyAddr{} }
func (c *chRecorder) RemoteAddr() net.Addr             { return emptyAddr{} }
func (c *chRecorder) SetDeadline(time.Time) error      { return nil }
func (c *chRecorder) SetReadDeadline(time.Time) error  { return nil }
func (c *chRecorder) SetWriteDeadline(time.Time) error { return nil }

// echConfigList builds a valid ECHConfigList with a fresh X25519 key and publicName as the
// name the outer ClientHello shows, the shape a client fetches from DNS.
func echConfigList(t *testing.T, publicName string) []byte {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub := key.PublicKey().Bytes()

	var contents []byte
	contents = append(contents, 0x01)       // config_id
	contents = append(contents, 0x00, 0x20) // DHKEM X25519 with HKDF-SHA256
	contents = binary.BigEndian.AppendUint16(contents, uint16(len(pub)))
	contents = append(contents, pub...)
	contents = append(contents, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01) // HKDF-SHA256, AES-128-GCM
	contents = append(contents, 64)                                 // maximum_name_length
	contents = append(contents, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = append(contents, 0x00, 0x00) // no extensions

	config := []byte{0xfe, 0x0d}
	config = binary.BigEndian.AppendUint16(config, uint16(len(contents)))
	config = append(config, contents...)

	list := binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	return append(list, config...)
}

// greaseECH is the payload of a GREASE encrypted_client_hello extension, RFC 9849 section
// 6.2.1.
func greaseECH(t *testing.T) []byte {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	enc := key.PublicKey().Bytes()

	ext := []byte{0x00, 0x00, 0x01, 0x00, 0x01} // outer, HKDF-SHA256, AES-128-GCM
	ext = append(ext, randomBytes(t, 1)...)     // config_id
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(enc)))
	ext = append(ext, enc...)
	ext = binary.BigEndian.AppendUint16(ext, 208)
	return append(ext, randomBytes(t, 208)...)
}

// captureClientHello returns the TLS records of the first flight a client configured with
// cfg would send.
func captureClientHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	rec := &chRecorder{}
	_ = tls.Client(rec, cfg).Handshake()
	require.NotEmpty(t, rec.buf.Bytes(), "the client wrote no ClientHello")
	return rec.buf.Bytes()
}

// echClientHello returns the records of a genuine outer ClientHello offering ECH, with
// publicName visible and innerName encrypted inside the extension.
func echClientHello(t *testing.T, publicName, innerName string) []byte {
	t.Helper()
	// The recorder fails the handshake at the first read, so no certificate is ever
	// checked and no verification setting is needed.
	return captureClientHello(t, &tls.Config{
		ServerName:                     innerName,
		MinVersion:                     tls.VersionTLS13,
		NextProtos:                     []string{"http/1.1"},
		EncryptedClientHelloConfigList: echConfigList(t, publicName),
	})
}

// plainClientHello returns the records of a ClientHello without ECH.
func plainClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	return captureClientHello(t, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
}

func TestECH_OffersECH(t *testing.T) {
	withECH := handshakeFromRecords(echClientHello(t, "allowed.test", "secret.test"))
	require.NotNil(t, withECH)
	offered, ok := offersECH(withECH)
	assert.True(t, ok)
	assert.True(t, offered, "a genuine ECH ClientHello should be detected")

	without := handshakeFromRecords(plainClientHello(t, "allowed.test"))
	require.NotNil(t, without)
	offered, ok = offersECH(without)
	assert.True(t, ok)
	assert.False(t, offered, "a plain ClientHello should not be flagged")
}

func TestECH_OffersECHWithoutExtensionsBlock(t *testing.T) {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00) // null compression

	msg := []byte{0x01, 0x00, 0x00, byte(len(body))}
	msg = append(msg, body...)

	offered, ok := offersECH(msg)
	assert.True(t, ok)
	assert.False(t, offered)
}

func TestECH_OffersECHRefusesMalformedHellos(t *testing.T) {
	valid := handshakeFromRecords(plainClientHello(t, "allowed.test"))
	require.NotNil(t, valid)

	corrupted := bytes.Clone(valid)
	off := 4 + 34
	off += 1 + int(corrupted[off])                              // session_id
	off += 2 + (int(corrupted[off])<<8 | int(corrupted[off+1])) // cipher_suites
	off += 1 + int(corrupted[off])                              // compression_methods
	corrupted[off+1]++                                          // extensions length

	cases := map[string][]byte{
		"empty":                   {},
		"not a client hello":      append([]byte{0x02}, valid[1:]...),
		"truncated":               valid[:len(valid)-1],
		"trailing bytes":          append(bytes.Clone(valid), 0x00),
		"extensions length wrong": corrupted,
	}
	for name, msg := range cases {
		_, ok := offersECH(msg)
		assert.False(t, ok, name)
	}
}

func TestECH_HandshakeFromRecordsReassemblesSplitRecords(t *testing.T) {
	record := plainClientHello(t, "allowed.test")
	require.GreaterOrEqual(t, len(record), 25)

	payload := record[5:]
	cut := len(payload) / 2
	split := []byte{0x16, 0x03, 0x01}
	split = binary.BigEndian.AppendUint16(split, uint16(cut))
	split = append(split, payload[:cut]...)
	split = append(split, 0x16, 0x03, 0x01)
	split = binary.BigEndian.AppendUint16(split, uint16(len(payload)-cut))
	split = append(split, payload[cut:]...)

	assert.Equal(t, handshakeFromRecords(record), handshakeFromRecords(split))
}

func TestECH_CheckECH(t *testing.T) {
	assert.ErrorIs(t, checkECH(echClientHello(t, "allowed.test", "secret.test")), errECHOffered)
	assert.ErrorIs(t, checkECH([]byte{0x16, 0x03, 0x01, 0x00}), errECHUnverifiable)
	assert.NoError(t, checkECH(plainClientHello(t, "allowed.test")))
}

func TestTransparent_RejectECHRefusesBeforeDialing(t *testing.T) {
	var dials atomic.Int32
	tr := DefaultTransport()
	tr.DialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, fmt.Errorf("no upstream in this test")
	}

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithRejectECH(true), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd[TCP]("allowed.test", relayStream)

	addr := startTransparent(t, p)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// The outer name is the allowed one, so only the refusal stands between the client
	// and a tunnel to whatever the inner name reaches.
	_, err = conn.Write(echClientHello(t, "allowed.test", "secret.test"))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	typ, alert := firstRecord(t, conn)
	assert.Equal(t, [2]byte{tlsAlert, alertHandshakeFailure}, [2]byte{typ, alert})
	_, err = conn.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, int32(0), dials.Load(), "a refused connection should never reach the dialer")
}

func TestTransparent_WithoutRejectECHTheOuterNameDecides(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = origin.Close() }()

	received := make(chan []byte, 1)
	go func() {
		c, aerr := origin.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, clientHelloPeekSize)
		n, _ := io.ReadAtLeast(c, buf, 1)
		received <- buf[:n]
	}()

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(origin.Addr().String())

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd[TCP]("allowed.test", relayStream)

	addr := startTransparent(t, p)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	hello := echClientHello(t, "allowed.test", "secret.test")
	_, err = conn.Write(hello)
	require.NoError(t, err)

	// Without the refusal the outer name is what the connection is placed on, so the proxy
	// admits it and answers the handshake, with a record of its own or an alert. A refusal
	// closes the connection without a word, which is what tells the two apart.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	answer := make([]byte, 1)
	n, rerr := conn.Read(answer)
	require.NoError(t, rerr, "the connection was closed without an answer, so the outer name did not decide")
	require.Equal(t, 1, n)
	assert.Contains(t, []byte{0x16, 0x15}, answer[0], "the proxy should answer the handshake")

	select {
	case got := <-received:
		t.Fatalf("the origin was reached with %d byte(s); a terminated connection re-originates its own handshake", len(got))
	case <-time.After(200 * time.Millisecond):
	}
}

// connectRaw opens a CONNECT tunnel through the proxy at addr and returns the connection
// past the 200.
func connectRaw(t *testing.T, addr, authority string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, line, "200", "the CONNECT should be granted")
	for {
		line, err = br.ReadString('\n')
		require.NoError(t, err)
		if line == "\r\n" {
			break
		}
	}
	require.Zero(t, br.Buffered(), "nothing should follow the CONNECT response")
	require.NoError(t, conn.SetDeadline(time.Time{}))
	return conn
}

func TestConnect_RejectECHClosesTheTunnel(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = origin.Close() }()

	received := make(chan int, 4)
	go func() {
		for {
			c, aerr := origin.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, _ := io.Copy(io.Discard, c)
				received <- int(n)
			}()
		}
	}()

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithRejectECH(true))
	require.NoError(t, err)
	p.MustAdd[TCP](origin.Addr().String(), relayStream)

	addr := startProxy(t, p)
	conn := connectRaw(t, addr, origin.Addr().String())

	_, err = conn.Write(echClientHello(t, "allowed.test", "secret.test"))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	typ, alert := firstRecord(t, conn)
	assert.Equal(t, [2]byte{tlsAlert, alertHandshakeFailure}, [2]byte{typ, alert})
	_, err = conn.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)

	// The refusal lands before anything upstream is opened, so the origin sees no connection
	// at all rather than one that carried nothing.
	select {
	case n := <-received:
		t.Fatalf("the origin was reached, and read %d byte(s)", n)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestConnect_RejectECHLeavesOtherTrafficAlone(t *testing.T) {
	t.Run("plaintext", func(t *testing.T) {
		origin, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer func() { _ = origin.Close() }()

		received := make(chan []byte, 1)
		go func() {
			c, aerr := origin.Accept()
			if aerr != nil {
				return
			}
			defer func() { _ = c.Close() }()
			buf := make([]byte, 4)
			n, _ := io.ReadFull(c, buf)
			received <- buf[:n]
			_, _ = c.Write([]byte("pong"))
			time.Sleep(200 * time.Millisecond)
		}()

		p, err := New(WithRejectECH(true))
		require.NoError(t, err)
		p.MustAdd[TCP](origin.Addr().String(), relayStream)
		addr := startProxy(t, p)

		conn := connectRaw(t, addr, origin.Addr().String())
		_, err = conn.Write([]byte("ping"))
		require.NoError(t, err)

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		reply := make([]byte, 4)
		_, err = io.ReadFull(conn, reply)
		require.NoError(t, err)
		assert.Equal(t, "pong", string(reply))
		assert.Equal(t, []byte("ping"), <-received)
	})

	t.Run("tls without ech", func(t *testing.T) {
		origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "origin")
		}))
		defer origin.Close()
		originURL, err := url.Parse(origin.URL)
		require.NoError(t, err)

		ca, err := GenerateCA()
		require.NoError(t, err)
		tr := DefaultTransport()
		tr.RootCAs = originPool(t, origin)
		p := Must(WithCA(ca), WithTransport(tr), WithRejectECH(true))
		p.MustAdd[TCP](originHost(originURL), relayStream)
		addr := startProxy(t, p)

		// A real client, so the ClientHello is a real one: the check reads it, finds no ECH
		// and lets the handshake through.
		resp, err := proxyClient(addr, ca.CertPool()).Get(origin.URL)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "origin", string(body))
	})
}

func TestConnect_RejectECHRefusesAnInterceptedHandshake(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)

	p, err := New(WithCA(ca), WithRejectECH(true))
	require.NoError(t, err)
	p.MustAdd("secret.test/+{any}", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	})

	addr := startProxy(t, p)
	conn := connectRaw(t, addr, "secret.test:443")

	_, err = conn.Write(echClientHello(t, "secret.test", "secret.test"))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	typ, alert := firstRecord(t, conn)
	assert.Equal(t, [2]byte{tlsAlert, alertHandshakeFailure}, [2]byte{typ, alert}, "no ServerHello should come back")
	_, err = conn.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

func TestConnect_RejectECHClosesAnH2Stream(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = origin.Close() }()

	received := make(chan int, 1)
	go func() {
		c, aerr := origin.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := io.Copy(io.Discard, c)
		received <- int(n)
	}()

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithRejectECH(true))
	require.NoError(t, err)
	p.MustAdd[TCP](origin.Addr().String(), relayStream)

	addr := startProxy(t, p)

	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	require.NoError(t, err)

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, "https://"+origin.Addr().String(), pr)
	require.NoError(t, err)

	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	_, err = pw.Write(echClientHello(t, "allowed.test", "secret.test"))
	require.NoError(t, err)

	got, _ := io.ReadAll(resp.Body)
	assert.Equal(t, []byte{tlsAlert, 0x03, 0x03, 0x00, 0x02, 0x02, alertHandshakeFailure}, got)

	// Nothing upstream is opened until a handler asks for it, so a refused stream leaves the
	// origin untouched rather than reached and then dropped.
	select {
	case n := <-received:
		t.Fatalf("the origin was reached, and read %d byte(s)", n)
	case <-time.After(500 * time.Millisecond):
	}
}

// syncBuffer collects log output written from the demux goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestQUIC_RejectECHRefusesTheConnection(t *testing.T) {
	logs := &syncBuffer{}
	p, err := New(
		WithRejectECH(true),
		WithLogger(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))),
	)
	require.NoError(t, err)
	p.MustAdd[TCP]("allowed.test", relayStream)

	addr := startQUIC(t, p)

	_, err = quic.DialAddr(t.Context(), addr.String(), &tls.Config{
		ServerName:                     "secret.test",
		MinVersion:                     tls.VersionTLS13,
		NextProtos:                     []string{"h3"},
		EncryptedClientHelloConfigList: echConfigList(t, "allowed.test"),
	}, &quic.Config{HandshakeIdleTimeout: 2 * time.Second})
	wantClosedWith(t, err, quicHandshakeFailure)

	assert.Contains(t, logs.String(), "offers Encrypted Client Hello",
		"the demux should have refused the connection on its ClientHello")
}

func FuzzOffersECH(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00, 0x00, 0x00})
	f.Fuzz(func(_ *testing.T, msg []byte) {
		offersECH(msg)
		handshakeFromRecords(msg)
	})
}
