// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sslRequest is the Postgres request to start TLS: a length of 8 and the code 80877103.
var sslRequest = [8]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}

// startTLSOrigin serves a Postgres-shaped upgrade: the 8-byte request answered with 'S', a
// TLS handshake with cert, then a line naming the negotiated protocol and every line echoed.
func startTLSOrigin(t *testing.T, cert tls.Certificate, protos ...string) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				var req [8]byte
				if _, err := io.ReadFull(conn, req[:]); err != nil || req != sslRequest {
					return
				}
				if _, err := conn.Write([]byte{'S'}); err != nil {
					return
				}
				tc := tls.Server(conn, &tls.Config{
					Certificates: []tls.Certificate{cert},
					NextProtos:   protos,
					MinVersion:   tls.VersionTLS12,
				})
				if err := tc.Handshake(); err != nil {
					return
				}
				_, _ = fmt.Fprintf(tc, "alpn=%s\n", tc.ConnectionState().NegotiatedProtocol)
				_, _ = io.Copy(tc, tc)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// relaySSLRequest relays the request and the origin's one-byte answer, and returns the answer.
func relaySSLRequest(client, up net.Conn) (byte, error) {
	var req [8]byte
	if _, err := io.ReadFull(client, req[:]); err != nil {
		return 0, err
	}
	if _, err := up.Write(req[:]); err != nil {
		return 0, err
	}
	var answer [1]byte
	if _, err := io.ReadFull(up, answer[:]); err != nil {
		return 0, err
	}
	if _, err := client.Write(answer[:]); err != nil {
		return 0, err
	}
	return answer[0], nil
}

// startTLSClient sends the request on raw, expects 'S', and completes the handshake with cfg.
func startTLSClient(t *testing.T, raw net.Conn, cfg *tls.Config) *tls.Conn {
	t.Helper()
	_, err := raw.Write(sslRequest[:])
	require.NoError(t, err)
	var answer [1]byte
	_, err = io.ReadFull(raw, answer[:])
	require.NoError(t, err)
	require.Equal(t, byte('S'), answer[0])
	tc := tls.Client(raw, cfg)
	require.NoError(t, tc.Handshake())
	return tc
}

func clientTLSConfig(ca *CA, name string, protos ...string) *tls.Config {
	return &tls.Config{ServerName: name, RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12, NextProtos: protos}
}

// tcpSession returns the session serving the stream, once it is reported.
func tcpSession(t *testing.T, p *Proxy) *Session {
	t.Helper()
	var sess *Session
	require.Eventually(t, func() bool {
		for s := range p.Sessions() {
			if s.Kind() == KindTCP {
				sess = s
				return true
			}
		}
		return false
	}, 3*time.Second, 5*time.Millisecond)
	return sess
}

// exchange writes a line and expects it echoed, past the line the origin sends first.
func exchange(t *testing.T, conn net.Conn, wantALPN string) {
	t.Helper()
	br := bufio.NewReader(conn)
	first, err := br.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "alpn="+wantALPN+"\n", first, "the upstream handshake must mirror the client's protocol")
	_, err = conn.Write([]byte("hello\n"))
	require.NoError(t, err)
	line, err := br.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "hello\n", line)
}

type startTLSObserved struct {
	tls  *tls.ConnectionState
	alpn string
	line string
}

// observingStartTLS relays the request, terminates when the origin agrees, reads the first
// line in the clear and reports what it saw, then relays the rest.
func observingStartTLS(seen chan<- startTLSObserved) TCP {
	return func(c *TCPCtx) error {
		up, err := c.Dial()
		if err != nil {
			return err
		}
		answer, err := relaySSLRequest(c.Client(), up)
		if err != nil {
			return err
		}
		if answer == 'S' {
			if err := c.StartTLS(); err != nil {
				return err
			}
		}
		// The origin speaks first past the handshake, so its line is relayed before the
		// client's is read. Both are read through the connections held before StartTLS.
		first := make([]byte, 0, 32)
		for b := make([]byte, 1); ; {
			if _, err := io.ReadFull(up, b); err != nil {
				return err
			}
			first = append(first, b[0])
			if b[0] == '\n' {
				break
			}
		}
		if _, err := c.Client().Write(first); err != nil {
			return err
		}
		line := make([]byte, len("hello\n"))
		if _, err := io.ReadFull(c.Client(), line); err != nil {
			return err
		}
		seen <- startTLSObserved{tls: c.TLS(), alpn: c.ALPN(), line: string(line)}
		if _, err := up.Write(line); err != nil {
			return err
		}
		return c.Relay()
	}
}

func TestTCP_StartTLS_TerminatesAnInBandUpgrade(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := startTLSOrigin(t, selfSignedFor(t, ca, "db.test"), "postgresql")

	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	tr.DialContext = pinnedDialer(origin.String())
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	seen := make(chan startTLSObserved, 1)
	p.MustAdd[TCP]("db.test", observingStartTLS(seen))
	addr := startProxy(t, p)

	authority := fmt.Sprintf("db.test:%d", origin.Port())
	raw := connectRaw(t, addr, authority)
	client := startTLSClient(t, raw, clientTLSConfig(ca, "db.test", "postgresql"))
	assert.Equal(t, "postgresql", client.ConnectionState().NegotiatedProtocol)
	exchange(t, client, "postgresql")

	got := <-seen
	require.NotNil(t, got.tls, "the handler must see the terminated handshake")
	assert.Equal(t, "postgresql", got.alpn)
	assert.Equal(t, "hello\n", got.line, "the handler must read the client in the clear")

	sess := tcpSession(t, p)
	require.NotNil(t, sess.TLS(), "the session must report the handshake")
	assert.Equal(t, "postgresql", sess.ALPN())
	require.NotNil(t, sess.ClientHello())
	assert.Equal(t, "db.test", sess.ClientHello().ServerName)
	assert.Equal(t, "http", sess.Target().Scheme, "the target reports how the stream arrived")
	assert.False(t, sess.Stale())
}

func TestTransparent_StartTLS_TerminatesAnInBandUpgrade(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := startTLSOrigin(t, selfSignedFor(t, ca, "db.test"))

	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	seen := make(chan startTLSObserved, 1)
	p.MustAdd[TCP](origin.String(), observingStartTLS(seen))
	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) { return origin, nil })

	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()
	client := startTLSClient(t, raw, clientTLSConfig(ca, "db.test"))
	exchange(t, client, "")

	got := <-seen
	require.NotNil(t, got.tls)
	assert.Equal(t, "hello\n", got.line)

	sess := tcpSession(t, p)
	require.NotNil(t, sess.TLS())
	assert.Equal(t, origin, sess.Upstream())
	assert.Equal(t, "db.test", sess.ClientHello().ServerName)
}

func TestTCP_StartTLS_DialToSpeaksTLSAfterwards(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := startTLSOrigin(t, selfSignedFor(t, ca, "db.test"))
	other, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedFor(t, ca, "other.test")},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer func() { _ = other.Close() }()
	go func() {
		for {
			c, err := other.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
		}
	}()

	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	dialed := make(chan error, 1)
	p.MustAdd[TCP]("[127.0.0.0/8]", func(c *TCPCtx) error {
		up, err := c.Dial()
		if err != nil {
			return err
		}
		if _, err := relaySSLRequest(c.Client(), up); err != nil {
			return err
		}
		if err := c.StartTLS(); err != nil {
			return err
		}
		conn, err := c.DialTo(context.Background(), other.Addr().String())
		if err == nil {
			if _, ok := conn.(*tls.Conn); !ok {
				err = fmt.Errorf("DialTo returned %T, want a TLS connection", conn)
			}
		}
		dialed <- err
		return c.Relay()
	})
	addr := startProxy(t, p)

	raw := connectRaw(t, addr, origin.String())
	client := startTLSClient(t, raw, clientTLSConfig(ca, "db.test"))
	exchange(t, client, "")
	require.NoError(t, <-dialed)
}

func TestTCP_StartTLS_DialAfterwardsUsesTheClientServerName(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedFor(t, ca, "db.test")},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	defer func() { _ = origin.Close() }()
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()

	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	tr.DialContext = pinnedDialer(origin.Addr().String())
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	errs := make(chan error, 1)
	p.MustAdd[TCP]("wrong.test", handlerError(errs, func(c *TCPCtx) error {
		// The origin is TLS from the first byte, so the handler answers the request itself.
		var req [8]byte
		if _, err := io.ReadFull(c.Client(), req[:]); err != nil {
			return err
		}
		if _, err := c.Client().Write([]byte{'S'}); err != nil {
			return err
		}
		if err := c.StartTLS(); err != nil {
			return err
		}
		if _, err := c.Dial(); err != nil {
			return err
		}
		return c.Relay()
	}))
	addr := startProxy(t, p)

	raw := connectRaw(t, addr, "wrong.test:5432")
	client := startTLSClient(t, raw, clientTLSConfig(ca, "db.test"))
	_, err = client.Write([]byte("hello\n"))
	require.NoError(t, err)
	line, err := bufio.NewReader(client).ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "hello\n", line)
	_ = client.Close()
	assert.NoError(t, <-errs)
}

// startTLSAfterRequest consumes the client's request, standing in for a relay to an origin
// that agreed, then terminates.
func startTLSAfterRequest(c *TCPCtx) error {
	var req [8]byte
	if _, err := io.ReadFull(c.Client(), req[:]); err != nil {
		return err
	}
	return c.StartTLS()
}

// handlerError runs fn on the stream, reports its error, and ends the connection.
func handlerError(errs chan<- error, fn func(c *TCPCtx) error) TCP {
	return func(c *TCPCtx) error {
		err := fn(c)
		errs <- err
		return err
	}
}

func TestTCP_StartTLS_RefusesAStreamAlreadyUnderTLS(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	errs := make(chan error, 1)
	p.MustAdd[TCP]("db.test", handlerError(errs, (*TCPCtx).StartTLS))
	addr := startProxy(t, p)

	raw := connectRaw(t, addr, "db.test:5432")
	client := tls.Client(raw, clientTLSConfig(ca, "db.test", "postgresql"))
	require.NoError(t, client.Handshake())

	assert.ErrorIs(t, <-errs, errAlreadyTLS)
	_, err = client.Read(make([]byte, 1))
	assert.Error(t, err, "the stream ends with the handler")
}

func TestTCP_StartTLS_NeedsACertificateAuthority(t *testing.T) {
	p, err := New()
	require.NoError(t, err)
	errs := make(chan error, 1)
	p.MustAdd[TCP]("[127.0.0.0/8]", handlerError(errs, startTLSAfterRequest))
	addr := startProxy(t, p)

	raw := connectRaw(t, addr, "127.0.0.1:5432")
	_, err = raw.Write(sslRequest[:])
	require.NoError(t, err)
	assert.ErrorIs(t, <-errs, ErrNoCertificateAuthority)
}

func TestTCP_StartTLS_FailsWithoutAHandshake(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.TLSHandshakeTimeout = time.Second
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	errs := make(chan error, 1)
	p.MustAdd[TCP]("[127.0.0.0/8]", handlerError(errs, startTLSAfterRequest))
	addr := startProxy(t, p)

	raw := connectRaw(t, addr, "127.0.0.1:5432")
	_, err = raw.Write(sslRequest[:])
	require.NoError(t, err)
	_, err = raw.Write([]byte("not a handshake, and long enough to be decided on"))
	require.NoError(t, err)
	require.Error(t, <-errs)
	_ = raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = raw.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

func TestTCP_StartTLS_BoundsTheHandshake(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.TLSHandshakeTimeout = 200 * time.Millisecond
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	errs := make(chan error, 1)
	p.MustAdd[TCP]("[127.0.0.0/8]", handlerError(errs, startTLSAfterRequest))
	addr := startProxy(t, p)

	raw := connectRaw(t, addr, "127.0.0.1:5432")
	_, err = raw.Write(sslRequest[:])
	require.NoError(t, err)
	select {
	case err := <-errs:
		require.Error(t, err)
		assert.True(t, isTimeout(err), "got %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("the handshake was not bounded")
	}
}

func TestTCP_StartTLS_FailsOnAnUntrustedOrigin(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	originCA, err := GenerateCA()
	require.NoError(t, err)
	origin := startTLSOrigin(t, selfSignedFor(t, originCA, "db.test"))

	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	errs := make(chan error, 1)
	p.MustAdd[TCP]("[127.0.0.0/8]", handlerError(errs, func(c *TCPCtx) error {
		up, err := c.Dial()
		if err != nil {
			return err
		}
		if _, err := relaySSLRequest(c.Client(), up); err != nil {
			return err
		}
		return c.StartTLS()
	}))
	addr := startProxy(t, p)

	raw := connectRaw(t, addr, origin.String())
	client := startTLSClient(t, raw, clientTLSConfig(ca, "db.test"))
	err = <-errs
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls handshake with "+origin.String())
	_ = raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = client.Read(make([]byte, 1))
	assert.Error(t, err)
}

func TestTCP_StartTLS_RejectsECH(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithRejectECH(true))
	require.NoError(t, err)
	errs := make(chan error, 1)
	p.MustAdd[TCP]("[127.0.0.0/8]", handlerError(errs, startTLSAfterRequest))
	addr := startProxy(t, p)

	raw := connectRaw(t, addr, "127.0.0.1:5432")
	_, err = raw.Write(sslRequest[:])
	require.NoError(t, err)
	client := tls.Client(raw, &tls.Config{
		ServerName:                     "db.test",
		RootCAs:                        ca.CertPool(),
		MinVersion:                     tls.VersionTLS13,
		EncryptedClientHelloConfigList: echConfigList(t, "public.test"),
	})
	require.Error(t, client.Handshake())
	err = <-errs
	assert.ErrorIs(t, err, errECHOffered)
	assert.ErrorIs(t, err, ErrConnectionRejected)
}

func TestTCP_StartTLS_NameVerification(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := startTLSOrigin(t, selfSignedFor(t, ca, "db.test"))

	tests := []struct {
		name     string
		resolver *fakeResolver
		wantErr  error
	}{
		{name: "a confirmed name terminates", resolver: &fakeResolver{addrs: map[string][]netip.Addr{"db.test": addrsOf("127.0.0.1")}}},
		{name: "a name resolving elsewhere is refused", resolver: &fakeResolver{addrs: map[string][]netip.Addr{"db.test": addrsOf("10.0.0.1")}}, wantErr: errNameMismatch},
		{name: "a name that does not resolve is refused", resolver: &fakeResolver{err: errors.New("no such host")}, wantErr: errNameUnresolved},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := DefaultTransport()
			tr.RootCAs = poolOf(ca)
			p, err := New(WithCA(ca), WithTransport(tr), WithNameVerification(VerifyReject), WithNameResolver(tc.resolver))
			require.NoError(t, err)
			errs := make(chan error, 1)
			p.MustAdd[TCP]("[127.0.0.0/8]", handlerError(errs, func(c *TCPCtx) error {
				up, err := c.Dial()
				if err != nil {
					return err
				}
				if _, err := relaySSLRequest(c.Client(), up); err != nil {
					return err
				}
				if err := c.StartTLS(); err != nil {
					return err
				}
				return c.Relay()
			}))
			addr := startProxy(t, p)

			raw := connectRaw(t, addr, origin.String())
			_, err = raw.Write(sslRequest[:])
			require.NoError(t, err)
			var answer [1]byte
			_, err = io.ReadFull(raw, answer[:])
			require.NoError(t, err)
			client := tls.Client(raw, clientTLSConfig(ca, "db.test"))
			herr := client.Handshake()

			if tc.wantErr == nil {
				require.NoError(t, herr)
				exchange(t, client, "")
				_ = client.Close()
				assert.NoError(t, <-errs)
				assert.Equal(t, int32(1), tc.resolver.calls.Load())
				return
			}
			require.Error(t, herr, "a refused name must not complete the handshake")
			assert.ErrorIs(t, <-errs, tc.wantErr)
			assert.Equal(t, int32(1), tc.resolver.calls.Load())
		})
	}
}

func TestTCP_StartTLS_ClientHelloIsReadConcurrently(t *testing.T) {
	// The race detector checks this test.
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := startTLSOrigin(t, selfSignedFor(t, ca, "db.test"))
	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd[TCP]("[127.0.0.0/8]", func(c *TCPCtx) error {
		up, err := c.Dial()
		if err != nil {
			return err
		}
		if _, err := relaySSLRequest(c.Client(), up); err != nil {
			return err
		}
		if err := c.StartTLS(); err != nil {
			return err
		}
		return c.Relay()
	})
	addr := startProxy(t, p)

	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			for s := range p.Sessions() {
				_ = s.ClientHello()
				_ = s.TLS()
			}
		}
	}()

	raw := connectRaw(t, addr, origin.String())
	client := startTLSClient(t, raw, clientTLSConfig(ca, "db.test"))
	exchange(t, client, "")
	stop.Store(true)
	<-done

	sess := tcpSession(t, p)
	assert.True(t, slices.Equal([]Kind{KindTCP}, sess.ServableAs()))
}

func TestTCP_StreamEntryTerminatesAndReoriginates(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "streamed")
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()

	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)
	p, err := New(WithCA(ca), WithTransport(tr))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	if _, err := p.Add[TCP](originHost(originURL), relayStream); err != nil {
		t.Fatalf("stream entry %s: %v", originHost(originURL), err)
	}

	// A request-level catch-all on every other authority. The stream entry names a static
	// host, so on that host the HTTP kind has nothing registered and the connection is
	// served as the byte stream the entry asked for.
	var handlerRan bool
	p.MustAdd("+{any}/", func(c *HTTPCtx) (*http.Response, error) {
		handlerRan = true
		return c.Forward()
	}, WithMethods[HTTP](http.MethodGet))

	addr := startProxy(t, p)

	// Everything admitted is terminated, so the certificate the client checks is the proxy's
	// and the proxy is the one that has to trust the origin.
	client := proxyClient(addr, ca.CertPool())

	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("get through the stream entry: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "streamed" {
		t.Fatalf("body = %q, want streamed", body)
	}
	if handlerRan {
		t.Fatal("a request handler ran on a connection served as a stream")
	}
}

// A wrapper a tunnel is handed must keep the half-close reachable.
var (
	_ closeWriter = (*peekConn)(nil)
	_ closeWriter = transparentConn{}
)

func TestTCP_TunnelRelaysTheHalfClose(t *testing.T) {
	const head, rest = "head", "the rest of the upload"

	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = originLn.Close() }()

	received := make(chan string, 1)
	go func() {
		conn, aerr := originLn.Accept()
		if aerr != nil {
			received <- "accept: " + aerr.Error()
			return
		}
		defer func() { _ = conn.Close() }()

		first := make([]byte, len(head))
		if _, rerr := io.ReadFull(conn, first); rerr != nil {
			received <- "read: " + rerr.Error()
			return
		}
		// Done sending while the client is still uploading.
		_ = conn.(*net.TCPConn).CloseWrite()

		tail, _ := io.ReadAll(conn)
		received <- string(first) + string(tail)
	}()

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd[TCP](originLn.Addr().String(), relayStream)

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.Serve(proxyLn) }()
	t.Cleanup(func() { _ = p.Close() })

	client, err := net.Dial("tcp", proxyLn.Addr().String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	require.NoError(t, client.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", originLn.Addr(), originLn.Addr())
	require.NoError(t, err)

	br := bufio.NewReader(client)
	established, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, established.StatusCode)

	_, err = client.Write([]byte(head))
	require.NoError(t, err)

	// Reading to EOF is what says the origin's half-close reached the client.
	_, err = io.ReadAll(br)
	require.NoError(t, err)

	_, err = client.Write([]byte(rest))
	require.NoError(t, err)
	require.NoError(t, client.(*net.TCPConn).CloseWrite())

	assert.Equal(t, head+rest, <-received)
}
