// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
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
	"os"
	"slices"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stdapi/edge/internal/netutil"
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

func TestTCP_StartTLS_HandlerReturnSendsCloseNotify(t *testing.T) {
	p, ca := newTLSProxy(t)
	p.MustAdd[TCP](tlsDB, startTLSLine)
	conn := connectRaw(t, startProxy(t, p), tlsDB+":5432")
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := io.WriteString(conn, "STARTTLS\n")
	require.NoError(t, err)
	ok := make([]byte, len("OK\n"))
	_, err = io.ReadFull(conn, ok)
	require.NoError(t, err)

	rec := &recordingConn{Conn: conn}
	tc := tls.Client(rec, &tls.Config{ServerName: tlsDB, RootCAs: ca.CertPool(), MaxVersion: tls.VersionTLS12, MinVersion: tls.VersionTLS12})
	got, err := io.ReadAll(tc)
	require.NoError(t, err)
	assert.Equal(t, "tls\n", string(got))
	assert.Equal(t, byte(tlsAlert), rec.lastRecord())
}

func TestTCP_StartTLS_HandlerReturnEndsAStalledClient(t *testing.T) {
	p, ca := newTLSProxy(t)
	returned := make(chan struct{})
	p.MustAdd[TCP](tlsDB, func(c *TCPCtx) error {
		if err := startTLSLine(c); err != nil {
			return err
		}
		writeUntilFull(c.Client())
		close(returned)
		return nil
	})
	conn := connectRaw(t, startProxy(t, p), tlsDB+":5432")
	_, err := io.WriteString(conn, "STARTTLS\n")
	require.NoError(t, err)
	_, err = io.ReadFull(conn, make([]byte, len("OK\n")))
	require.NoError(t, err)
	require.NoError(t, tls.Client(conn, clientTLSConfig(ca, tlsDB)).Handshake())
	tcpSession(t, p)

	<-returned
	// The legs end within alertWriteTimeout, the normal end of TCP waiting that long at most for
	// the peer's FIN.
	assert.Eventually(t, func() bool { return len(slices.Collect(p.Sessions())) == 0 },
		2*alertWriteTimeout, 10*time.Millisecond, "the session outlived its handler")
}

func TestTCP_StartTLS_HandlerReturnEndsAStalledOrigin(t *testing.T) {
	originCA, err := GenerateCA()
	require.NoError(t, err)
	cert := selfSignedFor(t, originCA, tlsDB)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	addr, _ := tlsOrigin(t, &cert, nil, func(*tls.Conn) { <-stop })
	tr := DefaultTransport()
	tr.RootCAs = poolOf(originCA)
	tr.DialContext = pinnedDialer(addr)
	p, ca := newTLSProxy(t, WithTransport(tr))

	returned := make(chan struct{})
	p.MustAdd[TCP](tlsDB, func(c *TCPCtx) error {
		if err := startTLSLine(c); err != nil {
			return err
		}
		up, err := c.Dial()
		if err != nil {
			return err
		}
		writeUntilFull(up)
		close(returned)
		return nil
	})
	conn := connectRaw(t, startProxy(t, p), tlsDB+":5432")
	_, err = io.WriteString(conn, "STARTTLS\n")
	require.NoError(t, err)
	_, err = io.ReadFull(conn, make([]byte, len("OK\n")))
	require.NoError(t, err)
	client := tls.Client(conn, clientTLSConfig(ca, tlsDB))
	require.NoError(t, client.Handshake())
	go func() { _, _ = io.Copy(io.Discard, client) }()
	tcpSession(t, p)

	<-returned
	// The legs end within alertWriteTimeout, the normal end of TCP waiting that long at most for
	// the peer's FIN.
	assert.Eventually(t, func() bool { return len(slices.Collect(p.Sessions())) == 0 },
		2*alertWriteTimeout, 10*time.Millisecond, "the session outlived its handler")
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
			if _, ok := conn.(*tlsConn); !ok {
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

func TestTCP_StartTLS_RefusalLeavesTheConnectionToTheHandler(t *testing.T) {
	p, err := New()
	require.NoError(t, err)
	got := make(chan string, 1)
	p.MustAdd[TCP](tlsDB, func(c *TCPCtx) error {
		if _, err := io.ReadFull(c.Client(), make([]byte, len("STARTTLS\n"))); err != nil {
			return err
		}
		if _, err := io.WriteString(c.Client(), "OK\n"); err != nil {
			return err
		}
		serr := c.StartTLS()
		_, werr := io.WriteString(c.Client(), "454 TLS not available\n")
		line := make([]byte, len("HELLO AFTER\n"))
		_, rerr := io.ReadFull(c.Client(), line)
		got <- fmt.Sprintf("%v %v %v %q", errors.Is(serr, ErrNoCertificateAuthority), werr, rerr, line)
		return nil
	})
	c := connectRaw(t, startProxy(t, p), tlsDB+":5432")
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = io.WriteString(c, "STARTTLS\n")
	require.NoError(t, err)
	_, err = io.ReadFull(c, make([]byte, len("OK\n")))
	require.NoError(t, err)
	_, err = io.WriteString(c, "HELLO AFTER\n")
	require.NoError(t, err)

	want := "\x15\x03\x03\x00\x02\x02\x50454 TLS not available\n"
	head := make([]byte, len(want))
	_, err = io.ReadFull(c, head)
	require.NoError(t, err)
	assert.Equal(t, want, string(head))
	assert.Equal(t, `true <nil> <nil> "HELLO AFTER\n"`, <-got)

	// Bytes the handler never reads still leave the alert and the end of the stream intact.
	_, _ = c.Write(make([]byte, 2*clientHelloPeekSize))
	time.Sleep(200 * time.Millisecond)
	_, err = c.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
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
	// crypto/tls sends no alert on a first record that is no handshake, so the end is the failed
	// one.
	assert.Equal(t, "RST", peerEnd(raw, 3*time.Second))
}

func TestTCP_StartTLS_BoundsTheHandshake(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithReadHeaderTimeout(200*time.Millisecond))
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

func TestTCP_SessionCloseResetsEveryLeg(t *testing.T) {
	for _, front := range []string{"h1", "h2c", "h3"} {
		for _, how := range []string{"Session.Close", "Proxy.Close"} {
			t.Run(front+"/"+how, func(t *testing.T) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { _ = ln.Close() })
				upstream := make(chan net.Conn, 1)
				go func() {
					if c, aerr := ln.Accept(); aerr == nil {
						t.Cleanup(func() { _ = c.Close() })
						upstream <- c
					}
				}()
				release := make(chan struct{})
				t.Cleanup(func() { close(release) })
				dialed := make(chan struct{})
				hold := func(c *TCPCtx) error {
					if _, derr := c.Dial(); derr != nil {
						return derr
					}
					close(dialed)
					<-release
					return nil
				}
				var p *Proxy
				switch front {
				case "h3":
					var rstr *http3.RequestStream
					p, rstr = openH3ConnectTo(t, ln, hold)
					_, err = rstr.Write([]byte{0})
				case "h2c":
					p = testProxy(t)
					p.MustAdd[TCP](ln.Addr().String(), hold)
					w, _ := h2cConnect(t, startProxy(t, p), ln.Addr().String())
					_, err = w.Write([]byte{0})
				default:
					p = testProxy(t)
					p.MustAdd[TCP](ln.Addr().String(), hold)
					connectStream(t, startProxy(t, p), ln.Addr().String())
				}
				require.NoError(t, err)
				<-dialed
				up := <-upstream
				if how == "Session.Close" {
					require.NoError(t, waitForSessions(t, p, 1)[0].Close())
				} else {
					require.NoError(t, p.Close())
				}
				assert.Equal(t, "RST", peerEnd(up, 2*time.Second), "origin leg")
			})
		}
	}
}

func TestTCP_HandlerErrorResetsEveryLeg(t *testing.T) {
	origin, upstream := oneConnOrigin(t)
	p := testProxy(t)
	p.MustAdd[TCP](origin, func(c *TCPCtx) error {
		if _, err := c.Dial(); err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
		return errors.New("handler failure")
	})
	client := connectStream(t, startProxy(t, p), origin)
	up := <-upstream
	assert.Equal(t, "RST", peerEnd(client, 2*time.Second), "client leg")
	assert.Equal(t, "RST", peerEnd(up, 2*time.Second), "origin leg")
}

func TestTCP_NilReturnEndsEveryLegCleanlyWithBytesUnread(t *testing.T) {
	origin, upstream := oneConnOrigin(t)
	p := testProxy(t)
	p.MustAdd[TCP](origin, func(c *TCPCtx) error {
		_, err := c.Dial()
		time.Sleep(100 * time.Millisecond)
		return err
	})
	client := connectStream(t, startProxy(t, p), origin)
	up := <-upstream
	_, err := client.Write([]byte("unread by the handler"))
	require.NoError(t, err)
	_, err = up.Write([]byte("unread by the handler"))
	require.NoError(t, err)
	assert.Equal(t, "FIN", peerEnd(client, 2*time.Second), "client leg")
	assert.Equal(t, "FIN", peerEnd(up, 2*time.Second), "origin leg")
}

func TestTCP_SessionCloseDuringTheNormalEndKeepsItsFIN(t *testing.T) {
	origin, upstream := oneConnOrigin(t)
	release := make(chan struct{})
	p := testProxy(t)
	p.MustAdd[TCP](origin, func(c *TCPCtx) error {
		_, err := c.Dial()
		<-release
		return err
	})
	client := connectStream(t, startProxy(t, p), origin)
	<-upstream
	sess := waitForSessions(t, p, 1)[0]
	close(release)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF, "the normal end sent no FIN")

	// The normal end waits for the client's FIN, which never comes, while the session closes.
	require.NoError(t, sess.Close())
	time.Sleep(100 * time.Millisecond)
	_, err = client.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF, "the closer reset a leg in its normal end")
}

func TestTCP_DialAfterSessionCloseFails(t *testing.T) {
	origin, upstream := oneConnOrigin(t)
	dialed := make(chan error, 1)
	p := testProxy(t)
	p.MustAdd[TCP](origin, func(c *TCPCtx) error {
		<-c.Context().Done()
		_, err := c.DialTo(context.Background(), origin)
		dialed <- err
		return err
	})
	connectStream(t, startProxy(t, p), origin)
	require.NoError(t, waitForSessions(t, p, 1)[0].Close())
	assert.Error(t, <-dialed)
	select {
	case up := <-upstream:
		assert.Equal(t, "RST", peerEnd(up, 2*time.Second), "a leg opened after the closer ran")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestTCP_DialAfterTheCutFails(t *testing.T) {
	origin, upstream := oneConnOrigin(t)
	cut, dialed := make(chan struct{}), make(chan error, 1)
	p := testProxy(t)
	p.MustAdd[TCP](origin, func(c *TCPCtx) error {
		<-cut
		_, err := c.DialTo(context.Background(), origin)
		dialed <- err
		return err
	})
	connectStream(t, startProxy(t, p), origin)
	waitForSessions(t, p, 1)
	require.NoError(t, p.Close())
	close(cut)
	assert.ErrorIs(t, <-dialed, net.ErrClosed)
	select {
	case <-upstream:
		t.Error("a dial after the cut reached the origin")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestTCP_H2TunnelEndsOnTheOriginHalfClose(t *testing.T) {
	const head = "head"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	received := make(chan string, 1)
	halfClosed := make(chan time.Time, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		first := make([]byte, len(head))
		if _, rerr := io.ReadFull(conn, first); rerr != nil {
			received <- "read: " + rerr.Error()
			return
		}
		_, _ = conn.Write([]byte("hi"))
		_ = conn.(*net.TCPConn).CloseWrite()
		halfClosed <- time.Now()
		tail, _ := io.ReadAll(conn)
		received <- string(first) + string(tail)
	}()

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd[TCP](ln.Addr().String(), relayStream)
	w, r := h2cConnect(t, startProxy(t, p), ln.Addr().String())
	_, err = w.Write([]byte(head))
	require.NoError(t, err)
	var at time.Time
	select {
	case at = <-halfClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("the origin was never reached")
	}

	type read struct {
		b   []byte
		err error
	}
	got := make(chan read, 1)
	go func() {
		b, rerr := io.ReadAll(r)
		got <- read{b, rerr}
	}()
	select {
	case rd := <-got:
		require.NoError(t, rd.err)
		assert.Equal(t, "hi", string(rd.b))
	case <-time.After(time.Until(at.Add(alertWriteTimeout / 2))):
		t.Fatal("the half-close of the origin did not end the stream")
	}
	select {
	case s := <-received:
		assert.Equal(t, head, s, "the origin reads its normal end, the later upload stopped")
	case <-time.After(3 * time.Second):
		t.Fatal("the origin never saw the end")
	}
}

func TestTCP_H2TunnelNormalEndIsImmediate(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	returned := make(chan time.Time, 1)
	p.MustAdd[TCP]("svc.test:7000", func(c *TCPCtx) error {
		_, _ = c.Client().Write([]byte("bye"))
		returned <- time.Now()
		return nil
	})
	w, r := h2cConnect(t, startProxy(t, p), "svc.test:7000")
	_, err = w.Write([]byte("hello"))
	require.NoError(t, err)
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, "bye", string(b))
	assert.Less(t, time.Since(<-returned), alertWriteTimeout/2)
}

func TestTCP_StartTLSTerminatesAClientHelloAfterTheSniffTimeout(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithSniffTimeout(200*time.Millisecond))
	require.NoError(t, err)
	res := make(chan error, 1)
	p.MustAdd[TCP]("svc.test:465", func(c *TCPCtx) error {
		serr := c.StartTLS()
		res <- serr
		return serr
	})
	conn := connectRaw(t, startProxy(t, p), "svc.test:465")
	time.Sleep(400 * time.Millisecond)
	cli := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "svc.test"})
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	require.NoError(t, cli.Handshake())
	select {
	case serr := <-res:
		assert.NoError(t, serr, "StartTLS terminates the ClientHello the handler asked for")
	case <-time.After(3 * time.Second):
		t.Fatal("no StartTLS result")
	}
}

func TestTCP_CloseCancelsADialToInProgressWhateverItsContext(t *testing.T) {
	for _, by := range []string{"Session.Close", "cut"} {
		t.Run(by, func(t *testing.T) {
			canceled := make(chan bool, 1)
			tr := DefaultTransport()
			tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				select {
				case <-ctx.Done():
					canceled <- true
					return nil, ctx.Err()
				case <-time.After(5 * time.Second):
					canceled <- false
					return nil, errors.New("the dial was never canceled")
				}
			}
			p := testProxy(t, WithTransport(tr))
			running := make(chan *Session, 1)
			p.MustAdd[TCP]("stream.test", func(c *TCPCtx) error {
				running <- c.Session()
				_, err := c.DialTo(context.Background(), "blackhole.test:1")
				return err
			})
			conn, err := net.Dial("tcp", startProxy(t, p))
			require.NoError(t, err)
			t.Cleanup(func() { _ = conn.Close() })
			_, err = fmt.Fprintf(conn, "CONNECT stream.test:5000 HTTP/1.1\r\nHost: stream.test:5000\r\n\r\n")
			require.NoError(t, err)
			resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			_, err = io.WriteString(conn, "\x01\x02hello")
			require.NoError(t, err)
			sess := <-running
			time.Sleep(200 * time.Millisecond)
			if by == "cut" {
				require.NoError(t, p.Close())
			} else {
				require.NoError(t, sess.Close())
			}
			select {
			case ok := <-canceled:
				assert.True(t, ok, "a closer cancels every dial in progress for its unit")
			case <-time.After(2 * time.Second):
				t.Fatal("the dial outlived the close")
			}
		})
	}
}

func TestTCP_HandlerErrorResetsOnceTheQueueIsAcknowledged(t *testing.T) {
	origin, _ := oneConnOrigin(t)
	p := testProxy(t)
	returned := make(chan time.Time, 1)
	p.MustAdd[TCP](origin, func(c *TCPCtx) error {
		writeUntilFull(c.Client())
		_ = c.Client().SetWriteDeadline(time.Time{})
		returned <- time.Now()
		return errors.New("handler failure")
	})
	// A receive buffer of a fixed size grows no further, so the client kernel never takes in
	// the queue the client does not read.
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
		})
	}}
	client, err := d.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	_, err = fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", origin, origin)
	require.NoError(t, err)
	var head []byte
	for !bytes.HasSuffix(head, []byte("\r\n\r\n")) {
		b := make([]byte, 1)
		_, err = client.Read(b)
		require.NoError(t, err)
		head = append(head, b...)
	}
	require.Contains(t, string(head), " 200 ")
	_, err = client.Write([]byte{0})
	require.NoError(t, err)
	tc := socketOf(client)
	if _, err := netutil.UnsentBytes(tc); errors.Is(err, errors.ErrUnsupported) {
		t.Skip("no send queue")
	}
	r := <-returned
	// The client never reads, so the queue on the proxy side stays full.
	failedAt := make(chan time.Time, 1)
	go func() {
		chunk := make([]byte, 1024)
		for {
			_ = client.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
			if _, err := client.Write(chunk); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
				if !errors.Is(err, syscall.ECONNRESET) && !errors.Is(err, syscall.EPIPE) {
					t.Errorf("the client write failed with %v, no reset", err)
				}
				failedAt <- time.Now()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	select {
	case f := <-failedAt:
		t.Logf("reset %v after the handler returned", f.Sub(r))
		assert.GreaterOrEqual(t, f.Sub(r), alertWriteTimeout*8/10, "the client leg was reset with bytes still queued")
	case <-time.After(3 * time.Second):
		t.Fatal("the client leg never ended")
	}
}

func TestTCP_RelayIdleTimeoutFailsEveryLeg(t *testing.T) {
	origin, upstream := oneConnOrigin(t)
	side, sideConns := oneConnOrigin(t)
	p := testProxy(t)
	relayErr := make(chan error, 1)
	p.MustAdd[TCP](origin, func(c *TCPCtx) error {
		up, err := c.Dial()
		if err != nil {
			return err
		}
		if _, err := c.DialTo(context.Background(), side); err != nil {
			return err
		}
		_, _, err = (&Relayer{IdleTimeout: 100 * time.Millisecond}).Relay(c.Client(), up)
		relayErr <- err
		return err
	})
	connectStream(t, startProxy(t, p), origin)
	<-upstream
	sideConn := <-sideConns
	select {
	case err := <-relayErr:
		t.Logf("Relay returned %v at its idle timeout", err)
		assert.Error(t, err, "the failed timer reached the handler as nil")
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not end")
	}
	assert.Equal(t, "RST", peerEnd(sideConn, 2*time.Second), "a leg of a unit a failed timer ended")
}

func TestTCP_StartTLS_ClientResetInsideTheClientHelloGetsNoAlert(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run("reject ECH "+strconv.FormatBool(reject), func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			p, err := New(WithCA(ca), WithSniffTimeout(100*time.Millisecond), WithRejectECH(reject))
			require.NoError(t, err)
			type result struct {
				err     error
				alerted bool
			}
			got := make(chan result, 1)
			p.MustAdd[TCP]("127.0.0.1:9", func(c *TCPCtx) error {
				if _, err := io.ReadFull(c.Client(), make([]byte, 1)); err != nil {
					got <- result{err: err}
					return err
				}
				err := c.StartTLS()
				got <- result{err: err, alerted: c.alerted}
				return err
			})
			conn := connectRaw(t, startProxy(t, p), "127.0.0.1:9")
			_, err = conn.Write([]byte{0})
			require.NoError(t, err)
			time.Sleep(200 * time.Millisecond)
			_, err = conn.Write([]byte{0x16, 0x03, 0x01, 0x01, 0x00, 0x01})
			require.NoError(t, err)
			time.Sleep(100 * time.Millisecond)
			require.NoError(t, conn.(*net.TCPConn).SetLinger(0))
			require.NoError(t, conn.Close())
			select {
			case r := <-got:
				require.ErrorIs(t, r.err, syscall.ECONNRESET)
				require.False(t, r.alerted)
			case <-time.After(5 * time.Second):
				t.Fatal("the handler did not return")
			}
		})
	}
}

func TestTCP_StartTLS_EndOfTheStreamBeforeTheHandshake(t *testing.T) {
	cases := []struct {
		name    string
		sent    []byte
		reject  bool
		alerted bool
	}{
		{name: "nothing, reject ECH", reject: true},
		{name: "bytes of no TLS record", sent: []byte("QU")},
		{name: "a ClientHello cut short", sent: []byte{0x16, 0x03, 0x01, 0x01, 0x00, 0x01}, alerted: true},
		{name: "a ClientHello cut short, reject ECH", sent: []byte{0x16, 0x03, 0x01, 0x01, 0x00, 0x01}, reject: true, alerted: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			p, err := New(WithCA(ca), WithSniffTimeout(100*time.Millisecond), WithRejectECH(tc.reject))
			require.NoError(t, err)
			type result struct {
				err     error
				alerted bool
			}
			got := make(chan result, 1)
			p.MustAdd[TCP]("127.0.0.1:9", func(c *TCPCtx) error {
				if _, err := io.ReadFull(c.Client(), make([]byte, 1)); err != nil {
					got <- result{err: err}
					return err
				}
				err := c.StartTLS()
				got <- result{err: err, alerted: c.alerted}
				return err
			})
			conn := connectRaw(t, startProxy(t, p), "127.0.0.1:9")
			_, err = conn.Write([]byte{0})
			require.NoError(t, err)
			time.Sleep(200 * time.Millisecond)
			if len(tc.sent) > 0 {
				_, err = conn.Write(tc.sent)
				require.NoError(t, err)
			}
			require.NoError(t, conn.(*net.TCPConn).CloseWrite())
			select {
			case r := <-got:
				require.Error(t, r.err)
				require.Equal(t, tc.alerted, r.alerted, "%v", r.err)
				if tc.alerted {
					require.ErrorIs(t, r.err, errHelloCutShort)
				} else {
					require.ErrorIs(t, r.err, io.EOF)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the handler did not return")
			}
		})
	}
}

func TestTCP_NormalEndOfATerminatedConnectionGivesTheFINAtOnce(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			p, err := New(WithCA(ca))
			require.NoError(t, err)
			p.MustAdd[TCP]("review.test:443", func(c *TCPCtx) error { return nil })
			raw, err := net.Dial("tcp", startProxy(t, p))
			require.NoError(t, err)
			defer raw.Close()
			_, err = fmt.Fprintf(raw, "CONNECT review.test:443 HTTP/1.1\r\nHost: review.test:443\r\n\r\n")
			require.NoError(t, err)
			br := bufio.NewReader(raw)
			resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
			require.NoError(t, err)
			require.Equal(t, 200, resp.StatusCode)
			tc := tls.Client(raw, &tls.Config{ServerName: "review.test", RootCAs: ca.CertPool(), MinVersion: version, MaxVersion: version, NextProtos: []string{"x-review"}})
			require.NoError(t, tc.Handshake())
			start := time.Now()
			_ = raw.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, _ = io.ReadAll(tc)
			_, rerr := raw.Read(make([]byte, 1))
			require.ErrorIs(t, rerr, io.EOF)
			require.Less(t, time.Since(start), alertWriteTimeout/2, "the FIN waited for the client")
		})
	}
}
