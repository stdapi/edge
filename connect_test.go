// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
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
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// namedOrigin starts a TLS origin holding a certificate for name, signed by ca, that answers
// with the Host it was asked for.
func namedOrigin(t *testing.T, ca *CA, name string) *url.URL {
	t.Helper()
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin host=%s", r.Host)
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedFor(t, ca, name)}}
	origin.StartTLS()
	t.Cleanup(origin.Close)
	u, err := url.Parse(origin.URL)
	require.NoError(t, err)
	return u
}

// tunnelClient opens a CONNECT to authority through the proxy at addr and returns a client
// speaking TLS to name inside it, trusting the certificates ca mints.
func tunnelClient(t *testing.T, addr, authority, name string, ca *CA) *http.Client {
	t.Helper()
	raw := connectRaw(t, addr, authority)
	t.Cleanup(func() { _ = raw.Close() })
	tunnel := tls.Client(raw, &tls.Config{
		ServerName: name,
		RootCAs:    ca.CertPool(),
		MinVersion: tls.VersionTLS12,
	})
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return tunnel, nil },
		},
	}
}

func TestConnect_NameRoutesAndTheTargetDials(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := namedOrigin(t, ca, "example.test")

	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)

	var routed atomic.Value
	p.MustAdd("example.test/", func(c *HTTPCtx) (*http.Response, error) {
		routed.Store(c.Authority())
		return c.Forward()
	})
	// The CONNECT is admitted on the literal it names, before any server name exists.
	p.MustAdd[TCP]("[127.0.0.0/8]", relayStream)
	addr := startProxy(t, p)

	// The CONNECT target is the literal the client resolved itself, which no resolver of
	// the proxy could ever produce for example.test.
	client := tunnelClient(t, addr, origin.Host, "example.test", ca)
	resp, err := client.Get("https://example.test/")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, "origin host=example.test", string(body))
	_, port, err := net.SplitHostPort(origin.Host)
	require.NoError(t, err)
	assert.Equal(t, "example.test:"+port, routed.Load())

	sess := waitForSessions(t, p, 1)[0]
	assert.Equal(t, "example.test", sess.Target().Host)
	assert.Equal(t, netip.MustParseAddrPort(origin.Host), sess.Upstream())
}

func TestConnect_DeclaredNameIsDialed(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := namedOrigin(t, ca, "inner.test")

	var dialed atomic.Value
	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed.Store(addr)
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, origin.Host)
	}
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd("inner.test/", forwardHandler)
	p.MustAdd[TCP]("declared.test", relayStream)
	addr := startProxy(t, p)

	_, port, err := net.SplitHostPort(origin.Host)
	require.NoError(t, err)
	client := tunnelClient(t, addr, "declared.test:"+port, "inner.test", ca)
	resp, err := client.Get("https://inner.test/")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	assert.Equal(t, "declared.test:"+port, dialed.Load())
	sess := waitForSessions(t, p, 1)[0]
	assert.Equal(t, "inner.test", sess.Target().Host)
	assert.False(t, sess.Upstream().IsValid(), "a name is left to the dial to resolve")
}

func TestConnect_NameVerificationAppliesToALiteralTarget(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := namedOrigin(t, ca, "example.test")
	originAddr := netip.MustParseAddrPort(origin.Host)

	run := func(t *testing.T, resolved []netip.Addr) (*http.Response, error) {
		t.Helper()
		tr := DefaultTransport()
		tr.RootCAs = poolOf(ca)
		resolver := &fakeResolver{addrs: map[string][]netip.Addr{"example.test": resolved}}
		p, err := New(WithCA(ca), WithTransport(tr),
			WithNameVerification(VerifyReject), WithNameResolver(resolver))
		require.NoError(t, err)
		p.MustAdd("example.test/", forwardHandler)
		p.MustAdd[TCP]("[127.0.0.0/8]", relayStream)
		addr := startProxy(t, p)

		client := tunnelClient(t, addr, origin.Host, "example.test", ca)
		resp, err := client.Get("https://example.test/")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		assert.EqualValues(t, 1, resolver.calls.Load(), "the name is resolved once")
		return resp, err
	}

	t.Run("confirmed", func(t *testing.T) {
		resp, err := run(t, []netip.Addr{originAddr.Addr()})
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("lying", func(t *testing.T) {
		_, err := run(t, addrsOf("6.6.6.6"))
		require.Error(t, err, "the handshake never completes, the connection is closed before it")
	})
}

// floodingOrigin is a TCP origin that writes to every connection until it fails.
func floodingOrigin(t *testing.T) net.Listener {
	t.Helper()
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		chunk := make([]byte, 64<<10)
		for {
			c, aerr := origin.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				for {
					if _, werr := c.Write(chunk); werr != nil {
						return
					}
				}
			}()
		}
	}()
	return origin
}

// sinkOrigin is a TCP origin that reads every connection to its end and then closes it.
func sinkOrigin(t *testing.T) net.Listener {
	t.Helper()
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		for {
			c, aerr := origin.Accept()
			if aerr != nil {
				return
			}
			go func() {
				_, _ = io.Copy(io.Discard, c)
				_ = c.Close()
			}()
		}
	}()
	return origin
}

// stalledH2Connect opens a CONNECT over HTTP/2 to an origin that floods, reads nothing back,
// and returns once the relay has filled the stream's window and stalled in its write.
func stalledH2Connect(t *testing.T) (*Proxy, *Session, *http.Response) {
	t.Helper()
	p, sess, resp := openH2Connect(t, floodingOrigin(t))
	time.Sleep(300 * time.Millisecond)
	return p, sess, resp
}

// openH2Connect opens a CONNECT over HTTP/2 to origin, reads nothing back, and returns once the
// relay serving it is reported.
func openH2Connect(t *testing.T, origin net.Listener) (*Proxy, *Session, *http.Response) {
	t.Helper()
	return openH2ConnectTo(t, origin, relayStream)
}

func openH2ConnectTo(t *testing.T, origin net.Listener, h TCP) (*Proxy, *Session, *http.Response) {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd[TCP](origin.Addr().String(), h)
	addr := startProxy(t, p)

	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	require.NoError(t, err)
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	req, err := http.NewRequest(http.MethodConnect, "https://"+origin.Addr().String(), pr)
	require.NoError(t, err)
	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// One byte decides the stream is a plaintext relay.
	_, err = io.WriteString(pw, "x")
	require.NoError(t, err)
	return p, waitForSessions(t, p, 1)[0], resp
}

// assertStreamReset checks that the client sees its CONNECT stream reset, how a cut reaches
// it over HTTP/2, and returns the error of its read.
func assertStreamReset(t *testing.T, resp *http.Response) error {
	t.Helper()
	ended := make(chan error, 1)
	go func() {
		_, rerr := io.Copy(io.Discard, resp.Body)
		ended <- rerr
	}()
	select {
	case err := <-ended:
		require.Error(t, err, "the stream is reset for the client")
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the client never saw the stream end")
		return nil
	}
}

func assertResetCode(t *testing.T, err error, code http2.ErrCode) {
	t.Helper()
	se, ok := errors.AsType[http2.StreamError](err)
	require.True(t, ok, "the stream ended with %v", err)
	assert.Equal(t, code, se.Code)
}

func TestConnect_CloseOnAStalledH2StreamReturns(t *testing.T) {
	_, sess, resp := stalledH2Connect(t)

	closed := make(chan error, 1)
	go func() { closed <- sess.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Session.Close waited for the stalled write")
	}
	assertStreamReset(t, resp)
}

func TestConnect_ShutdownDeadlineCutsAStalledH2Stream(t *testing.T) {
	p, _, resp := stalledH2Connect(t)

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	err := p.Shutdown(ctx)
	assert.True(t, errors.Is(err, context.DeadlineExceeded), "%v", err)
	assertStreamReset(t, resp)
}

func TestConnect_CloseOnAnIdleH2StreamResets(t *testing.T) {
	_, sess, resp := openH2Connect(t, sinkOrigin(t))
	require.NoError(t, sess.Close())
	assertStreamReset(t, resp)
}

func TestConnect_ShutdownDeadlineCutsAnIdleH2Stream(t *testing.T) {
	p, _, resp := openH2Connect(t, sinkOrigin(t))

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	err := p.Shutdown(ctx)
	assert.True(t, errors.Is(err, context.DeadlineExceeded), "%v", err)
	assertStreamReset(t, resp)
}

// idleH2Connect opens a CONNECT over HTTP/2 served by a handler that does no I/O on the stream
// and returns once its context ends.
func idleH2Connect(t *testing.T) (*Proxy, *Session, *http.Response, <-chan struct{}) {
	t.Helper()
	started, ended := make(chan struct{}), make(chan struct{})
	p, sess, resp := openH2ConnectTo(t, sinkOrigin(t), func(c *TCPCtx) error {
		close(started)
		<-c.Context().Done()
		close(ended)
		return nil
	})
	<-started
	return p, sess, resp, ended
}

func TestConnect_CloseResetsAnH2StreamOutsideItsHandlerIO(t *testing.T) {
	_, sess, resp, ended := idleH2Connect(t)
	require.NoError(t, sess.Close())
	assertResetCode(t, assertStreamReset(t, resp), http2.ErrCodeInternal)
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("the handler context did not end")
	}
}

func TestConnect_ShutdownDeadlineCutsAnH2StreamOutsideItsHandlerIO(t *testing.T) {
	p, _, resp, ended := idleH2Connect(t)
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	err := p.Shutdown(ctx)
	assert.True(t, errors.Is(err, context.DeadlineExceeded), "%v", err)
	// The client reads the reset or the end of the connection, see the limits in
	// docs/lifecycle.md.
	assertStreamReset(t, resp)
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("the handler context did not end")
	}
}

func TestConnect_CloseWaitsForTheRequestsInFlightBeforeItReturns(t *testing.T) {
	p, _, resp := openH2ConnectTo(t, sinkOrigin(t), func(c *TCPCtx) error {
		<-c.Context().Done()
		return nil
	})
	var returned atomic.Bool
	started := make(chan struct{})
	p.MustAdd("allowed.test/", func(c *HTTPCtx) (*http.Response, error) {
		close(started)
		<-c.Request().Context().Done()
		time.Sleep(500 * time.Millisecond)
		returned.Store(true)
		return nil, c.Request().Context().Err()
	})
	addr := startProxy(t, p)
	go func() { _, _ = getBody(proxyClient(addr, nil), "http://allowed.test/") }()
	<-started

	closed := make(chan struct{})
	go func() {
		_ = p.Close()
		close(closed)
	}()
	assertStreamReset(t, resp)
	<-closed
	assert.True(t, returned.Load(), "the cut returned before the handler of a request in flight")
}

func TestConnect_CloseEndsTheContextOfAnH2StreamNotYetAdmitted(t *testing.T) {
	res := newGatedResolver(netip.MustParseAddr("127.0.0.1"))
	p := testProxy(t, WithNameVerification(VerifyReject), WithNameResolver(res))
	p.MustAdd("name.test/", okHandler)
	p.MustAdd[TCP]("127.0.0.1:443", func(*TCPCtx) error { return nil })
	raw, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	require.NoError(t, err)
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	req, err := http.NewRequest(http.MethodConnect, "https://127.0.0.1:443", pr)
	require.NoError(t, err)
	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	go func() {
		tc := tls.Client(&tunnelConn{r: resp.Body, w: pw}, &tls.Config{ServerName: "name.test", InsecureSkipVerify: true})
		_ = tc.Handshake()
	}()
	<-res.entered

	require.NoError(t, p.Close())
	select {
	case err := <-res.ctxErr:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("the name lookup outlived Close")
	}
}

// tcpStalledH2Connect opens a CONNECT over HTTP/2 to an origin that floods, with windows wide
// enough that the relay fills the socket, and a client that never reads its connection.
func tcpStalledH2Connect(t *testing.T) *Session {
	t.Helper()
	origin := floodingOrigin(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd[TCP](origin.Addr().String(), relayStream)
	addr := startProxy(t, p)

	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	_, err = raw.Write([]byte(http2.ClientPreface))
	require.NoError(t, err)
	fr := http2.NewFramer(raw, raw)
	require.NoError(t, fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1<<31 - 1}))
	require.NoError(t, fr.WriteWindowUpdate(0, 1<<31-1-65535))
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	require.NoError(t, enc.WriteField(hpack.HeaderField{Name: ":method", Value: http.MethodConnect}))
	require.NoError(t, enc.WriteField(hpack.HeaderField{Name: ":authority", Value: origin.Addr().String()}))
	require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: buf.Bytes(), EndHeaders: true}))
	require.NoError(t, fr.WriteData(1, false, []byte("x")))
	sess := waitForSessions(t, p, 1)[0]
	time.Sleep(time.Second)
	return sess
}

func TestConnect_CloseEndsTheSessionBehindAClientThatStoppedReadingItsConnection(t *testing.T) {
	sess := tcpStalledH2Connect(t)
	closed := make(chan error, 1)
	go func() { closed <- sess.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Session.Close waited for the client to read its connection")
	}
	assertSessionEnded(t, sess.p, sess)
}

func TestConnect_TLSInsideAnH2StreamHalfClosesAndEndsCleanly(t *testing.T) {
	const head, rest = "head", "the rest of the upload"
	originCA, err := GenerateCA()
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	received := make(chan string, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		tc := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{selfSignedFor(t, originCA, "127.0.0.1")},
			MinVersion:   tls.VersionTLS12,
		})
		first := make([]byte, len(head))
		if _, rerr := io.ReadFull(tc, first); rerr != nil {
			received <- "read: " + rerr.Error()
			return
		}
		_ = tc.CloseWrite()
		tail, _ := io.ReadAll(tc)
		received <- string(first) + string(tail)
	}()

	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.RootCAs = poolOf(originCA)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd[TCP](ln.Addr().String(), relayStream)
	w, r := h2cConnect(t, startProxy(t, p), ln.Addr().String())
	client := tls.Client(&tunnelConn{r: io.NopCloser(r), w: w.(io.WriteCloser)}, clientTLSConfig(ca, "127.0.0.1"))
	require.NoError(t, client.Handshake())

	_, err = client.Write([]byte(head))
	require.NoError(t, err)
	_, err = io.ReadAll(client)
	require.NoError(t, err, "the origin's half-close reaches the client as a close_notify")
	_, err = client.Write([]byte(rest))
	require.NoError(t, err)
	require.NoError(t, client.CloseWrite())

	select {
	case got := <-received:
		assert.Equal(t, head+rest, got)
	case <-time.After(5 * time.Second):
		t.Fatal("the origin never saw the end of the upload")
	}
	_, err = io.Copy(io.Discard, r)
	assert.NoError(t, err, "the stream ends with END_STREAM")
}

// openH3Connect opens a CONNECT over HTTP/3 to origin and returns once its response header
// arrived, with nothing sent on it.
func openH3Connect(t *testing.T, origin net.Listener) (*Proxy, *http3.RequestStream) {
	t.Helper()
	return openH3ConnectTo(t, origin, relayStream)
}

func openH3ConnectTo(t *testing.T, origin net.Listener, h TCP) (*Proxy, *http3.RequestStream) {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd[TCP](origin.Addr().String(), h)
	front, _ := startQUICFront(t, p, ca)

	tr := &http3.Transport{}
	t.Cleanup(func() { _ = tr.Close() })
	cc := tr.NewClientConn(dialQUICFront(t, front, ca))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	rstr, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodConnect, "https://"+origin.Addr().String(), nil)
	require.NoError(t, err)
	require.NoError(t, rstr.SendRequestHeader(req))
	resp, err := rstr.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, rstr.SetReadDeadline(time.Now().Add(5*time.Second)))
	return p, rstr
}

func TestConnect_CloseOnAnIdleH3StreamResets(t *testing.T) {
	p, rstr := openH3Connect(t, sinkOrigin(t))
	_, err := rstr.Write([]byte("x"))
	require.NoError(t, err)

	require.NoError(t, waitForSessions(t, p, 1)[0].Close())
	_, err = io.Copy(io.Discard, rstr)
	code, reset := h3ResetCode(err)
	require.True(t, reset, "the stream ended with %v", err)
	assert.Equal(t, http3.ErrCodeConnectError, code)
}

func TestConnect_ProxyCloseEndsAnH3StreamAnsweredAndUnread(t *testing.T) {
	p, rstr := openH3Connect(t, sinkOrigin(t))
	require.NoError(t, p.Close())
	_, err := io.Copy(io.Discard, rstr)
	require.Error(t, err)
}

func TestConnect_CloseOnAStalledH3StreamReturns(t *testing.T) {
	origin := floodingOrigin(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd[TCP](origin.Addr().String(), relayStream)
	front, _ := startQUICFront(t, p, ca)

	tr := &http3.Transport{}
	t.Cleanup(func() { _ = tr.Close() })
	cc := tr.NewClientConn(dialQUICFront(t, front, ca))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	rstr, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodConnect, "https://"+origin.Addr().String(), nil)
	require.NoError(t, err)
	require.NoError(t, rstr.SendRequestHeader(req))
	resp, err := rstr.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	_, err = rstr.Write([]byte("x"))
	require.NoError(t, err)
	sess := waitForSessions(t, p, 1)[0]
	time.Sleep(300 * time.Millisecond)

	closed := make(chan error, 1)
	go func() { closed <- sess.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Session.Close waited for the stalled write")
	}

	ended := make(chan error, 1)
	go func() {
		_, rerr := io.Copy(io.Discard, rstr)
		ended <- rerr
	}()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the client never saw the stream end")
	}
	require.Eventually(t, func() bool {
		_, werr := rstr.Write([]byte("x"))
		return werr != nil
	}, 5*time.Second, 20*time.Millisecond, "the client's send side is canceled")
}

func TestConnect_CloseOnAnH2StreamEndsOnlyThatTunnel(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		for {
			c, aerr := origin.Accept()
			if aerr != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd[TCP](origin.Addr().String(), relayStream)
	addr := startProxy(t, p)

	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	require.NoError(t, err)

	type tunnel struct {
		r io.ReadCloser
		w *io.PipeWriter
	}
	open := func() tunnel {
		pr, pw := io.Pipe()
		req, rerr := http.NewRequest(http.MethodConnect, "https://"+origin.Addr().String(), pr)
		require.NoError(t, rerr)
		resp, rerr := cc.RoundTrip(req)
		require.NoError(t, rerr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		return tunnel{r: resp.Body, w: pw}
	}
	echo := func(tn tunnel, line string) (string, error) {
		if _, werr := io.WriteString(tn.w, line); werr != nil {
			return "", werr
		}
		got := make(chan string, 1)
		fail := make(chan error, 1)
		go func() {
			buf := make([]byte, len(line))
			if _, rerr := io.ReadFull(tn.r, buf); rerr != nil {
				fail <- rerr
				return
			}
			got <- string(buf)
		}()
		select {
		case s := <-got:
			return s, nil
		case rerr := <-fail:
			return "", rerr
		case <-time.After(3 * time.Second):
			return "", context.DeadlineExceeded
		}
	}

	first, second := open(), open()
	line, err := echo(first, "one\n")
	require.NoError(t, err)
	require.Equal(t, "one\n", line)
	line, err = echo(second, "two\n")
	require.NoError(t, err)
	require.Equal(t, "two\n", line)

	sessions := waitForSessions(t, p, 2)
	require.NoError(t, sessions[0].Close())
	require.NoError(t, sessions[0].Close(), "closing twice is a no-op")

	// One tunnel is over and the client sees it on its stream, the other is untouched.
	_, err1 := echo(first, "again\n")
	_, err2 := echo(second, "again\n")
	require.True(t, (err1 == nil) != (err2 == nil), "exactly one tunnel ends: %v / %v", err1, err2)
	ended := err1
	if ended == nil {
		ended = err2
	}
	// The stream is reset, and the transport closes the request body with it. Which of the
	// two the client trips on first depends on the side it was using at that moment.
	var reset http2.StreamError
	assert.True(t, errors.As(ended, &reset) || errors.Is(ended, io.ErrClosedPipe),
		"the client observes the reset of the stream, got %v", ended)

	third := open()
	line, err = echo(third, "three\n")
	require.NoError(t, err)
	assert.Equal(t, "three\n", line, "the front connection survives its tunnel")
	waitForSessions(t, p, 2)
}

func TestConnect_PoolIsKeyedOnTheDeclaredDestination(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	cert := selfSignedFor(t, ca, "example.test")
	a, b := twoOriginsOnOnePort(t, func(ln net.Listener, id string) {
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, id)
		})}
		go func() { _ = srv.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})) }()
		t.Cleanup(func() { _ = srv.Close() })
	})

	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd("example.test/", forwardHandler)
	p.MustAdd[TCP]("[127.0.0.0/8]", relayStream)
	p.MustAdd[TCP]("[::1]", relayStream)
	addr := startProxy(t, p)

	get := func(target netip.AddrPort) string {
		client := tunnelClient(t, addr, target.String(), "example.test", ca)
		resp, err := client.Get("https://example.test/")
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return string(body)
	}
	assert.Equal(t, "A", get(a))
	assert.Equal(t, "B", get(b), "the second CONNECT declared B")
	assert.Equal(t, "A", get(a))
}

// twoOriginsOnOnePort starts serve on 127.0.0.1 and on [::1], both on the same port, so the
// two origins share an authority and differ only by the address a client declares.
func twoOriginsOnOnePort(t *testing.T, serve func(ln net.Listener, id string)) (a, b netip.AddrPort) {
	t.Helper()
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	lnB, err := net.Listen("tcp", fmt.Sprintf("[::1]:%d", lnA.Addr().(*net.TCPAddr).Port))
	if err != nil {
		_ = lnA.Close()
		t.Skipf("no IPv6 loopback: %v", err)
	}
	serve(lnA, "A")
	serve(lnB, "B")
	return netip.MustParseAddrPort(lnA.Addr().String()), netip.MustParseAddrPort(lnB.Addr().String())
}

func TestConnect_PortIsCanonical(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := namedOrigin(t, ca, "example.test")
	host, port, err := net.SplitHostPort(origin.Host)
	require.NoError(t, err)

	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd("example.test/", forwardHandler)
	p.MustAdd[TCP]("[127.0.0.0/8]:"+port, relayStream)
	addr := startProxy(t, p)

	client := tunnelClient(t, addr, host+":0"+port, "example.test", ca)
	resp, err := client.Get("https://example.test/")
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	sess := waitForSessions(t, p, 1)[0]
	assert.Equal(t, port, sess.Target().Port)
	assert.Equal(t, netip.MustParseAddrPort(origin.Host), sess.Upstream())
}

func TestTargetFromConnect_PortIsCanonical(t *testing.T) {
	r := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: "example.test:0443"}, Host: "example.test:0443"}
	target, err := targetFromConnect(r)
	require.NoError(t, err)
	assert.Equal(t, "443", target.Port)

	r.URL.Host, r.Host = "example.test:65536", "example.test:65536"
	_, err = targetFromConnect(r)
	require.Error(t, err)
}

func TestTargetFromConnect_RootDotIsDropped(t *testing.T) {
	for authority, host := range map[string]string{"Example.Test.:443": "example.test", "127.0.0.1.:443": "127.0.0.1"} {
		target, err := targetFromConnect(&http.Request{Method: http.MethodConnect, URL: &url.URL{Host: authority}, Host: authority})
		require.NoError(t, err)
		assert.Equal(t, host, target.Host)
	}
	for _, authority := range []string{".:443", "example.test..:443"} {
		_, err := targetFromConnect(&http.Request{Method: http.MethodConnect, URL: &url.URL{Host: authority}, Host: authority})
		assert.Error(t, err, authority)
	}
}

func TestTargetFromConnect_MalformedAuthorityIsRefused(t *testing.T) {
	for _, authority := range []string{"origin.test:80:80", "[origin.test]:443", "[::1]x", "::1"} {
		_, err := targetFromConnect(&http.Request{Method: http.MethodConnect, URL: &url.URL{Host: authority}, Host: authority})
		assert.Error(t, err, authority)
	}
	target, err := targetFromConnect(&http.Request{Method: http.MethodConnect, URL: &url.URL{Host: "[::1]:443"}, Host: "[::1]:443"})
	require.NoError(t, err)
	assert.Equal(t, "::1", target.Host)
}

func TestConnect_PlaintextIsPlacedOnItsFirstAuthority(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin got host=%s", r.Host)
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)
	const headerTimeout = 500 * time.Millisecond
	p := testProxy(t, WithProxyAuth(testBasic()), WithTransport(tr), WithReadHeaderTimeout(headerTimeout))
	p.MustAdd("allowed.test/*{rest}", forwardHandler)
	streamed := new(atomic.Int32)
	p.MustAdd[TCP]("internal.test:80", func(c *TCPCtx) error {
		streamed.Add(1)
		return c.Relay()
	})
	addr := startProxy(t, p)

	connect := func(t *testing.T) (net.Conn, *bufio.Reader) {
		t.Helper()
		conn, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		credentials := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
		_, err = fmt.Fprintf(conn, "CONNECT allowed.test:80 HTTP/1.1\r\nHost: allowed.test:80\r\n%s: %s\r\n\r\n", HeaderProxyAuthorization, credentials)
		require.NoError(t, err)
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		return conn, br
	}
	get := func(t *testing.T, conn net.Conn, br *bufio.Reader, host string) (*http.Response, string) {
		t.Helper()
		_, err := fmt.Fprintf(conn, "GET /probe HTTP/1.1\r\nHost: %s\r\n\r\n", host)
		require.NoError(t, err)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp, string(body)
	}

	t.Run("a host nothing admits refuses the connection", func(t *testing.T) {
		conn, br := connect(t)
		resp, _ := get(t, conn, br, "nothing.test")
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		_, err := fmt.Fprint(conn, "GET /probe HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
		if err == nil {
			_, err = http.ReadResponse(br, nil)
		}
		assert.Error(t, err, "the refusal ends the connection, a later request on it is not served")
		assert.Empty(t, slices.Collect(p.Sessions()))
	})

	t.Run("an admitted host is reported with the identity", func(t *testing.T) {
		conn, br := connect(t)
		resp, body := get(t, conn, br, "allowed.test")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "origin got host=allowed.test", body)
		sessions := waitForSessions(t, p, 1)
		assert.Equal(t, KindHTTP, sessions[0].Kind())
		assert.Equal(t, "allowed.test", sessions[0].Target().Host)
		assert.Equal(t, "alice", sessions[0].Identity())
	})

	t.Run("a stream entry on the host takes the bytes", func(t *testing.T) {
		waitForSessions(t, p, 0)
		conn, br := connect(t)
		resp, body := get(t, conn, br, "internal.test")
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "origin got host=internal.test", body)
		assert.EqualValues(t, 1, streamed.Load())
	})

	t.Run("a client that stalls in its headers gets 408 through the tunnel", func(t *testing.T) {
		conn, br := connect(t)
		start := time.Now()
		_, err := fmt.Fprint(conn, "GET /probe HTTP/1.1\r\nX-A: a\r\n")
		require.NoError(t, err)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusRequestTimeout, resp.StatusCode)
		assert.Less(t, time.Since(start), 2*headerTimeout-100*time.Millisecond)
	})
}

func TestConnect_InterceptHTTPS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "yes")
		fmt.Fprintf(w, "origin saw %s %s idem=%s", r.Method, r.URL.Path, r.Header.Get("Idempotency-Key"))
	}))
	defer origin.Close()

	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatalf("parse origin url: %v", err)
	}

	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	var seenPattern string
	p.MustAdd(originHost(originURL)+"/v1/charges", func(c *HTTPCtx) (*http.Response, error) {
		seenPattern = c.Pattern()
		c.Request().Header.Set("Idempotency-Key", "abc-123")

		resp, err := c.Forward()
		if err != nil {
			return nil, err
		}
		body, err := ReadBody(resp, 0)
		if err != nil {
			return nil, err
		}
		return Rewrite(resp, []byte(string(body)+" | patched")), nil
	}, WithMethods[HTTP](http.MethodGet))

	addr := startProxy(t, p)
	client := proxyClient(addr, ca.CertPool())

	resp, err := client.Get(origin.URL + "/v1/charges")
	if err != nil {
		t.Fatalf("get through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	want := "origin saw GET /v1/charges idem=abc-123 | patched"
	if string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
	if got := resp.Header.Get("X-Origin"); got != "yes" {
		t.Fatalf("X-Origin = %q, want yes", got)
	}
	if seenPattern != originHost(originURL)+"/v1/charges" {
		t.Fatalf("pattern = %q", seenPattern)
	}
	if resp.ContentLength != int64(len(want)) {
		t.Fatalf("ContentLength = %d, want %d", resp.ContentLength, len(want))
	}
}

// tunnelConn adapts the two halves of an HTTP/2 CONNECT stream to a net.Conn, so a TLS
// client can run inside a tunnel opened over h2c.
type tunnelConn struct {
	r io.ReadCloser
	w io.WriteCloser
}

func (c *tunnelConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (c *tunnelConn) Write(b []byte) (int, error) { return c.w.Write(b) }

func (c *tunnelConn) Close() error {
	_ = c.w.Close()
	return c.r.Close()
}

func (c *tunnelConn) LocalAddr() net.Addr { return dummyTunnelAddr{} }

func (c *tunnelConn) RemoteAddr() net.Addr { return dummyTunnelAddr{} }

func (c *tunnelConn) SetDeadline(time.Time) error { return nil }

func (c *tunnelConn) SetReadDeadline(time.Time) error { return nil }

func (c *tunnelConn) SetWriteDeadline(time.Time) error { return nil }

type dummyTunnelAddr struct{}

func (dummyTunnelAddr) Network() string { return "tunnel" }

func (dummyTunnelAddr) String() string { return "tunnel" }

func TestConnect_H2C(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)

	var seenProto Protocol
	var seenAuthority string
	p.MustAdd(originHost(originURL)+"/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		seenProto, seenAuthority = c.Protocol(), c.Authority()
		return c.Forward()
	})
	addr := startProxy(t, p)

	// h2c to the proxy, opened by hand since http2.Transport has no proxy support.
	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	require.NoError(t, err)

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodConnect, "https://"+originURL.Host, pr)
	require.NoError(t, err)

	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "the proxy must accept the CONNECT stream")

	// The tunnel now carries the client's own TLS, which the proxy terminates with its CA.
	tunnel := tls.Client(&tunnelConn{r: resp.Body, w: pw}, &tls.Config{
		RootCAs:    ca.CertPool(),
		ServerName: originURL.Hostname(),
		MinVersion: tls.VersionTLS12,
	})
	defer func() { _ = tunnel.Close() }()

	// The tunnel is already handshaken, so it is handed over as the TLS connection itself.
	inner := http.Client{Transport: &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return tunnel, nil },
	}}
	got, err := inner.Get(origin.URL + "/foo")
	require.NoError(t, err)
	body, _ := io.ReadAll(got.Body)
	_ = got.Body.Close()

	assert.Equal(t, "origin", string(body))
	assert.Equal(t, originURL.Host, seenAuthority)
	// The tunnel carries HTTP/1.1 inside, whatever the stream that opened it was.
	assert.Equal(t, HTTP11, seenProto)
}

func TestConnect_HostHeaderCannotReachAnUnnamedAuthority(t *testing.T) {
	reached := new(atomic.Bool)
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached.Store(true)
	}))
	defer other.Close()

	otherURL, err := url.Parse(other.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd("allowed.example.test/+{rest}", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	})
	require.Equal(t, false, p.Admits(Target{Scheme: "http", Host: "127.0.0.1", Port: otherURL.Port()}, KindHTTP))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.Serve(ln) }()
	t.Cleanup(func() { _ = p.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = fmt.Fprint(conn, "CONNECT allowed.example.test:80 HTTP/1.1\r\nHost: allowed.example.test:80\r\n\r\n")
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	established, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, established.StatusCode)

	_, err = fmt.Fprintf(conn, "GET /probe HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", otherURL.Host)
	require.NoError(t, err)

	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.False(t, reached.Load())
}

func TestConnect_OriginResetEndsAnHTTP3ConnectWithConnectError(t *testing.T) {
	b := newProxyBench(t, func(o *rawOrigin, w *wire) {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(w.br, buf); err != nil {
			return
		}
		o.note(string(buf))
		_ = w.Conn.(*net.TCPConn).SetLinger(0)
	})
	b.p.MustAdd("origin.test", relayStream)
	ca, err := GenerateCA()
	require.NoError(t, err)
	front, _ := startQUICFront(t, b.p, ca)
	tr := &http3.Transport{}
	defer func() { _ = tr.Close() }()
	cc := tr.NewClientConn(dialQUICFront(t, front, ca))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	str, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodConnect, "https://origin.test:80", nil)
	require.NoError(t, err)
	require.NoError(t, str.SendRequestHeader(req))
	resp, err := str.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = str.Write([]byte("\x01ping"))
	require.NoError(t, err)
	assert.Equal(t, "\x01ping", b.origin.nextNote(t))

	require.NoError(t, str.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = io.Copy(io.Discard, str)
	h3err, ok := errors.AsType[*http3.Error](err)
	require.True(t, ok, "the stream ended with %v", err)
	assert.Equal(t, http3.ErrCodeConnectError, h3err.ErrorCode)

	require.Eventually(t, func() bool {
		_, err = str.Write([]byte("x"))
		return err != nil
	}, 5*time.Second, 10*time.Millisecond)
	stopped, ok := errors.AsType[*quic.StreamError](err)
	require.True(t, ok, "the write ended with %v", err)
	assert.Equal(t, quic.StreamErrorCode(http3.ErrCodeConnectError), stopped.ErrorCode)
}

func TestConnect_RefusedDialResetsTheTerminatedClient(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.DialContext = func(_ context.Context, network, _ string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd[TCP]("origin.test", relayStream)
	w := dialWire(t, startProxy(t, p))
	w.send(t, "CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n")
	require.Equal(t, http.StatusOK, headStatus(t, w.readHead(t)))
	require.Zero(t, w.br.Buffered())

	tc := tls.Client(w.Conn, &tls.Config{RootCAs: poolOf(ca), ServerName: "origin.test", MinVersion: tls.VersionTLS12})
	require.NoError(t, tc.Handshake())
	_, err = tc.Write([]byte("\x01ping"))
	require.NoError(t, err)
	_, err = tc.Read(make([]byte, 1))
	assert.ErrorIs(t, err, syscall.ECONNRESET, "the session ended cleanly where the dial failed")
}

func TestConnect_CarrierPeerResetFailsTheStream(t *testing.T) {
	origin, upstream := oneConnOrigin(t)
	p := testProxy(t)
	dialed := make(chan struct{})
	returned := make(chan error, 1)
	p.MustAdd[TCP](origin, func(c *TCPCtx) error {
		if _, err := c.Dial(); err != nil {
			return err
		}
		close(dialed)
		<-c.Context().Done()
		returned <- nil
		return nil
	})
	addr := startProxy(t, p)
	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	require.NoError(t, err)
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	req, err := http.NewRequest(http.MethodConnect, "https://"+origin, pr)
	require.NoError(t, err)
	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = pw.Write([]byte{0})
	require.NoError(t, err)
	<-dialed
	up := <-upstream
	require.NoError(t, raw.(*net.TCPConn).SetLinger(0))
	require.NoError(t, raw.Close())
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("the handler context did not end with its carrier")
	}
	assert.Equal(t, "RST", peerEnd(up, 2*time.Second), "origin leg of a byte stream whose carrier its peer reset")
}

func TestConnect_H3NormalEndStopsTheClientDirectionWithNoError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	_, rstr := openH3ConnectTo(t, ln, func(c *TCPCtx) error {
		_, err := c.Client().Read(make([]byte, 1))
		return err
	})
	_, err = rstr.Write([]byte{0})
	require.NoError(t, err)
	require.NoError(t, rstr.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, err = io.Copy(io.Discard, rstr)
	require.NoError(t, err, "the proxy's direction ended with no FIN")
	var werr error
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, werr = rstr.Write([]byte("x")); werr != nil {
			break
		}
	}
	var se *quic.StreamError
	require.ErrorAs(t, werr, &se)
	require.Equal(t, quic.StreamErrorCode(http3.ErrCodeNoError), se.ErrorCode, "the normal end of a CONNECT stream stopped the client's direction with an error code")
}

func TestConnect_H2ClientResetReachesTheHandlerAsARead(t *testing.T) {
	origin, upstream := oneConnOrigin(t)
	p := testProxy(t)
	type seen struct {
		ctxDone  bool
		writeErr error
	}
	got := make(chan seen, 1)
	p.MustAdd[TCP](origin, func(c *TCPCtx) error {
		up, err := c.Dial()
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, c.Client())
		time.Sleep(100 * time.Millisecond)
		var s seen
		s.ctxDone = c.Context().Err() != nil
		_, s.writeErr = up.Write([]byte("bye"))
		got <- s
		return nil
	})
	raw, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
	require.NoError(t, err)
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+origin, pr)
	require.NoError(t, err)
	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = pw.Write([]byte{0})
	require.NoError(t, err)
	up := <-upstream
	time.Sleep(100 * time.Millisecond)
	// RST_STREAM CANCEL from the client.
	cancel()
	_ = resp.Body.Close()
	var s seen
	select {
	case s = <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("the handler did not read the reset")
	}
	require.False(t, s.ctxDone, "the session ended on a peer end while its handler ran, I1")
	require.NoError(t, s.writeErr, "the closer ran on a peer end while the handler ran, I1")
	require.NoError(t, up.SetReadDeadline(time.Now().Add(2*time.Second)))
	b, _ := io.ReadAll(up)
	require.Equal(t, "bye", string(b))
}

func TestConnect_CutEndsAnH2StreamPlacedAsHTTPBeforeItsConnection(t *testing.T) {
	for i := range 5 {
		p := testProxy(t)
		p.MustAdd("origin.test/", okHandler)
		h := dialH2(t, startProxy(t, p))
		h.h2Connect(t)
		require.NoError(t, h.fr.WriteData(1, false, []byte("GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n")))
		var got []byte
		for !bytes.Contains(got, []byte("\r\n\r\nok")) {
			d, ok := h.next(t, 1).(*h2Data)
			require.True(t, ok)
			got = append(got, d.data...)
		}
		go func() { _ = p.Close() }()
		ended := false
		for {
			f, err := h.fr.ReadFrame()
			if err != nil {
				break
			}
			switch f := f.(type) {
			case *http2.DataFrame:
				ended = ended || f.StreamEnded()
			case *http2.MetaHeadersFrame:
				ended = ended || f.StreamEnded()
			case *http2.RSTStreamFrame:
				ended = true
			}
		}
		require.True(t, ended, "run %d: the cut ended the connection before the stream on it", i)
	}
}
