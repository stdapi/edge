// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
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

// A CONNECT names where the packets go and the server name says what the client expects
// there. The name is what the tree routes on, the CONNECT target is what the proxy dials.
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

// A CONNECT naming a hostname is dialed as that name, whatever server name the client sends
// inside, and the name inside is still what routes.
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

// A CONNECT to a literal gives name verification the same two facts a redirect does, the
// name the client wants and the address it chose, so the check applies to it as well.
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

// stalledH2Connect opens a CONNECT over HTTP/2 to an origin that floods, reads nothing back,
// and returns once the relay has filled the stream's window and stalled in its write.
func stalledH2Connect(t *testing.T) (*Proxy, *Session, *http.Response) {
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
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	req, err := http.NewRequest(http.MethodConnect, "https://"+origin.Addr().String(), pr)
	require.NoError(t, err)
	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// One byte decides the stream is a plaintext relay. Nothing reads the response, so the
	// relay fills the stream's window and stalls.
	_, err = io.WriteString(pw, "x")
	require.NoError(t, err)
	sess := waitForSessions(t, p, 1)[0]
	time.Sleep(300 * time.Millisecond)
	return p, sess, resp
}

// assertStreamEnds checks that the client sees the end of its CONNECT stream.
func assertStreamEnds(t *testing.T, resp *http.Response) {
	t.Helper()
	ended := make(chan error, 1)
	go func() {
		_, rerr := io.Copy(io.Discard, resp.Body)
		ended <- rerr
	}()
	select {
	case err := <-ended:
		require.Error(t, err, "the stream ends for the client")
	case <-time.After(5 * time.Second):
		t.Fatal("the client never saw the stream end")
	}
}

// Closing the session of a CONNECT carried on an HTTP/2 stream returns while the relay is
// stalled on a client that stopped reading, and the client sees the stream end.
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
	assertStreamEnds(t, resp)
}

// The Shutdown deadline cuts a stalled CONNECT stream like any other connection.
func TestConnect_ShutdownDeadlineCutsAStalledH2Stream(t *testing.T) {
	p, _, resp := stalledH2Connect(t)

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	assert.ErrorIs(t, p.Shutdown(ctx), context.DeadlineExceeded)
	assertStreamEnds(t, resp)
}

// Closing the session of a CONNECT carried on an HTTP/2 stream ends that stream and nothing
// else. The sibling tunnel keeps echoing and the front connection still opens new ones.
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
	// net/http ends the stream cleanly once the handler returned, and closes the request
	// body with it. Which of the two the client trips on first depends on the side it was
	// using at that moment, and either is the end.
	assert.True(t, errors.Is(ended, io.EOF) || errors.Is(ended, io.ErrClosedPipe),
		"the client observes the end of the stream, got %v", ended)

	third := open()
	line, err = echo(third, "three\n")
	require.NoError(t, err)
	assert.Equal(t, "three\n", line, "the front connection survives its tunnel")
	waitForSessions(t, p, 2)
}

// Two CONNECTs to two different literals on one port under one server name reach the two
// origins they declared, and a third to the first literal does too. Upstream connections are
// pooled per destination, so the requests of one client never go over a connection another
// client chose.
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

// A CONNECT to a port spelled with a leading zero reaches the entry written without it, and
// the session reports the decimal form.
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
