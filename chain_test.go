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
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fox-toolkit/edge/internal/h2tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// fixedProxy selects one proxy for every connection.
func fixedProxy(raw string) func(*http.Request) (*url.URL, error) {
	u, err := url.Parse(raw)
	return func(*http.Request) (*url.URL, error) { return u, err }
}

// A TCP stream reaches its origin with a CONNECT to the proxy Transport.Proxy selects, which
// is asked with the destination as a URL, and the proxy is the only address the front dials.
func TestChain_TCPStreamThroughCONNECT(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := namedOrigin(t, ca, "inner.test")
	_, port, err := net.SplitHostPort(origin.Host)
	require.NoError(t, err)

	backTr := DefaultTransport()
	backTr.RootCAs = poolOf(ca)
	backTr.DialContext = pinnedDialer(origin.Host)
	back, err := New(WithCA(ca), WithTransport(backTr))
	require.NoError(t, err)
	back.MustAdd[TCP]("inner.test", relayStream)
	backAddr := startProxy(t, back)

	frontTr := DefaultTransport()
	frontTr.RootCAs = poolOf(ca)
	dialed := new(recorder)
	frontTr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed.add(network + " " + addr)
		return defaultDialer.DialContext(ctx, network, addr)
	}
	asked := new(recorder)
	frontTr.Proxy = func(r *http.Request) (*url.URL, error) {
		asked.add(r.URL.String())
		return url.Parse("http://" + backAddr)
	}
	front, err := New(WithCA(ca), WithTransport(frontTr))
	require.NoError(t, err)
	front.MustAdd[TCP]("inner.test", relayStream)
	frontAddr := startProxy(t, front)

	client := tunnelClient(t, frontAddr, "inner.test:"+port, "inner.test", ca)
	resp, err := client.Get("https://inner.test/")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "origin host=inner.test", string(body))

	assert.Equal(t, []string{"https://inner.test:" + port}, asked.all())
	assert.Equal(t, []string{"tcp " + backAddr}, dialed.all())
	sess := waitForSessions(t, back, 1)[0]
	assert.Equal(t, "inner.test", sess.Target().Host)
	assert.Equal(t, KindTCP, sess.Kind())
}

// Credentials in the proxy URL are sent as a Basic Proxy-Authorization, and a proxy that
// refuses the CONNECT fails the dial with its status.
func TestChain_CONNECTCarriesTheCredentials(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := namedOrigin(t, ca, "inner.test")
	_, port, err := net.SplitHostPort(origin.Host)
	require.NoError(t, err)

	backTr := DefaultTransport()
	backTr.RootCAs = poolOf(ca)
	backTr.DialContext = pinnedDialer(origin.Host)
	back, err := New(WithCA(ca), WithTransport(backTr), WithProxyAuth(BasicAuth("edge", func(user, pass string) bool {
		return user == "alice" && pass == "s3cret"
	})))
	require.NoError(t, err)
	back.MustAdd[TCP]("inner.test", relayStream)
	backAddr := startProxy(t, back)

	frontTr := DefaultTransport()
	frontTr.RootCAs = poolOf(ca)
	frontTr.Proxy = fixedProxy("http://alice:s3cret@" + backAddr)
	front, err := New(WithCA(ca), WithTransport(frontTr))
	require.NoError(t, err)
	front.MustAdd[TCP]("inner.test", relayStream)
	frontAddr := startProxy(t, front)

	client := tunnelClient(t, frontAddr, "inner.test:"+port, "inner.test", ca)
	resp, err := client.Get("https://inner.test/")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	frontTr.Proxy = fixedProxy("http://" + backAddr)
	_, err = newUpstreamDialer(frontTr).dial(t.Context(), "tcp", "inner.test:"+port, "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "407")
}

// A datagram flow reaches its origin through a CONNECT-UDP tunnel to the proxy, and every
// tunnel to one proxy shares one HTTP/3 connection.
func TestChain_DatagramFlowThroughCONNECTUDP(t *testing.T) {
	echo := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)

	back, err := New(WithCA(ca))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	backFront, _ := startQUICFront(t, back, ca)

	frontTr := DefaultTransport()
	frontTr.RootCAs = poolOf(ca)
	frontTr.Proxy = fixedProxy("https://" + backFront.String())
	front, err := New(WithCA(ca), WithTransport(frontTr))
	require.NoError(t, err)
	front.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	frontAddr := startQUICRedirected(t, front, echo)

	for _, msg := range []string{"ping", "pong"} {
		pc, err := loopbackUDP()
		require.NoError(t, err)
		defer func() { _ = pc.Close() }()
		_, err = pc.WriteTo([]byte(msg), net.UDPAddrFromAddrPort(frontAddr))
		require.NoError(t, err)
		require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))
		buf := make([]byte, 64)
		n, _, err := pc.ReadFrom(buf)
		require.NoError(t, err)
		assert.Equal(t, msg, string(buf[:n]))
	}

	var tunnels, flows int
	for _, s := range waitForSessions(t, back, 4) {
		if s.Via() == nil {
			tunnels++
		} else {
			flows++
		}
	}
	assert.Equal(t, 2, tunnels, "one tunnel per flow")
	assert.Equal(t, 2, flows, "one flow inside each tunnel")
	front.srv.fwd.up.mu.Lock()
	assert.Len(t, front.srv.fwd.up.conns, 1, "one HTTP/3 connection to the proxy")
	front.srv.fwd.up.mu.Unlock()
}

// A QUIC connection a handler dials runs inside a CONNECT-UDP tunnel to the proxy, which
// terminates it in turn.
func TestChain_QUICConnectionThroughCONNECTUDP(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)
	ca, err := GenerateCA()
	require.NoError(t, err)

	backTr := DefaultTransport()
	backTr.RootCAs = poolOf(originCA)
	back, err := New(WithCA(ca), WithTransport(backTr))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	back.MustAdd[QUIC](h3Authority, relayQUIC)
	backFront, _ := startQUICFront(t, back, ca)

	frontTr := DefaultTransport()
	frontTr.RootCAs = poolOf(ca)
	frontTr.Proxy = fixedProxy("https://" + backFront.String())
	front, err := New(WithCA(ca), WithTransport(frontTr))
	require.NoError(t, err)
	front.MustAdd[QUIC](h3Authority, relayQUIC)
	frontAddr := startQUICRedirected(t, front, origin)

	tr := dialQUICTo(frontAddr, poolOf(ca))
	defer func() { _ = tr.Close() }()
	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/echo", h3Authority, frontAddr.Port()), nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Contains(t, string(body), "path=/echo")

	var tunnel, inner *Session
	for _, s := range waitForSessions(t, back, 2) {
		if s.Via() == nil {
			tunnel = s
		} else {
			inner = s
		}
	}
	require.NotNil(t, tunnel)
	require.NotNil(t, inner)
	assert.Equal(t, origin, tunnel.Upstream())
	assert.Equal(t, KindQUIC, inner.Kind())
	assert.Equal(t, h3Authority, inner.Target().Host)
	assert.Same(t, tunnel, inner.Via())
}

// An HTTP/3 upstream runs inside a CONNECT-UDP tunnel to the proxy.
func TestChain_H3UpstreamThroughCONNECTUDP(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)
	ca, err := GenerateCA()
	require.NoError(t, err)

	backTr := DefaultTransport()
	backTr.RootCAs = poolOf(originCA)
	back, err := New(WithCA(ca), WithTransport(backTr))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	back.MustAdd[QUIC](h3Authority, relayQUIC)
	backFront, _ := startQUICFront(t, back, ca)

	frontTr := DefaultTransport()
	frontTr.AllowHTTP3 = true
	frontTr.RootCAs = poolOf(ca)
	frontTr.Proxy = fixedProxy("https://" + backFront.String())
	front, err := New(WithCA(ca), WithTransport(frontTr))
	require.NoError(t, err)
	seen := new(recorder)
	front.MustAdd(h3Authority+"/+{any}", func(c *HTTPCtx) (*http.Response, error) {
		seen.add(c.Protocol().String())
		return c.Forward()
	})
	frontAddr := startQUICRedirected(t, front, origin)

	tr := dialQUICTo(frontAddr, poolOf(ca))
	defer func() { _ = tr.Close() }()
	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/echo", h3Authority, frontAddr.Port()), nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Contains(t, string(body), "path=/echo")
	assert.Contains(t, string(body), "proto=HTTP/3.0", "the origin was reached over HTTP/3")
	assert.Equal(t, []string{"HTTP/3.0"}, seen.all())
	waitForSessions(t, back, 2)
}

// What the selected proxy cannot serve fails the dial, and nothing goes around it.
func TestChain_RefusesWhatTheProxyCannotCarry(t *testing.T) {
	tr := DefaultTransport()
	tr.Proxy = fixedProxy("socks5://127.0.0.1:1")
	_, err := newUpstreamDialer(tr).dial(t.Context(), "tcp", "127.0.0.1:443", "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

// fakeProxy answers every connection with the bytes reply writes, and keeps the connection
// open.
func fakeProxy(t *testing.T, reply func(w io.Writer)) string {
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
				br := bufio.NewReader(conn)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				reply(conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// A refused CONNECT fails the dial with the status the proxy answered, without waiting for a
// body the proxy never finishes.
func TestChain_RefusedCONNECTReportsTheStatus(t *testing.T) {
	proxy := fakeProxy(t, func(w io.Writer) {
		_, _ = io.WriteString(w, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 100\r\n\r\nhello")
		time.Sleep(10 * time.Second)
	})
	tr := DefaultTransport()
	tr.Proxy = fixedProxy("http://" + proxy)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err := newUpstreamDialer(tr).dial(ctx, "tcp", "example.test:443", "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "407")
	assert.Less(t, time.Since(start), time.Second)
}

// The response to a CONNECT is read up to a bound, so a proxy that never ends its headers
// fails the dial instead of growing them without limit.
func TestChain_CONNECTResponseIsBounded(t *testing.T) {
	proxy := fakeProxy(t, func(w io.Writer) {
		_, _ = io.WriteString(w, "HTTP/1.1 200 OK\r\n")
		line := []byte("X-Pad: " + strings.Repeat("x", 4096) + "\r\n")
		for {
			if _, err := w.Write(line); err != nil {
				return
			}
		}
	})
	tr := DefaultTransport()
	tr.Proxy = fixedProxy("http://" + proxy)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := newUpstreamDialer(tr).dial(ctx, "tcp", "example.test:443", "https")
	require.Error(t, err)
	assert.NotErrorIs(t, err, context.DeadlineExceeded)
	assert.Contains(t, err.Error(), "read CONNECT response")
}

// silencedPacketConn drops everything once silent, as a proxy that went away does.
type silencedPacketConn struct {
	net.PacketConn
	silent atomic.Bool
}

func (c *silencedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil || !c.silent.Load() {
			return n, addr, err
		}
	}
}

func (c *silencedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.silent.Load() {
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, addr)
}

// A flow ends when the connection to its proxy dies in silence, so a client is not left with a
// dead tunnel until the flow idles out.
func TestChain_DeadProxyEndsTheFlow(t *testing.T) {
	echo := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)

	back, err := New(WithCA(ca))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	backPC := &silencedPacketConn{PacketConn: raw}
	go func() { _ = back.ServeQUIC(backPC, *cert) }()
	t.Cleanup(func() { _ = back.Close() })

	frontTr := DefaultTransport()
	frontTr.RootCAs = poolOf(ca)
	frontTr.IdleConnTimeout = time.Second
	frontTr.Proxy = fixedProxy("https://" + backPC.LocalAddr().String())
	front, err := New(WithCA(ca), WithTransport(frontTr))
	require.NoError(t, err)
	front.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	frontAddr := startQUICRedirected(t, front, echo)

	pc, err := loopbackUDP()
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()
	_, err = pc.WriteTo([]byte("ping"), net.UDPAddrFromAddrPort(frontAddr))
	require.NoError(t, err)
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 64)
	n, _, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf[:n]))
	waitForSessions(t, front, 1)

	// The proxy falls silent without a CONNECTION_CLOSE, so the connection to it times out.
	backPC.silent.Store(true)
	assert.Eventually(t, func() bool { return len(slices.Collect(front.Sessions())) == 0 },
		10*time.Second, 50*time.Millisecond, "the flow outlived its tunnel")
}

// An HTTP request with a declared destination, a CONNECT target, reaches it with a CONNECT to
// the proxy Transport.Proxy selects.
func TestChain_HTTPWithDeclaredDestinationThroughCONNECT(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := namedOrigin(t, ca, "inner.test")
	_, port, err := net.SplitHostPort(origin.Host)
	require.NoError(t, err)

	backTr := DefaultTransport()
	backTr.RootCAs = poolOf(ca)
	backTr.DialContext = pinnedDialer(origin.Host)
	back, err := New(WithCA(ca), WithTransport(backTr))
	require.NoError(t, err)
	back.MustAdd("inner.test/", forwardHandler)
	backAddr := startProxy(t, back)

	frontTr := DefaultTransport()
	frontTr.RootCAs = poolOf(ca)
	dialed := new(recorder)
	frontTr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed.add(network + " " + addr)
		return defaultDialer.DialContext(ctx, network, addr)
	}
	frontTr.Proxy = fixedProxy("http://" + backAddr)
	front, err := New(WithCA(ca), WithTransport(frontTr))
	require.NoError(t, err)
	front.MustAdd("inner.test/", forwardHandler)
	frontAddr := startProxy(t, front)

	client := tunnelClient(t, frontAddr, "inner.test:"+port, "inner.test", ca)
	resp, err := client.Get("https://inner.test/")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "origin host=inner.test", string(body))
	assert.Equal(t, []string{"tcp " + backAddr}, dialed.all())
}

// countingDialer counts the connections the front opens, by network.
type countingDialer struct {
	udp, tcp atomic.Int32
}

func (d *countingDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "udp":
		d.udp.Add(1)
	case "tcp":
		d.tcp.Add(1)
	}
	return defaultDialer.DialContext(ctx, network, addr)
}

// chainedFront builds a front proxy chained through the proxy at back, admitting UDP to the
// loopback, with HTTP/3 to the proxy bounded short enough for the fallback to be quick.
func chainedFront(t *testing.T, ca *CA, back string) (*Proxy, *countingDialer) {
	t.Helper()
	dialer := new(countingDialer)
	frontTr := DefaultTransport()
	frontTr.DialContext = dialer.dial
	frontTr.RootCAs = poolOf(ca)
	frontTr.TLSHandshakeTimeout = 300 * time.Millisecond
	frontTr.Proxy = fixedProxy(back)
	front, err := New(WithCA(ca), WithTransport(frontTr))
	require.NoError(t, err)
	front.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	return front, dialer
}

func echoThrough(t *testing.T, frontAddr netip.AddrPort, msgs ...string) {
	t.Helper()
	for _, msg := range msgs {
		pc, err := loopbackUDP()
		require.NoError(t, err)
		defer func() { _ = pc.Close() }()
		_, err = pc.WriteTo([]byte(msg), net.UDPAddrFromAddrPort(frontAddr))
		require.NoError(t, err)
		require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))
		buf := make([]byte, 64)
		n, _, err := pc.ReadFrom(buf)
		require.NoError(t, err)
		assert.Equal(t, msg, string(buf[:n]))
	}
}

// A proxy that cannot be reached over HTTP/3 is reached over TCP, the tunnel a GET the proxy
// upgrades, and the failure is remembered so the next tunnel does not try HTTP/3 again.
func TestChain_DatagramFlowThroughCONNECTUDPUpgrade(t *testing.T) {
	echo := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	back, err := New(WithCA(ca))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	backFront := startTLSFront(t, back, ca, "http/1.1")

	front, dialer := chainedFront(t, ca, "https://"+backFront.String())
	frontAddr := startQUICRedirected(t, front, echo)
	echoThrough(t, frontAddr, "ping", "pong")

	var tunnels, flows int
	for _, s := range waitForSessions(t, back, 4) {
		if s.Tunnel() {
			tunnels++
			assert.Equal(t, HTTP11, s.Protocol())
		} else {
			flows++
		}
	}
	assert.Equal(t, 2, tunnels, "one tunnel per flow")
	assert.Equal(t, 2, flows, "one flow inside each tunnel")
	assert.EqualValues(t, 1, dialer.udp.Load(), "HTTP/3 was tried once, then remembered as unreachable")
	assert.EqualValues(t, 2, dialer.tcp.Load(), "one connection per tunnel")
	assert.True(t, front.srv.fwd.up.deferred(front.srv.fwd.up.noH3, &url.URL{Scheme: "https", Host: backFront.String()}))
}

// A plain http proxy carries CONNECT-UDP the way it carries CONNECT, in the clear, and HTTP/3
// is never tried on it.
func TestChain_PlainProxyCarriesCONNECTUDP(t *testing.T) {
	echo := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	back, err := New(WithCA(ca))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	backFront := startProxy(t, back)

	front, dialer := chainedFront(t, ca, "http://"+backFront)
	frontAddr := startQUICRedirected(t, front, echo)
	echoThrough(t, frontAddr, "ping")
	waitForSessions(t, back, 2)
	assert.Zero(t, dialer.udp.Load())
	assert.EqualValues(t, 1, dialer.tcp.Load())
}

// An HTTP/3 upstream runs inside a tunnel over TCP.
func TestChain_H3UpstreamThroughCONNECTUDPUpgrade(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)
	ca, err := GenerateCA()
	require.NoError(t, err)

	backTr := DefaultTransport()
	backTr.RootCAs = poolOf(originCA)
	back, err := New(WithCA(ca), WithTransport(backTr))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	back.MustAdd[QUIC](h3Authority, relayQUIC)
	backFront := startTLSFront(t, back, ca, "http/1.1")

	front, _ := chainedFront(t, ca, "https://"+backFront.String())
	front.srv.fwd.up.t.AllowHTTP3 = true
	seen := new(recorder)
	front.MustAdd(h3Authority+"/+{any}", func(c *HTTPCtx) (*http.Response, error) {
		seen.add(c.Protocol().String())
		return c.Forward()
	})
	frontAddr := startQUICRedirected(t, front, origin)

	tr := dialQUICTo(frontAddr, poolOf(ca))
	defer func() { _ = tr.Close() }()
	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/echo", h3Authority, frontAddr.Port()), nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Contains(t, string(body), "path=/echo")
	assert.Contains(t, string(body), "proto=HTTP/3.0", "the origin was reached over HTTP/3")
	assert.Equal(t, []string{"HTTP/3.0"}, seen.all())
	for _, s := range waitForSessions(t, back, 2) {
		if s.Tunnel() {
			assert.Equal(t, HTTP11, s.Protocol())
		}
	}
}

// A refusal the proxy answers on a connection that exists is final, the dial fails with the
// status and nothing is tried another way.
func TestChain_RefusedCONNECTUDPIsFinal(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	back, err := New(WithCA(ca))
	require.NoError(t, err)
	backFront := startTLSFront(t, back, ca, "http/1.1")

	front, dialer := chainedFront(t, ca, "https://"+backFront.String())
	_, err = front.srv.fwd.up.dial(t.Context(), "udp", "127.0.0.1:53", "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CONNECT-UDP refused with 403")
	assert.EqualValues(t, 1, dialer.tcp.Load())
	_, err = front.srv.fwd.up.dial(t.Context(), "udp", "127.0.0.1:53", "https")
	require.Error(t, err)
	assert.EqualValues(t, 1, dialer.udp.Load(), "HTTP/3 is not tried again while the failure is remembered")
	assert.EqualValues(t, 2, dialer.tcp.Load())
}

// A proxy that goes away ends the flows tunnelled over TCP through it.
func TestChain_DeadProxyEndsTheFlowOverTCP(t *testing.T) {
	echo := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	back, err := New(WithCA(ca))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	backFront := startTLSFront(t, back, ca, "http/1.1")

	front, _ := chainedFront(t, ca, "https://"+backFront.String())
	frontAddr := startQUICRedirected(t, front, echo)
	echoThrough(t, frontAddr, "ping")
	waitForSessions(t, front, 1)

	require.NoError(t, back.Close())
	assert.Eventually(t, func() bool { return len(slices.Collect(front.Sessions())) == 0 },
		10*time.Second, 50*time.Millisecond, "the flow outlived its tunnel")
}

// A proxy whose HTTP/2 lacks extended CONNECT, which Go's server does unless it runs with
// GODEBUG=http2xconnect=1, is reached over HTTP/1.1 on another connection, and remembered.
func TestChain_H2ProxyWithoutExtendedConnectUpgradesOverHTTP11(t *testing.T) {
	if extendedConnectEnabled() {
		t.Skip("Go's server accepts extended CONNECT under GODEBUG=http2xconnect=1")
	}
	echo := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	back, err := New(WithCA(ca))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	backFront := startTLSFront(t, back, ca, "h2", "http/1.1")

	front, dialer := chainedFront(t, ca, "https://"+backFront.String())
	frontAddr := startQUICRedirected(t, front, echo)
	echoThrough(t, frontAddr, "ping", "pong")
	for _, s := range waitForSessions(t, back, 4) {
		if s.Tunnel() {
			assert.Equal(t, HTTP11, s.Protocol())
		}
	}
	assert.EqualValues(t, 3, dialer.tcp.Load(), "HTTP/2 tried once, then one HTTP/1.1 connection per tunnel")
	up := front.srv.fwd.up
	assert.True(t, up.deferred(up.noH2, &url.URL{Scheme: "https", Host: backFront.String()}))
	assert.Empty(t, up.h2conns, "the useless HTTP/2 connection is dropped")
}

// Tunnels share one HTTP/2 connection to a proxy that speaks extended CONNECT, an edge front
// running with GODEBUG=http2xconnect=1.
func TestChain_DatagramFlowThroughCONNECTUDPOverHTTP2(t *testing.T) {
	if !extendedConnectEnabled() {
		t.Skip("run with GODEBUG=http2xconnect=1, Go's HTTP/2 server refuses extended CONNECT without it")
	}
	echo := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	back, err := New(WithCA(ca))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	backFront := startTLSFront(t, back, ca, "h2", "http/1.1")

	front, dialer := chainedFront(t, ca, "https://"+backFront.String())
	frontAddr := startQUICRedirected(t, front, echo)
	echoThrough(t, frontAddr, "ping", "pong")
	var tunnels int
	for _, s := range waitForSessions(t, back, 4) {
		if s.Tunnel() {
			tunnels++
			assert.Equal(t, HTTP2, s.Protocol())
		}
	}
	assert.Equal(t, 2, tunnels)
	assert.EqualValues(t, 1, dialer.tcp.Load(), "one HTTP/2 connection for every tunnel")
	assert.Len(t, front.srv.fwd.up.h2conns, 1)

	// A refusal on the shared connection is final and leaves it in place.
	_, err = front.srv.fwd.up.dial(t.Context(), "udp", "127.0.0.2:53", "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CONNECT-UDP refused with 403")
	assert.EqualValues(t, 1, dialer.tcp.Load())
}

// An HTTP/3 upstream runs inside a tunnel on the HTTP/2 connection to the proxy.
func TestChain_H3UpstreamThroughCONNECTUDPOverHTTP2(t *testing.T) {
	if !extendedConnectEnabled() {
		t.Skip("run with GODEBUG=http2xconnect=1, Go's HTTP/2 server refuses extended CONNECT without it")
	}
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)
	ca, err := GenerateCA()
	require.NoError(t, err)

	backTr := DefaultTransport()
	backTr.RootCAs = poolOf(originCA)
	back, err := New(WithCA(ca), WithTransport(backTr))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	back.MustAdd[QUIC](h3Authority, relayQUIC)
	backFront := startTLSFront(t, back, ca, "h2", "http/1.1")

	front, _ := chainedFront(t, ca, "https://"+backFront.String())
	front.srv.fwd.up.t.AllowHTTP3 = true
	front.MustAdd(h3Authority+"/+{any}", forwardHandler)
	frontAddr := startQUICRedirected(t, front, origin)

	tr := dialQUICTo(frontAddr, poolOf(ca))
	defer func() { _ = tr.Close() }()
	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/echo", h3Authority, frontAddr.Port()), nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Contains(t, string(body), "proto=HTTP/3.0", "the origin was reached over HTTP/3")
	for _, s := range waitForSessions(t, back, 2) {
		if s.Tunnel() {
			assert.Equal(t, HTTP2, s.Protocol())
		}
	}
}

// A tunnel refused on the HTTP/2 connection the dial just opened leaves that connection
// shared for the next tunnel.
func TestChain_RefusedCONNECTUDPLeavesTheHTTP2ConnectionShared(t *testing.T) {
	if !extendedConnectEnabled() {
		t.Skip("run with GODEBUG=http2xconnect=1, Go's HTTP/2 server refuses extended CONNECT without it")
	}
	ca, err := GenerateCA()
	require.NoError(t, err)
	back, err := New(WithCA(ca))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	backFront := startTLSFront(t, back, ca, "h2", "http/1.1")

	front, dialer := chainedFront(t, ca, "https://"+backFront.String())
	up := front.srv.fwd.up
	_, err = up.dial(t.Context(), "udp", "127.0.0.2:53", "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CONNECT-UDP refused with 403")
	conn, err := up.dial(t.Context(), "udp", "127.0.0.1:53", "https")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	assert.EqualValues(t, 1, dialer.tcp.Load(), "the refusal did not cost the connection")
}

// h2Peer is the server end of an HTTP/2 connection to a fake proxy, answering every CONNECT
// with 200 and going away when told.
func h2Peer(t *testing.T, nc net.Conn) chan<- uint32 {
	t.Helper()
	goAway := make(chan uint32, 1)
	go func() {
		fr := http2.NewFramer(nc, nc)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		var mu sync.Mutex
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(nc, preface); err != nil {
			return
		}
		if err := fr.WriteSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1}); err != nil {
			return
		}
		go func() {
			last, ok := <-goAway
			if !ok {
				return
			}
			mu.Lock()
			_ = fr.WriteGoAway(last, http2.ErrCodeNo, nil)
			mu.Unlock()
		}()
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				mu.Lock()
				buf.Reset()
				_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: mh.StreamID, BlockFragment: buf.Bytes(), EndHeaders: true})
				mu.Unlock()
			}
		}
	}()
	return goAway
}

// An HTTP/2 connection to a proxy replaced after a GOAWAY, with a tunnel still on it, ends
// with the dialer like the one that replaced it.
func TestChain_ReplacedHTTP2ConnectionEndsWithTheDialer(t *testing.T) {
	u := newUpstreamDialer(&Transport{})
	proxy, err := url.Parse("https://proxy.test:443")
	require.NoError(t, err)

	cli1, srv1 := tcpPair(t)
	goAway := h2Peer(t, srv1)
	cc1, err := u.shareH2Conn(proxy, cli1)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, _, err := cc1.Open(ctx, h2tunnel.Request{Authority: "proxy.test:443"})
	require.NoError(t, err)
	goAway <- 1
	require.Eventually(t, func() bool { return !cc1.CanOpen() }, 5*time.Second, 10*time.Millisecond)

	cli2, srv2 := tcpPair(t)
	h2Peer(t, srv2)
	cc2, err := u.shareH2Conn(proxy, cli2)
	require.NoError(t, err)
	require.NotSame(t, cc1, cc2, "a connection going away is not reused")
	require.NoError(t, cc1.Err(), "a connection with a tunnel on it stays until the tunnel ends")

	u.close()
	for i, srv := range []net.Conn{srv1, srv2} {
		// The GOAWAY the close sends arrives ahead of the end, and a socket closed with the
		// peer's bytes still unread ends in a reset rather than an EOF.
		require.NoError(t, srv.SetReadDeadline(time.Now().Add(2*time.Second)))
		for {
			_, err = srv.Read(make([]byte, 64))
			if err != nil {
				break
			}
		}
		require.Error(t, err)
		require.False(t, isTimeout(err), "connection %d outlived the dialer", i+1)
	}
	_, err = str.Read(make([]byte, 1))
	require.Error(t, err)
}

// h2Proxies dials fake HTTP/2 proxies over TLS, one connection per dial, each answering
// every CONNECT with 200, closing the socket instead on the CONNECT number closeOn when it
// is not zero.
type h2Proxies struct {
	t        *testing.T
	ca       *CA
	settings []http2.Setting
	closeOn  int
	dials    atomic.Int32
	ended    chan struct{}
}

func (p *h2Proxies) dial(_ context.Context, network, _ string) (net.Conn, error) {
	p.dials.Add(1)
	cli, srv := tcpPair(p.t)
	cert, err := p.ca.Leaf("127.0.0.1")
	if err != nil {
		return nil, err
	}
	first := p.dials.Load() == 1
	go func() {
		tc := tls.Server(srv, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
		if err := tc.Handshake(); err != nil {
			return
		}
		fr := http2.NewFramer(tc, tc)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(tc, preface); err != nil {
			return
		}
		settings := append([]http2.Setting{{ID: http2.SettingEnableConnectProtocol, Val: 1}}, p.settings...)
		if err := fr.WriteSettings(settings...); err != nil {
			return
		}
		headers := 0
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				if first && p.ended != nil {
					close(p.ended)
				}
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				headers++
				if first && headers == p.closeOn {
					_ = tc.Close()
					return
				}
				buf.Reset()
				_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: mh.StreamID, BlockFragment: buf.Bytes(), EndHeaders: true})
			}
		}
	}()
	_ = network
	return cli, nil
}

func (p *h2Proxies) dialer(t *testing.T) *upstreamDialer {
	t.Helper()
	tr := DefaultTransport()
	tr.DialContext = p.dial
	tr.RootCAs = poolOf(p.ca)
	u := newUpstreamDialer(tr)
	t.Cleanup(u.close)
	return u
}

// A tunnel opened on a pooled HTTP/2 connection the proxy dropped meanwhile is opened again
// on a fresh one, the proxy having seen nothing of it.
func TestChain_StaleH2ConnectionIsRetried(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	proxies := &h2Proxies{t: t, ca: ca, closeOn: 2}
	u := proxies.dialer(t)
	proxy, err := url.Parse("https://127.0.0.1:443")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := u.connectUDPStream(ctx, proxy, "192.0.2.1", "53")
	require.NoError(t, err)
	defer func() { _ = first.close() }()
	second, err := u.connectUDPStream(ctx, proxy, "192.0.2.1", "53")
	require.NoError(t, err, "the dial failed instead of opening a fresh connection")
	defer func() { _ = second.close() }()
	assert.EqualValues(t, 2, proxies.dials.Load())
}

// A pooled HTTP/2 connection at the proxy's stream limit is left to its tunnels and a fresh
// one opened, and it ends once those tunnels end.
func TestChain_FullH2ConnectionOpensAnother(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	proxies := &h2Proxies{t: t, ca: ca, ended: make(chan struct{}),
		settings: []http2.Setting{{ID: http2.SettingMaxConcurrentStreams, Val: 1}}}
	u := proxies.dialer(t)
	proxy, err := url.Parse("https://127.0.0.1:443")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := u.connectUDPStream(ctx, proxy, "192.0.2.1", "53")
	require.NoError(t, err)
	second, err := u.connectUDPStream(ctx, proxy, "192.0.2.1", "53")
	require.NoError(t, err, "the dial failed instead of opening a fresh connection")
	defer func() { _ = second.close() }()
	assert.EqualValues(t, 2, proxies.dials.Load())

	require.NoError(t, first.close())
	select {
	case <-proxies.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the full connection outlived its last tunnel")
	}
}

// An HTTP/2 request with no declared destination, sent to a TLS front without a CONNECT, is
// forwarded through an https proxy that offers h2. net/http would offer the proxy the h2 pool's
// ALPN list and write its CONNECT on the HTTP/2 connection the proxy selected.
func TestChain_H2RequestWithNoDeclaredDestinationThroughTLSProxy(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := namedOrigin(t, ca, "inner.test")
	_, port, err := net.SplitHostPort(origin.Host)
	require.NoError(t, err)

	backTr := DefaultTransport()
	backTr.RootCAs = poolOf(ca)
	backTr.DialContext = pinnedDialer(origin.Host)
	back, err := New(WithCA(ca), WithTransport(backTr))
	require.NoError(t, err)
	back.MustAdd("inner.test/", forwardHandler)
	backAddr, _ := startProxyTLS(t, back, ca)

	frontTr := DefaultTransport()
	frontTr.RootCAs = poolOf(ca)
	dialed := new(recorder)
	frontTr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed.add(network + " " + addr)
		return defaultDialer.DialContext(ctx, network, addr)
	}
	frontTr.Proxy = fixedProxy("https://" + backAddr)
	front, err := New(WithCA(ca), WithTransport(frontTr))
	require.NoError(t, err)
	front.MustAdd("inner.test/", forwardHandler)
	frontAddr, frontPool := startProxyTLS(t, front, ca)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&tls.Dialer{Config: &tls.Config{
					ServerName: "127.0.0.1",
					RootCAs:    frontPool,
					NextProtos: []string{"h2", "http/1.1"},
					MinVersion: tls.VersionTLS12,
				}}).DialContext(ctx, "tcp", frontAddr)
			},
		},
	}
	resp, err := client.Get("https://inner.test:" + port + "/")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.Equal(t, "HTTP/2.0", resp.Proto, "the client must have reached the front over HTTP/2")
	assert.Equal(t, "origin host=inner.test:"+port, string(body))
	assert.Equal(t, []string{"tcp " + backAddr}, dialed.all())
}
