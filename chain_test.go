// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/fox-toolkit/edge/internal/h2tunnel"
	"github.com/quic-go/quic-go/http3"
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

func TestChain_RefusesWhatTheProxyCannotCarry(t *testing.T) {
	tr := DefaultTransport()
	tr.Proxy = fixedProxy("ftp://127.0.0.1:1")
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
	refusedTCP, refusedUDP string
	udp, tcp               atomic.Int32
}

func (d *countingDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	refused := ""
	switch network {
	case "udp":
		d.udp.Add(1)
		refused = d.refusedUDP
	case "tcp":
		d.tcp.Add(1)
		refused = d.refusedTCP
	}
	if addr == refused {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	return defaultDialer.DialContext(ctx, network, addr)
}

// backListens is what the proxy a chained front goes through listens on.
type backListens uint8

const (
	onBoth backListens = iota
	onQUIC
	onTCP
)

// chainedFront builds a front proxy chained through the proxy at back, admitting UDP to the
// loopback, with HTTP/3 to the proxy bounded short enough for the fallback to be quick. A dial
// to back over the transport it does not listen on is counted and refused, since another test
// may listen on the port of the same number.
func chainedFront(t *testing.T, ca *CA, back string, listens backListens) (*Proxy, *countingDialer) {
	t.Helper()
	dialer := new(countingDialer)
	if listens != onBoth {
		u, err := url.Parse(back)
		require.NoError(t, err)
		if listens == onQUIC {
			dialer.refusedTCP = u.Host
		} else {
			dialer.refusedUDP = u.Host
		}
	}
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

func TestChain_DatagramFlowThroughCONNECTUDPUpgrade(t *testing.T) {
	echo := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	back, err := New(WithCA(ca))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	backFront := startTLSFront(t, back, ca, "http/1.1")

	front, dialer := chainedFront(t, ca, "https://"+backFront.String(), onBoth)
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
	assert.EqualValues(t, 1, dialer.udp.Load(), "HTTP/3 was tried once, then the failed dial remembered")
	assert.EqualValues(t, 2, dialer.tcp.Load(), "one connection per tunnel")
	assert.True(t, front.srv.fwd.up.remembers(noH3Dial, &url.URL{Scheme: "https", Host: backFront.String()}))
}

func TestChain_PlainProxyCarriesCONNECTUDP(t *testing.T) {
	echo := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	back, err := New(WithCA(ca))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	backFront := startProxy(t, back)

	front, dialer := chainedFront(t, ca, "http://"+backFront, onTCP)
	frontAddr := startQUICRedirected(t, front, echo)
	echoThrough(t, frontAddr, "ping")
	waitForSessions(t, back, 2)
	assert.Zero(t, dialer.udp.Load())
	assert.EqualValues(t, 1, dialer.tcp.Load())
}

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

	front, _ := chainedFront(t, ca, "https://"+backFront.String(), onTCP)
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

func TestChain_RefusedCONNECTUDPIsFinal(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	back, err := New(WithCA(ca))
	require.NoError(t, err)
	backFront := startTLSFront(t, back, ca, "http/1.1")

	front, dialer := chainedFront(t, ca, "https://"+backFront.String(), onBoth)
	_, err = front.srv.fwd.up.dial(t.Context(), "udp", "127.0.0.1:53", "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CONNECT-UDP refused with 403")
	assert.EqualValues(t, 1, dialer.tcp.Load())
	_, err = front.srv.fwd.up.dial(t.Context(), "udp", "127.0.0.1:53", "https")
	require.Error(t, err)
	assert.EqualValues(t, 1, dialer.udp.Load(), "HTTP/3 is not tried again while the failure is remembered")
	assert.EqualValues(t, 2, dialer.tcp.Load())
}

func TestChain_DeadProxyEndsTheFlowOverTCP(t *testing.T) {
	echo := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	back, err := New(WithCA(ca))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	backFront := startTLSFront(t, back, ca, "http/1.1")

	front, _ := chainedFront(t, ca, "https://"+backFront.String(), onTCP)
	frontAddr := startQUICRedirected(t, front, echo)
	echoThrough(t, frontAddr, "ping")
	waitForSessions(t, front, 1)

	require.NoError(t, back.Close())
	assert.Eventually(t, func() bool { return len(slices.Collect(front.Sessions())) == 0 },
		10*time.Second, 50*time.Millisecond, "the flow outlived its tunnel")
}

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
	back.MustAdd[TCP]("127.0.0.1", relayStream)
	backFront := startTLSFront(t, back, ca, "h2", "http/1.1")

	front, dialer := chainedFront(t, ca, "https://"+backFront.String(), onTCP)
	frontAddr := startQUICRedirected(t, front, echo)
	echoThrough(t, frontAddr, "ping", "pong")
	for _, s := range waitForSessions(t, back, 4) {
		if s.Tunnel() {
			assert.Equal(t, HTTP11, s.Protocol())
		}
	}
	assert.EqualValues(t, 3, dialer.tcp.Load(), "HTTP/2 tried once, then one HTTP/1.1 connection per tunnel")
	up := front.srv.fwd.up
	assert.True(t, up.remembers(noH2Extended, &url.URL{Scheme: "https", Host: backFront.String()}))

	conn, err := up.dial(t.Context(), "tcp", "127.0.0.1:443", "https")
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	assert.EqualValues(t, 3, dialer.tcp.Load(), "the CONNECT went on the HTTP/2 connection")
}

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

	front, dialer := chainedFront(t, ca, "https://"+backFront.String(), onTCP)
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

	front, _ := chainedFront(t, ca, "https://"+backFront.String(), onTCP)
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

	front, dialer := chainedFront(t, ca, "https://"+backFront.String(), onTCP)
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

func TestChain_ReplacedHTTP2ConnectionEndsWithTheDialer(t *testing.T) {
	u := newUpstreamDialer(&Transport{})
	proxy, err := url.Parse("https://proxy.test:443")
	require.NoError(t, err)

	cli1, srv1 := tcpPair(t)
	goAway := h2Peer(t, srv1)
	cc1, _, err := u.shareH2Conn(proxy, cli1)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, _, err := cc1.Open(ctx, h2tunnel.Request{Authority: "proxy.test:443"})
	require.NoError(t, err)
	goAway <- 1
	require.Eventually(t, func() bool { return !cc1.CanOpen() }, 5*time.Second, 10*time.Millisecond)

	cli2, srv2 := tcpPair(t)
	h2Peer(t, srv2)
	cc2, _, err := u.shareH2Conn(proxy, cli2)
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

func streamingBack(t *testing.T, ca *CA, origin string) *Proxy {
	t.Helper()
	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network == "tcp" {
			addr = origin
		}
		return defaultDialer.DialContext(ctx, network, addr)
	}
	back, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	back.MustAdd[TCP]("inner.test", relayStream)
	return back
}

func getThroughTunnel(t *testing.T, addr, port string, ca *CA) {
	t.Helper()
	client := tunnelClient(t, addr, "inner.test:"+port, "inner.test", ca)
	resp, err := client.Get("https://inner.test/")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "origin host=inner.test", string(body))
}

func TestChain_TCPStreamThroughCONNECTOverHTTP2(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := namedOrigin(t, ca, "inner.test")
	_, port, err := net.SplitHostPort(origin.Host)
	require.NoError(t, err)
	back := streamingBack(t, ca, origin.Host)
	backFront := startTLSFront(t, back, ca, "h2")

	front, dialer := chainedFront(t, ca, "https://"+backFront.String(), onTCP)
	front.MustAdd[TCP]("inner.test", relayStream)
	frontAddr := startProxy(t, front)

	getThroughTunnel(t, frontAddr, port, ca)
	getThroughTunnel(t, frontAddr, port, ca)
	assert.EqualValues(t, 1, dialer.tcp.Load(), "the tunnels share one connection to the proxy")
	assert.Zero(t, dialer.udp.Load())
	waitForSessions(t, back, 2)
}

func TestChain_TCPStreamThroughCONNECTOverHTTP3(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := namedOrigin(t, ca, "inner.test")
	_, port, err := net.SplitHostPort(origin.Host)
	require.NoError(t, err)
	back := streamingBack(t, ca, origin.Host)
	backFront, _ := startQUICFront(t, back, ca)

	front, dialer := chainedFront(t, ca, "https://"+backFront.String(), onQUIC)
	front.MustAdd[TCP]("inner.test", relayStream)
	frontAddr := startProxy(t, front)

	getThroughTunnel(t, frontAddr, port, ca)
	getThroughTunnel(t, frontAddr, port, ca)
	assert.EqualValues(t, 1, dialer.tcp.Load(), "TCP refused once")
	assert.EqualValues(t, 1, dialer.udp.Load(), "the tunnels share one HTTP/3 connection")
	waitForSessions(t, back, 2)
	proxy := &url.URL{Scheme: "https", Host: backFront.String()}
	up := front.srv.fwd.up
	assert.False(t, up.remembers(noTCPDial, proxy))

	require.NoError(t, up.h3Conn(proxy).CloseWithError(0, ""))
	getThroughTunnel(t, frontAddr, port, ca)
	assert.EqualValues(t, 2, dialer.tcp.Load(), "TCP tried again")
	assert.EqualValues(t, 2, dialer.udp.Load())
}

// listenBoth listens on one port over TCP and over UDP.
func listenBoth(t *testing.T) (net.Listener, net.PacketConn) {
	t.Helper()
	for range 10 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		if pc, perr := net.ListenPacket("udp", ln.Addr().String()); perr == nil {
			return ln, pc
		}
		_ = ln.Close()
	}
	t.Fatal("no port free on both tcp and udp")
	return nil, nil
}

// startDualFront serves p over TLS and over QUIC on one port.
func startDualFront(t *testing.T, p *Proxy, ca *CA) netip.AddrPort {
	t.Helper()
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	ln, pc := listenBoth(t)
	cfg := &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	go func() { _ = p.serveFront(tls.NewListener(cancelListener{ln}, cfg)) }()
	go func() { _ = p.ServeQUIC(pc, *cert) }()
	t.Cleanup(func() {
		_ = p.Close()
		_ = pc.Close()
	})
	return netip.MustParseAddrPort(ln.Addr().String())
}

func TestChain_TCPStreamJoinsTheHTTP3ConnectionAFlowOpened(t *testing.T) {
	echo := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := namedOrigin(t, ca, "inner.test")
	_, port, err := net.SplitHostPort(origin.Host)
	require.NoError(t, err)
	back := streamingBack(t, ca, origin.Host)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	backFront := startDualFront(t, back, ca)

	front, dialer := chainedFront(t, ca, "https://"+backFront.String(), onBoth)
	front.MustAdd[TCP]("inner.test", relayStream)
	frontAddr := startProxy(t, front)
	udpFront := startQUICRedirected(t, front, echo)

	getThroughTunnel(t, frontAddr, port, ca)
	assert.EqualValues(t, 1, dialer.tcp.Load())
	assert.Zero(t, dialer.udp.Load(), "nothing probed HTTP/3")

	echoThrough(t, udpFront, "ping")
	assert.EqualValues(t, 1, dialer.udp.Load())
	conn, err := front.srv.fwd.up.dial(t.Context(), "tcp", "inner.test:"+port, "https")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.IsType(t, (*h3StreamConn)(nil), conn, "the tunnel joined the HTTP/3 connection")
	assert.EqualValues(t, 1, dialer.tcp.Load())
}

func TestChain_HTTP3ConnectionGoingAwayIsLeft(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	proxyAddr, srv := h3ConnectEcho(t, ca)
	front, _ := chainedFront(t, ca, "https://"+proxyAddr.String(), onQUIC)
	up := front.srv.fwd.up
	proxy := &url.URL{Scheme: "https", Host: proxyAddr.String()}

	first, err := up.dial(t.Context(), "tcp", "192.0.2.1:443", "https")
	require.NoError(t, err)
	defer func() { _ = first.Close() }()
	require.IsType(t, (*h3StreamConn)(nil), first)

	// Shutdown sends GOAWAY and waits for the first tunnel, which outlives the test.
	go func() { _ = srv.Shutdown(context.Background()) }()
	require.Eventually(t, func() bool {
		if conn, derr := up.dial(t.Context(), "tcp", "192.0.2.1:443", "https"); derr == nil {
			_ = conn.Close()
		}
		return up.h3Conn(proxy) == nil
	}, 5*time.Second, 50*time.Millisecond, "the connection going away stayed in the cache")

	_, err = first.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(first, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf), "the tunnel on the connection going away lives on")
}

func TestChain_ProxyDownOnBothIsDialedOverTCPAlone(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	front, dialer := chainedFront(t, ca, "https://127.0.0.1:1", onBoth)
	up := front.srv.fwd.up

	_, err = up.dial(t.Context(), "tcp", "192.0.2.1:443", "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dial proxy")
	assert.Contains(t, err.Error(), "over HTTP/3")
	proxy := &url.URL{Scheme: "https", Host: "127.0.0.1:1"}
	assert.False(t, up.remembers(noTCPDial, proxy), "a refusal is not remembered")
	assert.True(t, up.remembers(noH3Dial, proxy))

	_, err = up.dial(t.Context(), "tcp", "192.0.2.1:443", "https")
	require.Error(t, err)
	assert.EqualValues(t, 2, dialer.tcp.Load())
	assert.EqualValues(t, 1, dialer.udp.Load(), "HTTP/3 is not dialed again")
}

// versionedProxy serves CONNECT over HTTP/1.1 alone and answers 405 over HTTP/2 and HTTP/3, on
// one port for TCP and UDP.
func versionedProxy(t *testing.T, ca *CA) netip.AddrPort {
	t.Helper()
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	ln, pc := listenBoth(t)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.ProtoMajor != 1 {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		conn, _, herr := http.NewResponseController(w).Hijack()
		if herr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if _, werr := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); werr != nil {
			return
		}
		_, _ = io.Copy(conn, conn)
	})
	tcp := &http.Server{Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12}}
	udp := &http3.Server{Handler: handler, EnableDatagrams: true, TLSConfig: &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS13}}
	go func() { _ = tcp.ServeTLS(ln, "", "") }()
	go func() { _ = udp.Serve(pc) }()
	t.Cleanup(func() {
		_ = tcp.Close()
		_ = udp.Close()
		_ = pc.Close()
	})
	return netip.MustParseAddrPort(ln.Addr().String())
}

func TestChain_CONNECTNotServedOverHTTP3AndHTTP2GoesOverHTTP11(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	proxyAddr := versionedProxy(t, ca)
	front, dialer := chainedFront(t, ca, "https://"+proxyAddr.String(), onBoth)
	up := front.srv.fwd.up
	proxy := &url.URL{Scheme: "https", Host: proxyAddr.String()}

	_, err = up.dial(t.Context(), "udp", "192.0.2.1:53", "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CONNECT-UDP refused with 405")
	require.NotNil(t, up.h3Conn(proxy), "the HTTP/3 connection stays")

	conn, err := up.dial(t.Context(), "tcp", "192.0.2.1:443", "https")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))
	assert.True(t, up.remembers(noH3Connect, proxy))
	assert.True(t, up.remembers(noH2Connect, proxy))
	assert.EqualValues(t, 2, dialer.tcp.Load(), "one HTTP/2 connection, then one HTTP/1.1 connection")
	assert.NotNil(t, up.h2Conn(proxy), "the HTTP/2 connection stays")

	second, err := up.dial(t.Context(), "tcp", "192.0.2.1:443", "https")
	require.NoError(t, err)
	defer func() { _ = second.Close() }()
	assert.EqualValues(t, 3, dialer.tcp.Load(), "HTTP/1.1 at once")
	assert.EqualValues(t, 1, dialer.udp.Load())
}

func TestChain_RefusedCONNECTLeavesTheHTTP2ConnectionShared(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := namedOrigin(t, ca, "inner.test")
	back := streamingBack(t, ca, origin.Host)
	backFront := startTLSFront(t, back, ca, "h2")

	front, dialer := chainedFront(t, ca, "https://"+backFront.String(), onTCP)
	up := front.srv.fwd.up
	_, err = up.dial(t.Context(), "tcp", "other.test:443", "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CONNECT refused with 403 Forbidden")
	conn, err := up.dial(t.Context(), "tcp", "inner.test:443", "https")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	assert.EqualValues(t, 1, dialer.tcp.Load(), "the refusal did not cost the connection")
}

func TestChain_StaleH2ConnectionIsRetriedForCONNECT(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	proxies := &h2Proxies{t: t, ca: ca, closeOn: 2}
	u := proxies.dialer(t)
	proxy, err := url.Parse("https://127.0.0.1:443")
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := u.connect(ctx, proxy, "192.0.2.1:443")
	require.NoError(t, err)
	defer func() { _ = first.Close() }()
	second, err := u.connect(ctx, proxy, "192.0.2.1:443")
	require.NoError(t, err, "the dial failed instead of opening a fresh connection")
	defer func() { _ = second.Close() }()
	assert.EqualValues(t, 2, proxies.dials.Load())
}

func TestChain_TunnelOverHTTP3IsAConnection(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		c, aerr := origin.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = c.Close() }()
		time.Sleep(200 * time.Millisecond)
		_, _ = io.WriteString(c, "banner")
		got, _ := io.ReadAll(c)
		_, _ = fmt.Fprintf(c, "got:%s", got)
	}()

	back, err := New(WithCA(ca))
	require.NoError(t, err)
	back.MustAdd[TCP]("127.0.0.1", relayStream)
	backFront, _ := startQUICFront(t, back, ca)
	front, dialer := chainedFront(t, ca, "https://"+backFront.String(), onQUIC)

	conn, err := front.srv.fwd.up.dial(t.Context(), "tcp", origin.Addr().String(), "http")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.IsType(t, (*h3StreamConn)(nil), conn)
	assert.EqualValues(t, 1, dialer.udp.Load())

	// A first byte no HTTP method starts with, which the proxy serves as a byte stream on the
	// spot.
	_, err = conn.Write([]byte("\x00hello"))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	_, err = conn.Read(make([]byte, 16))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.NoError(t, conn.SetReadDeadline(time.Time{}))
	banner := make([]byte, 6)
	_, err = io.ReadFull(conn, banner)
	require.NoError(t, err)
	assert.Equal(t, "banner", string(banner), "the bytes the cut read received")
	require.NoError(t, conn.(closeWriter).CloseWrite())
	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	assert.Equal(t, "got:\x00hello", string(got))
}

func TestChain_WriteDeadlineResetsTheStreamAlone(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	proxyAddr, _ := h3ConnectEcho(t, ca)
	front, _ := chainedFront(t, ca, "https://"+proxyAddr.String(), onQUIC)
	up := front.srv.fwd.up

	late, err := up.dial(t.Context(), "tcp", "192.0.2.1:443", "https")
	require.NoError(t, err)
	defer func() { _ = late.Close() }()
	other, err := up.dial(t.Context(), "tcp", "192.0.2.1:443", "https")
	require.NoError(t, err)
	defer func() { _ = other.Close() }()

	require.NoError(t, late.SetWriteDeadline(time.Now().Add(-time.Second)))
	_, err = late.Write([]byte("late"))
	require.Error(t, err)
	assert.True(t, isTimeout(err))
	require.NoError(t, late.SetWriteDeadline(time.Time{}))
	_, err = late.Write([]byte("again"))
	require.Error(t, err, "the stream is reset")
	assert.False(t, isTimeout(err))

	_, err = other.Write([]byte("pong"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(other, buf)
	require.NoError(t, err)
	assert.Equal(t, "pong", string(buf))
}

func h3ConnectEcho(t *testing.T, ca *CA) (netip.AddrPort, *http3.Server) {
	t.Helper()
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS13},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusOK)
			rc := http.NewResponseController(w)
			_ = rc.Flush()
			buf := make([]byte, 1024)
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
		}),
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = pc.Close()
	})
	return netip.MustParseAddrPort(pc.LocalAddr().String()), srv
}

func TestChain_H3ProxyWithoutCONNECTUDPCarriesCONNECT(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	proxyAddr, _ := h3ConnectEcho(t, ca)
	front, dialer := chainedFront(t, ca, "https://"+proxyAddr.String(), onQUIC)
	up := front.srv.fwd.up

	_, err = up.dial(t.Context(), "udp", "192.0.2.1:53", "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "the proxy does not support CONNECT-UDP")
	proxy := &url.URL{Scheme: "https", Host: proxyAddr.String()}
	assert.False(t, up.remembers(noH3Dial, proxy), "the dial over HTTP/3 succeeded")

	conn, err := up.dial(t.Context(), "tcp", "192.0.2.1:443", "https")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))
	assert.EqualValues(t, 1, dialer.udp.Load(), "the CONNECT went on the HTTP/3 connection")
}

func TestChain_ConcurrentCONNECTsShareOneHTTP3Dial(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	proxyAddr, _ := h3ConnectEcho(t, ca)
	front, dialer := chainedFront(t, ca, "https://"+proxyAddr.String(), onQUIC)
	up := front.srv.fwd.up

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() {
			conn, derr := up.dial(t.Context(), "tcp", "192.0.2.1:443", "https")
			if derr == nil {
				_ = conn.Close()
			}
			errs[i] = derr
		})
	}
	wg.Wait()
	for i, derr := range errs {
		require.NoError(t, derr, "dial %d", i)
	}
	assert.EqualValues(t, 1, dialer.udp.Load(), "one dial over HTTP/3 for all")
}

func TestChain_WaiterDialsWhenTheHTTP3DialWasCancelled(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	proxyAddr, _ := h3ConnectEcho(t, ca)
	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	tr.Proxy = fixedProxy("https://" + proxyAddr.String())
	var udpDials atomic.Int32
	gate := make(chan struct{})
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network == "tcp" && addr == proxyAddr.String() {
			return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
		}
		if network == "udp" && udpDials.Add(1) == 1 {
			select {
			case <-gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return defaultDialer.DialContext(ctx, network, addr)
	}
	u := newUpstreamDialer(tr)
	t.Cleanup(u.close)
	proxy := &url.URL{Scheme: "https", Host: proxyAddr.String()}

	initCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	initErr := make(chan error, 1)
	go func() {
		_, derr := u.connect(initCtx, proxy, "192.0.2.1:443")
		initErr <- derr
	}()
	require.Eventually(t, func() bool { return udpDials.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	waiter := make(chan error, 1)
	go func() {
		conn, derr := u.connect(t.Context(), proxy, "192.0.2.1:443")
		if derr == nil {
			_ = conn.Close()
		}
		waiter <- derr
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	require.ErrorIs(t, <-initErr, context.Canceled)
	require.NoError(t, <-waiter, "the waiter took the cancellation of another caller")
	assert.EqualValues(t, 2, udpDials.Load())
}

func TestChain_ConcurrentCONNECTsShareOneHTTP2Dial(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	proxies := &h2Proxies{t: t, ca: ca}
	u := proxies.dialer(t)
	proxy, err := url.Parse("https://127.0.0.1:443")
	require.NoError(t, err)

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() {
			conn, derr := u.connect(t.Context(), proxy, "192.0.2.1:443")
			if derr == nil {
				_ = conn.Close()
			}
			errs[i] = derr
		})
	}
	wg.Wait()
	for i, derr := range errs {
		require.NoError(t, derr, "dial %d", i)
	}
	assert.EqualValues(t, 1, proxies.dials.Load(), "one dial for all")
}

// fakeProxyTLS is fakeProxy over TLS, offering protos in ALPN and calling hello, when set, on
// every ClientHello.
func fakeProxyTLS(t *testing.T, ca *CA, protos []string, hello func(), reply func(w io.Writer)) string {
	t.Helper()
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	cfg := &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: protos, MinVersion: tls.VersionTLS12}
	if hello != nil {
		cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			hello()
			return nil, nil
		}
	}
	ln := tls.NewListener(raw, cfg)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if _, rerr := http.ReadRequest(bufio.NewReader(conn)); rerr != nil {
					return
				}
				reply(conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestChain_HTTP11ProxyIsDialedOncePerCONNECTOnceKnown(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	var firstHello sync.Once
	var firstDone atomic.Int64
	addr := fakeProxyTLS(t, ca, []string{"http/1.1"}, func() {
		firstHello.Do(func() {
			time.Sleep(200 * time.Millisecond)
			firstDone.Store(time.Now().UnixNano())
		})
	}, func(w io.Writer) {
		_, _ = io.WriteString(w, "HTTP/1.1 200 Connection Established\r\n\r\n")
		time.Sleep(time.Second)
	})
	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	tr.Proxy = fixedProxy("https://" + addr)
	var mu sync.Mutex
	var starts []int64
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		starts = append(starts, time.Now().UnixNano())
		mu.Unlock()
		return defaultDialer.DialContext(ctx, network, address)
	}
	u := newUpstreamDialer(tr)
	t.Cleanup(u.close)
	proxy := &url.URL{Scheme: "https", Host: addr}

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() {
			conn, derr := u.connect(t.Context(), proxy, "192.0.2.1:443")
			if derr == nil {
				_ = conn.Close()
			}
			errs[i] = derr
		})
	}
	wg.Wait()
	for i, derr := range errs {
		require.NoError(t, derr, "dial %d", i)
	}
	require.Len(t, starts, 8, "one connection per CONNECT")
	var before int
	for _, at := range starts {
		if at < firstDone.Load() {
			before++
		}
	}
	assert.Equal(t, 1, before, "one dial ran alone until TLS negotiated http/1.1")
	assert.True(t, u.remembers(noH2, proxy))
}

func TestChain_ConcurrentCONNECTsToAFailingProxyEachFail(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	front, dialer := chainedFront(t, ca, "https://"+ln.Addr().String(), onTCP)
	up := front.srv.fwd.up

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() {
			_, errs[i] = up.dial(t.Context(), "tcp", "192.0.2.1:443", "https")
		})
	}
	wg.Wait()
	for i, derr := range errs {
		require.Error(t, derr, "dial %d", i)
		assert.Contains(t, derr.Error(), "tls handshake", "dial %d", i)
		assert.NotContains(t, derr.Error(), errDialWaited.Error(), "dial %d", i)
	}
	assert.EqualValues(t, 8, dialer.tcp.Load())
}

func TestChain_ConcurrentCONNECTsToAOneStreamProxyEachSucceed(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	proxies := &h2Proxies{t: t, ca: ca, settings: []http2.Setting{{ID: http2.SettingMaxConcurrentStreams, Val: 1}}}
	u := proxies.dialer(t)
	proxy, err := url.Parse("https://127.0.0.1:443")
	require.NoError(t, err)

	var wg sync.WaitGroup
	conns := make([]net.Conn, 8)
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() { conns[i], errs[i] = u.connect(t.Context(), proxy, "192.0.2.1:443") })
	}
	wg.Wait()
	for i, derr := range errs {
		require.NoError(t, derr, "dial %d", i)
		defer func() { _ = conns[i].Close() }()
	}
	assert.GreaterOrEqual(t, proxies.dials.Load(), int32(8), "one connection per CONNECT at least")
}

func TestChain_RequestFollowsTheProxySwitch(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	tlsOrigin := namedOrigin(t, ca, "inner.test")
	plainOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin host=%s", r.Host)
	}))
	t.Cleanup(plainOrigin.Close)
	plainURL, err := url.Parse(plainOrigin.URL)
	require.NoError(t, err)

	// chained builds a back proxy in front of origin and a front proxy chained to it, and
	// returns the front, the address of the back, what the front dialed and what selects
	// its proxy, nil for a direct connection.
	chained := func(t *testing.T, origin string) (*Proxy, string, *recorder, *atomic.Pointer[url.URL]) {
		t.Helper()
		backTr := DefaultTransport()
		backTr.RootCAs = poolOf(ca)
		backTr.DialContext = pinnedDialer(origin)
		back, err := New(WithCA(ca), WithTransport(backTr))
		require.NoError(t, err)
		back.MustAdd("inner.test/", forwardHandler)
		backAddr := startProxy(t, back)

		frontTr := DefaultTransport()
		frontTr.RootCAs = poolOf(ca)
		dialed := new(recorder)
		frontTr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed.add(addr)
			if addr != backAddr {
				addr = origin
			}
			return defaultDialer.DialContext(ctx, network, addr)
		}
		selected := new(atomic.Pointer[url.URL])
		frontTr.Proxy = func(*http.Request) (*url.URL, error) { return selected.Load(), nil }
		front, err := New(WithCA(ca), WithTransport(frontTr))
		require.NoError(t, err)
		front.MustAdd("inner.test/", forwardHandler)
		return front, backAddr, dialed, selected
	}

	get := func(t *testing.T, client *http.Client, target string) {
		t.Helper()
		resp, err := client.Get(target)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
		assert.Equal(t, "origin host="+resp.Request.URL.Host, string(body))
	}

	// through checks the three requests, through the back, direct and through the back
	// again on the connection the first one left idle.
	through := func(t *testing.T, client *http.Client, target, dest, backAddr string, dialed *recorder, selected *atomic.Pointer[url.URL]) {
		t.Helper()
		back, err := url.Parse("http://" + backAddr)
		require.NoError(t, err)
		selected.Store(back)
		get(t, client, target)
		assert.Equal(t, []string{backAddr}, dialed.all())
		selected.Store(nil)
		get(t, client, target)
		assert.Equal(t, []string{backAddr, dest}, dialed.all())
		selected.Store(back)
		get(t, client, target)
		assert.Equal(t, []string{backAddr, dest}, dialed.all())
	}

	_, port, err := net.SplitHostPort(tlsOrigin.Host)
	require.NoError(t, err)
	t.Run("declared destination", func(t *testing.T) {
		front, backAddr, dialed, selected := chained(t, tlsOrigin.Host)
		frontAddr := startProxy(t, front)
		client := tunnelClient(t, frontAddr, "inner.test:"+port, "inner.test", ca)
		through(t, client, "https://inner.test/", "inner.test:"+port, backAddr, dialed, selected)
	})
	t.Run("no declared destination over TLS", func(t *testing.T) {
		front, backAddr, dialed, selected := chained(t, tlsOrigin.Host)
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
		through(t, client, "https://inner.test:"+port+"/", "inner.test:"+port, backAddr, dialed, selected)
	})
	t.Run("no declared destination in plaintext", func(t *testing.T) {
		front, backAddr, dialed, selected := chained(t, plainURL.Host)
		frontAddr := startProxy(t, front)
		client := &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: frontAddr})},
		}
		_, plainPort, err := net.SplitHostPort(plainURL.Host)
		require.NoError(t, err)
		through(t, client, "http://inner.test:"+plainPort+"/", "inner.test:"+plainPort, backAddr, dialed, selected)
	})
}

func TestChain_PoolPerProxy(t *testing.T) {
	tr := DefaultTransport()
	selected := new(atomic.Pointer[url.URL])
	tr.Proxy = func(*http.Request) (*url.URL, error) { return selected.Load(), nil }
	p, err := New(WithTransport(tr))
	require.NoError(t, err)
	f := p.srv.fwd
	req := httptest.NewRequest(http.MethodGet, "https://inner.test/", nil)

	direct, err := f.poolFor(req, "")
	require.NoError(t, err)
	assert.Same(t, f.shared.https, direct)

	first, err := url.Parse("http://first.test:8080")
	require.NoError(t, err)
	selected.Store(first)
	throughFirst, err := f.poolFor(req, "")
	require.NoError(t, err)
	assert.NotSame(t, direct, throughFirst)
	again, err := f.poolFor(req, "")
	require.NoError(t, err)
	assert.Same(t, throughFirst, again)
	fixedThroughFirst, err := f.poolFor(req, "127.0.0.1:443")
	require.NoError(t, err)
	assert.NotSame(t, throughFirst, fixedThroughFirst)

	second, err := url.Parse("http://second.test:8080")
	require.NoError(t, err)
	selected.Store(second)
	throughSecond, err := f.poolFor(req, "")
	require.NoError(t, err)
	assert.NotSame(t, throughFirst, throughSecond)
	assert.Equal(t, 3, f.pools.Len())

	selected.Store(nil)
	direct, err = f.poolFor(req, "")
	require.NoError(t, err)
	assert.Same(t, f.shared.https, direct)

	unsupported, err := url.Parse("ftp://127.0.0.1:1080")
	require.NoError(t, err)
	selected.Store(unsupported)
	_, err = f.poolFor(req, "")
	require.ErrorContains(t, err, "not supported")
	assert.Equal(t, 3, f.pools.Len(), "no pool for a proxy that cannot be dialed")

	boom := errors.New("boom")
	f.up.t.Proxy = func(*http.Request) (*url.URL, error) { return nil, boom }
	_, err = f.poolFor(req, "")
	require.ErrorIs(t, err, boom)
	_, err = f.poolFor(req, "127.0.0.1:443")
	require.ErrorIs(t, err, boom)
	assert.Equal(t, 3, f.pools.Len())
}

func TestChain_RefusedTCPDialIsNotRemembered(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		remembered bool
	}{
		{"timed out", &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}, true},
		{"refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := DefaultTransport()
			tr.DialContext = func(_ context.Context, network, _ string) (net.Conn, error) {
				if network == "tcp" {
					return nil, tc.err
				}
				return nil, errors.New("no udp")
			}
			proxy, err := url.Parse("https://127.0.0.1:1")
			require.NoError(t, err)
			u := newUpstreamDialer(tr)
			_, err = u.connect(t.Context(), proxy, "127.0.0.1:443")
			require.ErrorIs(t, err, tc.err)
			assert.Equal(t, tc.remembered, u.remembers(noTCPDial, proxy))
			assert.True(t, u.remembers(noH3Dial, proxy))
		})
	}
}

func TestChain_TCPStreamThroughSOCKS5(t *testing.T) {
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
	backAddr := startSOCKS5(t, back)

	for _, scheme := range []string{"socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			frontTr := DefaultTransport()
			frontTr.RootCAs = poolOf(ca)
			dialed := new(recorder)
			frontTr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialed.add(network + " " + addr)
				return defaultDialer.DialContext(ctx, network, addr)
			}
			frontTr.Proxy = fixedProxy(scheme + "://" + backAddr)
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
			assert.Equal(t, []string{"tcp " + backAddr}, dialed.all())

			sess := waitForSessions(t, back, 1)[0]
			assert.Equal(t, "inner.test", sess.Target().Host)
			assert.Equal(t, KindTCP, sess.Kind())
			require.NoError(t, sess.Close())
			waitForSessions(t, back, 0)
		})
	}
}

func TestChain_HTTPWithDeclaredDestinationThroughSOCKS5(t *testing.T) {
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
	backAddr := startSOCKS5(t, back)

	frontTr := DefaultTransport()
	frontTr.RootCAs = poolOf(ca)
	dialed := new(recorder)
	frontTr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed.add(network + " " + addr)
		return defaultDialer.DialContext(ctx, network, addr)
	}
	frontTr.Proxy = fixedProxy("socks5://" + backAddr)
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

func TestChain_SOCKS5CarriesTheCredentials(t *testing.T) {
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
	backAddr := startSOCKS5(t, back)

	frontTr := DefaultTransport()
	frontTr.RootCAs = poolOf(ca)
	frontTr.Proxy = fixedProxy("socks5://alice:s3cret@" + backAddr)
	front, err := New(WithCA(ca), WithTransport(frontTr))
	require.NoError(t, err)
	front.MustAdd[TCP]("inner.test", relayStream)
	frontAddr := startProxy(t, front)

	client := tunnelClient(t, frontAddr, "inner.test:"+port, "inner.test", ca)
	resp, err := client.Get("https://inner.test/")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "alice", waitForSessions(t, back, 1)[0].Identity())

	frontTr.Proxy = fixedProxy("socks5://alice:wrong@" + backAddr)
	_, err = newUpstreamDialer(frontTr).dial(t.Context(), "tcp", "inner.test:"+port, "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")

	frontTr.Proxy = fixedProxy("socks5://" + backAddr)
	_, err = newUpstreamDialer(frontTr).dial(t.Context(), "tcp", "inner.test:"+port, "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "none of the authentication methods")
}

// fakeSOCKS5 answers every CONNECT with rep, written by hand so the test shares nothing with
// the codec the dialer reads with.
func fakeSOCKS5(t *testing.T, rep byte) string {
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
				var greeting [2]byte
				if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting[0] != 5 {
					return
				}
				methods := make([]byte, greeting[1])
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				if _, err := conn.Write([]byte{5, 0}); err != nil {
					return
				}
				var head [4]byte
				if _, err := io.ReadFull(conn, head[:]); err != nil {
					return
				}
				var rest []byte
				switch head[3] {
				case 1:
					rest = make([]byte, 4+2)
				case 4:
					rest = make([]byte, 16+2)
				case 3:
					var l [1]byte
					if _, err := io.ReadFull(conn, l[:]); err != nil {
						return
					}
					rest = make([]byte, int(l[0])+2)
				}
				if _, err := io.ReadFull(conn, rest); err != nil {
					return
				}
				_, _ = conn.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
				time.Sleep(10 * time.Second)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestChain_RefusedSOCKS5CONNECTReportsTheReply(t *testing.T) {
	proxy := fakeSOCKS5(t, 2)
	tr := DefaultTransport()
	tr.Proxy = fixedProxy("socks5://" + proxy)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err := newUpstreamDialer(tr).dial(ctx, "tcp", "example.test:443", "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed by ruleset")
	assert.Less(t, time.Since(start), time.Second)
}

func TestChain_DatagramFlowThroughSOCKS5(t *testing.T) {
	echo := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)

	back, err := New(WithCA(ca))
	require.NoError(t, err)
	back.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	backAddr := startSOCKS5(t, back)

	front, dialer := chainedFront(t, ca, "socks5://"+backAddr, onBoth)
	frontAddr := startQUICRedirected(t, front, echo)
	echoThrough(t, frontAddr, "ping", "pong")

	var tunnels, flows int
	for _, s := range waitForSessions(t, back, 4) {
		if s.Tunnel() {
			tunnels++
			assert.Equal(t, Protocol(0), s.Protocol())
		} else {
			flows++
			assert.Equal(t, KindUDP, s.Kind())
		}
	}
	assert.Equal(t, 2, tunnels, "one association per flow")
	assert.Equal(t, 2, flows, "one flow inside each association")
	assert.EqualValues(t, 2, dialer.tcp.Load(), "one control connection per association")
	assert.EqualValues(t, 2, dialer.udp.Load(), "one relay socket per association")
}

func TestChain_H3UpstreamThroughSOCKS5(t *testing.T) {
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
	backAddr := startSOCKS5(t, back)

	frontTr := DefaultTransport()
	frontTr.AllowHTTP3 = true
	frontTr.RootCAs = poolOf(ca)
	frontTr.Proxy = fixedProxy("socks5://" + backAddr)
	front, err := New(WithCA(ca), WithTransport(frontTr))
	require.NoError(t, err)
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
	assert.Contains(t, string(body), "path=/echo")
	assert.Contains(t, string(body), "proto=HTTP/3.0", "the origin was reached over HTTP/3")

	var assoc, inner *Session
	for _, s := range waitForSessions(t, back, 2) {
		if s.Tunnel() {
			assoc = s
		} else {
			inner = s
		}
	}
	require.NotNil(t, assoc)
	require.NotNil(t, inner)
	assert.Equal(t, KindQUIC, inner.Kind())
	assert.Equal(t, h3Authority, inner.Target().Host)
	assert.Equal(t, origin, inner.Upstream())
	assert.Same(t, assoc, inner.Via())
}

func TestChain_RefusedSOCKS5AssociateReportsTheReply(t *testing.T) {
	proxy := fakeSOCKS5(t, 7)
	tr := DefaultTransport()
	tr.Proxy = fixedProxy("socks5://" + proxy)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := newUpstreamDialer(tr).dial(ctx, "udp", "127.0.0.1:443", "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "command not supported")
}

func TestChain_H3AnswerPastInformational(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	for _, tc := range []struct {
		name  string
		codes []string
		ok    bool
	}{
		{"a 100", []string{"100"}, true},
		{"five", []string{"100", "103", "103", "103", "103"}, true},
		{"six", []string{"100", "103", "103", "103", "103", "103"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := newRawQUIC(t, *cert, func(_ *rawOrigin, _ *h3Conn, s *h3Stream) {
				if _, _, err := s.next(); err != nil {
					return
				}
				for _, code := range append(tc.codes, "200") {
					if _, err := s.Write(h3Headers([]hpack.HeaderField{hf(":status", code)})); err != nil {
						return
					}
				}
				_, _ = io.Copy(io.Discard, s.br)
			})
			cc, _ := dialH3(t, up.addr, ca, true)
			req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: "origin.test:443"}, Host: "origin.test:443", Header: make(http.Header)}
			str, err := requestOn(t.Context(), cc, req, "CONNECT-UDP", connectUDPAnswer)
			if !tc.ok {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "too many 1xx answers")
				return
			}
			require.NoError(t, err)
			str.CancelRead(0)
			str.CancelWrite(0)
		})
	}
}

func TestChain_NoUserAgentToTheProxy(t *testing.T) {
	t.Run("CONNECT", func(t *testing.T) {
		for _, exit := range allExits {
			t.Run(exit, func(t *testing.T) {
				b := newExitBench(t, exit, nil, "HTTP/1.1 200 OK\r\n\r\n")
				b.tunnel(t, "origin.test:80", "")
				assert.Empty(t, b.origin.next(t).req.Header.Values("User-Agent"))
			})
		}
	})
	t.Run("CONNECT-UDP", func(t *testing.T) {
		ca, err := GenerateCA()
		require.NoError(t, err)
		eachExit(t, allExits, func(t *testing.T, version string) {
			u := exitDialer(t, ca)
			switch version {
			case viaH3:
				up := startH3Upstream(t, ca, nil, true, answerH3(http.StatusOK, capsuleProtocolOn))
				_, err := exitTunnel(t, u, version, up.addr, "192.0.2.1:53")
				require.NoError(t, err)
				assert.Empty(t, up.head(t)["user-agent"])
			case viaH2:
				up := startH2Upstream(t, ca, h2Status("200"), capsuleProtocolField)
				_, err := exitTunnel(t, u, version, up.addr, "192.0.2.1:53")
				require.NoError(t, err)
				assert.Empty(t, up.head(t)["user-agent"])
			default:
				up := startH1Upstream(t, nil, upgraded101)
				_, err := exitTunnel(t, u, version, up.addr, "192.0.2.1:53")
				require.NoError(t, err)
				_, header := up.head(t)
				assert.Empty(t, header.Values("User-Agent"))
			}
		})
	})
}
