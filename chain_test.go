// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	tr.Proxy = fixedProxy("http://127.0.0.1:1")
	_, err := newUpstreamDialer(tr).dial(t.Context(), "udp", "127.0.0.1:53", "https")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CONNECT-UDP needs an https proxy")

	tr.Proxy = fixedProxy("socks5://127.0.0.1:1")
	_, err = newUpstreamDialer(tr).dial(t.Context(), "tcp", "127.0.0.1:443", "https")
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
