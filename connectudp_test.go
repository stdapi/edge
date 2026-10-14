// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	h3qlog "github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stdapi/edge/internal/h2tunnel"
	"github.com/stdapi/edge/internal/netutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/ipv4"
)

// masqueClient connects to the proxy front at addr as an HTTP/3 client with datagrams,
// trusting ca, and returns the connection CONNECT-UDP tunnels are opened on.
func masqueClient(t *testing.T, addr netip.AddrPort, ca *CA) *http3.ClientConn {
	t.Helper()
	pc, err := loopbackUDP()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The outer connection needs room for a 1200 byte Initial plus the datagram overhead,
	// which quic-go's default initial packet size does not leave.
	qconn, err := quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(addr), &tls.Config{
		RootCAs:    poolOf(ca),
		ServerName: "127.0.0.1",
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	if err != nil {
		_ = pc.Close()
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = qconn.CloseWithError(0, "")
		_ = pc.Close()
	})
	tr := &http3.Transport{EnableDatagrams: true}
	t.Cleanup(func() { _ = tr.Close() })
	cc := tr.NewClientConn(qconn)
	select {
	case <-cc.ReceivedSettings():
	case <-time.After(5 * time.Second):
		t.Fatal("no SETTINGS from the proxy")
	}
	require.True(t, cc.Settings().EnableDatagrams, "the front negotiates HTTP Datagrams")
	require.True(t, cc.Settings().EnableExtendedConnect, "the front negotiates extended CONNECT")
	return cc
}

// masqueConn is a CONNECT-UDP client of RFC 9298 written from the RFC, the counterpart of
// what the proxy implements. It is a net.PacketConn over the tunnel, every datagram carrying
// context ID 0.
type masqueConn struct {
	str      *http3.RequestStream
	deadline atomic.Pointer[time.Time]
}

// openTunnel asks the proxy at front for a tunnel to target, host:port, with the given
// headers. A refusal returns the response the proxy answered with.
func openTunnel(t *testing.T, cc *http3.ClientConn, front netip.AddrPort, target string, header http.Header) (*masqueConn, *http.Response, error) {
	t.Helper()
	host, port, err := net.SplitHostPort(target)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodConnect,
		fmt.Sprintf("https://%s%s%s/%s/", front, connectUDPPath, url.PathEscape(host), port), nil)
	require.NoError(t, err)
	req.Proto = "connect-udp"
	req.Header.Set(http3.CapsuleProtocolHeader, "?1")
	for k, vv := range header {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	str, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	if err := str.SendRequestHeader(req); err != nil {
		return nil, nil, err
	}
	resp, err := str.ReadResponse()
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		return nil, resp, fmt.Errorf("CONNECT-UDP refused with %d", resp.StatusCode)
	}
	mc := &masqueConn{str: str}
	t.Cleanup(func() { _ = mc.Close() })
	go func() {
		// Capsules are read and dropped so the stream keeps flowing, and its end is the
		// proxy's.
		parser := http3.NewCapsuleParser(str)
		for {
			_, r, perr := parser.Next()
			if perr != nil {
				return
			}
			if perr := r.Discard(); perr != nil {
				return
			}
		}
	}()
	return mc, resp, nil
}

func (c *masqueConn) ReadFrom(b []byte) (int, net.Addr, error) {
	ctx := context.Background()
	if dl := c.deadline.Load(); dl != nil && !dl.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, *dl)
		defer cancel()
	}
	for {
		data, err := c.str.ReceiveDatagram(ctx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			return 0, nil, err
		}
		id, n, err := quicvarint.Parse(data)
		if err != nil || id != 0 {
			continue
		}
		return copy(b, data[n:]), emptyAddr{}, nil
	}
}

func (c *masqueConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	out := make([]byte, 1+len(b))
	copy(out[1:], b)
	return len(b), c.str.SendDatagram(out)
}

func (c *masqueConn) Close() error {
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	return c.str.Close()
}

func (c *masqueConn) LocalAddr() net.Addr               { return emptyAddr{} }
func (c *masqueConn) SetReadBuffer(int) error           { return nil }
func (c *masqueConn) SetWriteBuffer(int) error          { return nil }
func (c *masqueConn) SetDeadline(t time.Time) error     { return c.SetReadDeadline(t) }
func (c *masqueConn) SetReadDeadline(t time.Time) error { c.deadline.Store(&t); return nil }
func (c *masqueConn) SetWriteDeadline(time.Time) error  { return nil }

// innerH3 opens an HTTP/3 connection to origin through the tunnel, as a client of name that
// trusts the certificates ca mints, and returns a round tripper on it.
func innerH3(t *testing.T, pconn net.PacketConn, origin netip.AddrPort, name string, ca *CA) (*http3.ClientConn, *quic.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qconn, err := quic.DialEarly(ctx, pconn, net.UDPAddrFromAddrPort(origin), &tls.Config{
		RootCAs:    poolOf(ca),
		ServerName: name,
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{DisablePathMTUDiscovery: true, MaxIdleTimeout: 10 * time.Second})
	require.NoError(t, err)
	tr := &http3.Transport{}
	t.Cleanup(func() { _ = tr.Close() })
	return tr.NewClientConn(qconn), qconn
}

// requireEnded waits for a QUIC connection to end, which a CONNECTION_CLOSE from the proxy or
// the end of the tunnel carrying it both bring about.
func requireEnded(t *testing.T, conn *quic.Conn, msg string) {
	t.Helper()
	select {
	case <-conn.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal(msg)
	}
}

func getThrough(cc *http3.ClientConn, u string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// udpEcho starts a UDP origin echoing every datagram back.
func udpEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

// masqueProxy builds a proxy with an HTTP/3 origin behind it, admitted for HTTP on
// h3Authority, resolving that name to the origin, and serves it on an HTTP/3 front.
func masqueProxy(t *testing.T, opts ...ProxyOption) (*Proxy, *CA, netip.AddrPort, netip.AddrPort) {
	t.Helper()
	p, proxyCA, origin := newMasqueProxy(t, opts...)
	front, _ := startQUICFront(t, p, proxyCA)
	return p, proxyCA, front, origin
}

// newMasqueProxy builds the proxy masqueProxy serves, without a front.
func newMasqueProxy(t *testing.T, opts ...ProxyOption) (*Proxy, *CA, netip.AddrPort) {
	t.Helper()
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	upstream := DefaultTransport()
	upstream.AllowHTTP3 = true
	upstream.RootCAs = poolOf(originCA)
	resolver := &fakeResolver{addrs: map[string][]netip.Addr{h3Authority: {origin.Addr()}}}

	p, err := New(append([]ProxyOption{
		WithCA(proxyCA), WithTransport(upstream), WithNameResolver(resolver),
	}, opts...)...)
	require.NoError(t, err)
	p.MustAdd(h3Authority+"/+{any}", forwardHandler)
	return p, proxyCA, origin
}

func TestConnectUDP_TerminatesTheInnerHTTP3(t *testing.T) {
	p, ca, front, origin := masqueProxy(t)
	cc := masqueClient(t, front, ca)

	target := fmt.Sprintf("%s:%d", h3Authority, origin.Port())
	pconn, resp, err := openTunnel(t, cc, front, target, nil)
	require.NoError(t, err)
	assert.Equal(t, "?1", resp.Header.Get(http3.CapsuleProtocolHeader))

	inner, _ := innerH3(t, pconn, origin, h3Authority, ca)
	body, err := getThrough(inner, fmt.Sprintf("https://%s/echo", target))
	require.NoError(t, err)
	assert.Contains(t, body, "path=/echo")
	assert.Contains(t, body, "proto=HTTP/3.0", "the origin was reached over HTTP/3 too")

	sessions := waitForSessions(t, p, 2)
	var tunnel, conn *Session
	for _, s := range sessions {
		if s.Tunnel() {
			tunnel = s
		} else {
			conn = s
		}
	}
	require.NotNil(t, tunnel)
	require.NotNil(t, conn)
	assert.Equal(t, KindHTTP, tunnel.Kind(), "admitted under the most specific kind an entry names")
	assert.Equal(t, []Kind{KindHTTP, KindQUIC, KindUDP}, tunnel.ServableAs())
	assert.Equal(t, HTTP3, tunnel.Protocol())
	assert.Equal(t, h3Authority, tunnel.Target().Host)
	assert.Equal(t, origin, tunnel.Upstream(), "resolved once, when the tunnel was opened")
	assert.False(t, tunnel.Transparent())
	assert.Nil(t, tunnel.Via())
	assert.NotNil(t, tunnel.TLS(), "the front handshake")

	assert.Same(t, tunnel, conn.Via())
	assert.Equal(t, KindHTTP, conn.Kind())
	assert.Equal(t, HTTP3, conn.Protocol())
	assert.Equal(t, h3Authority, conn.Target().Host)
	assert.Equal(t, origin, conn.Upstream())
	assert.False(t, conn.Transparent())
	assert.Equal(t, tunnel.RemoteAddr(), conn.RemoteAddr())

	// Closing the inner connection leaves the tunnel, and the client opens another inside
	// it, decided again.
	require.NoError(t, conn.Close())
	waitForSessions(t, p, 1)
	again, againConn := innerH3(t, pconn, origin, h3Authority, ca)
	body, err = getThrough(again, fmt.Sprintf("https://%s/again", target))
	require.NoError(t, err)
	assert.Contains(t, body, "path=/again")
	waitForSessions(t, p, 2)

	// Closing the tunnel ends what it carries, and the client sees its stream end.
	require.NoError(t, tunnel.Close())
	assertSessionEnded(t, p, tunnel)
	require.NoError(t, tunnel.Close(), "closing twice is a no-op")
	waitForSessions(t, p, 0)
	requireEnded(t, againConn, "the inner connection is closed through the tunnel")
	_, err = getThrough(again, fmt.Sprintf("https://%s/dead", target))
	require.Error(t, err, "the inner connection is over")

	// The front connection survives, and a new tunnel is decided afresh.
	pconn2, _, err := openTunnel(t, cc, front, target, nil)
	require.NoError(t, err)
	third, _ := innerH3(t, pconn2, origin, h3Authority, ca)
	body, err = getThrough(third, fmt.Sprintf("https://%s/third", target))
	require.NoError(t, err)
	assert.Contains(t, body, "path=/third")
}

func TestConnectUDP_RoutesRawDatagramsOnTheDeclaredTarget(t *testing.T) {
	echo := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	resolver := &fakeResolver{addrs: map[string][]netip.Addr{"echo.udp.test": {echo.Addr()}}}
	p, err := New(WithCA(ca), WithNameResolver(resolver))
	require.NoError(t, err)

	seen := new(recorder)
	p.MustAdd[UDP](fmt.Sprintf("{name}.udp.test:%d", echo.Port()), func(c *DatagramCtx) error {
		seen.add(fmt.Sprintf("%s %s %v %s", c.Param("name"), c.Target().Host, c.Inbound(), c.Bytes()))
		return c.Forward()
	})
	front, _ := startQUICFront(t, p, ca)
	cc := masqueClient(t, front, ca)

	pconn, _, err := openTunnel(t, cc, front, fmt.Sprintf("echo.udp.test:%d", echo.Port()), nil)
	require.NoError(t, err)
	_, err = pconn.WriteTo([]byte("ping"), nil)
	require.NoError(t, err)
	require.NoError(t, pconn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 64)
	n, _, err := pconn.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf[:n]))
	assert.Equal(t, []string{"echo echo.udp.test false ping", "echo echo.udp.test true ping"}, seen.all())

	sessions := waitForSessions(t, p, 2)
	for _, s := range sessions {
		assert.Equal(t, KindUDP, s.Kind())
		assert.Equal(t, "echo.udp.test", s.Target().Host)
		assert.Equal(t, echo, s.Upstream())
		if !s.Tunnel() {
			require.NotNil(t, s.Via())
			assert.True(t, s.Via().Tunnel())
		}
	}
}

func TestConnectUDP_TunnelCloseClosesTheAlternates(t *testing.T) {
	echo := udpEcho(t)
	other := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	resolver := &fakeResolver{addrs: map[string][]netip.Addr{"echo.udp.test": {echo.Addr()}}}
	p, err := New(WithCA(ca), WithNameResolver(resolver))
	require.NoError(t, err)
	p.MustAdd[UDP](fmt.Sprintf("{name}.udp.test:%d", echo.Port()), func(c *DatagramCtx) error {
		if !c.Inbound() {
			return c.SendTo(other.String(), c.Bytes())
		}
		return c.Forward()
	})
	front, _ := startQUICFront(t, p, ca)
	cc := masqueClient(t, front, ca)

	pconn, _, err := openTunnel(t, cc, front, fmt.Sprintf("echo.udp.test:%d", echo.Port()), nil)
	require.NoError(t, err)
	_, err = pconn.WriteTo([]byte("ping"), nil)
	require.NoError(t, err)
	require.NoError(t, pconn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 64)
	n, _, err := pconn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf[:n]))

	p.srv.mu.Lock()
	d := p.srv.tunnels
	p.srv.mu.Unlock()
	require.NotNil(t, d)
	var alt net.Conn
	d.mu.Lock()
	for _, flow := range d.flows {
		for _, u := range flow.udp {
			for _, a := range u.alts {
				alt = a.conn
			}
		}
	}
	d.mu.Unlock()
	require.NotNil(t, alt, "the flow reached the other origin through an alternate")

	var closed int
	for s := range p.Sessions() {
		if s.Tunnel() {
			require.NoError(t, s.Close())
			closed++
		}
	}
	require.Equal(t, 1, closed)
	_, err = alt.Write([]byte("x"))
	assert.ErrorIs(t, err, net.ErrClosed, "closing the tunnel closes the alternate")
}

func TestConnectUDP_RefusesBeforeTheTunnelExists(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	resolver := &fakeResolver{addrs: map[string][]netip.Addr{"spray.test": addrsOf("10.9.9.9")}}
	p, err := New(WithCA(ca), WithNameResolver(resolver))
	require.NoError(t, err)
	p.MustAdd("unresolved.test/+{any}", forwardHandler)
	front, _ := startQUICFront(t, p, ca)
	cc := masqueClient(t, front, ca)

	_, resp, err := openTunnel(t, cc, front, "spray.test:443", nil)
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "a name no entry admits")
	assert.Zero(t, resolver.calls.Load(), "a refused name is not resolved")

	_, resp, err = openTunnel(t, cc, front, "unresolved.test:443", nil)
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode, "a name the proxy cannot resolve")
	assert.EqualValues(t, 1, resolver.calls.Load())

	_, resp, err = openTunnel(t, cc, front, "10.9.9.9:443", nil)
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "a literal no entry admits")
	assert.Empty(t, waitForSessions(t, p, 0))
}

func TestConnectUDP_ClosedTunnelOwnsNoFlow(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca))
	require.NoError(t, err)
	p.MustAdd(h3Authority+"/+{any}", forwardHandler)
	d, err := newQUICDemux(p, newTunnelPacketConn())
	require.NoError(t, err)
	t.Cleanup(d.close)

	ctx, cancel := context.WithCancel(t.Context())
	target := Target{Scheme: "https", Host: h3Authority, Port: "443"}
	sess := newSession(p, ctx, nil, target, KindHTTP, HTTP3)
	sess.remoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}
	tun := newConnectUDPTunnel(d, sess, &contextFraming{target: target, upstream: netip.MustParseAddrPort("127.0.0.1:443")}, cancel)
	require.True(t, d.publishTunnel(tun))
	tun.close()

	initial := make([]byte, 1200)
	initial[0], initial[4], initial[5] = 0xC0, 1, 8
	copy(initial[6:14], "12345678")
	d.dispatchLong(tun.addr, tun.key, initial, false)

	d.mu.Lock()
	defer d.mu.Unlock()
	assert.Nil(t, d.flowLocked(tun.key, tun.addr, time.Now()))
	assert.Nil(t, d.admitConnLocked(tun.key, tun.addr, "12345678", time.Now()))
	assert.Empty(t, d.flows)
}

func TestConnectUDP_SweepAfterDelete(t *testing.T) {
	p, ca, front, origin := masqueProxy(t)
	cc := masqueClient(t, front, ca)
	target := fmt.Sprintf("%s:%d", h3Authority, origin.Port())

	pconn, _, err := openTunnel(t, cc, front, target, nil)
	require.NoError(t, err)
	inner, innerConn := innerH3(t, pconn, origin, h3Authority, ca)
	_, err = getThrough(inner, fmt.Sprintf("https://%s/echo", target))
	require.NoError(t, err)
	waitForSessions(t, p, 2)

	_, err = p.Delete[HTTP](h3Authority + "/+{any}")
	require.NoError(t, err)
	for s := range p.Sessions() {
		if !p.Admits(s.Target(), s.Kind()) {
			require.NoError(t, s.Close())
		}
	}
	waitForSessions(t, p, 0)
	requireEnded(t, innerConn, "the inner connection is closed through the tunnel")

	_, resp, err := openTunnel(t, cc, front, target, nil)
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestConnectUDP_IdentityRevocation(t *testing.T) {
	p, ca, front, origin := masqueProxy(t, WithProxyAuth(testBasic()))
	cc := masqueClient(t, front, ca)
	target := fmt.Sprintf("%s:%d", h3Authority, origin.Port())

	_, resp, err := openTunnel(t, cc, front, target, nil)
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)

	creds := http.Header{HeaderProxyAuthorization: []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))}}
	pconn, _, err := openTunnel(t, cc, front, target, creds)
	require.NoError(t, err)
	inner, innerConn := innerH3(t, pconn, origin, h3Authority, ca)
	_, err = getThrough(inner, fmt.Sprintf("https://%s/echo", target))
	require.NoError(t, err)

	for _, s := range waitForSessions(t, p, 2) {
		assert.Equal(t, "alice", s.Identity(), "the tunnel and what it carries report the identity")
	}
	for s := range p.Sessions() {
		if s.Identity() == "alice" {
			require.NoError(t, s.Close())
		}
	}
	waitForSessions(t, p, 0)
	requireEnded(t, innerConn, "the inner connection is closed through the tunnel")
	_, err = getThrough(inner, fmt.Sprintf("https://%s/dead", target))
	require.Error(t, err)
}

func TestConnectUDP_IdleTunnelIsClosed(t *testing.T) {
	p, ca, front, origin := masqueProxy(t)
	cc := masqueClient(t, front, ca)
	target := fmt.Sprintf("%s:%d", h3Authority, origin.Port())

	pconn, _, err := openTunnel(t, cc, front, target, nil)
	require.NoError(t, err)
	tunnel := waitForSessions(t, p, 1)[0]
	require.True(t, tunnel.Tunnel())

	d := p.srv.tunnels
	require.NotNil(t, d)
	d.mu.Lock()
	for _, flow := range d.flows {
		flow.lastSeen = time.Now().Add(-2 * udpFlowIdle)
	}
	d.mu.Unlock()
	d.sweepIdle()

	waitForSessions(t, p, 0)
	require.NoError(t, pconn.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, _, err = pconn.ReadFrom(make([]byte, 16))
	require.Error(t, err)
	assert.False(t, errors.Is(err, os.ErrDeadlineExceeded), "%v", err)
}

func FuzzTargetFromConnectUDP(f *testing.F) {
	for _, seed := range []string{
		"/.well-known/masque/udp/example.test/443/",
		"/.well-known/masque/udp/2001%3Adb8%3A%3A1/53/",
		"/.well-known/masque/udp/10.0.0.1/8080/",
		"/.well-known/masque/udp/a%2Fb/443/",
		"/.well-known/masque/udp/[::1]/443/",
		"/.well-known/masque/udp/example.test/0/",
		"/.well-known/masque/udp/example.test/443",
		"/.well-known/masque/udp//443/",
		"/other/example.test/443/",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, path string) {
		u, err := url.ParseRequestURI(path)
		if err != nil {
			return
		}
		target, err := targetFromConnectUDP(&http.Request{Method: http.MethodConnect, URL: u})
		if err != nil {
			return
		}
		if target.Host == "" || target.Port == "" {
			t.Fatalf("accepted an empty authority from %q", path)
		}
		host, port := splitHostPort(target.Authority())
		if host != target.Host || port != target.Port {
			t.Fatalf("%q does not survive a rejoin: %q -> %q %q", path, target.Authority(), host, port)
		}
		if _, perr := strconv.ParseUint(port, 10, 16); perr != nil {
			t.Fatalf("accepted port %q", port)
		}
	})
}

func TestTargetFromConnectUDP_PortIsCanonical(t *testing.T) {
	u, err := url.ParseRequestURI(connectUDPPath + "example.test/0443/")
	require.NoError(t, err)
	target, err := targetFromConnectUDP(&http.Request{Method: http.MethodConnect, URL: u})
	require.NoError(t, err)
	assert.Equal(t, "443", target.Port)
}

func TestTargetFromWire_RootDotIsDropped(t *testing.T) {
	target, err := targetFromWire("Example.Test.", "443")
	require.NoError(t, err)
	assert.Equal(t, "example.test", target.Host)
	target, err = targetFromWire("127.0.0.1.", "443")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", target.Host)
	_, err = targetFromWire(".", "443")
	assert.Error(t, err)
}

func TestTargetFromWire_HostIsANameOrAnAddress(t *testing.T) {
	target, err := targetFromWire("2001:DB8::1", "443")
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::1", target.Host)
	for _, host := range []string{"origin.test:80", "[::1]", "a]b", "a b", "a/b", "a@b", "a?b", "a#b"} {
		_, err := targetFromWire(host, "443")
		assert.Error(t, err, host)
	}
}

func TestConnectUDP_NoServerNameGetsTheTargetsCertificate(t *testing.T) {
	probe, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	_ = probe.Close()

	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3OriginAt(t, originCA, "[::1]:0", "::1")
	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	upstream := DefaultTransport()
	upstream.AllowHTTP3 = true
	upstream.RootCAs = poolOf(originCA)
	p, err := New(WithCA(proxyCA), WithTransport(upstream))
	require.NoError(t, err)
	p.MustAdd("[::1]/+{any}", forwardHandler)
	front, _ := startQUICFront(t, p, proxyCA)
	cc := masqueClient(t, front, proxyCA)

	target := origin.String()
	pconn, _, err := openTunnel(t, cc, front, target, nil)
	require.NoError(t, err)
	inner, qconn := innerH3(t, pconn, origin, "::1", proxyCA)
	body, err := getThrough(inner, fmt.Sprintf("https://%s/echo", target))
	require.NoError(t, err)
	assert.Contains(t, body, "host="+target)

	leaf := qconn.ConnectionState().TLS.PeerCertificates[0]
	require.Len(t, leaf.IPAddresses, 1)
	assert.True(t, leaf.IPAddresses[0].Equal(net.ParseIP("::1")), "the certificate is for the declared target")
}

func TestConnectUDP_TunnelStaleOnTheKind(t *testing.T) {
	p, ca, front, origin := masqueProxy(t)
	cc := masqueClient(t, front, ca)
	target := fmt.Sprintf("%s:%d", h3Authority, origin.Port())
	_, _, err := openTunnel(t, cc, front, target, nil)
	require.NoError(t, err)

	tunnel := waitForSessions(t, p, 1)[0]
	require.True(t, tunnel.Tunnel())
	require.Equal(t, KindHTTP, tunnel.Kind())
	assert.False(t, tunnel.Stale())

	p.MustAdd(h3Authority+"/echo", forwardHandler)
	assert.False(t, tunnel.Stale(), "still admitted under HTTP")

	p.MustAdd[QUIC](h3Authority, relayQUIC)
	_, err = p.Delete[HTTP](h3Authority + "/+{any}")
	require.NoError(t, err)
	_, err = p.Delete[HTTP](h3Authority + "/echo")
	require.NoError(t, err)
	assert.True(t, tunnel.Stale(), "a new tunnel would be admitted under QUIC")
}

func TestConnectUDP_FlowSocketSetsDontFragment(t *testing.T) {
	fx := newUDPFixture(t)
	origin := newUDPOrigin(t, "127.0.0.1:0", nil)
	tun := fx.mustOpen(t, viaH1, udpReq{target: origin.addr.String()})
	tun.send(t, 0, []byte("ping"))
	origin.next(t)
	set, err := netutil.DontFragment(flowSocket(t, fx.p))
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skip("the Don't Fragment bit is set on Linux and darwin alone")
	}
	require.NoError(t, err)
	assert.True(t, set)
}

// fakeH3Stream is an HTTP/3 stream whose capsules are read from the Reader and whose QUIC
// datagrams arrive on dgrams. It records the first code each direction is cancelled with.
type fakeH3Stream struct {
	io.Reader
	dgrams    chan []byte
	readCode  atomic.Pointer[quic.StreamErrorCode]
	writeCode atomic.Pointer[quic.StreamErrorCode]
}

func (s *fakeH3Stream) Write(b []byte) (int, error)      { return len(b), nil }
func (s *fakeH3Stream) Close() error                     { return nil }
func (s *fakeH3Stream) SetWriteDeadline(time.Time) error { return nil }
func (s *fakeH3Stream) SendDatagram([]byte) error        { return nil }
func (s *fakeH3Stream) CancelRead(c quic.StreamErrorCode) {
	s.readCode.CompareAndSwap(nil, &c)
}

func (s *fakeH3Stream) CancelWrite(c quic.StreamErrorCode) {
	s.writeCode.CompareAndSwap(nil, &c)
}

func (s *fakeH3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case b := <-s.dgrams:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestConnectUDP_CleanEndOfTheHTTP3StreamResetsNothing(t *testing.T) {
	str := &fakeH3Stream{Reader: bytes.NewReader(capsuleOf(capsuleDatagram, httpDatagram(0, []byte("last")))), dgrams: make(chan []byte)}
	pipe := newDatagramPipe(str, quic.StreamErrorCode(http3.ErrCodeNoError), false)
	ended := make(chan struct{})
	pipe.run(func() { close(ended) })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	b, err := pipe.recv(ctx)
	require.NoError(t, err)
	assert.Equal(t, httpDatagram(0, []byte("last")), b)
	_, err = pipe.recv(ctx)
	require.ErrorIs(t, err, errTunnelEnded)
	<-ended
	assert.Nil(t, str.writeCode.Load(), "the stream was reset")
	assert.Nil(t, str.readCode.Load(), "the stream was stopped")
}

func TestConnectUDP_CapsuleQueuedAsRecvWaitsWakesIt(t *testing.T) {
	str := &fakeH3Stream{Reader: bytes.NewReader(nil), dgrams: make(chan []byte)}
	pipe := newDatagramPipe(str, quic.StreamErrorCode(http3.ErrCodeNoError), true)
	t.Cleanup(func() { _ = pipe.close() })
	want := httpDatagram(0, []byte("capsule"))
	pipe.checked = func() {
		pipe.checked = nil
		queued := make(chan struct{})
		// What readCapsules does with every DATAGRAM capsule.
		go func() {
			pipe.caps <- want
			pipe.wakeRecv(nil)
			close(queued)
		}()
		select {
		case <-queued:
		case <-time.After(50 * time.Millisecond):
		}
	}
	require.NoError(t, pipe.setReadDeadline(time.Now().Add(500*time.Millisecond)))
	b, err := pipe.recv(t.Context())
	require.NoError(t, err, "recv waited with a DATAGRAM capsule queued")
	assert.Equal(t, want, b)
}

func TestConnectUDP_ContentFieldsRefusedBeforeTheBody(t *testing.T) {
	fx := newUDPFixture(t)
	origin := newUDPOrigin(t, "127.0.0.1:0", nil)
	for _, h := range []http.Header{{"Content-Length": {"5"}}, {"Transfer-Encoding": {"chunked"}}} {
		tun := fx.open(t, viaH1, udpReq{target: origin.addr.String(), header: h})
		assert.Equal(t, http.StatusBadRequest, tun.status, "%v", h)
	}
}

func TestConnectUDP_HTTP3ReadDeadlineLeavesTheTunnelReadable(t *testing.T) {
	silent, end := io.Pipe()
	t.Cleanup(func() { _ = end.Close() })
	str := &fakeH3Stream{Reader: silent, dgrams: make(chan []byte, 1)}
	pipe := newDatagramPipe(str, quic.StreamErrorCode(http3.ErrCodeNoError), false)
	pipe.run(func() {})
	require.NoError(t, pipe.setReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, err := pipe.recv(t.Context())
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	str.dgrams <- httpDatagram(0, []byte("after"))
	require.NoError(t, pipe.setReadDeadline(time.Now().Add(5*time.Second)))
	b, err := pipe.recv(t.Context())
	require.NoError(t, err)
	assert.Equal(t, httpDatagram(0, []byte("after")), b)
}

func TestConnectUDP_OversizedDatagramAbortsTheHTTP3Stream(t *testing.T) {
	oversized := httpDatagram(0, make([]byte, maxCapsuleDatagram+1))
	silent, end := io.Pipe()
	t.Cleanup(func() { _ = end.Close() })
	for name, str := range map[string]*fakeH3Stream{
		"QUIC datagram":    {Reader: silent, dgrams: make(chan []byte, 1)},
		"DATAGRAM capsule": {Reader: bytes.NewReader(capsuleOf(capsuleDatagram, oversized)), dgrams: make(chan []byte)},
	} {
		t.Run(name, func(t *testing.T) {
			if cap(str.dgrams) > 0 {
				str.dgrams <- oversized
			}
			pipe := newDatagramPipe(str, quic.StreamErrorCode(http3.ErrCodeNoError), false)
			ended := make(chan struct{})
			pipe.run(func() { close(ended) })
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, err := pipe.recv(ctx)
			require.ErrorIs(t, err, errTunnelMalformed)
			require.NotNil(t, str.writeCode.Load(), "the stream was not reset")
			require.NotNil(t, str.readCode.Load(), "the stream was not stopped")
			assert.Equal(t, quic.StreamErrorCode(http3.ErrCodeMessageError), *str.writeCode.Load())
			assert.Equal(t, quic.StreamErrorCode(http3.ErrCodeMessageError), *str.readCode.Load())
		})
	}
}

// capsuleClient is a CONNECT-UDP client over a byte stream written from RFC 9297 and RFC
// 9298, the counterpart of what the proxy implements over HTTP/2 and HTTP/1.1. It is a
// net.PacketConn over the tunnel, every datagram in a DATAGRAM capsule with context ID 0.
type capsuleClient struct {
	rw       io.ReadWriteCloser
	in       chan []byte
	done     chan struct{}
	stalled  chan struct{}
	err      error
	deadline atomic.Pointer[time.Time]
	wmu      sync.Mutex
}

func newCapsuleClient(rw io.ReadWriteCloser) *capsuleClient {
	c := &capsuleClient{rw: rw, in: make(chan []byte), done: make(chan struct{}), stalled: make(chan struct{})}
	go c.read()
	return c
}

// stopReading parks the reader, so the proxy's writes fill the buffers and then block.
func (c *capsuleClient) stopReading() { close(c.stalled) }

// read parses the capsules the proxy sends. The error ending the stream is sticky, every
// reader of the tunnel sees it.
func (c *capsuleClient) read() {
	br := bufio.NewReader(c.rw)
	for {
		typ, err := quicvarint.Read(br)
		if err != nil {
			c.err = err
			close(c.done)
			return
		}
		length, err := quicvarint.Read(br)
		if err != nil {
			c.err = err
			close(c.done)
			return
		}
		value := make([]byte, length)
		if _, err := io.ReadFull(br, value); err != nil {
			c.err = err
			close(c.done)
			return
		}
		if typ != 0 {
			continue
		}
		select {
		case c.in <- value:
		case <-c.stalled:
			<-make(chan struct{})
		}
	}
}

func (c *capsuleClient) ReadFrom(b []byte) (int, net.Addr, error) {
	var timeout <-chan time.Time
	if dl := c.deadline.Load(); dl != nil && !dl.IsZero() {
		timer := time.NewTimer(time.Until(*dl))
		defer timer.Stop()
		timeout = timer.C
	}
	for {
		select {
		case value := <-c.in:
			id, n, err := quicvarint.Parse(value)
			if err != nil || id != 0 {
				continue
			}
			return copy(b, value[n:]), emptyAddr{}, nil
		case <-c.done:
			return 0, nil, c.err
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
}

func (c *capsuleClient) WriteTo(b []byte, _ net.Addr) (int, error) {
	out := make([]byte, 1+len(b))
	copy(out[1:], b)
	return len(b), c.writeCapsule(0, out)
}

// writeCapsule writes one capsule of any type, in as many writes as the caller wants to see
// it split into.
func (c *capsuleClient) writeCapsule(typ uint64, value []byte) error {
	hdr := quicvarint.Append(quicvarint.Append(nil, typ), uint64(len(value)))
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.rw.Write(hdr); err != nil {
		return err
	}
	_, err := c.rw.Write(value)
	return err
}

// CloseWrite ends the client's direction alone, a FIN on the stream.
func (c *capsuleClient) CloseWrite() error {
	return c.rw.(interface{ CloseWrite() error }).CloseWrite()
}

func (c *capsuleClient) Close() error                      { return c.rw.Close() }
func (c *capsuleClient) LocalAddr() net.Addr               { return emptyAddr{} }
func (c *capsuleClient) SetReadBuffer(int) error           { return nil }
func (c *capsuleClient) SetWriteBuffer(int) error          { return nil }
func (c *capsuleClient) SetDeadline(t time.Time) error     { return c.SetReadDeadline(t) }
func (c *capsuleClient) SetReadDeadline(t time.Time) error { c.deadline.Store(&t); return nil }
func (c *capsuleClient) SetWriteDeadline(time.Time) error  { return nil }

// startTLSFront serves p as an explicit proxy over TLS, offering protos in ALPN.
func startTLSFront(t *testing.T, p *Proxy, ca *CA, protos ...string) netip.AddrPort {
	t.Helper()
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	cfg := &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12, NextProtos: protos}
	go func() { _ = p.serveFront(tlsListener{Listener: cancelListener{ln}, cfg: cfg}) }()
	t.Cleanup(func() { _ = p.Close() })
	return netip.MustParseAddrPort(ln.Addr().String())
}

// tunnelOpener asks the front for a tunnel to target, host:port, with the given headers. A
// refusal returns the response the proxy answered with.
type tunnelOpener func(target string, header http.Header) (*capsuleClient, *http.Response, error)

// capsuleFront is one way of reaching the proxy over TCP, and how a tunnel is opened on it.
type capsuleFront struct {
	open  func(t *testing.T, front netip.AddrPort, ca *CA) tunnelOpener
	name  string
	alpn  string
	proto Protocol
}

var capsuleFronts = []capsuleFront{
	{name: "h2", alpn: "h2", proto: HTTP2, open: openTunnelsH2},
	{name: "h1", alpn: "http/1.1", proto: HTTP11, open: openTunnelsH1},
}

// extendedConnectEnabled reports whether Go's HTTP/2 server accepts an extended CONNECT,
// which it does behind GODEBUG=http2xconnect=1, read from the environment at startup.
func extendedConnectEnabled() bool {
	return strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1")
}

// skipWithoutExtendedConnect skips a test of the HTTP/2 front unless Go's server accepts
// extended CONNECT.
func skipWithoutExtendedConnect(t *testing.T, f capsuleFront) {
	t.Helper()
	if f.alpn == "h2" && !extendedConnectEnabled() {
		t.Skip("run with GODEBUG=http2xconnect=1, Go's HTTP/2 server refuses extended CONNECT without it")
	}
}

func connectUDPURL(front netip.AddrPort, target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("https://%s%s%s/%s/", front, connectUDPPath, url.PathEscape(host), port), nil
}

func dialFront(t *testing.T, front netip.AddrPort, ca *CA, alpn string) *tls.Conn {
	t.Helper()
	tc, err := tls.Dial("tcp", front.String(), &tls.Config{
		RootCAs:    poolOf(ca),
		ServerName: "127.0.0.1",
		NextProtos: []string{alpn},
		MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, err)
	require.Equal(t, alpn, tc.ConnectionState().NegotiatedProtocol)
	return tc
}

// openTunnelsH2 opens one HTTP/2 connection to the front and returns an opener sending an
// extended CONNECT on it for every tunnel, RFC 9298 section 3.4. Go's client cannot send one,
// so the connection is the proxy's own client.
func openTunnelsH2(t *testing.T, front netip.AddrPort, ca *CA) tunnelOpener {
	t.Helper()
	tc := dialFront(t, front, ca, "h2")
	cc, err := h2tunnel.Client(tc, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return func(target string, header http.Header) (*capsuleClient, *http.Response, error) {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			return nil, nil, err
		}
		req := h2tunnel.Request{
			Protocol:  "connect-udp",
			Scheme:    "https",
			Authority: front.String(),
			Path:      connectUDPPath + url.PathEscape(host) + "/" + port + "/",
			Header:    http.Header{http3.CapsuleProtocolHeader: {"?1"}},
		}
		for k, vv := range header {
			req.Header[k] = vv
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		str, resp, err := cc.Open(ctx, req)
		if err != nil {
			return nil, nil, err
		}
		hresp := &http.Response{StatusCode: resp.StatusCode, Header: resp.Header}
		if resp.StatusCode != http.StatusOK {
			_ = str.Close()
			return nil, hresp, fmt.Errorf("CONNECT-UDP refused with %d", resp.StatusCode)
		}
		c := newCapsuleClient(str)
		t.Cleanup(func() { _ = c.Close() })
		return c, hresp, nil
	}
}

// h1TunnelStream is the client side of a connection an Upgrade left behind, read through the
// buffer the response was read with.
type h1TunnelStream struct {
	*tls.Conn
	br *bufio.Reader
}

func (s *h1TunnelStream) Read(b []byte) (int, error) { return s.br.Read(b) }

// openTunnelsH1 returns an opener dialing the front and sending a GET with an Upgrade for
// every tunnel, RFC 9298 section 3.2.
func openTunnelsH1(t *testing.T, front netip.AddrPort, ca *CA) tunnelOpener {
	t.Helper()
	return func(target string, header http.Header) (*capsuleClient, *http.Response, error) {
		u, err := connectUDPURL(front, target)
		if err != nil {
			return nil, nil, err
		}
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "connect-udp")
		req.Header.Set(http3.CapsuleProtocolHeader, "?1")
		for k, vv := range header {
			req.Header[k] = vv
		}
		tc := dialFront(t, front, ca, "http/1.1")
		t.Cleanup(func() { _ = tc.Close() })
		if err := req.WriteProxy(tc); err != nil {
			return nil, nil, err
		}
		br := bufio.NewReader(tc)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return nil, nil, err
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			_ = resp.Body.Close()
			return nil, resp, fmt.Errorf("CONNECT-UDP refused with %d", resp.StatusCode)
		}
		c := newCapsuleClient(&h1TunnelStream{Conn: tc, br: br})
		return c, resp, nil
	}
}

func TestConnectUDP_Capsules_TerminatesTheInnerHTTP3(t *testing.T) {
	for _, f := range capsuleFronts {
		t.Run(f.name, func(t *testing.T) {
			skipWithoutExtendedConnect(t, f)
			p, ca, origin := newMasqueProxy(t)
			front := startTLSFront(t, p, ca, f.alpn)
			open := f.open(t, front, ca)
			target := fmt.Sprintf("%s:%d", h3Authority, origin.Port())

			pconn, resp, err := open(target, nil)
			require.NoError(t, err)
			assert.Equal(t, "?1", resp.Header.Get(http3.CapsuleProtocolHeader))

			inner, _ := innerH3(t, pconn, origin, h3Authority, ca)
			body, err := getThrough(inner, fmt.Sprintf("https://%s/echo", target))
			require.NoError(t, err)
			assert.Contains(t, body, "path=/echo")
			assert.Contains(t, body, "proto=HTTP/3.0", "the origin was reached over HTTP/3")

			var tunnel, conn *Session
			for _, s := range waitForSessions(t, p, 2) {
				if s.Tunnel() {
					tunnel = s
				} else {
					conn = s
				}
			}
			require.NotNil(t, tunnel)
			require.NotNil(t, conn)
			assert.Equal(t, KindHTTP, tunnel.Kind())
			assert.Equal(t, f.proto, tunnel.Protocol())
			assert.Equal(t, h3Authority, tunnel.Target().Host)
			assert.Equal(t, origin, tunnel.Upstream())
			assert.NotNil(t, tunnel.TLS(), "the front handshake")
			assert.Nil(t, tunnel.Via())
			assert.Same(t, tunnel, conn.Via())
			assert.Equal(t, HTTP3, conn.Protocol())
			assert.Equal(t, tunnel.RemoteAddr(), conn.RemoteAddr())

			// Closing the tunnel ends what it carries, and the client sees its stream end.
			require.NoError(t, tunnel.Close())
			assertSessionEnded(t, p, tunnel)
			waitForSessions(t, p, 0)
			require.NoError(t, pconn.SetReadDeadline(time.Now().Add(5*time.Second)))
			_, _, err = pconn.ReadFrom(make([]byte, 64))
			require.Error(t, err)
			assert.NotErrorIs(t, err, os.ErrDeadlineExceeded, "the stream ended rather than went quiet")

			// The front connection survives, and a new tunnel is decided afresh.
			pconn2, _, err := open(target, nil)
			require.NoError(t, err)
			again, _ := innerH3(t, pconn2, origin, h3Authority, ca)
			body, err = getThrough(again, fmt.Sprintf("https://%s/again", target))
			require.NoError(t, err)
			assert.Contains(t, body, "path=/again")
		})
	}
}

func TestConnectUDP_Capsules_RoutesRawDatagramsOnTheDeclaredTarget(t *testing.T) {
	for _, f := range capsuleFronts {
		t.Run(f.name, func(t *testing.T) {
			skipWithoutExtendedConnect(t, f)
			echo := udpEcho(t)
			ca, err := GenerateCA()
			require.NoError(t, err)
			resolver := &fakeResolver{addrs: map[string][]netip.Addr{"echo.udp.test": {echo.Addr()}}}
			p, err := New(WithCA(ca), WithNameResolver(resolver))
			require.NoError(t, err)
			seen := new(recorder)
			p.MustAdd[UDP](fmt.Sprintf("{name}.udp.test:%d", echo.Port()), func(c *DatagramCtx) error {
				seen.add(fmt.Sprintf("%s %s %v %s", c.Param("name"), c.Target().Host, c.Inbound(), c.Bytes()))
				return c.Forward()
			})
			front := startTLSFront(t, p, ca, f.alpn)
			open := f.open(t, front, ca)

			pconn, _, err := open(fmt.Sprintf("echo.udp.test:%d", echo.Port()), nil)
			require.NoError(t, err)
			_, err = pconn.WriteTo([]byte("ping"), nil)
			require.NoError(t, err)
			require.NoError(t, pconn.SetReadDeadline(time.Now().Add(5*time.Second)))
			buf := make([]byte, 64)
			n, _, err := pconn.ReadFrom(buf)
			require.NoError(t, err)
			assert.Equal(t, "ping", string(buf[:n]))
			assert.Equal(t, []string{"echo echo.udp.test false ping", "echo echo.udp.test true ping"}, seen.all())

			for _, s := range waitForSessions(t, p, 2) {
				assert.Equal(t, KindUDP, s.Kind())
				assert.Equal(t, "echo.udp.test", s.Target().Host)
				if s.Tunnel() {
					assert.Equal(t, f.proto, s.Protocol())
				} else {
					require.NotNil(t, s.Via())
				}
			}
		})
	}
}

func TestConnectUDP_Capsules_RefusesBeforeTheTunnelExists(t *testing.T) {
	for _, f := range capsuleFronts {
		t.Run(f.name, func(t *testing.T) {
			skipWithoutExtendedConnect(t, f)
			ca, err := GenerateCA()
			require.NoError(t, err)
			resolver := &fakeResolver{addrs: map[string][]netip.Addr{"spray.test": addrsOf("10.9.9.9")}}
			p, err := New(WithCA(ca), WithNameResolver(resolver))
			require.NoError(t, err)
			p.MustAdd("unresolved.test/+{any}", forwardHandler)
			front := startTLSFront(t, p, ca, f.alpn)
			open := f.open(t, front, ca)

			_, resp, err := open("spray.test:443", nil)
			require.Error(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, http.StatusForbidden, resp.StatusCode, "a name no entry admits")
			assert.Zero(t, resolver.calls.Load(), "a refused name is not resolved")

			_, resp, err = open("unresolved.test:443", nil)
			require.Error(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, http.StatusBadGateway, resp.StatusCode, "a name the proxy cannot resolve")
			assert.Empty(t, waitForSessions(t, p, 0))
		})
	}
}

func TestConnectUDP_Capsules_ClientEndEndsTheTunnel(t *testing.T) {
	for _, f := range capsuleFronts {
		t.Run(f.name, func(t *testing.T) {
			skipWithoutExtendedConnect(t, f)
			p, ca, origin := newMasqueProxy(t)
			front := startTLSFront(t, p, ca, f.alpn)
			open := f.open(t, front, ca)
			target := fmt.Sprintf("%s:%d", h3Authority, origin.Port())

			pconn, _, err := open(target, nil)
			require.NoError(t, err)
			inner, innerConn := innerH3(t, pconn, origin, h3Authority, ca)
			_, err = getThrough(inner, fmt.Sprintf("https://%s/echo", target))
			require.NoError(t, err)
			waitForSessions(t, p, 2)
			require.NoError(t, pconn.CloseWrite())
			waitForSessions(t, p, 0)
			requireEnded(t, innerConn, "the inner connection is closed through the tunnel")

			pconn, _, err = open(target, nil)
			require.NoError(t, err)
			inner, innerConn = innerH3(t, pconn, origin, h3Authority, ca)
			_, err = getThrough(inner, fmt.Sprintf("https://%s/echo", target))
			require.NoError(t, err)
			waitForSessions(t, p, 2)
			require.NoError(t, pconn.Close())
			waitForSessions(t, p, 0)
			requireEnded(t, innerConn, "the inner connection ends with the stream")
		})
	}
}

func TestConnectUDP_Capsules_SkipsWhatIsNotADatagram(t *testing.T) {
	for _, f := range capsuleFronts {
		t.Run(f.name, func(t *testing.T) {
			skipWithoutExtendedConnect(t, f)
			echo := udpEcho(t)
			ca, err := GenerateCA()
			require.NoError(t, err)
			p, err := New(WithCA(ca))
			require.NoError(t, err)
			p.MustAdd[UDP]("127.0.0.1", forwardDatagram)
			front := startTLSFront(t, p, ca, f.alpn)
			open := f.open(t, front, ca)

			pconn, _, err := open(echo.String(), nil)
			require.NoError(t, err)
			require.NoError(t, pconn.writeCapsule(0x2b, []byte("an extension the proxy does not know")))
			require.NoError(t, pconn.writeCapsule(0, httpDatagram(2, make([]byte, maxCapsuleDatagram+1))))
			_, err = pconn.WriteTo([]byte("still here"), nil)
			require.NoError(t, err)
			require.NoError(t, pconn.SetReadDeadline(time.Now().Add(5*time.Second)))
			buf := make([]byte, 64)
			n, _, err := pconn.ReadFrom(buf)
			require.NoError(t, err)
			assert.Equal(t, "still here", string(buf[:n]))

			_ = pconn.writeCapsule(0, httpDatagram(0, make([]byte, maxCapsuleDatagram+1)))
			_, _, err = pconn.ReadFrom(buf)
			require.Error(t, err, "a datagram of context ID 0 past 65527 bytes left the tunnel open")
			assert.False(t, isTimeout(err), "a datagram of context ID 0 past 65527 bytes left the tunnel open")
		})
	}
}

// udpFlood answers every datagram with a burst of large ones, enough to fill every buffer
// between the proxy and a client that stopped reading.
func udpFlood(t *testing.T, bursts, size int) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		payload := make([]byte, size)
		for {
			_, addr, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			for range bursts {
				if _, werr := pc.WriteTo(payload, addr); werr != nil {
					return
				}
			}
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func TestConnectUDP_Capsules_CloseEndsAStalledClient(t *testing.T) {
	for _, f := range capsuleFronts {
		t.Run(f.name, func(t *testing.T) {
			skipWithoutExtendedConnect(t, f)
			flood := udpFlood(t, 20000, 1400)
			ca, err := GenerateCA()
			require.NoError(t, err)
			p, err := New(WithCA(ca))
			require.NoError(t, err)
			p.MustAdd[UDP]("127.0.0.1", forwardDatagram)
			front := startTLSFront(t, p, ca, f.alpn)
			open := f.open(t, front, ca)

			pconn, _, err := open(flood.String(), nil)
			require.NoError(t, err)
			// Nothing reads the tunnel past this point, the burst fills what it can.
			pconn.stopReading()
			for range 3 {
				_, err = pconn.WriteTo([]byte("go"), nil)
				require.NoError(t, err)
				time.Sleep(200 * time.Millisecond)
			}
			var tunnel *Session
			for _, s := range waitForSessions(t, p, 2) {
				if s.Tunnel() {
					tunnel = s
				}
			}
			require.NotNil(t, tunnel)

			start := time.Now()
			require.NoError(t, tunnel.Close())
			assert.Less(t, time.Since(start), time.Second, "Close waited on the client")
			assert.Eventually(t, func() bool { return len(slices.Collect(p.Sessions())) == 0 },
				3*time.Second, 20*time.Millisecond, "the tunnel outlived its close")
		})
	}
}

func TestConnectUDP_CloseEndsAnH2TunnelBehindAClientThatStoppedReadingItsConnection(t *testing.T) {
	if !extendedConnectEnabled() {
		t.Skip("needs GODEBUG=http2xconnect=1")
	}
	fx := newUDPFixture(t)
	flood := udpFlood(t, 20000, 1200)
	front := fx.frontAddr(t, viaH2)
	tc := dialFront(t, netip.MustParseAddrPort(front), fx.ca, "h2")
	t.Cleanup(func() { _ = tc.Close() })
	_, err := tc.Write([]byte(http2.ClientPreface))
	require.NoError(t, err)
	fr := http2.NewFramer(tc, tc)
	require.NoError(t, fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1<<31 - 1}))
	require.NoError(t, fr.WriteWindowUpdate(0, 1<<31-1-65535))
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":protocol", Value: connectUDPUpgrade},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: front},
		{Name: ":path", Value: templatePath(flood.String())},
		{Name: "capsule-protocol", Value: "?1"},
	} {
		require.NoError(t, enc.WriteField(f))
	}
	require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: buf.Bytes(), EndHeaders: true}))
	require.NoError(t, fr.WriteData(1, false, capsuleOf(0, append([]byte{0}, "go"...))))
	// Nothing reads the connection, the flood fills the socket.
	time.Sleep(1500 * time.Millisecond)

	var tunnel *Session
	for s := range fx.p.Sessions() {
		if s.Tunnel() {
			tunnel = s
		}
	}
	require.NotNil(t, tunnel)
	closed := make(chan error, 1)
	go func() { closed <- tunnel.Close() }()
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("Session.Close waited for the client to read its connection")
	}
	assertSessionEnded(t, fx.p, tunnel)
}

func TestConformanceConnectUDP(t *testing.T) {
	runConformance(t, connectUDPConformance)
}

const (
	viaH3 = "h3"
	viaH2 = "h2"
	viaH1 = "h1"
)

var (
	allFronts     = []string{viaH3, viaH2, viaH1}
	connectFronts = []string{viaH3, viaH2}
)

func eachFront(t *testing.T, fronts []string, run func(t *testing.T, front string)) {
	t.Helper()
	for _, front := range fronts {
		t.Run(front, func(t *testing.T) {
			if front == viaH2 && !extendedConnectEnabled() {
				t.Skip("run with GODEBUG=http2xconnect=1, Go's HTTP/2 server refuses extended CONNECT without it")
			}
			run(t, front)
		})
	}
}

func eachExit(t *testing.T, versions []string, run func(t *testing.T, version string)) {
	t.Helper()
	for _, v := range versions {
		t.Run(v, func(t *testing.T) { run(t, v) })
	}
}

type udpFixture struct {
	p        *Proxy
	ca       *CA
	resolver *fakeResolver
	h3cc     *http3.ClientConn
	h3qc     *quic.Conn
	h2c      *h2Raw
	h1       string
	h3       netip.AddrPort
	h2       netip.AddrPort
}

func newUDPFixture(t *testing.T) *udpFixture {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	resolver := &fakeResolver{addrs: map[string][]netip.Addr{"echo.udp.test": addrsOf("127.0.0.1")}}
	p, err := New(WithCA(ca), WithNameResolver(resolver))
	require.NoError(t, err)
	for _, pattern := range []string{"127.0.0.1", "[::1]", "echo.udp.test", "unresolved.udp.test"} {
		p.MustAdd[UDP](pattern, forwardDatagram)
	}
	return &udpFixture{p: p, ca: ca, resolver: resolver}
}

func (fx *udpFixture) frontAddr(t *testing.T, front string) string {
	t.Helper()
	switch front {
	case viaH3:
		if !fx.h3.IsValid() {
			fx.h3, _ = startQUICFront(t, fx.p, fx.ca)
		}
		return fx.h3.String()
	case viaH2:
		if !fx.h2.IsValid() {
			fx.h2 = startTLSFront(t, fx.p, fx.ca, "h2")
		}
		return fx.h2.String()
	}
	if fx.h1 == "" {
		fx.h1 = startProxy(t, fx.p)
	}
	return fx.h1
}

// udpReq is a CONNECT-UDP request as a peer writes it, the fields RFC 9298 shows in its
// examples unless a scenario sets them. A header field with no value removes a default one.
type udpReq struct {
	header    http.Header
	target    string
	path      string
	protocol  string
	authority string
	method    string
	early     []byte
}

func templatePath(target string) string {
	host, port, _ := net.SplitHostPort(target)
	return connectUDPPath + strings.ReplaceAll(url.PathEscape(host), ":", "%3A") + "/" + port + "/"
}

func (r udpReq) resolve(front string) (path, protocol, authority string) {
	path, protocol, authority = r.path, r.protocol, r.authority
	if path == "" {
		path = templatePath(r.target)
	}
	if protocol == "" {
		protocol = connectUDPUpgrade
	}
	if authority == "" {
		authority = front
	}
	return path, protocol, authority
}

func (r udpReq) headerOver(defaults http.Header) http.Header {
	for k, v := range r.header {
		if len(v) == 0 {
			defaults.Del(k)
			continue
		}
		defaults[http.CanonicalHeaderKey(k)] = v
	}
	return defaults
}

type capsuleMsg struct {
	value []byte
	typ   uint64
}

type udpTunnel struct {
	err    error
	header http.Header
	dgrams chan []byte
	caps   chan capsuleMsg
	end    chan error
	sendDG func([]byte) error
	write  func([]byte) error
	finish func() error
	status int
}

func newUDPTunnel() *udpTunnel {
	return &udpTunnel{caps: make(chan capsuleMsg, 64), end: make(chan error, 1)}
}

func httpDatagram(id uint64, payload []byte) []byte {
	return append(quicvarint.Append(nil, id), payload...)
}

func capsuleOf(typ uint64, value []byte) []byte {
	return append(quicvarint.Append(quicvarint.Append(nil, typ), uint64(len(value))), value...)
}

func succeeded(status int) bool {
	return status == http.StatusSwitchingProtocols || status >= 200 && status < 300
}

// h3ResetCode returns the code a peer reset an HTTP/3 stream with.
func h3ResetCode(err error) (http3.ErrCode, bool) {
	if e, ok := errors.AsType[*http3.Error](err); ok {
		return e.ErrorCode, true
	}
	if e, ok := errors.AsType[*quic.StreamError](err); ok {
		return http3.ErrCode(e.ErrorCode), true
	}
	return 0, false
}

func (fx *udpFixture) open(t *testing.T, front string, req udpReq) *udpTunnel {
	t.Helper()
	switch front {
	case viaH3:
		tun, _ := fx.openH3(t, req)
		return tun
	case viaH2:
		return fx.openH2(t, req)
	}
	return fx.openH1(t, req)
}

func (fx *udpFixture) mustOpen(t *testing.T, front string, req udpReq) *udpTunnel {
	t.Helper()
	tun := fx.open(t, front, req)
	require.NoError(t, tun.err)
	want := http.StatusOK
	if front == viaH1 {
		want = http.StatusSwitchingProtocols
	}
	require.Equal(t, want, tun.status)
	return tun
}

func (u *udpTunnel) send(t *testing.T, id uint64, payload []byte) {
	t.Helper()
	if u.sendDG != nil {
		require.NoError(t, u.sendDG(httpDatagram(id, payload)))
		return
	}
	require.NoError(t, u.write(capsuleOf(capsuleDatagram, httpDatagram(id, payload))))
}

func (u *udpTunnel) recv(t *testing.T) []byte {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		var dg []byte
		select {
		case dg = <-u.dgrams:
		case c := <-u.caps:
			if c.typ != capsuleDatagram {
				continue
			}
			dg = c.value
		case err := <-u.end:
			t.Fatalf("the tunnel ended with %v", err)
		case <-timeout:
			t.Fatal("no datagram from the proxy")
		}
		if id, n, err := quicvarint.Parse(dg); err == nil && id == 0 {
			return dg[n:]
		}
	}
}

func (u *udpTunnel) quiet(t *testing.T) {
	t.Helper()
	select {
	case dg := <-u.dgrams:
		t.Fatalf("a QUIC datagram of %d bytes arrived", len(dg))
	case c := <-u.caps:
		t.Fatalf("a capsule of type %d and %d bytes arrived", c.typ, len(c.value))
	case <-time.After(300 * time.Millisecond):
	}
}

func (u *udpTunnel) waitEnd(t *testing.T) error {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case <-u.dgrams:
		case <-u.caps:
		case err := <-u.end:
			return err
		case <-timeout:
			t.Fatal("the tunnel did not end")
			return nil
		}
	}
}

// readCapsule reads one capsule, or one HTTP/3 frame, which has the same layout. A stream
// ending inside one is io.ErrUnexpectedEOF.
func readCapsule(br *bufio.Reader) (uint64, []byte, error) {
	typ, err := quicvarint.Read(br)
	if err != nil {
		return 0, nil, err
	}
	length, err := quicvarint.Read(br)
	if err == nil && length > 1<<20 {
		err = fmt.Errorf("a capsule of %d bytes", length)
	}
	var value []byte
	if err == nil {
		value = make([]byte, length)
		_, err = io.ReadFull(br, value)
	}
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return typ, value, err
}

func readCapsules(ctx context.Context, r io.Reader, caps chan<- capsuleMsg, end chan<- error) {
	br := bufio.NewReader(r)
	for {
		typ, value, err := readCapsule(br)
		if err != nil {
			end <- err
			return
		}
		select {
		case caps <- capsuleMsg{typ: typ, value: value}:
		case <-ctx.Done():
			return
		}
	}
}

func dialH3(t *testing.T, addr string, ca *CA, datagrams bool) (*http3.ClientConn, *quic.Conn) {
	t.Helper()
	pc, err := loopbackUDP()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ua, err := net.ResolveUDPAddr("udp", addr)
	require.NoError(t, err)
	qconn, err := quic.Dial(ctx, pc, ua, &tls.Config{
		RootCAs:    poolOf(ca),
		ServerName: "127.0.0.1",
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	if err != nil {
		_ = pc.Close()
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = qconn.CloseWithError(0, "")
		_ = pc.Close()
	})
	tr := &http3.Transport{EnableDatagrams: datagrams}
	t.Cleanup(func() { _ = tr.Close() })
	cc := tr.NewClientConn(qconn)
	select {
	case <-cc.ReceivedSettings():
	case <-time.After(5 * time.Second):
		t.Fatal("no SETTINGS from the proxy")
	}
	return cc, qconn
}

func (fx *udpFixture) h3Conn(t *testing.T) (*http3.ClientConn, *quic.Conn) {
	t.Helper()
	if fx.h3cc == nil {
		fx.h3cc, fx.h3qc = dialH3(t, fx.frontAddr(t, viaH3), fx.ca, true)
	}
	return fx.h3cc, fx.h3qc
}

func (fx *udpFixture) openH3(t *testing.T, req udpReq) (*udpTunnel, *http3.RequestStream) {
	t.Helper()
	cc, _ := fx.h3Conn(t)
	path, protocol, authority := req.resolve(fx.h3.String())
	u, err := url.Parse("https://" + authority + path)
	require.NoError(t, err)
	r := &http.Request{
		Method: http.MethodConnect, Proto: protocol, URL: u, Host: authority,
		Header: req.headerOver(http.Header{http3.CapsuleProtocolHeader: {"?1"}}),
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	str, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
	})
	require.NoError(t, str.SendRequestHeader(r))
	tun := newUDPTunnel()
	require.NoError(t, str.SetReadDeadline(time.Now().Add(5*time.Second)))
	resp, err := str.ReadResponse()
	if err != nil {
		tun.err = err
		return tun, str
	}
	require.NoError(t, str.SetReadDeadline(time.Time{}))
	tun.status, tun.header = resp.StatusCode, resp.Header
	tun.dgrams = make(chan []byte, 64)
	tun.sendDG = str.SendDatagram
	tun.write = func(b []byte) error { _, err := str.Write(b); return err }
	tun.finish = str.Close
	done := t.Context()
	go func() {
		for {
			dg, err := str.ReceiveDatagram(done)
			if err != nil {
				return
			}
			select {
			case tun.dgrams <- dg:
			case <-done.Done():
				return
			}
		}
	}()
	go readCapsules(done, str, tun.caps, tun.end)
	return tun, str
}

func (fx *udpFixture) openH1(t *testing.T, req udpReq) *udpTunnel {
	t.Helper()
	addr := fx.frontAddr(t, viaH1)
	path, _, authority := req.resolve(addr)
	header := req.headerOver(http.Header{
		"Connection":                {"Upgrade"},
		"Upgrade":                   {connectUDPUpgrade},
		http3.CapsuleProtocolHeader: {"?1"},
	})
	var head strings.Builder
	fmt.Fprintf(&head, "%s %s HTTP/1.1\r\nHost: %s\r\n", cmp.Or(req.method, http.MethodGet), path, authority)
	for k, vv := range header {
		for _, v := range vv {
			fmt.Fprintf(&head, "%s: %s\r\n", k, v)
		}
	}
	head.WriteString("\r\n")

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_, err = conn.Write(append([]byte(head.String()), req.early...))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	br := bufio.NewReader(conn)
	tun := newUDPTunnel()
	tun.status, tun.header = readHead(t, br)
	require.NoError(t, conn.SetReadDeadline(time.Time{}))
	if tun.status != http.StatusSwitchingProtocols {
		return tun
	}
	tun.write = func(b []byte) error { _, err := conn.Write(b); return err }
	tun.finish = conn.(*net.TCPConn).CloseWrite
	go readCapsules(t.Context(), br, tun.caps, tun.end)
	return tun
}

// readHead reads the head of an HTTP/1.1 response field by field, so a field sent twice
// stays twice and none is folded into the framing.
func readHead(t *testing.T, br *bufio.Reader) (int, http.Header) {
	t.Helper()
	line, err := br.ReadString('\n')
	require.NoError(t, err)
	parts := strings.SplitN(strings.TrimRight(line, "\r\n"), " ", 3)
	require.GreaterOrEqual(t, len(parts), 2, "status line %q", line)
	status, err := strconv.Atoi(parts[1])
	require.NoError(t, err)
	header := http.Header{}
	for {
		line, err = br.ReadString('\n')
		require.NoError(t, err)
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return status, header
		}
		k, v, ok := strings.Cut(line, ":")
		require.True(t, ok, "field line %q", line)
		header.Add(k, strings.TrimSpace(v))
	}
}

// h2Raw is an HTTP/2 client written on the framer, so what it sends is what the test wrote.
type h2Raw struct {
	fr       *http2.Framer
	enc      *hpack.Encoder
	settings chan map[http2.SettingID]uint32
	streams  map[uint32]chan h2Event
	buf      bytes.Buffer
	wmu      sync.Mutex
	mu       sync.Mutex
	next     uint32
}

type h2Event struct {
	err  error
	head *http2.MetaHeadersFrame
	data []byte
}

func dialH2Raw(t *testing.T, addr string, ca *CA) *h2Raw {
	t.Helper()
	tc := dialFront(t, netip.MustParseAddrPort(addr), ca, "h2")
	t.Cleanup(func() { _ = tc.Close() })
	_, err := io.WriteString(tc, http2.ClientPreface)
	require.NoError(t, err)
	c := &h2Raw{
		fr:       http2.NewFramer(tc, tc),
		settings: make(chan map[http2.SettingID]uint32, 1),
		streams:  make(map[uint32]chan h2Event),
		next:     1,
	}
	c.enc = hpack.NewEncoder(&c.buf)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	require.NoError(t, c.fr.WriteSettings())
	go c.read()
	return c
}

func (c *h2Raw) control(f func(fr *http2.Framer) error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = f(c.fr)
}

func (c *h2Raw) read() {
	first := true
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			c.mu.Lock()
			streams := slices.Collect(maps.Values(c.streams))
			c.mu.Unlock()
			for _, ch := range streams {
				ch <- h2Event{err: err}
			}
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			if first {
				first = false
				got := make(map[http2.SettingID]uint32)
				_ = f.ForeachSetting(func(s http2.Setting) error { got[s.ID] = s.Val; return nil })
				c.settings <- got
			}
			c.control(func(fr *http2.Framer) error { return fr.WriteSettingsAck() })
		case *http2.PingFrame:
			if !f.IsAck() {
				c.control(func(fr *http2.Framer) error { return fr.WritePing(true, f.Data) })
			}
		case *http2.MetaHeadersFrame:
			c.deliver(f.StreamID, h2Event{head: f})
			if f.StreamEnded() {
				c.deliver(f.StreamID, h2Event{err: io.EOF})
			}
		case *http2.DataFrame:
			if n := uint32(len(f.Data())); n > 0 {
				c.control(func(fr *http2.Framer) error {
					if !f.StreamEnded() {
						_ = fr.WriteWindowUpdate(f.StreamID, n)
					}
					return fr.WriteWindowUpdate(0, n)
				})
				c.deliver(f.StreamID, h2Event{data: bytes.Clone(f.Data())})
			}
			if f.StreamEnded() {
				c.deliver(f.StreamID, h2Event{err: io.EOF})
			}
		case *http2.RSTStreamFrame:
			c.deliver(f.StreamID, h2Event{err: http2.StreamError{StreamID: f.StreamID, Code: f.ErrCode}})
		}
	}
}

func (c *h2Raw) deliver(id uint32, ev h2Event) {
	c.mu.Lock()
	ch := c.streams[id]
	c.mu.Unlock()
	if ch != nil {
		ch <- ev
	}
}

func (c *h2Raw) serverSettings(t *testing.T) map[http2.SettingID]uint32 {
	t.Helper()
	select {
	case s := <-c.settings:
		c.settings <- s
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("no SETTINGS from the proxy")
		return nil
	}
}

func (c *h2Raw) open(t *testing.T, fields []hpack.HeaderField) (uint32, chan h2Event) {
	t.Helper()
	c.mu.Lock()
	id := c.next
	c.next += 2
	events := make(chan h2Event, 1024)
	c.streams[id] = events
	c.mu.Unlock()
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.buf.Reset()
	for _, f := range fields {
		require.NoError(t, c.enc.WriteField(f))
	}
	require.NoError(t, c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: c.buf.Bytes(), EndHeaders: true}))
	return id, events
}

func (c *h2Raw) data(id uint32, b []byte, end bool) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	for len(b) > 16384 {
		if err := c.fr.WriteData(id, false, b[:16384]); err != nil {
			return err
		}
		b = b[16384:]
	}
	return c.fr.WriteData(id, end, b)
}

func (fx *udpFixture) h2Conn(t *testing.T) *h2Raw {
	t.Helper()
	if fx.h2c == nil {
		fx.h2c = dialH2Raw(t, fx.frontAddr(t, viaH2), fx.ca)
	}
	return fx.h2c
}

func (fx *udpFixture) openH2(t *testing.T, req udpReq) *udpTunnel {
	t.Helper()
	path, protocol, authority := req.resolve(fx.frontAddr(t, viaH2))
	fields := []hpack.HeaderField{
		{Name: ":method", Value: cmp.Or(req.method, http.MethodConnect)},
		{Name: ":protocol", Value: protocol},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	}
	for k, vv := range req.headerOver(http.Header{http3.CapsuleProtocolHeader: {"?1"}}) {
		for _, v := range vv {
			fields = append(fields, hpack.HeaderField{Name: strings.ToLower(k), Value: v})
		}
	}
	return fx.h2Tunnel(t, fields, req.early)
}

func (fx *udpFixture) h2Tunnel(t *testing.T, fields []hpack.HeaderField, early []byte) *udpTunnel {
	t.Helper()
	c := fx.h2Conn(t)
	id, events := c.open(t, fields)
	if len(early) > 0 {
		require.NoError(t, c.data(id, early, false))
	}
	tun := newUDPTunnel()
	select {
	case ev := <-events:
		if ev.head == nil {
			tun.err = cmp.Or(ev.err, errors.New("DATA ahead of the answer"))
			return tun
		}
		tun.status, _ = strconv.Atoi(ev.head.PseudoValue("status"))
		tun.header = http.Header{}
		for _, hf := range ev.head.RegularFields() {
			tun.header.Add(hf.Name, hf.Value)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no answer from the proxy")
	}
	tun.write = func(b []byte) error { return c.data(id, b, false) }
	tun.finish = func() error { return c.data(id, nil, true) }
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })
	go func() {
		for ev := range events {
			if ev.data != nil {
				if _, err := pw.Write(ev.data); err != nil {
					return
				}
			}
			if ev.err != nil {
				if errors.Is(ev.err, io.EOF) {
					_ = pw.Close()
				} else {
					_ = pw.CloseWithError(ev.err)
				}
				return
			}
		}
	}()
	go readCapsules(t.Context(), pr, tun.caps, tun.end)
	return tun
}

type originDatagram struct {
	from net.Addr
	b    []byte
}

type udpOrigin struct {
	pc   net.PacketConn
	got  chan originDatagram
	addr netip.AddrPort
}

func echoReply(b []byte) [][]byte { return [][]byte{b} }

func newUDPOrigin(t *testing.T, laddr string, reply func([]byte) [][]byte) *udpOrigin {
	t.Helper()
	pc, err := net.ListenPacket("udp", laddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })
	o := &udpOrigin{pc: pc, got: make(chan originDatagram, 64), addr: netip.MustParseAddrPort(pc.LocalAddr().String())}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			b := bytes.Clone(buf[:n])
			select {
			case o.got <- originDatagram{from: from, b: b}:
			default:
			}
			if reply != nil {
				for _, r := range reply(b) {
					_, _ = pc.WriteTo(r, from)
				}
			}
		}
	}()
	return o
}

func (o *udpOrigin) next(t *testing.T) originDatagram {
	t.Helper()
	select {
	case d := <-o.got:
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("nothing reached the target")
		return originDatagram{}
	}
}

func (o *udpOrigin) quiet(t *testing.T) {
	t.Helper()
	select {
	case d := <-o.got:
		t.Fatalf("a datagram of %d bytes reached the target", len(d.b))
	case <-time.After(300 * time.Millisecond):
	}
}

func ageTunnels(t *testing.T, p *Proxy, age time.Duration) {
	t.Helper()
	p.srv.mu.Lock()
	d := p.srv.tunnels
	p.srv.mu.Unlock()
	require.NotNil(t, d)
	then := time.Now().Add(-age)
	d.mu.Lock()
	for _, flow := range d.flows {
		flow.lastSeen = then
		for _, u := range flow.udp {
			u.touch(then)
		}
	}
	d.mu.Unlock()
	d.sweepIdle()
}

// flowSocket returns the socket of a datagram flow of p, behind a tunnel or off a transparent
// socket.
func flowSocket(t *testing.T, p *Proxy) *net.UDPConn {
	t.Helper()
	p.srv.mu.Lock()
	demuxes := slices.Collect(maps.Keys(p.srv.quics))
	p.srv.mu.Unlock()
	for _, d := range demuxes {
		if uc := udpSocketOf(d); uc != nil {
			return uc
		}
	}
	t.Fatal("no datagram flow with a UDP socket")
	return nil
}

func udpSocketOf(d *quicDemux) *net.UDPConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, flow := range d.flows {
		for _, u := range flow.udp {
			c := u.upstream
			if n, ok := c.(noICMPConn); ok {
				c = n.Conn
			}
			if own, ok := c.(*ownUDPConn); ok {
				return own.UDPConn
			}
			if uc, ok := c.(*net.UDPConn); ok {
				return uc
			}
		}
	}
	return nil
}

func loopbackMTU(t *testing.T) int {
	t.Helper()
	ifs, err := net.Interfaces()
	require.NoError(t, err)
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 {
			return ifc.MTU
		}
	}
	t.Skip("no loopback interface")
	return 0
}

func exitDialer(t *testing.T, ca *CA) *upstreamDialer {
	t.Helper()
	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	tr.TLSHandshakeTimeout = 2 * time.Second
	u := newUpstreamDialer(tr)
	t.Cleanup(u.close)
	return u
}

func exitTunnel(t *testing.T, u *upstreamDialer, version, addr, target string) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var conn net.Conn
	var err error
	switch version {
	case viaH3:
		conn, err = u.connectUDP(ctx, &url.URL{Scheme: "https", Host: addr}, target)
	case viaH2:
		host, port, serr := net.SplitHostPort(target)
		require.NoError(t, serr)
		var pipe tunnelPipe
		if pipe, err = u.connectUDPStream(ctx, &url.URL{Scheme: "https", Host: addr}, host, port); err == nil {
			conn = &connectUDPConn{pipe: pipe, remote: tunnelTarget(target)}
		}
	default:
		conn, err = u.connectUDP(ctx, &url.URL{Scheme: "http", Host: addr}, target)
	}
	if conn != nil {
		t.Cleanup(func() { _ = conn.Close() })
	}
	return conn, err
}

type h3Upstream struct {
	reqs  chan *http.Request
	heads chan []h3qlog.HeaderField
	addr  string
}

// headTrace sends to heads the header fields of every HEADERS frame the server parses. The
// request quic-go builds has no :scheme.
type headTrace chan []h3qlog.HeaderField

func (h headTrace) AddProducer() qlogwriter.Recorder { return h }
func (h headTrace) SupportsSchemas(s string) bool    { return s == h3qlog.EventSchema }
func (h headTrace) Close() error                     { return nil }

func (h headTrace) RecordEvent(ev qlogwriter.Event) {
	fp, ok := ev.(h3qlog.FrameParsed)
	if !ok {
		return
	}
	if hf, ok := fp.Frame.Frame.(h3qlog.HeadersFrame); ok {
		select {
		case h <- hf.HeaderFields:
		default:
		}
	}
}

func startH3Upstream(t *testing.T, ca *CA, pc net.PacketConn, datagrams bool, serve http.HandlerFunc) *h3Upstream {
	t.Helper()
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	if pc == nil {
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
	}
	up := &h3Upstream{addr: pc.LocalAddr().String(), reqs: make(chan *http.Request, 8), heads: make(chan []h3qlog.HeaderField, 8)}
	srv := &http3.Server{
		EnableDatagrams: datagrams,
		QUICConfig: &quic.Config{
			Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return headTrace(up.heads) },
		},
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS13},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			up.reqs <- r
			serve(w, r)
		}),
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = pc.Close()
	})
	return up
}

func (up *h3Upstream) head(t *testing.T) map[string][]string {
	t.Helper()
	select {
	case fields := <-up.heads:
		out := make(map[string][]string)
		for _, f := range fields {
			out[f.Name] = append(out[f.Name], f.Value)
		}
		return out
	case <-time.After(5 * time.Second):
		t.Fatal("no request reached the upstream proxy")
		return nil
	}
}

func (up *h3Upstream) request(t *testing.T) *http.Request {
	t.Helper()
	select {
	case r := <-up.reqs:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no request reached the upstream proxy")
		return nil
	}
}

// answerH3 keeps the stream open until the client ends it, quic-go ending it once the handler
// returns.
func answerH3(status int, header http.Header) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		maps.Copy(w.Header(), header)
		w.WriteHeader(status)
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done()
	}
}

// answerH3Read answers, then reads the request until it ends and sends the error to read.
func answerH3Read(status int, header http.Header, read chan<- error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		maps.Copy(w.Header(), header)
		w.WriteHeader(status)
		_ = http.NewResponseController(w).Flush()
		_, err := io.ReadAll(r.Body)
		read <- err
	}
}

func wantH3Reset(t *testing.T, read <-chan error, want http3.ErrCode) {
	t.Helper()
	select {
	case err := <-read:
		code, reset := h3ResetCode(err)
		require.True(t, reset, "the request ended with %v", err)
		assert.Equal(t, want, code)
	case <-time.After(5 * time.Second):
		t.Fatal("the client left the request open")
	}
}

var capsuleProtocolOn = http.Header{http3.CapsuleProtocolHeader: {"?1"}}

type h2Upstream struct {
	heads  chan []hpack.HeaderField
	data   chan []byte
	rsts   chan http2.ErrCode
	addr   string
	answer []hpack.HeaderField
	body   []byte
}

func startH2Upstream(t *testing.T, ca *CA, answer ...hpack.HeaderField) *h2Upstream {
	t.Helper()
	return startH2UpstreamBody(t, ca, nil, answer...)
}

// startH2UpstreamBody starts an upstream proxy that answers every stream with answer, then
// with body and the end of the stream when body is not nil.
func startH2UpstreamBody(t *testing.T, ca *CA, body []byte, answer ...hpack.HeaderField) *h2Upstream {
	t.Helper()
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, err)
	up := &h2Upstream{
		addr: ln.Addr().String(), answer: answer, body: body,
		heads: make(chan []hpack.HeaderField, 8), data: make(chan []byte, 64), rsts: make(chan http2.ErrCode, 8),
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			go up.serve(conn)
		}
	}()
	return up
}

func (up *h2Upstream) serve(conn net.Conn) {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	if err := fr.WriteSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1}); err != nil {
		return
	}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				_ = fr.WritePing(true, f.Data)
			}
		case *http2.MetaHeadersFrame:
			up.heads <- f.Fields
			buf.Reset()
			for _, hf := range up.answer {
				_ = enc.WriteField(hf)
			}
			_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: buf.Bytes(), EndHeaders: true})
			if up.body != nil {
				_ = fr.WriteData(f.StreamID, true, up.body)
			}
		case *http2.DataFrame:
			if n := uint32(len(f.Data())); n > 0 {
				up.data <- bytes.Clone(f.Data())
				_ = fr.WriteWindowUpdate(0, n)
			}
		case *http2.RSTStreamFrame:
			up.rsts <- f.ErrCode
		}
	}
}

func (up *h2Upstream) head(t *testing.T) map[string][]string {
	t.Helper()
	select {
	case fields := <-up.heads:
		out := make(map[string][]string)
		for _, f := range fields {
			out[f.Name] = append(out[f.Name], f.Value)
		}
		return out
	case <-time.After(5 * time.Second):
		t.Fatal("no request reached the upstream proxy")
		return nil
	}
}

func (up *h2Upstream) wantReset(t *testing.T, want http2.ErrCode) {
	t.Helper()
	select {
	case code := <-up.rsts:
		assert.Equal(t, want, code)
	case <-time.After(5 * time.Second):
		t.Fatal("the client left the stream open")
	}
}

func h2Status(code string) hpack.HeaderField { return hpack.HeaderField{Name: ":status", Value: code} }

var capsuleProtocolField = hpack.HeaderField{Name: "capsule-protocol", Value: "?1"}

type h1Upstream struct {
	heads chan []string
	conns chan h1Peer
	addr  string
}

type h1Peer struct {
	conn net.Conn
	br   *bufio.Reader
}

const upgraded101 = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n"

func startH1Upstream(t *testing.T, ln net.Listener, answer string) *h1Upstream {
	t.Helper()
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
	}
	up := &h1Upstream{addr: ln.Addr().String(), heads: make(chan []string, 8), conns: make(chan h1Peer, 8)}
	t.Cleanup(func() {
		_ = ln.Close()
		for {
			select {
			case p := <-up.conns:
				_ = p.conn.Close()
			default:
				return
			}
		}
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go up.serve(conn, answer)
		}
	}()
	return up
}

func (up *h1Upstream) serve(conn net.Conn, answer string) {
	br := bufio.NewReader(conn)
	var lines []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	up.heads <- lines
	if _, err := io.WriteString(conn, answer); err != nil {
		_ = conn.Close()
		return
	}
	up.conns <- h1Peer{conn: conn, br: br}
}

func (up *h1Upstream) head(t *testing.T) (string, http.Header) {
	t.Helper()
	select {
	case lines := <-up.heads:
		header := http.Header{}
		for _, l := range lines[1:] {
			k, v, _ := strings.Cut(l, ":")
			header.Add(k, strings.TrimSpace(v))
		}
		return lines[0], header
	case <-time.After(5 * time.Second):
		t.Fatal("no request reached the upstream proxy")
		return "", nil
	}
}

func (up *h1Upstream) peer(t *testing.T) h1Peer {
	t.Helper()
	select {
	case p := <-up.conns:
		t.Cleanup(func() { _ = p.conn.Close() })
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("no connection reached the upstream proxy")
		return h1Peer{}
	}
}

func (p h1Peer) capsule(t *testing.T) capsuleMsg {
	t.Helper()
	require.NoError(t, p.conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	typ, err := quicvarint.Read(p.br)
	require.NoError(t, err)
	length, err := quicvarint.Read(p.br)
	require.NoError(t, err)
	value := make([]byte, length)
	_, err = io.ReadFull(p.br, value)
	require.NoError(t, err)
	return capsuleMsg{typ: typ, value: value}
}

// connectUDPConformance lists the requirements of RFC 9298, RFC 9297 and RFC 8441, checked
// against the front and the exit.
var connectUDPConformance = []conformanceCase{
	// RFC 9298, the front as the UDP proxy.
	{
		id: "rfc9298/2/1", name: "a tunnel at the default template",
		req: "UDP proxy deployments SHOULD offer service at this location if they need to interoperate with such clients.",
		run: func(t *testing.T) {
			eachFront(t, allFronts, func(t *testing.T, front string) {
				fx := newUDPFixture(t)
				origin := newUDPOrigin(t, "127.0.0.1:0", echoReply)
				tun := fx.mustOpen(t, front, udpReq{target: origin.addr.String()})
				tun.send(t, 0, []byte("ping"))
				assert.Equal(t, "ping", string(origin.next(t).b))
				assert.Equal(t, "ping", string(tun.recv(t)))
			})
		},
	},
	{
		id: "rfc9298/2/2", name: "a URI Template the client cannot use",
		req:  "If a client detects that any of the requirements above are not met by a URI Template, the client MUST reject its configuration and abort the request without sending it to the UDP proxy.",
		skip: "the exit expands the default template alone, Transport.Proxy configures a proxy URL and no template",
	},
	{
		id: "rfc9298/3/1", name: "an empty target_host and an empty target_port",
		req: "both the \"target_host\" and \"target_port\" variables MUST NOT be empty.",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			for _, path := range []string{connectUDPPath + "/53/", connectUDPPath + "127.0.0.1//"} {
				tun := fx.open(t, viaH1, udpReq{path: path})
				assert.Equal(t, http.StatusBadRequest, tun.status, path)
			}
		},
	},
	{
		id: "rfc9298/3/2", name: "a target_port of 0 and of 65536",
		req: "\"target_port\" MUST represent an integer between 1 and 65535 inclusive.",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			for _, path := range []string{connectUDPPath + "127.0.0.1/0/", connectUDPPath + "127.0.0.1/65536/"} {
				tun := fx.open(t, viaH1, udpReq{path: path})
				assert.Equal(t, http.StatusBadRequest, tun.status, path)
			}
		},
	},
	{
		id: "rfc9298/3/3", name: "the exit's request for an IPv6 target",
		req: "if \"target_host\" contains an IPv6 literal, the colons (\":\") MUST be percent-encoded.",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			const want = connectUDPPath + "2001%3Adb8%3A%3A42/53/"
			eachExit(t, allFronts, func(t *testing.T, version string) {
				u := exitDialer(t, ca)
				switch version {
				case viaH3:
					up := startH3Upstream(t, ca, nil, true, answerH3(http.StatusOK, capsuleProtocolOn))
					_, err := exitTunnel(t, u, version, up.addr, "[2001:db8::42]:53")
					require.NoError(t, err)
					assert.Equal(t, want, up.request(t).URL.EscapedPath())
				case viaH2:
					up := startH2Upstream(t, ca, h2Status("200"), capsuleProtocolField)
					_, err := exitTunnel(t, u, version, up.addr, "[2001:db8::42]:53")
					require.NoError(t, err)
					assert.Equal(t, []string{want}, up.head(t)[":path"])
				default:
					up := startH1Upstream(t, nil, upgraded101)
					_, err := exitTunnel(t, u, version, up.addr, "[2001:db8::42]:53")
					require.NoError(t, err)
					line, _ := up.head(t)
					assert.Contains(t, line, want)
				}
			})
		},
	},
	{
		id: "rfc9298/3.1/1", name: "a target_host in percent-encoding",
		req: "It extracts the \"target_host\" and \"target_port\" variables from the URI it has reconstructed from the request headers, decodes their percent-encoding, and establishes a tunnel by directly opening a UDP socket to the requested target.",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", echoReply)
			tun := fx.mustOpen(t, viaH1, udpReq{path: fmt.Sprintf("%s127%%2E0%%2E0%%2E1/%d/", connectUDPPath, origin.addr.Port())})
			tun.send(t, 0, []byte("v4"))
			assert.Equal(t, "v4", string(origin.next(t).b))

			probe, err := net.ListenPacket("udp", "[::1]:0")
			if err != nil {
				t.Logf("the IPv6 literal is not checked without an IPv6 loopback, %v", err)
				return
			}
			_ = probe.Close()
			origin6 := newUDPOrigin(t, "[::1]:0", echoReply)
			tun = fx.mustOpen(t, viaH1, udpReq{path: connectUDPPath + "%3A%3A1/" + strconv.Itoa(int(origin6.addr.Port())) + "/"})
			tun.send(t, 0, []byte("v6"))
			assert.Equal(t, "v6", string(origin6.next(t).b))
		},
	},
	{
		id: "rfc9298/3.1/2", name: "a target_port in percent-encoding",
		req: "It extracts the \"target_host\" and \"target_port\" variables from the URI it has reconstructed from the request headers, decodes their percent-encoding, and establishes a tunnel by directly opening a UDP socket to the requested target.",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", echoReply)
			port := strconv.Itoa(int(origin.addr.Port()))
			tun := fx.mustOpen(t, viaH1, udpReq{path: connectUDPPath + "127.0.0.1/%3" + port[:1] + port[1:] + "/"})
			tun.send(t, 0, []byte("ping"))
			assert.Equal(t, "ping", string(origin.next(t).b))
		},
	},
	{
		id: "rfc9298/3.1/3", name: "a target_host the proxy resolves",
		req: "However, if the \"target_host\" is a DNS name, the UDP proxy MUST perform DNS resolution before replying to the HTTP request.",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", echoReply)
			tun := fx.mustOpen(t, viaH1, udpReq{target: fmt.Sprintf("echo.udp.test:%d", origin.addr.Port())})
			assert.EqualValues(t, 1, fx.resolver.calls.Load(), "the answer came before the resolution")
			tun.send(t, 0, []byte("ping"))
			assert.Equal(t, "ping", string(origin.next(t).b))
		},
	},
	{
		id: "rfc9298/3.1/4", name: "a target_host that does not resolve",
		req: "If errors occur during this process, the UDP proxy MUST reject the request and SHOULD send details using an appropriate Proxy-Status header field [PROXY-STATUS].",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			tun := fx.open(t, viaH1, udpReq{target: "unresolved.udp.test:53"})
			assert.False(t, succeeded(tun.status), "status %d", tun.status)
		},
	},
	{
		id: "rfc9298/3.1/5", name: "the details of a failed resolution",
		req:  "If errors occur during this process, the UDP proxy MUST reject the request and SHOULD send details using an appropriate Proxy-Status header field [PROXY-STATUS].",
		skip: "writeStatus in server.go answers with the status text alone and logs the reason, so no Proxy-Status field is written",
	},
	{
		id: "rfc9298/3.1/6", name: "a datagram to the proxy's socket from another port",
		req: "If the UDP proxy uses a non-connected socket, it MUST validate the IP source address and UDP source port on received packets to ensure they match the client's request. Packets that do not match MUST be discarded by the UDP proxy.",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", nil)
			tun := fx.mustOpen(t, viaH1, udpReq{target: origin.addr.String()})
			tun.send(t, 0, []byte("ping"))
			from := origin.next(t).from
			rogue, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = rogue.Close() })
			_, err = rogue.WriteTo([]byte("rogue"), from)
			require.NoError(t, err)
			time.Sleep(50 * time.Millisecond)
			_, err = origin.pc.WriteTo([]byte("target"), from)
			require.NoError(t, err)
			assert.Equal(t, "target", string(tun.recv(t)))
			tun.quiet(t)
		},
	},
	{
		id: "rfc9298/3.1/7", name: "two datagrams around two minutes of silence less a second",
		req: "The UDP proxy MUST keep the socket open while the request stream is open.",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", nil)
			tun := fx.mustOpen(t, viaH1, udpReq{target: origin.addr.String()})
			tun.send(t, 0, []byte("before"))
			first := origin.next(t).from
			ageTunnels(t, fx.p, 2*time.Minute-time.Second)
			tun.send(t, 0, []byte("after"))
			second := origin.next(t)
			assert.Equal(t, "after", string(second.b))
			assert.Equal(t, first.String(), second.from.String(), "the proxy sent through another socket")
		},
	},
	{
		id: "rfc9298/3.1/8", name: "a tunnel idle past the sweep",
		req: "UDP proxies MAY choose to close sockets due to a period of inactivity, but they MUST close the request stream when closing the socket.",
		run: func(t *testing.T) {
			eachFront(t, []string{viaH3, viaH1}, func(t *testing.T, front string) {
				fx := newUDPFixture(t)
				origin := newUDPOrigin(t, "127.0.0.1:0", echoReply)
				tun := fx.mustOpen(t, front, udpReq{target: origin.addr.String()})
				tun.send(t, 0, []byte("ping"))
				origin.next(t)
				tun.recv(t)
				socket := flowSocket(t, fx.p)
				ageTunnels(t, fx.p, udpFlowIdle+time.Second)
				_ = tun.waitEnd(t)
				_, err := socket.Write([]byte("late"))
				assert.ErrorIs(t, err, net.ErrClosed, "the socket outlived the stream")
			})
		},
	},
	{
		id: "rfc9298/3.1/9", name: "an idle period shorter than two minutes",
		req:  "UDP proxies that close sockets after a period of inactivity SHOULD NOT use a period lower than two minutes; see Section 4.3 of [BEHAVE].",
		skip: "checked by rfc9298/3.1/7, whose sweep follows two minutes of silence less a second",
	},
	{
		id: "rfc9298/3.1/10", name: "an ICMP error on the socket",
		req:  "If a UDP proxy is notified by its operating system that its socket is no longer usable, it MUST close the request stream.",
		skip: "a datagram flow skips the ICMP errors its connected socket reports, icmp.go, since an unconnected socket never receives them",
	},
	{
		id: "rfc9298/3.1/11", name: "a datagram past the MTU of the path to the target",
		req: "UDP proxies MUST NOT introduce fragmentation at the IP layer when forwarding HTTP Datagrams onto a UDP socket; overly large datagrams are silently dropped. In IPv4, the Don't Fragment (DF) bit MUST be set, if possible, to prevent fragmentation on the path.",
		run: func(t *testing.T) {
			mtu := loopbackMTU(t)
			size := mtu - 28 + 512
			if size > 65507 {
				t.Skipf("a loopback MTU of %d leaves no datagram to fragment", mtu)
			}
			origin := newUDPOrigin(t, "127.0.0.1:0", nil)
			// macOS refuses to send a datagram past net.inet.udp.maxdgram, below its loopback MTU.
			probe, err := net.Dial("udp", origin.addr.String())
			require.NoError(t, err)
			_, err = probe.Write(make([]byte, size))
			_ = probe.Close()
			if err != nil {
				t.Skipf("this host sends no datagram of %d bytes on the loopback, %v", size, err)
			}
			require.Len(t, origin.next(t).b, size)
			fx := newUDPFixture(t)
			tun := fx.mustOpen(t, viaH1, udpReq{target: origin.addr.String()})
			tun.send(t, 0, make([]byte, size))
			tun.send(t, 0, []byte("small"))
			got := origin.next(t)
			assert.Equal(t, "small", string(got.b), "a datagram of %d bytes reached the target fragmented", len(got.b))
		},
	},
	{
		id: "rfc9298/3.1/12", name: "a refusal from the upstream proxy",
		req: "Any response other than a successful response indicates that the request has failed; thus, the client MUST abort the request.",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			eachExit(t, allFronts, func(t *testing.T, version string) {
				u := exitDialer(t, ca)
				switch version {
				case viaH3:
					read := make(chan error, 1)
					up := startH3Upstream(t, ca, nil, true, func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusForbidden)
						_ = http.NewResponseController(w).Flush()
						_, err := io.ReadAll(r.Body)
						read <- err
					})
					_, err := exitTunnel(t, u, version, up.addr, "192.0.2.1:53")
					require.ErrorContains(t, err, "403")
					select {
					case err := <-read:
						assert.Error(t, err, "the client ended the request instead of aborting it")
					case <-time.After(5 * time.Second):
						t.Fatal("the client left the request open")
					}
				case viaH2:
					up := startH2Upstream(t, ca, h2Status("403"))
					_, err := exitTunnel(t, u, version, up.addr, "192.0.2.1:53")
					require.ErrorContains(t, err, "403")
					select {
					case <-up.rsts:
					case <-time.After(5 * time.Second):
						t.Fatal("the client left the stream open")
					}
				default:
					up := startH1Upstream(t, nil, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
					_, err := exitTunnel(t, u, version, up.addr, "192.0.2.1:53")
					require.ErrorContains(t, err, "403")
					p := up.peer(t)
					require.NoError(t, p.conn.SetReadDeadline(time.Now().Add(5*time.Second)))
					_, err = p.br.ReadByte()
					assert.False(t, isTimeout(err), "the client left the connection open")
				}
			})
		},
	},
	{
		id: "rfc9298/3.1/13", name: "a CONNECT-UDP the proxy could forward to another proxy",
		req:  "if the recipient is configured to use another HTTP proxy, it will act as an intermediary by forwarding the request to another HTTP server.",
		skip: "edge ends every tunnel itself and opens its own CONNECT-UDP through the proxy Transport.Proxy selects, see CLAUDE.md",
	},
	{
		id: "rfc9298/3.2/1", name: "a POST with Upgrade: connect-udp",
		req: "the method SHALL be \"GET\".",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", nil)
			tun := fx.open(t, viaH1, udpReq{target: origin.addr.String(), method: http.MethodPost})
			assert.Equal(t, http.StatusBadRequest, tun.status)
		},
	},
	{
		id: "rfc9298/3.2/2", name: "a request with two Host fields",
		req:  "the request SHALL include a single Host header field containing the origin of the UDP proxy.",
		skip: "net/http answers 400 to a request with two Host fields before the proxy reads it",
	},
	{
		id: "rfc9298/3.2/3", name: "a GET with an Upgrade and no Connection field",
		req: "the request SHALL include a Connection header field with value \"Upgrade\" (note that this requirement is case-insensitive as per Section 7.6.1 of [HTTP]).",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", nil)
			tun := fx.open(t, viaH1, udpReq{target: origin.addr.String(), header: http.Header{"Connection": nil}})
			assert.Equal(t, http.StatusBadRequest, tun.status)
		},
	},
	{
		id: "rfc9298/3.2/4", name: "the GET with an Upgrade the exit sends",
		req: "When using HTTP/1.1 [HTTP/1.1], a UDP proxying request will meet the following requirements:",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			up := startH1Upstream(t, nil, upgraded101)
			_, err = exitTunnel(t, exitDialer(t, ca), viaH1, up.addr, "192.0.2.1:53")
			require.NoError(t, err)
			line, header := up.head(t)
			method, rest, _ := strings.Cut(line, " ")
			assert.Equal(t, http.MethodGet, method)
			assert.Contains(t, rest, connectUDPPath+"192.0.2.1/53/ HTTP/1.1")
			assert.Equal(t, []string{up.addr}, header.Values("Host"))
			assert.True(t, strings.EqualFold("Upgrade", header.Get("Connection")))
			assert.Equal(t, []string{connectUDPUpgrade}, header.Values("Upgrade"))
		},
	},
	{
		id: "rfc9298/3.3/1", name: "the 101 the front answers",
		req: "The UDP proxy SHALL indicate a successful response by replying with the following requirements:",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", nil)
			tun := fx.mustOpen(t, viaH1, udpReq{target: origin.addr.String()})
			assert.True(t, strings.EqualFold("Upgrade", tun.header.Get("Connection")))
			assert.Len(t, tun.header.Values("Upgrade"), 1)
			assert.True(t, strings.EqualFold(connectUDPUpgrade, tun.header.Get("Upgrade")))
			assert.Equal(t, "?1", tun.header.Get(http3.CapsuleProtocolHeader))
			for _, field := range []string{"Content-Length", "Content-Type", "Transfer-Encoding"} {
				assert.Empty(t, tun.header.Values(field), field)
			}
		},
	},
	{
		id: "rfc9298/3.3/2", name: "a 101 that misses a requirement",
		req: "If any of these requirements are not met, the client MUST treat this proxying attempt as failed and abort the connection.",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			for name, answer := range map[string]string{
				"no Connection field":  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n",
				"two Upgrade fields":   "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n",
				"another upgrade":      "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nCapsule-Protocol: ?1\r\n\r\n",
				"a 200 with no switch": "HTTP/1.1 200 OK\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n",
			} {
				t.Run(name, func(t *testing.T) {
					up := startH1Upstream(t, nil, answer)
					_, err := exitTunnel(t, exitDialer(t, ca), viaH1, up.addr, "192.0.2.1:53")
					assert.Error(t, err)
				})
			}
		},
	},
	{
		id: "rfc9110/15.2/1", name: "a 100 and a 103 before the 101 answering the upgrade the exit sends",
		req: "A client MUST be able to parse one or more 1xx responses received prior to a final response, even if the client does not expect one.",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			up := startH1Upstream(t, nil, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n"+upgraded101)
			_, err = exitTunnel(t, exitDialer(t, ca), viaH1, up.addr, "192.0.2.1:53")
			require.NoError(t, err)
		},
	},
	{
		id: "rfc9298/3.4/1", name: "the SETTINGS of the front",
		req: "This requires that servers send an HTTP Setting as specified in [EXT-CONNECT2] and [EXT-CONNECT3]",
		run: func(t *testing.T) {
			eachFront(t, connectFronts, func(t *testing.T, front string) {
				fx := newUDPFixture(t)
				if front == viaH3 {
					cc, _ := fx.h3Conn(t)
					assert.True(t, cc.Settings().EnableExtendedConnect)
					return
				}
				assert.EqualValues(t, 1, fx.h2Conn(t).serverSettings(t)[http2.SettingEnableConnectProtocol])
			})
		},
	},
	{
		id: "rfc9298/3.4/2", name: "an extended CONNECT of another :protocol",
		req: "The :protocol pseudo-header field SHALL be \"connect-udp\".",
		run: func(t *testing.T) {
			eachFront(t, connectFronts, func(t *testing.T, front string) {
				fx := newUDPFixture(t)
				origin := newUDPOrigin(t, "127.0.0.1:0", nil)
				tun := fx.open(t, front, udpReq{target: origin.addr.String(), protocol: "connect-ip"})
				assert.False(t, tun.err == nil && succeeded(tun.status), "status %d", tun.status)
			})
		},
	},
	{
		id: "rfc9298/3.4/3", name: "an :authority other than the proxy",
		req:  "The :authority pseudo-header field SHALL contain the authority of the UDP proxy.",
		skip: "a forward proxy has no fixed authority of its own to compare with, a client reaches it under any name or address",
	},
	{
		id: "rfc9298/3.4/4", name: "an extended CONNECT over HTTP/2 without :scheme, without :path, or with :method GET",
		req:  "A UDP proxying request that does not conform to these restrictions is malformed (see Section 8.1.1 of [HTTP/2] and Section 4.1.2 of [HTTP/3]).",
		skip: "net/http's HTTP/2 server accepts an extended CONNECT without :scheme and the proxy never reads the field",
	},
	{
		id: "rfc9298/3.4/5", name: "the extended CONNECT the exit sends",
		req: "The :path and :scheme pseudo-header fields SHALL NOT be empty. Their values SHALL contain the scheme and path from the URI Template after the URI Template expansion process has been completed.",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			const path = connectUDPPath + "192.0.2.1/53/"
			eachExit(t, connectFronts, func(t *testing.T, version string) {
				u := exitDialer(t, ca)
				if version == viaH3 {
					up := startH3Upstream(t, ca, nil, true, answerH3(http.StatusOK, capsuleProtocolOn))
					_, err := exitTunnel(t, u, version, up.addr, "192.0.2.1:53")
					require.NoError(t, err)
					r := up.request(t)
					assert.Equal(t, http.MethodConnect, r.Method)
					assert.Equal(t, connectUDPUpgrade, r.Proto)
					head := up.head(t)
					assert.Equal(t, []string{"https"}, head[":scheme"])
					assert.Equal(t, []string{path}, head[":path"])
					assert.Equal(t, up.addr, r.Host)
					assert.Equal(t, "?1", r.Header.Get(http3.CapsuleProtocolHeader))
					return
				}
				up := startH2Upstream(t, ca, h2Status("200"), capsuleProtocolField)
				_, err := exitTunnel(t, u, version, up.addr, "192.0.2.1:53")
				require.NoError(t, err)
				head := up.head(t)
				assert.Equal(t, []string{http.MethodConnect}, head[":method"])
				assert.Equal(t, []string{connectUDPUpgrade}, head[":protocol"])
				assert.Equal(t, []string{"https"}, head[":scheme"])
				assert.Equal(t, []string{path}, head[":path"])
				assert.Equal(t, []string{up.addr}, head[":authority"])
				assert.Equal(t, []string{"?1"}, head["capsule-protocol"])
				assert.Empty(t, head["connection"])
				assert.Empty(t, head["upgrade"])
			})
		},
	},
	{
		id: "rfc9298/3.5/1", name: "the 2xx the front answers",
		req: "the HTTP status code on the response SHALL be in the 2xx (Successful) range.",
		run: func(t *testing.T) {
			eachFront(t, connectFronts, func(t *testing.T, front string) {
				fx := newUDPFixture(t)
				origin := newUDPOrigin(t, "127.0.0.1:0", nil)
				tun := fx.mustOpen(t, front, udpReq{target: origin.addr.String()})
				assert.Equal(t, "?1", tun.header.Get(http3.CapsuleProtocolHeader))
				for _, field := range []string{"Content-Length", "Content-Type", "Transfer-Encoding"} {
					assert.Empty(t, tun.header.Values(field), field)
				}
			})
		},
	},
	{
		id: "rfc9298/3.5/2", name: "a 202 from the upstream proxy",
		req: "the HTTP status code on the response SHALL be in the 2xx (Successful) range.",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			eachExit(t, connectFronts, func(t *testing.T, version string) {
				u := exitDialer(t, ca)
				var addr string
				if version == viaH3 {
					addr = startH3Upstream(t, ca, nil, true, answerH3(http.StatusAccepted, capsuleProtocolOn)).addr
				} else {
					addr = startH2Upstream(t, ca, h2Status("202"), capsuleProtocolField).addr
				}
				_, err := exitTunnel(t, u, version, addr, "192.0.2.1:53")
				assert.NoError(t, err)
			})
		},
	},
	{
		id: "rfc9298/4/1", name: "a context ID allocated twice",
		req:  "Context IDs MUST NOT be re-allocated within a given HTTP namespace but MAY be allocated in any order.",
		skip: "edge allocates no context ID, it sends context ID 0 alone",
	},
	{
		id: "rfc9298/5/1", name: "a datagram of a context ID nothing registered",
		req: "If an HTTP/3 Datagram that carries an unknown Context ID is received, the receiver SHALL either drop that datagram silently or buffer it temporarily (on the order of a round trip) while awaiting the registration of the corresponding Context ID.",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", echoReply)
			tun := fx.mustOpen(t, viaH3, udpReq{target: origin.addr.String()})
			tun.send(t, 2, []byte("context 2"))
			tun.send(t, 0, []byte("context 0"))
			assert.Equal(t, "context 0", string(origin.next(t).b))
			origin.quiet(t)
			assert.Equal(t, "context 0", string(tun.recv(t)))
		},
	},
	{
		id: "rfc9298/5/2", name: "a datagram of a context ID nothing registered, at the exit",
		req: "If an HTTP/3 Datagram that carries an unknown Context ID is received, the receiver SHALL either drop that datagram silently or buffer it temporarily (on the order of a round trip) while awaiting the registration of the corresponding Context ID.",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			up := startH3Upstream(t, ca, nil, true, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(http3.CapsuleProtocolHeader, "?1")
				w.WriteHeader(http.StatusOK)
				str := w.(http3.HTTPStreamer).HTTPStream()
				_ = str.SendDatagram(httpDatagram(2, []byte("context 2")))
				_ = str.SendDatagram(httpDatagram(0, []byte("context 0")))
				<-r.Context().Done()
			})
			conn, err := exitTunnel(t, exitDialer(t, ca), viaH3, up.addr, "192.0.2.1:53")
			require.NoError(t, err)
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
			buf := make([]byte, 64)
			n, err := conn.Read(buf)
			require.NoError(t, err)
			assert.Equal(t, "context 0", string(buf[:n]))
		},
	},
	{
		id: "rfc9298/5/3", name: "datagrams buffered while a context ID is unknown",
		req:  "Receivers that buffer datagrams SHOULD apply buffering limits in order to reduce the risk of resource exhaustion occurring.",
		skip: "neither end buffers a datagram of an unknown context ID, rfc9298/5/1 and rfc9298/5/2 check it is dropped",
	},
	{
		id: "rfc9298/5/4", name: "an empty UDP payload toward the target",
		req: "When the Context ID field is set to zero, the UDP Proxying Payload field contains the unmodified payload of a UDP packet (referred to as data octets in [UDP]).",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", nil)
			tun := fx.mustOpen(t, viaH3, udpReq{target: origin.addr.String()})
			tun.send(t, 0, nil)
			assert.Empty(t, origin.next(t).b)
		},
	},
	{
		id: "rfc9298/5/5", name: "an empty UDP payload from the target",
		req: "When the Context ID field is set to zero, the UDP Proxying Payload field contains the unmodified payload of a UDP packet (referred to as data octets in [UDP]).",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", func([]byte) [][]byte { return [][]byte{{}, []byte("after")} })
			tun := fx.mustOpen(t, viaH3, udpReq{target: origin.addr.String()})
			tun.send(t, 0, []byte("ping"))
			assert.Empty(t, tun.recv(t))
		},
	},
	{
		id: "rfc9298/5/6", name: "an empty UDP payload through the exit",
		req: "When the Context ID field is set to zero, the UDP Proxying Payload field contains the unmodified payload of a UDP packet (referred to as data octets in [UDP]).",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			up := startH1Upstream(t, nil, upgraded101)
			conn, err := exitTunnel(t, exitDialer(t, ca), viaH1, up.addr, "192.0.2.1:53")
			require.NoError(t, err)
			p := up.peer(t)
			_, err = conn.Write(nil)
			require.NoError(t, err)
			assert.Equal(t, capsuleMsg{typ: capsuleDatagram, value: []byte{0}}, p.capsule(t))
			_, err = p.conn.Write(capsuleOf(capsuleDatagram, httpDatagram(0, nil)))
			require.NoError(t, err)
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
			n, err := conn.Read(make([]byte, 64))
			require.NoError(t, err)
			assert.Zero(t, n)
		},
	},
	{
		id: "rfc9298/5/7", name: "a DATAGRAM capsule of 65528 bytes of UDP payload",
		req: "An endpoint that receives an HTTP Datagram using Context ID zero whose UDP Proxying Payload field is longer than 65527 MUST abort the corresponding stream.",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", nil)
			tun := fx.mustOpen(t, viaH1, udpReq{target: origin.addr.String()})
			tun.send(t, 0, make([]byte, 65528))
			_ = tun.waitEnd(t)
		},
	},
	{
		id: "rfc9298/5/8", name: "the exit writing 65528 bytes",
		req: "Therefore, endpoints MUST NOT send HTTP Datagrams with a UDP Proxying Payload field longer than 65527 using Context ID zero.",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			up := startH1Upstream(t, nil, upgraded101)
			conn, err := exitTunnel(t, exitDialer(t, ca), viaH1, up.addr, "192.0.2.1:53")
			require.NoError(t, err)
			p := up.peer(t)
			_, _ = conn.Write(make([]byte, 65528))
			_, err = conn.Write([]byte("small"))
			require.NoError(t, err)
			got := p.capsule(t)
			assert.Equal(t, httpDatagram(0, []byte("small")), got.value, "a DATAGRAM capsule of %d bytes left the exit", len(got.value))
		},
	},
	{
		id: "rfc9298/5/9", name: "an HTTP/3 Datagram ahead of its request",
		req:  "If a UDP proxy receives an HTTP Datagram before it has received the corresponding request, it SHALL either drop that HTTP Datagram silently or buffer it temporarily (on the order of a round trip) while awaiting the corresponding request.",
		skip: "quic-go drops a datagram whose stream does not exist yet, http3/conn.go, and a capsule cannot precede the request on its stream",
	},
	{
		id: "rfc9298/5/10", name: "a DATAGRAM capsule right behind the request",
		req: "A client MAY optimistically start sending UDP packets in HTTP Datagrams before receiving the response to its UDP proxying request.",
		run: func(t *testing.T) {
			eachFront(t, []string{viaH2, viaH1}, func(t *testing.T, front string) {
				fx := newUDPFixture(t)
				origin := newUDPOrigin(t, "127.0.0.1:0", echoReply)
				early := capsuleOf(capsuleDatagram, httpDatagram(0, []byte("early")))
				tun := fx.mustOpen(t, front, udpReq{target: origin.addr.String(), early: early})
				assert.Equal(t, "early", string(origin.next(t).b))
				assert.Equal(t, "early", string(tun.recv(t)))
			})
		},
	},
	{
		id: "rfc9298/6/1", name: "datagrams queued toward the client",
		req:  "To avoid this, UDP proxies SHOULD strive to avoid increasing burstiness of UDP traffic; they SHOULD NOT queue packets in order to increase batching.",
		skip: "the tunnel writes each datagram as soon as it is dequeued, no write waits for another datagram",
	},
	{
		id: "rfc9298/6/2", name: "congestion control on the front connection",
		req:  "The underlying HTTP connection MUST NOT disable congestion control unless it has an out-of-band way of knowing with absolute certainty that the inner traffic is congestion-controlled.",
		skip: "quic-go and TCP run congestion control on every connection, edge disables none",
	},
	{
		id: "rfc9298/6/3", name: "ECN on a connection without congestion control",
		req:  "If a client or UDP proxy with a connection containing a UDP Proxying request stream disables congestion control, it MUST NOT signal Explicit Congestion Notification (ECN) [ECN] support on that connection.",
		skip: "edge disables congestion control on no connection, the condition of this requirement",
	},
	{
		id: "rfc9298/6.1/1", name: "a reply past a QUIC DATAGRAM frame",
		req: "If a UDP proxy is using QUIC DATAGRAM frames and it receives a UDP payload from the target that will not fit inside a QUIC DATAGRAM frame, the UDP proxy SHOULD NOT send the UDP payload in a DATAGRAM capsule, as that defeats the end-to-end unreliability characteristic that methods such as Datagram Packetization Layer PMTU Discovery (DPLPMTUD) depend on [DPLPMTUD].",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", func(b []byte) [][]byte {
				if string(b) == "large" {
					return [][]byte{make([]byte, 2000)}
				}
				return [][]byte{b}
			})
			tun := fx.mustOpen(t, viaH3, udpReq{target: origin.addr.String()})
			tun.send(t, 0, []byte("large"))
			origin.next(t)
			tun.send(t, 0, []byte("small"))
			assert.Equal(t, "small", string(tun.recv(t)))
			tun.quiet(t)
		},
	},
	{
		id: "rfc9298/6.1/2", name: "an ICMP Packet Too Big toward the target",
		req:  "In this scenario, the UDP proxy SHOULD drop the UDP payload and send an ICMP Packet Too Big message to the target; see Section 3.2 of [ICMP6].",
		skip: "the proxy opens no raw socket and sends no ICMP",
	},
	{
		id: "rfc9298/6.2/1", name: "ECN bits on a datagram from the target",
		req: "A UDP proxy MUST ignore ECN bits in the IP header of UDP packets received from the target, and it MUST set the ECN bits to Not-ECT on UDP packets it sends to the target.",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", echoReply)
			tun := fx.mustOpen(t, viaH1, udpReq{target: origin.addr.String()})
			tun.send(t, 0, []byte("ping"))
			origin.next(t)
			tos, err := ipv4.NewConn(flowSocket(t, fx.p)).TOS()
			require.NoError(t, err)
			assert.Zero(t, tos&0x3, "the socket toward the target marks ECN")
		},
	},

	// RFC 9297, HTTP Datagrams and the Capsule Protocol.
	{
		id: "rfc9297/2/1", name: "an HTTP Datagram on a request that defines none",
		req:  "HTTP Datagrams MUST only be sent with an association to an HTTP request that explicitly supports them.",
		skip: "edge sends HTTP Datagrams on CONNECT-UDP streams alone, the one request it defines them for",
	},
	{
		id: "rfc9297/2/2", name: "a QUIC datagram on the stream of a GET",
		req:  "If an HTTP Datagram is received and it is associated with a request that has no known semantics for HTTP Datagrams, the receiver MUST terminate the request. If HTTP/3 is in use, the request stream MUST be aborted with H3_DATAGRAM_ERROR (0x33).",
		skip: "quic-go queues the datagrams of any request stream, and detecting one on a request without datagram semantics would cost the proxy a reader per HTTP/3 request",
	},
	{
		id: "rfc9297/2.1/1", name: "a Quarter Stream ID past 2^60-1",
		req:  "Receipt of an HTTP/3 Datagram that includes a larger value MUST be treated as an HTTP/3 connection error of type H3_DATAGRAM_ERROR (0x33).",
		skip: "quic-go parses the Quarter Stream ID and closes the connection, http3/conn.go",
	},
	{
		id: "rfc9297/2.1/2", name: "a QUIC DATAGRAM frame too short for a Quarter Stream ID",
		req:  "Receipt of a QUIC DATAGRAM frame whose payload is too short to allow parsing the Quarter Stream ID field MUST be treated as an HTTP/3 connection error of type H3_DATAGRAM_ERROR (0x33).",
		skip: "quic-go parses the Quarter Stream ID and closes the connection, http3/conn.go",
	},
	{
		id: "rfc9297/2.1/3", name: "a datagram from the proxy after its FIN",
		req:  "HTTP/3 Datagrams MUST NOT be sent unless the corresponding stream's send side is open.",
		skip: "a QUIC DATAGRAM frame and the FIN of the stream may arrive in either order, so no peer can observe the order the tunnel sends them in",
	},
	{
		id: "rfc9297/2.1/4", name: "a datagram after the client's FIN",
		req: "If a datagram is received after the corresponding stream's receive side is closed, the received datagrams MUST be silently dropped.",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", echoReply)
			tun, str := fx.openH3(t, udpReq{target: origin.addr.String()})
			require.Equal(t, http.StatusOK, tun.status)
			tun.send(t, 0, []byte("ping"))
			origin.next(t)
			tun.recv(t)
			require.NoError(t, tun.finish())
			_ = tun.waitEnd(t)
			_, qc := fx.h3Conn(t)
			quarter := quicvarint.Append(nil, uint64(str.StreamID()/4))
			require.NoError(t, qc.SendDatagram(append(quarter, httpDatagram(0, []byte("late"))...)))
			origin.quiet(t)
		},
	},
	{
		id: "rfc9297/2.1/5", name: "a datagram for a stream not yet open",
		req:  "If an HTTP/3 Datagram is received and its Quarter Stream ID field maps to a stream that has not yet been created, the receiver SHALL either drop that datagram silently or buffer it temporarily (on the order of a round trip) while awaiting the creation of the corresponding stream.",
		skip: "quic-go drops a datagram whose stream does not exist yet, http3/conn.go",
	},
	{
		id: "rfc9297/2.1/6", name: "a datagram for a stream past the stream limit",
		req:  "If an HTTP/3 Datagram is received and its Quarter Stream ID field maps to a stream that cannot be created due to client-initiated bidirectional stream limits, it SHOULD be treated as an HTTP/3 connection error of type H3_ID_ERROR.",
		skip: "quic-go owns the stream limits and the datagrams of streams it never opened, http3/conn.go",
	},
	{
		id: "rfc9297/2.1.1/1", name: "the SETTINGS_H3_DATAGRAM of the front",
		req: "It is RECOMMENDED that implementations that support receiving HTTP/3 Datagrams always send the SETTINGS_H3_DATAGRAM setting with a value of 1, even if the application does not intend to use HTTP/3 Datagrams.",
		run: func(t *testing.T) {
			cc, _ := newUDPFixture(t).h3Conn(t)
			assert.True(t, cc.Settings().EnableDatagrams)
		},
	},
	{
		id: "rfc9297/2.1.1/2", name: "a SETTINGS_H3_DATAGRAM of 2",
		req:  "If the SETTINGS_H3_DATAGRAM setting is received with a value that is neither 0 nor 1, the receiver MUST terminate the connection with error H3_SETTINGS_ERROR.",
		skip: "quic-go parses the SETTINGS frame of both ends",
	},
	{
		id: "rfc9297/2.1.1/3", name: "an HTTP/3 upstream proxy without SETTINGS_H3_DATAGRAM",
		req: "QUIC DATAGRAM frames MUST NOT be sent until the SETTINGS_H3_DATAGRAM setting has been both sent and received with a value of 1.",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			cert, err := ca.Leaf("127.0.0.1")
			require.NoError(t, err)
			ln, pc := listenBoth(t)
			h3 := startH3Upstream(t, ca, pc, false, answerH3(http.StatusOK, capsuleProtocolOn))
			h1 := startH1Upstream(t, tls.NewListener(ln, &tls.Config{
				Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12,
			}), upgraded101)
			_, err = exitTunnel(t, exitDialer(t, ca), viaH3, h3.addr, "192.0.2.1:53")
			require.NoError(t, err)
			line, _ := h1.head(t)
			assert.True(t, strings.HasPrefix(line, http.MethodGet), "the tunnel went over HTTP/1.1")
			select {
			case r := <-h3.reqs:
				t.Fatalf("a %s reached the HTTP/3 proxy", r.Method)
			default:
			}
		},
	},
	{
		id: "rfc9297/2.1.1/4", name: "SETTINGS_H3_DATAGRAM remembered for 0-RTT",
		req:  "When servers decide to accept 0-RTT data, they MUST send a SETTINGS_H3_DATAGRAM setting greater than or equal to the value they sent to the client in the connection where they sent them the NewSessionTicket message.",
		skip: "neither the front nor the exit accepts or sends 0-RTT",
	},
	{
		id: "rfc9297/2.1.1/5", name: "an HTTP/3 client without SETTINGS_H3_DATAGRAM",
		req: "QUIC DATAGRAM frames MUST NOT be sent until the SETTINGS_H3_DATAGRAM setting has been both sent and received with a value of 1.",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", echoReply)
			fx.h3cc, fx.h3qc = dialH3(t, fx.frontAddr(t, viaH3), fx.ca, false)
			tun := fx.mustOpen(t, viaH3, udpReq{target: origin.addr.String()})
			require.NoError(t, tun.write(capsuleOf(capsuleDatagram, httpDatagram(0, []byte("ping")))))
			assert.Equal(t, "ping", string(origin.next(t).b))
			select {
			case c := <-tun.caps:
				assert.Equal(t, capsuleMsg{typ: capsuleDatagram, value: httpDatagram(0, []byte("ping"))}, c)
			case dg := <-tun.dgrams:
				t.Fatalf("a QUIC datagram of %d bytes arrived", len(dg))
			case <-time.After(5 * time.Second):
				t.Fatal("no datagram from the proxy")
			}
		},
	},
	{
		id: "rfc9297/3.2/1", name: "a capsule of unknown type",
		req: "Endpoints that receive a Capsule with an unknown Capsule Type MUST silently drop that Capsule and skip over it to parse the next Capsule.",
		run: func(t *testing.T) {
			eachFront(t, []string{viaH3, viaH1}, func(t *testing.T, front string) {
				fx := newUDPFixture(t)
				origin := newUDPOrigin(t, "127.0.0.1:0", echoReply)
				tun := fx.mustOpen(t, front, udpReq{target: origin.addr.String()})
				require.NoError(t, tun.write(capsuleOf(0x2b, []byte("an extension"))))
				require.NoError(t, tun.write(capsuleOf(0x17, nil)))
				tun.send(t, 0, []byte("ping"))
				assert.Equal(t, "ping", string(origin.next(t).b))
				assert.Equal(t, "ping", string(tun.recv(t)))
			})
		},
	},
	{
		id: "rfc9297/3.2/2", name: "a capsule of unknown type an intermediary could forward",
		req:  "In particular, intermediaries SHOULD forward Capsules with an unknown Capsule Type without modification.",
		skip: "edge ends every tunnel as the UDP proxy and forwards no capsule",
	},
	{
		id: "rfc9297/3.2/3", name: "a request with a Content-Type field",
		req: "The Capsule Protocol MUST NOT be used with messages that contain Content-Length, Content-Type, or Transfer-Encoding header fields.",
		run: func(t *testing.T) {
			eachFront(t, allFronts, func(t *testing.T, front string) {
				fx := newUDPFixture(t)
				origin := newUDPOrigin(t, "127.0.0.1:0", nil)
				tun := fx.open(t, front, udpReq{
					target: origin.addr.String(),
					header: http.Header{"Content-Type": {"application/octet-stream"}},
				})
				assert.False(t, tun.err == nil && succeeded(tun.status), "a malformed request opened a tunnel")
			})
		},
	},
	{
		id: "rfc9297/3.2/4", name: "a 204 or a 206 from the upstream proxy",
		req: "Additionally, HTTP status codes 204 (No Content), 205 (Reset Content), and 206 (Partial Content) MUST NOT be sent on responses that use the Capsule Protocol.",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			eachExit(t, connectFronts, func(t *testing.T, version string) {
				for _, code := range []int{http.StatusNoContent, http.StatusPartialContent} {
					u := exitDialer(t, ca)
					if version == viaH3 {
						read := make(chan error, 1)
						up := startH3Upstream(t, ca, nil, true, answerH3Read(code, capsuleProtocolOn, read))
						_, err := exitTunnel(t, u, version, up.addr, "192.0.2.1:53")
						assert.Error(t, err, "a %d opened a tunnel", code)
						wantH3Reset(t, read, http3.ErrCodeMessageError)
						continue
					}
					up := startH2Upstream(t, ca, h2Status(strconv.Itoa(code)), capsuleProtocolField)
					_, err := exitTunnel(t, u, version, up.addr, "192.0.2.1:53")
					assert.Error(t, err, "a %d opened a tunnel", code)
					up.wantReset(t, http2.ErrCodeProtocol)
				}
			})
		},
	},
	{
		id: "rfc9297/3.2/5", name: "a success with Content-Type or Content-Length from the upstream proxy",
		req: "A receiver that observes a violation of these requirements MUST treat the HTTP message as malformed.",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			eachExit(t, allFronts, func(t *testing.T, version string) {
				u := exitDialer(t, ca)
				switch version {
				case viaH3:
					read := make(chan error, 1)
					header := http.Header{http3.CapsuleProtocolHeader: {"?1"}, "Content-Type": {"application/octet-stream"}}
					up := startH3Upstream(t, ca, nil, true, answerH3Read(http.StatusOK, header, read))
					_, err := exitTunnel(t, u, version, up.addr, "192.0.2.1:53")
					assert.Error(t, err, "a malformed answer opened a tunnel")
					wantH3Reset(t, read, http3.ErrCodeMessageError)
				case viaH2:
					up := startH2Upstream(t, ca, h2Status("200"), capsuleProtocolField,
						hpack.HeaderField{Name: "content-length", Value: "0"})
					_, err := exitTunnel(t, u, version, up.addr, "192.0.2.1:53")
					assert.Error(t, err, "a malformed answer opened a tunnel")
					up.wantReset(t, http2.ErrCodeProtocol)
				default:
					addr := startH1Upstream(t, nil, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"+
						"Upgrade: connect-udp\r\nCapsule-Protocol: ?1\r\nContent-Type: application/octet-stream\r\n\r\n").addr
					_, err := exitTunnel(t, u, version, addr, "192.0.2.1:53")
					assert.Error(t, err, "a malformed answer opened a tunnel")
				}
			})
		},
	},
	{
		id: "rfc9297/3.2/6", name: "a capsule accumulated before it is handled",
		req:  "When processing Capsules, a receiver might be tempted to accumulate the full length of the Capsule Value field in the data stream before handling it. This approach SHOULD be avoided because it can consume flow control in underlying layers, and that might lead to deadlocks if the Capsule data exhausts the flow control window.",
		skip: "checked by rfc9297/3.5/2, the reader drops every capsule it does not keep through one path, DATAGRAM or not",
	},
	{
		id: "rfc9297/3.3/1", name: "an error in the Capsule Protocol",
		req:  "When a receiver encounters an error processing the Capsule Protocol, the receiver MUST treat it as if it had received a malformed or incomplete HTTP message.",
		skip: "a stream of capsules presents one error, a capsule truncated by the end of the stream, whose requirement follows in section 3.3",
	},
	{
		id: "rfc9297/3.3/2", name: "a capsule with bytes past its fields",
		req:  "A Capsule payload that contains additional bytes after the identified fields or a Capsule payload that terminates before the end of the identified fields MUST be treated as it if were a malformed or incomplete message.",
		skip: "the DATAGRAM capsule is the one type the proxy parses, and its payload has no fixed fields",
	},
	{
		id: "rfc9297/3.3/3", name: "a capsule truncated by the end of the stream",
		req: "If the receive side of a stream carrying Capsules is terminated cleanly (for example, in HTTP/3 this is defined as receiving a QUIC STREAM frame with the FIN bit set) and the last Capsule on the stream was truncated, this MUST be treated as if it were a malformed or incomplete message.",
		run: func(t *testing.T) {
			eachFront(t, allFronts, func(t *testing.T, front string) {
				fx := newUDPFixture(t)
				origin := newUDPOrigin(t, "127.0.0.1:0", echoReply)
				tun := fx.mustOpen(t, front, udpReq{target: origin.addr.String()})
				tun.send(t, 0, []byte("ping"))
				origin.next(t)
				tun.recv(t)
				require.NoError(t, tun.write(capsuleOf(capsuleDatagram, httpDatagram(0, []byte("truncated")))[:4]))
				require.NoError(t, tun.finish())
				err := tun.waitEnd(t)
				switch front {
				case viaH3:
					code, reset := h3ResetCode(err)
					require.True(t, reset, "the stream ended with %v", err)
					assert.Equal(t, http3.ErrCodeMessageError, code)
				case viaH2:
					var se http2.StreamError
					assert.True(t, errors.As(err, &se), "the stream ended cleanly")
				default:
					require.Error(t, err)
					assert.NotErrorIs(t, err, io.EOF, "the connection ended cleanly")
				}
			})
		},
	},
	{
		id: "rfc9297/3.3/4", name: "a capsule truncated by the end of the stream, at the exit",
		req: "If the receive side of a stream carrying Capsules is terminated cleanly (for example, in HTTP/3 this is defined as receiving a QUIC STREAM frame with the FIN bit set) and the last Capsule on the stream was truncated, this MUST be treated as if it were a malformed or incomplete message.",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			truncated := capsuleOf(capsuleDatagram, httpDatagram(0, []byte("truncated")))[:4]
			eachExit(t, connectFronts, func(t *testing.T, version string) {
				u := exitDialer(t, ca)
				if version == viaH3 {
					read := make(chan error, 1)
					up := startH3Upstream(t, ca, nil, true, func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set(http3.CapsuleProtocolHeader, "?1")
						w.WriteHeader(http.StatusOK)
						str := w.(http3.HTTPStreamer).HTTPStream()
						_, _ = str.Write(truncated)
						_ = str.Close()
						_, err := io.ReadAll(str)
						read <- err
					})
					conn, err := exitTunnel(t, u, version, up.addr, "192.0.2.1:53")
					require.NoError(t, err)
					wantH3Reset(t, read, http3.ErrCodeMessageError)
					require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
					_, err = conn.Read(make([]byte, 64))
					assert.Error(t, err)
					return
				}
				up := startH2UpstreamBody(t, ca, truncated, h2Status("200"), capsuleProtocolField)
				conn, err := exitTunnel(t, u, version, up.addr, "192.0.2.1:53")
				require.NoError(t, err)
				require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
				_, err = conn.Read(make([]byte, 64))
				assert.ErrorIs(t, err, errTunnelMalformed)
				up.wantReset(t, http2.ErrCodeProtocol)
			})
		},
	},
	{
		id: "rfc9297/3.4/1", name: "a Capsule-Protocol field absent, false, or of another type",
		req: "Its value MUST be a Boolean; any other value type MUST be handled as if the field were not present by recipients (for example, if this field is included multiple times, its type will become a List and the field will be ignored).",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", echoReply)
			for _, value := range [][]string{nil, {"?0"}, {"1"}, {"?1;x=1"}, {"?1", "?1"}} {
				tun := fx.mustOpen(t, viaH1, udpReq{
					target: origin.addr.String(),
					header: http.Header{http3.CapsuleProtocolHeader: value},
				})
				tun.send(t, 0, []byte("ping"))
				assert.Equal(t, "ping", string(tun.recv(t)), "Capsule-Protocol %q", value)
				origin.next(t)
			}
		},
	},
	{
		id: "rfc9297/3.4/2", name: "a Capsule-Protocol field of false",
		req:  "A Capsule-Protocol header field with a false value has the same semantics as when the header is not present.",
		skip: "checked by rfc9297/3.4/1",
	},
	{
		id: "rfc9297/3.4/3", name: "the refusal the front answers",
		req: "The Capsule-Protocol header field MUST NOT be used on HTTP responses with a status code that is both different from 101 (Switching Protocols) and outside the 2xx (Successful) range.",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			for _, target := range []string{"10.9.9.9:53", "unresolved.udp.test:53"} {
				tun := fx.open(t, viaH1, udpReq{target: target})
				require.False(t, succeeded(tun.status))
				assert.Empty(t, tun.header.Values(http3.CapsuleProtocolHeader), "status %d", tun.status)
			}
		},
	},
	{
		id: "rfc9297/3.4/4", name: "the Capsule-Protocol field of the front",
		req:  "When using the Capsule Protocol, HTTP endpoints SHOULD send the Capsule-Protocol header field to simplify intermediary processing.",
		skip: "checked by the 101 of rfc9298/3.3/1 and the 2xx of rfc9298/3.5/1",
	},
	{
		id: "rfc9297/3.5/1", name: "a DATAGRAM capsule on an HTTP/3 stream",
		req: "HTTP Datagrams sent using the DATAGRAM Capsule have the same semantics as those sent in QUIC DATAGRAM frames.",
		run: func(t *testing.T) {
			fx := newUDPFixture(t)
			origin := newUDPOrigin(t, "127.0.0.1:0", nil)
			tun := fx.mustOpen(t, viaH3, udpReq{target: origin.addr.String()})
			require.NoError(t, tun.write(capsuleOf(capsuleDatagram, httpDatagram(0, []byte("capsule")))))
			assert.Equal(t, "capsule", string(origin.next(t).b))
		},
	},
	{
		id: "rfc9297/3.5/2", name: "a DATAGRAM capsule of 256 MiB",
		req: "If an incoming DATAGRAM Capsule has a length that is known to be so large as to not be usable, the implementation SHOULD discard the Capsule without buffering its contents into memory.",
		run: func(t *testing.T) {
			const size = 256 << 20
			pr, pw := io.Pipe()
			t.Cleanup(func() { _ = pr.Close() })
			go func() {
				chunk := make([]byte, 1<<20)
				// Context ID 2, as one of context ID 0 this large aborts the stream, RFC 9298 section 5.
				chunk[0] = 2
				if _, err := pw.Write(quicvarint.Append([]byte{capsuleDatagram}, size)); err != nil {
					return
				}
				for range size / len(chunk) {
					if _, err := pw.Write(chunk); err != nil {
						return
					}
				}
				_, _ = pw.Write(capsuleOf(capsuleDatagram, httpDatagram(0, []byte("after"))))
			}()
			pipe := newCapsulePipe(nil, bufio.NewReader(pr))
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			b, err := pipe.recv(t.Context())
			runtime.ReadMemStats(&after)
			require.NoError(t, err)
			assert.Equal(t, httpDatagram(0, []byte("after")), b)
			assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(size/2), "the capsule was buffered")
		},
	},
	{
		id: "rfc9297/3.5/3", name: "a datagram past the QUIC DATAGRAM frame of the upstream connection",
		req: "If the HTTP Datagram is too large to fit in a DATAGRAM frame (for example, because the Path MTU (PMTU) of that QUIC connection is too low or if the maximum UDP payload size advertised on that connection is too low), the intermediary SHOULD drop the HTTP Datagram instead of converting it to a DATAGRAM Capsule.",
		run: func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			dgrams := make(chan []byte, 8)
			stream := make(chan int, 8)
			up := startH3Upstream(t, ca, nil, true, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(http3.CapsuleProtocolHeader, "?1")
				w.WriteHeader(http.StatusOK)
				str := w.(http3.HTTPStreamer).HTTPStream()
				go func() {
					buf := make([]byte, 4096)
					for {
						n, err := str.Read(buf)
						if n > 0 {
							stream <- n
						}
						if err != nil {
							return
						}
					}
				}()
				for {
					dg, err := str.ReceiveDatagram(r.Context())
					if err != nil {
						return
					}
					dgrams <- dg
				}
			})
			conn, err := exitTunnel(t, exitDialer(t, ca), viaH3, up.addr, "192.0.2.1:53")
			require.NoError(t, err)
			n, err := conn.Write(make([]byte, 2000))
			require.NoError(t, err)
			assert.Equal(t, 2000, n)
			_, err = conn.Write([]byte("small"))
			require.NoError(t, err)
			select {
			case dg := <-dgrams:
				assert.Equal(t, httpDatagram(0, []byte("small")), dg)
			case <-time.After(5 * time.Second):
				t.Fatal("no datagram reached the upstream proxy")
			}
			select {
			case n := <-stream:
				t.Fatalf("%d bytes reached the stream", n)
			case <-time.After(300 * time.Millisecond):
			}
		},
	},
	{
		id: "rfc9297/3.5/4", name: "a DATAGRAM capsule an intermediary could re-encode",
		req:  "Intermediaries MUST NOT perform this re-encoding unless they have identified the use of the Capsule Protocol on the corresponding request stream; see Section 3.2.",
		skip: "edge is the UDP proxy end of every tunnel and re-encodes nothing",
	},

	// RFC 8441, extended CONNECT over HTTP/2.
	{
		id: "rfc8441/3/1", name: "SETTINGS_ENABLE_CONNECT_PROTOCOL of the front",
		req:  "Upon receipt of SETTINGS_ENABLE_CONNECT_PROTOCOL with a value of 1, a client MAY use the Extended CONNECT as defined in this document when creating new streams.",
		skip: "checked by rfc9298/3.4/1",
	},
	{
		id: "rfc8441/3/2", name: "SETTINGS_ENABLE_CONNECT_PROTOCOL from 1 back to 0",
		req:  "A sender MUST NOT send a SETTINGS_ENABLE_CONNECT_PROTOCOL parameter with the value of 0 after previously sending a value of 1.",
		skip: "net/http sends the setting of the front, and internal/h2tunnel checks the exit in its own table",
	},
	{
		id: "rfc8441/4/1", name: "an :authority other than the target",
		req: "In particular, the server MUST NOT create a tunnel to the host indicated by the :authority as it would with a CONNECT method request that was not modified by this extension.",
		run: func(t *testing.T) {
			eachFront(t, connectFronts, func(t *testing.T, front string) {
				fx := newUDPFixture(t)
				target := newUDPOrigin(t, "127.0.0.1:0", nil)
				other := newUDPOrigin(t, "127.0.0.1:0", nil)
				tun := fx.mustOpen(t, front, udpReq{target: target.addr.String(), authority: other.addr.String()})
				tun.send(t, 0, []byte("ping"))
				assert.Equal(t, "ping", string(target.next(t).b))
				other.quiet(t)
			})
		},
	},
	{
		id: "rfc8441/4/2", name: "the :scheme and :path of the exit",
		req:  "On requests that contain the :protocol pseudo-header field, the :scheme and :path pseudo-header fields of the target URI (see Section 5) MUST also be included.",
		skip: "checked by rfc9298/3.4/5",
	},
}

func tunnelBench(b *testing.B) (*quicDemux, *connectUDPTunnel, *demuxPacketConn, []byte) {
	b.Helper()
	ca, err := GenerateCA()
	if err != nil {
		b.Fatal(err)
	}
	p, err := New(WithCA(ca))
	if err != nil {
		b.Fatal(err)
	}
	d, err := newQUICDemux(p, newTunnelPacketConn())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = p.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)
	target := Target{Scheme: "https", Host: "bench.test", Port: "443"}
	sess := newSession(p, ctx, nil, target, KindHTTP, HTTP3)
	sess.remoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}
	origin := netip.MustParseAddrPort("127.0.0.1:443")
	tun := newConnectUDPTunnel(d, sess, &contextFraming{target: target, upstream: origin}, cancel)
	if !d.publishTunnel(tun) {
		b.Fatal("publish")
	}
	dpc := newDemuxPacketConn(nil, 64)
	it := &quicIntercept{conn: dpc}
	dcid := "ABCDEFGH"
	d.mu.Lock()
	flow := d.flows[tun.key]
	flow.conns[dcid] = &quicConn{odcid: dcid, state: connTerminated, stack: it}
	d.mu.Unlock()

	pkt := make([]byte, 1200)
	pkt[0] = 0xC3
	pkt[4] = 1
	pkt[5] = 8
	copy(pkt[6:], dcid)
	pkt[14] = 0
	return d, tun, dpc, pkt
}

func BenchmarkTunnelInbound(b *testing.B) {
	d, tun, dpc, pkt := tunnelBench(b)
	buf := make([]byte, maxUDPPayload)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		d.dispatch(tun.addr, pkt, true)
		if _, _, err := dpc.ReadFrom(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTunnelOutbound(b *testing.B) {
	_, tun, _, pkt := tunnelBench(b)
	origin := netip.MustParseAddrPort("127.0.0.1:443")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		tun.send(origin, pkt)
		out := <-tun.sendCh
		putTunnelBuf(out)
	}
}

// blackHoleRelay forwards datagrams between one client and front, and drops every one past
// the moment cut is set.
func blackHoleRelay(t *testing.T, front netip.AddrPort, cut *atomic.Bool) netip.AddrPort {
	t.Helper()
	in, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	out, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = in.Close()
		_ = out.Close()
	})
	var client atomic.Pointer[net.Addr]
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, rerr := in.ReadFrom(buf)
			if rerr != nil {
				return
			}
			client.Store(&addr)
			if !cut.Load() {
				_, _ = out.WriteTo(buf[:n], net.UDPAddrFromAddrPort(front))
			}
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, rerr := out.ReadFrom(buf)
			if rerr != nil {
				return
			}
			if c := client.Load(); c != nil && !cut.Load() {
				_, _ = in.WriteTo(buf[:n], *c)
			}
		}
	}()
	return netip.MustParseAddrPort(in.LocalAddr().String())
}

func TestConnectUDP_CloseEndsATunnelBehindAClientThatStoppedAcknowledging(t *testing.T) {
	flood := udpFlood(t, 20000, 1200)
	p, ca, front, _ := masqueProxy(t, WithIdleTimeout(10*time.Second))
	p.MustAdd[UDP]("127.0.0.1", forwardDatagram)
	var cut atomic.Bool
	relay := blackHoleRelay(t, front, &cut)
	cc := masqueClient(t, relay, ca)
	mc, _, err := openTunnel(t, cc, relay, flood.String(), nil)
	require.NoError(t, err)
	_, err = mc.WriteTo([]byte("go"), nil)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	cut.Store(true)
	time.Sleep(500 * time.Millisecond)

	var tunnel *Session
	for _, s := range waitForSessions(t, p, 2) {
		if s.Tunnel() {
			tunnel = s
		}
	}
	require.NotNil(t, tunnel)
	require.NoError(t, tunnel.Close())
	assert.Eventually(t, func() bool { return !slices.Contains(slices.Collect(p.Sessions()), tunnel) },
		2*time.Second, 20*time.Millisecond, "the tunnel outlived its close")
}

func TestConnectUDP_HalfCloseOverHTTP2WhileTheSenderIsBlocked(t *testing.T) {
	if !extendedConnectEnabled() {
		t.Skip("needs GODEBUG=http2xconnect=1")
	}
	fx := newUDPFixture(t)
	flood := udpFlood(t, 2000, 1200)
	front := fx.frontAddr(t, viaH2)
	tc := dialFront(t, netip.MustParseAddrPort(front), fx.ca, "h2")
	t.Cleanup(func() { _ = tc.Close() })
	_, err := tc.Write([]byte(http2.ClientPreface))
	require.NoError(t, err)
	fr := http2.NewFramer(tc, tc)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	// A stream window of 64 bytes leaves the sender blocked in its first write.
	require.NoError(t, fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 64}))
	head := make(chan *http2.MetaHeadersFrame, 1)
	ended := make(chan http2.Frame, 4)
	writes := make(chan func(), 16)
	go func() {
		for {
			f, rerr := fr.ReadFrame()
			if rerr != nil {
				return
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					writes <- func() { _ = fr.WriteSettingsAck() }
				}
			case *http2.PingFrame:
				if !f.IsAck() {
					data := f.Data
					writes <- func() { _ = fr.WritePing(true, data) }
				}
			case *http2.MetaHeadersFrame:
				head <- f
			case *http2.RSTStreamFrame:
				ended <- f
			case *http2.DataFrame:
				if f.StreamEnded() {
					ended <- f
				}
			}
		}
	}()
	write := func(fn func()) {
		done := make(chan struct{})
		writes <- func() {
			fn()
			close(done)
		}
		<-done
	}
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":protocol", Value: connectUDPUpgrade},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: front},
		{Name: ":path", Value: templatePath(flood.String())},
		{Name: "capsule-protocol", Value: "?1"},
	} {
		require.NoError(t, enc.WriteField(f))
	}
	require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: buf.Bytes(), EndHeaders: true}))
	go func() {
		for fn := range writes {
			fn()
		}
	}()
	select {
	case h := <-head:
		require.Equal(t, "200", h.PseudoValue("status"))
	case <-time.After(5 * time.Second):
		t.Fatal("the tunnel was not answered")
	}
	write(func() { _ = fr.WriteData(1, false, capsuleOf(0, append([]byte{0}, "go"...))) })
	time.Sleep(300 * time.Millisecond)
	write(func() { _ = fr.WriteData(1, true, nil) })
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream never ended")
	}
	time.Sleep(500 * time.Millisecond)
}
