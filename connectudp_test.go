// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fox-toolkit/edge/internal/h2tunnel"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// A CONNECT-UDP tunnel carries an HTTP/3 connection the proxy terminates and routes request
// by request, exactly as it would off a redirected socket. The tunnel and the connection
// inside it are two sessions, the second hanging under the first.
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

// Raw datagrams in a tunnel are routed one by one on the declared target, which may be a
// hostname, so a UDP entry captures parameters a redirected socket never could.
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

// Closing a tunnel closes the alternates its datagram flows opened with their upstream
// sockets.
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

// The declared target is admitted before it is resolved, so a refused target is not resolved,
// and resolution comes before the proxy answers. Neither failure opens anything.
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

// A datagram that passed the closed check in dispatch while the tunnel was closing finds no
// flow and must not create one. The guard runs under the lock the close ran under.
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
	tun := newConnectUDPTunnel(d, sess, target, netip.MustParseAddrPort("127.0.0.1:443"), cancel)
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

// Deleting the entry that admitted a tunnel makes the documented sweep close it, and the next
// CONNECT-UDP for the target is refused.
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

// A tunnel is the authenticated unit. Revoking its identity by closing every session carrying
// it ends the tunnel and what it carries, and the next CONNECT-UDP is challenged again.
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

// A tunnel nothing has lived in for a while is closed, the way an idle datagram flow is
// forgotten, and the client learns it from its stream.
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
	assert.NotErrorIs(t, err, os.ErrDeadlineExceeded)
}

// The target parser is fed by the network. Whatever it accepts must be an authority that
// splits and rejoins to itself, so the target written back is the one that was routed on.
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

// A client that sends no server name gets a certificate for the target its tunnel declared.
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

// A tunnel is decided on its kind alone, so it goes stale when its target would now be
// admitted under another kind, and not when the entries within that kind change.
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
	go func() { _ = p.serveFront(tls.NewListener(cancelListener{ln}, cfg)) }()
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

// A tunnel over TCP carries an HTTP/3 connection the proxy terminates and routes request by
// request, the tunnel reporting the front's protocol, and closing it ends the stream.
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

// Raw datagrams in a tunnel over TCP are routed one by one on the declared target.
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

// A refused or unresolvable target is answered with an ordinary status, before any tunnel
// exists, on a TCP front as on the HTTP/3 one.
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

// The client ending its direction ends the tunnel, and so does dropping the stream.
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

// A capsule of another type is skipped, RFC 9297 section 3.2, and a DATAGRAM capsule larger
// than a UDP payload can be is dropped, neither ending the tunnel.
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
			require.NoError(t, pconn.writeCapsule(0, make([]byte, maxCapsuleDatagram+1)))
			_, err = pconn.WriteTo([]byte("still here"), nil)
			require.NoError(t, err)
			require.NoError(t, pconn.SetReadDeadline(time.Now().Add(5*time.Second)))
			buf := make([]byte, 64)
			n, _, err := pconn.ReadFrom(buf)
			require.NoError(t, err)
			assert.Equal(t, "still here", string(buf[:n]))
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

// A client that stops reading its tunnel leaves the proxy's writes stuck. Closing the tunnel
// still ends it, within the drain timeout, and a shutdown reaches it.
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
