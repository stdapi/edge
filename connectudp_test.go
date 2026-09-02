// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
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
	"strconv"
	"sync/atomic"
	"testing"
	"time"

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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The outer connection needs room for a 1200 byte Initial plus the datagram overhead,
	// which quic-go's default initial packet size does not leave.
	qconn, err := quic.DialAddr(ctx, addr.String(), &tls.Config{
		RootCAs:    poolOf(ca),
		ServerName: "127.0.0.1",
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	require.NoError(t, err)
	t.Cleanup(func() { _ = qconn.CloseWithError(0, "") })
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
func innerH3(t *testing.T, pconn *masqueConn, origin netip.AddrPort, name string, ca *CA) (*http3.ClientConn, *quic.Conn) {
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
	front, _ := startQUICFront(t, p, proxyCA)
	return p, proxyCA, front, origin
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
	sess := newSession(ctx, nil, target, KindHTTP, HTTP3)
	sess.remoteAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}
	tun := newConnectUDPTunnel(d, sess, target, netip.MustParseAddrPort("127.0.0.1:443"), cancel)
	require.True(t, d.publishTunnel(tun))
	tun.close()

	initial := make([]byte, 1200)
	initial[0], initial[4], initial[5] = 0xC0, 1, 8
	copy(initial[6:14], "12345678")
	d.dispatchLong(tun.addr, tun.key, initial)

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
