// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fox-toolkit/edge/internal/socks5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

// startSOCKS5 serves p as a SOCKS5 proxy on a loopback port and returns its address.
func startSOCKS5(t *testing.T, p *Proxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.ServeSOCKS5(ln) }()
	t.Cleanup(func() { _ = p.Close() })
	return ln.Addr().String()
}

// socksDialer returns a client of the SOCKS5 proxy at addr, one independent of the codec the
// proxy reads with.
func socksDialer(t *testing.T, addr string, auth *proxy.Auth) proxy.ContextDialer {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", addr, auth, &net.Dialer{Timeout: 5 * time.Second})
	require.NoError(t, err)
	return d.(proxy.ContextDialer)
}

// socksTLSClient reaches name through the SOCKS5 proxy at addr, asking it for authority and
// trusting the certificates ca mints.
func socksTLSClient(t *testing.T, addr, authority, name string, ca *CA, auth *proxy.Auth) *http.Client {
	t.Helper()
	d := socksDialer(t, addr, auth)
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				raw, err := d.DialContext(ctx, "tcp", authority)
				if err != nil {
					return nil, err
				}
				return tls.Client(raw, &tls.Config{
					ServerName: name,
					RootCAs:    ca.CertPool(),
					MinVersion: tls.VersionTLS12,
				}), nil
			},
		},
	}
}

func TestSOCKS5_NameRoutesAndTheTargetDials(t *testing.T) {
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
	p.MustAdd[TCP]("[127.0.0.0/8]", relayStream)
	addr := startSOCKS5(t, p)

	client := socksTLSClient(t, addr, origin.Host, "example.test", ca, nil)
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
	assert.False(t, sess.Transparent())
	assert.Empty(t, sess.Identity())
}

func TestSOCKS5_DeclaredNameIsDialed(t *testing.T) {
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
	addr := startSOCKS5(t, p)

	_, port, err := net.SplitHostPort(origin.Host)
	require.NoError(t, err)
	client := socksTLSClient(t, addr, "declared.test:"+port, "inner.test", ca, nil)
	resp, err := client.Get("https://inner.test/")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	assert.Equal(t, "declared.test:"+port, dialed.Load())
	sess := waitForSessions(t, p, 1)[0]
	assert.Equal(t, "inner.test", sess.Target().Host)
	assert.False(t, sess.Upstream().IsValid(), "a name is left to the dial to resolve")
}

func TestSOCKS5_RefusesWhatNothingAdmits(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[TCP]("allowed.test", relayStream)
	addr := startSOCKS5(t, p)
	d := socksDialer(t, addr, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "nothing.test:443")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed by ruleset")
	assert.Empty(t, slices.Collect(p.Sessions()))
}

func TestSOCKS5_BindIsNotServed(t *testing.T) {
	p := testProxy(t)
	addr := startSOCKS5(t, p)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	require.NoError(t, socks5.WriteMethods(conn, socks5.MethodNoAuth))
	method, err := socks5.ReadMethod(conn)
	require.NoError(t, err)
	require.Equal(t, byte(socks5.MethodNoAuth), method)
	require.NoError(t, socks5.WriteRequest(conn, socks5.CmdBind, socks5.Addr{IP: netip.MustParseAddr("127.0.0.1"), Port: 1}))
	_, _, err = socks5.ReadReply(conn)
	assert.ErrorIs(t, err, socks5.CommandNotSupported)
}

func TestSOCKS5_Auth(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	origin := namedOrigin(t, ca, "example.test")
	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	p, err := New(WithCA(ca), WithTransport(tr), WithProxyAuth(testBasic()))
	require.NoError(t, err)
	p.MustAdd("example.test/", forwardHandler)
	p.MustAdd[TCP]("[127.0.0.0/8]", relayStream)
	addr := startSOCKS5(t, p)

	t.Run("no credentials", func(t *testing.T) {
		d := socksDialer(t, addr, nil)
		_, err := d.DialContext(t.Context(), "tcp", origin.Host)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no acceptable authentication")
	})

	t.Run("wrong credentials", func(t *testing.T) {
		d := socksDialer(t, addr, &proxy.Auth{User: "alice", Password: "wrong"})
		_, err := d.DialContext(t.Context(), "tcp", origin.Host)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authentication failed")
		assert.Empty(t, slices.Collect(p.Sessions()))
	})

	t.Run("the identity is reported", func(t *testing.T) {
		client := socksTLSClient(t, addr, origin.Host, "example.test", ca, &proxy.Auth{User: "alice", Password: "secret"})
		resp, err := client.Get("https://example.test/")
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		sess := waitForSessions(t, p, 1)[0]
		assert.Equal(t, "alice", sess.Identity())
	})
}

// An authenticator reading HTTP requests alone has nothing to read on a SOCKS5 front, which
// is refused before it accepts a client.
func TestSOCKS5_RefusesAnAuthenticatorWithoutPasswords(t *testing.T) {
	p := testProxy(t, WithProxyAuth(httpOnlyAuth{}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	assert.ErrorIs(t, p.ServeSOCKS5(ln), ErrInvalidConfig)
}

type httpOnlyAuth struct{}

func (httpOnlyAuth) Authenticate(*http.Request) (string, bool) { return "anyone", true }
func (httpOnlyAuth) Challenges(*http.Request) []string         { return nil }

// A plaintext connection through a SOCKS5 CONNECT has no absolute target, so it is routed on
// the Host of its first request, as a redirected connection is.
func TestSOCKS5_PlaintextIsRoutedOnItsFirstAuthority(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin got host=%s", r.Host)
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)
	p := testProxy(t, WithTransport(tr), WithProxyAuth(testBasic()))
	p.MustAdd("allowed.test/*{rest}", forwardHandler)
	addr := startSOCKS5(t, p)

	d := socksDialer(t, addr, &proxy.Auth{User: "bob", Password: "hunter2"})
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DialContext: d.DialContext},
	}

	resp, err := client.Get("http://allowed.test/probe")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "origin got host=allowed.test", string(body))

	sess := waitForSessions(t, p, 1)[0]
	assert.Equal(t, KindHTTP, sess.Kind())
	assert.Equal(t, HTTP11, sess.Protocol())
	assert.Equal(t, "bob", sess.Identity())

	_, err = client.Get("http://nothing.test/probe")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed by ruleset")
}

// socksUDPClient is a client of one UDP association, its handshake and its headers written
// by hand. Each datagram written to a *net.UDPAddr is addressed to that address, and one
// written to a hostDest to that hostname.
type socksUDPClient struct {
	ctrl  net.Conn
	conn  *net.UDPConn
	relay *net.UDPAddr
}

type hostDest string

func (hostDest) Network() string  { return "udp" }
func (n hostDest) String() string { return string(n) }

// associate opens a UDP association on the SOCKS5 proxy at addr, authenticating as user when
// one is given.
func associate(t *testing.T, addr, user, pass string) *socksUDPClient {
	t.Helper()
	ctrl, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctrl.Close() })
	require.NoError(t, ctrl.SetDeadline(time.Now().Add(5*time.Second)))

	method := byte(0)
	if user != "" {
		method = 2
	}
	_, err = ctrl.Write([]byte{5, 1, method})
	require.NoError(t, err)
	var reply [2]byte
	_, err = io.ReadFull(ctrl, reply[:])
	require.NoError(t, err)
	require.Equal(t, [2]byte{5, method}, reply)
	if user != "" {
		creds := append([]byte{1, byte(len(user))}, user...)
		creds = append(creds, byte(len(pass)))
		creds = append(creds, pass...)
		_, err = ctrl.Write(creds)
		require.NoError(t, err)
		_, err = io.ReadFull(ctrl, reply[:])
		require.NoError(t, err)
		require.Equal(t, [2]byte{1, 0}, reply)
	}

	_, err = ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	require.NoError(t, err)
	var head [4 + 4 + 2]byte
	_, err = io.ReadFull(ctrl, head[:])
	require.NoError(t, err)
	require.Equal(t, byte(0), head[1], "the association is granted")
	require.Equal(t, byte(1), head[3], "the relay is an IPv4 address")
	relay := &net.UDPAddr{IP: net.IP(head[4:8]), Port: int(head[8])<<8 | int(head[9])}
	require.NoError(t, ctrl.SetDeadline(time.Time{}))

	conn, err := net.DialUDP("udp4", nil, relay)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return &socksUDPClient{ctrl: ctrl, conn: conn, relay: relay}
}

func (c *socksUDPClient) WriteTo(b []byte, addr net.Addr) (int, error) {
	var hdr []byte
	switch a := addr.(type) {
	case *net.UDPAddr:
		hdr = append([]byte{0, 0, 0, 1}, a.IP.To4()...)
		hdr = append(hdr, byte(a.Port>>8), byte(a.Port))
	case hostDest:
		host, port, err := net.SplitHostPort(string(a))
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(port)
		if err != nil {
			return 0, err
		}
		hdr = append([]byte{0, 0, 0, 3, byte(len(host))}, host...)
		hdr = append(hdr, byte(n>>8), byte(n))
	default:
		return 0, fmt.Errorf("address %T is not addressable", addr)
	}
	if _, err := c.conn.Write(append(hdr, b...)); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *socksUDPClient) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, 65535)
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < 10 || buf[3] != 1 {
			continue
		}
		from := &net.UDPAddr{IP: net.IP(slices.Clone(buf[4:8])), Port: int(buf[8])<<8 | int(buf[9])}
		return copy(b, buf[10:n]), from, nil
	}
}

func (c *socksUDPClient) Close() error {
	_ = c.ctrl.Close()
	return c.conn.Close()
}

func (c *socksUDPClient) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *socksUDPClient) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *socksUDPClient) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *socksUDPClient) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
func (c *socksUDPClient) SetReadBuffer(int) error            { return nil }
func (c *socksUDPClient) SetWriteBuffer(int) error           { return nil }

// echoThroughSOCKS sends msg to dest through the association and returns what came back with
// the address it came from.
func echoThroughSOCKS(t *testing.T, c *socksUDPClient, dest net.Addr, msg string) (string, net.Addr) {
	t.Helper()
	_, err := c.WriteTo([]byte(msg), dest)
	require.NoError(t, err)
	require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 64)
	n, from, err := c.ReadFrom(buf)
	require.NoError(t, err)
	return string(buf[:n]), from
}

// Every datagram in an association is routed on its own destination, an address or a name
// the proxy resolves, and the flows inside it hang under the association with its identity.
func TestSOCKS5_AssociateRoutesDatagramsOnTheirDestination(t *testing.T) {
	echo := udpEcho(t)
	byHost := udpEcho(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	resolver := &fakeResolver{addrs: map[string][]netip.Addr{"echo.udp.test": {byHost.Addr()}}}
	p, err := New(WithCA(ca), WithNameResolver(resolver), WithProxyAuth(testBasic()))
	require.NoError(t, err)

	seen := new(recorder)
	p.MustAdd[UDP](fmt.Sprintf("{name}.udp.test:%d", byHost.Port()), func(c *DatagramCtx) error {
		seen.add(fmt.Sprintf("%s %s %v %s", c.Param("name"), c.Target().Host, c.Inbound(), c.Bytes()))
		return c.Forward()
	})
	p.MustAdd[UDP]("[127.0.0.0/8]", func(c *DatagramCtx) error {
		seen.add(fmt.Sprintf("literal %s %v %s", c.Target().Host, c.Inbound(), c.Bytes()))
		return c.Forward()
	})
	addr := startSOCKS5(t, p)
	client := associate(t, addr, "alice", "secret")

	body, from := echoThroughSOCKS(t, client, net.UDPAddrFromAddrPort(echo), "ping")
	assert.Equal(t, "ping", body)
	assert.Equal(t, echo.String(), from.String(), "the reply reports the origin it came from")

	body, from = echoThroughSOCKS(t, client, hostDest(fmt.Sprintf("Echo.udp.test:%d", byHost.Port())), "pong")
	assert.Equal(t, "pong", body)
	assert.Equal(t, byHost.String(), from.String())
	assert.Equal(t, []string{
		"literal 127.0.0.1 false ping", "literal 127.0.0.1 true ping",
		"echo echo.udp.test false pong", "echo echo.udp.test true pong",
	}, seen.all())
	assert.EqualValues(t, 1, resolver.calls.Load(), "resolved once for the association")

	sessions := waitForSessions(t, p, 3)
	var assoc *Session
	for _, s := range sessions {
		if s.Tunnel() {
			assoc = s
		}
	}
	require.NotNil(t, assoc)
	assert.Equal(t, Kind(0), assoc.Kind())
	assert.Empty(t, assoc.Target().Host)
	assert.Equal(t, "alice", assoc.Identity())
	assert.False(t, assoc.Stale())
	for _, s := range sessions {
		if s.Tunnel() {
			continue
		}
		assert.Same(t, assoc, s.Via())
		assert.Equal(t, KindUDP, s.Kind())
		assert.Equal(t, "alice", s.Identity())
	}

	// Closing the control connection ends the association and everything inside it.
	require.NoError(t, client.ctrl.Close())
	waitForSessions(t, p, 0)
}

// An HTTP/3 connection inside an association is terminated on a stack of the association
// and the origin, and routed request by request.
func TestSOCKS5_AssociateTerminatesTheInnerHTTP3(t *testing.T) {
	p, ca, origin := newMasqueProxy(t)
	addr := startSOCKS5(t, p)
	client := associate(t, addr, "", "")

	inner, qconn := innerH3(t, client, origin, h3Authority, ca)
	target := fmt.Sprintf("%s:%d", h3Authority, origin.Port())
	body, err := getThrough(inner, fmt.Sprintf("https://%s/echo", target))
	require.NoError(t, err)
	assert.Contains(t, body, "path=/echo")
	assert.Contains(t, body, "proto=HTTP/3.0")

	sessions := waitForSessions(t, p, 2)
	var assoc, conn *Session
	for _, s := range sessions {
		if s.Tunnel() {
			assoc = s
		} else {
			conn = s
		}
	}
	require.NotNil(t, assoc)
	require.NotNil(t, conn)
	assert.Same(t, assoc, conn.Via())
	assert.Equal(t, KindHTTP, conn.Kind())
	assert.Equal(t, HTTP3, conn.Protocol())
	assert.Equal(t, h3Authority, conn.Target().Host)
	assert.Equal(t, origin, conn.Upstream())

	require.NoError(t, assoc.Close())
	waitForSessions(t, p, 0)
	requireEnded(t, qconn, "the inner connection is closed through the association")
	_, err = io.ReadAll(client.ctrl)
	assert.NoError(t, err, "the control connection is closed by the proxy")
}

// A datagram from a source other than the one the association is bound to is dropped.
func TestSOCKS5_AssociationDropsOtherSources(t *testing.T) {
	echo := udpEcho(t)
	p := testProxy(t)
	p.MustAdd[UDP]("[127.0.0.0/8]", forwardDatagram)
	addr := startSOCKS5(t, p)
	client := associate(t, addr, "", "")
	body, _ := echoThroughSOCKS(t, client, net.UDPAddrFromAddrPort(echo), "first")
	assert.Equal(t, "first", body)

	other, err := net.DialUDP("udp4", nil, client.relay)
	require.NoError(t, err)
	defer func() { _ = other.Close() }()
	hdr := append([]byte{0, 0, 0, 1}, echo.Addr().AsSlice()...)
	hdr = append(hdr, byte(echo.Port()>>8), byte(echo.Port()))
	_, err = other.Write(append(hdr, "intruder"...))
	require.NoError(t, err)
	require.NoError(t, other.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
	buf := make([]byte, 64)
	_, err = other.Read(buf)
	require.Error(t, err, "nothing comes back to a source the association is not bound to")

	body, _ = echoThroughSOCKS(t, client, net.UDPAddrFromAddrPort(echo), "second")
	assert.Equal(t, "second", body)
}

// An association nothing has lived in for udpFlowIdle is closed by the sweep, and the client
// learns it from the end of its control connection.
func TestSOCKS5_IdleAssociationIsClosed(t *testing.T) {
	p := testProxy(t)
	addr := startSOCKS5(t, p)
	client := associate(t, addr, "", "")
	assoc := waitForSessions(t, p, 1)[0]
	require.True(t, assoc.Tunnel())

	d := p.srv.tunnels
	require.NotNil(t, d)
	d.mu.Lock()
	for _, flow := range d.flows {
		flow.lastSeen = time.Now().Add(-2 * udpFlowIdle)
	}
	d.mu.Unlock()
	d.sweepIdle()

	waitForSessions(t, p, 0)
	require.NoError(t, client.ctrl.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, err := client.ctrl.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

// Past maxUDPPerFlow destinations the least recently used flow of the association makes
// room, so a client talking to many destinations is never locked out.
func TestSOCKS5_AssociationEvictsTheLeastRecentlyUsedFlow(t *testing.T) {
	p := testProxy(t)
	p.MustAdd[UDP]("[127.0.0.0/8]", forwardDatagram)
	addr := startSOCKS5(t, p)
	client := associate(t, addr, "", "")

	echoes := make([]netip.AddrPort, maxUDPPerFlow+1)
	for i := range echoes {
		echoes[i] = udpEcho(t)
	}
	for i, echo := range echoes[:maxUDPPerFlow] {
		body, _ := echoThroughSOCKS(t, client, net.UDPAddrFromAddrPort(echo), fmt.Sprint("d", i))
		require.Equal(t, fmt.Sprint("d", i), body)
		time.Sleep(time.Millisecond)
	}
	body, _ := echoThroughSOCKS(t, client, net.UDPAddrFromAddrPort(echoes[maxUDPPerFlow]), "last")
	assert.Equal(t, "last", body)

	sessions := waitForSessions(t, p, maxUDPPerFlow+1)
	first := netip.AddrPortFrom(echoes[0].Addr(), echoes[0].Port())
	for _, s := range sessions {
		assert.NotEqual(t, first, s.Upstream(), "the first destination, the least recently used, was evicted")
	}
}

// The source of an association is the address of its control connection, whatever the client
// declared, so a client cannot bind an association to another address.
func TestSOCKS5_AssociationBindsToTheControlAddress(t *testing.T) {
	echo := udpEcho(t)
	p := testProxy(t)
	p.MustAdd[UDP]("[127.0.0.0/8]", forwardDatagram)
	addr := startSOCKS5(t, p)

	ctrl, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = ctrl.Close() }()
	require.NoError(t, ctrl.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, socks5.WriteMethods(ctrl, socks5.MethodNoAuth))
	_, err = socks5.ReadMethod(ctrl)
	require.NoError(t, err)
	require.NoError(t, socks5.WriteRequest(ctrl, socks5.CmdAssociate, socks5.Addr{IP: netip.MustParseAddr("10.9.9.9"), Port: 0}))
	_, relay, err := socks5.ReadReply(ctrl)
	require.NoError(t, err)
	relayAddr, ok := relay.AddrPort()
	require.True(t, ok)

	conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(relayAddr))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	client := &socksUDPClient{ctrl: ctrl, conn: conn}
	body, _ := echoThroughSOCKS(t, client, net.UDPAddrFromAddrPort(echo), "hello")
	assert.Equal(t, "hello", body, "the declared address is ignored, the control address is what binds")
}
