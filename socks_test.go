// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"encoding/binary"
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
	"testing"
	"time"

	"github.com/fox-toolkit/edge/internal/netutil"
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

type socksEcho struct {
	body string
	from string
}

// readAllThroughSOCKS reads up to n replies, stopping early when none arrives for a while.
func readAllThroughSOCKS(t *testing.T, c *socksUDPClient, n int) []socksEcho {
	t.Helper()
	var got []socksEcho
	buf := make([]byte, 64)
	for len(got) < n {
		require.NoError(t, c.SetReadDeadline(time.Now().Add(2*time.Second)))
		m, from, err := c.ReadFrom(buf)
		if err != nil {
			break
		}
		got = append(got, socksEcho{body: string(buf[:m]), from: from.String()})
	}
	return got
}

func bodies(echoes []socksEcho) []string {
	out := make([]string, 0, len(echoes))
	for _, e := range echoes {
		out = append(out, e.body)
	}
	return out
}

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

// heldResolver answers once released, and reports each lookup as it starts.
type heldResolver struct {
	addrs   map[string][]netip.Addr
	entered chan string
	release chan struct{}
}

func (r *heldResolver) LookupNetIP(ctx context.Context, _ string, host string) ([]netip.Addr, error) {
	r.entered <- host
	select {
	case <-r.release:
		return r.addrs[host], nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestSOCKS5_AssociationResolvesNamesOffItsLoop(t *testing.T) {
	echo := udpEcho(t)
	byHost := udpEcho(t)
	resolver := &heldResolver{
		addrs:   map[string][]netip.Addr{"echo.udp.test": {byHost.Addr()}},
		entered: make(chan string, 1),
		release: make(chan struct{}),
	}
	p := testProxy(t, WithNameResolver(resolver))
	p.MustAdd[UDP]("[127.0.0.0/8]", forwardDatagram)
	p.MustAdd[UDP]("echo.udp.test", forwardDatagram)
	addr := startSOCKS5(t, p)
	client := associate(t, addr, "", "")
	name := hostDest(fmt.Sprintf("echo.udp.test:%d", byHost.Port()))

	_, err := client.WriteTo([]byte("held"), name)
	require.NoError(t, err)
	select {
	case host := <-resolver.entered:
		assert.Equal(t, "echo.udp.test", host)
	case <-time.After(5 * time.Second):
		t.Fatal("the name was not looked up")
	}
	_, err = client.WriteTo([]byte("held too"), name)
	require.NoError(t, err)

	body, _ := echoThroughSOCKS(t, client, net.UDPAddrFromAddrPort(echo), "meanwhile")
	assert.Equal(t, "meanwhile", body, "an address flows while the name resolves")

	close(resolver.release)
	got := readAllThroughSOCKS(t, client, 2)
	assert.Equal(t, []string{"held", "held too"}, bodies(got), "released in arrival order")
	assert.Equal(t, byHost.String(), got[0].from, "answered from the resolved address")

	body, _ = echoThroughSOCKS(t, client, name, "cached")
	assert.Equal(t, "cached", body)
	select {
	case host := <-resolver.entered:
		t.Fatalf("%s was looked up again", host)
	default:
	}
}

func TestSOCKS5_AssociationBoundsWhatWaitsOnAName(t *testing.T) {
	echo := udpEcho(t)
	byHost := udpEcho(t)
	resolver := &heldResolver{
		addrs:   map[string][]netip.Addr{},
		entered: make(chan string, socks5NameResolving+1),
		release: make(chan struct{}),
	}
	p := testProxy(t, WithNameResolver(resolver))
	forwarded := make(chan string, (socks5NameResolving+1)*(maxPendingDatagrams+1))
	p.MustAdd[UDP]("+{any}.udp.test", func(c *DatagramCtx) error {
		if !c.Inbound() {
			forwarded <- c.Param("any")
		}
		return c.Forward()
	})
	p.MustAdd[UDP]("[127.0.0.0/8]", forwardDatagram)
	addr := startSOCKS5(t, p)
	client := associate(t, addr, "", "")

	for i := range socks5NameResolving + 1 {
		host := fmt.Sprintf("n%d.udp.test", i)
		resolver.addrs[host] = []netip.Addr{byHost.Addr()}
		name := hostDest(fmt.Sprintf("%s:%d", host, byHost.Port()))
		for range maxPendingDatagrams + 1 {
			_, err := client.WriteTo([]byte(host), name)
			require.NoError(t, err)
		}
	}
	for range socks5NameResolving {
		select {
		case <-resolver.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("a name was not looked up")
		}
	}
	// The relay reads in order, so once the probe is answered every datagram above is queued
	// or dropped.
	body, _ := echoThroughSOCKS(t, client, net.UDPAddrFromAddrPort(echo), "probe")
	require.Equal(t, "probe", body)
	close(resolver.release)
	got := make(map[string]int)
	for range socks5NameResolving * maxPendingDatagrams {
		select {
		case name := <-forwarded:
			got[name]++
		case <-time.After(5 * time.Second):
			t.Fatalf("forwarded %v", got)
		}
	}
	want := make(map[string]int)
	for i := range socks5NameResolving {
		want[fmt.Sprintf("n%d", i)] = maxPendingDatagrams
	}
	assert.Equal(t, want, got, "every name within the bound reached its entry up to its own bound")
}

func TestSOCKS5_AssociationFlowSocketLeavesDontFragmentUnset(t *testing.T) {
	echo := udpEcho(t)
	p, err := New()
	require.NoError(t, err)
	p.MustAdd[UDP]("[127.0.0.0/8]", func(c *DatagramCtx) error { return c.Forward() })
	client := associate(t, startSOCKS5(t, p), "", "")

	body, _ := echoThroughSOCKS(t, client, net.UDPAddrFromAddrPort(echo), "ping")
	require.Equal(t, "ping", body)
	set, err := netutil.DontFragment(flowSocket(t, p))
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skip("the Don't Fragment bit is read on Linux and darwin alone")
	}
	require.NoError(t, err)
	assert.False(t, set)
}

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

func TestConformanceSOCKS5(t *testing.T) {
	runConformance(t, socksConformance)
}

type socksWire struct {
	t    *testing.T
	conn net.Conn
}

func dialSOCKSWire(t *testing.T, addr string) *socksWire {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return &socksWire{t: t, conn: conn}
}

func (w *socksWire) write(parts ...[]byte) {
	w.t.Helper()
	require.NoError(w.t, w.conn.SetWriteDeadline(time.Now().Add(5*time.Second)))
	_, err := w.conn.Write(slices.Concat(parts...))
	require.NoError(w.t, err)
}

func (w *socksWire) read(n int) []byte {
	w.t.Helper()
	require.NoError(w.t, w.conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	b := make([]byte, n)
	_, err := io.ReadFull(w.conn, b)
	require.NoError(w.t, err)
	return b
}

func (w *socksWire) want(want ...byte) {
	w.t.Helper()
	require.Equal(w.t, want, w.read(len(want)))
}

func (w *socksWire) readReply() []byte {
	w.t.Helper()
	head := w.read(5)
	switch head[3] {
	case 1:
		return append(head, w.read(4+2-1)...)
	case 4:
		return append(head, w.read(16+2-1)...)
	case 3:
		return append(head, w.read(int(head[4])+2)...)
	}
	w.t.Fatalf("reply %x has an unknown address type", head)
	return nil
}

// The deadline is the ten seconds RFC 1928 section 6 allows after a failure.
func (w *socksWire) wantClosed() {
	w.t.Helper()
	require.NoError(w.t, w.conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	b := make([]byte, 64)
	n, err := w.conn.Read(b)
	require.Zero(w.t, n, "the peer wrote %x", b[:n])
	require.Error(w.t, err)
	require.NotErrorIs(w.t, err, os.ErrDeadlineExceeded, "the connection is still open")
}

func (w *socksWire) wantSilent() {
	w.t.Helper()
	require.NoError(w.t, w.conn.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
	b := make([]byte, 64)
	n, err := w.conn.Read(b)
	require.Zero(w.t, n, "the peer wrote %x", b[:n])
	require.ErrorIs(w.t, err, os.ErrDeadlineExceeded)
}

func be16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func socksAddrBytes(ap netip.AddrPort) []byte {
	atyp := byte(4)
	if ap.Addr().Is4() {
		atyp = 1
	}
	return slices.Concat([]byte{atyp}, ap.Addr().AsSlice(), be16(ap.Port()))
}

func socksNameBytes(name string, port uint16) []byte {
	return slices.Concat([]byte{3, byte(len(name))}, []byte(name), be16(port))
}

func socksDatagram(frag byte, dst []byte, payload string) []byte {
	return slices.Concat([]byte{0, 0, frag}, dst, []byte(payload))
}

var (
	socksGranted4 = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	socksZeros4   = socksAddrBytes(netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	// socksPayload starts with a byte no HTTP method does, so the front relays it at once.
	socksPayload = []byte{0x00, 0x2a, 's', 'o', 'c', 'k', 's'}
)

func socksConnect(t *testing.T, addr string, dst []byte) *socksWire {
	t.Helper()
	w := dialSOCKSWire(t, addr)
	w.write([]byte{5, 1, 0})
	w.want(5, 0)
	w.write([]byte{5, 1, 0}, dst)
	return w
}

func (w *socksWire) wantEcho() {
	w.t.Helper()
	w.write(socksPayload)
	w.want(socksPayload...)
}

func socksAssociate(t *testing.T, addr string, from []byte) (*socksWire, netip.AddrPort) {
	t.Helper()
	w := dialSOCKSWire(t, addr)
	w.write([]byte{5, 1, 0})
	w.want(5, 0)
	w.write([]byte{5, 3, 0}, from)
	reply := w.read(10)
	require.Equal(t, []byte{5, 0, 0, 1}, reply[:4], "the association is granted on an IPv4 relay")
	return w, netip.AddrPortFrom(netip.AddrFrom4([4]byte(reply[4:8])), binary.BigEndian.Uint16(reply[8:]))
}

func startSOCKS5On(t *testing.T, p *Proxy, addr string) string {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	go func() { _ = p.ServeSOCKS5(ln) }()
	t.Cleanup(func() { _ = p.Close() })
	return ln.Addr().String()
}

func tcpEchoOn(t *testing.T, addr string) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	return addrPort(ln.Addr())
}

func listenUDP(t *testing.T, addr string) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func udpOriginOn(t *testing.T, addr string) (netip.AddrPort, <-chan string) {
	t.Helper()
	conn := listenUDP(t, addr)
	got := make(chan string, 16)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			select {
			case got <- string(buf[:n]):
			default:
			}
			_, _ = conn.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	return addrPort(conn.LocalAddr()), got
}

func wantPayload(t *testing.T, got <-chan string, want string) {
	t.Helper()
	select {
	case p := <-got:
		require.Equal(t, want, p)
	case <-time.After(5 * time.Second):
		t.Fatalf("the origin did not receive %q", want)
	}
}

func wantNoPayload(t *testing.T, got <-chan string) {
	t.Helper()
	select {
	case p := <-got:
		t.Fatalf("the origin received %q", p)
	case <-time.After(300 * time.Millisecond):
	}
}

func socksReadDatagram(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	return buf[:n]
}

type socksSpoofedListener struct {
	net.Listener
	remote net.Addr
}

func (l socksSpoofedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return socksSpoofedConn{Conn: c, remote: l.remote}, nil
}

type socksSpoofedConn struct {
	net.Conn
	remote net.Addr
}

func (c socksSpoofedConn) RemoteAddr() net.Addr { return c.remote }

type socksUpstream struct {
	t     *testing.T
	conns chan net.Conn
	addr  string
}

func newSOCKSUpstream(t *testing.T) *socksUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	u := &socksUpstream{t: t, conns: make(chan net.Conn, 4), addr: ln.Addr().String()}
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			u.conns <- c
		}
	}()
	return u
}

func (u *socksUpstream) url(userinfo string) string { return "socks5://" + userinfo + u.addr }

func (u *socksUpstream) accept() *socksWire {
	u.t.Helper()
	select {
	case c := <-u.conns:
		u.t.Cleanup(func() { _ = c.Close() })
		return &socksWire{t: u.t, conn: c}
	case <-time.After(5 * time.Second):
		u.t.Fatal("the exit did not dial its upstream")
		return nil
	}
}

func (u *socksUpstream) greeted() *socksWire {
	u.t.Helper()
	w := u.accept()
	w.want(5, 1, 0)
	w.write([]byte{5, 0})
	return w
}

type socksDialResult struct {
	conn net.Conn
	err  error
}

func socksExitDial(proxyURL, network, addr string) <-chan socksDialResult {
	tr := DefaultTransport()
	tr.Proxy = fixedProxy(proxyURL)
	u := newUpstreamDialer(tr)
	done := make(chan socksDialResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := u.dial(ctx, network, addr, "https")
		done <- socksDialResult{conn: conn, err: err}
	}()
	return done
}

func socksDialed(t *testing.T, done <-chan socksDialResult) net.Conn {
	t.Helper()
	select {
	case r := <-done:
		require.NoError(t, r.err)
		t.Cleanup(func() { _ = r.conn.Close() })
		return r.conn
	case <-time.After(10 * time.Second):
		t.Fatal("the dial did not return")
		return nil
	}
}

func socksDialFailed(t *testing.T, done <-chan socksDialResult) error {
	t.Helper()
	select {
	case r := <-done:
		require.Error(t, r.err)
		require.Nil(t, r.conn)
		return r.err
	case <-time.After(10 * time.Second):
		t.Fatal("the dial did not return")
		return nil
	}
}

func socksExitAssociate(t *testing.T, dest string) (net.Conn, *socksWire, *net.UDPConn) {
	t.Helper()
	up := newSOCKSUpstream(t)
	relay := listenUDP(t, "127.0.0.1:0")
	done := socksExitDial(up.url(""), "udp", dest)
	w := up.greeted()
	w.want(5, 3, 0, 1, 0, 0, 0, 0, 0, 0)
	w.write([]byte{5, 0, 0}, socksAddrBytes(addrPort(relay.LocalAddr())))
	return socksDialed(t, done), w, relay
}

func readRelay(t *testing.T, relay *net.UDPConn) ([]byte, netip.AddrPort) {
	t.Helper()
	require.NoError(t, relay.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 2048)
	n, from, err := relay.ReadFromUDPAddrPort(buf)
	require.NoError(t, err)
	return buf[:n], from
}

const socksNoEncapsulation = "edge negotiates no authentication and username/password only, and neither defines an encapsulation"

// socksConformance lists the requirements of RFC 1928 and RFC 1929, checked on the wire against
// the SOCKS5 front with a scripted client, or against the exit with a scripted upstream proxy.
var socksConformance = []conformanceCase{
	{
		id: "rfc1928/3/1", name: "the client offers GSSAPI, a private method and no authentication",
		req: "The server selects from one of the methods given in METHODS, and sends a METHOD selection message",
		run: func(t *testing.T) {
			w := dialSOCKSWire(t, startSOCKS5(t, testProxy(t)))
			w.write([]byte{5, 3, 0x01, 0x80, 0x00})
			w.want(5, 0x00)
		},
	},
	{
		id: "rfc1928/3/2", name: "the client offers no method the front accepts",
		req: "If the selected METHOD is X'FF', none of the methods listed by the client are acceptable, and the client MUST close the connection.",
		run: func(t *testing.T) {
			open := dialSOCKSWire(t, startSOCKS5(t, testProxy(t)))
			open.write([]byte{5, 1, 0x02})
			open.want(5, 0xFF)
			open.wantClosed()

			authenticated := dialSOCKSWire(t, startSOCKS5(t, testProxy(t, WithProxyAuth(testBasic()))))
			authenticated.write([]byte{5, 1, 0x00})
			authenticated.want(5, 0xFF)
			authenticated.wantClosed()
		},
	},
	{
		id: "rfc1928/3/3", name: "the client greets with version 4",
		req: "The VER field is set to X'05' for this version of the protocol.",
		run: func(t *testing.T) {
			w := dialSOCKSWire(t, startSOCKS5(t, testProxy(t)))
			w.write([]byte{4, 1, 0x00})
			w.wantClosed()
		},
	},
	{
		id: "rfc1928/3/4", name: "the client greets with NMETHODS zero",
		req: "The NMETHODS field contains the number of method identifier octets that appear in the METHODS field.",
		run: func(t *testing.T) {
			w := dialSOCKSWire(t, startSOCKS5(t, testProxy(t)))
			w.write([]byte{5, 0})
			w.wantClosed()
		},
	},
	{
		id: "rfc1928/3/5", name: "the client offers GSSAPI alone",
		req:  "Compliant implementations MUST support GSSAPI and SHOULD support USERNAME/PASSWORD authentication methods.",
		skip: "ListenAndServeSOCKS5 documents that GSSAPI is not offered, and the exit offers no authentication and username/password only",
	},
	{
		id: "rfc1928/3/6", name: "the proxy is greeted without and with credentials and selects no authentication",
		req: "The client connects to the server, and sends a version identifier/method selection message",
		run: func(t *testing.T) {
			up := newSOCKSUpstream(t)
			target := netip.MustParseAddrPort("127.0.0.1:443")
			request := slices.Concat([]byte{5, 1, 0}, socksAddrBytes(target))

			done := socksExitDial(up.url(""), "tcp", target.String())
			w := up.accept()
			w.want(5, 1, 0x00)
			w.write([]byte{5, 0x00})
			w.want(request...)
			w.write(socksGranted4)
			socksDialed(t, done)

			done = socksExitDial(up.url("alice:secret@"), "tcp", target.String())
			w = up.accept()
			w.want(5, 2, 0x00, 0x02)
			w.write([]byte{5, 0x00})
			w.want(request...)
			w.write(socksGranted4)
			socksDialed(t, done)
		},
	},
	{
		id: "rfc1928/3/7", name: "the proxy selects X'FF'",
		req: "If the selected METHOD is X'FF', none of the methods listed by the client are acceptable, and the client MUST close the connection.",
		run: func(t *testing.T) {
			up := newSOCKSUpstream(t)
			done := socksExitDial(up.url("alice:secret@"), "tcp", "127.0.0.1:443")
			w := up.accept()
			w.want(5, 2, 0x00, 0x02)
			w.write([]byte{5, 0xFF})
			w.wantClosed()
			socksDialFailed(t, done)
		},
	},
	{
		id: "rfc1928/3/8", name: "the proxy selects a method the exit did not offer",
		req: "The server selects from one of the methods given in METHODS, and sends a METHOD selection message",
		run: func(t *testing.T) {
			up := newSOCKSUpstream(t)
			for _, tc := range []struct {
				userinfo string
				greeting []byte
				method   byte
			}{
				{"", []byte{5, 1, 0x00}, 0x02},
				{"", []byte{5, 1, 0x00}, 0x01},
				{"alice:secret@", []byte{5, 2, 0x00, 0x02}, 0x80},
			} {
				done := socksExitDial(up.url(tc.userinfo), "tcp", "127.0.0.1:443")
				w := up.accept()
				w.want(tc.greeting...)
				w.write([]byte{5, tc.method})
				w.wantClosed()
				socksDialFailed(t, done)
			}
		},
	},
	{
		id: "rfc1928/3/9", name: "the proxy answers the greeting with version 4",
		req: "The VER field is set to X'05' for this version of the protocol.",
		run: func(t *testing.T) {
			up := newSOCKSUpstream(t)
			done := socksExitDial(up.url(""), "tcp", "127.0.0.1:443")
			w := up.accept()
			w.want(5, 1, 0x00)
			w.write([]byte{4, 0x00})
			w.wantClosed()
			require.ErrorIs(t, socksDialFailed(t, done), socks5.ErrVersion)
		},
	},
	{
		id: "rfc1928/4/1", name: "a method with encapsulation",
		req:  "If the negotiated method includes encapsulation for purposes of integrity checking and/or confidentiality, these requests MUST be encapsulated in the method-dependent encapsulation.",
		skip: socksNoEncapsulation,
	},
	{
		id: "rfc1928/4/2", name: "the client sends a request with version 4",
		req: "VER    protocol version: X'05'",
		run: func(t *testing.T) {
			w := dialSOCKSWire(t, startSOCKS5(t, testProxy(t)))
			w.write([]byte{5, 1, 0})
			w.want(5, 0)
			w.write([]byte{4, 1, 0}, socksAddrBytes(netip.MustParseAddrPort("127.0.0.1:443")))
			w.wantClosed()
		},
	},
	{
		id: "rfc1928/4/3", name: "the client sends a BIND and a command of unknown value",
		req: "X'07' Command not supported",
		run: func(t *testing.T) {
			addr := startSOCKS5(t, testProxy(t))
			for _, cmd := range []byte{0x02, 0x09} {
				w := dialSOCKSWire(t, addr)
				w.write([]byte{5, 1, 0})
				w.want(5, 0)
				w.write([]byte{5, cmd, 0}, socksAddrBytes(netip.MustParseAddrPort("127.0.0.1:443")))
				w.want(5, 0x07, 0, 1, 0, 0, 0, 0, 0, 0)
				w.wantClosed()
			}
		},
	},
	{
		id: "rfc1928/5/1", name: "the client sends a CONNECT to an IPv4 address",
		req: "the address is a version-4 IP address, with a length of 4 octets",
		run: func(t *testing.T) {
			echo := tcpEchoOn(t, "127.0.0.1:0")
			p := testProxy(t)
			p.MustAdd[TCP]("[127.0.0.0/8]", relayStream)
			w := socksConnect(t, startSOCKS5(t, p), socksAddrBytes(echo))
			w.want(socksGranted4...)
			w.wantEcho()
			assert.Equal(t, echo, waitForSessions(t, p, 1)[0].Upstream())
		},
	},
	{
		id: "rfc1928/5/2", name: "the client sends a CONNECT to a domain name",
		req: "the address field contains a fully-qualified domain name. The first octet of the address field contains the number of octets of name that follow, there is no terminating NUL octet.",
		run: func(t *testing.T) {
			echo := tcpEchoOn(t, "127.0.0.1:0")
			dialed := new(recorder)
			tr := DefaultTransport()
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialed.add(addr)
				return pinnedDialer(echo.String())(ctx, network, addr)
			}
			p := testProxy(t, WithTransport(tr))
			p.MustAdd[TCP]("echo.test", relayStream)
			w := socksConnect(t, startSOCKS5(t, p), socksNameBytes("echo.test", echo.Port()))
			w.want(socksGranted4...)
			w.wantEcho()
			assert.Equal(t, []string{fmt.Sprintf("echo.test:%d", echo.Port())}, dialed.all())
		},
	},
	{
		id: "rfc1928/5/3", name: "the client reaches the front over IPv6 and sends a CONNECT to an IPv6 address",
		req: "the address is a version-6 IP address, with a length of 16 octets.",
		run: func(t *testing.T) {
			echo := tcpEchoOn(t, "[::1]:0")
			p := testProxy(t)
			p.MustAdd[TCP]("[::1]", relayStream)
			w := socksConnect(t, startSOCKS5On(t, p, "[::1]:0"), socksAddrBytes(echo))
			w.want(slices.Concat([]byte{5, 0, 0, 4}, make([]byte, 16+2))...)
			w.wantEcho()
		},
	},
	{
		id: "rfc1928/5/4", name: "the client sends a datagram to a domain name",
		req: "the address field contains a fully-qualified domain name. The first octet of the address field contains the number of octets of name that follow, there is no terminating NUL octet.",
		run: func(t *testing.T) {
			origin, got := udpOriginOn(t, "127.0.0.1:0")
			resolver := &fakeResolver{addrs: map[string][]netip.Addr{"echo.test": {origin.Addr()}}}
			p := testProxy(t, WithNameResolver(resolver))
			p.MustAdd[UDP]("echo.test", forwardDatagram)
			_, relay := socksAssociate(t, startSOCKS5(t, p), socksZeros4)
			sock := listenUDP(t, "127.0.0.1:0")
			_, err := sock.WriteToUDPAddrPort(socksDatagram(0, socksNameBytes("echo.test", origin.Port()), "ping"), relay)
			require.NoError(t, err)
			wantPayload(t, got, "ping")
			assert.Equal(t, socksDatagram(0, socksAddrBytes(origin), "ping"), socksReadDatagram(t, sock))
		},
	},
	{
		id: "rfc1928/5/5", name: "the client sends a datagram to an IPv6 address",
		req: "the address is a version-6 IP address, with a length of 16 octets.",
		run: func(t *testing.T) {
			origin, got := udpOriginOn(t, "[::1]:0")
			p := testProxy(t)
			p.MustAdd[UDP]("[::1]", forwardDatagram)
			_, relay := socksAssociate(t, startSOCKS5(t, p), socksZeros4)
			sock := listenUDP(t, "127.0.0.1:0")
			_, err := sock.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(origin), "ping"), relay)
			require.NoError(t, err)
			wantPayload(t, got, "ping")
			assert.Equal(t, socksDatagram(0, socksAddrBytes(origin), "ping"), socksReadDatagram(t, sock))
		},
	},
	{
		id: "rfc1928/5/6", name: "the client sends a CONNECT with an address type of unknown value",
		req: "X'08' Address type not supported",
		run: func(t *testing.T) {
			w := socksConnect(t, startSOCKS5(t, testProxy(t)), []byte{5, 127, 0, 0, 1, 1, 187})
			w.want(5, 0x08, 0, 1, 0, 0, 0, 0, 0, 0)
			w.wantClosed()
		},
	},
	{
		id: "rfc1928/5/7", name: "the client sends a CONNECT to a domain name of zero octets",
		req: "X'01' general SOCKS server failure",
		run: func(t *testing.T) {
			w := socksConnect(t, startSOCKS5(t, testProxy(t)), []byte{3, 0, 1, 187})
			w.want(5, 0x01, 0, 1, 0, 0, 0, 0, 0, 0)
			w.wantClosed()
		},
	},
	{
		id: "rfc1928/5/8", name: "the proxy receives a CONNECT to an address of each type",
		req: "In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies the type of address contained within the field",
		run: func(t *testing.T) {
			up := newSOCKSUpstream(t)
			for _, scheme := range []string{"socks5", "socks5h"} {
				for _, tc := range []struct {
					addr string
					want []byte
				}{
					{"127.0.0.1:443", []byte{1, 127, 0, 0, 1, 1, 187}},
					{"[::ffff:127.0.0.1]:443", []byte{1, 127, 0, 0, 1, 1, 187}},
					{"[2001:db8::1]:443", socksAddrBytes(netip.MustParseAddrPort("[2001:db8::1]:443"))},
					{"inner.test:443", socksNameBytes("inner.test", 443)},
				} {
					done := socksExitDial(scheme+"://"+up.addr, "tcp", tc.addr)
					w := up.greeted()
					w.want(slices.Concat([]byte{5, 1, 0}, tc.want)...)
					w.write(socksGranted4)
					socksDialed(t, done)
				}
			}
		},
	},
	{
		id: "rfc1928/6/1", name: "the client sends a CONNECT, a BIND and a UDP ASSOCIATE",
		req: "Fields marked RESERVED (RSV) must be set to X'00'.",
		run: func(t *testing.T) {
			echo := tcpEchoOn(t, "127.0.0.1:0")
			p := testProxy(t)
			p.MustAdd[TCP]("[127.0.0.0/8]", relayStream)
			addr := startSOCKS5(t, p)
			for _, cmd := range []byte{0x01, 0x02, 0x03} {
				w := dialSOCKSWire(t, addr)
				w.write([]byte{5, 1, 0})
				w.want(5, 0)
				w.write([]byte{5, cmd, 0}, socksAddrBytes(echo))
				reply := w.readReply()
				assert.Equal(t, byte(0), reply[2], "the reply %x to command %d", reply, cmd)
			}
		},
	},
	{
		id: "rfc1928/6/2", name: "the client sends a CONNECT",
		req:  "In the reply to a CONNECT, BND.PORT contains the port number that the server assigned to connect to the target host, while BND.ADDR contains the associated IP address.",
		skip: "the front replies before it dials, so socks5Bound in socks.go writes port zero and the unspecified address of the family the client reached the proxy on",
	},
	{
		id: "rfc1928/6/3", name: "the client sends a CONNECT to a domain name that is not a hostname",
		req: "X'01' general SOCKS server failure",
		run: func(t *testing.T) {
			p := testProxy(t)
			p.MustAdd[TCP]("+{any}", relayStream)
			w := socksConnect(t, startSOCKS5(t, p), socksNameBytes("bad/host", 443))
			w.want(5, 0x01, 0, 1, 0, 0, 0, 0, 0, 0)
			w.wantClosed()
			assert.Empty(t, slices.Collect(p.Sessions()))
		},
	},
	{
		id: "rfc1928/6/4", name: "the client sends a CONNECT to a port no entry admits",
		req: "When a reply (REP value other than X'00') indicates a failure, the SOCKS server MUST terminate the TCP connection shortly after sending the reply. This must be no more than 10 seconds after detecting the condition that caused a failure.",
		run: func(t *testing.T) {
			p := testProxy(t)
			p.MustAdd[TCP]("allowed.test:443", relayStream)
			w := socksConnect(t, startSOCKS5(t, p), socksNameBytes("allowed.test", 80))
			w.want(5, 0x02, 0, 1, 0, 0, 0, 0, 0, 0)
			w.wantClosed()
		},
	},
	{
		id: "rfc1928/6/5", name: "the client sends a CONNECT to a port nothing listens on",
		req:  "X'05' Connection refused",
		skip: "the front replies before it dials, socks.go serveSOCKS5, since the client sends the ClientHello that decides the entry only once it has the reply, so no dial failure reaches a reply, X'03', X'04' and X'06' included",
	},
	{
		id: "rfc1928/6/6", name: "the client sends its first bytes in the segment of its CONNECT",
		req: "If the reply code (REP value of X'00') indicates a success, and the request was either a BIND or a CONNECT, the client may now start passing data.",
		run: func(t *testing.T) {
			echo := tcpEchoOn(t, "127.0.0.1:0")
			p := testProxy(t)
			p.MustAdd[TCP]("[127.0.0.0/8]", relayStream)
			w := dialSOCKSWire(t, startSOCKS5(t, p))
			w.write([]byte{5, 1, 0})
			w.want(5, 0)
			w.write([]byte{5, 1, 0}, socksAddrBytes(echo), socksPayload)
			w.want(socksGranted4...)
			w.want(socksPayload...)
		},
	},
	{
		id: "rfc1928/6/7", name: "the proxy grants a CONNECT with each BND address type and its first bytes in the same segment",
		req: "If the reply code (REP value of X'00') indicates a success, and the request was either a BIND or a CONNECT, the client may now start passing data.",
		run: func(t *testing.T) {
			up := newSOCKSUpstream(t)
			target := netip.MustParseAddrPort("127.0.0.1:443")
			for _, bnd := range [][]byte{
				socksAddrBytes(netip.MustParseAddrPort("10.0.0.1:4000")),
				socksNameBytes("bound.test", 4000),
				socksAddrBytes(netip.MustParseAddrPort("[2001:db8::1]:4000")),
			} {
				done := socksExitDial(up.url(""), "tcp", target.String())
				w := up.greeted()
				w.want(slices.Concat([]byte{5, 1, 0}, socksAddrBytes(target))...)
				w.write([]byte{5, 0, 0}, bnd, []byte("early"))
				conn := socksDialed(t, done)
				require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
				got := make([]byte, len("early"))
				_, err := io.ReadFull(conn, got)
				require.NoError(t, err)
				assert.Equal(t, "early", string(got))
				_, err = conn.Write([]byte("late"))
				require.NoError(t, err)
				w.want([]byte("late")...)
			}
		},
	},
	{
		id: "rfc1928/6/8", name: "the proxy answers each failure code and leaves the connection open",
		req: "When a reply (REP value other than X'00') indicates a failure, the SOCKS server MUST terminate the TCP connection shortly after sending the reply.",
		run: func(t *testing.T) {
			up := newSOCKSUpstream(t)
			for _, rep := range []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0xFF} {
				done := socksExitDial(up.url(""), "tcp", "127.0.0.1:443")
				w := up.greeted()
				w.read(10)
				w.write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
				require.ErrorIs(t, socksDialFailed(t, done), socks5.Reply(rep))
				w.wantClosed()
			}
		},
	},
	{
		id: "rfc1928/6/9", name: "the proxy sends a malformed reply",
		req: "The server evaluates the request, and returns a reply formed as follows",
		run: func(t *testing.T) {
			up := newSOCKSUpstream(t)
			for _, tc := range []struct {
				err       error
				reply     []byte
				truncated bool
			}{
				{err: socks5.ErrVersion, reply: []byte{4, 0, 0, 1, 0, 0, 0, 0, 0, 0}},
				{err: socks5.ErrAddressType, reply: []byte{5, 0, 0, 5, 0, 0, 0, 0, 0, 0}},
				{err: socks5.ErrNameLength, reply: []byte{5, 0, 0, 3, 0, 0, 0}},
				{err: io.ErrUnexpectedEOF, reply: []byte{5, 0, 0, 1, 10}, truncated: true},
			} {
				done := socksExitDial(up.url(""), "tcp", "127.0.0.1:443")
				w := up.greeted()
				w.read(10)
				w.write(tc.reply)
				if tc.truncated {
					require.NoError(t, w.conn.Close())
				}
				require.ErrorIs(t, socksDialFailed(t, done), tc.err, "reply %x", tc.reply)
				if !tc.truncated {
					w.wantClosed()
				}
			}
		},
	},
	{
		id: "rfc1928/6/10", name: "the client sends a UDP ASSOCIATE declaring the port it sends from",
		req: "The DST.ADDR and DST.PORT fields contain the address and port that the client expects to use to send UDP datagrams on for the association. The server MAY use this information to limit access to the association.",
		run: func(t *testing.T) {
			origin, got := udpOriginOn(t, "127.0.0.1:0")
			p := testProxy(t)
			p.MustAdd[UDP]("[127.0.0.0/8]", forwardDatagram)
			declared := listenUDP(t, "127.0.0.1:0")
			other := listenUDP(t, "127.0.0.1:0")
			_, relay := socksAssociate(t, startSOCKS5(t, p), socksAddrBytes(addrPort(declared.LocalAddr())))

			_, err := other.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(origin), "other"), relay)
			require.NoError(t, err)
			_, err = declared.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(origin), "declared"), relay)
			require.NoError(t, err)
			wantPayload(t, got, "declared")
			assert.Equal(t, socksDatagram(0, socksAddrBytes(origin), "declared"), socksReadDatagram(t, declared))
		},
	},
	{
		id: "rfc1928/6/11", name: "the client sends a UDP ASSOCIATE of all zeros",
		req: "In the reply to a UDP ASSOCIATE request, the BND.PORT and BND.ADDR fields indicate the port number/address where the client MUST send UDP request messages to be relayed.",
		run: func(t *testing.T) {
			origin, got := udpOriginOn(t, "127.0.0.1:0")
			p := testProxy(t)
			p.MustAdd[UDP]("[127.0.0.0/8]", forwardDatagram)
			_, relay := socksAssociate(t, startSOCKS5(t, p), socksZeros4)
			assert.Equal(t, netip.MustParseAddr("127.0.0.1"), relay.Addr(), "the relay is on the address the client reached the front on")
			assert.NotZero(t, relay.Port())

			sock := listenUDP(t, "127.0.0.1:0")
			_, err := sock.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(origin), "relayed"), relay)
			require.NoError(t, err)
			wantPayload(t, got, "relayed")
		},
	},
	{
		id: "rfc1928/6/12", name: "the proxy receives a UDP ASSOCIATE",
		req: "If the client is not in possesion of the information at the time of the UDP ASSOCIATE, the client MUST use a port number and address of all zeros.",
		run: func(t *testing.T) {
			up := newSOCKSUpstream(t)
			relay := listenUDP(t, "127.0.0.1:0")
			done := socksExitDial(up.url(""), "udp", "127.0.0.1:53")
			w := up.greeted()
			w.want(5, 3, 0, 1, 0, 0, 0, 0, 0, 0)
			w.write([]byte{5, 0, 0}, socksAddrBytes(addrPort(relay.LocalAddr())))
			socksDialed(t, done)
		},
	},
	{
		id: "rfc1928/6/13", name: "the client closes the connection of its association",
		req: "A UDP association terminates when the TCP connection that the UDP ASSOCIATE request arrived on terminates.",
		run: func(t *testing.T) {
			origin, got := udpOriginOn(t, "127.0.0.1:0")
			p := testProxy(t)
			p.MustAdd[UDP]("[127.0.0.0/8]", forwardDatagram)
			ctrl, relay := socksAssociate(t, startSOCKS5(t, p), socksZeros4)
			sock := listenUDP(t, "127.0.0.1:0")
			_, err := sock.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(origin), "before"), relay)
			require.NoError(t, err)
			wantPayload(t, got, "before")

			require.NoError(t, ctrl.conn.Close())
			waitForSessions(t, p, 0)
			_, err = sock.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(origin), "after"), relay)
			require.NoError(t, err)
			wantNoPayload(t, got)
		},
	},
	{
		id: "rfc1928/6/14", name: "the proxy closes the connection of the association",
		req: "A UDP association terminates when the TCP connection that the UDP ASSOCIATE request arrived on terminates.",
		run: func(t *testing.T) {
			conn, ctrl, _ := socksExitAssociate(t, "127.0.0.1:53")
			require.NoError(t, ctrl.conn.Close())
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				require.ErrorIs(t, err, net.ErrClosed)
				return
			}
			_, err := conn.Read(make([]byte, 64))
			require.Error(t, err)
			require.NotErrorIs(t, err, os.ErrDeadlineExceeded, "the association outlived its connection")
		},
	},
	{
		id: "rfc1928/6/15", name: "a method with encapsulation",
		req:  "Similarly, when data arrives at the SOCKS server for the client, the server MUST encapsulate the data as appropriate for the authentication method in use.",
		skip: socksNoEncapsulation,
	},
	{
		id: "rfc1928/7/1", name: "the proxy grants a UDP ASSOCIATE on an IPv6 relay and on the unspecified address",
		req: "A UDP-based client MUST send its datagrams to the UDP relay server at the UDP port indicated by BND.PORT in the reply to the UDP ASSOCIATE request.",
		run: func(t *testing.T) {
			up := newSOCKSUpstream(t)
			for _, tc := range []struct {
				bnd   func(netip.AddrPort) []byte
				relay string
			}{
				{socksAddrBytes, "[::1]:0"},
				{func(ap netip.AddrPort) []byte {
					return socksAddrBytes(netip.AddrPortFrom(netip.IPv4Unspecified(), ap.Port()))
				}, "127.0.0.1:0"},
			} {
				relay := listenUDP(t, tc.relay)
				done := socksExitDial(up.url(""), "udp", "127.0.0.1:53")
				w := up.greeted()
				w.read(10)
				w.write([]byte{5, 0, 0}, tc.bnd(addrPort(relay.LocalAddr())))
				conn := socksDialed(t, done)
				_, err := conn.Write([]byte("query"))
				require.NoError(t, err)
				b, _ := readRelay(t, relay)
				assert.Equal(t, socksDatagram(0, socksAddrBytes(netip.MustParseAddrPort("127.0.0.1:53")), "query"), b)
			}
		},
	},
	{
		id: "rfc1928/7/2", name: "the proxy receives datagrams to an address of each type",
		req: "Each UDP datagram carries a UDP request header with it",
		run: func(t *testing.T) {
			for _, tc := range []struct {
				dest string
				want []byte
			}{
				{"127.0.0.1:53", socksAddrBytes(netip.MustParseAddrPort("127.0.0.1:53"))},
				{"[2001:db8::1]:53", socksAddrBytes(netip.MustParseAddrPort("[2001:db8::1]:53"))},
				{"dns.test:53", socksNameBytes("dns.test", 53)},
			} {
				conn, _, relay := socksExitAssociate(t, tc.dest)
				_, err := conn.Write([]byte("query"))
				require.NoError(t, err)
				b, _ := readRelay(t, relay)
				assert.Equal(t, socksDatagram(0, tc.want, "query"), b)
			}
		},
	},
	{
		id: "rfc1928/7/3", name: "the client sends a datagram to an IPv4 address and gets its answer",
		req: "When a UDP relay server receives a reply datagram from a remote host, it MUST encapsulate that datagram using the above UDP request header, and any authentication-method-dependent encapsulation.",
		run: func(t *testing.T) {
			origin, got := udpOriginOn(t, "127.0.0.1:0")
			p := testProxy(t)
			p.MustAdd[UDP]("[127.0.0.0/8]", forwardDatagram)
			_, relay := socksAssociate(t, startSOCKS5(t, p), socksZeros4)
			sock := listenUDP(t, "127.0.0.1:0")
			_, err := sock.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(origin), "ping"), relay)
			require.NoError(t, err)
			wantPayload(t, got, "ping")
			assert.Equal(t, socksDatagram(0, socksAddrBytes(origin), "ping"), socksReadDatagram(t, sock))
		},
	},
	{
		id: "rfc1928/7/4", name: "the proxy relays an answer to the exit",
		req: "When a UDP relay server receives a reply datagram from a remote host, it MUST encapsulate that datagram using the above UDP request header, and any authentication-method-dependent encapsulation.",
		run: func(t *testing.T) {
			dest := netip.MustParseAddrPort("127.0.0.1:53")
			conn, _, relay := socksExitAssociate(t, dest.String())
			_, err := conn.Write([]byte("query"))
			require.NoError(t, err)
			_, from := readRelay(t, relay)
			_, err = relay.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(dest), "answer"), from)
			require.NoError(t, err)
			assert.Equal(t, "answer", string(socksReadDatagram(t, conn)))
		},
	},
	{
		id: "rfc1928/7/5", name: "the client sends a datagram with an address type of unknown value",
		req: "When a UDP relay server decides to relay a UDP datagram, it does so silently, without any notification to the requesting client. Similarly, it will drop datagrams it cannot or will not relay.",
		run: func(t *testing.T) {
			origin, got := udpOriginOn(t, "127.0.0.1:0")
			p := testProxy(t)
			p.MustAdd[UDP]("[127.0.0.0/8]", forwardDatagram)
			ctrl, relay := socksAssociate(t, startSOCKS5(t, p), socksZeros4)
			sock := listenUDP(t, "127.0.0.1:0")
			unknown := slices.Concat([]byte{5}, origin.Addr().AsSlice(), be16(origin.Port()))
			_, err := sock.WriteToUDPAddrPort(socksDatagram(0, unknown, "unknown"), relay)
			require.NoError(t, err)
			_, err = sock.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(origin), "known"), relay)
			require.NoError(t, err)
			wantPayload(t, got, "known")
			ctrl.wantSilent()
		},
	},
	{
		id: "rfc1928/7/6", name: "the client sends a datagram to a destination no entry admits",
		req: "When a UDP relay server decides to relay a UDP datagram, it does so silently, without any notification to the requesting client. Similarly, it will drop datagrams it cannot or will not relay.",
		run: func(t *testing.T) {
			admitted, got := udpOriginOn(t, "127.0.0.1:0")
			refused, gotRefused := udpOriginOn(t, "127.0.0.1:0")
			p := testProxy(t)
			p.MustAdd[UDP](admitted.String(), forwardDatagram)
			ctrl, relay := socksAssociate(t, startSOCKS5(t, p), socksZeros4)
			sock := listenUDP(t, "127.0.0.1:0")
			_, err := sock.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(refused), "refused"), relay)
			require.NoError(t, err)
			_, err = sock.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(admitted), "admitted"), relay)
			require.NoError(t, err)
			wantPayload(t, got, "admitted")
			assert.Equal(t, socksDatagram(0, socksAddrBytes(admitted), "admitted"), socksReadDatagram(t, sock))
			wantNoPayload(t, gotRefused)
			ctrl.wantSilent()
		},
	},
	{
		id: "rfc1928/7/7", name: "a datagram from an address other than the one of the control connection",
		req: "The UDP relay server MUST acquire from the SOCKS server the expected IP address of the client that will send datagrams to the BND.PORT given in the reply to UDP ASSOCIATE. It MUST drop any datagrams arriving from any source IP address other than the one recorded for the particular association.",
		run: func(t *testing.T) {
			origin, got := udpOriginOn(t, "127.0.0.1:0")
			p := testProxy(t)
			p.MustAdd[UDP]("[127.0.0.0/8]", forwardDatagram)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = ln.Close() })
			// A second loopback address cannot be assumed, so the control connection reports one.
			spoofed := socksSpoofedListener{Listener: ln, remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 40000}}
			go func() { _ = p.ServeSOCKS5(spoofed) }()
			_, elsewhere := socksAssociate(t, ln.Addr().String(), socksZeros4)
			_, recorded := socksAssociate(t, startSOCKS5(t, p), socksZeros4)

			sock := listenUDP(t, "127.0.0.1:0")
			_, err = sock.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(origin), "elsewhere"), elsewhere)
			require.NoError(t, err)
			wantNoPayload(t, got)
			_, err = sock.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(origin), "recorded"), recorded)
			require.NoError(t, err)
			wantPayload(t, got, "recorded")
		},
	},
	{
		id: "rfc1928/7/8", name: "the client sends fragments",
		req: "Implementation of fragmentation is optional; an implementation that does not support fragmentation MUST drop any datagram whose FRAG field is other than X'00'.",
		run: func(t *testing.T) {
			origin, got := udpOriginOn(t, "127.0.0.1:0")
			p := testProxy(t)
			p.MustAdd[UDP]("[127.0.0.0/8]", forwardDatagram)
			_, relay := socksAssociate(t, startSOCKS5(t, p), socksZeros4)
			sock := listenUDP(t, "127.0.0.1:0")
			for _, frag := range []byte{0x01, 0x82} {
				_, err := sock.WriteToUDPAddrPort(socksDatagram(frag, socksAddrBytes(origin), fmt.Sprint("fragment ", frag)), relay)
				require.NoError(t, err)
			}
			_, err := sock.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(origin), "standalone"), relay)
			require.NoError(t, err)
			wantPayload(t, got, "standalone")
		},
	},
	{
		id: "rfc1928/7/9", name: "the proxy relays a fragment to the exit",
		req: "Implementation of fragmentation is optional; an implementation that does not support fragmentation MUST drop any datagram whose FRAG field is other than X'00'.",
		run: func(t *testing.T) {
			dest := netip.MustParseAddrPort("127.0.0.1:53")
			conn, _, relay := socksExitAssociate(t, dest.String())
			_, err := conn.Write([]byte("query"))
			require.NoError(t, err)
			_, from := readRelay(t, relay)
			_, err = relay.WriteToUDPAddrPort(socksDatagram(0x01, socksAddrBytes(dest), "fragment"), from)
			require.NoError(t, err)
			_, err = relay.WriteToUDPAddrPort(socksDatagram(0, socksAddrBytes(dest), "standalone"), from)
			require.NoError(t, err)
			assert.Equal(t, "standalone", string(socksReadDatagram(t, conn)))
		},
	},
	{
		id: "rfc1928/7/10", name: "the client sends fragments over more than five seconds",
		req:  "The reassembly timer MUST be no less than 5 seconds.",
		skip: "ListenAndServeSOCKS5 documents that a fragmented datagram is dropped, so there is no reassembly",
	},
	{
		id: "rfc1928/7/11", name: "a method with encapsulation",
		req:  "If the selected authentication method provides encapsulation for the purposes of authenticity, integrity, and/or confidentiality, the datagram MUST be encapsulated using the appropriate encapsulation.",
		skip: socksNoEncapsulation,
	},
	{
		id: "rfc1928/7/12", name: "a SOCKS-aware UDP programming interface",
		req:  "The programming interface for a SOCKS-aware UDP MUST report an available buffer space for UDP datagrams that is smaller than the actual space provided by the operating system",
		skip: "edge exposes no programming interface for SOCKS-aware UDP, and quicOn in chain.go keeps the QUIC packets on the exit's socket at 1200 bytes",
	},
	{
		id: "rfc1929/2/1", name: "the client presents valid credentials",
		req: "The server verifies the supplied UNAME and PASSWD, and sends the following response",
		run: func(t *testing.T) {
			echo := tcpEchoOn(t, "127.0.0.1:0")
			p := testProxy(t, WithProxyAuth(testBasic()))
			p.MustAdd[TCP]("[127.0.0.0/8]", relayStream)
			w := dialSOCKSWire(t, startSOCKS5(t, p))
			w.write([]byte{5, 2, 0x00, 0x02})
			w.want(5, 0x02)
			w.write([]byte{1, 5}, []byte("alice"), []byte{6}, []byte("secret"))
			w.want(1, 0)
			w.write([]byte{5, 1, 0}, socksAddrBytes(echo))
			w.want(socksGranted4...)
			w.wantEcho()
			assert.Equal(t, "alice", waitForSessions(t, p, 1)[0].Identity())
		},
	},
	{
		id: "rfc1929/2/2", name: "the client presents a wrong password",
		req: "A STATUS field of X'00' indicates success. If the server returns a `failure' (STATUS value other than X'00') status, it MUST close the connection.",
		run: func(t *testing.T) {
			p := testProxy(t, WithProxyAuth(testBasic()))
			p.MustAdd[TCP]("[127.0.0.0/8]", relayStream)
			w := dialSOCKSWire(t, startSOCKS5(t, p))
			w.write([]byte{5, 1, 0x02})
			w.want(5, 0x02)
			w.write([]byte{1, 5}, []byte("alice"), []byte{5}, []byte("wrong"))
			status := w.read(2)
			assert.Equal(t, byte(1), status[0])
			assert.NotZero(t, status[1])
			w.wantClosed()
			assert.Empty(t, slices.Collect(p.Sessions()))
		},
	},
	{
		id: "rfc1929/2/3", name: "the client sends its credentials with version 5",
		req: "The VER field contains the current version of the subnegotiation, which is X'01'.",
		run: func(t *testing.T) {
			w := dialSOCKSWire(t, startSOCKS5(t, testProxy(t, WithProxyAuth(testBasic()))))
			w.write([]byte{5, 1, 0x02})
			w.want(5, 0x02)
			w.write([]byte{5, 5}, []byte("alice"), []byte{6}, []byte("secret"))
			w.wantClosed()
		},
	},
	{
		id: "rfc1929/2/4", name: "the proxy selects username/password",
		req: "This begins with the client producing a Username/Password request",
		run: func(t *testing.T) {
			up := newSOCKSUpstream(t)
			target := netip.MustParseAddrPort("127.0.0.1:443")
			done := socksExitDial(up.url("alice:s%3Acret@"), "tcp", target.String())
			w := up.accept()
			w.want(5, 2, 0x00, 0x02)
			w.write([]byte{5, 0x02})
			w.want(slices.Concat([]byte{1, 5}, []byte("alice"), []byte{6}, []byte("s:cret"))...)
			w.write([]byte{1, 0})
			w.want(slices.Concat([]byte{5, 1, 0}, socksAddrBytes(target))...)
			w.write(socksGranted4)
			socksDialed(t, done)
		},
	},
	{
		id: "rfc1929/2/5", name: "the proxy refuses the credentials and leaves the connection open",
		req: "A STATUS field of X'00' indicates success. If the server returns a `failure' (STATUS value other than X'00') status, it MUST close the connection.",
		run: func(t *testing.T) {
			up := newSOCKSUpstream(t)
			done := socksExitDial(up.url("alice:wrong@"), "tcp", "127.0.0.1:443")
			w := up.accept()
			w.want(5, 2, 0x00, 0x02)
			w.write([]byte{5, 0x02})
			w.read(2 + len("alice") + 1 + len("wrong"))
			w.write([]byte{1, 0x01})
			require.ErrorIs(t, socksDialFailed(t, done), socks5.ErrAuthFailed)
			w.wantClosed()
		},
	},
	{
		id: "rfc1929/2/6", name: "the proxy answers the credentials with version 5",
		req: "The VER field contains the current version of the subnegotiation, which is X'01'.",
		run: func(t *testing.T) {
			up := newSOCKSUpstream(t)
			done := socksExitDial(up.url("alice:secret@"), "tcp", "127.0.0.1:443")
			w := up.accept()
			w.want(5, 2, 0x00, 0x02)
			w.write([]byte{5, 0x02})
			w.read(2 + len("alice") + 1 + len("secret"))
			w.write([]byte{5, 0x00})
			require.ErrorIs(t, socksDialFailed(t, done), socks5.ErrVersion)
			w.wantClosed()
		},
	},
	{
		id: "rfc1929/2/7", name: "the proxy selects username/password for a URL with an empty username or an empty password",
		req: "The ULEN field contains the length of the UNAME field that follows. The UNAME field contains the username as known to the source operating system. The PLEN field contains the length of the PASSWD field that follows.",
		run: func(t *testing.T) {
			up := newSOCKSUpstream(t)
			for _, userinfo := range []string{":secret@", "alice@"} {
				done := socksExitDial(up.url(userinfo), "tcp", "127.0.0.1:443")
				w := up.accept()
				w.want(5, 2, 0x00, 0x02)
				w.write([]byte{5, 0x02})
				w.wantClosed()
				require.ErrorIs(t, socksDialFailed(t, done), socks5.ErrCredentials)
			}
		},
	},
}

func TestSOCKS5_RelayIsNotBoundToASocketOfTheProxy(t *testing.T) {
	p := testProxy(t)
	sink := listenUDP(t, "127.0.0.1:0")
	own, err := p.srv.fwd.up.dialRaw(t.Context(), "udp", sink.LocalAddr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = own.Close() })
	client, err := loopbackUDP()
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	a := newSOCKSAssociation(t.Context(), p, nil, socks5.Addr{}, netip.MustParseAddr("127.0.0.1"))
	assert.False(t, a.accepts(addrPort(own.LocalAddr())))
	assert.True(t, a.accepts(addrPort(client.LocalAddr())))
}
