// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const h3Authority = "h3.example.test"

// h3Origin starts an HTTP/3 origin holding a certificate signed by ca for each of names,
// h3Authority when none is given, and returns its address.
func h3Origin(t *testing.T, ca *CA, names ...string) netip.AddrPort {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	if len(names) == 0 {
		names = []string{h3Authority}
	}
	certs := make([]tls.Certificate, 0, len(names))
	for _, name := range names {
		certs = append(certs, selfSignedFor(t, ca, name))
	}

	srv := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Origin-Proto", r.Proto)
			fmt.Fprintf(w, "origin method=%s path=%s proto=%s host=%s", r.Method, r.URL.Path, r.Proto, r.Host)
		}),
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{
			Certificates: certs,
			MinVersion:   tls.VersionTLS13,
		}),
		QUICConfig: &quic.Config{},
	}

	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = pc.Close()
	})

	addr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	require.NoError(t, err)
	return addr
}

// startQUIC starts p on a loopback UDP port and returns it.
func startQUIC(t *testing.T, p *Proxy) netip.AddrPort {
	t.Helper()
	return serveQUIC(t, p, func(pc net.PacketConn) net.PacketConn { return pc })
}

// startQUICRedirected starts p on a loopback UDP port whose datagrams all report origin as
// the address they were headed to, standing in for the redirect that would have sent them.
func startQUICRedirected(t *testing.T, p *Proxy, origin netip.AddrPort) netip.AddrPort {
	t.Helper()
	return serveQUIC(t, p, func(pc net.PacketConn) net.PacketConn {
		return fixedOriginPacketConn{PacketConn: pc, origin: origin}
	})
}

func serveQUIC(t *testing.T, p *Proxy, wrap func(net.PacketConn) net.PacketConn) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() { _ = p.ServeQUIC(wrap(pc)) }()
	t.Cleanup(func() { _ = p.Close() })

	addr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	require.NoError(t, err)
	return addr
}

type fixedOriginPacketConn struct {
	net.PacketConn
	origin netip.AddrPort
}

func (c fixedOriginPacketConn) OriginalDestination(net.Addr) (netip.AddrPort, error) {
	return c.origin, nil
}

func caFileOf(t *testing.T, ca *CA, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, ca.CertificatePEM(), 0o600))
	return path
}

func poolOf(ca *CA) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())
	return pool
}

func TestQUIC_InterceptWithCurl(t *testing.T) {
	requireCurl(t)

	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)

	tr := DefaultTransport()
	tr.AllowHTTP3 = true
	tr.RootCAs = poolOf(originCA)

	p, err := New(WithCA(proxyCA), WithTransport(tr))
	require.NoError(t, err)

	seen := new(recorder)
	p.MustAddInterceptor(nil, h3Authority+"/+{any}", func(c *Context) (*http.Response, error) {
		seen.add(c.Protocol().String() + " " + c.Request().URL.Path)
		return c.Forward()
	})

	proxyAddr := startQUICRedirected(t, p, origin)
	port := fmt.Sprint(proxyAddr.Port())

	res := runCurl(t,
		"--http3-only",
		"--resolve", h3Authority+":"+port+":127.0.0.1",
		"--cacert", caFileOf(t, proxyCA, "proxy.pem"),
		fmt.Sprintf("https://%s:%s/echo", h3Authority, port),
	)

	require.Equal(t, "200", res.status, "body %q", res.body)
	assert.Equal(t, "3", res.version, "curl must have used HTTP/3")
	assert.Contains(t, res.body, "proto=HTTP/3.0", "the origin must have been reached over HTTP/3 too")
	assert.Contains(t, res.body, "path=/echo")
	require.Equal(t, []string{"HTTP/3.0 /echo"}, seen.all())
}

func TestQUIC_TunnelWithCurl(t *testing.T) {
	requireCurl(t)

	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)

	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	require.NoError(t, p.AddTunnel(h3Authority))

	// On every other authority: the tunnel is the more precise entry and decides first.
	// An interceptor on the tunneled authority itself is refused, since it could never run.
	handlerRan := new(atomic.Bool)
	p.MustAddInterceptor(nil, "+{any}/+{rest}", func(c *Context) (*http.Response, error) {
		handlerRan.Store(true)
		return c.Forward()
	})

	proxyAddr := startQUICRedirected(t, p, origin)
	port := fmt.Sprint(proxyAddr.Port())

	// Only the origin CA is trusted. A relayed handshake reaches the origin certificate, an
	// intercepted one would present the proxy's and fail.
	res := runCurl(t,
		"--http3-only",
		"--resolve", h3Authority+":"+port+":127.0.0.1",
		"--cacert", caFileOf(t, originCA, "origin.pem"),
		fmt.Sprintf("https://%s:%s/echo", h3Authority, port),
	)

	require.Equal(t, "200", res.status, "body %q", res.body)
	assert.Equal(t, "3", res.version)
	assert.Contains(t, res.body, "proto=HTTP/3.0")
	assert.False(t, handlerRan.Load(), "no handler may run on a relayed connection")
}

func TestQUIC_HandlerCanShortCircuit(t *testing.T) {
	requireCurl(t)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)

	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)

	p.MustAddInterceptor([]string{http.MethodGet}, h3Authority+"/blocked", func(c *Context) (*http.Response, error) {
		return Text(http.StatusForbidden, "blocked by edge over "+c.Protocol().String()), nil
	})

	proxyAddr := startQUIC(t, p)
	port := fmt.Sprint(proxyAddr.Port())

	res := runCurl(t,
		"--http3-only",
		"--resolve", h3Authority+":"+port+":127.0.0.1",
		"--cacert", caFileOf(t, proxyCA, "proxy.pem"),
		fmt.Sprintf("https://%s:%s/blocked", h3Authority, port),
	)

	assert.Equal(t, "403", res.status)
	assert.Equal(t, "3", res.version)
	assert.Contains(t, res.body, "blocked by edge over HTTP/3.0")
}

func TestQUIC_RejectDropsTheConnection(t *testing.T) {
	proxyCA, err := GenerateCA()
	require.NoError(t, err)

	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)

	proxyAddr := startQUIC(t, p)

	pc, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()

	ctx := t.Context()
	_, err = quic.Dial(ctx,
		pc,
		net.UDPAddrFromAddrPort(proxyAddr),
		&tls.Config{ServerName: h3Authority, RootCAs: poolOf(proxyCA), NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
		&quic.Config{HandshakeIdleTimeout: 2 * time.Second},
	)
	require.Error(t, err, "a rejected authority must never complete a handshake")
}

// dialQUICTo returns an HTTP/3 transport reaching addr whatever the URL says, so a test can
// use the authority the proxy sniffs without it having to resolve.
func dialQUICTo(addr netip.AddrPort, roots *x509.CertPool) *http3.Transport {
	return &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		// A short idle timeout so a connection the proxy cut does not hold the test open.
		QUICConfig: &quic.Config{MaxIdleTimeout: time.Second},
		Dial: func(ctx context.Context, _ string, cfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			pc, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			conn, err := quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(addr), cfg, qcfg)
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
			return conn, nil
		},
	}
}

// A tunneled QUIC peer is decided once, when its ClientHello is read, and never again, so it
// needs a session of its own for a sweep to reach it.
func TestQUIC_TunnelSessionIsListedAndClosed(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	require.NoError(t, p.AddTunnel(h3Authority))

	proxyAddr := startQUICRedirected(t, p, origin)

	tr := dialQUICTo(proxyAddr, poolOf(originCA))
	defer func() { _ = tr.Close() }()

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/echo", h3Authority, proxyAddr.Port()), nil)
	require.NoError(t, err)

	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	// End to end, the origin answered its own certificate and the proxy only moved datagrams.
	assert.Contains(t, string(body), "path=/echo")

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, Tunnel, sessions[0].Action())
	assert.Equal(t, h3Authority, sessions[0].Target().Host)
	assert.Equal(t, HTTP3, sessions[0].Protocol())

	require.NoError(t, sessions[0].Close())
	assert.Empty(t, slices.Collect(p.Sessions()), "closing removes the peer under the demux lock")
}

// The proxy terminated the connection of an intercepted QUIC peer, so closing its session goes
// through CloseWithError rather than leaving the client to time out. What the client
// then observes is not asserted, an http3.Transport is free to redial on its own.
func TestQUIC_InterceptedSessionIsListedAndClosed(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)

	upstream := DefaultTransport()
	upstream.AllowHTTP3 = true
	upstream.RootCAs = poolOf(originCA)

	p, err := New(WithCA(proxyCA), WithTransport(upstream))
	require.NoError(t, err)
	p.MustAddInterceptor(nil, h3Authority+"/+{any}", func(c *Context) (*http.Response, error) {
		return c.Forward()
	})

	proxyAddr := startQUICRedirected(t, p, origin)

	tr := dialQUICTo(proxyAddr, poolOf(proxyCA))
	defer func() { _ = tr.Close() }()

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/echo", h3Authority, proxyAddr.Port()), nil)
	require.NoError(t, err)

	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "path=/echo")

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, Intercept, sessions[0].Action())
	assert.Equal(t, h3Authority, sessions[0].Target().Host)
	assert.NotNil(t, sessions[0].TLS(), "the handshake the proxy terminated is recorded")

	require.NoError(t, sessions[0].Close())
	assert.Empty(t, slices.Collect(p.Sessions()))
}

// A handler waiting on the session context has to be released when the session ends. A QUIC
// peer owns its own, since nothing upstream of it cancels one.
func TestQUIC_SessionContextEndsWithTheSession(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	require.NoError(t, p.AddTunnel(h3Authority))

	proxyAddr := startQUICRedirected(t, p, origin)
	tr := dialQUICTo(proxyAddr, poolOf(originCA))
	defer func() { _ = tr.Close() }()

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/echo", h3Authority, proxyAddr.Port()), nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	sess := waitForSessions(t, p, 1)[0]
	sessCtx := sess.Context()
	select {
	case <-sessCtx.Done():
		t.Fatal("the context fired while the session was alive")
	default:
	}

	require.NoError(t, sess.Close())
	select {
	case <-sessCtx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("closing the session did not end its context")
	}
}

// dialSharedQUIC dials a QUIC connection to addr from tr, so several connections share one
// client socket.
func dialSharedQUIC(t *testing.T, tr *quic.Transport, addr netip.AddrPort, sni string, roots *x509.CertPool) *quic.Conn {
	t.Helper()
	conn, err := tr.Dial(t.Context(), net.UDPAddrFromAddrPort(addr), &tls.Config{
		ServerName: sni,
		RootCAs:    roots,
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{
		MaxIdleTimeout:       10 * time.Second,
		KeepAlivePeriod:      200 * time.Millisecond,
		HandshakeIdleTimeout: 3 * time.Second,
	})
	require.NoError(t, err, "handshake for %s", sni)
	return conn
}

func h3Get(t *testing.T, cc *http3.ClientConn, authority string, port uint16) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s:%d/", authority, port), nil)
	require.NoError(t, err)
	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return string(body)
}

// Two intercepted connections multiplexed on one client socket each get a session of their
// own.
func TestQUIC_TwoInterceptedConnectionsOnOneSocket(t *testing.T) {
	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	handler := func(c *Context) (*http.Response, error) {
		// A request served under its sibling's session would echo the wrong authority.
		return Text(http.StatusOK, c.Session().Target().Host), nil
	}
	p.MustAddInterceptor(nil, "a.example.test/", handler)
	p.MustAddInterceptor(nil, "b.example.test/", handler)

	proxyAddr := startQUIC(t, p)

	clientPC, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	ctr := &quic.Transport{Conn: clientPC}
	defer func() { _ = ctr.Close(); _ = clientPC.Close() }()

	connA := dialSharedQUIC(t, ctr, proxyAddr, "a.example.test", poolOf(proxyCA))
	connB := dialSharedQUIC(t, ctr, proxyAddr, "b.example.test", poolOf(proxyCA))

	h3tr := &http3.Transport{}
	defer func() { _ = h3tr.Close() }()
	ccA, ccB := h3tr.NewClientConn(connA), h3tr.NewClientConn(connB)

	require.Equal(t, "a.example.test", h3Get(t, ccA, "a.example.test", proxyAddr.Port()))
	require.Equal(t, "b.example.test", h3Get(t, ccB, "b.example.test", proxyAddr.Port()))

	sessions := waitForSessions(t, p, 2)
	slices.SortFunc(sessions, func(x, y *Session) int { return strings.Compare(x.Target().Host, y.Target().Host) })
	a, b := sessions[0], sessions[1]
	assert.Equal(t, "a.example.test", a.Target().Host)
	assert.Equal(t, "b.example.test", b.Target().Host)
	require.NotNil(t, a.TLS())
	require.NotNil(t, b.TLS())
	assert.Equal(t, "a.example.test", a.TLS().ServerName, "each session records its own handshake")
	assert.Equal(t, "b.example.test", b.TLS().ServerName)

	require.NoError(t, a.Close())
	select {
	case <-a.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("closing the session did not end its context")
	}
	select {
	case <-b.Context().Done():
		t.Fatal("closing one session ended its sibling")
	default:
	}
	require.Equal(t, "b.example.test", h3Get(t, ccB, "b.example.test", proxyAddr.Port()),
		"the sibling keeps serving after the close")
	remaining := waitForSessions(t, p, 1)
	assert.Equal(t, "b.example.test", remaining[0].Target().Host)
}

// A second tunneled connection from the same client socket used to be fed into the first
// one's tunnel and could never establish. Each is now decided on its own server name, and
// closing either cuts the relay they share, so a survivor would re-handshake.
func TestQUIC_TunnelSiblingsShareOneRelayAndCloseTogether(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA, "a.example.test", "b.example.test")

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	require.NoError(t, p.AddTunnel("a.example.test"))
	require.NoError(t, p.AddTunnel("b.example.test"))

	proxyAddr := startQUICRedirected(t, p, origin)

	clientPC, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	ctr := &quic.Transport{Conn: clientPC}
	defer func() { _ = ctr.Close(); _ = clientPC.Close() }()

	connA := dialSharedQUIC(t, ctr, proxyAddr, "a.example.test", poolOf(originCA))
	connB := dialSharedQUIC(t, ctr, proxyAddr, "b.example.test", poolOf(originCA))

	h3tr := &http3.Transport{}
	defer func() { _ = h3tr.Close() }()
	ccA, ccB := h3tr.NewClientConn(connA), h3tr.NewClientConn(connB)
	assert.Contains(t, h3Get(t, ccA, "a.example.test", proxyAddr.Port()), "host=a.example.test")
	assert.Contains(t, h3Get(t, ccB, "b.example.test", proxyAddr.Port()), "host=b.example.test")

	sessions := waitForSessions(t, p, 2)
	slices.SortFunc(sessions, func(x, y *Session) int { return strings.Compare(x.Target().Host, y.Target().Host) })
	assert.Equal(t, "a.example.test", sessions[0].Target().Host)
	assert.Equal(t, "b.example.test", sessions[1].Target().Host)
	assert.Equal(t, Tunnel, sessions[0].Action())
	assert.Equal(t, Tunnel, sessions[1].Action())

	require.NoError(t, sessions[0].Close())
	for _, sess := range sessions {
		select {
		case <-sess.Context().Done():
		case <-time.After(3 * time.Second):
			t.Fatal("cutting the relay did not end every session riding it")
		}
	}
	assert.Empty(t, slices.Collect(p.Sessions()))
}

// The tag routes a connection with no flow state, a client whose address changed included,
// so it must recognize exactly the IDs its own generator minted.
func TestQUIC_CIDTagRecognizesOnlyItsOwnIDs(t *testing.T) {
	tag, err := newQUICCIDTag([16]byte{1: 0xa5, 7: 0x5a})
	require.NoError(t, err)
	other, err := newQUICCIDTag([16]byte{2: 0xff})
	require.NoError(t, err)

	for range 64 {
		cid, err := tag.GenerateConnectionID()
		require.NoError(t, err)
		require.Equal(t, 8, cid.Len(), "quic-go parses short headers at the generator's length")
		b := cid.Bytes()
		assert.True(t, tag.matches(b))
		assert.False(t, other.matches(b), "a demux with another key may not adopt it")
		flipped := slices.Clone(b)
		flipped[7] ^= 1
		assert.False(t, tag.matches(flipped))
	}
	assert.False(t, tag.matches(nil))
	assert.False(t, tag.matches(make([]byte, 7)))
	assert.False(t, tag.matches(make([]byte, 20)))
}

// The session context of an intercepted QUIC peer follows the connection. A client that
// closes it and leaves ends the context right away, not two minutes later when the idle
// sweep gets to the peer.
func TestQUIC_SessionContextEndsWhenTheClientLeaves(t *testing.T) {
	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddInterceptor(nil, h3Authority+"/", func(c *Context) (*http.Response, error) {
		return Text(http.StatusOK, "ok"), nil
	})

	proxyAddr := startQUIC(t, p)
	tr := dialQUICTo(proxyAddr, poolOf(proxyCA))

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/", h3Authority, proxyAddr.Port()), nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	sessCtx := waitForSessions(t, p, 1)[0].Context()
	select {
	case <-sessCtx.Done():
		t.Fatal("the context fired while the connection was alive")
	default:
	}

	require.NoError(t, tr.Close())
	select {
	case <-sessCtx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the client leaving did not end the session context")
	}
}
