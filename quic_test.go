// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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
	"sync"
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
	p.MustAddTunnel(h3Authority)

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

// A tunneled QUIC connection is decided once, when its ClientHello is read, and never again,
// so it needs a session of its own for a sweep to reach it.
func TestQUIC_TunnelSessionIsListedAndClosed(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddTunnel(h3Authority)

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
	assert.Equal(t, QUIC, sessions[0].Protocol(), "a tunneled handshake stays opaque, HTTP/3 is never established")
	require.NotNil(t, sessions[0].ClientHello(), "the sniffed ClientHello belongs to the session")
	assert.Equal(t, h3Authority, sessions[0].ClientHello().ServerName)
	assert.Contains(t, sessions[0].ClientHello().ALPN, "h3")

	require.NoError(t, sessions[0].Close())
	assert.Empty(t, slices.Collect(p.Sessions()), "closing removes the peer under the demux lock")
}

// The proxy terminated an intercepted QUIC connection itself, so closing its session goes
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
	assert.Equal(t, HTTP3, sessions[0].Protocol(), "established once the server adopts the connection")
	assert.NotNil(t, sessions[0].TLS(), "the handshake the proxy terminated is recorded")
	require.NotNil(t, sessions[0].ClientHello(), "the sniffed ClientHello belongs to the session")
	assert.Equal(t, h3Authority, sessions[0].ClientHello().ServerName)

	require.NoError(t, sessions[0].Close())
	assert.Empty(t, slices.Collect(p.Sessions()))
}

// A handler waiting on the session context has to be released when the session ends. A QUIC
// connection owns its own, since nothing upstream of it cancels one.
func TestQUIC_SessionContextEndsWithTheSession(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddTunnel(h3Authority)

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
	p.MustAddTunnel("a.example.test")
	p.MustAddTunnel("b.example.test")

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

// Closing an intercepted session before the HTTP/3 server has adopted the connection must
// still end it. The tag keeps delivering its packets with no state to drop, so the demux
// dooms the connection and the adoption is where it dies.
func TestQUIC_CloseBeforeAdoptionEndsTheConnection(t *testing.T) {
	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddInterceptor(nil, h3Authority+"/", func(c *Context) (*http.Response, error) {
		return Text(http.StatusOK, "ok"), nil
	})
	proxyAddr := startQUIC(t, p)

	pc, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()

	type dialed struct {
		conn *quic.Conn
		err  error
	}
	res := make(chan dialed, 1)
	go func() {
		conn, err := quic.Dial(t.Context(), pc, net.UDPAddrFromAddrPort(proxyAddr),
			&tls.Config{ServerName: h3Authority, RootCAs: poolOf(proxyCA), NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
			&quic.Config{MaxIdleTimeout: 30 * time.Second, HandshakeIdleTimeout: 5 * time.Second})
		res <- dialed{conn, err}
	}()

	// The session is published before the first Initial reaches the QUIC server, so this
	// close often lands before adoption, and either side of that race must end the
	// connection.
	sess := waitForSessions(t, p, 1)[0]
	require.NoError(t, sess.Close())
	assert.Empty(t, slices.Collect(p.Sessions()))

	d := <-res
	if d.err != nil {
		return // the close landed inside the handshake and killed it outright
	}
	select {
	case <-d.conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the connection survived a close that preceded its adoption")
	}
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

// The session context of an intercepted QUIC connection follows the connection. A client
// that closes it and leaves ends the context right away rather than through a sweep.
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

// udpEchoOrigin starts a UDP echo server and returns its address.
func udpEchoOrigin(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
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
	t.Cleanup(func() { _ = pc.Close() })
	addr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	require.NoError(t, err)
	return addr
}

// payloadOriginPacketConn reads the destination of each datagram out of its first two
// bytes, standing in for a platform reporting exact per datagram origins.
type payloadOriginPacketConn struct {
	net.PacketConn
	mu  sync.Mutex
	dst netip.AddrPort
}

func (c *payloadOriginPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil && n >= 2 {
		port := uint16(b[0])<<8 | uint16(b[1])
		c.mu.Lock()
		c.dst = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
		c.mu.Unlock()
	}
	return n, addr, err
}

func (c *payloadOriginPacketConn) OriginalDestination(net.Addr) (netip.AddrPort, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dst, nil
}

func (c *payloadOriginPacketConn) exactOriginalDestination() bool { return true }

// rawPayloadFor spells a datagram whose first two bytes name the origin's port, for
// payloadOriginPacketConn to read back.
func rawPayloadFor(origin netip.AddrPort) []byte {
	return []byte{byte(origin.Port() >> 8), byte(origin.Port()), 'p', 'i', 'n', 'g'}
}

func TestQUIC_RawUDPTunnelByDestination(t *testing.T) {
	origin := udpEchoOrigin(t)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddTunnel(origin.String())

	proxyAddr := startQUICRedirected(t, p, origin)

	client, err := net.Dial("udp", proxyAddr.String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	buf := make([]byte, 128)
	for _, payload := range [][]byte{
		[]byte("raw-low-bit"),
		{0x81, 0xde, 0xad, 0xbe, 0xef, 0x78, 0x01, 0x02}, // the high bit set, but not QUIC
	} {
		_, err = client.Write(payload)
		require.NoError(t, err)
		require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
		n, rerr := client.Read(buf)
		require.NoError(t, rerr)
		assert.Equal(t, payload, buf[:n])
	}

	sessions := waitForSessions(t, p, 1)
	sess := sessions[0]
	assert.Equal(t, Tunnel, sess.Action())
	assert.Equal(t, UDP, sess.Protocol())
	assert.Equal(t, origin.Addr().String(), sess.Target().Host)
	assert.Equal(t, fmt.Sprint(origin.Port()), sess.Target().Port)
	assert.Equal(t, origin, sess.Upstream())
	assert.True(t, sess.Transparent())
	assert.Nil(t, sess.ClientHello())

	_, err = p.DeleteTunnel(origin.String())
	require.NoError(t, err)
	require.NoError(t, sess.Close())
	assert.Empty(t, slices.Collect(p.Sessions()))
	select {
	case <-sess.Context().Done():
	default:
		t.Fatal("closing the session must end its context")
	}

	_, err = client.Write([]byte("after-close"))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
	_, err = client.Read(buf)
	require.Error(t, err, "a withdrawn destination must not be relayed")
}

func TestQUIC_RawUDPRejectedByDefault(t *testing.T) {
	origin := udpEchoOrigin(t)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)

	proxyAddr := startQUICRedirected(t, p, origin)

	client, err := net.Dial("udp", proxyAddr.String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	_, err = client.Write([]byte("nobody-said-yes"))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
	_, err = client.Read(make([]byte, 64))
	require.Error(t, err)
	assert.Empty(t, slices.Collect(p.Sessions()))
}

// An authority held by an interceptor names traffic the operator chose to inspect, and raw
// bytes offer nothing to terminate, so they drop rather than slipping through as a tunnel.
func TestQUIC_RawUDPInterceptedAuthorityDrops(t *testing.T) {
	origin := udpEchoOrigin(t)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddInterceptor(nil, fmt.Sprintf("%s/+{any}", origin.String()), func(c *Context) (*http.Response, error) {
		return c.Forward()
	})

	proxyAddr := startQUICRedirected(t, p, origin)

	client, err := net.Dial("udp", proxyAddr.String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	_, err = client.Write([]byte("raw-to-an-intercepted-ip"))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
	_, err = client.Read(make([]byte, 64))
	require.Error(t, err)
	assert.Empty(t, slices.Collect(p.Sessions()))
}

func TestQUIC_RawUDPWildcardTunnel(t *testing.T) {
	origin := udpEchoOrigin(t)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddTunnel("+{any}")

	proxyAddr := startQUICRedirected(t, p, origin)

	client, err := net.Dial("udp", proxyAddr.String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	_, err = client.Write([]byte("anything-goes"))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "anything-goes", string(buf[:n]))
}

func TestQUIC_RawUDPRelayCapPerFlow(t *testing.T) {
	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddTunnel("+{any}")

	origins := make([]netip.AddrPort, maxRelaysPerFlow+1)
	for i := range origins {
		origins[i] = udpEchoOrigin(t)
	}

	proxyAddr := serveQUIC(t, p, func(pc net.PacketConn) net.PacketConn {
		return &payloadOriginPacketConn{PacketConn: pc}
	})

	client, err := net.Dial("udp", proxyAddr.String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	buf := make([]byte, 64)
	for i, origin := range origins[:maxRelaysPerFlow] {
		payload := rawPayloadFor(origin)
		_, err = client.Write(payload)
		require.NoError(t, err)
		require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
		n, rerr := client.Read(buf)
		require.NoError(t, rerr, "origin %d must be relayed", i)
		assert.Equal(t, payload, buf[:n])
	}

	_, err = client.Write(rawPayloadFor(origins[maxRelaysPerFlow]))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
	_, err = client.Read(buf)
	require.Error(t, err, "the relay cap refuses the next origin")
	assert.Len(t, slices.Collect(p.Sessions()), maxRelaysPerFlow)
}

func TestQUIC_RawUDPSessionEndsOnProxyClose(t *testing.T) {
	origin := udpEchoOrigin(t)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddTunnel(origin.String())

	proxyAddr := startQUICRedirected(t, p, origin)

	client, err := net.Dial("udp", proxyAddr.String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	_, err = client.Write([]byte("warm-up"))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, err = client.Read(make([]byte, 64))
	require.NoError(t, err)

	sessions := waitForSessions(t, p, 1)
	require.NoError(t, p.Close())
	select {
	case <-sessions[0].Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("closing the proxy must end the raw session")
	}
}

// Closing a raw UDP session bars its destination, or the client's next datagram would
// re-open a relay under the tunnel that still matches, undoing the close. Once the bar
// expires the destination is decided afresh.
func TestQUIC_RawUDPSessionCloseBarsReadmission(t *testing.T) {
	origin := udpEchoOrigin(t)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddTunnel("+{any}")

	proxyAddr := startQUICRedirected(t, p, origin)

	client, err := net.Dial("udp", proxyAddr.String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	buf := make([]byte, 64)
	_, err = client.Write([]byte("ping"))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	n, err := client.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf[:n]))

	sess := waitForSessions(t, p, 1)[0]
	require.NoError(t, sess.Close())

	_, err = client.Write([]byte("zombie"))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
	_, err = client.Read(buf)
	require.Error(t, err, "the tunnel still matches, only the bar can refuse this datagram")
	assert.Empty(t, slices.Collect(p.Sessions()))

	var d *quicDemux
	p.srv.mu.Lock()
	for dd := range p.srv.quics {
		d = dd
	}
	p.srv.mu.Unlock()
	require.NotNil(t, d)

	// Backdating the deadline stands in for its expiry.
	from := netip.MustParseAddrPort(client.LocalAddr().String())
	revoked := 0
	d.mu.Lock()
	flow := d.flows[from]
	if flow != nil {
		revoked = len(flow.revoked)
		for o := range flow.revoked {
			flow.revoked[o] = time.Now().Add(-time.Second)
		}
	}
	d.mu.Unlock()
	require.NotNil(t, flow)
	require.Equal(t, 1, revoked)

	_, err = client.Write([]byte("fresh"))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	n, err = client.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "fresh", string(buf[:n]))
	waitForSessions(t, p, 1)
}

// With exact per datagram destinations, closing one origin's session refuses that origin
// alone and the flow's other relay keeps going.
func TestQUIC_RawUDPSessionClosePerOrigin(t *testing.T) {
	originA := udpEchoOrigin(t)
	originB := udpEchoOrigin(t)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddTunnel("+{any}")

	proxyAddr := serveQUIC(t, p, func(pc net.PacketConn) net.PacketConn {
		return &payloadOriginPacketConn{PacketConn: pc}
	})

	client, err := net.Dial("udp", proxyAddr.String())
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	buf := make([]byte, 64)
	for _, origin := range []netip.AddrPort{originA, originB} {
		payload := rawPayloadFor(origin)
		_, err = client.Write(payload)
		require.NoError(t, err)
		require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
		n, rerr := client.Read(buf)
		require.NoError(t, rerr)
		assert.Equal(t, payload, buf[:n])
	}

	var sessA *Session
	for _, sess := range waitForSessions(t, p, 2) {
		if sess.Upstream() == originA {
			sessA = sess
		}
	}
	require.NotNil(t, sessA)
	require.NoError(t, sessA.Close())

	_, err = client.Write(rawPayloadFor(originA))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
	_, err = client.Read(buf)
	require.Error(t, err, "the closed origin must be refused")

	payload := rawPayloadFor(originB)
	_, err = client.Write(payload)
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	n, err := client.Read(buf)
	require.NoError(t, err, "the other origin's relay must keep going")
	assert.Equal(t, payload, buf[:n])
	assert.Len(t, slices.Collect(p.Sessions()), 1)
}

// Closing a tunneled QUIC session leaves the client's connection sending datagrams no
// header can attribute, which land in raw admission. With a catch-all tunnel still
// matching the destination they would re-open a relay and the connection would survive
// its own close, never re-handshaking, never re-decided.
func TestQUIC_TunnelSessionCloseBarsOrphanedDatagrams(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddTunnel("+{any}")

	proxyAddr := startQUICRedirected(t, p, origin)

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(proxyAddr), &tls.Config{
		ServerName: h3Authority,
		RootCAs:    poolOf(originCA),
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{MaxIdleTimeout: time.Second})
	require.NoError(t, err)
	defer func() { _ = conn.CloseWithError(0, "") }()

	sess := waitForSessions(t, p, 1)[0]
	require.Equal(t, Tunnel, sess.Action())
	require.NoError(t, sess.Close())
	require.Empty(t, slices.Collect(p.Sessions()))

	// A short header from the closed connection, past its handshake, reaches raw admission.
	orphan := make([]byte, 48)
	_, err = rand.Read(orphan)
	require.NoError(t, err)
	orphan[0] = orphan[0]&0x3f | 0x40
	_, err = pc.WriteToUDP(orphan, net.UDPAddrFromAddrPort(proxyAddr))
	require.NoError(t, err)

	time.Sleep(300 * time.Millisecond)
	assert.Empty(t, slices.Collect(p.Sessions()), "an orphaned datagram must not become a session")
}

// tproxyOriginPacketConn stands in for a TPROXY socket: exact per datagram origins, reply
// sockets that are plain loopback ones, and a shared socket that black-holes every direct
// client write so a reply sneaking around the reply sockets fails the test. perClient is
// keyed by the client address as the proxy reads it off its socket, and a client not in it
// reports the shared origin, so a test may hold one origin live per client socket.
type tproxyOriginPacketConn struct {
	net.PacketConn
	origin    atomic.Value
	perClient sync.Map
	replies   chan net.Addr
	direct    atomic.Int64
}

func newTProxyOriginPacketConn(pc net.PacketConn, origin netip.AddrPort) *tproxyOriginPacketConn {
	c := &tproxyOriginPacketConn{PacketConn: pc, replies: make(chan net.Addr, 8)}
	c.origin.Store(origin)
	return c
}

func (c *tproxyOriginPacketConn) OriginalDestination(remote net.Addr) (netip.AddrPort, error) {
	if origin, ok := c.perClient.Load(remote.String()); ok {
		return origin.(netip.AddrPort), nil
	}
	return c.origin.Load().(netip.AddrPort), nil
}

func (c *tproxyOriginPacketConn) exactOriginalDestination() bool { return true }

func (c *tproxyOriginPacketConn) transparentReplies() bool { return true }

func (c *tproxyOriginPacketConn) replySocket(netip.AddrPort) (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err == nil {
		select {
		case c.replies <- pc.LocalAddr():
		default:
		}
	}
	return pc, err
}

func (c *tproxyOriginPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.direct.Add(1)
	return len(b), nil
}

// startTProxyQUIC starts p on a loopback UDP port wrapped as a TPROXY socket, built before
// the serving goroutine so the test may touch the wrapper freely.
func startTProxyQUIC(t *testing.T, p *Proxy, origin netip.AddrPort) (*tproxyOriginPacketConn, netip.AddrPort) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	wrapper := newTProxyOriginPacketConn(pc, origin)

	go func() { _ = p.ServeQUIC(wrapper) }()
	t.Cleanup(func() { _ = p.Close() })

	addr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	require.NoError(t, err)
	return wrapper, addr
}

func TestQUIC_TProxyRawRelayRepliesFromTheOrigin(t *testing.T) {
	origin := udpEchoOrigin(t)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddTunnel(origin.String())

	wrapper, proxyAddr := startTProxyQUIC(t, p, origin)

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	payload := []byte("spoofed-return-path")
	_, err = client.WriteTo(payload, net.UDPAddrFromAddrPort(proxyAddr))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	buf := make([]byte, 64)
	n, from, err := client.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf[:n])

	replyAddr := <-wrapper.replies
	assert.Equal(t, replyAddr.String(), from.String(), "the reply must leave from the origin's socket")
	assert.NotEqual(t, proxyAddr.String(), from.String())
	assert.Zero(t, wrapper.direct.Load(), "nothing may write to a client through the shared socket")
}

func TestQUIC_TProxyInterceptRepliesFromTheOrigin(t *testing.T) {
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

	wrapper, proxyAddr := startTProxyQUIC(t, p, origin)

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
	assert.Zero(t, wrapper.direct.Load(), "every handshake byte must leave from the origin's socket")
}

// Two intercepted origins reached from one client socket each get a terminating stack of
// their own, each replying from its origin's address. The wrapper reports one origin per
// client at a time, so the two run in sequence here, the concurrent case needing the per
// datagram attribution only a real TPROXY deployment gives.
func TestQUIC_TProxyTwoInterceptedOriginsOnOneSocket(t *testing.T) {
	first := netip.MustParseAddrPort("127.0.0.1:4431")
	second := netip.MustParseAddrPort("127.0.0.1:4432")

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	handler := func(c *Context) (*http.Response, error) {
		return Text(http.StatusOK, c.Session().Target().Host), nil
	}
	p.MustAddInterceptor(nil, "first.test/", handler)
	p.MustAddInterceptor(nil, "second.test/", handler)

	wrapper, proxyAddr := startTProxyQUIC(t, p, first)

	clientPC, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	tr := &quic.Transport{Conn: clientPC}
	defer func() { _ = tr.Close(); _ = clientPC.Close() }()
	h3tr := &http3.Transport{}
	defer func() { _ = h3tr.Close() }()

	connA := dialSharedQUIC(t, tr, proxyAddr, "first.test", poolOf(proxyCA))
	require.Equal(t, "first.test", h3Get(t, h3tr.NewClientConn(connA), "first.test", proxyAddr.Port()))
	_ = connA.CloseWithError(0, "")

	wrapper.origin.Store(second)
	connB := dialSharedQUIC(t, tr, proxyAddr, "second.test", poolOf(proxyCA))
	require.Equal(t, "second.test", h3Get(t, h3tr.NewClientConn(connB), "second.test", proxyAddr.Port()))
	_ = connB.CloseWithError(0, "")

	assert.Zero(t, wrapper.direct.Load(), "every reply must leave from an origin's socket")
	replyA, replyB := <-wrapper.replies, <-wrapper.replies
	assert.NotEqual(t, replyA.String(), replyB.String(), "each origin replies from its own socket")
}

// A tagged short header with no stack left behind it is answered with a stateless reset
// holding the token the stack advertised, from the reply socket of the origin the client
// targeted.
func TestQUIC_StatelessResetForOrphanedTag(t *testing.T) {
	first := netip.MustParseAddrPort("127.0.0.1:4431")
	orphanOrigin := udpEchoOrigin(t)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAddInterceptor(nil, "first.test/", func(c *Context) (*http.Response, error) {
		return Text(http.StatusOK, "ok"), nil
	})
	p.MustAddTunnel(orphanOrigin.String())

	wrapper, proxyAddr := startTProxyQUIC(t, p, first)

	// Arms the tag and the reset key.
	clientA, err := net.ListenUDP("udp", nil)
	require.NoError(t, err)
	tr := &quic.Transport{Conn: clientA}
	defer func() { _ = tr.Close(); _ = clientA.Close() }()
	connA := dialSharedQUIC(t, tr, proxyAddr, "first.test", poolOf(proxyCA))
	_ = connA.CloseWithError(0, "")

	// A raw relay to the orphan origin, so its reply socket exists with no stack behind it.
	wrapper.origin.Store(orphanOrigin)
	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	_, err = client.WriteTo([]byte("warm-up"), net.UDPAddrFromAddrPort(proxyAddr))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	buf := make([]byte, 128)
	_, _, err = client.ReadFrom(buf)
	require.NoError(t, err)

	// The same derivation the demux ran, so the minted ID and the token are the ones a
	// previous process would have handed a client.
	tag, resetKey, err := quicInterceptKeys(proxyCA)
	require.NoError(t, err)
	cid, err := tag.GenerateConnectionID()
	require.NoError(t, err)

	orphan := make([]byte, 60)
	_, err = rand.Read(orphan)
	require.NoError(t, err)
	orphan[0] = orphan[0]&0x3f | 0x40
	copy(orphan[1:], cid.Bytes())
	_, err = client.WriteTo(orphan, net.UDPAddrFromAddrPort(proxyAddr))
	require.NoError(t, err)

	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	n, _, err := client.ReadFrom(buf)
	require.NoError(t, err, "the orphaned tag must be answered")
	require.Equal(t, 42, n)
	mac := hmac.New(sha256.New, resetKey[:])
	mac.Write(cid.Bytes())
	assert.Equal(t, mac.Sum(nil)[:16], buf[n-16:n], "the reset must end with the advertised token")
}

// One shutdown drains every terminating stack, its single HTTP/3 server sending the GOAWAYs.
func TestQUIC_ShutdownDrainsEveryInterceptStack(t *testing.T) {
	first := netip.MustParseAddrPort("127.0.0.1:4431")
	second := netip.MustParseAddrPort("127.0.0.1:4432")

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	release := make(chan struct{})
	inflight := make(chan struct{}, 2)
	handler := func(c *Context) (*http.Response, error) {
		inflight <- struct{}{}
		<-release
		return Text(http.StatusOK, c.Session().Target().Host), nil
	}
	p.MustAddInterceptor(nil, "first.test/", handler)
	p.MustAddInterceptor(nil, "second.test/", handler)

	wrapper, proxyAddr := startTProxyQUIC(t, p, first)

	h3tr := &http3.Transport{}
	defer func() { _ = h3tr.Close() }()

	dialFrom := func(origin netip.AddrPort, sni string) (*quic.Transport, *http3.ClientConn) {
		// Bound to 127.0.0.1 so the address stored here is the one the proxy reads off
		// its own socket, or the per client lookup misses and one stack serves both.
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		wrapper.perClient.Store(pc.LocalAddr().String(), origin)
		tr := &quic.Transport{Conn: pc}
		t.Cleanup(func() { _ = tr.Close(); _ = pc.Close() })
		return tr, h3tr.NewClientConn(dialSharedQUIC(t, tr, proxyAddr, sni, poolOf(proxyCA)))
	}
	_, ccA := dialFrom(first, "first.test")
	_, ccB := dialFrom(second, "second.test")
	replyA, replyB := <-wrapper.replies, <-wrapper.replies
	require.NotEqual(t, replyA.String(), replyB.String(), "each origin must hold a stack of its own")

	results := make(chan string, 2)
	errs := make(chan error, 2)
	do := func(cc *http3.ClientConn, sni string) {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s:%d/", sni, proxyAddr.Port()), nil)
		if err != nil {
			errs <- err
			return
		}
		resp, err := cc.RoundTrip(req)
		if err != nil {
			errs <- err
			return
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			errs <- err
			return
		}
		results <- string(body)
	}
	go do(ccA, "first.test")
	go do(ccB, "second.test")
	<-inflight
	<-inflight

	done := make(chan error, 1)
	go func() { done <- p.Shutdown(t.Context()) }()
	// The requests in flight hold the drain open, and once released both must complete.
	time.Sleep(100 * time.Millisecond)
	close(release)

	require.NoError(t, <-done, "the drain must cover both stacks")
	var bodies []string
	for range 2 {
		select {
		case body := <-results:
			bodies = append(bodies, body)
		case err := <-errs:
			t.Fatal(err)
		}
	}
	slices.Sort(bodies)
	assert.Equal(t, []string{"first.test", "second.test"}, bodies)
}

// The eviction candidate at the stack cap is the least recently used idle stack and never
// one with live connections.
func TestQUICDemux_EvictInterceptPrefersIdleLRU(t *testing.T) {
	d := &quicDemux{intercepts: map[netip.AddrPort]*quicIntercept{}}
	busy := &quicIntercept{origin: netip.MustParseAddrPort("10.0.0.1:443"), conns: 1, lastSeen: time.Unix(1, 0)}
	older := &quicIntercept{origin: netip.MustParseAddrPort("10.0.0.2:443"), lastSeen: time.Unix(2, 0)}
	newer := &quicIntercept{origin: netip.MustParseAddrPort("10.0.0.3:443"), lastSeen: time.Unix(3, 0)}
	for _, it := range []*quicIntercept{busy, older, newer} {
		d.intercepts[it.origin] = it
	}
	require.Same(t, older, d.evictableLocked())
	delete(d.intercepts, older.origin)
	require.Same(t, newer, d.evictableLocked())
	delete(d.intercepts, newer.origin)
	assert.Nil(t, d.evictableLocked(), "a stack with live connections is never evicted")
	assert.Contains(t, d.intercepts, busy.origin)
}

// The read loop holds no lock between reading a datagram and publishing the relay it leads
// to, so an immediate close can run to completion in between. The publication must be
// refused, not land in a demux already swept.
func TestQUICDemux_CloseRefusesLatePublish(t *testing.T) {
	p, err := New()
	require.NoError(t, err)
	p.MustAddTunnel("+{any}")

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	origin, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = origin.Close() }()

	originAddr, err := netip.ParseAddrPort(origin.LocalAddr().String())
	require.NoError(t, err)

	d, err := newQUICDemux(p, fixedOriginPacketConn{pc, originAddr})
	require.NoError(t, err)

	d.close()

	// The dispatch a read-loop goroutine had in flight when close ran. The datagram sets
	// the long-header bit but is not QUIC, so it is placed by its destination.
	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	d.dispatch(client, []byte{0xC0, 0xDE})

	d.mu.Lock()
	flows := len(d.flows)
	relays := d.relays
	d.mu.Unlock()
	require.Zerof(t, relays, "%d relay(s) published into a closed demux, %d flow(s) recreated", relays, flows)
}
