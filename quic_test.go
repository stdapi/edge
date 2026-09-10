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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
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
	return h3OriginAt(t, ca, "127.0.0.1:0", names...)
}

func h3OriginAt(t *testing.T, ca *CA, listen string, names ...string) netip.AddrPort {
	t.Helper()

	pc, err := net.ListenPacket("udp", listen)
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

	go func() { _ = p.ServeTransparentUDP(wrap(pc)) }()
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
	p.MustAdd(h3Authority+"/+{any}", func(c *HTTPCtx) (*http.Response, error) {
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
func TestQUIC_HandlerCanShortCircuit(t *testing.T) {
	requireCurl(t)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)

	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)

	p.MustAdd(h3Authority+"/blocked", func(c *HTTPCtx) (*http.Response, error) {
		return Text(http.StatusForbidden, "blocked by edge over "+c.Protocol().String()), nil
	}, WithMethods[HTTP](http.MethodGet))

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

	pc, err := loopbackUDP()
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

// The application error space belongs to the protocol a connection negotiated, so a close
// with nothing to report says H3_NO_ERROR where h3 was negotiated and 0 everywhere else,
// KindQUIC either way.
func TestQUIC_CloseCarriesTheProtocolsNoErrorCode(t *testing.T) {
	for _, tc := range []struct {
		name       string
		alpn       string
		code       quic.ApplicationErrorCode
		servableAs []Kind
	}{
		{name: "h3 served stream by stream", alpn: "h3", code: h3NoError, servableAs: []Kind{KindHTTP, KindQUIC}},
		{name: "doq", alpn: "doq", code: 0, servableAs: []Kind{KindQUIC}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxyCA, err := GenerateCA()
			require.NoError(t, err)
			p, err := New(WithCA(proxyCA))
			require.NoError(t, err)
			p.MustAdd[QUIC](h3Authority, func(c *QUICCtx) error {
				<-c.Context().Done()
				return nil
			})

			proxyAddr := startQUIC(t, p)

			pc, err := loopbackUDP()
			require.NoError(t, err)
			defer func() { _ = pc.Close() }()
			conn, err := quic.Dial(t.Context(), pc, net.UDPAddrFromAddrPort(proxyAddr),
				&tls.Config{ServerName: h3Authority, RootCAs: poolOf(proxyCA), NextProtos: []string{tc.alpn}, MinVersion: tls.VersionTLS13},
				&quic.Config{MaxIdleTimeout: 10 * time.Second, HandshakeIdleTimeout: 3 * time.Second},
			)
			require.NoError(t, err)
			defer func() { _ = conn.CloseWithError(0, "") }()

			sess := waitForSessions(t, p, 1)[0]
			require.Equal(t, KindQUIC, sess.Kind())
			assert.Equal(t, tc.servableAs, sess.ServableAs())
			require.NoError(t, sess.Close())

			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			_, err = conn.AcceptStream(ctx)
			var appErr *quic.ApplicationError
			require.ErrorAs(t, err, &appErr, "the close must reach the client as an application close")
			assert.True(t, appErr.Remote)
			assert.Equal(t, tc.code, appErr.ErrorCode)
		})
	}
}

// A QUIC session is listed while its handshake still runs, so a handshake fact written to a
// plain field after publication races this loop under the race detector.
func TestQUIC_SessionALPNDuringHandshake(t *testing.T) {
	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAdd[QUIC](h3Authority, func(c *QUICCtx) error {
		<-c.Context().Done()
		return nil
	})
	proxyAddr := startQUIC(t, p)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	defer wg.Wait()
	defer close(stop)
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			for s := range p.Sessions() {
				_ = s.ALPN()
			}
			runtime.Gosched()
		}
	})

	for range 5 {
		pc, err := loopbackUDP()
		require.NoError(t, err)
		conn, err := quic.Dial(t.Context(), pc, net.UDPAddrFromAddrPort(proxyAddr),
			&tls.Config{ServerName: h3Authority, RootCAs: poolOf(proxyCA), NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13},
			&quic.Config{MaxIdleTimeout: 5 * time.Second, HandshakeIdleTimeout: 3 * time.Second},
		)
		require.NoError(t, err)
		_ = conn.CloseWithError(0, "")
		_ = pc.Close()
	}
}

// dialQUICTo returns an HTTP/3 transport reaching addr whatever the URL says, so a test can
// use the authority the proxy sniffs without it having to resolve.
func dialQUICTo(addr netip.AddrPort, roots *x509.CertPool) *http3.Transport {
	return &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		// A short idle timeout so a connection the proxy cut does not hold the test open.
		QUICConfig: &quic.Config{MaxIdleTimeout: time.Second},
		Dial: func(ctx context.Context, _ string, cfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			pc, err := loopbackUDP()
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
	p.MustAdd(h3Authority+"/+{any}", func(c *HTTPCtx) (*http.Response, error) {
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
	assert.Equal(t, KindHTTP, sessions[0].Kind())
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
	tr2 := DefaultTransport()
	tr2.RootCAs = poolOf(originCA)
	p, err := New(WithCA(proxyCA), WithTransport(tr2))
	require.NoError(t, err)
	// Served stream by stream: the client offers h3 and nothing admits HTTP here, so the
	// connection falls to the QUIC entry, which carries its streams opaque.
	p.MustAdd[QUIC](h3Authority, relayQUIC)

	proxyAddr := startQUICRedirected(t, p, origin)
	// Terminated either way, so the certificate the client checks is the proxy's.
	tr := dialQUICTo(proxyAddr, poolOf(proxyCA))
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
	handler := func(c *HTTPCtx) (*http.Response, error) {
		// A request served under its sibling's session would echo the wrong authority.
		return Text(http.StatusOK, c.Session().Target().Host), nil
	}
	p.MustAdd("a.example.test/", handler)
	p.MustAdd("b.example.test/", handler)

	proxyAddr := startQUIC(t, p)

	clientPC, err := loopbackUDP()
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
func TestQUIC_CloseBeforeAdoptionEndsTheConnection(t *testing.T) {
	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	p.MustAdd(h3Authority+"/", func(c *HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, "ok"), nil
	})
	proxyAddr := startQUIC(t, p)

	pc, err := loopbackUDP()
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
	p.MustAdd(h3Authority+"/", func(c *HTTPCtx) (*http.Response, error) {
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

// tproxyOriginPacketConn is a socket that reports an original destination for every datagram
// and sources its replies from that destination, the TPROXY contract.
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

	go func() { _ = p.ServeTransparentUDP(wrapper) }()
	t.Cleanup(func() { _ = p.Close() })

	addr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	require.NoError(t, err)
	return wrapper, addr
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
	p.MustAdd(h3Authority+"/+{any}", func(c *HTTPCtx) (*http.Response, error) {
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
	handler := func(c *HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, c.Session().Target().Host), nil
	}
	p.MustAdd("first.test/", handler)
	p.MustAdd("second.test/", handler)

	wrapper, proxyAddr := startTProxyQUIC(t, p, first)

	clientPC, err := loopbackUDP()
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
	p.MustAdd("first.test/", func(c *HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, "ok"), nil
	})
	p.MustAdd[UDP](orphanOrigin.String(), forwardDatagram)

	wrapper, proxyAddr := startTProxyQUIC(t, p, first)

	// Arms the tag and the reset key.
	clientA, err := loopbackUDP()
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
	handler := func(c *HTTPCtx) (*http.Response, error) {
		inflight <- struct{}{}
		<-release
		return Text(http.StatusOK, c.Session().Target().Host), nil
	}
	p.MustAdd("first.test/", handler)
	p.MustAdd("second.test/", handler)

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
	d := &quicDemux{intercepts: map[interceptKey]*quicIntercept{}}
	at := func(s string) interceptKey { return interceptKey{origin: netip.MustParseAddrPort(s)} }
	busy := &quicIntercept{key: at("10.0.0.1:443"), conns: 1, lastSeen: time.Unix(1, 0)}
	older := &quicIntercept{key: at("10.0.0.2:443"), lastSeen: time.Unix(2, 0)}
	newer := &quicIntercept{key: at("10.0.0.3:443"), lastSeen: time.Unix(3, 0)}
	for _, it := range []*quicIntercept{busy, older, newer} {
		d.intercepts[it.key] = it
	}
	require.Same(t, older, d.evictableLocked())
	delete(d.intercepts, older.key)
	require.Same(t, newer, d.evictableLocked())
	delete(d.intercepts, newer.key)
	assert.Nil(t, d.evictableLocked(), "a stack with live connections is never evicted")
	assert.Contains(t, d.intercepts, busy.key)
}

// The read loop holds no lock between reading a datagram and publishing the relay it leads
// to, so an immediate close can run to completion in between. The publication must be
// refused, not land in a demux already swept.
func TestQUICDemux_CloseRefusesLatePublish(t *testing.T) {
	p, err := New()
	require.NoError(t, err)
	p.MustAdd[TCP]("+{any}", relayStream)

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
	d.dispatch(client, []byte{0xC0, 0xDE}, false)

	d.mu.Lock()
	flows := len(d.flows)
	udps := d.udps
	d.mu.Unlock()
	require.Zerof(t, udps, "%d datagram flow(s) published into a closed demux, %d flow(s) recreated", udps, flows)
}

// Shutdown can win the race against a ServeTransparentUDP that is tracked but has not reached run yet,
// and the demux WaitGroup has to survive that ordering.
func TestQUICDemux_ShutdownRacesServeQUICStartup(t *testing.T) {
	for range 200 {
		p := testProxy(t)

		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		served := make(chan error, 1)
		go func() { served <- p.ServeTransparentUDP(pc) }()

		for {
			p.srv.mu.Lock()
			tracked := len(p.srv.quics) == 1
			p.srv.mu.Unlock()
			if tracked {
				break
			}
			runtime.Gosched()
		}

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		require.NoError(t, p.Shutdown(ctx))
		cancel()

		select {
		case err := <-served:
			assert.ErrorIs(t, err, ErrProxyClosed)
		case <-time.After(5 * time.Second):
			t.Fatal("ServeTransparentUDP did not return after Shutdown")
		}
	}
}

// The accept loop replaces relaying blind: a handler sees each stream, reads its first bytes,
// and Relay carries the rest after what was consumed went over by hand.
func TestQUIC_AcceptInspectsAndRelaysStreams(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	tr2 := DefaultTransport()
	tr2.RootCAs = poolOf(originCA)
	p, err := New(WithCA(proxyCA), WithTransport(tr2))
	require.NoError(t, err)

	var streams atomic.Int64
	p.MustAdd[QUIC](h3Authority, func(c *QUICCtx) error {
		var wg sync.WaitGroup
		defer wg.Wait()
		for {
			st, aerr := c.Accept()
			if aerr != nil {
				return nil
			}
			streams.Add(1)
			wg.Go(func() {
				buf := make([]byte, 64)
				n, rerr := st.Reader().Read(buf)
				if n == 0 && rerr != nil {
					return
				}
				w, _, oerr := st.Open()
				if oerr != nil {
					return
				}
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				_ = st.Relay()
			})
		}
	})

	proxyAddr := startQUICRedirected(t, p, origin)
	tr := dialQUICTo(proxyAddr, poolOf(proxyCA))
	defer func() { _ = tr.Close() }()

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/inspected", h3Authority, proxyAddr.Port()), nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "path=/inspected", "the inspected bytes were not lost")
	assert.Greater(t, streams.Load(), int64(0), "the handler saw the streams it carried")
}

// A QUIC connection keeps the entry it was decided on, and Stale reports when the entries as
// they stand would pick another one.
func TestQUIC_StaleFollowsTheEntry(t *testing.T) {
	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(proxyCA))
	require.NoError(t, err)
	started := make(chan struct{}, 1)
	block := func(c *QUICCtx) error {
		started <- struct{}{}
		<-c.Context().Done()
		return nil
	}
	p.MustAdd[QUIC]("+{any}", block)
	proxyAddr := startQUIC(t, p)

	pc, err := loopbackUDP()
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()
	conn, err := quic.Dial(t.Context(), pc, net.UDPAddrFromAddrPort(proxyAddr),
		&tls.Config{ServerName: h3Authority, RootCAs: poolOf(proxyCA), NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13},
		&quic.Config{MaxIdleTimeout: 10 * time.Second, HandshakeIdleTimeout: 3 * time.Second},
	)
	require.NoError(t, err)
	defer func() { _ = conn.CloseWithError(0, "") }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("the handler did not start")
	}

	sess := waitForSessions(t, p, 1)[0]
	require.Equal(t, KindQUIC, sess.Kind())
	assert.False(t, sess.Stale(), "decided on the only entry there is")

	p.MustAdd[QUIC](h3Authority, block)
	assert.True(t, sess.Stale(), "a more specific entry would serve it now")

	_, err = p.Delete[QUIC](h3Authority)
	require.NoError(t, err)
	assert.False(t, sess.Stale(), "back on the entry it was decided on")

	_, err = p.Update[QUIC]("+{any}", block)
	require.NoError(t, err)
	assert.True(t, sess.Stale(), "the entry serving it was replaced")

	_, err = p.Delete[QUIC]("+{any}")
	require.NoError(t, err)
	assert.True(t, sess.Stale(), "nothing admits it any more")
}

// An h3 connection served stream by stream, for want of an HTTP entry, goes stale once one
// admits its authority, since the traffic allowed HTTP from the start.
func TestQUIC_StaleWhenHTTPAdmitsAnH3Connection(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	upstream := DefaultTransport()
	upstream.RootCAs = poolOf(originCA)
	p, err := New(WithCA(proxyCA), WithTransport(upstream))
	require.NoError(t, err)
	p.MustAdd[QUIC](h3Authority, relayQUIC)

	proxyAddr := startQUICRedirected(t, p, origin)
	tr := dialQUICTo(proxyAddr, poolOf(proxyCA))
	defer func() { _ = tr.Close() }()

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/echo", h3Authority, proxyAddr.Port()), nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	sess := waitForSessions(t, p, 1)[0]
	require.Equal(t, KindQUIC, sess.Kind())
	assert.False(t, sess.Stale())

	p.MustAdd(h3Authority+"/+{any}", forwardHandler)
	assert.True(t, sess.Stale(), "HTTP admits the traffic of this connection")
}

// An h3 connection served as HTTP stays HTTP when its last HTTP entry goes, and Stale reports
// that a new connection would be served stream by stream.
func TestQUIC_StaleWhenTheLastHTTPEntryGoes(t *testing.T) {
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
	p.MustAdd(h3Authority+"/+{any}", forwardHandler)
	p.MustAdd[QUIC](h3Authority, relayQUIC)

	proxyAddr := startQUICRedirected(t, p, origin)
	tr := dialQUICTo(proxyAddr, poolOf(proxyCA))
	defer func() { _ = tr.Close() }()

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/echo", h3Authority, proxyAddr.Port()), nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	sess := waitForSessions(t, p, 1)[0]
	require.Equal(t, KindHTTP, sess.Kind())
	assert.False(t, sess.Stale())

	_, err = p.Delete[HTTP](h3Authority + "/+{any}")
	require.NoError(t, err)
	assert.True(t, sess.Stale(), "a new connection would be served stream by stream")

	p.MustAdd(h3Authority+"/+{any}", forwardHandler)
	assert.False(t, sess.Stale(), "HTTP admits it again, and each request is routed on its own")
}

// A QUIC handler dials the origin through the transport's dialer, on the socket it returns,
// and the socket is closed once the handler has returned.
func TestQUIC_DialUsesTheTransportDialer(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	upstream := DefaultTransport()
	upstream.RootCAs = poolOf(originCA)
	var seenNetwork, local atomic.Pointer[string]
	upstream.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		seenNetwork.Store(&network)
		l := conn.LocalAddr().String()
		local.Store(&l)
		return conn, nil
	}
	p, err := New(WithCA(proxyCA), WithTransport(upstream))
	require.NoError(t, err)
	p.MustAdd[QUIC](h3Authority, relayQUIC)

	proxyAddr := startQUICRedirected(t, p, origin)
	tr := dialQUICTo(proxyAddr, poolOf(proxyCA))

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("https://%s:%d/echo", h3Authority, proxyAddr.Port()), nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Contains(t, string(body), "path=/echo")
	require.NotNil(t, seenNetwork.Load())
	assert.Equal(t, "udp", *seenNetwork.Load())

	require.NoError(t, tr.Close())
	assert.Eventually(t, func() bool {
		pc, err := net.ListenPacket("udp", *local.Load())
		if err != nil {
			return false
		}
		_ = pc.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond, "the socket the handler dialed on is still open")
}

// closeTrackedConn reports when a connection a dialer handed out is closed.
type closeTrackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackedConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// An h3 upstream is reached through the transport's dialer, whatever connection it returns,
// and the connection is closed with the QUIC connection it carried.
func TestQUIC_H3UpstreamUsesTheTransportDialer(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	proxyCA, err := GenerateCA()
	require.NoError(t, err)
	upstream := DefaultTransport()
	upstream.AllowHTTP3 = true
	upstream.RootCAs = poolOf(originCA)
	var dialed atomic.Pointer[closeTrackedConn]
	upstream.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		require.Equal(t, "udp", network)
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, origin.String())
		if err != nil {
			return nil, err
		}
		tracked := &closeTrackedConn{Conn: conn}
		dialed.Store(tracked)
		return tracked, nil
	}
	p, err := New(WithCA(proxyCA), WithTransport(upstream))
	require.NoError(t, err)
	seen := new(recorder)
	p.MustAdd(h3Authority+"/+{any}", func(c *HTTPCtx) (*http.Response, error) {
		seen.add(c.Protocol().String())
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
	assert.Contains(t, string(body), "path=/echo")
	assert.Equal(t, []string{"HTTP/3.0"}, seen.all())
	require.NotNil(t, dialed.Load(), "the h3 upstream was not reached through the dialer")
	assert.False(t, dialed.Load().closed.Load())

	require.NoError(t, p.Close())
	assert.Eventually(t, func() bool { return dialed.Load().closed.Load() },
		5*time.Second, 20*time.Millisecond, "the socket the h3 upstream ran on is still open")
}

// A dialer that returns a socket with no peer fails the dial, since a QUIC connection needs
// one address to write to.
func TestQUIC_DialRefusesASocketWithNoPeer(t *testing.T) {
	tr := DefaultTransport()
	tr.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	cfg := &tls.Config{ServerName: h3Authority, NextProtos: []string{"h3"}, InsecureSkipVerify: true}
	conn, err := newUpstreamDialer(tr).dialQUIC(t.Context(), "127.0.0.1:1", cfg, &quic.Config{})
	require.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "no peer")
}

// noDeadlineConn is a connected socket whose deadlines do nothing, as a tunnel's often do.
type noDeadlineConn struct{ net.Conn }

func (c noDeadlineConn) SetReadDeadline(time.Time) error { return nil }
func (c noDeadlineConn) SetDeadline(time.Time) error     { return nil }

// The socket a QUIC connection ran on is released when the connection ends, even when a read
// deadline cannot end its read loop.
func TestQUIC_DialReleasesASocketWithoutDeadlines(t *testing.T) {
	originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
	require.NoError(t, err)
	origin := h3Origin(t, originCA)

	tr := DefaultTransport()
	var local atomic.Pointer[string]
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		l := c.LocalAddr().String()
		local.Store(&l)
		return noDeadlineConn{c}, nil
	}
	cfg := &tls.Config{ServerName: h3Authority, NextProtos: []string{"h3"}, RootCAs: poolOf(originCA), MinVersion: tls.VersionTLS13}
	conn, err := newUpstreamDialer(tr).dialQUIC(t.Context(), origin.String(), cfg, &quic.Config{})
	require.NoError(t, err)
	require.NoError(t, conn.CloseWithError(0, ""))

	assert.Eventually(t, func() bool {
		pc, err := net.ListenPacket("udp", *local.Load())
		if err != nil {
			return false
		}
		_ = pc.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond, "the socket the connection ran on is still open")
}

// udpSinkOrigin records every datagram it receives, in arrival order.
func udpSinkOrigin(t *testing.T) (netip.AddrPort, func() []string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	var mu sync.Mutex
	var got []string
	go func() {
		buf := make([]byte, maxUDPPayload)
		for {
			n, _, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			mu.Lock()
			got = append(got, string(buf[:n]))
			mu.Unlock()
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	addr, err := netip.ParseAddrPort(pc.LocalAddr().String())
	require.NoError(t, err)
	return addr, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

func udpClient(t *testing.T) (*net.UDPConn, netip.AddrPort) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	addr, err := netip.ParseAddrPort(conn.LocalAddr().String())
	require.NoError(t, err)
	return conn, addr
}

func readDatagram(t *testing.T, conn *net.UDPConn, timeout time.Duration) (string, error) {
	t.Helper()
	buf := make([]byte, maxUDPPayload)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(timeout)))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// blockingUDPProxy serves origin with a handler that parks the outbound datagrams of blocked
// until release is closed, and forwards everything else.
func blockingUDPProxy(t *testing.T, origin, blocked netip.AddrPort) (p *Proxy, proxyAddr netip.AddrPort, entered <-chan struct{}, release func()) {
	t.Helper()
	p, err := New()
	require.NoError(t, err)
	in := make(chan struct{}, 1)
	rel := make(chan struct{})
	p.MustAdd[UDP](origin.String(), func(c *DatagramCtx) error {
		if !c.Inbound() && c.Client() == blocked {
			select {
			case in <- struct{}{}:
			default:
			}
			<-rel
		}
		return c.Forward()
	})
	_, addr := startTProxyQUIC(t, p, origin)
	// Registered after the serve helper's Close, so the handler is released before Close waits.
	once := sync.OnceFunc(func() { close(rel) })
	t.Cleanup(once)
	return p, addr, in, once
}

func waitEntered(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the datagram never reached the handler")
	}
}

func sendTo(t *testing.T, conn *net.UDPConn, to netip.AddrPort, payload string) {
	t.Helper()
	_, err := conn.WriteToUDPAddrPort([]byte(payload), to)
	require.NoError(t, err)
}

// A handler parked on one client's datagram does not delay another client on the same socket.
func TestTransparentUDP_ParkedHandlerDoesNotDelayAnotherClient(t *testing.T) {
	origin := udpEchoOrigin(t)
	slow, slowAddr := udpClient(t)
	fast, _ := udpClient(t)
	_, proxyAddr, entered, release := blockingUDPProxy(t, origin, slowAddr)

	sendTo(t, slow, proxyAddr, "slow")
	waitEntered(t, entered)

	sendTo(t, fast, proxyAddr, "fast")
	got, err := readDatagram(t, fast, 2*time.Second)
	require.NoError(t, err, "the other client must be served while the handler is parked")
	assert.Equal(t, "fast", got)

	release()
	got, err = readDatagram(t, slow, 3*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "slow", got)
}

// While the handler is parked, the flow keeps udpQueue datagrams and drops the rest. Another
// client loses nothing.
func TestTransparentUDP_FullQueueDropsForThatClientOnly(t *testing.T) {
	origin, received := udpSinkOrigin(t)
	slow, slowAddr := udpClient(t)
	other, _ := udpClient(t)
	_, proxyAddr, entered, release := blockingUDPProxy(t, origin, slowAddr)

	sendTo(t, slow, proxyAddr, "slow-0")
	waitEntered(t, entered)
	const extra = udpQueue + 10
	for i := 1; i <= extra; i++ {
		sendTo(t, slow, proxyAddr, fmt.Sprintf("slow-%d", i))
	}
	for i := range 10 {
		sendTo(t, other, proxyAddr, fmt.Sprintf("other-%d", i))
	}
	// Long enough for the socket to be read empty before the handler resumes.
	time.Sleep(300 * time.Millisecond)
	release()

	var slowGot, otherGot []string
	require.Eventually(t, func() bool {
		slowGot, otherGot = slowGot[:0], otherGot[:0]
		for _, s := range received() {
			if len(s) > 5 && s[:5] == "slow-" {
				slowGot = append(slowGot, s)
			} else {
				otherGot = append(otherGot, s)
			}
		}
		return len(otherGot) == 10 && len(slowGot) >= 1+udpQueue
	}, 3*time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	slowGot = nil
	for _, s := range received() {
		if len(s) > 5 && s[:5] == "slow-" {
			slowGot = append(slowGot, s)
		}
	}
	assert.Len(t, slowGot, 1+udpQueue, "one in the handler and udpQueue behind it")
	for i, s := range slowGot {
		assert.Equal(t, fmt.Sprintf("slow-%d", i), s, "the queued datagrams keep their order")
	}
}

// The queue is bounded in bytes as well, so large datagrams fill it before udpQueue of them.
func TestTransparentUDP_QueueIsBoundedInBytes(t *testing.T) {
	origin, received := udpSinkOrigin(t)
	slow, slowAddr := udpClient(t)
	_, proxyAddr, entered, release := blockingUDPProxy(t, origin, slowAddr)

	const size = 8000
	fits := udpQueueBytes / size
	require.Less(t, fits, udpQueue)
	payload := func(i int) string {
		b := make([]byte, size)
		copy(b, fmt.Sprintf("big-%d", i))
		return string(b)
	}
	sendTo(t, slow, proxyAddr, payload(0))
	waitEntered(t, entered)
	for i := 1; i <= fits+8; i++ {
		sendTo(t, slow, proxyAddr, payload(i))
	}
	time.Sleep(300 * time.Millisecond)
	release()

	require.Eventually(t, func() bool { return len(received()) >= 1+fits }, 3*time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	got := received()
	assert.Len(t, got, 1+fits)
	for i, s := range got {
		assert.Len(t, s, size)
		assert.Equal(t, payload(i)[:8], s[:8])
	}
}

// Datagrams of one flow are served in the order they arrived, in both directions.
func TestTransparentUDP_FlowKeepsOrder(t *testing.T) {
	origin := udpEchoOrigin(t)
	p, err := New()
	require.NoError(t, err)
	p.MustAdd[UDP](origin.String(), func(c *DatagramCtx) error { return c.Forward() })
	_, proxyAddr := startTProxyQUIC(t, p, origin)
	client, _ := udpClient(t)

	const count = 200
	for i := range count {
		sendTo(t, client, proxyAddr, fmt.Sprintf("%03d", i))
		time.Sleep(100 * time.Microsecond)
	}
	for i := range count {
		got, err := readDatagram(t, client, 3*time.Second)
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("%03d", i), got)
	}
}

// gatedDialer parks the first UDP dial until released, or fails it with err when set, and
// dials the rest itself.
type gatedDialer struct {
	entered chan struct{}
	release chan struct{}
	ctxErr  chan error
	err     error
	calls   atomic.Int64
}

func newGatedDialer(err error) *gatedDialer {
	return &gatedDialer{entered: make(chan struct{}, 1), release: make(chan struct{}), ctxErr: make(chan error, 1), err: err}
}

func (g *gatedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network == "udp" && g.calls.Add(1) == 1 {
		if g.err != nil {
			return nil, g.err
		}
		g.entered <- struct{}{}
		select {
		case <-g.release:
		case <-ctx.Done():
			g.ctxErr <- ctx.Err()
			return nil, ctx.Err()
		}
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func gatedUDPProxy(t *testing.T, origin netip.AddrPort, dialErr error) (*Proxy, netip.AddrPort, *gatedDialer, func()) {
	t.Helper()
	g := newGatedDialer(dialErr)
	tr := DefaultTransport()
	tr.DialContext = g.DialContext
	p, err := New(WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd[UDP](origin.String(), func(c *DatagramCtx) error { return c.Forward() })
	_, addr := startTProxyQUIC(t, p, origin)
	release := sync.OnceFunc(func() { close(g.release) })
	t.Cleanup(release)
	return p, addr, g, release
}

// A dial in flight for one client does not delay another client on the same socket, and the
// datagram that opened the flow is served once the dial returns.
func TestTransparentUDP_DialInFlightDoesNotDelayAnotherClient(t *testing.T) {
	origin := udpEchoOrigin(t)
	_, proxyAddr, g, release := gatedUDPProxy(t, origin, nil)
	slow, _ := udpClient(t)
	fast, _ := udpClient(t)

	sendTo(t, slow, proxyAddr, "slow")
	waitEntered(t, g.entered)

	sendTo(t, fast, proxyAddr, "fast")
	got, err := readDatagram(t, fast, 2*time.Second)
	require.NoError(t, err, "the other client must be served while the dial is in flight")
	assert.Equal(t, "fast", got)

	release()
	got, err = readDatagram(t, slow, 3*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "slow", got)
}

// A flow is a session from its first datagram, and closing it cancels the dial in flight.
func TestTransparentUDP_CloseCancelsTheDialInFlight(t *testing.T) {
	origin := udpEchoOrigin(t)
	p, proxyAddr, g, _ := gatedUDPProxy(t, origin, nil)
	client, _ := udpClient(t)

	sendTo(t, client, proxyAddr, "first")
	waitEntered(t, g.entered)

	var sess *Session
	for s := range p.Sessions() {
		if s.Kind() == KindUDP {
			sess = s
		}
	}
	require.NotNil(t, sess, "the flow must be a session while its dial is in flight")
	require.NoError(t, sess.Close())
	select {
	case err := <-g.ctxErr:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("Close must cancel the dial")
	}

	sendTo(t, client, proxyAddr, "second")
	got, err := readDatagram(t, client, 3*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "second", got)
}

func hasSession(p *Proxy, kind Kind) bool {
	for s := range p.Sessions() {
		if s.Kind() == kind {
			return true
		}
	}
	return false
}

// onlyUDPFlow returns the one datagram flow the proxy serves.
func onlyUDPFlow(t *testing.T, p *Proxy) *udpFlow {
	t.Helper()
	p.srv.mu.Lock()
	defer p.srv.mu.Unlock()
	var found *udpFlow
	for d := range p.srv.quics {
		d.mu.Lock()
		for _, flow := range d.flows {
			for _, u := range flow.udp {
				require.Nil(t, found, "more than one datagram flow")
				found = u
			}
		}
		d.mu.Unlock()
	}
	require.NotNil(t, found, "no datagram flow")
	return found
}

// A datagram arriving behind a parked handler keeps its flow in use, so the idle sweep does
// not reap a flow whose client is sending.
func TestTransparentUDP_ArrivalKeepsTheFlowInUse(t *testing.T) {
	origin := udpEchoOrigin(t)
	slow, slowAddr := udpClient(t)
	p, proxyAddr, entered, _ := blockingUDPProxy(t, origin, slowAddr)

	sendTo(t, slow, proxyAddr, "0")
	waitEntered(t, entered)
	u := onlyUDPFlow(t, p)
	time.Sleep(300 * time.Millisecond)
	sendTo(t, slow, proxyAddr, "1")
	require.Eventually(t, func() bool { return time.Since(u.lastUse()) < 200*time.Millisecond }, 2*time.Second, 10*time.Millisecond)
}

// A failed dial drops the datagram that opened the flow, and the next one dials again.
func TestTransparentUDP_FailedDialIsRetriedByTheNextDatagram(t *testing.T) {
	origin := udpEchoOrigin(t)
	p, proxyAddr, g, _ := gatedUDPProxy(t, origin, errors.New("no route"))
	client, _ := udpClient(t)

	sendTo(t, client, proxyAddr, "first")
	require.Eventually(t, func() bool { return g.calls.Load() == 1 && !hasSession(p, KindUDP) }, 2*time.Second, 5*time.Millisecond)
	sendTo(t, client, proxyAddr, "second")
	got, err := readDatagram(t, client, 3*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "second", got)
	assert.Equal(t, int64(2), g.calls.Load())
}

// gatedResolver parks its first lookup until released and answers every lookup with addr.
type gatedResolver struct {
	addr    netip.Addr
	entered chan struct{}
	release chan struct{}
	ctxErr  chan error
	once    sync.Once
}

func newGatedResolver(addr netip.Addr) *gatedResolver {
	return &gatedResolver{addr: addr, entered: make(chan struct{}, 1), release: make(chan struct{}), ctxErr: make(chan error, 1)}
}

func (r *gatedResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	first := false
	r.once.Do(func() { first = true })
	if first {
		r.entered <- struct{}{}
		select {
		case <-r.release:
		case <-ctx.Done():
			r.ctxErr <- ctx.Err()
			return nil, ctx.Err()
		}
	}
	return []netip.Addr{r.addr}, nil
}

// verifiedQUICProxy serves origin behind a gated resolver, with a QUIC entry on sni and a
// UDP entry on the origin.
func verifiedQUICProxy(t *testing.T, origin netip.AddrPort, sni string) (*Proxy, *CA, *tproxyOriginPacketConn, netip.AddrPort, *gatedResolver, func()) {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	r := newGatedResolver(origin.Addr())
	p, err := New(WithCA(ca), WithNameVerification(VerifyReject), WithNameResolver(r))
	require.NoError(t, err)
	p.MustAdd[QUIC](sni, func(*QUICCtx) error { return nil })
	p.MustAdd[UDP](origin.String(), func(c *DatagramCtx) error { return c.Forward() })
	wrapper, addr := startTProxyQUIC(t, p, origin)
	release := sync.OnceFunc(func() { close(r.release) })
	t.Cleanup(release)
	return p, ca, wrapper, addr, r, release
}

// dialQUICAsync starts a handshake to the proxy and reports its outcome on the returned channel.
func dialQUICAsync(t *testing.T, wrapper *tproxyOriginPacketConn, origin, proxyAddr netip.AddrPort, sni string, ca *CA) <-chan error {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	wrapper.perClient.Store(pc.LocalAddr().String(), origin)
	tr := &quic.Transport{Conn: pc}
	t.Cleanup(func() { _ = tr.Close(); _ = pc.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := tr.Dial(t.Context(), net.UDPAddrFromAddrPort(proxyAddr), &tls.Config{
			ServerName: sni,
			RootCAs:    poolOf(ca),
			NextProtos: []string{"h3"},
			MinVersion: tls.VersionTLS13,
		}, &quic.Config{HandshakeIdleTimeout: 10 * time.Second})
		if err == nil {
			_ = closeNoError(conn)
		}
		done <- err
	}()
	return done
}

func awaitHandshake(t *testing.T, done <-chan error, timeout time.Duration, msg string) {
	t.Helper()
	select {
	case err := <-done:
		require.NoError(t, err, msg)
	case <-time.After(timeout):
		t.Fatal(msg)
	}
}

// A name resolution in flight for one QUIC connection delays neither a datagram nor another
// QUIC connection on the same socket.
func TestTransparentQUIC_ResolutionInFlightDoesNotDelayOtherClients(t *testing.T) {
	origin := udpEchoOrigin(t)
	_, ca, wrapper, proxyAddr, r, release := verifiedQUICProxy(t, origin, "example.test")

	parked := dialQUICAsync(t, wrapper, origin, proxyAddr, "example.test", ca)
	waitEntered(t, r.entered)

	client, _ := udpClient(t)
	sendTo(t, client, proxyAddr, "ping")
	got, err := readDatagram(t, client, 2*time.Second)
	require.NoError(t, err, "a datagram must be served while the resolution is in flight")
	assert.Equal(t, "ping", got)

	other := dialQUICAsync(t, wrapper, origin, proxyAddr, "example.test", ca)
	awaitHandshake(t, other, 3*time.Second, "another connection must be placed while the resolution is in flight")

	release()
	awaitHandshake(t, parked, 5*time.Second, "the parked connection must be placed once the name resolves")
}

// initialDatagram builds a datagram with an Initial long header addressed to dcid.
func initialDatagram(dcid []byte) []byte {
	b := make([]byte, 0, 1200)
	b = append(b, 0xC3, 0, 0, 0, 1, byte(len(dcid)))
	b = append(b, dcid...)
	b = append(b, 0)
	return b[:1200]
}

// The datagrams of a connection being placed wait for its stack, within the pending bounds,
// and none of them rejects it.
func TestQUICDemux_PlacingConnectionKeepsItsDatagrams(t *testing.T) {
	p := testProxy(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	d, err := newQUICDemux(p, fixedOriginPacketConn{pc, netip.MustParseAddrPort("127.0.0.1:4433")})
	require.NoError(t, err)
	t.Cleanup(d.close)

	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	d.mu.Lock()
	conn := d.admitConnLocked(flowKeyOf(client), client, string(dcid), time.Now())
	require.NotNil(t, conn)
	d.setStateLocked(conn, connPlacing)
	d.mu.Unlock()

	for range maxPendingDatagrams + 4 {
		d.dispatch(client, initialDatagram(dcid), false)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	assert.Equal(t, connPlacing, conn.state)
	assert.Len(t, conn.pending, maxPendingDatagrams)
	assert.Equal(t, maxPendingDatagrams*1200, conn.pendingBytes)
	assert.Equal(t, 1, d.sniffing, "a connection being placed still counts against the sniffing cap")
}
