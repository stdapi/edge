// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upgradeOrigin answers an Upgrade request with 101 and then echoes whatever it is sent,
// which is the shape every WebSocket handshake ends up in once the framing is stripped.
func upgradeOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(upgradeHandler(t))
	t.Cleanup(srv.Close)
	return srv
}

// plainUpgradeOrigin is upgradeOrigin without TLS, which is what a redirected plaintext
// connection and an absolute-form proxy request reach.
func plainUpgradeOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(upgradeHandler(t))
	t.Cleanup(srv.Close)
	return srv
}

func upgradeHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "echo") {
			http.Error(w, "expected an upgrade", http.StatusBadRequest)
			return
		}

		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("origin hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()

		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		if err := brw.Flush(); err != nil {
			return
		}
		_, _ = io.Copy(conn, brw)
	}
}

func TestProxy_ProtocolUpgrade(t *testing.T) {
	origin := upgradeOrigin(t)
	originURL, _ := url.Parse(origin.URL)

	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)

	var sawUpgrade string
	// Past the 101 the connection is a byte stream, and a stream entry is what serves it.
	p.MustAdd[TCP](originHost(originURL), relayStream)
	p.MustAdd(originHost(originURL)+"/ws", func(c *HTTPCtx) (*http.Response, error) {
		sawUpgrade = c.Request().Header.Get("Upgrade")
		return c.Forward()
	}, WithMethods(http.MethodGet))

	addr := startProxy(t, p)

	// Reaching the tunnel by hand: an upgrade is not something an http.Client exposes.
	raw, err := dialThroughProxy(t, addr, originURL.Host, ca)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	_, err = raw.Write([]byte("GET /ws HTTP/1.1\r\nHost: " + originURL.Host + "\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n"))
	require.NoError(t, err)

	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	assert.Equal(t, "echo", resp.Header.Get("Upgrade"))
	assert.Equal(t, "echo", sawUpgrade, "the handler must still see the upgrade request")

	_, err = raw.Write([]byte("ping\n"))
	require.NoError(t, err)

	line, err := br.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "ping\n", line, "bytes must flow both ways once upgraded")
}

// dialThroughProxy opens a CONNECT tunnel to authority and completes the TLS handshake the
// proxy intercepts, returning the plaintext side of it.
func dialThroughProxy(t *testing.T, proxyAddr, authority string, ca *CA) (*tls.Conn, error) {
	t.Helper()

	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}

	if _, err := raw.Write([]byte("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n")); err != nil {
		return nil, err
	}
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Zero(t, br.Buffered(), "the proxy must not send anything past the CONNECT response")

	host, _ := splitHostPort(authority)
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: host,
		RootCAs:    ca.CertPool(),
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

const upgradeRequest = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n"

// A redirected plaintext connection is decided request by request and is never reported. The
// pipe an upgrade leaves on it is, because past the 101 nothing on it is routed again.
func TestUpgrade_TransparentPlaintextPipeIsListedAndClosed(t *testing.T) {
	origin := plainUpgradeOrigin(t)
	originURL, _ := url.Parse(origin.URL)
	originAddr, err := netip.ParseAddrPort(originURL.Host)
	require.NoError(t, err)

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)
	p := testProxy(t, WithTransport(tr))
	p.MustAdd[TCP]("ws.example.test", relayStream)
	p.MustAdd("ws.example.test/ws", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	}, WithMethods(http.MethodGet))

	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
		return originAddr, nil
	})

	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	_, err = fmt.Fprintf(raw, upgradeRequest, "/ws", "ws.example.test")
	require.NoError(t, err)

	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, KindTCP, sessions[0].Kind())
	assert.Equal(t, "ws.example.test", sessions[0].Target().Host)
	assert.True(t, sessions[0].Transparent())

	require.NoError(t, sessions[0].Close())
	_, _ = raw.Write([]byte("ping\n"))
	_, err = br.ReadString('\n')
	assert.Error(t, err, "the pipe is cut, nothing echoes back")
	waitForSessions(t, p, 0)
}

// A request routes on its Host header, which on an intercepted connection can differ from the
// CONNECT authority. Without a session of its own the pipe would hide behind a connection the
// sweep still accepts.
func TestUpgrade_HostDivergesFromTheConnectAuthority(t *testing.T) {
	origin := upgradeOrigin(t)
	originURL, _ := url.Parse(origin.URL)

	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)
	tr.InsecureSkipVerify = true

	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd("a.example.test/*{rest}", noopHandler)
	p.MustAdd[TCP]("b.example.test", relayStream)
	p.MustAdd("b.example.test/ws", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	}, WithMethods(http.MethodGet))

	raw, err := dialThroughProxy(t, startProxy(t, p), "a.example.test:443", ca)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	_, err = fmt.Fprintf(raw, upgradeRequest, "/ws", "b.example.test")
	require.NoError(t, err)

	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	// The connection and the pipe, each reporting the authority it talks to.
	sessions := waitForSessions(t, p, 2)
	hosts := make([]string, 0, 2)
	for _, s := range sessions {
		hosts = append(hosts, s.Target().Host)
	}
	slices.Sort(hosts)
	assert.Equal(t, []string{"a.example.test", "b.example.test"}, hosts)

	// The pipe is a stream past the 101, so what admits it is the stream entry on the host
	// its request named, not the one the connection was opened for.
	_, err = p.Delete[TCP]("b.example.test")
	require.NoError(t, err)

	var closed int
	for s := range p.Sessions() {
		if !p.Admits(s.Target(), s.Kind()) {
			require.NoError(t, s.Close())
			closed++
		}
	}
	assert.Equal(t, 1, closed, "the pipe is swept while its connection stays allowed")
	assert.Equal(t, true, p.Admits(target("a.example.test:443"), KindHTTP))
}

// The tree can change while the upstream is answering. The pipe is registered before the 101
// reaches the client, so a refusal is an ordinary status and not a granted upgrade torn down.
func TestUpgrade_RefusedWhenTheRouteGoesAwayFirst(t *testing.T) {
	origin := upgradeOrigin(t)
	originURL, _ := url.Parse(origin.URL)
	pattern := originHost(originURL) + "/ws"

	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd[TCP](originHost(originURL), relayStream)
	p.MustAdd(pattern, func(c *HTTPCtx) (*http.Response, error) {
		resp, ferr := c.Forward()
		if ferr != nil {
			return nil, ferr
		}
		// Between the upstream 101 and the splice, which is the window the re-check covers.
		// What the 101 switches to is a stream, so withdrawing the stream entry is what
		// leaves the upgrade with nothing to serve it.
		if _, derr := p.Delete[TCP](originHost(originURL)); derr != nil {
			return nil, derr
		}
		_, derr := p.Delete[HTTP](pattern, WithMethods(http.MethodGet))
		return resp, derr
	}, WithMethods(http.MethodGet))

	raw, err := dialThroughProxy(t, startProxy(t, p), originURL.Host, ca)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	_, err = fmt.Fprintf(raw, upgradeRequest, "/ws", originURL.Host)
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(raw), nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "the client never sees the 101")
	// The refusal is written before the hijack, so the client reads an ordinary status and
	// keeps its connection. What matters is that no pipe was left behind: the one session is
	// the terminated connection itself.
	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, KindHTTP, sessions[0].Kind())
}

// A hijacked connection is one http.Server neither closes nor waits for, so without the pipe
// being tracked a shutdown would return while it is still relaying.
func TestUpgrade_CloseEndsAPipeOnAFrontConnection(t *testing.T) {
	origin := plainUpgradeOrigin(t)
	originURL, _ := url.Parse(origin.URL)

	p := testProxy(t)
	p.MustAdd[TCP](originHost(originURL), relayStream)
	p.MustAdd(originHost(originURL)+"/ws", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	}, WithMethods(http.MethodGet))

	raw, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	// An absolute-form request, so no CONNECT and no session for the connection it arrives on.
	_, err = fmt.Fprintf(raw, upgradeRequest, origin.URL+"/ws", originURL.Host)
	require.NoError(t, err)

	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, originHost(originURL), sessions[0].Target().Host)
	assert.False(t, sessions[0].Transparent())

	require.NoError(t, p.Close())
	_, _ = raw.Write([]byte("ping\n"))
	_, err = br.ReadString('\n')
	assert.Error(t, err, "Close must reach a pipe http.Server no longer owns")
}
