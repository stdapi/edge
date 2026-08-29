// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upgradeOrigin answers an Upgrade request with 101 and then echoes whatever it is sent,
// which is the shape every WebSocket handshake ends up in once the framing is stripped.
func upgradeOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestProxy_ProtocolUpgrade(t *testing.T) {
	origin := upgradeOrigin(t)
	originURL, _ := url.Parse(origin.URL)

	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithIntercept(originHost(originURL)), WithTransport(tr))
	require.NoError(t, err)

	var sawUpgrade string
	p.MustHandle([]string{http.MethodGet}, originHost(originURL)+"/ws", func(c *Context) (*http.Response, error) {
		sawUpgrade = c.Request().Header.Get("Upgrade")
		return c.Forward()
	})

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
