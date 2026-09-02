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
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startQUICFront serves p as an explicit proxy over HTTP/3 on a loopback UDP port, with a
// certificate for 127.0.0.1 minted by ca, and returns the address and the channel ServeQUIC
// reports on.
func startQUICFront(t *testing.T, p *Proxy, ca *CA) (netip.AddrPort, <-chan error) {
	t.Helper()
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		served <- p.ServeQUIC(pc, *cert)
		close(done)
	}()
	t.Cleanup(func() {
		_ = p.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("ServeQUIC did not return after Close")
		}
		select {
		case err := <-served:
			assert.ErrorIs(t, err, ErrProxyClosed)
		default:
		}
		_ = pc.Close()
	})
	return netip.MustParseAddrPort(pc.LocalAddr().String()), served
}

// loopbackUDP opens the client socket of a QUIC test. A dual-stack socket, what quic.DialAddr
// opens, loses datagrams on macOS loopback under load and the handshake waits out its timeout.
func loopbackUDP() (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

// dialQUICFront opens a QUIC connection to the proxy front at addr, trusting ca.
func dialQUICFront(t *testing.T, addr netip.AddrPort, ca *CA) *quic.Conn {
	t.Helper()
	pc, err := loopbackUDP()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(addr), &tls.Config{
		RootCAs:    poolOf(ca),
		ServerName: "127.0.0.1",
		NextProtos: []string{http3.NextProtoH3},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		_ = pc.Close()
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.CloseWithError(0, "")
		_ = pc.Close()
	})
	return conn
}

// streamConn adapts an HTTP/3 request stream to a net.Conn, for a TLS client to run inside a
// CONNECT carried on it.
type streamConn struct {
	*http3.RequestStream
}

func (streamConn) LocalAddr() net.Addr  { return emptyAddr{} }
func (streamConn) RemoteAddr() net.Addr { return emptyAddr{} }

// A request with an absolute target on the HTTP/3 front is a proxy request like any other on
// the TCP front, and the front connection is not a session anyone can list.
func TestServeQUIC_AbsoluteRequest(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin proto=%s host=%s path=%s", r.Proto, r.Host, r.URL.Path)
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)

	var seen atomic.Uint32
	p.MustAdd(originHost(originURL)+"/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		seen.Store(uint32(c.Protocol()))
		return c.Forward()
	})
	front, served := startQUICFront(t, p, ca)

	h3 := &http3.Transport{
		Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			return dialQUICFront(t, front, ca), nil
		},
	}
	defer func() { _ = h3.Close() }()

	req, err := http.NewRequest(http.MethodGet, origin.URL+"/hello", nil)
	require.NoError(t, err)
	resp, err := h3.RoundTrip(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "origin proto=HTTP/1.1 host="+originURL.Host+" path=/hello", string(body))
	assert.Equal(t, HTTP3, Protocol(seen.Load()), "the request reached the proxy over HTTP/3")
	assert.Empty(t, waitForSessions(t, p, 0), "a front connection is addressed to the proxy itself")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, p.Shutdown(ctx))
	select {
	case err := <-served:
		assert.ErrorIs(t, err, ErrProxyClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeQUIC did not return after Shutdown")
	}
}

// A CONNECT on an HTTP/3 stream opens a connection the way one on an HTTP/2 stream does. The
// stream is the connection, terminated and routed like every other.
func TestServeQUIC_ConnectStream(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin host=%s", r.Host)
	}))
	defer origin.Close()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd(originHost(originURL)+"/*{any}", forwardHandler)
	front, _ := startQUICFront(t, p, ca)

	h3 := &http3.Transport{}
	defer func() { _ = h3.Close() }()
	cc := h3.NewClientConn(dialQUICFront(t, front, ca))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rstr, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodConnect, "https://"+originURL.Host, nil)
	require.NoError(t, err)
	require.NoError(t, rstr.SendRequestHeader(req))
	resp, err := rstr.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "the proxy accepts the CONNECT stream")

	tunnel := tls.Client(streamConn{rstr}, &tls.Config{
		RootCAs:    ca.CertPool(),
		ServerName: originURL.Hostname(),
		MinVersion: tls.VersionTLS12,
	})
	inner := http.Client{Transport: &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return tunnel, nil },
	}}
	got, err := inner.Get(origin.URL + "/foo")
	require.NoError(t, err)
	body, _ := io.ReadAll(got.Body)
	_ = got.Body.Close()
	assert.Equal(t, "origin host="+originURL.Host, string(body))

	sess := waitForSessions(t, p, 1)[0]
	assert.Equal(t, KindHTTP, sess.Kind())
	assert.Equal(t, HTTP11, sess.Protocol(), "the tunnel carries HTTP/1.1 inside, whatever the stream that opened it")
	assert.Equal(t, originURL.Hostname(), sess.Target().Host)
	assert.Equal(t, netip.MustParseAddrPort(originURL.Host), sess.Upstream())
	_ = tunnel.Close()
	waitForSessions(t, p, 0)
}

func TestProxyTarget_PortIsCanonical(t *testing.T) {
	u, err := url.Parse("http://example.test:0080/x")
	require.NoError(t, err)
	target, err := proxyTarget(&http.Request{URL: u, Host: u.Host, ProtoMajor: 1})
	require.NoError(t, err)
	assert.Equal(t, "80", target.Port)

	target, err = proxyTarget(&http.Request{URL: &url.URL{Path: "/x"}, Host: "example.test:08080", ProtoMajor: 2})
	require.NoError(t, err)
	assert.Equal(t, "8080", target.Port)

	_, err = proxyTarget(&http.Request{URL: &url.URL{Path: "/x"}, Host: "example.test:70000", ProtoMajor: 2})
	require.Error(t, err)
}
