// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fox-toolkit/edge/internal/h2tunnel"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	// proxyConnectTimeout bounds the CONNECT and CONNECT-UDP exchange with a proxy.
	proxyConnectTimeout = time.Minute
	// proxyResponseBytes bounds the response head a proxy may answer a CONNECT with.
	proxyResponseBytes = http.DefaultMaxHeaderBytes
	// proxyKeepAlive keeps the connection to a proxy open while its tunnels are silent.
	proxyKeepAlive = 10 * time.Second
	// proxyRetry is how long the dialer remembers a failed dial to a proxy, over HTTP/3 or
	// over TCP.
	proxyRetry = 5 * time.Minute
)

var (
	// errTunnelEnded ends the reads of a tunnel once its stream or the connection to the
	// proxy has ended.
	errTunnelEnded = errors.New("edge: tunnel ended")
	errRefused     = errors.New("refused")
)

// upstreamDialer opens every connection the proxy makes upstream, through the proxy
// [Transport.Proxy] selects when it selects one.
type upstreamDialer struct {
	t       *Transport
	h3      *http3.Transport
	conns   map[string]*h3ProxyConn
	h2conns map[string]*h2tunnel.Conn
	// noH3 and noTCP record until when a failed dial to a proxy, over HTTP/3 or over TCP, is
	// remembered, and noH2 until when HTTP/2 is not tried for a CONNECT-UDP, for lack of
	// extended CONNECT.
	noH3, noTCP, noH2 map[string]time.Time
	// draining holds the HTTP/2 connections replaced after a GOAWAY while their last tunnels
	// end, so that close reaches them.
	draining []*h2tunnel.Conn
	mu       sync.Mutex
	// closed refuses a proxy connection opened after close, so none outlives the forwarder.
	closed bool
}

func newUpstreamDialer(t *Transport) *upstreamDialer {
	return &upstreamDialer{
		t:       t,
		h3:      &http3.Transport{EnableDatagrams: true, DisableCompression: true},
		conns:   make(map[string]*h3ProxyConn),
		h2conns: make(map[string]*h2tunnel.Conn),
		noH3:    make(map[string]time.Time),
		noTCP:   make(map[string]time.Time),
		noH2:    make(map[string]time.Time),
	}
}

func (u *upstreamDialer) close() {
	u.mu.Lock()
	u.closed = true
	conns, h2conns, draining := u.conns, u.h2conns, u.draining
	u.conns, u.h2conns, u.draining = nil, nil, nil
	u.mu.Unlock()
	for _, cc := range conns {
		_ = cc.CloseWithError(0, "")
	}
	for _, cc := range h2conns {
		_ = cc.Close()
	}
	for _, cc := range draining {
		_ = cc.Close()
	}
	_ = u.h3.Close()
}

// proxyFor returns the proxy selected for a connection to addr, nil for a direct one. scheme
// is https for TLS and QUIC and http for the clear.
func (u *upstreamDialer) proxyFor(addr, scheme string) (*url.URL, error) {
	if u.t.Proxy == nil {
		return nil, nil
	}
	req := &http.Request{URL: &url.URL{Scheme: scheme, Host: addr}, Host: addr, Header: make(http.Header)}
	return u.t.Proxy(req)
}

// dial opens a connection to addr on network, through the proxy selected for it when there
// is one.
func (u *upstreamDialer) dial(ctx context.Context, network, addr, scheme string) (net.Conn, error) {
	proxy, err := u.proxyFor(addr, scheme)
	if err != nil {
		return nil, fmt.Errorf("edge: select a proxy for %s: %w", addr, err)
	}
	if proxy == nil {
		return u.t.dialer()(ctx, network, addr)
	}
	switch proxy.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("edge: dial %s through %s: proxy scheme %q is not supported", addr, proxy.Redacted(), proxy.Scheme)
	}
	switch network {
	case "tcp":
		return u.connect(ctx, proxy, addr)
	case "udp":
		return u.connectUDP(ctx, proxy, addr)
	}
	return nil, fmt.Errorf("edge: dial %s %s through %s: network not supported", network, addr, proxy.Redacted())
}

// dialQUIC opens a QUIC connection to addr on a socket dial returns. The socket is closed when
// the connection ends.
func (u *upstreamDialer) dialQUIC(ctx context.Context, addr string, tlsCfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
	sock, err := u.dial(ctx, "udp", addr, "https")
	if err != nil {
		return nil, err
	}
	return quicOn(ctx, sock, addr, tlsCfg, qcfg)
}

// quicOn opens a QUIC connection on a connected socket and ties the socket to it.
func quicOn(ctx context.Context, sock net.Conn, addr string, tlsCfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
	if sock.RemoteAddr() == nil {
		_ = sock.Close()
		return nil, fmt.Errorf("edge: dial %s: the dialer returned a socket with no peer", addr)
	}
	if _, ok := sock.(*connectUDPConn); ok {
		// Each packet goes inside one QUIC datagram of the proxy connection, so the packets
		// stay at the size every path accepts.
		qcfg = qcfg.Clone()
		qcfg.InitialPacketSize = 1200
		qcfg.DisablePathMTUDiscovery = true
	}
	tr := &quic.Transport{Conn: packetConnOf(sock)}
	// The socket goes first, so the read loop the transport waits on ends whatever the socket
	// does with a read deadline.
	release := func() {
		_ = sock.Close()
		_ = tr.Close()
	}
	conn, err := tr.Dial(ctx, sock.RemoteAddr(), tlsCfg, qcfg)
	if err != nil {
		release()
		return nil, err
	}
	context.AfterFunc(conn.Context(), release)
	return conn, nil
}

// proxyAddr returns the host:port a proxy URL is reached at.
func proxyAddr(proxy *url.URL) string {
	if proxy.Port() != "" {
		return proxy.Host
	}
	return joinHostPort(proxy.Hostname(), defaultPort(proxy.Scheme))
}

// proxyAuthorization returns the Proxy-Authorization value the credentials of a proxy URL
// make, or an empty string without credentials.
func proxyAuthorization(proxy *url.URL) string {
	if proxy.User == nil {
		return ""
	}
	pass, _ := proxy.User.Password()
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(proxy.User.Username()+":"+pass))
}

// connect opens a TCP connection to addr with a CONNECT to the proxy. The CONNECT goes on
// the connection the dialer has to the proxy, HTTP/3 or HTTP/2, and over TCP otherwise, where
// TLS negotiates HTTP/2 or HTTP/1.1, and a proxy whose dial over TCP failed is dialed over
// HTTP/3 for proxyRetry. A refusal the proxy answers is final.
func (u *upstreamDialer) connect(ctx context.Context, proxy *url.URL, addr string) (net.Conn, error) {
	retried := false
	for {
		conn, pooled, err := u.connectOnce(ctx, proxy, addr)
		if retryPooled(ctx, err, pooled, retried) {
			retried = true
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("dial %s through %s: %w", addr, proxy.Redacted(), err)
		}
		return conn, nil
	}
}

// retryPooled reports whether a tunnel is opened again after failing on a pooled connection,
// one that was gone, going away or full when the tunnel was opened on it, so the proxy
// received nothing of the tunnel.
func retryPooled(ctx context.Context, err error, pooled, retried bool) bool {
	return err != nil && pooled && !retried && ctx.Err() == nil && !errors.Is(err, errRefused)
}

// connectOnce reports whether the tunnel went on a pooled connection.
func (u *upstreamDialer) connectOnce(ctx context.Context, proxy *url.URL, addr string) (net.Conn, bool, error) {
	if proxy.Scheme == "https" {
		if cc := u.h3Conn(proxy); cc != nil {
			conn, err := connectOnH3(ctx, cc, proxy, addr)
			return conn, true, err
		}
		if cc := u.h2Conn(proxy); cc != nil {
			conn, err := connectOnH2(ctx, cc, proxy, addr)
			return conn, true, err
		}
	}
	var h3err error
	if proxy.Scheme == "https" && u.deferred(u.noTCP, proxy) && !u.deferred(u.noH3, proxy) {
		conn, dialed, err := u.connectH3(ctx, proxy, addr)
		if dialed || ctx.Err() != nil {
			return conn, false, err
		}
		h3err = err
	}
	nc, err := u.t.dialer()(ctx, "tcp", proxyAddr(proxy))
	if err != nil {
		err = fmt.Errorf("dial proxy %s: %w", proxy.Redacted(), err)
		if proxy.Scheme == "https" && h3err == nil && ctx.Err() == nil && !u.deferred(u.noH3, proxy) {
			u.deferVersion(u.noTCP, proxy)
			conn, dialed, oerr := u.connectH3(ctx, proxy, addr)
			if dialed {
				return conn, false, oerr
			}
			return nil, false, errors.Join(err, oerr)
		}
		if h3err != nil {
			err = errors.Join(h3err, err)
		}
		return nil, false, err
	}
	conn, err := overTCP(ctx, u, nc, proxy, true,
		func(conn net.Conn) (net.Conn, error) { return connectOn(conn, proxy, addr) },
		func(cc *h2tunnel.Conn) (net.Conn, error) { return connectOnH2(ctx, cc, proxy, addr) })
	return conn, false, err
}

// connectH3 opens the tunnel over HTTP/3 and reports whether the dial to the proxy succeeded.
func (u *upstreamDialer) connectH3(ctx context.Context, proxy *url.URL, addr string) (net.Conn, bool, error) {
	cc, err := u.proxyConn(ctx, proxy)
	if err != nil {
		if ctx.Err() == nil {
			u.deferVersion(u.noH3, proxy)
		}
		return nil, false, fmt.Errorf("over HTTP/3: %w", err)
	}
	conn, err := connectOnH3(ctx, cc, proxy, addr)
	return conn, true, err
}

// overTCP opens a tunnel on nc, a connection to the proxy, with onH2 when TLS negotiates h2
// and with h1 otherwise.
func overTCP[T any](ctx context.Context, u *upstreamDialer, nc net.Conn, proxy *url.URL, h2 bool, h1 func(net.Conn) (T, error), onH2 func(*h2tunnel.Conn) (T, error)) (T, error) {
	var zero T
	_ = nc.SetDeadline(time.Now().Add(proxyConnectTimeout))
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	conn := nc
	if proxy.Scheme == "https" {
		cfg := u.t.upstreamTLSConfig()
		cfg.ServerName = proxy.Hostname()
		cfg.NextProtos = []string{"http/1.1"}
		if h2 {
			cfg.NextProtos = []string{"h2", "http/1.1"}
		}
		tc := tls.Client(nc, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			stop()
			_ = nc.Close()
			return zero, fmt.Errorf("tls handshake: %w", err)
		}
		if tc.ConnectionState().NegotiatedProtocol == "h2" {
			// The connection outlives this tunnel, so the dial's cancellation and deadline
			// come off it here, and a tunnel refused on it leaves it shared.
			if !stop() {
				_ = nc.Close()
				return zero, ctx.Err()
			}
			_ = nc.SetDeadline(time.Time{})
			cc, err := u.shareH2Conn(proxy, tc)
			if err != nil {
				return zero, err
			}
			return onH2(cc)
		}
		conn = tc
	}
	v, err := h1(conn)
	if !stop() {
		_ = conn.Close()
		return zero, ctx.Err()
	}
	if err != nil {
		_ = conn.Close()
		return zero, err
	}
	_ = nc.SetDeadline(time.Time{})
	return v, nil
}

// connectOn sends a CONNECT to the proxy on conn and returns the connection once the proxy
// answered 200, with the bytes the proxy sent behind its answer.
func connectOn(conn net.Conn, proxy *url.URL, addr string) (net.Conn, error) {
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: make(http.Header)}
	if auth := proxyAuthorization(proxy); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}
	br := bufio.NewReader(io.LimitReader(conn, proxyResponseBytes))
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The body is left unread, the caller closes the connection.
		return nil, fmt.Errorf("CONNECT %w with %s", errRefused, resp.Status)
	}
	if br.Buffered() == 0 {
		return conn, nil
	}
	// A peer that sends first, an SMTP banner for instance, may already be behind the
	// response.
	early, _ := br.Peek(br.Buffered())
	return bufferedConn{Conn: conn, r: io.MultiReader(bytes.NewReader(slices.Clone(early)), conn)}, nil
}

// connectOnH2 opens the tunnel as a CONNECT stream on the HTTP/2 connection to the proxy.
func connectOnH2(ctx context.Context, cc *h2tunnel.Conn, proxy *url.URL, addr string) (net.Conn, error) {
	ctx, done := context.WithTimeout(ctx, proxyConnectTimeout)
	defer done()
	var header http.Header
	if auth := proxyAuthorization(proxy); auth != "" {
		header = http.Header{"Proxy-Authorization": {auth}}
	}
	str, resp, err := cc.Open(ctx, h2tunnel.Request{Authority: addr, Header: header})
	if err != nil {
		return nil, fmt.Errorf("CONNECT: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = str.Close()
		return nil, fmt.Errorf("CONNECT %w with %d %s", errRefused, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return str, nil
}

// connectOnH3 opens the tunnel as a CONNECT stream on the HTTP/3 connection to the proxy.
func connectOnH3(ctx context.Context, cc *h3ProxyConn, proxy *url.URL, addr string) (net.Conn, error) {
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: addr}, Host: addr, Header: make(http.Header)}
	if auth := proxyAuthorization(proxy); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	str, err := requestOn(ctx, cc.ClientConn, req, "CONNECT")
	if err != nil {
		return nil, err
	}
	return newH3StreamConn(str, cc.local, cc.remote), nil
}

// connectUDP opens a UDP tunnel to addr with a CONNECT-UDP to the proxy, RFC 9298. HTTP/3
// comes first, and a proxy whose dial over HTTP/3 failed is dialed over TCP for proxyRetry.
// A refusal the proxy answers is final.
func (u *upstreamDialer) connectUDP(ctx context.Context, proxy *url.URL, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("edge: dial udp %q: %w", addr, err)
	}
	var h3err error
	if proxy.Scheme == "https" && !u.deferred(u.noH3, proxy) {
		cc, cerr := u.proxyConn(ctx, proxy)
		switch {
		case cerr == nil:
			if s := cc.Settings(); s.EnableDatagrams && s.EnableExtendedConnect {
				pipe, oerr := openTunnelOn(ctx, cc.ClientConn, proxy, host, port)
				if oerr != nil {
					return nil, fmt.Errorf("dial udp %s through %s: %w", addr, proxy.Redacted(), oerr)
				}
				return &connectUDPConn{pipe: pipe, remote: tunnelTarget(addr)}, nil
			}
			// The connection stays for the CONNECT tunnels.
			h3err = errors.New("over HTTP/3: the proxy does not support CONNECT-UDP")
		case ctx.Err() != nil:
			return nil, fmt.Errorf("dial proxy %s: %w", proxy.Redacted(), cerr)
		default:
			u.deferVersion(u.noH3, proxy)
			h3err = fmt.Errorf("over HTTP/3: %w", cerr)
		}
	}
	pipe, err := u.connectUDPStream(ctx, proxy, host, port)
	if err != nil {
		if h3err != nil {
			err = errors.Join(h3err, err)
		}
		return nil, fmt.Errorf("dial udp %s through %s: %w", addr, proxy.Redacted(), err)
	}
	return &connectUDPConn{pipe: pipe, remote: tunnelTarget(addr)}, nil
}

func (u *upstreamDialer) deferred(m map[string]time.Time, proxy *url.URL) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	until, ok := m[proxyAddr(proxy)]
	return ok && time.Now().Before(until)
}

func (u *upstreamDialer) deferVersion(m map[string]time.Time, proxy *url.URL) {
	u.mu.Lock()
	defer u.mu.Unlock()
	m[proxyAddr(proxy)] = time.Now().Add(proxyRetry)
}

func openTunnelOn(ctx context.Context, cc *http3.ClientConn, proxy *url.URL, host, port string) (tunnelPipe, error) {
	target, err := url.Parse(fmt.Sprintf("https://%s%s%s/%s/", proxyAddr(proxy), connectUDPPath, url.PathEscape(host), port))
	if err != nil {
		return nil, err
	}
	req := &http.Request{Method: http.MethodConnect, Proto: connectUDPUpgrade, URL: target, Host: target.Host, Header: make(http.Header)}
	req.Header.Set(http3.CapsuleProtocolHeader, "?1")
	if auth := proxyAuthorization(proxy); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	str, err := requestOn(ctx, cc, req, "CONNECT-UDP")
	if err != nil {
		return nil, err
	}
	pipe := newDatagramPipe(str, quic.StreamErrorCode(http3.ErrCodeNoError))
	pipe.run(func() { _ = pipe.close() })
	return pipe, nil
}

// requestOn sends req on a new stream of the HTTP/3 connection to a proxy and returns the
// stream once the proxy answered 200, the errors prefixed with verb.
func requestOn(ctx context.Context, cc *http3.ClientConn, req *http.Request, verb string) (*http3.RequestStream, error) {
	ctx, done := context.WithTimeout(ctx, proxyConnectTimeout)
	defer done()
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	cancel := func() {
		str.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	}
	stop := context.AfterFunc(ctx, cancel)
	if werr := str.SendRequestHeader(req); werr != nil {
		stop()
		cancel()
		return nil, fmt.Errorf("write %s: %w", verb, werr)
	}
	resp, err := str.ReadResponse()
	if !stop() {
		return nil, ctx.Err()
	}
	if err != nil {
		cancel()
		return nil, fmt.Errorf("read %s response: %w", verb, err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		return nil, fmt.Errorf("%s %w with %d %s", verb, errRefused, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return str, nil
}

// connectUDPStream opens a tunnel over TCP, an extended CONNECT on the HTTP/2 connection to
// the proxy when TLS negotiates h2, a GET with an Upgrade over HTTP/1.1 otherwise, RFC 9298
// section 3.2, and always over HTTP/1.1 on a plain http proxy.
func (u *upstreamDialer) connectUDPStream(ctx context.Context, proxy *url.URL, host, port string) (tunnelPipe, error) {
	retried := false
	for {
		h2 := proxy.Scheme == "https" && !u.deferred(u.noH2, proxy)
		var pipe tunnelPipe
		var err error
		pooled := false
		if cc := u.h2Conn(proxy); h2 && cc != nil {
			pooled = true
			pipe, err = openTunnelOnH2(ctx, cc, proxy, host, port)
		} else {
			pipe, err = u.dialTunnel(ctx, proxy, host, port, h2)
		}
		switch {
		case errors.Is(err, h2tunnel.ErrExtendedConnect):
			// An HTTP/2 proxy without extended CONNECT may still upgrade an HTTP/1.1
			// connection, so the next one offers nothing else. The connection stays for the
			// CONNECT tunnels.
			u.deferVersion(u.noH2, proxy)
			continue
		case retryPooled(ctx, err, pooled, retried):
			retried = true
			continue
		}
		return pipe, err
	}
}

func (u *upstreamDialer) dialTunnel(ctx context.Context, proxy *url.URL, host, port string, h2 bool) (tunnelPipe, error) {
	nc, err := u.t.dialer()(ctx, "tcp", proxyAddr(proxy))
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxy.Redacted(), err)
	}
	return overTCP(ctx, u, nc, proxy, h2,
		func(conn net.Conn) (tunnelPipe, error) { return upgradeOn(conn, proxy, host, port) },
		func(cc *h2tunnel.Conn) (tunnelPipe, error) { return openTunnelOnH2(ctx, cc, proxy, host, port) })
}

func (u *upstreamDialer) h2Conn(proxy *url.URL) *h2tunnel.Conn {
	u.mu.Lock()
	defer u.mu.Unlock()
	if cc := u.h2conns[proxyAddr(proxy)]; cc != nil && cc.CanOpen() {
		return cc
	}
	return nil
}

// shareH2Conn records the HTTP/2 connection on tc for the next tunnels. When another tunnel
// recorded one first, that one is returned and tc closed.
func (u *upstreamDialer) shareH2Conn(proxy *url.URL, tc net.Conn) (*h2tunnel.Conn, error) {
	cc, err := h2tunnel.Client(tc, proxyKeepAlive)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxy.Redacted(), err)
	}
	key := proxyAddr(proxy)
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		_ = cc.Close()
		return nil, net.ErrClosed
	}
	if other := u.h2conns[key]; other != nil {
		if other.CanOpen() {
			_ = cc.Close()
			return other, nil
		}
		other.Retire()
		u.draining = slices.DeleteFunc(u.draining, func(d *h2tunnel.Conn) bool { return d.Err() != nil })
		u.draining = append(u.draining, other)
	}
	u.h2conns[key] = cc
	return cc, nil
}

func openTunnelOnH2(ctx context.Context, cc *h2tunnel.Conn, proxy *url.URL, host, port string) (tunnelPipe, error) {
	ctx, done := context.WithTimeout(ctx, proxyConnectTimeout)
	defer done()
	header := http.Header{http3.CapsuleProtocolHeader: {"?1"}}
	if auth := proxyAuthorization(proxy); auth != "" {
		header.Set("Proxy-Authorization", auth)
	}
	str, resp, err := cc.Open(ctx, h2tunnel.Request{
		Protocol:  connectUDPUpgrade,
		Scheme:    "https",
		Authority: proxyAddr(proxy),
		Path:      connectUDPPath + url.PathEscape(host) + "/" + port + "/",
		Header:    header,
	})
	if err != nil {
		return nil, fmt.Errorf("CONNECT-UDP: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = str.Close()
		return nil, fmt.Errorf("CONNECT-UDP %w with %d %s", errRefused, resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	return newCapsulePipe(str, bufio.NewReader(str)), nil
}

func upgradeOn(conn net.Conn, proxy *url.URL, host, port string) (tunnelPipe, error) {
	target, err := url.Parse(fmt.Sprintf("%s://%s%s%s/%s/", proxy.Scheme, proxyAddr(proxy), connectUDPPath, url.PathEscape(host), port))
	if err != nil {
		return nil, err
	}
	req := &http.Request{Method: http.MethodGet, URL: target, Host: target.Host, Header: make(http.Header)}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", connectUDPUpgrade)
	req.Header.Set(http3.CapsuleProtocolHeader, "?1")
	if auth := proxyAuthorization(proxy); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	if werr := req.WriteProxy(conn); werr != nil {
		return nil, fmt.Errorf("write CONNECT-UDP: %w", werr)
	}
	br := bufio.NewReader(io.LimitReader(conn, proxyResponseBytes))
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("read CONNECT-UDP response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		// The body is left unread, the caller closes the connection.
		return nil, fmt.Errorf("CONNECT-UDP %w with %s", errRefused, resp.Status)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), connectUDPUpgrade) {
		return nil, errors.New("CONNECT-UDP upgraded to " + resp.Header.Get("Upgrade"))
	}
	// Capsules the proxy sent right behind the 101 may already be in the buffer.
	early, _ := br.Peek(br.Buffered())
	return newCapsulePipe(conn, bufio.NewReader(io.MultiReader(bytes.NewReader(slices.Clone(early)), conn))), nil
}

// h3ProxyConn is the HTTP/3 connection to a proxy. The tunnels on it report the addresses of
// its QUIC connection.
type h3ProxyConn struct {
	*http3.ClientConn
	local, remote net.Addr
}

// proxyConn returns the HTTP/3 connection to a proxy, opened on the first tunnel and shared
// by every later one until it ends.
func (u *upstreamDialer) proxyConn(ctx context.Context, proxy *url.URL) (*h3ProxyConn, error) {
	key := proxyAddr(proxy)
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil, net.ErrClosed
	}
	if cc := u.h3Locked(key); cc != nil {
		u.mu.Unlock()
		return cc, nil
	}
	u.mu.Unlock()

	cc, err := u.openProxyConn(ctx, proxy, key)
	if err != nil {
		return nil, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		_ = cc.CloseWithError(0, "")
		return nil, net.ErrClosed
	}
	if other := u.h3Locked(key); other != nil {
		_ = cc.CloseWithError(0, "")
		return other, nil
	}
	u.conns[key] = cc
	return cc, nil
}

func (u *upstreamDialer) h3Conn(proxy *url.URL) *h3ProxyConn {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.h3Locked(proxyAddr(proxy))
}

// h3Locked is h3Conn with u.mu held.
func (u *upstreamDialer) h3Locked(key string) *h3ProxyConn {
	if cc := u.conns[key]; cc != nil && cc.Context().Err() == nil {
		return cc
	}
	return nil
}

func (u *upstreamDialer) openProxyConn(ctx context.Context, proxy *url.URL, addr string) (*h3ProxyConn, error) {
	// The proxy itself is dialed directly, it cannot be reached through itself.
	sock, err := u.t.dialer()(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	cfg := u.t.upstreamTLSConfig()
	cfg.MinVersion = tls.VersionTLS13
	cfg.ServerName = proxy.Hostname()
	cfg.NextProtos = []string{http3.NextProtoH3}
	qc, err := quicOn(ctx, sock, addr, cfg, &quic.Config{
		EnableDatagrams:      true,
		HandshakeIdleTimeout: u.t.TLSHandshakeTimeout,
		MaxIdleTimeout:       u.t.IdleConnTimeout,
		KeepAlivePeriod:      proxyKeepAlive,
		// The 1200 byte Initial of an inner QUIC connection goes inside one datagram, which
		// the default initial packet size does not leave room for.
		InitialPacketSize: 1350,
	})
	if err != nil {
		return nil, err
	}
	cc := u.h3.NewClientConn(qc)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		_ = cc.CloseWithError(0, "")
		return nil, ctx.Err()
	case <-cc.Context().Done():
		return nil, context.Cause(cc.Context())
	}
	return &h3ProxyConn{ClientConn: cc, local: qc.LocalAddr(), remote: qc.RemoteAddr()}, nil
}

// h3StreamConn is a CONNECT tunnel on an HTTP/3 stream as a net.Conn. The stream frames its
// bytes in DATA frames and a deadline that cuts a frame short loses the parser's place, so a
// read waits on a deadlineReader and a write the deadline cut resets the stream.
type h3StreamConn struct {
	str    *http3.RequestStream
	r      *deadlineReader
	local  net.Addr
	remote net.Addr
	wmu    sync.Mutex
	closed atomic.Bool
}

func newH3StreamConn(str *http3.RequestStream, local, remote net.Addr) *h3StreamConn {
	return &h3StreamConn{str: str, r: newDeadlineReader(tunnelReader{str}), local: local, remote: remote}
}

// tunnelReader reads the stream of a tunnel. The error of a stream or a connection is sticky,
// and some report themselves as a timeout, which a reader would retry.
type tunnelReader struct{ str *http3.RequestStream }

func (r tunnelReader) Read(b []byte) (int, error) {
	n, err := r.str.Read(b)
	if err != nil && !errors.Is(err, io.EOF) && isTimeout(err) {
		err = fmt.Errorf("%w: %v", errTunnelEnded, err)
	}
	return n, err
}

func (c *h3StreamConn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.r.Read(b)
}

func (c *h3StreamConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.str.Write(b)
	if err != nil && isTimeout(err) {
		// The deadline may have cut a frame short, and the proxy cannot parse the stream past
		// it.
		c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	}
	return n, err
}

func (c *h3StreamConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.str.Close()
}

func (c *h3StreamConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	if c.wmu.TryLock() {
		_ = c.str.Close()
		c.wmu.Unlock()
	} else {
		// A write blocked on flow control only returns on a reset.
		c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	}
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	return nil
}

func (c *h3StreamConn) LocalAddr() net.Addr  { return c.local }
func (c *h3StreamConn) RemoteAddr() net.Addr { return c.remote }

func (c *h3StreamConn) SetDeadline(t time.Time) error {
	c.r.setDeadline(t)
	return c.str.SetWriteDeadline(t)
}

func (c *h3StreamConn) SetReadDeadline(t time.Time) error {
	c.r.setDeadline(t)
	return nil
}

func (c *h3StreamConn) SetWriteDeadline(t time.Time) error { return c.str.SetWriteDeadline(t) }

// connectUDPConn is a CONNECT-UDP tunnel as a connected socket, one datagram per Read and per
// Write. A datagram too large for the tunnel is dropped.
type connectUDPConn struct {
	pipe      tunnelPipe
	remote    tunnelTarget
	closeOnce sync.Once
}

// tunnelTarget is the address a tunnel is opened to, as the proxy resolves it.
type tunnelTarget string

func (tunnelTarget) Network() string  { return "udp" }
func (t tunnelTarget) String() string { return string(t) }

func (c *connectUDPConn) Read(b []byte) (int, error) {
	for {
		data, err := c.pipe.recv(context.Background())
		if err != nil {
			return 0, err
		}
		// Context ID 0 is a UDP payload, RFC 9298 section 5. Anything else is dropped.
		id, n, perr := quicvarint.Parse(data)
		if perr != nil || id != 0 {
			continue
		}
		return copy(b, data[n:]), nil
	}
}

func (c *connectUDPConn) Write(b []byte) (int, error) {
	out := tunnelBuf(capsuleHeadroom + 1 + len(b))
	out[capsuleHeadroom] = 0
	copy(out[capsuleHeadroom+1:], b)
	err := c.pipe.send(out)
	putTunnelBuf(out)
	if err != nil {
		if _, tooLarge := errors.AsType[*quic.DatagramTooLargeError](err); tooLarge {
			return len(b), nil
		}
		return 0, err
	}
	return len(b), nil
}

func (c *connectUDPConn) Close() error {
	c.closeOnce.Do(func() { _ = c.pipe.close() })
	return nil
}

func (c *connectUDPConn) LocalAddr() net.Addr                { return emptyAddr{} }
func (c *connectUDPConn) RemoteAddr() net.Addr               { return c.remote }
func (c *connectUDPConn) SetDeadline(t time.Time) error      { return c.SetReadDeadline(t) }
func (c *connectUDPConn) SetReadDeadline(t time.Time) error  { return c.pipe.setReadDeadline(t) }
func (c *connectUDPConn) SetWriteDeadline(t time.Time) error { return c.pipe.setWriteDeadline(t) }
