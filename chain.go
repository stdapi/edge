// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// upstreamDialer opens every connection the proxy makes upstream, through the proxy
// [Transport.Proxy] selects when it selects one.
type upstreamDialer struct {
	t     *Transport
	h3    *http3.Transport
	conns map[string]*http3.ClientConn
	mu    sync.Mutex
	// closed refuses a proxy connection opened after close, so none outlives the forwarder.
	closed bool
}

func newUpstreamDialer(t *Transport) *upstreamDialer {
	return &upstreamDialer{
		t:     t,
		h3:    &http3.Transport{EnableDatagrams: true, DisableCompression: true},
		conns: make(map[string]*http3.ClientConn),
	}
}

func (u *upstreamDialer) close() {
	u.mu.Lock()
	u.closed = true
	conns := u.conns
	u.conns = nil
	u.mu.Unlock()
	for _, cc := range conns {
		_ = cc.CloseWithError(0, "")
	}
	_ = u.h3.Close()
}

// proxyFor returns the proxy selected for a connection to addr, nil for a direct one. scheme
// is what the connection carries, https for TLS and QUIC and http for the clear.
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
		if proxy.Scheme != "https" {
			return nil, fmt.Errorf("edge: dial udp %s through %s: CONNECT-UDP needs an https proxy", addr, proxy.Redacted())
		}
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
		// A tunnel carries one datagram per QUIC datagram of the proxy connection, so the
		// packets stay at the size every path carries.
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

// connect opens a TCP connection to addr with a CONNECT to the proxy.
func (u *upstreamDialer) connect(ctx context.Context, proxy *url.URL, addr string) (net.Conn, error) {
	conn, err := u.t.dialer()(ctx, "tcp", proxyAddr(proxy))
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxy.Redacted(), err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	tunnel, err := u.connectOn(ctx, conn, proxy, addr)
	if !stop() {
		_ = conn.Close()
		return nil, fmt.Errorf("dial %s through %s: %w", addr, proxy.Redacted(), ctx.Err())
	}
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("dial %s through %s: %w", addr, proxy.Redacted(), err)
	}
	return tunnel, nil
}

func (u *upstreamDialer) connectOn(ctx context.Context, conn net.Conn, proxy *url.URL, addr string) (net.Conn, error) {
	if proxy.Scheme == "https" {
		cfg := u.t.upstreamTLSConfig()
		cfg.ServerName = proxy.Hostname()
		cfg.NextProtos = []string{"http/1.1"}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		conn = tc
	}

	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: make(http.Header)}
	if auth := proxyAuthorization(proxy); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, errors.New("CONNECT refused with " + resp.Status)
	}
	if br.Buffered() == 0 {
		return conn, nil
	}
	// A peer that speaks first, an SMTP banner for instance, may already be behind the
	// response.
	return bufferedConn{Conn: conn, r: br}, nil
}

// connectUDP opens a UDP tunnel to addr with a CONNECT-UDP to the proxy, RFC 9298.
func (u *upstreamDialer) connectUDP(ctx context.Context, proxy *url.URL, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("edge: dial udp %q: %w", addr, err)
	}
	cc, err := u.proxyConn(ctx, proxy)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxy.Redacted(), err)
	}
	tunnel, err := openTunnelOn(ctx, cc, proxy, host, port)
	if err != nil {
		return nil, fmt.Errorf("dial udp %s through %s: %w", addr, proxy.Redacted(), err)
	}
	tunnel.remote = tunnelTarget(addr)
	return tunnel, nil
}

func openTunnelOn(ctx context.Context, cc *http3.ClientConn, proxy *url.URL, host, port string) (*connectUDPConn, error) {
	target, err := url.Parse(fmt.Sprintf("https://%s%s%s/%s/", proxyAddr(proxy), connectUDPPath, url.PathEscape(host), port))
	if err != nil {
		return nil, err
	}
	req := &http.Request{Method: http.MethodConnect, Proto: "connect-udp", URL: target, Host: target.Host, Header: make(http.Header)}
	req.Header.Set(http3.CapsuleProtocolHeader, "?1")
	if auth := proxyAuthorization(proxy); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}

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
		return nil, fmt.Errorf("write CONNECT-UDP: %w", werr)
	}
	resp, err := str.ReadResponse()
	if !stop() {
		return nil, ctx.Err()
	}
	if err != nil {
		cancel()
		return nil, fmt.Errorf("read CONNECT-UDP response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		return nil, errors.New("CONNECT-UDP refused with " + resp.Status)
	}
	tunnel := &connectUDPConn{str: str}
	go tunnel.drainCapsules()
	return tunnel, nil
}

// proxyConn returns the HTTP/3 connection to a proxy, opened on the first tunnel and shared
// by every later one until it ends.
func (u *upstreamDialer) proxyConn(ctx context.Context, proxy *url.URL) (*http3.ClientConn, error) {
	key := proxyAddr(proxy)
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil, net.ErrClosed
	}
	if cc := u.conns[key]; cc != nil && cc.Context().Err() == nil {
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
	if other := u.conns[key]; other != nil && other.Context().Err() == nil {
		_ = cc.CloseWithError(0, "")
		return other, nil
	}
	u.conns[key] = cc
	return cc, nil
}

func (u *upstreamDialer) openProxyConn(ctx context.Context, proxy *url.URL, addr string) (*http3.ClientConn, error) {
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
		EnableDatagrams: true,
		MaxIdleTimeout:  u.t.IdleConnTimeout,
		// The connection carries the 1200 byte Initial of a QUIC connection inside a
		// datagram, which the default initial packet size does not leave room for.
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
	if s := cc.Settings(); !s.EnableDatagrams || !s.EnableExtendedConnect {
		_ = cc.CloseWithError(0, "")
		return nil, errors.New("the proxy does not support CONNECT-UDP")
	}
	return cc, nil
}

// connectUDPConn is a CONNECT-UDP tunnel as a connected socket, one datagram per Read and per
// Write. A datagram larger than the tunnel carries is dropped.
type connectUDPConn struct {
	str       *http3.RequestStream
	deadline  atomic.Pointer[time.Time]
	remote    tunnelTarget
	closeOnce sync.Once
}

// tunnelTarget is the address a tunnel is opened to, as the proxy resolves it.
type tunnelTarget string

func (tunnelTarget) Network() string  { return "udp" }
func (t tunnelTarget) String() string { return string(t) }

// drainCapsules reads and drops the capsules the proxy sends, and closes the tunnel when the
// stream ends.
func (c *connectUDPConn) drainCapsules() {
	parser := http3.NewCapsuleParser(c.str)
	for {
		_, r, err := parser.Next()
		if err != nil {
			break
		}
		if err := r.Discard(); err != nil {
			break
		}
	}
	_ = c.Close()
}

func (c *connectUDPConn) Read(b []byte) (int, error) {
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
				return 0, os.ErrDeadlineExceeded
			}
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
	var out []byte
	if 1+len(b) <= tunnelBufSize {
		out = tunnelBufPool.Get().(*[tunnelBufSize]byte)[:1+len(b)]
	} else {
		out = make([]byte, 1+len(b))
	}
	out[0] = 0
	copy(out[1:], b)
	err := c.str.SendDatagram(out)
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
	c.closeOnce.Do(func() {
		c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		_ = c.str.Close()
	})
	return nil
}

func (c *connectUDPConn) LocalAddr() net.Addr               { return emptyAddr{} }
func (c *connectUDPConn) RemoteAddr() net.Addr              { return c.remote }
func (c *connectUDPConn) SetDeadline(t time.Time) error     { return c.SetReadDeadline(t) }
func (c *connectUDPConn) SetReadDeadline(t time.Time) error { c.deadline.Store(&t); return nil }
func (c *connectUDPConn) SetWriteDeadline(time.Time) error  { return nil }
