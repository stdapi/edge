// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/ipv4"
)

// Transport configures how the proxy reaches upstream servers. The zero value is not usable;
// start from [DefaultTransport] and change what you need.
//
// Connections are pooled per destination, the address a redirect was headed to or the CONNECT
// target, and per proxy, and a destination keeps at most MaxIdleConnsPerHost idle connections.
// Requests with no fixed destination share one pool per scheme and proxy, each bounded by
// MaxIdleConns.
type Transport struct {
	// DialContext dials an upstream. It is called with network tcp for a TCP upstream and udp
	// for a QUIC one, and a QUIC connection runs on the socket it returns. It defaults to a
	// net.Dialer with a 30s timeout and keep-alives enabled. Override it to pin a resolver,
	// force a source address, or route upstream traffic through a tunnel.
	//
	// The proxy refuses a connection to one of its listeners when its addresses are those of a
	// connection DialContext returned. It does not recognize a connection without IP addresses,
	// one whose addresses were translated after the dial, as by NAT or a tunnel, or one dialed by
	// another Proxy.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// Proxy specifies a function to return a proxy for a given Request. An upstream reached
	// through a CONNECT, or one that has no request, calls it with a request for the
	// destination alone, so [http.ProxyFromEnvironment] applies to it as well.
	//
	// The proxy type is determined by the URL scheme. "http", "https", "socks5" and "socks5h"
	// are supported. Through an HTTP proxy a TCP upstream goes through a CONNECT, over HTTP/3
	// or over TCP, where TLS negotiates HTTP/2 or HTTP/1.1, and a QUIC or UDP upstream
	// through a CONNECT-UDP tunnel, RFC 9298, over HTTP/3 when the proxy answers on UDP and
	// over TCP otherwise. An "http" proxy is reached over HTTP/1.1. Through a SOCKS5 proxy a
	// TCP upstream goes through a CONNECT and a QUIC or UDP upstream through a UDP
	// ASSOCIATE, RFC 1928, and a hostname is sent for the proxy to resolve under both
	// schemes. The credentials of the URL are sent with the Basic scheme to an HTTP proxy
	// and with the username/password method of RFC 1929 to a SOCKS5 one. A request through
	// an HTTP proxy fails if the Basic scheme cannot encode the credentials of the URL, or if
	// the proxy answers 407.
	//
	// If Proxy is nil or returns a nil *URL, no proxy is used.
	Proxy func(*http.Request) (*url.URL, error)

	// TLSClientConfig is the base configuration for upstream TLS handshakes. The proxy
	// clones it and fills in the server name and the ALPN list per connection, so setting
	// those here has no effect.
	TLSClientConfig *tls.Config

	// RootCAs verifies upstream certificates. A nil pool uses the host trust store.
	RootCAs *x509.CertPool

	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	ExpectContinueTimeout time.Duration
	IdleConnTimeout       time.Duration

	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int

	// InsecureSkipVerify disables upstream certificate verification. Interception already
	// breaks the end to end guarantee for the client, so leaving verification on is what
	// keeps the proxy from turning a broken upstream certificate into a silent success.
	InsecureSkipVerify bool

	// AllowHTTP2 lets the proxy negotiate h2 with upstreams, and use h2c with a plaintext
	// upstream when the client did. It defaults to true.
	AllowHTTP2 bool

	// AllowHTTP3 lets the proxy speak h3 to upstreams that advertise it. It defaults to
	// false: an h3 upstream is only reachable over UDP, which is not always allowed where
	// the proxy runs.
	AllowHTTP3 bool

	// DisableKeepAlives closes every upstream connection after a single request.
	DisableKeepAlives bool
}

// DefaultTransport returns the upstream configuration the proxy uses when none is given.
func DefaultTransport() *Transport {
	return &Transport{
		DialContext:           defaultDialer.DialContext,
		AllowHTTP2:            true,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
	}
}

var defaultDialer = &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

// dialer returns the function every upstream is dialed with.
func (t *Transport) dialer() func(context.Context, string, string) (net.Conn, error) {
	if t.DialContext != nil {
		return t.DialContext
	}
	return defaultDialer.DialContext
}

// httpTransport builds a net/http transport for TCP upstreams. allowH2 decides whether it
// may negotiate HTTP/2, which is how the proxy mirrors upstream the version the client chose
// downstream: an app that asked for HTTP/1.1 must not have its request delivered over h2.
//
// Compression is deliberately left off. A proxy must put back on the wire the body the
// origin produced, encoded the way the client asked for it: letting net/http add its own
// Accept-Encoding and transparently gunzip would change both the request the origin sees and
// the bytes the client gets, and would hide Content-Encoding from handlers.
func (t *Transport) httpTransport(allowH2, fixed bool, dial func(context.Context, string, string) (net.Conn, error), proxy func(*http.Request) (*url.URL, error)) *http.Transport {
	tlsCfg := t.upstreamTLSConfig()

	if allowH2 {
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	} else {
		tlsCfg.NextProtos = []string{"http/1.1"}
	}

	tr := &http.Transport{
		Proxy:                 proxy,
		DialContext:           dial,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   t.TLSHandshakeTimeout,
		ResponseHeaderTimeout: t.ResponseHeaderTimeout,
		ExpectContinueTimeout: t.ExpectContinueTimeout,
		IdleConnTimeout:       t.IdleConnTimeout,
		MaxIdleConns:          t.MaxIdleConns,
		MaxIdleConnsPerHost:   t.MaxIdleConnsPerHost,
		MaxConnsPerHost:       t.MaxConnsPerHost,
		DisableKeepAlives:     t.DisableKeepAlives,
		DisableCompression:    true,
		ForceAttemptHTTP2:     allowH2,
		ReadBufferSize:        h1ReadBuffer,
	}
	if !allowH2 {
		// A non-nil map is what tells net/http never to hand the connection to the HTTP/2
		// implementation, whatever ALPN ends up negotiating.
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	if fixed {
		// A destination serves one authority, so the per host limit is its limit.
		tr.MaxIdleConns = cmp.Or(t.MaxIdleConnsPerHost, http.DefaultMaxIdleConnsPerHost)
	}
	return tr
}

// h2cTransport builds the transport for h2c. It is given no proxy, net/http would start
// HTTP/2 with the proxy itself.
func (t *Transport) h2cTransport(dial func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	tr := t.httpTransport(true, true, dial, nil)
	tr.Protocols = new(http.Protocols)
	tr.Protocols.SetUnencryptedHTTP2(true)
	return tr
}

// upstreamTLSConfig is the base configuration for a handshake the proxy performs on behalf of
// a client. The kinds that carry a whole connection use it too, so the trust settings a caller
// configured apply wherever the proxy speaks TLS upstream.
func (t *Transport) upstreamTLSConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if t.TLSClientConfig != nil {
		cfg = t.TLSClientConfig.Clone()
	}
	if t.RootCAs != nil {
		cfg.RootCAs = t.RootCAs
	}
	if t.InsecureSkipVerify {
		cfg.InsecureSkipVerify = true
	}
	return cfg
}

// newHTTP3Transport builds the upstream transport used when a client speaks HTTP/3 and
// [Transport.AllowHTTP3] is on.
func newHTTP3Transport(up *upstreamDialer, fixed string, proxy *url.URL) http.RoundTripper {
	t := up.t
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if t.TLSClientConfig != nil {
		tlsCfg = t.TLSClientConfig.Clone()
		if tlsCfg.MinVersion < tls.VersionTLS13 {
			// QUIC requires TLS 1.3; a lower floor inherited from the TCP configuration
			// would make every handshake fail.
			tlsCfg.MinVersion = tls.VersionTLS13
		}
	}
	if t.RootCAs != nil {
		tlsCfg.RootCAs = t.RootCAs
	}
	if t.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}

	return &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  t.IdleConnTimeout,
			KeepAlivePeriod: 0,
		},
		DisableCompression: true,
		Dial: func(ctx context.Context, addr string, cfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			// The server name stays the one in the request, so the certificate is still
			// checked against the authority the client asked for.
			if fixed != "" {
				addr = fixed
			}
			sock, err := up.dialThrough(ctx, "udp", addr, proxy)
			if err != nil {
				return nil, err
			}
			return quicOn(ctx, sock, addr, cfg, qcfg)
		},
	}
}

// packetConnOf presents a connected socket as the packet connection quic-go reads and writes.
func packetConnOf(c net.Conn) net.PacketConn {
	u, ok := c.(*net.UDPConn)
	if own, isOwn := c.(*ownUDPConn); isOwn {
		u, ok = own.UDPConn, true
	}
	if ok {
		return &connectedUDPConn{UDPConn: u, batch: ipv4.NewPacketConn(u)}
	}
	return connectedConn{noICMPConn{c}}
}

// noICMPConn is a connected socket that skips the ICMP errors the kernel hands it, as an
// unconnected socket never receives one.
type noICMPConn struct{ net.Conn }

func (c noICMPConn) Read(b []byte) (int, error) {
	for {
		n, err := c.Conn.Read(b)
		if !icmpError(err) {
			return n, err
		}
	}
}

func (c noICMPConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if icmpError(err) {
		n, err = c.Conn.Write(b)
	}
	return n, err
}

// connectedUDPConn keeps the batched reads, ECN and GSO quic-go enables on a *net.UDPConn. A
// write on a connected socket takes no address, so the one quic-go passes is dropped.
type connectedUDPConn struct {
	*net.UDPConn
	batch *ipv4.PacketConn
}

func (c *connectedUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.UDPConn.ReadFrom(b)
		if !icmpError(err) {
			return n, addr, err
		}
	}
}

// quic-go batches its reads through ReadBatch when the connection offers one, and otherwise
// on the socket itself, past this wrapper.
func (c *connectedUDPConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	for {
		n, err := c.batch.ReadBatch(ms, flags)
		if !icmpError(err) {
			return n, err
		}
	}
}

func (c *connectedUDPConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	n, err := c.Write(b)
	if icmpError(err) {
		n, err = c.Write(b)
	}
	return n, err
}

func (c *connectedUDPConn) WriteMsgUDP(b, oob []byte, _ *net.UDPAddr) (int, int, error) {
	n, oobn, err := c.UDPConn.WriteMsgUDP(b, oob, nil)
	if icmpError(err) {
		n, oobn, err = c.UDPConn.WriteMsgUDP(b, oob, nil)
	}
	return n, oobn, err
}

// connectedConn serves any other connected socket, a tunnel for instance, one packet per read.
type connectedConn struct{ noICMPConn }

func (c connectedConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.RemoteAddr(), err
}

func (c connectedConn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }

func (connectedConn) SetReadBuffer(int) error  { return nil }
func (connectedConn) SetWriteBuffer(int) error { return nil }
