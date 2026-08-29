// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fox-toolkit/edge/internal/stringsutil"
)

// Protocol is the HTTP version spoken on a connection.
type Protocol uint8

const (
	// HTTP11 is HTTP/1.1 over TCP, with or without TLS.
	HTTP11 Protocol = iota + 1
	// HTTP2 is HTTP/2 over TCP, either negotiated through ALPN or started with prior knowledge.
	HTTP2
	// HTTP3 is HTTP/3 over QUIC.
	HTTP3
)

func (p Protocol) String() string {
	switch p {
	case HTTP11:
		return "HTTP/1.1"
	case HTTP2:
		return "HTTP/2.0"
	case HTTP3:
		return "HTTP/3.0"
	default:
		return "unknown"
	}
}

// ALPN returns the protocol identifier used in the TLS ALPN extension.
func (p Protocol) ALPN() string {
	switch p {
	case HTTP11:
		return "http/1.1"
	case HTTP2:
		return "h2"
	case HTTP3:
		return "h3"
	default:
		return ""
	}
}

func protocolFromALPN(s string) Protocol {
	switch s {
	case "h2":
		return HTTP2
	case "h3":
		return HTTP3
	default:
		return HTTP11
	}
}

// Action is what the proxy does with a connection to a given authority.
type Action uint8

const (
	// Tunnel relays the connection byte for byte. The proxy never sees the plaintext and
	// no route is consulted.
	Tunnel Action = iota + 1
	// Intercept terminates TLS with a minted leaf certificate and routes every request on
	// the connection.
	Intercept
	// Reject refuses the connection. Explicit proxy clients get 403 Forbidden.
	Reject
)

func (a Action) String() string {
	switch a {
	case Tunnel:
		return "tunnel"
	case Intercept:
		return "intercept"
	case Reject:
		return "reject"
	default:
		return "unknown"
	}
}

// Target is a request target authority: the scheme, the hostname and the port. The port is
// always explicit, defaulted from the scheme when the client did not send one.
type Target struct {
	Scheme string
	Host   string
	Port   string
}

// Authority returns the target as host:port, bracketing an IPv6 literal.
func (t Target) Authority() string { return joinHostPort(t.Host, t.Port) }

// String returns the target as scheme://host:port.
func (t Target) String() string {
	if t.Scheme == "" {
		return t.Authority()
	}
	return t.Scheme + "://" + t.Authority()
}

// normalized fills in the scheme and the port from each other when one of them is missing,
// so a caller-built target matches the same routes a real request would.
func (t Target) normalized() Target {
	if t.Scheme == "" {
		t.Scheme = schemeForPort(t.Port)
	}
	if t.Port == "" {
		t.Port = defaultPort(t.Scheme)
	}
	t.Host = stringsutil.ToLowerASCIIString(strings.TrimSuffix(t.Host, "."))
	return t
}

// IsDefaultPort reports whether the port is the default for the scheme.
func (t Target) IsDefaultPort() bool {
	return (t.Scheme == "https" && t.Port == "443") || (t.Scheme == "http" && t.Port == "80")
}

var sessionSeq atomic.Uint64

// Session is a client connection handled by the proxy. One session carries every request
// multiplexed on that connection, so an HTTP/2 or HTTP/3 connection has a single session
// and many requests.
//
// A Session is safe for concurrent use by the goroutines serving its requests.
type Session struct {
	createdAt   time.Time
	remoteAddr  net.Addr
	localAddr   net.Addr
	ctx         context.Context
	tlsState    *tls.ConnectionState
	clientHello *ClientHello
	values      atomic.Pointer[map[any]any]
	target      Target
	// upstream is the address a transparently redirected connection was headed to. It is
	// preferred over resolving the authority again, which may not even resolve outside the
	// client's own network.
	upstream    netip.AddrPort
	id          uint64
	mu          sync.Mutex
	action      Action
	proto       Protocol
	transparent bool
}

// ID returns a process-unique identifier for this session.
func (s *Session) ID() uint64 { return s.id }

// RemoteAddr returns the address of the client.
func (s *Session) RemoteAddr() net.Addr { return s.remoteAddr }

// LocalAddr returns the proxy-side address of the connection.
func (s *Session) LocalAddr() net.Addr { return s.localAddr }

// RemoteIP returns the client IP, or the zero value when the connection has none.
func (s *Session) RemoteIP() netip.Addr {
	if s.remoteAddr == nil {
		return netip.Addr{}
	}
	host, _, err := net.SplitHostPort(s.remoteAddr.String())
	if err != nil {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// Target returns the authority the client asked for. For an explicit proxy this is the
// CONNECT target or the authority of the absolute request target; in transparent mode it
// is derived from the TLS server name or the Host header.
func (s *Session) Target() Target { return s.target }

// Action returns how the proxy decided to handle this connection.
func (s *Session) Action() Action { return s.action }

// Protocol returns the protocol negotiated with the client.
func (s *Session) Protocol() Protocol { return s.proto }

// TLS returns the state of the intercepted TLS connection, or nil when the client is not
// speaking TLS to the proxy.
func (s *Session) TLS() *tls.ConnectionState { return s.tlsState }

// ClientHello returns what the client offered in its TLS handshake with the proxy, or nil
// for a plaintext session. It is the ground truth for mirroring a client's capabilities
// upstream.
func (s *Session) ClientHello() *ClientHello { return s.clientHello }

// Upstream returns the address a transparently redirected connection was headed to before
// the redirect, or the zero value when the proxy was reached explicitly.
func (s *Session) Upstream() netip.AddrPort { return s.upstream }

// Transparent reports whether the client reached the proxy without being configured to use
// it, its traffic having been redirected by the network.
func (s *Session) Transparent() bool { return s.transparent }

// CreatedAt returns when the session was accepted.
func (s *Session) CreatedAt() time.Time { return s.createdAt }

// Context returns a context canceled when the session ends.
func (s *Session) Context() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

// Value returns the value stored on this session under key, or nil. Session values let
// middleware carry state across every request multiplexed on one connection.
func (s *Session) Value(key any) any {
	m := s.values.Load()
	if m == nil {
		return nil
	}
	return (*m)[key]
}

// SetValue stores a value on this session under key. It is safe for concurrent use.
func (s *Session) SetValue(key, val any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.values.Load()
	next := make(map[any]any, 1)
	if old != nil {
		for k, v := range *old {
			next[k] = v
		}
	}
	next[key] = val
	s.values.Store(&next)
}

// ClientHello is the part of a TLS ClientHello the proxy needs to mirror a client upstream.
type ClientHello struct {
	// ServerName is the SNI sent by the client, empty when it sent none.
	ServerName string
	// ALPN lists the protocols the client offered, in preference order.
	ALPN []string
	// SupportedVersions lists the TLS versions the client offered.
	SupportedVersions []uint16
	// CipherSuites lists the cipher suites the client offered.
	CipherSuites []uint16
}

// joinHostPort joins a hostname and a port, bracketing an IPv6 literal.
func joinHostPort(host, port string) string {
	if needsBrackets(host) {
		if port == "" {
			return "[" + host + "]"
		}
		return "[" + host + "]:" + port
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}

// needsBrackets reports whether a host has to be bracketed to appear in an authority.
//
// A host holding a colon does, or the colons of an IPv6 address cannot be told from the one
// before a port. A host starting with "[" does too, or the authority would be read back as a
// bracketed one and cut at the wrong place.
//
// A host already holding a "]" is the exception to both. It only ever comes from a malformed
// authority, and bracketing it would put a second "]" in a string the split cuts at the
// first one, so the pair would not survive a rejoin. Left alone it does.
//
// The rule is exactly what makes splitting and rejoining stable for every pair splitHostPort
// can produce, which FuzzSplitHostPort checks. Authorities arrive off the wire, and a proxy
// that reads one back differently than it wrote it is how routing gets bypassed.
func needsBrackets(host string) bool {
	if strings.IndexByte(host, ']') >= 0 {
		return false
	}
	return strings.IndexByte(host, ':') >= 0 || strings.HasPrefix(host, "[")
}

// splitHostPort splits an authority into its host and port. The host of an IPv6 literal is
// returned without its brackets. When the authority carries no port, port is empty.
func splitHostPort(authority string) (host, port string) {
	if authority == "" {
		return "", ""
	}
	if authority[0] == '[' {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return authority, ""
		}
		host = authority[1:end]
		// What follows a bracketed host is either nothing or a port. A remainder holding
		// another colon is not a port, and reading one out of it would produce a pair that
		// rejoins into a different authority.
		if rest := authority[end+1:]; len(rest) > 1 && rest[0] == ':' && strings.IndexByte(rest[1:], ':') < 0 {
			port = rest[1:]
		}
		return host, port
	}
	i := strings.LastIndexByte(authority, ':')
	if i < 0 || strings.IndexByte(authority[:i], ':') >= 0 {
		// No port, or an unbracketed IPv6 literal which by definition carries none.
		return authority, ""
	}
	return authority[:i], authority[i+1:]
}

// defaultPort returns the well-known port for scheme.
func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// schemeForPort guesses the scheme of a target from its port. It is only used when nothing
// better is known, such as a CONNECT to a non-standard port that turns out to be plaintext.
func schemeForPort(port string) string {
	if port == "443" {
		return "https"
	}
	return "http"
}
