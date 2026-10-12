// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stdapi/edge/internal/stringsutil"
)

// Protocol is the HTTP version spoken on a connection. It is the zero value on a connection
// carrying something else, where the kind of the entry serving it is what names the traffic.
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

// Target is a request target authority: the scheme, the hostname and the port. The port is
// always explicit, defaulted from the scheme when the client did not send one. An IPv6 host
// is carried unbracketed, the way [splitHostPort] returns it.
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
// so a caller-built target matches the same entries a real request would.
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

var sessionSeq atomic.Uint64

// Session is a unit the proxy decided once, when it arrived: a client connection, a CONNECT,
// a terminated QUIC connection, a datagram flow. Every request or stream multiplexed on it
// belongs to it, so an HTTP/2 or HTTP/3 connection has one session and many requests. A
// protocol upgrade gets a session of its own.
//
// Every request and every datagram is routed on the entries as they stand when it arrives.
// How a session is served is settled when it arrives and does not change when entries do.
// [Session.Stale] reports a session that would be served differently if it arrived now, and
// [Session.Close] ends it so the client connects again.
//
// A Session is safe for concurrent use by the goroutines serving its requests.
type Session struct {
	createdAt  time.Time
	remoteAddr net.Addr
	localAddr  net.Addr
	ctx        context.Context
	p          *Proxy
	// closer ends the connection. Each listener sets its own, a connection, a CONNECT stream,
	// or the bookkeeping a QUIC connection needs, before the session is registered and never
	// after.
	closer   io.Closer
	closeErr error
	// tlsState is atomic because the QUIC path fills it in once the handshake reaches the
	// server, by which point [Proxy.Sessions] already reports the session.
	tlsState atomic.Pointer[tls.ConnectionState]
	// entry is the one serving a connection whose handler owns it, TCP, QUIC or WebSocket,
	// and nil where each unit is routed on its own. Atomic for the same reason as tlsState.
	entry atomic.Pointer[entry]
	// tlsConn is set instead of tlsState when the session is created before the handshake,
	// so TLS() can read the state once it exists.
	tlsConn     *tls.Conn
	clientHello atomic.Pointer[ClientHello]
	// leaf is the certificate the proxy presented on a terminated connection.
	leaf atomic.Pointer[x509.Certificate]
	// upgrade is a copy of the request that switched the connection to the frames a WebSocket
	// session serves.
	upgrade *http.Request
	// via is the CONNECT-UDP tunnel this session arrived through, nil off a socket.
	via *Session
	// verified is the decision a connection took on the last name it checked. The requests of
	// an HTTP/2 or HTTP/3 connection read and write it concurrently.
	verified atomic.Pointer[verifiedHost]
	target   Target
	// upstream is the destination of a redirected connection or the literal a CONNECT
	// named, preferred over resolving the authority again, which may not even resolve
	// outside the client's network.
	upstream netip.AddrPort
	// dial is what the proxy dials, upstream as a string or the hostname of a CONNECT target,
	// empty when the proxy resolves the authority itself. It is computed once and read on
	// every request.
	dial     string
	identity string
	// servableAs holds the kinds the traffic allows, most specific first, and stays empty
	// where only the decided kind was ever possible.
	servableAs []Kind
	id         uint64
	closeOnce  sync.Once
	// proto is the protocol of the connection. The front listener builds its session from
	// ConnContext, before the protocol is known, so unlike every other field it is written
	// once a request has been read, from a goroutine serving one of them.
	proto atomic.Uint32
	kind  Kind
	// perRequest marks a plaintext connection nothing decided as a connection, which
	// [Proxy.Sessions] does not report. Each request is routed alone, or refused when the host
	// of the first request is admitted by nothing, which sets refused.
	perRequest  bool
	refused     bool
	transparent bool
	// tunnel marks a CONNECT-UDP tunnel, a session that serves nothing itself.
	tunnel bool
	// hasSchemeField marks a front connection whose HTTP/2 requests have their :scheme in
	// schemeHeader.
	hasSchemeField bool
}

func newSession(p *Proxy, ctx context.Context, c net.Conn, target Target, kind Kind, proto Protocol) *Session {
	s := &Session{
		id:        sessionSeq.Add(1),
		p:         p,
		target:    target,
		kind:      kind,
		createdAt: time.Now(),
		ctx:       ctx,
	}
	s.setProtocol(proto)
	if c != nil {
		s.remoteAddr = c.RemoteAddr()
		s.localAddr = c.LocalAddr()
		if sc := schemeConnOf(c); sc != nil {
			s.hasSchemeField = true
			c = sc.Conn
		}
		if tc, ok := c.(*tls.Conn); ok {
			if state := tc.ConnectionState(); state.HandshakeComplete {
				s.tlsState.Store(&state)
			} else {
				// http.Server calls ConnContext before it performs the handshake, so the
				// state read here would be the zero one. Keeping the connection lets it be
				// read once it exists, which is any time a request is being served.
				s.tlsConn = tc
			}
		}
	}
	return s
}

// ID returns a process-unique identifier for this session.
func (s *Session) ID() uint64 { return s.id }

// Identity returns what the configured [ProxyAuthenticator] reported for the request that
// established this connection, or an empty string when none did. It is what a revoked
// credential sweeps on.
func (s *Session) Identity() string { return s.identity }

// RemoteAddr returns the address of the client, or the zero value when the connection has
// none. Unlike [Context.RemoteAddr] it describes the connection, so it is the same for every
// request multiplexed on it and no handler can rewrite it.
func (s *Session) RemoteAddr() netip.AddrPort { return addrPort(s.remoteAddr) }

// LocalAddr returns the proxy-side address of the connection, or the zero value when it has
// none.
func (s *Session) LocalAddr() netip.AddrPort { return addrPort(s.localAddr) }

// Target returns the authority the session is routed on. It is the TLS server name when the
// client sent one, the host of the first request on a plaintext connection, and otherwise the
// CONNECT target or the destination the connection was headed to.
//
// A client sending requests with an absolute target to the proxy itself can address a
// different authority on each one, so the session of that connection reports none. A handler
// reads the authority it is serving from the [Context], which always has it.
func (s *Session) Target() Target { return s.target }

// Protocol returns the HTTP version spoken on the connection, or the zero value when it
// carries something else. It describes the connection, so it is the same for every request
// multiplexed on it.
func (s *Session) Protocol() Protocol {
	//nolint:gosec // the field is only ever written by setProtocol, from a Protocol.
	return Protocol(s.proto.Load())
}

// setProtocol records the protocol of the connection. Every request on one connection
// carries the same protocol, so writing it from each of them stores the same value.
func (s *Session) setProtocol(p Protocol) { s.proto.Store(uint32(p)) }

// TLS returns the state of the TLS connection with the client, or nil when the client is not
// speaking TLS to the proxy.
func (s *Session) TLS() *tls.ConnectionState {
	if state := s.tlsState.Load(); state != nil {
		return state
	}
	if s.tlsConn != nil {
		// The handshake had not run when the session was created. tls.Conn guards its own
		// state, so reading it now is safe from any of the goroutines serving the connection.
		if state := s.tlsConn.ConnectionState(); state.HandshakeComplete {
			return &state
		}
	}
	return nil
}

// ClientHello returns what the client offered in its TLS handshake, or nil for a plaintext
// session. It is the ground truth for mirroring a client's capabilities upstream.
func (s *Session) ClientHello() *ClientHello { return s.clientHello.Load() }

// Upstream returns the address the proxy sends to, the destination a redirected connection was
// headed to, the address literal a CONNECT named, or the address a CONNECT-UDP target
// resolved to. It is the zero value when the proxy resolves the authority itself.
func (s *Session) Upstream() netip.AddrPort { return s.upstream }

// setDestination records where a CONNECT asked the proxy to send.
func (s *Session) setDestination(t Target) {
	if addr, err := netip.ParseAddr(t.Host); err == nil {
		if port, perr := strconv.ParseUint(t.Port, 10, 16); perr == nil {
			s.setUpstream(netip.AddrPortFrom(addr.Unmap(), uint16(port)))
			return
		}
	}
	s.dial = t.Authority()
}

func (s *Session) setUpstream(ap netip.AddrPort) {
	if !ap.IsValid() {
		return
	}
	s.upstream = ap
	s.dial = ap.String()
}

func (s *Session) dialAddr() string { return s.dial }

// Transparent reports whether the client reached the proxy without being configured to use
// it, its traffic having been redirected by the network.
func (s *Session) Transparent() bool { return s.transparent }

// Kind returns the kind serving this connection. The proxy picks the most specific of
// [Session.ServableAs] admitted by an entry when the connection arrives, and keeps it for
// the life of the connection.
//
// A CONNECT-UDP tunnel reports the most specific kind an entry admitted it for, HTTP, QUIC or
// UDP in that order. The tunnel serves nothing itself. Each connection and datagram flow
// inside it is a session of its own, see [Session.Via]. A SOCKS5 UDP association declares no
// destination, so it is admitted by nothing and reports no kind, and every datagram inside it
// is admitted on its own.
func (s *Session) Kind() Kind { return s.kind }

// Tunnel reports whether the session is a CONNECT-UDP tunnel or a SOCKS5 UDP association.
// Closing one ends every session inside it, and the client has to open a new one, which is
// authenticated and admitted again.
func (s *Session) Tunnel() bool { return s.tunnel }

// Via returns the CONNECT-UDP tunnel or the SOCKS5 UDP association the session arrived
// through, or nil when its datagrams arrived off a socket. A session reports the identity of
// its tunnel.
func (s *Session) Via() *Session { return s.via }

// ServableAs returns the kinds that can serve this connection, from the most specific to the
// least. The negotiated ALPN or the first bytes fix the list when the connection arrives,
// and [Session.Kind] is always one of them. For example, an h3 connection reports KindHTTP
// then KindQUIC even when only a QUIC entry admits it. [Session.Stale] reports when a kind
// before [Session.Kind] in this list is admitted.
func (s *Session) ServableAs() []Kind {
	if len(s.servableAs) == 0 {
		return []Kind{s.kind}
	}
	return slices.Clone(s.servableAs)
}

// Stale reports whether the client would be served differently if it connected again now.
// That is the case once an Add, an Update or a Delete leaves its authority admitted by
// nothing, by a handler of a more specific kind, or by another handler of the same kind. An
// HTTP connection, a datagram flow and a CONNECT-UDP tunnel already route each request and
// each datagram on the current handlers, so they only go stale when their kind would change.
//
// Closing a stale session makes the client connect again, and the current handlers serve it.
//
//	for s := range p.Sessions() {
//		if s.Stale() {
//			s.Close()
//		}
//	}
func (s *Session) Stale() bool {
	if s.p == nil || s.target.Host == "" || s.perRequest {
		return false
	}
	return s.p.stale(s)
}

// ALPN returns the application protocol negotiated with the client, or an empty string when
// the connection carries no TLS or the client offered none. The value appears once the
// handshake completes.
func (s *Session) ALPN() string {
	if state := s.tlsState.Load(); state != nil {
		return state.NegotiatedProtocol
	}
	if s.tlsConn != nil {
		if state := s.tlsConn.ConnectionState(); state.HandshakeComplete {
			return state.NegotiatedProtocol
		}
	}
	return ""
}

// Close ends the session at once, without draining, and the requests or streams in flight
// fail. It ends this session and nothing else. The client sees the end in its own protocol, a
// FIN, a CONNECTION_CLOSE or a stream reset, and is free to come back, to be authenticated and
// admitted again on the entries as they stand then. A datagram flow has no such signal and
// the client sees its replies stop. Closing a session that already ended is a no-op.
// Revoking an identity uses the same call, see [Session.Identity].
func (s *Session) Close() error {
	if s.closer == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if err := s.closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.closeErr = err
		}
	})
	return s.closeErr
}

// CreatedAt returns when the session began.
func (s *Session) CreatedAt() time.Time { return s.createdAt }

// Context returns a context canceled when the session ends.
func (s *Session) Context() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
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

// addrPort converts a connection address to a netip.AddrPort. The two concrete types the
// listeners produce are converted without parsing; anything else, a test harness address or
// a unix socket, falls back to parsing and yields the zero value when it is not an IP.
func addrPort(a net.Addr) netip.AddrPort {
	var ap netip.AddrPort
	switch v := a.(type) {
	case nil:
		return netip.AddrPort{}
	case *net.TCPAddr:
		ap = v.AddrPort()
	case *net.UDPAddr:
		ap = v.AddrPort()
	default:
		var err error
		if ap, err = netip.ParseAddrPort(a.String()); err != nil {
			return netip.AddrPort{}
		}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
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
// The authority entry is exactly what makes splitting and rejoining stable for every pair splitHostPort
// can produce, which FuzzSplitHostPort checks. Authorities arrive off the wire, and a proxy
// that reads one back differently than it wrote it is how routing gets bypassed.
func needsBrackets(host string) bool {
	if strings.IndexByte(host, ']') >= 0 {
		return false
	}
	return strings.IndexByte(host, ':') >= 0 || strings.HasPrefix(host, "[")
}

// RFC 3986 allows leading zeros in a port, and a pattern spells none.
func canonicalPort(port string) (string, bool) {
	if port == "" {
		return "", true
	}
	i := 0
	for i < len(port)-1 && port[i] == '0' {
		i++
	}
	port = port[i:]
	if len(port) > 5 {
		return "", false
	}
	n := 0
	for j := range len(port) {
		c := port[j]
		if c < '0' || c > '9' {
			return "", false
		}
		n = n*10 + int(c-'0')
	}
	if n == 0 || n > 65535 {
		return "", false
	}
	return port, true
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

// splitAuthority splits an authority of the form "host", "host:port", "[host]" or "[host]:port"
// into host and port, the port in canonical form. It reports false when authority is not of that
// form, when a bracketed host is not an IPv6 address or when another host is not a reg-name of
// RFC 3986.
func splitAuthority(authority string) (host, port string, ok bool) {
	host, port = splitHostPort(authority)
	if strings.HasPrefix(authority, "[") {
		if addr, err := netip.ParseAddr(host); err != nil || !addr.Is6() {
			return "", "", false
		}
		// splitHostPort drops what follows the bracket when it is not a port.
		if rest := authority[len(host)+2:]; rest != "" && (rest[0] != ':' || rest[1:] != port) {
			return "", "", false
		}
	} else {
		for i := 0; i < len(host); i++ {
			switch {
			case host[i] == '%':
				if i+2 >= len(host) {
					return "", "", false
				}
				if _, hex := stringsutil.DecodeHexPair(host[i+1], host[i+2]); !hex {
					return "", "", false
				}
				i += 2
			case notInHost[host[i]]:
				return "", "", false
			}
		}
	}
	port, ok = canonicalPort(port)
	return host, port, ok
}

// notInHost marks every byte other than the unreserved characters and the sub-delims of RFC 3986,
// which a reg-name contains only percent-encoded. An IPv4 address is also a reg-name.
var notInHost = func() (t [256]bool) {
	for c := range 256 {
		t[c] = !stringsutil.IsUnreserved(byte(c)) && strings.IndexByte("!$&'()*+,;=", byte(c)) < 0
	}
	return t
}()

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
