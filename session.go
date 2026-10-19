// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
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
	// closer ends the legs of the session. Each listener sets its own, a connection, a CONNECT
	// stream, or the bookkeeping a QUIC connection needs, at the registration of the session,
	// and the admission replaces the closer of a pending socket. Guarded by the server lock
	// once the session is registered.
	closer   sessionCloser
	closeErr error
	// pendingTLS is set instead of tlsState when the session is created before the handshake,
	// so TLS() can read the state once it exists.
	pendingTLS connectionStater
	// httpConn is the connection of the HTTP requests of the session. Aborting it gives
	// an HTTP/1.1 response in flight its failed end.
	httpConn net.Conn
	// streamsCtx is the context the requests of an HTTP/3 connection derive from, which its end
	// cancels. quic-go also cancels the context of a request once its send side ends.
	streamsCtx context.Context
	// cancelRequests cancels the context of every request of an HTTP connection, nil elsewhere.
	// Guarded by the server lock where a server sets it after the session is registered.
	cancelRequests context.CancelFunc
	p              *Proxy
	// cancel ends ctx. Every session [Proxy.Sessions] reports has one, so Close ends the
	// session without waiting for the goroutines serving it.
	cancel context.CancelFunc
	// tlsState is atomic because the QUIC path fills it in once the handshake reaches the
	// server, by which point [Proxy.Sessions] already reports the session.
	tlsState atomic.Pointer[tls.ConnectionState]
	// entry is the one serving a connection whose handler owns it, TCP, QUIC or WebSocket,
	// and nil where each unit is routed on its own. Atomic for the same reason as tlsState.
	entry       atomic.Pointer[entry]
	clientHello atomic.Pointer[ClientHello]
	// leaf is the certificate the proxy presented on a terminated connection.
	leaf atomic.Pointer[x509.Certificate]
	// upgrade is a copy of the request that switched the connection to the frames a WebSocket
	// session serves.
	upgrade *http.Request
	// via is the CONNECT-UDP tunnel this session arrived through, nil off a socket.
	via *Session
	// carrier is the session on the connection of which the session is a stream, nil when the
	// session has a socket of its own. carried lists the sessions it is the carrier of. Both
	// are guarded by the server lock.
	carrier *Session
	carried map[*Session]struct{}
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
	end      unitEnd
	// servableAs holds the kinds the traffic allows, most specific first, and stays empty
	// where only the decided kind was ever possible.
	servableAs []Kind
	id         uint64
	// proto is the protocol of the connection. The front listener builds its session from
	// ConnContext, before the protocol is known, so unlike every other field it is written
	// once a request has been read, from a goroutine serving one of them.
	proto atomic.Uint32
	// requested is set once a request of the connection reached a handler.
	requested atomic.Bool
	// requestsEnded is set once the requests of the session were canceled, under the server
	// lock.
	requestsEnded bool
	kind          Kind
	// perRequest marks a plaintext connection nothing decided as a connection, which
	// [Proxy.Sessions] does not report. Each request is routed alone, or refused when the host
	// of the first request is admitted by nothing, which sets refused.
	perRequest  bool
	refused     bool
	transparent bool
	// tunnel marks a CONNECT-UDP tunnel, a session that serves nothing itself.
	tunnel bool
	// ended is set by Close under the server lock, so a registration racing it is refused.
	ended bool
	// shard is where the requests of the session are listed.
	shard uint8
	// serving is set while the session counts in server.serving, guarded by the server lock.
	serving bool
	// admitted is set once an entry admitted the session, guarded by the server lock.
	admitted bool
	// hasSchemeField marks a front connection whose HTTP/2 requests have their :scheme in
	// schemeHeader.
	hasSchemeField bool
}

func newSession(p *Proxy, ctx context.Context, c net.Conn, target Target, kind Kind, proto Protocol) *Session {
	id := sessionSeq.Add(1)
	s := &Session{
		id:        id,
		shard:     uint8(id % requestShards),
		p:         p,
		target:    target,
		kind:      kind,
		createdAt: time.Now(),
		ctx:       ctx,
	}
	s.end.done = make(chan struct{})
	s.setProtocol(proto)
	if c != nil {
		s.remoteAddr = c.RemoteAddr()
		s.localAddr = c.LocalAddr()
		if sc := schemeConnOf(c); sc != nil {
			s.hasSchemeField = true
			c = sc.Conn
		}
		if tc, ok := c.(connectionStater); ok {
			if state := tc.ConnectionState(); state.HandshakeComplete {
				s.tlsState.Store(&state)
			} else {
				// http.Server calls ConnContext before it performs the handshake, so the
				// state read here would be the zero one. Keeping the connection lets it be
				// read once it exists, which is any time a request is being served.
				s.pendingTLS = tc
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
	if s.pendingTLS != nil {
		// The handshake had not run when the session was created. tls.Conn guards its own
		// state, so reading it now is safe from any of the goroutines serving the connection.
		if state := s.pendingTLS.ConnectionState(); state.HandshakeComplete {
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
	if s.pendingTLS != nil {
		if state := s.pendingTLS.ConnectionState(); state.HandshakeComplete {
			return state.NegotiatedProtocol
		}
	}
	return ""
}

// Close ends the session at once, without draining, and the requests or streams in flight
// fail. Once it returns, [Proxy.Sessions] no longer reports the session and its context is
// done, even while a handler serving it has yet to return. It ends this session, the requests
// and the sessions on its connection, and nothing else. On the session of a connection to the
// proxy itself, it ends that connection with no GOAWAY. A byte stream ends with a reset on each
// of its connections, a request or a stream in flight with its reset, and a datagram flow stops
// relaying. The client is free to come back, to be authenticated and admitted again on the
// entries as they stand then. Closing a session that already ended is a no-op. Revoking an
// identity uses the same call, see [Session.Identity].
func (s *Session) Close() error {
	_ = s.endBy(causeClosed, time.Now().Add(alertWriteTimeout))
	return nil
}

// endBy ends the session by deadline with the forms c gives, unless an earlier cause did, I1.
// A later call lowers the deadline of the end in progress and returns once it ended.
func (s *Session) endBy(c cause, deadline time.Time) error { return s.endAfter(c, deadline, nil) }

// endAfter is endBy with answer, the answer of a refusal, written once c is stored and before
// the closer runs, so no later cause changes the forms of the session.
func (s *Session) endAfter(c cause, deadline time.Time, answer func()) error {
	if s.p == nil || s.end.done == nil {
		if answer != nil {
			answer()
		}
		return nil
	}
	if !s.end.begin(c, deadline) {
		<-s.end.done
		return s.closeErr
	}
	defer close(s.end.done)
	if answer != nil {
		answer()
	}
	closer, carried := s.p.srv.endSession(s)
	if closer == nil || c == causeHandedOver {
		return nil
	}
	c = s.end.first()
	if c == causeCarrierEnded && (s.inFlight(closer) || streamFailed(closer, s.end.by())) {
		// A peer end of the carrier fails a unit with a message in flight, and one the peer
		// reset before it ended the carrier, I3.
		c = causePeerFailed
		s.end.cause.Store(uint32(c))
	}
	// What the session carries ends before the connection under it, I3, and before the
	// contexts it derives from are canceled, so a handler returning on its context finds the
	// cause of the carrier stored.
	if len(carried) > 0 {
		var wg sync.WaitGroup
		for _, sub := range carried {
			wg.Go(func() { _ = sub.endBy(carriedCause(c), s.end.by()) })
		}
		wg.Wait()
	}
	s.p.srv.requests.closeOf(s)
	s.endRequests()
	if s.Protocol() == HTTP3 && !s.p.srv.requests.waitOf(s, s.end.by()) {
		// quic-go resets the stream of a request only as its handler returns, so the
		// connection waits for it, and one still in flight at the deadline gives it its failed
		// end, docs/lifecycle.md Limits.
		c = causeTimeout
	}
	// The closer comes first, so a handler returning on its context cannot end the stream
	// cleanly before the cut resets it.
	if err := closer.endBy(c, s.end.by()); err != nil && !errors.Is(err, net.ErrClosed) {
		s.closeErr = err
	}
	if s.cancel != nil {
		s.cancel()
	}
	return s.closeErr
}

// armRequests sets cancel as the end of the requests of the session and streams as the context
// they derive from, for a server that reads its connection after the session was registered.
// A session that already ended them runs cancel at once.
func (s *Session) armRequests(cancel context.CancelFunc, streams context.Context) {
	srv := s.p.srv
	srv.mu.Lock()
	ended := s.requestsEnded
	if !ended {
		s.cancelRequests, s.streamsCtx = cancel, streams
	}
	srv.mu.Unlock()
	if ended {
		cancel()
	}
}

// endRequests cancels the context of the requests of the session.
func (s *Session) endRequests() {
	srv := s.p.srv
	srv.mu.Lock()
	cancel := s.cancelRequests
	s.requestsEnded = true
	srv.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// endWith runs the closer of the session once parent ends, with the cause that ended it, as
// quic-go ends the streams of a connection with its close error. parent is the context the
// session was opened under, the request context of a stream. The returned function stops it.
func (s *Session) endWith(parent context.Context) func() bool {
	return context.AfterFunc(parent, func() {
		_ = s.endBy(s.causeOfParent(parent), time.Now().Add(alertWriteTimeout))
	})
}

// parentOf returns the context the session a request r opens ends with: on HTTP/2 and HTTP/3
// the context of its connection, a reset of the stream reaching the session as a read, I1.
// net/http cancels the request context at a reset of the stream, and quic-go once the proxy
// ended the send side of the stream, docs/lifecycle.md Limits.
func parentOf(r *http.Request, carrier *Session) context.Context {
	if r.ProtoMajor >= 2 && carrier != nil && carrier.streamsCtx != nil {
		return carrier.streamsCtx
	}
	return r.Context()
}

// causeOfParent is the cause a session reads in the end of parent: the cut, the cause of its
// carrier once the carrier ended, and otherwise a peer end of the carrier, a failure unless
// the error that ended parent reads as a clean end.
func (s *Session) causeOfParent(parent context.Context) cause {
	err := context.Cause(parent)
	if errors.Is(err, errCut) {
		return causeCut
	}
	if c, ok := s.carrierEnd(); ok {
		return c
	}
	if cleanEnd(err) {
		return causeCarrierEnded
	}
	return causePeerFailed
}

// endedWithConn reports whether err ended a stream because its connection ended, where a reset
// of the stream or a message it broke is a failure of the stream itself. net/http gives the
// streams of an HTTP/2 connection that ended the error "client disconnected", which it does not
// export.
func endedWithConn(err error) bool {
	if _, ok := errors.AsType[*quic.ApplicationError](err); ok {
		return true
	}
	if _, ok := errors.AsType[*quic.IdleTimeoutError](err); ok {
		return true
	}
	return err != nil && strings.Contains(err.Error(), "client disconnected")
}

// carrierEnd returns the cause the end of its carrier gives the session, once the carrier
// ended or the connection under it read the end of its peer. net/http ends the streams of a
// connection before its close runs the closer of the carrier.
func (s *Session) carrierEnd() (cause, bool) {
	if s.carrier == nil {
		return causeNone, false
	}
	if c := s.carrier.end.first(); c != causeNone {
		return carriedCause(c), true
	}
	switch peerEndOf(s.carrier.httpConn) {
	case peerClean:
		return carriedCause(causePeer), true
	case peerFailed:
		return carriedCause(causePeerFailed), true
	}
	return causeNone, false
}

// inFlight reports whether a message of the session is in flight: a request it carries, or a
// stream of the connection its closer ends.
func (s *Session) inFlight(closer sessionCloser) bool {
	if s.p.srv.requests.hasOf(s) {
		return true
	}
	f, ok := closer.(interface{ inFlight() bool })
	return ok && f.inFlight()
}

// streamFailed reports whether the peer reset the stream a closer ends or broke its framing
// before it ended the carrier, the read of that stream waited for until deadline.
func streamFailed(closer sessionCloser, deadline time.Time) bool {
	f, ok := closer.(interface{ streamFailed(time.Time) bool })
	return ok && f.streamFailed(deadline)
}

// waitUntil reports whether done is closed by deadline, a done already closed reading true at a
// deadline already past.
func waitUntil(done <-chan struct{}, deadline time.Time) bool {
	select {
	case <-done:
		return true
	default:
	}
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

// carriedCause is the cause a unit gets from the end of its carrier with cause c, I3.
func carriedCause(c cause) cause {
	switch c {
	case causePeer, causeReturned:
		return causeCarrierEnded
	case causeHandlerErr, causeTimeout:
		return causePeerFailed
	}
	return c
}

// handOver ends the session at the hijack of its socket by a session it registers, with no end
// form. A later Close returns nil.
func (s *Session) handOver() {
	if s == nil {
		return
	}
	_ = s.endBy(causeHandedOver, time.Now())
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

// cause is why a unit ends. The first cause stored decides the end forms of the unit.
type cause uint32

const (
	causeNone cause = iota
	// causePeer is a leg its peer ended normally.
	causePeer
	// causePeerFailed is a leg its peer ended with a failure or on which it broke its protocol.
	causePeerFailed
	causeReturned
	causeHandlerErr
	causeClosed
	causeCut
	// causeRefused is a refusal the proxy answered, causeRejected one with no answer.
	causeRefused
	causeRejected
	// causeIdle is a timer the Timers table of docs/lifecycle.md gives as normal.
	causeIdle
	// causeTimeout is a timer that table gives as failed.
	causeTimeout
	// causeHandedOver ends a connection whose socket a session it registered took, with no form.
	causeHandedOver
	// causeCarrierEnded is the normal end of a carrier, which a byte stream on it reads as a
	// failure, I3.
	causeCarrierEnded
)

func (c cause) failed() bool {
	return c == causePeerFailed || c == causeHandlerErr || c == causeTimeout
}

// form is the end a layer gets.
type form uint8

const (
	formNone form = iota
	formNormal
	formFailed
)

// class is the class of a unit, which decides with its cause the form of its layers.
type class uint8

const (
	byteStream class = iota
	framed
	datagramFlow
)

// formOf is the form a layer of a unit of class cl gets when c ends the unit, I2. answered
// reports an answer of the proxy other than the acceptance.
func formOf(cl class, c cause, answered bool) form {
	switch {
	case c == causeHandedOver:
		return formNone
	case cl == datagramFlow:
		return formNormal
	case cl == byteStream:
		if c == causePeer || c == causeReturned || c == causeRefused || answered {
			return formNormal
		}
		return formFailed
	case c.failed():
		return formFailed
	}
	return formNormal
}

// unitEnd is the end of one unit. The first cause wins, as the close error of a quic-go
// connection does, and the deadline only moves earlier, I4.
type unitEnd struct {
	// done is closed once the closer ended.
	done     chan struct{}
	deadline atomic.Int64
	cause    atomic.Uint32
}

// begin stores c unless a cause is stored, lowers the deadline to d, and reports whether c is
// the first cause.
func (e *unitEnd) begin(c cause, d time.Time) bool {
	first := e.cause.CompareAndSwap(uint32(causeNone), uint32(c))
	n := d.UnixNano()
	for {
		old := e.deadline.Load()
		if old != 0 && old <= n || e.deadline.CompareAndSwap(old, n) {
			return first
		}
	}
}

func (e *unitEnd) first() cause { return cause(e.cause.Load()) }

func (e *unitEnd) by() time.Time { return time.Unix(0, e.deadline.Load()) }

// sessionCloser ends the legs of a session with the forms c gives, by deadline, I2 and I4.
type sessionCloser interface {
	endBy(c cause, deadline time.Time) error
}
