// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/stdapi/edge/internal/stringsutil"
)

// tlsHandshakeRecord is the TLS record type of a handshake message. A connection whose first
// byte is anything else is not TLS, which is how a CONNECT to a plaintext port is detected.
const tlsHandshakeRecord = 0x16

// tlsClientHello is the handshake type of a ClientHello, RFC 8446 section 4.
const tlsClientHello = 0x01

// The alert record and the descriptions of RFC 9846 section 6.2 the proxy sends when it
// refuses a ClientHello.
const (
	tlsAlertRecord        = 0x15
	alertLevelFatal       = 2
	alertHandshakeFailure = 40
	alertDecodeError      = 50
	alertInternalError    = 80
	alertMissingExtension = 109
	alertUnrecognizedName = 112
)

const (
	// alertWriteTimeout bounds the write of an alert, so a peer that stopped reading cannot
	// keep a connection open.
	alertWriteTimeout = time.Second
	// alertDrainTimeout and alertDrainLimit bound what is read and discarded after an alert. A
	// close with bytes left unread sends a reset, which can destroy the alert before the client
	// reads it.
	alertDrainTimeout = 500 * time.Millisecond
	alertDrainLimit   = 64 << 10
)

// refuseHello refuses the session of conn with alert, a cause of the session that its closer
// ends, I1, the alert and the read after it written once the cause is stored.
func refuseHello(sess *Session, conn net.Conn, alert byte, err error) error {
	answer := func() {
		if writeAlert(conn, alert) == nil {
			lingerClose(conn)
		}
	}
	if sess == nil {
		answer()
		return err
	}
	_ = sess.endAfter(causeRefused, time.Now().Add(alertDrainTimeout), answer)
	return err
}

// writeAlert sends a fatal alert on conn. No version is negotiated before the ServerHello, and
// RFC 9846 section 5.1 sets 0x0303 on every record but an initial ClientHello.
func writeAlert(conn net.Conn, alert byte) error {
	_ = conn.SetWriteDeadline(time.Now().Add(alertWriteTimeout))
	_, err := conn.Write([]byte{tlsAlertRecord, 0x03, 0x03, 0x00, 0x02, alertLevelFatal, alert})
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

// lingerClose closes the write direction of conn after an alert and drains what the client
// still sends, so the close that follows leaves nothing unread.
func lingerClose(conn net.Conn) {
	_ = closeWrite(conn)
	_ = conn.SetReadDeadline(time.Now().Add(alertDrainTimeout))
	_, _ = io.CopyN(io.Discard, conn, alertDrainLimit)
	_ = conn.SetReadDeadline(time.Time{})
}

// terminate takes over an admitted connection, terminating TLS when there is TLS, works out
// what the traffic is, and serves it.
//
// What a connection is comes from the traffic alone, the negotiated ALPN when the client
// offered one and the first bytes otherwise. That fixes the kinds that could serve it, most
// specific first, and the tree picks among those. An HTTP connection with only a stream entry
// on its authority is served as a stream, and both see it in the clear.
func (p *Proxy) terminate(ctx context.Context, conn *peekConn, sess *Session) error {
	head, err := peekFirst(conn, p.cfg.server.sniffTimeout)
	if isTimeout(err) {
		return p.serveSilent(ctx, conn, sess)
	}
	if err != nil {
		// A peer end before the first byte, a session that runs no handler, I1.
		if errors.Is(err, io.EOF) {
			_ = sess.endBy(causePeer, time.Now().Add(alertWriteTimeout))
			return nil
		}
		_ = sess.endBy(causePeerFailed, time.Now().Add(alertWriteTimeout))
		return err
	}

	if head[0] != tlsHandshakeRecord {
		// A CONNECT to a plaintext port.
		sess.target.Scheme = "http"
		return p.servePlain(ctx, conn, sess)
	}

	if p.cfg.ca == nil {
		return refuseHello(sess, conn, alertInternalError, fmt.Errorf("%w: %w", ErrNoCertificateAuthority, errNoCA))
	}
	// The read header timeout bounds the ClientHello and the handshake, and its expiry is the
	// failed end of the connection.
	if d := p.cfg.server.readHeaderTimeout; d > 0 {
		_ = conn.SetDeadline(time.Now().Add(d))
	}
	if err := p.placeTLS(ctx, conn, sess); err != nil {
		return err
	}

	tc := tlsServer(conn, p.serverTLSConfig(sess, false))
	if err := tc.HandshakeContext(ctx); err != nil {
		// crypto/tls reports the alert it sent as a local error, and sends none on a read error.
		var local *net.OpError
		switch {
		case isTimeout(err):
			_ = sess.endBy(causeTimeout, time.Now().Add(alertWriteTimeout))
		case errors.As(err, &local) && local.Op == "local error":
			// crypto/tls sent the alert of the handshake error, a refusal.
			_ = sess.endAfter(causeRefused, time.Now().Add(alertDrainTimeout), func() { lingerClose(conn) })
		default:
			_ = sess.endBy(causePeerFailed, time.Now().Add(alertWriteTimeout))
		}
		return fmt.Errorf("tls handshake with client for %s: %w", sess.target.Authority(), err)
	}
	_ = conn.SetDeadline(time.Time{})

	state := tc.ConnectionState()
	sess.tlsState.Store(&state)

	candidates := candidatesForALPN(state.NegotiatedProtocol, KindTCP)
	if candidates == nil {
		// The client offered no ALPN, so nothing has said what this is. Past the handshake
		// the payload is in the clear, which is exactly what the sniff reads.
		peeked := newPeekConn(tc, nil, defaultPeekSize)
		candidates = sniffStreamCandidates(peeked, p.cfg.server.sniffTimeout)
		served := p.serveCandidates(ctx, peeked, sess, candidates, &state)
		closeRefused(sess, tc, served)
		return served
	}
	served := p.serveCandidates(ctx, tc, sess, candidates, &state)
	closeRefused(sess, tc, served)
	return served
}

// closeRefused ends a session refused after its handshake: the failed end when the cut or its
// carrier ended it, and otherwise close_notify then the normal end of TCP within
// alertDrainTimeout, RFC 8446 section 6.1, docs/lifecycle.md Refusals.
func closeRefused(sess *Session, tc *tlsConn, err error) {
	switch {
	case errors.Is(err, errSessionEnded):
		tc.Abort()
	case errors.Is(err, ErrConnectionRejected):
		deadline := time.Now().Add(alertDrainTimeout)
		_ = sess.endAfter(causeRefused, deadline, func() { closeNormallyBy(tc, deadline) })
	}
}

// placeTLS decides the authority a TLS connection is routed on, before the handshake commits
// the proxy to a certificate. The server name routes when the client sent one, the destination
// the connection was headed to is what the proxy dials, and name verification stands between
// the two. Nothing is consumed, the handshake reads the same bytes after.
func (p *Proxy) placeTLS(ctx context.Context, conn *peekConn, sess *Session) error {
	hello, alert, err := p.peekClientHello(conn)
	if isTimeout(err) {
		// The read header timeout is a failed cause, I2.
		_ = sess.endBy(causeTimeout, time.Now().Add(alertWriteTimeout))
		return err
	}
	if isPeerReadFailure(err) {
		// The peer failed its leg inside the ClientHello, no refusal to answer.
		_ = sess.endBy(causePeerFailed, time.Now().Add(alertWriteTimeout))
		return err
	}
	if err != nil {
		return refuseHello(sess, conn, alert, err)
	}

	target := sess.target
	target.Scheme = "https"
	if target.Port == "" {
		target.Port = "443"
	}
	named := hello != nil && hello.ServerName != ""
	if named {
		target.Host = stringsutil.ToLowerASCIIString(hello.ServerName)
	}
	// A ClientHello the peek could not read may have a server name. It gets the alert Go's
	// TLS server sent on it, or the decode_error RFC 9846 section 6.2 gives a message that
	// does not parse.
	unnamed := byte(alertMissingExtension)
	if hello == nil {
		unnamed = cmp.Or(alert, alertDecodeError)
	}
	if target.Host == "" {
		return refuseHello(sess, conn, unnamed, errors.New("edge: TLS connection with no server name and no destination"))
	}

	target, admitted, verdict := p.targetForTransparent(ctx, target, sess.upstream, named, KindHTTP, KindTCP)
	switch verdict {
	case nameMismatch:
		return refuseHello(sess, conn, alertUnrecognizedName, errNameMismatch)
	case nameUnresolved:
		return refuseHello(sess, conn, alertUnrecognizedName, errNameUnresolved)
	}
	if !admitted {
		if !named {
			return refuseHello(sess, conn, unnamed, ErrConnectionRejected)
		}
		return refuseHello(sess, conn, alertUnrecognizedName, ErrConnectionRejected)
	}
	sess.target = target
	if hello != nil {
		sess.clientHello.Store(hello)
		p.seedVerified(sess, hello.ServerName, target)
	}
	return nil
}

// peekClientHello reads the ClientHello waiting on conn without consuming it, nil when there
// is none it can read, with the alert of clientHelloFromRecords. It refuses the connection with
// the alert to send when the hello offers Encrypted Client Hello and the proxy rejects that.
func (p *Proxy) peekClientHello(conn *peekConn) (*ClientHello, byte, error) {
	raw, err := peekHandshakeRecords(conn)
	if isTimeout(err) || isPeerReadFailure(err) {
		// A timer or a failure of the peer inside the ClientHello, which no alert answers.
		return nil, 0, err
	}
	if p.cfg.rejectECH {
		if err != nil {
			return nil, alertDecodeError, errECHUnverifiable
		}
		if cerr := checkECH(raw); cerr != nil {
			if errors.Is(cerr, errECHUnverifiable) {
				return nil, alertDecodeError, cerr
			}
			return nil, alertHandshakeFailure, cerr
		}
	}
	if err != nil {
		return nil, 0, nil
	}
	hello, alert := clientHelloFromRecords(raw)
	return hello, alert, nil
}

// isPeerReadFailure reports a read the peer failed, a reset, where a malformed message, an end
// of the peer or a timeout is none.
func isPeerReadFailure(err error) bool {
	if err == nil || isTimeout(err) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return false
	}
	_, ok := errors.AsType[*net.OpError](err)
	return ok
}

// peekFirst waits for the first byte of conn for at most sniff.
func peekFirst(conn *peekConn, sniff time.Duration) ([]byte, error) {
	if sniff > 0 && conn.Buffered() == 0 {
		_ = conn.SetReadDeadline(time.Now().Add(sniff))
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	return conn.Peek(1)
}

// serveSilent serves a connection that sent nothing within the sniff timeout, a protocol where
// the server sends first, as a byte stream placed on its destination. A stream nothing admits
// is reset, and so is a stream after its client begins TLS.
func (p *Proxy) serveSilent(ctx context.Context, conn *peekConn, sess *Session) error {
	sess.servableAs = []Kind{KindTCP}
	conn.lateHello = true
	err := p.serveCandidates(ctx, conn, sess, sess.servableAs, nil)
	if errors.Is(err, ErrConnectionRejected) {
		// A byte stream refused with no answer gets its failed end.
		_ = sess.endBy(causeRejected, time.Now().Add(alertWriteTimeout))
	}
	return err
}

// servePlain serves a connection without TLS, routed on the authority of its first request. A
// stream nothing admits is reset.
func (p *Proxy) servePlain(ctx context.Context, conn *peekConn, sess *Session) error {
	candidates := sniffStreamCandidates(conn, p.cfg.server.sniffTimeout)
	sess.servableAs = candidates
	if !slices.Contains(candidates, KindHTTP) {
		err := p.serveCandidates(ctx, conn, sess, candidates, nil)
		if errors.Is(err, ErrConnectionRejected) {
			_ = sess.endBy(causeRejected, time.Now().Add(alertWriteTimeout))
		}
		return err
	}
	placed, err := p.placePlain(ctx, conn, sess)
	if placed == plainFailed {
		// The peer failed its leg inside the first request header, no answer to write.
		_ = sess.endBy(causePeerFailed, time.Now().Add(alertWriteTimeout))
		return err
	}
	if placed == plainTimedOut {
		// An answer, so the connection gets its normal end, docs/lifecycle.md Refusals.
		_ = sess.endAfter(causeRefused, time.Now().Add(alertWriteTimeout), func() {
			err = writeRawStatus(conn, http.StatusRequestTimeout)
		})
		return err
	}
	if placed != plainRefused && p.admitsAny(sess.target, candidates...) {
		return p.serveCandidates(ctx, conn, sess, candidates, nil)
	}
	// Refused in HTTP, once for all when the first request has a host, as a handshake ends on a
	// server name nothing admits. Without a host, each request is routed on its own.
	sess.kind = KindHTTP
	sess.perRequest = true
	sess.refused = placed != plainNameless
	return p.serveHTTPConnection(conn, sess, nil)
}

// plainPlacement is the outcome of placePlain.
type plainPlacement uint8

const (
	plainNameless plainPlacement = iota
	plainNamed
	plainRefused
	plainTimedOut
	plainFailed
)

// placePlain routes a plaintext HTTP connection on the host of its first request, as placeTLS
// does on the server name, verification included. The port stays the connection's, and nothing
// is consumed, the server reads the same bytes after. The error is that of a read that timed out
// or that the peer failed.
func (p *Proxy) placePlain(ctx context.Context, conn *peekConn, sess *Session) (plainPlacement, error) {
	if d := p.cfg.server.readHeaderTimeout; d > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(d))
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}
	// The read-ahead was sized for a ClientHello, and a header block runs to what the server
	// accepts.
	limit := p.cfg.server.maxHeaderBytes
	conn.max = max(conn.max, limit)

	authority, err := peekAuthority(conn, limit)
	if isTimeout(err) {
		return plainTimedOut, err
	}
	if isPeerReadFailure(err) {
		return plainFailed, err
	}
	host, _, ok := splitAuthority(authority)
	if !ok || host == "" {
		// A malformed authority gets a 400 on the request it opens.
		return plainNameless, nil
	}
	target := sess.target
	target.Host = canonicalHost(stringsutil.ToLowerASCIIString(host))
	verified, ok := p.verifyRequestHost(ctx, sess, target, KindHTTP, KindTCP)
	if !ok {
		return plainRefused, nil
	}
	sess.target = verified
	if verified.Host != target.Host {
		return plainNameless, nil
	}
	return plainNamed, nil
}

// serveCandidates serves the connection at the finest granularity its authority admits, and
// closes it when none is admitted.
func (p *Proxy) serveCandidates(ctx context.Context, conn net.Conn, sess *Session, candidates []Kind, state *tls.ConnectionState) error {
	sess.servableAs = candidates
	if kind, e, params := p.firstAdmittedWith(sess.target, candidates); kind != 0 {
		sess.kind = kind
		if kind == KindHTTP {
			return p.serveHTTPConnection(conn, sess, state)
		}
		return p.serveTerminatedStream(ctx, conn, sess, state, e, params)
	}

	return ErrConnectionRejected
}

// serveHTTPConnection records the version the handshake settled on and hands the connection to
// the HTTP server.
func (p *Proxy) serveHTTPConnection(conn net.Conn, sess *Session, state *tls.ConnectionState) error {
	if state != nil {
		sess.setProtocol(protocolFromALPN(state.NegotiatedProtocol))
	}
	if sess.Protocol() == 0 {
		sess.setProtocol(HTTP11)
	}
	return p.serveTerminatedHTTP(conn, sess, state)
}

// serveTerminatedStream runs the [TCP] handler admitting this authority. The stream is in the
// clear here, whatever it was wrapped in on the wire.
func (p *Proxy) serveTerminatedStream(ctx context.Context, conn net.Conn, sess *Session,
	state *tls.ConnectionState, e *entry, params []Param,
) error {
	sess.entry.Store(e)
	if sess.remoteAddr == nil {
		sess.remoteAddr = conn.RemoteAddr()
	}
	if sess.localAddr == nil {
		sess.localAddr = conn.LocalAddr()
	}
	c := &TCPCtx{
		ctx:      ctx,
		p:        p,
		sess:     sess,
		entry:    e,
		client:   heldConn{Conn: conn},
		params:   params,
		target:   sess.target,
		identity: sess.identity,
		tlsState: state,
	}
	if err := p.srv.admitSession(sess, (*tcpCloser)(c)); err != nil {
		return err
	}
	defer p.srv.untrackSession(sess)

	handler, _ := e.serve.(TCP)
	if handler == nil {
		c.end(errNoHandler)
		return errNoHandler
	}
	err := runKindHandler(p, sess, func() error { return handler(c) })
	c.end(err)
	return err
}

// serverTLSConfig builds the configuration the proxy presents to a terminated client. The
// whole configuration is decided from the ClientHello so the certificate matches the name the
// client asked for and the negotiated protocol matches what it offered.
//
// With decided unset, an offer with no HTTP protocol on an authority admitting no stream ends
// the handshake on no_application_protocol, RFC 7301 section 3.2.
func (p *Proxy) serverTLSConfig(sess *Session, decided bool) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			sess.clientHello.Store(&ClientHello{
				ServerName:        chi.ServerName,
				ALPN:              slices.Clone(chi.SupportedProtos),
				SupportedVersions: slices.Clone(chi.SupportedVersions),
				CipherSuites:      slices.Clone(chi.CipherSuites),
			})

			name := chi.ServerName
			if name == "" {
				// A client that sends no SNI, typically one connecting to an IP address,
				// still needs a certificate for the authority it asked to reach.
				name = sess.target.Host
			}

			next := negotiateALPN(chi.SupportedProtos, KindTCP)
			if !decided && len(next) == 1 && !slices.Contains(httpOver(KindTCP), next[0]) &&
				!p.admitsAny(sess.target, KindTCP) {
				// Offering only what the client did not makes crypto/tls send the alert.
				next = httpOver(KindTCP)
			}

			return &tls.Config{
				MinVersion: tls.VersionTLS12,
				NextProtos: next,
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					leaf, err := p.cfg.ca.Leaf(name)
					if err == nil {
						sess.leaf.Store(leaf.Leaf)
					}
					return leaf, err
				},
			}, nil
		},
	}
}

// serveTerminatedHTTP serves a terminated connection on term, whose one HTTP/2 server ties it
// to the graceful shutdown. ALPN selects the protocol over TLS, the connection preface over
// plaintext.
func (p *Proxy) serveTerminatedHTTP(conn net.Conn, sess *Session, state *tls.ConnectionState) error {
	if sess.remoteAddr == nil {
		sess.remoteAddr = conn.RemoteAddr()
	}
	if sess.localAddr == nil {
		sess.localAddr = conn.LocalAddr()
	}

	// Every terminated connection settles here, however it arrived, so this is the single
	// point where its session is admitted with a target a reader can rely on.
	sess.httpConn = conn
	if err := p.srv.admitSession(sess, normalEnd{conn}); err != nil {
		return err
	}
	defer p.srv.untrackSession(sess)

	ln := newSingleConnListener(conn, sess, state)
	srv := p.srv.term
	if p.terminatedHTTP2(conn, state) {
		srv = p.srv.term2
	} else {
		key := ln.conn
		begun := func() { p.srv.notFresh(key) }
		servedOf(key).begun.Store(&begun)
		p.srv.addFresh(key)
		defer p.srv.notFresh(key)
	}
	err := srv.Serve(ln)
	if srv == p.srv.term2 && errors.Is(err, http.ErrServerClosed) && !ln.isTaken() {
		// The drain shut its server down before the connection reached it.
		late := p.srv.newTerm(p.srv.term2.Protocols)
		shutdownOnceServing(late)
		err = late.Serve(ln)
	}
	ln.wait()
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// terminatedHTTP2 reports whether a terminated connection uses HTTP/2, from the ALPN of its
// handshake or the preface of a plaintext one, read within the read header timeout.
func (p *Proxy) terminatedHTTP2(conn net.Conn, state *tls.ConnectionState) bool {
	if state != nil {
		return state.NegotiatedProtocol == "h2"
	}
	pc, ok := conn.(*peekConn)
	if !ok {
		return false
	}
	if d := p.cfg.server.readHeaderTimeout; d > 0 {
		_ = pc.SetReadDeadline(time.Now().Add(d))
		defer func() { _ = pc.SetReadDeadline(time.Time{}) }()
	}
	// Byte by byte past what is buffered, so a short HTTP/1.1 request is told apart without
	// waiting for more.
	n := max(pc.Buffered(), 1)
	for {
		b, err := pc.Peek(min(n, len(h2Preface)))
		switch {
		case string(b) != h2Preface[:len(b)]:
			return false
		case len(b) == len(h2Preface):
			return true
		case err != nil:
			return false
		}
		n = len(b) + 1
	}
}

// serveTerminatedRequest routes one request read off a terminated connection.
func (p *Proxy) serveTerminatedRequest(w http.ResponseWriter, r *http.Request) {
	rq := p.srv.requests.begin(w, r)
	if rq == nil {
		rejectRequest(w, r)
	}
	defer p.srv.requests.end(rq, w, r)

	if r.Method == "PRI" && r.ProtoMajor == 2 && r.RequestURI == "*" {
		// The preface's request line read as HTTP/1.1, over TLS where ALPN did not select h2, RFC
		// 7301 section 3.2, or in plaintext after 24 octets that are not the exact preface.
		w.Header().Set("Connection", "close")
		p.writeStatus(w, r, http.StatusBadRequest, "HTTP/2 preface read as an HTTP/1.1 request")
		return
	}

	sess := sessionFromRequest(r)
	if sess == nil {
		sess = newSession(p, r.Context(), nil, Target{}, KindHTTP, protoOfRequest(r))
	}
	// A plaintext connection is announced as HTTP/1.1 before http.Server has had a chance to
	// read a connection preface. The request knows what was negotiated.
	sess.setProtocol(protoOfRequest(r))

	if sess.refused {
		w.Header().Set("Connection", "close")
		p.writeStatus(w, r, http.StatusForbidden, "no entry admits this authority")
		return
	}
	if p.refuseNewSession(w, r) {
		return
	}

	if !validRequestTarget(r) {
		p.writeStatus(w, r, http.StatusBadRequest, errRequestTargetForm.Error())
		return
	}
	target, ok := terminatedTarget(r, sess)
	if !ok {
		p.writeStatus(w, r, http.StatusBadRequest, errRequestAuthority.Error())
		return
	}
	if r.TLS != nil || sess.TLS() != nil {
		if leaf := sess.leaf.Load(); leaf == nil || !leafCovers(leaf, target.Host) {
			p.writeStatus(w, r, http.StatusMisdirectedRequest, "the certificate of the connection is not valid for the host")
			return
		}
	}
	if r.URL.IsAbs() {
		// The connection is the target, so its scheme is the scheme of the request, for the
		// forward as for the routing.
		r.URL.Scheme = target.Scheme
	}
	if sess.upstream.IsValid() {
		if target, ok = p.verifyRequestHost(r.Context(), sess, target, KindHTTP); !ok {
			if r.ProtoMajor == 1 {
				w.Header().Set("Connection", "close")
			}
			p.writeStatus(w, r, http.StatusForbidden, "the host does not resolve to the destination")
			return
		}
	}

	// Nothing on a terminated connection is challenged, since the client believes it is
	// talking to the origin. The identity is the one of whatever established the connection,
	// or none.
	p.dispatchRequest(w, r, sess, target, sess.identity, rq)
}

// leafCovers reports whether leaf, minted by a [CA], is valid for host, a hostname in lower
// case without its root dot or an IP address. A zoned address is valid for no leaf, as with
// x509.Certificate.VerifyHostname.
func leafCovers(leaf *x509.Certificate, host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		for _, ip := range leaf.IPAddresses {
			if a, ok := netip.AddrFromSlice(ip); ok && a.Unmap() == addr.Unmap() {
				return true
			}
		}
		return false
	}
	return slices.Contains(leaf.DNSNames, host)
}

// terminatedTarget resolves the target of a request read off a terminated connection from its
// Host header, with the port of the connection when the header has none. The caller then checks
// that host against the certificate of the connection and, under name verification, against
// its destination.
func terminatedTarget(r *http.Request, sess *Session) (Target, bool) {
	scheme := sess.target.Scheme
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host, port, ok := splitAuthority(r.Host)
	if !ok {
		return Target{}, false
	}
	if host == "" {
		host = sess.target.Host
	}
	if port == "" {
		port = sess.target.Port
	}
	if port == "" {
		port = defaultPort(scheme)
	}

	return Target{Scheme: scheme, Host: canonicalHost(stringsutil.ToLowerASCIIString(host)), Port: port}, true
}
