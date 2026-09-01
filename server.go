// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"iter"
	"log"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fox-toolkit/edge/internal/stringsutil"
)

type sessionKey struct{}

// server owns everything that is not routing: the listeners, the connections accepted on
// them, and the transports used to reach upstreams.
type server struct {
	p   *Proxy
	fwd *forwarder

	// h1 serves the explicit proxy port; mitm serves the connections the proxy terminated
	// itself, which speak origin semantics rather than proxy semantics.
	h1   *http.Server
	mitm *http.Server

	listeners map[*net.Listener]struct{}
	// active tracks connections the proxy owns outside of http.Server, which is every
	// connection it terminated. It answers what a shutdown must close, so a connection enters
	// it as soon as it is accepted, before anything has decided it.
	active map[io.Closer]struct{}
	// sessions is what [Proxy.Sessions] reports. A session enters it only once its target is
	// resolved, so a caller never sees one it cannot pass to [Proxy.Admits].
	sessions map[*Session]struct{}
	// quics tracks the QUIC demultiplexers. Their connections own their sessions under a
	// separate lock, merged when the sessions are read rather than mirrored here, so no
	// invariant spans the two locks.
	quics    map[*quicDemux]struct{}
	closed   chan struct{}
	wg       sync.WaitGroup
	closeOne sync.Once

	mu      sync.Mutex
	closing atomic.Bool
}

func newServer(p *Proxy) (*server, error) {
	fwd, err := newForwarder(p)
	if err != nil {
		return nil, err
	}

	s := &server{
		p:         p,
		fwd:       fwd,
		listeners: make(map[*net.Listener]struct{}),
		active:    make(map[io.Closer]struct{}),
		sessions:  make(map[*Session]struct{}),
		quics:     make(map[*quicDemux]struct{}),
		closed:    make(chan struct{}),
	}

	// A client may speak HTTP/2 over plaintext, with the connection preface instead of ALPN.
	// Without unencrypted HTTP/2 enabled it is answered as if it had sent a request whose
	// method is "PRI". Both servers can receive one, and for mitm it is the only HTTP/2
	// path: an intercepted connection arrives with its TLS already terminated, so even a
	// client that negotiated h2 through ALPN reaches the server as plaintext carrying the
	// preface every HTTP/2 connection must start with.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)

	http2Cfg := &http.HTTP2Config{
		MaxConcurrentStreams: p.cfg.server.maxConcurrentStreams,
		MaxReadFrameSize:     1 << 20,
	}

	s.h1 = &http.Server{
		Handler:           http.HandlerFunc(p.serveProxyRequest),
		Protocols:         protocols,
		HTTP2:             http2Cfg,
		ReadHeaderTimeout: p.cfg.server.readHeaderTimeout,
		ReadTimeout:       p.cfg.server.readTimeout,
		WriteTimeout:      p.cfg.server.writeTimeout,
		IdleTimeout:       p.cfg.server.idleTimeout,
		MaxHeaderBytes:    p.cfg.server.maxHeaderBytes,
		ErrorLog:          log.New(slogWriter{p.cfg.logger}, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			// A connection without a wrapper keeps the server context, since a cancel
			// nothing ever calls would leak.
			if cc := cancelConnOf(c); cc != nil {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cc.arm(cancel)
			}
			return context.WithValue(ctx, sessionKey{}, newSession(ctx, c, Target{}, KindHTTP, HTTP11))
		},
	}

	s.mitm = &http.Server{
		Handler:           http.HandlerFunc(p.serveTerminatedRequest),
		Protocols:         protocols,
		HTTP2:             http2Cfg,
		ReadHeaderTimeout: p.cfg.server.readHeaderTimeout,
		ReadTimeout:       p.cfg.server.readTimeout,
		WriteTimeout:      p.cfg.server.writeTimeout,
		IdleTimeout:       p.cfg.server.idleTimeout,
		MaxHeaderBytes:    p.cfg.server.maxHeaderBytes,
		ErrorLog:          log.New(slogWriter{p.cfg.logger}, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if sc, ok := c.(*servedConn); ok {
				return context.WithValue(ctx, sessionKey{}, sc.sess)
			}
			return ctx
		},
	}

	return s, nil
}

// ListenAndServe listens on addr and serves as an explicit forward proxy. Clients point at
// it with their proxy setting: plain HTTP requests carry an absolute target, HTTPS requests
// start with CONNECT.
//
// ListenAndServe always returns a non-nil error. After [Proxy.Shutdown] or [Proxy.Close] it
// returns [ErrProxyClosed].
func (p *Proxy) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	// This call built the listener, and a refused Serve never takes it over.
	defer func() { _ = ln.Close() }()
	return p.Serve(ln)
}

// Serve accepts connections on ln and serves them as an explicit forward proxy.
//
// Prefer [Proxy.ServeTLS] over a TLS listener built by the caller. Such a listener still
// works, but the [Session.Context] of its connections never ends.
func (p *Proxy) Serve(ln net.Listener) error {
	return p.serveFront(cancelListener{ln})
}

func (p *Proxy) serveFront(ln net.Listener) error {
	if p.srv.closing.Load() {
		return ErrProxyClosed
	}
	// The listener is not tracked. http.Server closes the one it serves on every return path,
	// and closing it here as well would make its own Shutdown report the second close.
	err := p.srv.h1.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return ErrProxyClosed
	}
	return err
}

// ListenAndServeTLS listens on addr and serves as an explicit forward proxy reached over
// TLS. The certificate authenticates the proxy itself, not the authorities it intercepts,
// so it must be one the client already trusts for that name.
func (p *Proxy) ListenAndServeTLS(addr string, cert tls.Certificate) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	return p.ServeTLS(ln, cert)
}

// ServeTLS accepts TLS connections on ln and serves them as an explicit forward proxy.
func (p *Proxy) ServeTLS(ln net.Listener, cert tls.Certificate) error {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	// The cancel wrapper sits under the TLS listener, where it cannot hide the handshake
	// from net/http.
	return p.serveFront(tls.NewListener(cancelListener{ln}, cfg))
}

// Shutdown stops accepting new connections, then waits for the requests in flight to finish.
// The servers drain together: idle HTTP/1.1 connections are closed, HTTP/2 and HTTP/3
// connections are told with a GOAWAY, and every request already started runs to completion.
// A handler serving a whole connection, a stream or a datagram flow, ends when its peers do,
// so it is waited on until ctx is done and cut then, along with anything else still open.
// Without a deadline on ctx, Shutdown waits indefinitely.
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.srv.beginClose()

	err := p.srv.closeListeners()

	// Past the deadline, whatever draining could not end is cut: streams, upgraded pipes, and
	// connections still handshaking. Cutting them is what unblocks the waits below.
	stop := context.AfterFunc(ctx, p.srv.closeActive)
	defer stop()

	p.srv.mu.Lock()
	demuxes := slices.Collect(maps.Keys(p.srv.quics))
	p.srv.mu.Unlock()

	// The planes drain together. An intercepted connection carried on a CONNECT stream of
	// the front server only ends once the mitm server drains it, so draining one server
	// after the other would hold the first open until the deadline.
	errs := make([]error, 2+len(demuxes))
	var drains sync.WaitGroup
	drains.Go(func() { errs[0] = p.srv.h1.Shutdown(ctx) })
	drains.Go(func() { errs[1] = p.srv.mitm.Shutdown(ctx) })
	for i, d := range demuxes {
		drains.Go(func() { errs[2+i] = d.shutdown(ctx) })
	}

	// Each drain bounds itself by ctx, but the cut only closes sockets and no close can
	// force a handler to return. The deadline has to bound Shutdown itself, so the waits
	// are raced against it rather than trusted; past it, Shutdown returns and whatever a
	// handler still holds unwinds behind it once the handler does.
	drained := make(chan struct{})
	go func() { drains.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-ctx.Done():
		// The drains may still be writing errs, so it is not read; the deadline is the
		// whole report.
		p.srv.fwd.close()
		return errors.Join(err, ctx.Err())
	}

	// Every drain that ran into the deadline reports it; the deadline is one fact and it is
	// reported once, on the paths that know it cut something.
	for i, e := range errs {
		if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
			errs[i] = nil
		}
	}
	err = errors.Join(err, errors.Join(errs...))

	done := make(chan struct{})
	go func() { p.srv.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		err = errors.Join(err, ctx.Err())
	}

	p.srv.fwd.close()
	return err
}

// Close stops the proxy at once, dropping every connection including the traffic in flight.
func (p *Proxy) Close() error {
	p.srv.beginClose()
	err := errors.Join(p.srv.closeListeners(), p.srv.h1.Close(), p.srv.mitm.Close())
	p.srv.closeActive()
	p.srv.fwd.close()
	return err
}

// beginClose marks the proxy as stopping. Writing closing under the lock orders it against
// every registration: one that saw it unset committed inside a critical section that ran
// first, so the snapshots a shutdown takes under the same lock cannot miss it.
func (s *server) beginClose() {
	s.mu.Lock()
	s.closing.Store(true)
	s.mu.Unlock()
	s.closeOne.Do(func() { close(s.closed) })
}

// tryTrack registers a connection the proxy owns outside of http.Server and reports whether
// it may be served. A refusal means the proxy is stopping and the caller still owns the
// connection. The WaitGroup shares the critical section with [server.beginClose], so a
// successful Add always happens before a shutdown starts waiting; without that ordering an
// Add racing the Wait from a counter of zero is a runtime panic.
func (s *server) tryTrack(c io.Closer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing.Load() {
		return false
	}
	s.wg.Add(1)
	s.active[c] = struct{}{}
	return true
}

func (s *server) untrack(c io.Closer) {
	s.mu.Lock()
	delete(s.active, c)
	s.mu.Unlock()
	s.wg.Done()
}

// tryTrackListener is [server.tryTrack] for the listeners the proxy accepts on itself, which
// live in a registry of their own because a shutdown closes them first, before any draining.
func (s *server) tryTrackListener(ln *net.Listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing.Load() {
		return false
	}
	s.wg.Add(1)
	s.listeners[ln] = struct{}{}
	return true
}

func (s *server) untrackListener(ln *net.Listener) {
	s.mu.Lock()
	delete(s.listeners, ln)
	s.mu.Unlock()
	s.wg.Done()
}

// tryTrackDemux is [server.tryTrack] for a QUIC demultiplexer, which enters both registries
// in one critical section so a shutdown cannot see one without the other: missing quics
// would skip the drain, missing active would skip the cut at the deadline.
func (s *server) tryTrackDemux(d *quicDemux) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing.Load() {
		return false
	}
	s.wg.Add(1)
	s.active[d] = struct{}{}
	s.quics[d] = struct{}{}
	return true
}

func (s *server) untrackDemux(d *quicDemux) {
	s.mu.Lock()
	delete(s.active, d)
	delete(s.quics, d)
	s.mu.Unlock()
	s.wg.Done()
}

// trackSession adds or removes a session. The goroutine serving the connection makes both
// calls, so membership stays single-writer.
func (s *server) trackSession(sess *Session, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.sessions[sess] = struct{}{}
		return
	}
	delete(s.sessions, sess)
}

// admitSession registers a session and reports whether the tree still accepts it.
//
// The decision that let the connection in was read from the tree as it stood then, and a
// delete may have committed since. Reading it again, after the session is registered, leaves
// no window. A sweep that missed this session missed it because the registration came after
// the snapshot, so it also came after the delete, and this read sees that delete. Registering
// after the read would reopen the window.
func (s *server) admitSession(sess *Session) bool {
	// A connection served request by request is not decided as a connection at all, so there
	// is nothing to register and nothing a sweep could act on. Only the kind actually serving
	// it says whether that is what happened.
	if sess.perRequest && sess.kind == KindHTTP {
		return true
	}

	s.trackSession(sess, true)
	if s.p.Admits(sess.target, sess.kind) {
		return true
	}
	s.trackSession(sess, false)
	return false
}

// Sessions returns an iterator over a point-in-time snapshot of the connections the proxy is
// serving. Each [Session] is one client connection, a CONNECT tunnel, a redirected TLS or
// QUIC connection, or a datagram flow, and covers every request or stream multiplexed on it.
// A protocol upgrade is reported as a session of its own, under the authority its request
// was routed on. Connections addressed to the proxy itself are not reported, and neither is
// a redirected plaintext connection decided on the Host header of each request.
//
// Deleting an entry does not close the connections already open. Use Sessions with
// [Session.Close] to end them.
//
//	p.Delete[edge.TCP]("example.com")
//	for s := range p.Sessions() {
//		if !p.Admits(s.Target(), s.Kind()) {
//			s.Close()
//		}
//	}
func (p *Proxy) Sessions() iter.Seq[*Session] {
	p.srv.mu.Lock()
	out := make([]*Session, 0, len(p.srv.sessions))
	for sess := range p.srv.sessions {
		out = append(out, sess)
	}
	demuxes := make([]*quicDemux, 0, len(p.srv.quics))
	for d := range p.srv.quics {
		demuxes = append(demuxes, d)
	}
	p.srv.mu.Unlock()

	// A demux owns its connections under a lock of its own, taken here only once the server
	// lock is released, so the two are never held at once.
	for _, d := range demuxes {
		out = d.appendSessions(out)
	}
	return slices.Values(out)
}

// closeListeners closes the listeners the proxy accepts on itself. A listener http.Server
// serves is not among them, it closes that one itself.
func (s *server) closeListeners() error {
	s.mu.Lock()
	lns := make([]*net.Listener, 0, len(s.listeners))
	for ln := range s.listeners {
		lns = append(lns, ln)
	}
	s.mu.Unlock()

	var err error
	for _, ln := range lns {
		if cerr := (*ln).Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) {
			err = errors.Join(err, cerr)
		}
	}
	return err
}

func (s *server) closeActive() {
	s.mu.Lock()
	conns := make([]io.Closer, 0, len(s.active))
	for c := range s.active {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	// Concurrently: a closer that blocks, a QUIC demux waiting out a handler that will not
	// return for instance, must not starve the cut of everything after it.
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Go(func() { _ = c.Close() })
	}
	wg.Wait()
}

// ServeHTTP serves one request with explicit forward proxy semantics: a CONNECT opens a
// connection, anything else is a plain HTTP request carrying an absolute target.
//
// It makes a Proxy an [http.Handler], so it can be mounted in a server you already own
// rather than given a listener of its own. The server must leave hijacking available, which
// authorities out anything that wraps the response writer without forwarding [http.Hijacker].
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.serveProxyRequest(w, r)
}

var _ http.Handler = (*Proxy)(nil)

// serveProxyRequest is the explicit forward proxy entry point: a CONNECT opens a connection,
// anything else is a plain HTTP request carrying an absolute target.
func (p *Proxy) serveProxyRequest(w http.ResponseWriter, r *http.Request) {
	// Before anything else, including the origin-form refusal below, so that an
	// unauthenticated client learns nothing from the answer it gets.
	identity, ok := p.authenticate(w, r)
	if !ok {
		return
	}

	if sess := sessionFromRequest(r); sess != nil {
		// ConnContext builds the session before ALPN or the h2c preface has set the protocol.
		sess.setProtocol(protoOfRequest(r))
	}

	if r.Method == http.MethodConnect {
		if isExtendedConnect(r) {
			http.Error(w, "edge: extended CONNECT is not served, WebSocket goes over HTTP/1.1",
				http.StatusNotImplemented)
			return
		}
		p.serveConnect(w, r, identity)
		return
	}

	target, ok := proxyTarget(r)
	if !ok {
		// An origin-form target on the proxy port means the client is not configured to use
		// a proxy. Answering with the target it should have sent is the only useful reply.
		http.Error(w, "edge: expected an absolute request target or CONNECT, this is a forward proxy", http.StatusBadRequest)
		return
	}

	sess := sessionFromRequest(r)
	if sess == nil {
		sess = newSession(r.Context(), nil, target, KindHTTP, protoOfRequest(r))
	}

	p.dispatchRequest(w, r, sess, target, identity)
}

// authenticate runs the configured proxy authenticator and answers the client itself when it
// refuses. It reports the identity and whether the request may go on.
func (p *Proxy) authenticate(w http.ResponseWriter, r *http.Request) (string, bool) {
	auth := p.cfg.proxyAuth
	if auth == nil {
		return "", true
	}

	if identity, ok := auth.Authenticate(r); ok {
		return identity, true
	}

	challenges := auth.Challenges(r)
	if len(challenges) == 0 {
		// Nothing the client could present would change the answer, so asking it to
		// authenticate would be a lie, and a 407 carrying no challenge is malformed.
		http.Error(w, "edge: proxy access denied", http.StatusForbidden)
		return "", false
	}

	header := w.Header()
	for _, challenge := range challenges {
		header.Add(HeaderProxyAuthenticate, challenge)
	}
	http.Error(w, "edge: proxy authentication required", http.StatusProxyAuthRequired)
	return "", false
}

// proxyTarget resolves the authority of an explicit proxy request, reporting false when the
// request gives none.
//
// HTTP/1.1 puts it in an absolute-form request target. HTTP/2 has no absolute form. RFC
// 9113 splits the target across :scheme, :authority and :path, which reach a handler as a
// relative URL, Host, and a TLS state net/http fills in only when :scheme is https. So an
// HTTP/2 request is indistinguishable from an origin-form one, and since a proxy connection
// carries nothing but proxy requests, it is read as one rather than refused.
func proxyTarget(r *http.Request) (Target, bool) {
	if r.URL != nil && r.URL.IsAbs() {
		return targetFromURL(r.URL), true
	}
	if r.ProtoMajor < 2 || r.Host == "" {
		return Target{}, false
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host, port := splitHostPort(r.Host)
	port = cmp.Or(port, defaultPort(scheme))
	return Target{Scheme: scheme, Host: stringsutil.ToLowerASCIIString(host), Port: port}, true
}

func targetFromURL(u *url.URL) Target {
	scheme := cmp.Or(u.Scheme, "http")
	host, port := splitHostPort(u.Host)
	port = cmp.Or(port, defaultPort(scheme))
	return Target{Scheme: scheme, Host: stringsutil.ToLowerASCIIString(host), Port: port}
}

func protoOfRequest(r *http.Request) Protocol {
	switch r.ProtoMajor {
	case 3:
		return HTTP3
	case 2:
		return HTTP2
	default:
		return HTTP11
	}
}

func sessionFromRequest(r *http.Request) *Session {
	sess, _ := r.Context().Value(sessionKey{}).(*Session)
	return sess
}

func newSession(ctx context.Context, c net.Conn, target Target, kind Kind, proto Protocol) *Session {
	s := &Session{
		id:        sessionSeq.Add(1),
		target:    target,
		kind:      kind,
		createdAt: time.Now(),
		ctx:       ctx,
	}
	s.setProtocol(proto)
	if c != nil {
		s.remoteAddr = c.RemoteAddr()
		s.localAddr = c.LocalAddr()
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

// slogWriter adapts the net/http error log to the configured structured logger.
type slogWriter struct{ l *slog.Logger }

func (w slogWriter) Write(b []byte) (int, error) {
	w.l.Debug("edge: server", slog.String("msg", strings.TrimRight(string(b), "\n")))
	return len(b), nil
}
