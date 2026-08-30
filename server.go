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
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fox-toolkit/edge/internal/stringsutil"
	"golang.org/x/net/http2"
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
	h2   *http2.Server

	listeners map[*net.Listener]struct{}
	// active tracks connections the proxy owns outside of http.Server, which is every
	// tunnel and every intercepted connection. It answers what a shutdown must close, so a
	// connection enters it as soon as it is accepted, before anything has decided it.
	active map[io.Closer]struct{}
	// sessions is what [Proxy.Sessions] reports. A session enters it only once its target is
	// resolved, so a caller never sees one it cannot pass to [Proxy.Decide].
	sessions map[*Session]struct{}
	// quics tracks the QUIC demultiplexers. Their peers own their sessions under a separate
	// lock, merged when the sessions are read rather than mirrored here, so no invariant
	// spans the two locks.
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

	s.h2 = &http2.Server{
		MaxConcurrentStreams: p.cfg.server.maxConcurrentStreams,
		IdleTimeout:          p.cfg.server.idleTimeout,
		MaxReadFrameSize:     1 << 20,
	}

	// A client may speak HTTP/2 over plaintext, with the connection preface instead of ALPN.
	// Without unencrypted HTTP/2 enabled it is answered as if it had sent a request whose
	// method is "PRI". Both servers can receive one.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)

	s.h1 = &http.Server{
		Handler:           http.HandlerFunc(p.serveProxyRequest),
		Protocols:         protocols,
		ReadHeaderTimeout: p.cfg.server.readHeaderTimeout,
		ReadTimeout:       p.cfg.server.readTimeout,
		WriteTimeout:      p.cfg.server.writeTimeout,
		IdleTimeout:       p.cfg.server.idleTimeout,
		MaxHeaderBytes:    p.cfg.server.maxHeaderBytes,
		ErrorLog:          log.New(slogWriter{p.cfg.logger}, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, sessionKey{}, newSession(ctx, c, Target{}, Intercept, HTTP11))
		},
	}

	s.mitm = &http.Server{
		Handler:           http.HandlerFunc(p.serveInterceptedRequest),
		Protocols:         protocols,
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
	return p.Serve(ln)
}

// Serve accepts connections on ln and serves them as an explicit forward proxy.
func (p *Proxy) Serve(ln net.Listener) error {
	if p.srv.closing.Load() {
		return ErrProxyClosed
	}
	p.srv.trackListener(&ln, true)
	defer p.srv.trackListener(&ln, false)

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
	return p.ServeTLS(ln, cert)
}

// ServeTLS accepts TLS connections on ln and serves them as an explicit forward proxy.
func (p *Proxy) ServeTLS(ln net.Listener, cert tls.Certificate) error {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	return p.Serve(tls.NewListener(ln, cfg))
}

// Shutdown stops accepting new connections, then waits for the requests in flight to finish.
// Tunneled connections carry traffic the proxy cannot see the end of, so they are closed
// once ctx is done rather than waited on.
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.srv.closing.Store(true)
	p.srv.closeOne.Do(func() { close(p.srv.closed) })

	err := errors.Join(p.srv.h1.Shutdown(ctx), p.srv.mitm.Shutdown(ctx))

	done := make(chan struct{})
	go func() {
		p.srv.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		p.srv.closeActive()
		err = errors.Join(err, ctx.Err())
	}

	p.srv.fwd.close()
	return err
}

// Close stops the proxy at once, dropping every connection including tunnels in flight.
func (p *Proxy) Close() error {
	p.srv.closing.Store(true)
	p.srv.closeOne.Do(func() { close(p.srv.closed) })
	err := errors.Join(p.srv.h1.Close(), p.srv.mitm.Close())
	p.srv.closeActive()
	p.srv.fwd.close()
	return err
}

func (s *server) trackListener(ln *net.Listener, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.listeners[ln] = struct{}{}
		return
	}
	delete(s.listeners, ln)
}

func (s *server) track(c io.Closer, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.active[c] = struct{}{}
		return
	}
	delete(s.active, c)
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

func (s *server) trackDemux(d *quicDemux, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.quics[d] = struct{}{}
		return
	}
	delete(s.quics, d)
}

// admitSession registers a session and reports whether the tree still accepts it.
//
// The decision that let the connection in was read from the tree as it stood then, and a
// delete may have committed since. Reading it again, after the session is registered, leaves
// no window. A sweep that missed this session missed it because the registration came after
// the snapshot, so it also came after the delete, and this read sees that delete. Registering
// after the read would reopen the window.
func (s *server) admitSession(sess *Session) bool {
	if sess.perRequest {
		return true
	}

	s.trackSession(sess, true)
	if s.p.Decide(sess.target) != Reject {
		return true
	}
	s.trackSession(sess, false)
	return false
}

// Sessions returns an iterator over a point-in-time snapshot of the connections the proxy
// decides on, the tunnels it relays and the connections it terminated.
//
// Three kinds are absent. A connection a client opens to the proxy itself addresses the proxy
// rather than an authority. A redirected plaintext connection resolves to no authority of its
// own and is decided request by request. A protocol upgrade rides the request that established
// it, so it is reachable only through the connection underneath.
//
// Removing a tunnel or an interceptor leaves the connections already open untouched. This is
// how a caller applies the change to them.
//
//	p.DeleteTunnel("example.com")
//	for s := range p.Sessions() {
//		if p.Decide(s.Target()) == Reject {
//			s.Close()
//		}
//	}
//
// A connection being established while the loop runs is not missed, it reads the tree again
// once it is registered and refuses itself. Two caveats. It may still be open when the loop
// returns, refusing itself a moment later without having relayed anything. And a tunnel the
// loop closes may have relayed bytes since the change. The snapshot only reflects what the
// calling goroutine committed before it started.
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

	// A demux owns its peers under a lock of its own, taken here only once the server lock
	// is released, so the two are never held at once.
	for _, d := range demuxes {
		out = d.appendSessions(out)
	}
	return slices.Values(out)
}

func (s *server) closeActive() {
	s.mu.Lock()
	conns := make([]io.Closer, 0, len(s.active))
	for c := range s.active {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// ServeHTTP serves one request with explicit forward proxy semantics: a CONNECT opens a
// tunnel, anything else is a plain HTTP request carrying an absolute target.
//
// It makes a Proxy an [http.Handler], so it can be mounted in a server you already own
// rather than given a listener of its own. The server must leave hijacking available, which
// authorities out anything that wraps the response writer without forwarding [http.Hijacker].
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.serveProxyRequest(w, r)
}

var _ http.Handler = (*Proxy)(nil)

// serveProxyRequest is the explicit forward proxy entry point: a CONNECT opens a tunnel,
// anything else is a plain HTTP request carrying an absolute target.
func (p *Proxy) serveProxyRequest(w http.ResponseWriter, r *http.Request) {
	if sess := sessionFromRequest(r); sess != nil {
		// ConnContext builds the session before ALPN or the h2c preface has set the protocol.
		sess.setProtocol(protoOfRequest(r))
	}

	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
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
		sess = newSession(r.Context(), nil, target, Intercept, protoOfRequest(r))
	}

	p.dispatchRequest(w, r, sess, target)
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

func newSession(ctx context.Context, c net.Conn, target Target, action Action, proto Protocol) *Session {
	s := &Session{
		id:        sessionSeq.Add(1),
		target:    target,
		action:    action,
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
