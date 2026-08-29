// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
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
	// tunnel and every intercepted connection.
	active   map[io.Closer]struct{}
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
		closed:    make(chan struct{}),
	}

	s.h2 = &http2.Server{
		MaxConcurrentStreams: p.cfg.server.maxConcurrentStreams,
		IdleTimeout:          p.cfg.server.idleTimeout,
		MaxReadFrameSize:     1 << 20,
	}

	// A client may speak HTTP/2 to the proxy over plaintext, with the connection preface
	// instead of ALPN. Without unencrypted HTTP/2 enabled such a client is answered as if it
	// had sent a request whose method is "PRI".
	frontProtocols := new(http.Protocols)
	frontProtocols.SetHTTP1(true)
	frontProtocols.SetHTTP2(true)
	frontProtocols.SetUnencryptedHTTP2(true)

	s.h1 = &http.Server{
		Handler:           http.HandlerFunc(p.serveProxyRequest),
		Protocols:         frontProtocols,
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
		// The front listener builds its session from ConnContext, which runs before the
		// protocol of the connection is known and can only assume HTTP/1.1.
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

	switch p.Decide(target) {
	case Reject:
		http.Error(w, "edge: connection rejected, no interceptor or tunnel names this authority", http.StatusForbidden)
	case Tunnel:
		// Nothing to tunnel at the byte level: the request is already parsed. Relay it
		// without consulting the routing tree so no handler observes it.
		p.relay(w, r, sess, target)
	default:
		p.serve(w, r, sess, target)
	}
}

// proxyTarget resolves the authority an explicit proxy request names, reporting false when
// the request names none.
//
// HTTP/1.1 carries it in an absolute-form request target. HTTP/2 has no absolute form: RFC
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
	if port == "" {
		port = defaultPort(scheme)
	}
	return Target{Scheme: scheme, Host: stringsutil.ToLowerASCIIString(host), Port: port}, true
}

func targetFromURL(u *url.URL) Target {
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host, port := splitHostPort(u.Host)
	if port == "" {
		port = defaultPort(scheme)
	}
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
				s.tlsState = &state
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
