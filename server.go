// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

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

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/stdapi/edge/internal/stringsutil"
	"golang.org/x/net/http/httpguts"
)

type sessionKey struct{}

type serverConfig struct {
	readHeaderTimeout    time.Duration
	readTimeout          time.Duration
	writeTimeout         time.Duration
	idleTimeout          time.Duration
	sniffTimeout         time.Duration
	maxHeaderBytes       int
	maxFrameBytes        int
	maxMessageBytes      int
	maxConcurrentStreams int
}

func defaultServerConfig() serverConfig {
	return serverConfig{
		readHeaderTimeout:    10 * time.Second,
		idleTimeout:          90 * time.Second,
		sniffTimeout:         time.Second,
		maxHeaderBytes:       1 << 20,
		maxFrameBytes:        1 << 20,
		maxMessageBytes:      defaultMaxMessageBytes,
		maxConcurrentStreams: 250,
	}
}

// server owns everything that is not routing: the listeners, the connections accepted on
// them, and the transports used to reach upstreams.
type server struct {
	// cutCtx is the parent of every request context. A cut cancels it with errCut, a drain
	// does not.
	cutCtx context.Context
	// ctx is canceled when the proxy starts closing.
	ctx context.Context
	p   *Proxy
	fwd *forwarder

	// h1, h2 and h3 serve the explicit proxy port over HTTP/1.1, HTTP/2 and QUIC. term and
	// term2 serve the connections the proxy terminated itself, with origin semantics,
	// over HTTP/1.1 and HTTP/2. newTerm and newFront2 build a server of the same kind for a
	// connection that reaches its server once the drain shut it down.
	h1        *http.Server
	h2        *http.Server
	h3        *http3.Server
	term      *http.Server
	term2     *http.Server
	newTerm   func(*http.Protocols) *http.Server
	newFront2 func() *http.Server

	listeners map[*net.Listener]struct{}
	// active tracks connections the proxy owns outside of http.Server, which is every
	// connection it terminated. It answers what a shutdown must close, so a connection enters
	// it as soon as it is accepted, before anything has decided it.
	active map[io.Closer]struct{}
	// sessions is what [Proxy.Sessions] reports. A session enters it only once its target is
	// resolved, so a caller never sees one it cannot pass to [Proxy.Admits].
	sessions map[*Session]struct{}
	// fronts tracks the connections accepted on an explicit TCP front, until a handler hijacks
	// one.
	fronts map[net.Conn]struct{}
	// frontSess is the session of each front connection, net.Conn or *quic.Conn, whose closer
	// the cut runs.
	frontSess map[any]*Session
	// waiting keeps the front connections before their first bytes or handshake, and
	// fresh the terminated HTTP/1.1 connections that have read no byte, which the drain ends.
	waiting map[net.Conn]struct{}
	fresh   sync.Map
	// quics tracks the QUIC demultiplexers. Their connections own their sessions under a
	// separate lock, merged when the sessions are read rather than mirrored here, so no
	// invariant spans the two locks.
	quics map[*quicDemux]struct{}
	// tunnels is the demultiplexer the CONNECT-UDP tunnels feed, brought up on the first
	// tunnel. It has no socket, so one serves the whole proxy.
	tunnels   *quicDemux
	cutCancel context.CancelCauseFunc
	// cutEnded is closed once a cut has ended, whoever started it.
	cutEnded chan struct{}
	cancel   context.CancelFunc
	// done is closed once Shutdown or Close has returned, when a front may close the socket
	// its connections run on.
	done chan struct{}
	// requests lists the requests in flight.
	requests *requestList
	// serving counts the admitted sessions with a handler still running, except those a
	// Session.Close ended before a cut, and the handlers of the CONNECT and CONNECT-UDP streams
	// on HTTP/2 and HTTP/3 until they return.
	serving gauge
	// tracked counts the connections and the listeners Shutdown waits for, frontsLive the
	// connections of the TCP fronts, and h3Live those of the HTTP/3 fronts from their first
	// Initial.
	tracked    gauge
	frontsLive gauge
	h3Live     gauge
	doneOne    sync.Once
	cutOnce    sync.Once
	// cutStarter records who started the cut, cutByDeadline or cutByClose.
	cutStarter atomic.Uint32

	mu      sync.Mutex
	closing atomic.Bool
	// refusing is set at the start of a cut, cut once it has ended the requests, both guarded by
	// mu.
	refusing bool
	cut      bool
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
		fronts:    make(map[net.Conn]struct{}),
		frontSess: make(map[any]*Session),
		waiting:   make(map[net.Conn]struct{}),
		quics:     make(map[*quicDemux]struct{}),
		done:      make(chan struct{}),
		cutEnded:  make(chan struct{}),
		requests:  newRequestList(),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.cutCtx, s.cutCancel = context.WithCancelCause(context.Background())
	cutBase := func(net.Listener) context.Context { return s.cutCtx }

	// HTTP/1.1 and HTTP/2 are served by servers of their own, so the drain disables the
	// keep-alives of the first and shuts the second down for its GOAWAY. A plaintext HTTP/2
	// client has no ALPN, so only unencrypted HTTP/2 serves it.
	http1 := new(http.Protocols)
	http1.SetHTTP1(true)
	http2 := new(http.Protocols)
	http2.SetHTTP2(true)
	http2.SetUnencryptedHTTP2(true)

	http2Cfg := &http.HTTP2Config{
		MaxConcurrentStreams:      p.cfg.server.maxConcurrentStreams,
		MaxReadFrameSize:          h2MaxReadFrameSize,
		MaxDecoderHeaderTableSize: h2HeaderTableSize,
	}

	newFront := func(protocols *http.Protocols) *http.Server {
		return &http.Server{
			Handler:           http.HandlerFunc(p.serveProxyRequest),
			Protocols:         protocols,
			HTTP2:             http2Cfg,
			ReadHeaderTimeout: p.cfg.server.readHeaderTimeout,
			ReadTimeout:       p.cfg.server.readTimeout,
			WriteTimeout:      p.cfg.server.writeTimeout,
			IdleTimeout:       p.cfg.server.idleTimeout,
			MaxHeaderBytes:    p.cfg.server.maxHeaderBytes,
			// One value more for the field a schemeConn adds.
			MaxHeaderValueCount: http.DefaultMaxHeaderValueCount + 1,
			ErrorLog:            log.New(slogWriter{p.cfg.logger}, "", 0),
			BaseContext:         cutBase,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				// The session outlives a cut of the requests. A connection without a wrapper gets no
				// cancel, since a cancel nothing ever calls would leak.
				sctx := context.WithoutCancel(ctx)
				var cancelRequests context.CancelFunc
				if cc := cancelConnOf(c); cc != nil {
					var cancel context.CancelFunc
					sctx, cancel = context.WithCancel(sctx)
					// The requests of the connection end with its session, before the connection.
					ctx, cancelRequests = context.WithCancel(ctx)
					cc.arm(func() {
						cancel()
						cancelRequests()
					})
				}
				sess := newSession(p, sctx, c, Target{}, KindHTTP, HTTP11)
				sess.httpConn = c
				sess.closer = normalEnd{c}
				sess.cancelRequests = cancelRequests
				if cancelRequests != nil {
					// A session opened on a stream ends with the connection, I3.
					sess.streamsCtx = ctx
				}
				if sc := cancelConnOf(c); sc != nil {
					sc.sess.Store(sess)
				}
				s.mu.Lock()
				s.frontSess[c] = sess
				s.mu.Unlock()
				return context.WithValue(ctx, sessionKey{}, sess)
			},
			ConnState: s.trackFront,
		}
	}
	s.h1, s.h2 = newFront(http1), newFront(http2)

	s.h3 = &http3.Server{
		Handler:         http.HandlerFunc(p.serveProxyRequest),
		EnableDatagrams: true,
		MaxHeaderBytes:  p.cfg.server.maxHeaderBytes,
		IdleTimeout:     p.cfg.server.idleTimeout,
		Logger:          p.cfg.logger,
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			// The handshake is over by the time a connection is handed here, so the session
			// has its TLS state from the start.
			sess := newSession(p, ctx, nil, Target{}, KindHTTP, HTTP3)
			sess.remoteAddr, sess.localAddr = c.RemoteAddr(), c.LocalAddr()
			state := c.ConnectionState().TLS
			sess.tlsState.Store(&state)
			sess.closer = quicConnEnd{c}
			s.endIdleH3(ctx, c, sess)
			// The requests of the connection end with its session, I1, and with the connection.
			rctx, cancel := context.WithCancel(s.cutChild(ctx))
			sess.cancelRequests = cancel
			sess.streamsCtx = rctx
			s.mu.Lock()
			s.frontSess[c] = sess
			s.mu.Unlock()
			context.AfterFunc(c.Context(), func() {
				s.mu.Lock()
				delete(s.frontSess, c)
				s.mu.Unlock()
			})
			return context.WithValue(rctx, sessionKey{}, sess)
		},
	}

	s.newTerm = func(protocols *http.Protocols) *http.Server {
		return &http.Server{
			Handler:           http.HandlerFunc(p.serveTerminatedRequest),
			Protocols:         protocols,
			HTTP2:             http2Cfg,
			ReadHeaderTimeout: p.cfg.server.readHeaderTimeout,
			ReadTimeout:       p.cfg.server.readTimeout,
			WriteTimeout:      p.cfg.server.writeTimeout,
			IdleTimeout:       p.cfg.server.idleTimeout,
			MaxHeaderBytes:    p.cfg.server.maxHeaderBytes,
			ErrorLog:          log.New(slogWriter{p.cfg.logger}, "", 0),
			// An OPTIONS * through a tunnel is about the origin, so it is routed like any request.
			DisableGeneralOptionsHandler: true,
			BaseContext:                  cutBase,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				if sc := servedConnOf(c); sc != nil {
					// The requests of the connection end with its session, I1, and with the
					// connection.
					rctx, cancel := context.WithCancel(ctx)
					sc.sess.armRequests(cancel, nil)
					return context.WithValue(rctx, sessionKey{}, sc.sess)
				}
				return ctx
			},
			ConnState: s.trackTerm,
		}
	}
	s.term, s.term2 = s.newTerm(http1), s.newTerm(http2)
	s.newFront2 = func() *http.Server { return newFront(http2) }

	return s, nil
}

// ListenAndServe listens on addr and serves as an explicit forward proxy. Clients point at
// it with their proxy setting: plain HTTP requests carry an absolute target, HTTPS requests
// start with CONNECT, and UDP goes through a CONNECT-UDP tunnel, RFC 9298, an Upgrade over
// HTTP/1.1 or an extended CONNECT over HTTP/2. The HTTP/2 form needs GODEBUG=http2xconnect=1
// in the environment of the process.
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
// It always returns a non-nil error and closes ln. After [Proxy.Shutdown] or [Proxy.Close] has
// begun, the returned error is [ErrProxyClosed], once ln is closed.
//
// Prefer [Proxy.ServeTLS] over a TLS listener built by the caller. Such a listener still
// works when it returns [*tls.Conn], but the [Session.Context] of a connection of another type
// with a ConnectionState method never ends.
func (p *Proxy) Serve(ln net.Listener) error {
	return p.serveFront(cancelListener{ln})
}

// acceptedHook runs between the accept of a front connection and its record, set by tests
// alone.
var acceptedHook func()

func (p *Proxy) serveFront(ln net.Listener) error {
	// The drain or the cut closes the listener, and so does a failed accept, so the second
	// close has to report nothing.
	ln = &onceCloseListener{Listener: ln}
	if !p.srv.tryTrackListener(&ln) {
		// As net/http's Serve does.
		_ = ln.Close()
		return ErrProxyClosed
	}
	defer p.srv.untrackListener(&ln)

	// The queues outlive the listener: a connection accepted before it closed is still being
	// dispatched. Each server closes its queue, the front stage closing both.
	q1, q2 := newConnQueue(ln.Addr()), newConnQueue(ln.Addr())
	go func() { _ = p.srv.h1.Serve(q1) }()
	go func() { _ = p.srv.h2.Serve(q2) }()

	// The limit on a field the schemeConn decodes is above the server's, which refuses the
	// request first.
	sl := schemeListener{Listener: ln, p: p, maxHeaderBytes: p.cfg.server.maxHeaderBytes + 64<<10}
	var delay time.Duration
	for {
		c, err := sl.Accept()
		if err == nil && acceptedHook != nil {
			acceptedHook()
		}
		if err != nil {
			if p.srv.closing.Load() {
				return ErrProxyClosed
			}
			if temporaryAccept(err) {
				delay = min(max(2*delay, 5*time.Millisecond), time.Second)
				time.Sleep(delay)
				continue
			}
			// The connections accepted before are still dispatched, and refused once the
			// queues closed.
			_ = ln.Close()
			_ = q1.Close()
			_ = q2.Close()
			return err
		}
		delay = 0
		if !p.srv.addFront(c) {
			abort(c)
			continue
		}
		go p.dispatchFront(c, q1, q2)
	}
}

// dispatchFront hands c to the server of its protocol, the ALPN of a TLS connection or the
// preface of a plaintext one, read under the deadline net/http gives a handshake. An HTTP/2
// connection that reaches its server once the drain shut it down gets a server of its own.
func (p *Proxy) dispatchFront(c net.Conn, q1, q2 *connQueue) {
	h2, err := p.frontHTTP2(c)
	if isTimeout(err) && schemeConnOf(c) != nil {
		// No request arrived within the read header timeout, a failed cause, or within the T
		// the drain gives a connection to begin one, a normal end.
		p.srv.removeFront(c)
		if p.srv.closing.Load() {
			closeNormally(c)
		} else {
			abortBy(c, time.Now().Add(alertWriteTimeout))
		}
		return
	}
	if err != nil || !h2 {
		// A failed handshake goes to the HTTP/1.1 server, which answers it as net/http does.
		if !q1.push(c) {
			p.srv.removeFront(c)
			_ = c.Close()
		}
		return
	}
	if sc := schemeConnOf(c); sc != nil {
		// HTTP/2 has no header timeout of its own to bound.
		sc.boundHeader(time.Time{})
	}
	if !q2.push(c) {
		p.serveLate(p.srv.newFront2(), c)
	}
}

func (p *Proxy) frontHTTP2(c net.Conn) (bool, error) {
	var deadline time.Time
	if d := p.cfg.server.readHeaderTimeout; d > 0 {
		deadline = time.Now().Add(d)
	}
	// Under the lock of endWaiting, so a drain that starts meanwhile cannot have its deadline
	// replaced.
	p.srv.mu.Lock()
	if p.srv.closing.Load() {
		// The drain started before the wait, and ends it as endWaiting does.
		if drained := time.Now().Add(alertWriteTimeout); deadline.IsZero() || drained.Before(deadline) {
			deadline = drained
		}
	}
	if !deadline.IsZero() {
		_ = c.SetDeadline(deadline)
		if sc := schemeConnOf(c); sc != nil {
			// The read header timeout of net/http counts from its own read, after this one.
			sc.boundHeader(deadline)
		}
	}
	p.srv.mu.Unlock()
	// Off the waits first, so the drain sets no deadline past the reset.
	defer func() {
		p.srv.served(c)
		_ = c.SetDeadline(time.Time{})
	}()
	if hs, ok := c.(interface {
		HandshakeContext(context.Context) error
	}); ok {
		if err := hs.HandshakeContext(context.Background()); err != nil {
			return false, err
		}
	}
	if sc := schemeConnOf(c); sc != nil {
		return sc.http2()
	}
	return false, nil
}

// serveLate serves c on srv, its own server, shut down once it has the connection, which writes
// its GOAWAY.
func (p *Proxy) serveLate(srv *http.Server, c net.Conn) {
	shutdownOnceServing(srv)
	q := newConnQueue(c.LocalAddr())
	go func() { _ = q.push(c) }()
	_ = srv.Serve(q)
}

// shutdownOnceServing shuts srv, the server of one connection, down at its first request, or T
// after the HTTP/2 server registered the connection, which it has once the connection is idle or
// active. Its GOAWAY then lets in the requests read by then.
func shutdownOnceServing(srv *http.Server) {
	var once sync.Once
	shutdown := func() { once.Do(func() { go func() { _ = srv.Shutdown(context.Background()) }() }) }
	handler := srv.Handler
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shutdown()
		handler.ServeHTTP(w, r)
	})
	next := srv.ConnState
	var armed sync.Once
	srv.ConnState = func(c net.Conn, state http.ConnState) {
		if next != nil {
			next(c, state)
		}
		if state == http.StateIdle || state == http.StateActive {
			armed.Do(func() { time.AfterFunc(alertWriteTimeout, shutdown) })
		}
	}
}

// onceCloseListener closes its listener once, and only the first call reports the result.
type onceCloseListener struct {
	net.Listener
	once sync.Once
}

func (l *onceCloseListener) Close() error {
	var err error
	l.once.Do(func() { err = l.Listener.Close() })
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
// It always returns a non-nil error and closes ln. After [Proxy.Shutdown] or [Proxy.Close] has
// begun, the returned error is [ErrProxyClosed], once ln is closed.
func (p *Proxy) ServeTLS(ln net.Listener, cert tls.Certificate) error {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	// The cancel wrapper sits under the TLS listener, where it cannot hide the handshake
	// from net/http.
	return p.serveFront(tlsListener{Listener: cancelListener{ln}, cfg: cfg})
}

// ListenAndServeQUIC listens for UDP on addr and serves as an explicit forward proxy reached
// over HTTP/3. Like [Proxy.ListenAndServeTLS], the certificate authenticates the proxy itself.
//
// A client configured with it sends plain requests with an absolute target, CONNECT for a TCP
// origin, and CONNECT-UDP (RFC 9298) for a UDP origin, HTTP/3 origins included.
func (p *Proxy) ListenAndServeQUIC(addr string, cert tls.Certificate) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = pc.Close() }()
	return p.ServeQUIC(pc, cert)
}

// ServeQUIC serves as an explicit forward proxy on the QUIC connections arriving on pc, see
// [Proxy.ListenAndServeQUIC]. It always returns a non-nil error and closes pc. After
// [Proxy.Shutdown] or [Proxy.Close] has begun, the returned error is [ErrProxyClosed], once pc
// is closed.
func (p *Proxy) ServeQUIC(pc net.PacketConn, cert tls.Certificate) error {
	// During the drain the listener stays open and refuses each new connection with
	// CONNECTION_REFUSED, until the start of the cut closes it.
	tr := &quic.Transport{Conn: pc, ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
		// Under the lock beginClose sets closing under, so a connection either is refused or
		// is counted before Shutdown reads the count.
		p.srv.mu.Lock()
		defer p.srv.mu.Unlock()
		if p.srv.closing.Load() {
			return nil, ErrProxyClosed
		}
		t := &h3Token{g: &p.srv.h3Live}
		t.g.add()
		return context.WithValue(ctx, h3TokenKey{}, t), nil
	}}
	acceptCtx, stopAccept := context.WithCancel(context.Background())
	front := &quicFront{late: p.srv.lateH3, logger: p.cfg.logger, own: p.srv.fwd.up.own, conns: make(map[*quic.Conn]struct{}),
		sessOf: func(c *quic.Conn) *Session { return p.srv.frontSessionOf(c) },
		tr:     tr, pc: pc, closed: make(chan struct{}), stopAccept: stopAccept}
	if !p.srv.tryTrackFront(front) {
		_ = pc.Close()
		return ErrProxyClosed
	}
	ln, err := tr.Listen(http3.ConfigureTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}), &quic.Config{
		MaxIdleTimeout:     p.cfg.server.idleTimeout,
		EnableDatagrams:    true,
		MaxIncomingStreams: int64(p.cfg.server.maxConcurrentStreams),
		Tracer:             h3Trace,
	})
	if err != nil {
		p.srv.untrackFront(front)
		_ = front.Close()
		return err
	}

	err = front.accept(acceptCtx, ln, p.srv.h3)
	closeListener(ln)
	if !p.srv.closing.Load() {
		p.srv.untrackFront(front)
		_ = front.Close()
		return err
	}

	// The front is closed in the front stage of the cut, or at the end of the drain.
	<-front.closed
	p.srv.untrackFront(front)
	return ErrProxyClosed
}

// h3Token is the place of one HTTP/3 front connection in h3Live, from its first Initial to its
// end.
type h3Token struct {
	g        *gauge
	once     sync.Once
	accepted atomic.Bool
}

type h3TokenKey struct{}

func (t *h3Token) release() { t.once.Do(t.g.done) }

// h3Handshake bounds the time the proxy keeps a connection quic-go never delivers, past the
// 10 s its default configuration gives a handshake.
const h3Handshake = 15 * time.Second

// h3Trace returns no trace. Its context is the connection's, which ends with it, whatever the
// end of its handshake.
func h3Trace(ctx context.Context, _ bool, _ quic.ConnectionID) qlogwriter.Trace {
	if t, ok := ctx.Value(h3TokenKey{}).(*h3Token); ok {
		context.AfterFunc(ctx, t.release)
		time.AfterFunc(h3Handshake, func() {
			if !t.accepted.Load() {
				t.release()
			}
		})
	}
	return nil
}

// quicFront records the connections accepted on an HTTP/3 front, so a cut closes them with
// a CONNECTION_CLOSE before the transport under them.
type quicFront struct {
	// late returns a server of its own for a connection that reaches the shared one after the
	// start of the drain, nil once a cut started.
	late   func() *http3.Server
	logger *slog.Logger
	own    *ownSockets
	conns  map[*quic.Conn]struct{}
	// sessOf returns the session of a connection, nil before it reached its server.
	sessOf func(*quic.Conn) *Session
	tr     *quic.Transport
	pc     net.PacketConn
	// closed is closed once Close has ended the connections, the transport and the socket.
	closed chan struct{}
	// stopAccept ends the accept loop at the start of the cut.
	stopAccept context.CancelFunc
	mu         sync.Mutex
	closeOnce  sync.Once
}

// accept serves each connection accepted on ln on a goroutine of its own until ctx ends,
// and returns the error Accept ended on. ServeListener would return only through
// http3.Server.Close or Shutdown, and a cut calls neither.
func (f *quicFront) accept(ctx context.Context, ln *quic.Listener, h3 *http3.Server) error {
	for {
		c, err := ln.Accept(ctx)
		if err != nil {
			return err
		}
		// Once the handshake is over, a connection from a socket the proxy recorded upstream is
		// the proxy itself.
		if f.own.datagram(addrPort(c.RemoteAddr())) {
			f.logger.Debug("edge: HTTP/3 connection refused", slog.String("client", c.RemoteAddr().String()),
				slog.String("reason", "the proxy opened it upstream, a request loop"))
			_ = c.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad), "")
			continue
		}
		if t, ok := c.Context().Value(h3TokenKey{}).(*h3Token); ok {
			t.accepted.Store(true)
		}
		f.add(c)
		go f.serve(h3, c)
	}
}

func (f *quicFront) serve(h3 *http3.Server, c *quic.Conn) {
	err := h3.ServeQUICConn(c)
	if errors.Is(err, http.ErrServerClosed) && c.Context().Err() == nil && f.late != nil {
		// The drain shut the server down before it had the connection.
		if late := f.late(); late != nil {
			err = late.ServeQUICConn(c)
		}
	}
	// Refused or failed before it was established, the connection is still open.
	_ = closeNoError(c)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		f.logger.Debug("edge: HTTP/3 connection closed", slog.String("error", err.Error()))
	}
}

func (f *quicFront) add(c *quic.Conn) {
	f.mu.Lock()
	f.conns[c] = struct{}{}
	f.mu.Unlock()
	context.AfterFunc(c.Context(), func() {
		f.mu.Lock()
		delete(f.conns, c)
		f.mu.Unlock()
	})
}

// Close closes every connection still open with a CONNECTION_CLOSE, sent before the call
// returns, then the transport and the socket under them. Closing the transport first would end
// the connections without a CONNECTION_CLOSE.
func (f *quicFront) Close() error {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		conns := make([]*quic.Conn, 0, len(f.conns))
		for c := range f.conns {
			conns = append(conns, c)
		}
		f.mu.Unlock()
		var wg sync.WaitGroup
		for _, c := range conns {
			if sess := f.sessOf(c); sess != nil {
				// The closer gives a connection with a request still in flight its failed end.
				wg.Go(func() { _ = sess.endBy(causeCut, time.Now().Add(alertWriteTimeout)) })
				continue
			}
			wg.Go(func() { _ = closeNoError(c) })
		}
		wg.Wait()
		_ = f.tr.Close()
		_ = f.pc.Close()
		close(f.closed)
	})
	return nil
}

// Shutdown stops accepting new connections, then waits for the requests in flight to finish.
// The servers drain together: idle HTTP/1.1 connections are closed, HTTP/2 and HTTP/3
// connections are told with a GOAWAY, and every request already started runs to completion.
// A handler serving a whole connection, a stream or a datagram flow, ends when its peers do,
// so it is waited on until ctx is done and cut then, along with anything else still open.
// Shutdown returns once that cut has ended. Without a deadline on ctx, Shutdown waits
// indefinitely. After Shutdown or Close has returned, a further Shutdown returns nil at once.
func (p *Proxy) Shutdown(ctx context.Context) error {
	// A cut that has ended left nothing to drain.
	select {
	case <-p.srv.done:
		return nil
	default:
	}
	p.srv.beginClose()
	defer p.srv.endClose()

	err := p.srv.closeListeners()
	p.srv.endWaiting()

	// Past the deadline, whatever draining could not end is cut: streams, upgraded pipes, and
	// connections still handshaking. Cutting them is what unblocks the waits below.
	stop := context.AfterFunc(ctx, func() { p.srv.cutBy(cutByDeadline) })

	p.srv.mu.Lock()
	demuxes := slices.Collect(maps.Keys(p.srv.quics))
	p.srv.mu.Unlock()

	// The planes drain together. An intercepted connection carried on a CONNECT stream of
	// the front server only ends once the terminating server drains it, so draining one
	// server after the other would hold the first open until the deadline.
	// HTTP/1.1 drains with its keep-alives disabled: net/http drops a request it reads after
	// Shutdown. HTTP/2 drains under Shutdown, which writes the GOAWAY.
	p.srv.h1.SetKeepAlivesEnabled(false)
	p.srv.term.SetKeepAlivesEnabled(false)
	errs := make([]error, 4+len(demuxes))
	var drains sync.WaitGroup
	drains.Go(func() { errs[0] = p.srv.h2.Shutdown(ctx) })
	// quic-go closes every connection once the context of its Shutdown ends, before the cut
	// has ended their requests, so the cut ends them instead.
	drains.Go(func() { errs[1] = p.srv.h3.Shutdown(context.WithoutCancel(ctx)) })
	drains.Go(func() { errs[2] = p.srv.term2.Shutdown(ctx) })
	drains.Go(func() { errs[3] = p.srv.frontsLive.waitCtx(ctx) })
	for i, d := range demuxes {
		drains.Go(func() { errs[4+i] = d.shutdown(ctx) })
	}

	// Each drain bounds itself by ctx, but no close can force a handler to return. The waits
	// are raced against the deadline, and past it Shutdown returns once the cut has ended,
	// leaving a handler that ignores its context to unwind behind it.
	drained := make(chan struct{})
	go func() { drains.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-ctx.Done():
		// The drains may still be writing errs, so it is not read; the deadline is the
		// whole report.
		p.srv.cutBy(cutByDeadline)
		p.srv.fwd.close()
		return errors.Join(err, p.srv.cutError(ctx))
	case <-p.srv.cutEnded:
		// A Close or the deadline cut the drain, and a handler that ignores its context is not
		// waited for.
		p.srv.fwd.close()
		return errors.Join(err, p.srv.cutError(ctx))
	}

	// Every drain that ran into the deadline reports it; the deadline is one fact and it is
	// reported once, on the paths that know it cut something.
	for i, e := range errs {
		if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
			errs[i] = nil
		}
	}
	err = errors.Join(err, errors.Join(errs...))

wait:
	for {
		// A connection accepted at the start may join a gauge another one left, so every
		// gauge is read again after each wait.
		zero := p.srv.tracked.zeroed()
		if zero == nil {
			zero = p.srv.frontsLive.zeroed()
		}
		if zero == nil {
			zero = p.srv.h3Live.zeroed()
		}
		if zero == nil {
			break
		}
		select {
		case <-zero:
		case <-p.srv.cutEnded:
			err = errors.Join(err, p.srv.cutError(ctx))
			break wait
		case <-ctx.Done():
			err = errors.Join(err, p.srv.cutError(ctx))
			break wait
		}
	}
	// A cut that the deadline or Close started ends before Shutdown returns. A drain that
	// ended ends the pools and the sockets itself. A deadline seen first by the wait above may
	// stop the AfterFunc before it ran, and still cuts.
	if !stop() || p.srv.cutCtx.Err() != nil || ctx.Err() != nil {
		p.srv.cutBy(cutByDeadline)
		if !errors.Is(err, ErrProxyClosed) && ctx.Err() == nil {
			err = errors.Join(err, ErrProxyClosed)
		}
	} else {
		// The pools end, then the UDP sockets close, docs/lifecycle.md Drain.
		p.srv.fwd.close()
		p.srv.closeQUICFronts()
		p.srv.closeHTTPServers()
	}

	p.srv.fwd.close()
	return err
}

// cutError is the error a Shutdown reports for a cut: its context's error when that context
// started it, ErrProxyClosed when Close did.
func (s *server) cutError(ctx context.Context) error {
	if err := ctx.Err(); err != nil && s.cutStarter.Load() != cutByClose {
		return err
	}
	return ErrProxyClosed
}

// closeQUICFronts closes the HTTP/3 fronts and the demultiplexers at the end of a drain.
func (s *server) closeQUICFronts() {
	s.mu.Lock()
	carriers := make([]io.Closer, 0, 2)
	for c := range s.active {
		switch c.(type) {
		case *quicFront, *quicDemux:
			carriers = append(carriers, c)
		}
	}
	s.mu.Unlock()
	var wg sync.WaitGroup
	for _, c := range carriers {
		wg.Go(func() { _ = c.Close() })
	}
	wg.Wait()
}

// stopQUICFronts is the start of the cut for the HTTP/3 fronts: their listeners close, refusing a
// connection in its handshake.
func (s *server) stopQUICFronts() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.active {
		if f, ok := c.(*quicFront); ok {
			f.stopAccept()
		}
	}
}

// Close stops the proxy, dropping every connection including the traffic in flight, and ends
// every session as [Session.Close] does. A handler that ignores its context may still be
// running when Close returns.
func (p *Proxy) Close() error {
	p.srv.beginClose()
	defer p.srv.endClose()
	// The cut comes first and covers the HTTP/3 fronts. http3.Server.Close waits for every
	// handler, and http.Server.Close closes its connections one after the other.
	err := p.srv.closeListeners()
	p.srv.cutBy(cutByClose)
	err = errors.Join(err, p.srv.h1.Close(), p.srv.h2.Close(), p.srv.term.Close(), p.srv.term2.Close())
	p.srv.fwd.close()
	return err
}

// Sessions returns an iterator over a point-in-time snapshot of the connections the proxy is
// serving. Each [Session] is one client connection, a connection opened by CONNECT, a
// redirected TLS or QUIC connection, or a datagram flow, and covers every request or stream
// multiplexed on it. A protocol upgrade is reported as a session of its own, under the
// authority its request was routed on, and so is a CONNECT-UDP tunnel, beside the
// connections and datagram flows inside it. Connections addressed to the proxy itself are
// not reported, and neither is a plaintext connection nothing admits.
//
// Changing an entry does not close the connections already open. Use Sessions with
// [Session.Stale] and [Session.Close] to end the ones that would be served differently now.
//
//	p.Delete[edge.TCP]("example.com")
//	for s := range p.Sessions() {
//		if s.Stale() {
//			s.Close()
//		}
//	}
func (p *Proxy) Sessions() iter.Seq[*Session] {
	p.srv.mu.Lock()
	out := make([]*Session, 0, len(p.srv.sessions))
	for sess := range p.srv.sessions {
		if sess.admitted && !sess.perRequest {
			out = append(out, sess)
		}
	}
	demuxes := make([]*quicDemux, 0, len(p.srv.quics))
	for d := range p.srv.quics {
		demuxes = append(demuxes, d)
	}
	p.srv.mu.Unlock()

	// A demux owns its connections under a lock of its own, taken here only once the server
	// lock is released, so the two are never held at once.
	for _, d := range demuxes {
		out = d.appendSessions(out, true)
	}
	return slices.Values(out)
}

// serveProxyRequest is the explicit forward proxy entry point: a CONNECT opens a connection,
// anything else is a plain HTTP request carrying an absolute target.
func (p *Proxy) serveProxyRequest(w http.ResponseWriter, r *http.Request) {
	// Taken from every request, so the field never outlives the front.
	scheme := takeScheme(r)

	rq := p.srv.requests.begin(w, r)
	if rq == nil {
		rejectRequest(w, r)
	}
	defer p.srv.requests.end(rq, w, r)

	// Before anything else, including the origin-form refusal below, so that an
	// unauthenticated client learns nothing from the answer it gets.
	identity, ok := p.authenticate(w, r)
	if !ok {
		return
	}
	if p.refuseNewSession(w, r) {
		return
	}

	// ConnContext builds the session before ALPN or the h2c preface has set the protocol.
	sess := sessionFromRequest(r)
	sess.setProtocol(protoOfRequest(r))

	if r.Method == http.MethodConnect {
		switch extendedConnectProtocol(r) {
		case "":
			p.serveConnect(w, r, identity, rq)
		case "connect-udp":
			p.serveConnectUDP(w, r, identity, rq)
		default:
			p.writeStatus(w, r, http.StatusNotImplemented, "extended CONNECT is not served, WebSocket goes over HTTP/1.1")
		}
		return
	}

	if isConnectUDPUpgrade(r) {
		p.serveConnectUDP(w, r, identity, rq)
		return
	}

	if !validRequestTarget(r) {
		p.writeStatus(w, r, http.StatusBadRequest, errRequestTargetForm.Error())
		return
	}
	target, err := proxyTarget(r, scheme)
	if err != nil {
		p.writeStatus(w, r, http.StatusBadRequest, err.Error())
		return
	}

	p.dispatchRequest(w, r, sess, target, identity, rq)
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

	header := w.Header()
	for _, challenge := range auth.Challenges(r) {
		if !httpguts.ValidHeaderFieldValue(challenge) {
			p.cfg.logger.LogAttrs(r.Context(), slog.LevelDebug, "edge: challenge dropped, invalid as a field value",
				slog.String("challenge", challenge))
			continue
		}
		header.Add(HeaderProxyAuthenticate, challenge)
	}
	if len(header[HeaderProxyAuthenticate]) == 0 {
		// Nothing the client could present would change the answer, so asking it to
		// authenticate would be a lie, and a 407 carrying no challenge is malformed.
		p.writeStatus(w, r, http.StatusForbidden, "proxy access denied")
		return "", false
	}
	p.writeStatus(w, r, http.StatusProxyAuthRequired, "proxy authentication required")
	return "", false
}

// refuseNewSession answers 503 to a request that arrived after the start of a drain and would
// register a session: a CONNECT, or an upgrade other than h2c. The answer ends an HTTP/1.1
// connection.
func (p *Proxy) refuseNewSession(w http.ResponseWriter, r *http.Request) bool {
	if !p.srv.closing.Load() {
		return false
	}
	if r.Method != http.MethodConnect && !isUpgrade(r) {
		return false
	}
	p.writeStatus(w, r, http.StatusServiceUnavailable, "the proxy is draining, a new session is refused")
	return true
}

// isUpgrade reports whether r requests a switch to a protocol other than h2c, which the
// HTTP/2 server serves as a request.
func isUpgrade(r *http.Request) bool {
	upgrade := r.Header.Get("Upgrade")
	return upgrade != "" && !strings.EqualFold(upgrade, "h2c")
}

// cutting reports whether a cut has started.
func (s *server) cutting() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refusing
}

// writeStatus answers the client with the status text of code and logs reason with the
// request, so the client reads the status and nothing else. On HTTP/1.1, a 400 and a refused
// CONNECT or upgrade end the connection before its next bytes, which may not be a request.
func (p *Proxy) writeStatus(w http.ResponseWriter, r *http.Request, code int, reason string) {
	if p.srv.cutting() {
		// A cut ends a request with its failed end and no status the proxy writes, I2.
		abortWith(w, r, http3.ErrCodeRequestCanceled, false)
	}
	if r.ProtoMajor == 1 && (code == http.StatusBadRequest || r.Method == http.MethodConnect || isUpgrade(r)) {
		w.Header().Set("Connection", "close")
	}
	if p.cfg.logger.Enabled(r.Context(), slog.LevelDebug) {
		request := r.RequestURI
		if r.URL != nil && r.URL.User != nil {
			request = r.URL.Redacted()
		}
		p.cfg.logger.LogAttrs(r.Context(), slog.LevelDebug, "edge: "+reason,
			slog.Int("status", code),
			slog.String("method", r.Method),
			slog.String("host", r.Host),
			slog.String("request", request),
			slog.String("client", r.RemoteAddr),
		)
	}
	if isGRPCRequest(r) {
		// A gRPC client reads a refusal from the status of a trailers-only response.
		grpcCode := grpcCodeOf(code)
		_ = writeResponse(w, r, grpcStatusResponse(grpcCode, grpcCode.String()))
		return
	}
	http.Error(w, http.StatusText(code), code)
}

// grpcCodeOf returns the gRPC status of a refusal with the HTTP status code.
func grpcCodeOf(code int) Code {
	switch code {
	case http.StatusBadRequest:
		return CodeInvalidArgument
	case http.StatusProxyAuthRequired:
		return CodeUnauthenticated
	case http.StatusForbidden:
		return CodePermissionDenied
	case http.StatusMisdirectedRequest, http.StatusBadGateway, http.StatusServiceUnavailable:
		return CodeUnavailable
	case http.StatusNotImplemented:
		return CodeUnimplemented
	case http.StatusInternalServerError:
		return CodeInternal
	}
	return CodeUnknown
}

func (p *Proxy) logf(ctx context.Context, level slog.Level, msg string, sess *Session, err error) {
	if !p.cfg.logger.Enabled(ctx, level) {
		return
	}
	attrs := []any{slog.String("target", sess.target.String())}
	if sess.remoteAddr != nil {
		attrs = append(attrs, slog.String("client", sess.remoteAddr.String()))
	}
	attrs = append(attrs,
		slog.Uint64("session", sess.id),
		slog.String("kind", sess.kind.String()),
	)
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	p.cfg.logger.Log(ctx, level, "edge: "+msg, attrs...)
}

// lateH3 is a server of its own for an HTTP/3 front connection that reaches the shared server
// after the start of the drain, nil once a cut started.
func (s *server) lateH3() *http3.Server {
	if s.cutting() {
		return nil
	}
	return newLateH3(s.h3)
}

// newLateH3 is a server of its own for one connection that reaches shared after the start of
// the drain. It shuts down at the first request or T after the connection, so its GOAWAY lets
// in the requests read by then, as the drained server let in those read before its own.
func newLateH3(shared *http3.Server) *http3.Server {
	late := &http3.Server{
		EnableDatagrams: shared.EnableDatagrams,
		MaxHeaderBytes:  shared.MaxHeaderBytes,
		IdleTimeout:     shared.IdleTimeout,
		Logger:          shared.Logger,
	}
	var once sync.Once
	goAway := new(atomic.Int64)
	shutdown := func() {
		once.Do(func() {
			goAway.Store(time.Now().UnixNano())
			go func() { _ = late.Shutdown(context.Background()) }()
		})
	}
	late.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shutdown()
		shared.Handler.ServeHTTP(w, r)
	})
	late.ConnContext = func(ctx context.Context, c *quic.Conn) context.Context {
		time.AfterFunc(alertWriteTimeout, shutdown)
		return shared.ConnContext(context.WithValue(ctx, lateGoAwayKey{}, goAway), c)
	}
	return late
}

// lateGoAwayKey is the context key of the time the late server of a connection began its
// GOAWAY, zero before.
type lateGoAwayKey struct{}

// endIdleH3 ends qc, the HTTP/3 connection of sess, through the closer of sess once the proxy
// stops and the connection has no request and no session on it. quic-go reports neither its
// GOAWAY nor the streams it accepted, so the check runs every T from T after the start, and T
// after the GOAWAY of a late server, ctx being the context its ConnContext was given. That
// leaves a request accepted before the GOAWAY T to reach its handler.
func (s *server) endIdleH3(ctx context.Context, qc *quic.Conn, sess *Session) {
	goAway, _ := ctx.Value(lateGoAwayKey{}).(*atomic.Int64)
	stop := context.AfterFunc(s.ctx, func() {
		t := time.NewTicker(alertWriteTimeout)
		defer t.Stop()
		for {
			select {
			case <-qc.Context().Done():
				return
			case <-t.C:
			}
			if goAway != nil {
				if at := goAway.Load(); at == 0 || time.Since(time.Unix(0, at)) < alertWriteTimeout {
					continue
				}
			}
			if s.idle(sess) {
				_ = sess.endBy(causeIdle, time.Now().Add(alertWriteTimeout))
				return
			}
		}
	})
	context.AfterFunc(qc.Context(), func() { stop() })
}

// idle reports whether no request and no session travels on sess. A session that takes its
// request over registers before the request leaves the list, so the list is read first.
func (s *server) idle(sess *Session) bool {
	if s.requests.hasOf(sess) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(sess.carried) == 0
}

// beginClose marks the proxy as stopping. Writing closing under the lock orders it against
// every registration: one that saw it unset committed inside a critical section that ran
// first, so the snapshots a shutdown takes under the same lock cannot miss it.
func (s *server) beginClose() {
	s.mu.Lock()
	s.closing.Store(true)
	s.mu.Unlock()
	s.cancel()
}

// endClose marks the shutdown as over, drained or cut at the deadline.
func (s *server) endClose() {
	s.doneOne.Do(func() { close(s.done) })
}

// tryTrack registers a connection the proxy owns outside of http.Server and reports whether
// it may be served. It is the arrival of a connection, refused once the proxy is stopping,
// the caller still owning the connection.
func (s *server) tryTrack(c io.Closer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing.Load() {
		return false
	}
	s.tracked.add()
	s.active[c] = struct{}{}
	return true
}

// trackRegistered is [server.tryTrack] for the socket or stream of a session that arrived
// before the start of a drain, refused only once a cut has started.
func (s *server) trackRegistered(c io.Closer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refusing {
		return false
	}
	s.tracked.add()
	s.active[c] = struct{}{}
	return true
}

func (s *server) untrack(c io.Closer) {
	s.mu.Lock()
	delete(s.active, c)
	s.mu.Unlock()
	s.tracked.done()
}

// tryTrackListener is [server.tryTrack] for the listeners the proxy accepts on itself, which
// live in a registry of their own because a shutdown closes them first, before any draining.
func (s *server) tryTrackListener(ln *net.Listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing.Load() {
		return false
	}
	s.tracked.add()
	s.listeners[ln] = struct{}{}
	return true
}

func (s *server) untrackListener(ln *net.Listener) {
	s.mu.Lock()
	delete(s.listeners, ln)
	s.mu.Unlock()
	s.tracked.done()
}

// tryTrackDemux is [server.tryTrack] for a QUIC demultiplexer, which enters both registries
// in one critical section so a shutdown cannot see one without the other: missing quics
// would skip the drain, missing active would skip the cut at the deadline. It takes no token
// of tracked: the drain waits for what the demultiplexer serves, and its end closes it.
func (s *server) tryTrackDemux(d *quicDemux) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing.Load() {
		return false
	}
	s.active[d] = struct{}{}
	s.quics[d] = struct{}{}
	return true
}

// tryTrackFront is [server.tryTrack] for an HTTP/3 front. It takes no WaitGroup token, the
// socket is released after Shutdown has returned.
func (s *server) tryTrackFront(f *quicFront) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing.Load() {
		return false
	}
	s.active[f] = struct{}{}
	return true
}

func (s *server) untrackFront(f *quicFront) {
	s.mu.Lock()
	delete(s.active, f)
	s.mu.Unlock()
}

// tunnelDemux returns the demultiplexer the tunnels feed, brought up on first use, also during
// a drain for a tunnel read before its start. It has no shutdown token, since the end of the
// drain or the front stage of the cut closes it.
func (s *server) tunnelDemux() (*quicDemux, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refusing {
		return nil, ErrProxyClosed
	}
	if s.tunnels == nil {
		d, err := newQUICDemux(s.p, newTunnelPacketConn())
		if err != nil {
			return nil, err
		}
		if s.closing.Load() {
			// Brought up during the drain, it refuses what arrives after the start as the
			// demultiplexers the drain began with do.
			d.draining.Store(true)
		}
		s.active[d] = struct{}{}
		s.quics[d] = struct{}{}
		s.tunnels = d
	}
	return s.tunnels, nil
}

func (s *server) untrackDemux(d *quicDemux) {
	s.mu.Lock()
	delete(s.active, d)
	delete(s.quics, d)
	s.mu.Unlock()
}

// untrackSession removes a session once the goroutine serving it is done with it.
func (s *server) untrackSession(sess *Session) {
	s.mu.Lock()
	s.unlinkLocked(sess)
	serving := sess.serving
	sess.serving = false
	s.mu.Unlock()
	if serving {
		s.serving.done()
	}
}

// endSession removes a session for good, before the goroutines serving it have returned, and
// returns its closer with the sessions it carries.
func (s *server) endSession(sess *Session) (sessionCloser, []*Session) {
	s.mu.Lock()
	sess.ended = true
	s.unlinkLocked(sess)
	closer := sess.closer
	var carried []*Session
	if len(sess.carried) > 0 {
		carried = make([]*Session, 0, len(sess.carried))
		for c := range sess.carried {
			carried = append(carried, c)
		}
	}
	// A cut waits only for the handlers of the sessions it closed.
	release := sess.serving && !s.cut
	if release {
		sess.serving = false
	}
	s.mu.Unlock()
	if release {
		s.serving.done()
	}
	return closer, carried
}

func (s *server) unlinkLocked(sess *Session) {
	delete(s.sessions, sess)
	if c := sess.carrier; c != nil {
		delete(c.carried, sess)
	}
}

// registerSession tracks sess from its registration, pending until admitSession, with closer
// ending it. It reports false once a cut has started, the caller then giving the session the
// failed end of its protocol.
func (s *server) registerSession(sess *Session, closer sessionCloser) bool {
	if sess.cancel == nil {
		panic("edge: a session is registered with no context Close can end")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A carrier whose closer ran collected what it carries already, I3.
	if sess.ended || s.refusing || sess.carrier != nil && sess.carrier.ended {
		return false
	}
	sess.closer = closer
	s.registerLocked(sess)
	return true
}

func (s *server) registerLocked(sess *Session) {
	s.sessions[sess] = struct{}{}
	if c := sess.carrier; c != nil {
		if c.carried == nil {
			c.carried = make(map[*Session]struct{})
		}
		c.carried[sess] = struct{}{}
	}
}

// admitSession admits a session, registering it first when its registration and its admission
// are one step, and reports whether the tree still decides it as it was decided. closer,
// when not nil, replaces the closer of a pending socket or stream.
//
// The decision that let the connection in was read from the tree as it stood then, and a
// commit may have landed since. A replay after the session is registered leaves no window. A
// sweep that missed this session missed it because the registration came after the snapshot,
// so it also came after the commit, and this replay sees that commit. A registration after
// the replay would reopen the window.
func (s *server) admitSession(sess *Session, closer sessionCloser) error {
	if sess.cancel == nil && !sess.perRequest {
		panic("edge: a session is registered with no context Close can end")
	}

	s.mu.Lock()
	ended := sess.ended || s.refusing || sess.carrier != nil && sess.carrier.ended
	if !ended {
		if _, ok := s.sessions[sess]; !ok {
			s.registerLocked(sess)
		}
		if closer != nil && pendingCloser(sess.closer) {
			sess.closer = closer
		}
		sess.admitted = true
		// A connection served request by request has no handler of its own, and nothing a sweep
		// could act on.
		if !sess.perRequest {
			sess.serving = true
			s.serving.add()
		}
	}
	s.mu.Unlock()
	if ended {
		return errSessionEnded
	}
	if sess.perRequest || !sess.Stale() {
		return nil
	}
	s.untrackSession(sess)
	return ErrConnectionRejected
}

// errSessionEnded is the admission of a session that a cut or the end of its carrier ended
// first, which gets the failed end of the cut, docs/lifecycle.md Refusals.
var errSessionEnded = errors.New("edge: the session ended before its admission")

// quicConnEnd ends a QUIC connection with the form of its transport.
type quicConnEnd struct{ c *quic.Conn }

func (q quicConnEnd) endBy(c cause, _ time.Time) error {
	if formOf(framed, c, false) == formFailed {
		return closeFailed(q.c)
	}
	return closeNoError(q.c)
}

// pendingCloser reports whether c ends a session not yet admitted, which its admission
// replaces with the closer of what serves it.
func pendingCloser(c sessionCloser) bool {
	switch c.(type) {
	case nil, *pendingSocket, *streamCut:
		return true
	}
	return false
}

// pendingSocket ends a session not yet admitted with the failed end of its socket.
type pendingSocket peekConn

func (c *pendingSocket) endBy(cs cause, deadline time.Time) error {
	if formOf(byteStream, cs, false) == formNormal {
		closeNormallyBy((*peekConn)(c), deadline)
		return nil
	}
	abortBy((*peekConn)(c), deadline)
	return nil
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

var errCut = errors.New("edge: proxy closed")

// gauge counts units in flight and wakes every caller waiting for none to remain.
type gauge struct {
	// zero is closed once the count reaches zero, made by the first wait on a count above it.
	zero chan struct{}
	n    int64
	mu   sync.Mutex
}

func (g *gauge) add() {
	g.mu.Lock()
	g.n++
	g.mu.Unlock()
}

func (g *gauge) done() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n--
	if g.n == 0 && g.zero != nil {
		close(g.zero)
		g.zero = nil
	}
}

// zeroed returns a channel closed once the count is zero, nil when it is already.
func (g *gauge) zeroed() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n == 0 {
		return nil
	}
	if g.zero == nil {
		g.zero = make(chan struct{})
	}
	return g.zero
}

// waitCtx waits for the gauge to reach zero, or returns the error of ctx once it ends.
func (g *gauge) waitCtx(ctx context.Context) error {
	for {
		zero := g.zeroed()
		if zero == nil {
			return nil
		}
		select {
		case <-zero:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (g *gauge) wait(expired <-chan struct{}) {
	for {
		zero := g.zeroed()
		if zero == nil {
			return
		}
		select {
		case <-zero:
		case <-expired:
			return
		}
	}
}

// request is an HTTP request in flight, from its read to its end or to the registration of
// the session it opens.
type request struct {
	w          http.ResponseWriter
	sess       *Session
	prev, next *request
	// callBody is the body of a gRPC call over HTTP/1.1, nil for any other request.
	callBody *h1CallBody
	proto    int
	listed   bool
	// byClose marks an HTTP/1.0 request, the response to which is delimited by the close.
	byClose bool
	// closed is set once the closer ran, so the response is reset when the handler returns.
	closed atomic.Bool
	// header is set once the response header is about to be written.
	header atomic.Bool
}

var requestPool = sync.Pool{New: func() any { return new(request) }}

// requestShards spreads the requests in flight over locks of their own, each request on the
// shard of the session it travels on.
const requestShards = 32

// requestList lists the requests in flight. A request is closed under the lock of its shard,
// so its handler cannot leave the list, and its response writer stays valid, during the close.
type requestList struct {
	shards [requestShards]requestShard
}

type requestShard struct {
	empty chan struct{}
	head  *request
	mu    sync.Mutex
	n     int
	cut   bool
	_     [24]byte
}

func newRequestList() *requestList {
	l := new(requestList)
	for i := range l.shards {
		l.shards[i].empty = make(chan struct{}, 1)
	}
	return l
}

func (l *requestList) shardOf(sess *Session) *requestShard {
	if sess == nil {
		return &l.shards[0]
	}
	return &l.shards[sess.shard]
}

// begin lists the request r read off w. It returns nil once a cut has started.
func (l *requestList) begin(w http.ResponseWriter, r *http.Request) *request {
	rq := requestPool.Get().(*request)
	rq.w, rq.sess, rq.proto = w, sessionFromRequest(r), r.ProtoMajor
	if rq.sess != nil {
		rq.sess.requested.Store(true)
	}
	rq.byClose = !r.ProtoAtLeast(1, 1)
	sh := l.shardOf(rq.sess)
	sh.mu.Lock()
	if sh.cut {
		sh.mu.Unlock()
		rq.w, rq.sess = nil, nil
		requestPool.Put(rq)
		return nil
	}
	rq.listed = true
	rq.next = sh.head
	if sh.head != nil {
		sh.head.prev = rq
	}
	sh.head = rq
	sh.n++
	sh.mu.Unlock()
	return rq
}

// release takes rq off the list once its session took the request over, and reports whether
// its closer ran.
func (l *requestList) release(rq *request) bool {
	if rq == nil {
		return false
	}
	sh := l.shardOf(rq.sess)
	sh.mu.Lock()
	closed := rq.closed.Load()
	if rq.listed {
		rq.listed = false
		if rq.prev != nil {
			rq.prev.next = rq.next
		} else {
			sh.head = rq.next
		}
		if rq.next != nil {
			rq.next.prev = rq.prev
		}
		rq.prev, rq.next = nil, nil
		sh.n--
		if sh.n == 0 {
			select {
			case sh.empty <- struct{}{}:
			default:
			}
		}
	}
	sh.mu.Unlock()
	return closed
}

// end releases rq once its handler returned and returns it to the pool. The response is reset
// once the closer of rq ran, where a return would end it cleanly. The goroutine
// serving the request calls it once.
func (l *requestList) end(rq *request, w http.ResponseWriter, r *http.Request) {
	if rq == nil {
		return
	}
	closed := l.release(rq)
	header := rq.header.Load()
	rq.w, rq.sess, rq.callBody = nil, nil, nil
	rq.closed.Store(false)
	rq.header.Store(false)
	requestPool.Put(rq)
	if closed {
		abortWith(w, r, http3.ErrCodeRequestCanceled, header)
	}
}

// isClosed reports whether the closer of rq ran.
func (l *requestList) isClosed(rq *request) bool {
	if rq == nil {
		return false
	}
	return rq.closed.Load()
}

// cutAll refuses every later request and closes every request listed.
func (l *requestList) cutAll() {
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.Lock()
		sh.cut = true
		for rq := sh.head; rq != nil; rq = rq.next {
			rq.close()
		}
		sh.mu.Unlock()
	}
}

// closeOf closes the requests that travel on sess.
func (l *requestList) closeOf(sess *Session) {
	sh := l.shardOf(sess)
	sh.mu.Lock()
	for rq := sh.head; rq != nil; rq = rq.next {
		if rq.sess == sess {
			rq.close()
		}
	}
	sh.mu.Unlock()
}

// waitOf waits until no request that travels on sess is in flight, polling as net/http's
// Shutdown polls its connections, and reports false when one still is at deadline.
func (l *requestList) waitOf(sess *Session, deadline time.Time) bool {
	for l.hasOf(sess) {
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(min(5*time.Millisecond, time.Until(deadline)))
	}
	return true
}

// hasOf reports whether a request that travels on sess is in flight.
func (l *requestList) hasOf(sess *Session) bool {
	sh := l.shardOf(sess)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	for rq := sh.head; rq != nil; rq = rq.next {
		if rq.sess == sess {
			return true
		}
	}
	return false
}

func (l *requestList) wait(expired <-chan struct{}) {
	for i := range l.shards {
		sh := &l.shards[i]
		for {
			sh.mu.Lock()
			n := sh.n
			sh.mu.Unlock()
			if n == 0 {
				break
			}
			select {
			case <-sh.empty:
			case <-expired:
				return
			}
		}
	}
}

// close gives the response of rq its failed end, docs/lifecycle.md. A handler still running
// finds its writes failing.
func (rq *request) close() {
	rq.closed.Store(true)
	past := time.Unix(1, 0)
	switch {
	case rq.byClose && rq.sess != nil && rq.sess.httpConn != nil:
		// A close after a truncated body delimited by the close reads as its end.
		abort(rq.sess.httpConn)
	case rq.proto == 3:
		// The stream of an HTTP/3 response is the handler's to reset. Past deadlines end its
		// reads and writes, and end resets it once the handler returns.
		rc := http.NewResponseController(rq.w)
		_ = rc.SetReadDeadline(past)
		_ = rc.SetWriteDeadline(past)
	default:
		// A past write deadline fails the writes of an HTTP/1.1 response, and is the one reset
		// net/http lets a handler trigger on HTTP/2.
		_ = http.NewResponseController(rq.w).SetWriteDeadline(past)
	}
}

// cutChild returns a child of ctx that a cut cancels with errCut. The HTTP/3 servers derive
// their request contexts from it, having no BaseContext.
func (s *server) cutChild(ctx context.Context) context.Context {
	cctx, cancel := context.WithCancelCause(ctx)
	stop := context.AfterFunc(s.cutCtx, func() { cancel(errCut) })
	context.AfterFunc(ctx, func() { stop() })
	return cctx
}

// waitHandling waits until no handler a session counts per run, a datagram handler, runs, or
// until expired.
func (s *server) waitHandling(sessions []*Session, expired <-chan struct{}) {
	for _, sess := range sessions {
		s.mu.Lock()
		h, ok := sess.closer.(interface{ handling() bool })
		s.mu.Unlock()
		for ok && h.handling() {
			select {
			case <-expired:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}
}

func expiry() (<-chan struct{}, func() bool) {
	expired := make(chan struct{})
	t := time.AfterFunc(alertWriteTimeout, func() { close(expired) })
	return expired, t.Stop
}

// closeActive cuts everything still open in the stages and bounds of docs/lifecycle.md, Cut. A
// later or concurrent call returns once the first cut has ended.
func (s *server) closeActive() {
	s.cutOnce.Do(s.cutAll)
}

// Who started the cut.
const (
	cutByDeadline uint32 = 1 + iota
	cutByClose
)

// cutBy records who started the cut unless another did, then joins it.
func (s *server) cutBy(by uint32) {
	s.cutStarter.CompareAndSwap(0, by)
	s.closeActive()
}

func (s *server) cutAll() {
	s.mu.Lock()
	s.refusing = true
	demuxes := make([]*quicDemux, 0, len(s.quics))
	for d := range s.quics {
		demuxes = append(demuxes, d)
	}
	s.mu.Unlock()
	for _, d := range demuxes {
		d.refuseNew()
	}
	s.stopQUICFronts()

	// A Shutdown under a done context starts the GOAWAY of every HTTP/2 connection and returns.
	// The HTTP/3 one waits for its connections, which the front stage ends: quic-go closes them all
	// once the context of its Shutdown ends.
	done, cancel := context.WithCancel(context.Background())
	cancel()
	go func() { _ = s.h2.Shutdown(done) }()
	go func() { _ = s.term2.Shutdown(done) }()
	go func() { _ = s.h3.Shutdown(context.Background()) }()

	// The units end first, the requests and the sessions together, so their origin reads a cut
	// and a stream is reset or a TLS connection writes its close_notify before the carrier or
	// the socket under it closes, I3. The cancel of the request contexts runs the closer of a
	// session opened on a stream. Each closer bounds itself.
	expired, stop := expiry()
	s.requests.cutAll()
	s.mu.Lock()
	sessions := make([]*Session, 0, len(s.sessions))
	for sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.cut = true
	s.mu.Unlock()
	s.cutCancel(errCut)
	// A demultiplexer lists its sessions under its own lock, never held with the server lock.
	for _, d := range demuxes {
		// The closer of a tunnel ends what it carries before its stream, I3.
		sessions = d.appendSessions(sessions, false)
	}
	var closed sync.WaitGroup
	for _, c := range sessions {
		closed.Go(func() { _ = c.endBy(causeCut, time.Now().Add(alertWriteTimeout)) })
	}
	s.requests.wait(expired)
	s.serving.wait(expired)
	s.waitHandling(sessions, expired)
	stop()
	closed.Wait()

	// Then the fronts. A front connection ends through its closer, which gives a connection with
	// a request still in flight its failed end, any other connection gets its failed end, and
	// the carriers close.
	s.mu.Lock()
	conns := make([]io.Closer, 0, len(s.active))
	for c := range s.active {
		conns = append(conns, c)
	}
	fronts := make([]net.Conn, 0, len(s.fronts))
	frontSess := make([]*Session, 0, len(s.fronts))
	for c := range s.fronts {
		fronts = append(fronts, c)
		frontSess = append(frontSess, s.frontSess[c])
	}
	s.mu.Unlock()
	for i, c := range fronts {
		if sess := frontSess[i]; sess != nil {
			closed.Go(func() { _ = sess.endBy(causeCut, time.Now().Add(alertWriteTimeout)) })
			continue
		}
		closed.Go(func() { closeNormally(c) })
	}
	for _, c := range conns {
		if nc, isConn := c.(net.Conn); isConn {
			closed.Go(func() { abortBy(nc, time.Now().Add(alertWriteTimeout)) })
			continue
		}
		closed.Go(func() { _ = c.Close() })
	}
	closed.Wait()
	s.closeHTTPServers()
	close(s.cutEnded)
}

// closeHTTPServers ends the HTTP servers once the front stage ended their connections, so they stop
// accepting from the queues of the fronts.
func (s *server) closeHTTPServers() {
	_ = s.h1.Close()
	_ = s.h2.Close()
	_ = s.term.Close()
	_ = s.term2.Close()
}

// trackFront is the ConnState of the front servers. It removes a connection hijacked or closed.
func (s *server) trackFront(c net.Conn, state http.ConnState) {
	switch state {
	case http.StateActive:
		if sc := schemeConnOf(c); sc != nil {
			sc.boundHeader(time.Time{})
		}
	case http.StateHijacked, http.StateClosed:
		s.removeFront(c)
	}
}

// trackTerm is the ConnState of the servers of terminated connections.
func (s *server) trackTerm(c net.Conn, state http.ConnState) {
	switch state {
	case http.StateActive, http.StateHijacked, http.StateClosed:
		s.notFresh(c)
	}

}

// addFront records a connection accepted on an explicit front, from its accept to its end or
// its hijack, so the drain waits for it and the front stage ends it. It reports false once a cut has
// started.
func (s *server) addFront(c net.Conn) bool {
	s.mu.Lock()
	if s.refusing {
		s.mu.Unlock()
		return false
	}
	s.fronts[c] = struct{}{}
	s.waiting[c] = struct{}{}
	s.mu.Unlock()
	s.frontsLive.add()
	return true
}

// addFresh records c until it begins a request. Past the start of the drain it ends within T
// unless it begins one.
func (s *server) addFresh(c net.Conn) {
	s.fresh.Store(c, struct{}{})
	if s.closing.Load() {
		time.AfterFunc(alertWriteTimeout, func() { s.endFresh(c) })
	}
}

// notFresh takes c off the connections that have not begun a request.
func (s *server) notFresh(c net.Conn) { s.fresh.Delete(c) }

// endFresh gives c the normal end of a session served as HTTP when it has not begun a request,
// T after the start of the drain gave it to begin one, with no further wait.
func (s *server) endFresh(c net.Conn) {
	if _, ok := s.fresh.LoadAndDelete(c); ok {
		closeNormallyBy(c, time.Now().Add(alertWriteTimeout))
	}
}

// served takes c off the connections awaited.
func (s *server) served(c net.Conn) {
	s.mu.Lock()
	delete(s.waiting, c)
	s.mu.Unlock()
}

// endWaiting is the drain of the connections that have not begun a request: within T they
// begin one or end. Bytes already on their way are still read.
func (s *server) endWaiting() {
	deadline := time.Now().Add(alertWriteTimeout)
	s.mu.Lock()
	for c := range s.waiting {
		_ = c.SetDeadline(deadline)
	}
	s.mu.Unlock()
	s.fresh.Range(func(c, _ any) bool {
		time.AfterFunc(alertWriteTimeout, func() { s.endFresh(c.(net.Conn)) })
		return true
	})
}

func (s *server) removeFront(c net.Conn) {
	s.mu.Lock()
	_, ok := s.fronts[c]
	delete(s.fronts, c)
	delete(s.frontSess, c)
	s.mu.Unlock()
	if ok {
		s.frontsLive.done()
	}
}

// proxyTarget resolves the target of an explicit proxy request, scheme being what takeScheme
// returned for it.
//
// HTTP/1.1 puts it in an absolute-form request target. HTTP/2 has no absolute form. RFC
// 9113 splits the target across :scheme, :authority and :path, which reach a handler as a
// relative URL and Host, :scheme left to takeScheme. So an HTTP/2 request is
// indistinguishable from an origin-form one, and a proxy connection has proxy requests only,
// so it is read as one.
func proxyTarget(r *http.Request, scheme string) (Target, error) {
	if r.URL != nil && r.URL.IsAbs() {
		return targetFromURL(r.URL)
	}
	if r.ProtoMajor < 2 || r.Host == "" {
		// An origin-form target on the proxy port means the client is not configured to use
		// a proxy. Answering with the target it should have sent is the only useful reply.
		return Target{}, errors.New("expected an absolute request target or CONNECT, this is a forward proxy")
	}

	if scheme == "" {
		return Target{}, errors.New("the request has no scheme")
	}
	host, port, ok := splitAuthority(r.Host)
	if !ok {
		return Target{}, errRequestAuthority
	}
	port = cmp.Or(port, defaultPort(scheme))
	return Target{Scheme: scheme, Host: canonicalHost(stringsutil.ToLowerASCIIString(host)), Port: port}, nil
}

var errRequestAuthority = errors.New("request authority is not a host and a port")

var errRequestTargetForm = errors.New("request target is in no form its method allows")

// validRequestTarget reports whether the target of r is in a form RFC 9112 section 3.2 allows
// for its method. The authority-form is left to CONNECT, which a front serves on its own.
func validRequestTarget(r *http.Request) bool {
	u := r.URL
	switch {
	case r.Method == http.MethodConnect:
		return true
	case u == nil:
		return false
	case u.Scheme == "":
		return u.Path != "*" || r.Method == http.MethodOptions
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func targetFromURL(u *url.URL) (Target, error) {
	scheme := cmp.Or(u.Scheme, "http")
	host, port, ok := splitAuthority(u.Host)
	if !ok {
		return Target{}, errRequestAuthority
	}
	port = cmp.Or(port, defaultPort(scheme))
	return Target{Scheme: scheme, Host: canonicalHost(stringsutil.ToLowerASCIIString(host)), Port: port}, nil
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

// slogWriter adapts the net/http error log to the configured structured logger.
type slogWriter struct{ l *slog.Logger }

func (w slogWriter) Write(b []byte) (int, error) {
	w.l.Debug("edge: server", slog.String("msg", strings.TrimRight(string(b), "\n")))
	return len(b), nil
}

// startServing counts the handler of sess among those the cut waits for, which an end of sess
// before the cut releases.
func (s *server) startServing(sess *Session) {
	s.mu.Lock()
	if !sess.serving && !sess.ended {
		sess.serving = true
		s.serving.add()
	}
	s.mu.Unlock()
}

// stopServing releases the count of startServing once the handler returned.
func (s *server) stopServing(sess *Session) {
	s.mu.Lock()
	release := sess.serving
	sess.serving = false
	s.mu.Unlock()
	if release {
		s.serving.done()
	}
}

// frontSessionOf returns the session of the front connection c, nil when it has none.
func (s *server) frontSessionOf(c any) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.frontSess[c]
}

// markHeader records that the response header of rq is about to be written. A gRPC call over
// HTTP/1.1 with its body not read to its end announces the close of its connection.
func (rq *request) markHeader() {
	if rq == nil {
		return
	}
	rq.header.Store(true)
	if rq.callBody != nil && !rq.callBody.eof.Load() {
		rq.w.Header().Set("Connection", "close")
	}
}
