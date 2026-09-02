// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
)

const (
	slashDelim   byte = '/'
	dotDelim     byte = '.'
	bracketDelim byte = '{'
	starDelim    byte = '*'
	plusDelim    byte = '+'
)

// Middleware wraps a handler of one kind. Middleware runs in registration order, outermost
// first, and the proxy-wide ones wrap the ones registered on an entry.
//
//	func log(next edge.HTTP) edge.HTTP {
//		return func(c *edge.HTTPCtx) (*http.Response, error) { ...; return next(c) }
//	}
type Middleware[H Handler] = func(next H) H

// ErrorHandler writes a response for a request that failed. err is never nil.
type ErrorHandler func(c *HTTPCtx, err error) *http.Response

// middleware is one registered wrapper, kept with the kind it wraps so an entry only picks
// up the ones written for its own handler signature.
type middleware struct {
	m    any
	kind Kind
}

// Proxy is a forward proxy that terminates what it admits. TLS is terminated when there is
// TLS, so every handler sees the traffic in the clear, and nothing is relayed encrypted.
//
// A Proxy is safe for concurrent use. Entries can be added and removed while traffic flows.
// Lookups are lock-free and never observe a partially applied write, and every request and
// every datagram is routed on the entries as they stand when it arrives.
type Proxy struct {
	cfg  *config
	tree atomic.Pointer[iTree]

	onError ErrorHandler

	// srv owns the accepted connections and the upstream transports.
	srv *server

	mws []middleware

	// mu serializes write transactions. Reads never take it.
	mu sync.Mutex
}

// config holds the resolved configuration of a [Proxy], read-only once it is built.
type config struct {
	ca        *CA
	logger    *slog.Logger
	proxyAuth ProxyAuthenticator

	transport *Transport
	resolver  NameResolver

	server serverConfig

	maxParams        int
	maxParamKeyBytes int
	maxMatchers      int

	handleSlash TrailingSlashOption
	allowRegexp bool
	rejectECH   bool
	verifyNames NameVerification
}

func newConfig() *config {
	return &config{
		logger:           slog.Default(),
		maxParams:        math.MaxUint8,
		maxParamKeyBytes: math.MaxUint8,
		maxMatchers:      math.MaxUint8,
		handleSlash:      ExactSlash,
		transport:        DefaultTransport(),
		resolver:         net.DefaultResolver,
		server:           defaultServerConfig(),
	}
}

// Must returns a ready to use [Proxy] and panics on error. It is a convenience wrapper for
// [New].
func Must(opts ...ProxyOption) *Proxy {
	p, err := New(opts...)
	if err != nil {
		panic(err)
	}
	return p
}

// New returns a ready to use [Proxy].
//
// Every admitted connection is terminated, so a proxy needs a certificate authority to serve
// anything carried over TLS. An [HTTP] or [QUIC] entry is refused without one, with
// [ErrNoCertificateAuthority]: QUIC is always TLS, and HTTP is in practice, so a registration
// that could not be served is reported at once rather than at the first handshake. That holds
// even for a deployment that only ever sees cleartext.
//
// A [TCP] or [UDP] entry needs none, a stream being often in the clear and a datagram carrying
// no handshake at all; a stream that turns out to carry TLS fails at that handshake instead.
// Use [NewCA], [LoadCA] or [GenerateCA] with [WithCA].
func New(opts ...ProxyOption) (*Proxy, error) {
	cfg := newConfig()
	p := &Proxy{cfg: cfg}
	p.onError = DefaultErrorHandler

	for _, opt := range opts {
		if err := opt.applyProxy(sealedOption{proxy: p}); err != nil {
			return nil, err
		}
	}

	// Clip so newEntry's append(p.mws, e.mws...) can never write into the shared backing array.
	p.mws = slices.Clip(p.mws)

	p.tree.Store(p.newTree())

	srv, err := newServer(p)
	if err != nil {
		return nil, err
	}
	p.srv = srv

	return p, nil
}

func (p *Proxy) newTree() *iTree {
	tree := new(iTree)
	tree.p = p
	tree.patterns = new(node)
	tree.addrs = new(node)
	tree.names = new(node)
	tree.pool = sync.Pool{
		New: func() any {
			return tree.allocateContext()
		},
	}
	return tree
}

func (p *Proxy) getTree() *iTree { return p.tree.Load() }

// MustAdd registers handler for pattern and panics on error. It is a convenience wrapper for
// [Proxy.Add].
func (p *Proxy) MustAdd[H Handler](pattern string, handler H, opts ...EntryOption) Entry[H] {
	e, err := p.Add(pattern, handler, opts...)
	if err != nil {
		panic(err)
	}
	return e
}

// Add registers handler for pattern. The handler signature is what selects the kind of
// traffic it serves, so no type argument is needed unless one is wanted for clarity.
//
//	p.Add("api.test/v1/charges/{id}", func(c *edge.HTTPCtx) (*http.Response, error) { ... })
//	p.Add[edge.TCP]("smtp.test:465", relay)
//
// A pattern is an authority, and a path for the kinds that route each message of a
// connection: [KindHTTP], [KindGRPC] and [KindWebSocket] take one, the others take none.
// The authority is required either way, it is the one the entry admits.
//
//	api.stripe.com/v1/charges       one host
//	+{sub}.corp.internal/health     every subdomain
//	+{any}/health                   every hostname
//	api.stripe.com/*{any}           every path on one host, which is how to just watch it
//	[10.0.0.0/8]/health             every address in a range
//	[::/0]/health                   every IPv6 address
//	smtp.test:465                   one authority, for a kind that routes connections
//
// The port belongs to the pattern, as "host:port/path". The scheme is a matcher, see
// [WithScheme], and so is the method, see [WithMethods].
//
// Registering an entry admits its authority for the traffic its kind rides on, and nothing
// else. An authority no entry names is refused, and so is a unit no entry matches.
//
// The entry takes effect on the next request or datagram routed, and a connection already
// open is served as before. See [Session.Stale] to find the connections the entry would now
// serve, and close them so their clients connect again.
//
// If an error occurs, it returns one of the following:
//   - [*PatternError]: the pattern syntax is invalid.
//   - [*EntryConflictError]: it conflicts with an existing entry.
//   - [*EntryNameConflictError]: the name is already registered.
//   - [ErrInvalidEntry]: the handler is nil or the pattern is empty.
//   - [ErrInvalidConfig]: an option is invalid, or does not apply to this kind.
//   - [ErrInvalidMatcher]: a matcher option is invalid.
//   - [ErrNoCertificateAuthority]: termination needs a CA and none is configured.
func (p *Proxy) Add[H Handler](pattern string, handler H, opts ...EntryOption) (Entry[H], error) {
	txn := p.Txn(true)
	defer txn.Abort()
	e, err := txn.Add(pattern, handler, opts...)
	if err != nil {
		return Entry[H]{}, err
	}
	txn.Commit()
	return e, nil
}

// Update overrides the handler and options of an existing entry. Options and middleware must
// be reapplied: anything not provided falls back to the proxy default.
//
// The change takes effect on the next unit routed, on connections already open included.
func (p *Proxy) Update[H Handler](pattern string, handler H, opts ...EntryOption) (Entry[H], error) {
	txn := p.Txn(true)
	defer txn.Abort()
	e, err := txn.Update(pattern, handler, opts...)
	if err != nil {
		return Entry[H]{}, err
	}
	txn.Commit()
	return e, nil
}

// Delete removes the entry registered for the given kind, pattern and matchers, and returns
// it. The kind has no handler to infer it from, so it is always written out.
//
//	p.Delete[edge.HTTP]("api.test/v1/charges/{id}")
//
// The connections already open are left untouched. Their next request or datagram is routed
// again and refused when nothing matches any more, and a TCP, QUIC or WebSocket connection
// keeps its handler until it ends. See [Proxy.Sessions] to close those.
func (p *Proxy) Delete[H Handler](pattern string, opts ...MatcherOption) (Entry[H], error) {
	txn := p.Txn(true)
	defer txn.Abort()
	e, err := txn.Delete[H](pattern, opts...)
	if err != nil {
		return Entry[H]{}, err
	}
	txn.Commit()
	return e, nil
}

// Has reports whether an entry is registered for the given kind, pattern and matchers.
func (p *Proxy) Has[H Handler](pattern string, matchers ...Matcher) bool {
	_, ok := p.Lookup[H](pattern, matchers...)
	return ok
}

// Lookup returns the entry registered for the given kind, pattern and matchers.
func (p *Proxy) Lookup[H Handler](pattern string, matchers ...Matcher) (Entry[H], bool) {
	e := p.getTree().entryFor(kindOf[H](), pattern, matchers)
	if e == nil {
		return Entry[H]{}, false
	}
	return Entry[H]{e: e}, true
}

// Named returns the entry registered under name for the given kind. An entry registered
// under another kind is not reported, so the lookup can hand back a typed handler.
func (p *Proxy) Named[H Handler](name string) (Entry[H], bool) {
	e := p.getTree().byName(name)
	if e == nil || e.kind != kindOf[H]() {
		return Entry[H]{}, false
	}
	return Entry[H]{e: e}, true
}

// Len returns the number of registered entries. The admissions implied by the per-message
// ones are internal bookkeeping and are not counted.
func (p *Proxy) Len() int { return p.getTree().handlers }

// Iter returns a set of range iterators over a point-in-time snapshot of the routing tree.
func (p *Proxy) Iter() Iter {
	tree := p.getTree()
	return Iter{patterns: tree.patterns, addrs: tree.addrs, names: tree.names, maxDepth: tree.maxDepth}
}

// Updates runs fn in a write transaction on the routing tree. The transaction is committed
// when fn returns nil and aborted otherwise. Only one write transaction runs at a time;
// lookups never block.
//
//	p.Updates(func(txn *edge.Txn) error {
//		if _, err := txn.Delete[edge.HTTP]("api.test/v1/charges/{id}"); err != nil {
//			return err
//		}
//		_, err := txn.Add("api.test/v1/charges/{id}", handler)
//		return err
//	})
func (p *Proxy) Updates(fn func(txn *Txn) error) error {
	txn := p.Txn(true)
	defer txn.Abort()
	if err := fn(txn); err != nil {
		return err
	}
	txn.Commit()
	return nil
}

// View runs fn in a read-only transaction on a point-in-time snapshot of the routing tree.
func (p *Proxy) View(fn func(txn *Txn) error) error {
	txn := p.Txn(false)
	defer txn.Abort()
	return fn(txn)
}

// Txn starts a transaction on the routing tree. A write transaction acquires the proxy write
// lock and must be finalized with [Txn.Commit] or [Txn.Abort].
func (p *Proxy) Txn(write bool) *Txn {
	if write {
		p.mu.Lock()
		return &Txn{p: p, write: true, rootTxn: p.getTree().txn()}
	}
	return &Txn{p: p, rootTxn: p.getTree().txn()}
}

// newEntry builds an entry without registering it. If an error occurs, it returns one of:
//   - [*PatternError]: the pattern syntax is invalid.
//   - [ErrInvalidEntry]: the handler is nil or the pattern is empty.
//   - [ErrInvalidConfig]: an option is invalid or does not apply to this kind.
//   - [ErrInvalidMatcher]: a matcher option is invalid.
func newEntry[H Handler](p *Proxy, pattern string, handler H, opts ...EntryOption) (*entry, error) {
	kind := kindOf[H]()
	if isNilHandler(handler) {
		return nil, fmt.Errorf("%w: nil handler", ErrInvalidEntry)
	}

	pat, paramsCnt, err := p.parsePattern(pattern, kind)
	if err != nil {
		return nil, err
	}

	e := &entry{
		handler:     handler,
		pattern:     pat,
		kind:        kind,
		handleSlash: p.cfg.handleSlash,
	}

	e.params = make([]string, 0, paramsCnt)
	for _, tk := range pat.tokens {
		if tk.typ != nodeStatic {
			e.params = append(e.params, tk.value)
		}
	}

	for _, opt := range opts {
		if err = opt.applyEntry(sealedOption{proxy: p, entry: e}); err != nil {
			return nil, err
		}
	}

	if len(e.matchers) > p.cfg.maxMatchers {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEntry, ErrTooManyMatchers)
	}
	if len(e.matchers) == 0 && e.priority > 0 {
		return nil, fmt.Errorf("%w: priority requires matchers", ErrInvalidEntry)
	}

	e.priority = cmp.Or(e.priority, uint(len(e.matchers)))
	e.serve = chain(append(p.mws, e.mws...), handler)

	return e, nil
}

// isNilHandler reports whether a handler value is nil. A nil func boxed in an interface makes
// the interface itself non-nil, so the comparison has to happen at the concrete type.
func isNilHandler[H Handler](h H) bool {
	switch v := any(h).(type) {
	case HTTP:
		return v == nil
	case GRPC:
		return v == nil
	case WebSocket:
		return v == nil
	case TCP:
		return v == nil
	case QUIC:
		return v == nil
	case UDP:
		return v == nil
	default:
		return true
	}
}

// chain wraps base with every middleware registered for its kind, outermost first. A
// middleware of another kind cannot have the right signature, and the option that accepted it
// already refused it, so the assertion here is the second half of one check.
func chain[H Handler](mws []middleware, base H) H {
	kind := kindOf[H]()
	h := base
	for _, mw := range slices.Backward(mws) {
		if mw.kind != kind {
			continue
		}
		if f, ok := mw.m.(Middleware[H]); ok {
			h = f(h)
		}
	}
	return h
}

// DefaultErrorHandler answers 502 Bad Gateway, and 500 Internal Server Error for a
// [PanicError]. The response body is the status text alone. The error is logged, a panic with
// its stack, and a replacement takes over that logging.
func DefaultErrorHandler(c *HTTPCtx, err error) *http.Response {
	code := http.StatusBadGateway
	pe, panicked := errors.AsType[*PanicError](err)
	if panicked {
		code = http.StatusInternalServerError
	}
	if c != nil && c.r != nil && c.r.p != nil {
		logger := c.r.p.cfg.logger
		if panicked {
			logger.Error("edge: handler panic",
				slog.String("pattern", c.Pattern()),
				slog.Any("panic", pe.Value),
				slog.String("stack", pe.Stack),
			)
		} else {
			logger.Debug("edge: handler error",
				slog.String("pattern", c.Pattern()),
				slog.String("error", err.Error()),
			)
		}
	}
	return Text(code, http.StatusText(code))
}
