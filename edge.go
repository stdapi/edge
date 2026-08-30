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
	"net/http"
	"regexp"
	"slices"
	"strings"
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

// HandlerFunc handles an intercepted request. It receives the request through c and returns
// the response to send back to the client.
//
// A handler forwards the request upstream with [Context.Forward], which returns the live
// upstream response. Returning that response streams it to the client untouched. Returning
// a response built locally, with [Text] or [JSON] for example, short circuits the upstream
// entirely and the request never leaves the proxy.
//
// A non-nil error is reported to the configured [ErrorHandler], which is responsible for
// the response sent to the client. A handler that returns a nil response and a nil error
// sends a bare 502 Bad Gateway.
type HandlerFunc func(c *Context) (*http.Response, error)

// MiddlewareFunc wraps a [HandlerFunc]. Middleware runs in registration order, outermost first.
type MiddlewareFunc func(next HandlerFunc) HandlerFunc

// ErrorHandler writes a response for a request that failed. err is never nil.
type ErrorHandler func(c *Context, err error) *http.Response

type middleware struct {
	m     MiddlewareFunc
	scope HandlerScope
	g     bool
}

// Proxy is a forward HTTP proxy. It tunnels connections it was not asked to look at and
// intercepts the rest, terminating TLS with its certificate authority so registered
// handlers can inspect and rewrite traffic.
//
// A Proxy is safe for concurrent use. Interceptors and tunnels can be changed while
// traffic is flowing: lookups are lock-free and never observe a partially applied write.
type Proxy struct {
	cfg  *config
	tree atomic.Pointer[iTree]

	noInterceptor HandlerFunc
	onError       ErrorHandler

	// srv owns the accepted connections and the upstream transports.
	srv *server

	mws []middleware

	// mu serializes write transactions. Reads never take it.
	mu sync.Mutex
}

// config holds the resolved configuration of a [Proxy], read-only once it is built.
type config struct {
	ca     *CA
	logger *slog.Logger

	transport *Transport

	server serverConfig

	maxParams        int
	maxParamKeyBytes int
	maxMatchers      int

	handleSlash TrailingSlashOption
	allowRegexp bool
}

func newConfig() *config {
	return &config{
		logger:           slog.Default(),
		maxParams:        math.MaxUint8,
		maxParamKeyBytes: math.MaxUint8,
		maxMatchers:      math.MaxUint8,
		handleSlash:      ExactSlash,
		transport:        DefaultTransport(),
		server:           defaultServerConfig(),
	}
}

// Must returns a ready to use [Proxy] and panics on error. It is a convenience wrapper
// for [New].
func Must(opts ...ProxyOption) *Proxy {
	p, err := New(opts...)
	if err != nil {
		panic(err)
	}
	return p
}

// New returns a ready to use [Proxy].
//
// A proxy with no certificate authority can still tunnel and observe connections, but it
// cannot intercept: anything that would require minting a leaf certificate, an intercept
// an interceptor, is reported as [ErrNoCertificateAuthority]. Use [NewCA], [LoadCA] or
// [GenerateCA] with [WithCA] to provide one.
func New(opts ...ProxyOption) (*Proxy, error) {
	cfg := newConfig()
	p := &Proxy{cfg: cfg}
	p.noInterceptor = DefaultNoInterceptorHandler
	p.onError = DefaultErrorHandler

	for _, opt := range opts {
		if err := opt.applyProxy(sealedOption{proxy: p}); err != nil {
			return nil, err
		}
	}

	// Clip so newInterceptor's append(p.mws, ic.mws...) can never write into the shared backing array.
	p.mws = slices.Clip(p.mws)
	p.noInterceptor = applyMiddleware(NoInterceptorHandler, p.mws, p.noInterceptor)

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
	tree.names = new(node)
	tree.methods = make(map[string]uint)
	tree.pool = sync.Pool{
		New: func() any {
			return tree.allocateContext()
		},
	}
	return tree
}

func (p *Proxy) getTree() *iTree { return p.tree.Load() }

// MustAddInterceptor registers handler for the given methods and pattern and panics on error. It is
// a convenience wrapper for [Proxy.AddInterceptor].
func (p *Proxy) MustAddInterceptor(methods []string, pattern string, handler HandlerFunc, opts ...InterceptorOption) *Interceptor {
	ic, err := p.AddInterceptor(methods, pattern, handler, opts...)
	if err != nil {
		panic(err)
	}
	return ic
}

// AddInterceptor registers handler for the given methods and pattern. An empty or nil set of
// methods matches every method. On success it returns the newly registered [Interceptor].
//
// A pattern is an authority and a path. The authority is required: it is the one the
// interceptor arms, and interception is what makes the handler reachable at all.
//
//	api.stripe.com/v1/charges       one host
//	+{sub}.corp.internal/health     every subdomain
//	+{any}/health                   every authority
//	api.stripe.com/*{any}           every path on one host, which is how to just watch it
//
// The port belongs to the pattern, as "host:port/path". The scheme is a matcher: see [WithScheme].
//
// Registering an interceptor marks its authority for interception, so nothing else has to be
// declared. An authority already tunneled is a conflict rather than a silent no-op, since the
// handler could never run.
//
// If an error occurs, it returns one of the following:
//   - [*PatternError]: the pattern syntax is invalid.
//   - [*InterceptorConflictError]: it conflicts with an existing interceptor.
//   - [*InterceptorNameConflictError]: the name is already registered.
//   - [ErrInvalidInterceptor]: a method is invalid, the handler is nil or the pattern is empty.
//   - [ErrInvalidConfig]: an option is invalid.
//   - [ErrInvalidMatcher]: a matcher option is invalid.
//   - [ErrAuthorityConflict]: the authority is tunneled, so the handler could never run.
//   - [ErrNoCertificateAuthority]: interception needs a CA and none is configured.
func (p *Proxy) AddInterceptor(methods []string, pattern string, handler HandlerFunc, opts ...InterceptorOption) (*Interceptor, error) {
	txn := p.Txn(true)
	defer txn.Abort()
	ic, err := txn.AddInterceptor(methods, pattern, handler, opts...)
	if err != nil {
		return nil, err
	}
	txn.Commit()
	return ic, nil
}

// UpdateInterceptor overrides the handler and options of an existing interceptor. Options and middleware
// must be reapplied: anything not provided falls back to the proxy default.
func (p *Proxy) UpdateInterceptor(methods []string, pattern string, handler HandlerFunc, opts ...InterceptorOption) (*Interceptor, error) {
	txn := p.Txn(true)
	defer txn.Abort()
	ic, err := txn.UpdateInterceptor(methods, pattern, handler, opts...)
	if err != nil {
		return nil, err
	}
	txn.Commit()
	return ic, nil
}

// DeleteInterceptor removes the interceptor registered for the given methods, pattern and matchers, and
// returns it.
func (p *Proxy) DeleteInterceptor(methods []string, pattern string, opts ...MatcherOption) (*Interceptor, error) {
	txn := p.Txn(true)
	defer txn.Abort()
	ic, err := txn.DeleteInterceptor(methods, pattern, opts...)
	if err != nil {
		return nil, err
	}
	txn.Commit()
	return ic, nil
}

// removeInterceptor removes the provided [Interceptor] and returns the deleted interceptor.
func (p *Proxy) removeInterceptor(ic *Interceptor) (*Interceptor, error) {
	txn := p.Txn(true)
	defer txn.Abort()
	ic, err := txn.removeInterceptor(ic)
	if err != nil {
		return nil, err
	}
	txn.Commit()
	return ic, nil
}

// Has reports whether an interceptor is registered for the given methods, pattern and matchers.
func (p *Proxy) Has(methods []string, pattern string, matchers ...Matcher) bool {
	return p.Interceptor(methods, pattern, matchers...) != nil
}

// Interceptor returns the [Interceptor] registered for the given methods, pattern and matchers, or nil.
func (p *Proxy) Interceptor(methods []string, pattern string, matchers ...Matcher) *Interceptor {
	return p.getTree().interceptor(methods, pattern, matchers)
}

// Name returns the [Interceptor] registered under the given name, or nil.
func (p *Proxy) Name(name string) *Interceptor {
	tree := p.getTree()
	return tree.byName(name)
}

// AuthoritiesLen returns the number of registered authority entries, the ones declared with
// [Proxy.AddTunnel] and the ones implied by interceptors alike.
func (p *Proxy) AuthoritiesLen() int { return p.getTree().authorities }

// InterceptorsLen returns the number of registered interceptors.
func (p *Proxy) InterceptorsLen() int { return p.getTree().interceptors }

// Iter returns a set of range iterators over a point-in-time snapshot of the routing tree.
func (p *Proxy) Iter() Iter {
	tree := p.getTree()
	return Iter{patterns: tree.patterns, names: tree.names, methods: tree.methods, maxDepth: tree.maxDepth}
}

// Updates runs fn in a write transaction on the routing tree. The transaction is committed
// when fn returns nil and aborted otherwise. Only one write transaction runs at a time;
// lookups never block.
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

// newInterceptor creates a [Interceptor] without registering it. If an error occurs, it returns one of:
//   - [*PatternError]: the pattern syntax is invalid.
//   - [ErrInvalidInterceptor]: the method is invalid, the handler is nil or the pattern is empty.
//   - [ErrInvalidConfig]: an interceptor option is invalid.
//   - [ErrInvalidMatcher]: a matcher option is invalid.
func (p *Proxy) newInterceptor(methods []string, pattern string, handler HandlerFunc, opts ...InterceptorOption) (*Interceptor, error) {
	if handler == nil {
		return nil, fmt.Errorf("%w: nil handler", ErrInvalidInterceptor)
	}

	for _, method := range methods {
		if !validMethod(method) {
			return nil, fmt.Errorf("%w: invalid method %q", ErrInvalidInterceptor, method)
		}
		if method == http.MethodConnect {
			return nil, fmt.Errorf("%w: CONNECT is handled by the tunnel layer, not by an interceptor", ErrInvalidInterceptor)
		}
	}

	pat, paramsCnt, err := p.parsePattern(pattern)
	if err != nil {
		return nil, err
	}

	ic := &Interceptor{
		hbase:       handler,
		pattern:     pat,
		handleSlash: p.cfg.handleSlash,
		methodFast:  noFastMethod,
	}

	ic.params = make([]string, 0, paramsCnt)
	for _, tk := range pat.tokens {
		if tk.typ != nodeStatic {
			ic.params = append(ic.params, tk.value)
		}
	}

	for _, opt := range opts {
		if err = opt.applyInterceptor(sealedOption{proxy: p, interceptor: ic}); err != nil {
			return nil, err
		}
	}

	if len(ic.matchers) > p.cfg.maxMatchers {
		return nil, fmt.Errorf("%w: %w", ErrInvalidInterceptor, ErrTooManyMatchers)
	}
	if len(ic.matchers) == 0 && ic.priority > 0 {
		return nil, fmt.Errorf("%w: priority requires matchers", ErrInvalidInterceptor)
	}

	ic.priority = cmp.Or(ic.priority, uint(len(ic.matchers)))
	ic.hself, ic.hall = applyInterceptorMiddleware(append(p.mws, ic.mws...), handler)

	if len(methods) > 0 {
		// Defensive copy: the caller keeps ownership of the slice it passed.
		ic.methods = slices.Clone(methods)
		slices.Sort(ic.methods)
		ic.methods = slices.Compact(ic.methods)
	}

	if len(ic.methods) == 1 && len(ic.matchers) == 0 && ic.pattern.port == "" {
		// A port is compared in matchSlow, so an interceptor naming one cannot take the fast
		// path any more than one carrying a matcher can.
		ic.methodFast = ic.methods[0]
	}

	return ic, nil
}

// DefaultNoInterceptorHandler forwards the request upstream unchanged. It is the handler used for
// intercepted requests that match no interceptor, which makes interception without a matching interceptor
// observable but not disruptive.
func DefaultNoInterceptorHandler(c *Context) (*http.Response, error) {
	return c.Forward()
}

// DefaultErrorHandler answers 502 Bad Gateway with the error text, and 500 for a
// [PanicError], which it logs with its stack. A replacement takes over that logging.
func DefaultErrorHandler(c *Context, err error) *http.Response {
	if pe, ok := errors.AsType[*PanicError](err); ok {
		if c != nil && c.p != nil {
			c.p.cfg.logger.Error("edge: handler panic",
				slog.String("pattern", c.Pattern()),
				slog.Any("panic", pe.Value),
				slog.String("stack", pe.Stack),
			)
		}
		return Text(http.StatusInternalServerError, pe.Error())
	}
	return Text(http.StatusBadGateway, err.Error())
}

func applyMiddleware(scope HandlerScope, mws []middleware, h HandlerFunc) HandlerFunc {
	m := h
	for _, mw := range slices.Backward(mws) {
		if mw.scope&scope != 0 {
			m = mw.m(m)
		}
	}
	return m
}

func applyInterceptorMiddleware(mws []middleware, base HandlerFunc) (self, all HandlerFunc) {
	self, all = base, base
	for _, mw := range slices.Backward(mws) {
		if mw.scope&InterceptorHandler != 0 {
			all = mw.m(all)
			if !mw.g {
				self = mw.m(self)
			}
		}
	}
	return self, all
}

func firstHeader(headers http.Header, k string) (string, bool) {
	if v := headers[k]; len(v) > 0 {
		return v[0], true
	}
	return "", false
}

func rawExpr(re *regexp.Regexp) string {
	expr := re.String()
	if strings.HasPrefix(expr, "(?i)") {
		return expr[8 : len(expr)-2]
	}
	return expr[4 : len(expr)-2]
}
