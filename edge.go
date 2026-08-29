// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"cmp"
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
// A Proxy is safe for concurrent use. Routes and interception rules can be changed while
// traffic is flowing: lookups are lock-free and never observe a partially applied write.
type Proxy struct {
	cfg    *Config
	routes atomic.Pointer[iTree]
	rules  atomic.Pointer[iTree]

	noRoute HandlerFunc
	onError ErrorHandler

	// srv owns the accepted connections and the upstream transports.
	srv *server

	mws []middleware

	// mu serializes write transactions on both trees. Reads never take it.
	mu sync.Mutex
}

// Config holds the resolved configuration of a [Proxy]. It is read-only once the proxy
// is built and is reported by [Proxy.Config].
type Config struct {
	ca     *CA
	logger *slog.Logger

	transport         *Transport
	originalDst       OriginalDestination
	packetOriginalDst PacketOriginalDestination
	rules             []ruleSpec

	server serverConfig

	maxParams        int
	maxParamKeyBytes int
	maxMatchers      int

	handleSlash  TrailingSlashOption
	mergeSlash   bool
	collapseDots bool
	allowRegexp  bool

	defaultAction Action
}

func newConfig() *Config {
	return &Config{
		logger:           slog.Default(),
		maxParams:        math.MaxUint8,
		maxParamKeyBytes: math.MaxUint8,
		maxMatchers:      math.MaxUint8,
		handleSlash:      ExactSlash,
		defaultAction:    Tunnel,
		transport:        DefaultTransport(),
		server:           defaultServerConfig(),
	}
}

// Logger returns the logger used for connection level errors.
func (c *Config) Logger() *slog.Logger { return c.logger }

// Transport returns the upstream transport configuration.
func (c *Config) Transport() *Transport { return c.transport }

// CA returns the certificate authority used to mint leaf certificates for intercepted
// authorities, or nil when the proxy can only tunnel.
func (c *Config) CA() *CA { return c.ca }

// MaxRouteParams returns the maximum number of parameters allowed in a route pattern.
func (c *Config) MaxRouteParams() int { return c.maxParams }

// MaxRouteParamKeyBytes returns the maximum length of a route parameter name.
func (c *Config) MaxRouteParamKeyBytes() int { return c.maxParamKeyBytes }

// MaxRouteMatchers returns the maximum number of matchers allowed on a route.
func (c *Config) MaxRouteMatchers() int { return c.maxMatchers }

// TrailingSlash returns the default [TrailingSlashOption] applied to new routes.
func (c *Config) TrailingSlash() TrailingSlashOption { return c.handleSlash }

// DefaultAction returns the [Action] applied to an authority matched by no rule.
func (c *Config) DefaultAction() Action { return c.defaultAction }

// AllowRegexpParam reports whether regular expression constraints are enabled in patterns.
func (c *Config) AllowRegexpParam() bool { return c.allowRegexp }

// Must returns a ready to use [Proxy] and panics on error. It is a convenience wrapper
// for [New].
func Must(opts ...Option) *Proxy {
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
// rule or a route, is reported as [ErrNoCertificateAuthority]. Use [NewCA], [LoadCA] or
// [GenerateCA] with [WithCA] to provide one.
func New(opts ...Option) (*Proxy, error) {
	cfg := newConfig()
	p := &Proxy{cfg: cfg}
	p.noRoute = DefaultNoRouteHandler
	p.onError = DefaultErrorHandler

	for _, opt := range opts {
		if err := opt.applyProxy(sealedOption{proxy: p, cfg: cfg}); err != nil {
			return nil, err
		}
	}

	// Clip so NewRoute's append(p.mws, rte.mws...) can never write into the shared backing array.
	p.mws = slices.Clip(p.mws)
	p.noRoute = applyMiddleware(NoRouteHandler, p.mws, p.noRoute)

	p.routes.Store(p.newTree())
	p.rules.Store(p.newTree())

	if cfg.defaultAction == Intercept && cfg.ca == nil {
		return nil, fmt.Errorf("%w: the default action intercepts every authority, configure one with WithCA", ErrNoCertificateAuthority)
	}

	if err := p.applyRuleOptions(); err != nil {
		return nil, err
	}

	srv, err := newServer(p)
	if err != nil {
		return nil, err
	}
	p.srv = srv

	return p, nil
}

// Config returns the resolved configuration of this [Proxy].
func (p *Proxy) Config() *Config { return p.cfg }

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

func (p *Proxy) getRoutes() *iTree { return p.routes.Load() }
func (p *Proxy) getRules() *iTree  { return p.rules.Load() }

// MustHandle registers handler for the given methods and pattern and panics on error. It is
// a convenience wrapper for [Proxy.Handle].
func (p *Proxy) MustHandle(methods []string, pattern string, handler HandlerFunc, opts ...RouteOption) *Route {
	rte, err := p.Handle(methods, pattern, handler, opts...)
	if err != nil {
		panic(err)
	}
	return rte
}

// Handle registers handler for the given methods and pattern. An empty or nil set of methods
// matches every method. On success it returns the newly registered [Route].
//
// A pattern is a request target: an optional scheme, an authority, and a path.
//
//	api.stripe.com/v1/charges           any scheme, any port
//	https://api.stripe.com/v1/charges   https only
//	localhost:8080/api/+{rest}          port 8080 only
//	+{sub}.corp.internal/health         every subdomain
//	/v1/charges                         every authority
//
// Registering a route implicitly marks its authority for interception, unless an explicit
// [WithTunnel] rule matches it more specifically.
//
// If an error occurs, it returns one of the following:
//   - [*PatternError]: the pattern syntax is invalid.
//   - [*RouteConflictError]: the route conflicts with an existing one.
//   - [*RouteNameConflictError]: the route name is already registered.
//   - [ErrInvalidRoute]: a method is invalid, the handler is nil or the pattern is empty.
//   - [ErrInvalidConfig]: a route option is invalid.
//   - [ErrInvalidMatcher]: a matcher option is invalid.
//   - [ErrNoCertificateAuthority]: the route needs interception and no CA is configured.
func (p *Proxy) Handle(methods []string, pattern string, handler HandlerFunc, opts ...RouteOption) (*Route, error) {
	txn := p.Txn(true)
	defer txn.Abort()
	rte, err := txn.Add(methods, pattern, handler, opts...)
	if err != nil {
		return nil, err
	}
	txn.Commit()
	return rte, nil
}

// AddRoute registers a [Route] built with [Proxy.NewRoute].
func (p *Proxy) AddRoute(route *Route) error {
	txn := p.Txn(true)
	defer txn.Abort()
	if err := txn.AddRoute(route); err != nil {
		return err
	}
	txn.Commit()
	return nil
}

// Update overrides the handler and options of an existing route. Route options and middleware
// must be reapplied: anything not provided falls back to the proxy default.
func (p *Proxy) Update(methods []string, pattern string, handler HandlerFunc, opts ...RouteOption) (*Route, error) {
	txn := p.Txn(true)
	defer txn.Abort()
	rte, err := txn.Update(methods, pattern, handler, opts...)
	if err != nil {
		return nil, err
	}
	txn.Commit()
	return rte, nil
}

// UpdateRoute overrides an existing route with the provided one.
func (p *Proxy) UpdateRoute(route *Route) error {
	txn := p.Txn(true)
	defer txn.Abort()
	if err := txn.UpdateRoute(route); err != nil {
		return err
	}
	txn.Commit()
	return nil
}

// Delete removes the route registered for the given methods, pattern and matchers, and
// returns it.
func (p *Proxy) Delete(methods []string, pattern string, opts ...MatcherOption) (*Route, error) {
	txn := p.Txn(true)
	defer txn.Abort()
	rte, err := txn.Delete(methods, pattern, opts...)
	if err != nil {
		return nil, err
	}
	txn.Commit()
	return rte, nil
}

// DeleteRoute removes the provided [Route] and returns the deleted route.
func (p *Proxy) DeleteRoute(route *Route) (*Route, error) {
	txn := p.Txn(true)
	defer txn.Abort()
	rte, err := txn.DeleteRoute(route)
	if err != nil {
		return nil, err
	}
	txn.Commit()
	return rte, nil
}

// Has reports whether a route is registered for the given methods, pattern and matchers.
func (p *Proxy) Has(methods []string, pattern string, matchers ...Matcher) bool {
	return p.Route(methods, pattern, matchers...) != nil
}

// Route returns the [Route] registered for the given methods, pattern and matchers, or nil.
func (p *Proxy) Route(methods []string, pattern string, matchers ...Matcher) *Route {
	return p.getRoutes().route(methods, pattern, matchers)
}

// Name returns the [Route] registered under the given name, or nil.
func (p *Proxy) Name(name string) *Route {
	tree := p.getRoutes()
	return tree.byName(name)
}

// Match looks up the [Route] that would serve r for target, without running any handler and
// without capturing parameters. It reports tsr when the match only holds with the trailing
// slash of the path added or removed.
func (p *Proxy) Match(target Target, r *http.Request) (route *Route, tsr bool) {
	txn := p.Txn(false)
	defer txn.Abort()
	return txn.Match(target, r)
}

// Lookup looks up the [Route] that would serve r for target and returns a [Context] holding
// the captured parameters. The context must be released with [Context.Close].
func (p *Proxy) Lookup(target Target, r *http.Request) (route *Route, cc *Context, tsr bool) {
	txn := p.Txn(false)
	defer txn.Abort()
	return txn.Lookup(target, r)
}

// Len returns the number of registered routes.
func (p *Proxy) Len() int { return p.getRoutes().size }

// Iter returns a set of range iterators over a point-in-time snapshot of the routing tree.
func (p *Proxy) Iter() Iter {
	tree := p.getRoutes()
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
		return &Txn{p: p, write: true, rootTxn: p.getRoutes().txn()}
	}
	return &Txn{p: p, rootTxn: p.getRoutes().txn()}
}

// NewRoute creates a [Route] without registering it. If an error occurs, it returns one of:
//   - [*PatternError]: the pattern syntax is invalid.
//   - [ErrInvalidRoute]: the method is invalid, the handler is nil or the pattern is empty.
//   - [ErrInvalidConfig]: a route option is invalid.
//   - [ErrInvalidMatcher]: a matcher option is invalid.
func (p *Proxy) NewRoute(methods []string, pattern string, handler HandlerFunc, opts ...RouteOption) (*Route, error) {
	if handler == nil {
		return nil, fmt.Errorf("%w: nil handler", ErrInvalidRoute)
	}

	for _, method := range methods {
		if !validMethod(method) {
			return nil, fmt.Errorf("%w: invalid method %q", ErrInvalidRoute, method)
		}
		if method == http.MethodConnect {
			return nil, fmt.Errorf("%w: CONNECT is handled by the tunnel layer, use WithIntercept or WithTunnel", ErrInvalidRoute)
		}
	}

	pat, paramsCnt, err := p.parsePattern(pattern)
	if err != nil {
		return nil, err
	}

	rte := &Route{
		hbase:       handler,
		pattern:     pat,
		handleSlash: p.cfg.handleSlash,
		methodFast:  noFastMethod,
	}

	rte.params = make([]string, 0, paramsCnt)
	for _, tk := range pat.tokens {
		if tk.typ != nodeStatic {
			rte.params = append(rte.params, tk.value)
		}
	}

	for _, opt := range opts {
		if err = opt.applyRoute(sealedOption{route: rte, cfg: p.cfg}); err != nil {
			return nil, err
		}
	}

	if len(rte.matchers) > p.cfg.maxMatchers {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRoute, ErrTooManyMatchers)
	}
	if len(rte.matchers) == 0 && rte.priority > 0 {
		return nil, fmt.Errorf("%w: priority requires matchers", ErrInvalidRoute)
	}

	rte.priority = cmp.Or(rte.priority, uint(len(rte.matchers)))
	rte.hself, rte.hall = applyRouteMiddleware(append(p.mws, rte.mws...), handler)

	if len(methods) > 0 {
		// Defensive copy: the caller keeps ownership of the slice it passed.
		rte.methods = slices.Clone(methods)
		slices.Sort(rte.methods)
		rte.methods = slices.Compact(rte.methods)
	}

	if len(rte.methods) == 1 && len(rte.matchers) == 0 {
		rte.methodFast = rte.methods[0]
	}

	return rte, nil
}

// DefaultNoRouteHandler forwards the request upstream unchanged. It is the handler used for
// intercepted requests that match no route, which makes interception without a matching route
// observable but not disruptive.
func DefaultNoRouteHandler(c *Context) (*http.Response, error) {
	return c.Forward()
}

// DefaultErrorHandler answers 502 Bad Gateway with the error text.
func DefaultErrorHandler(c *Context, err error) *http.Response {
	return Text(http.StatusBadGateway, err.Error())
}

func applyMiddleware(scope HandlerScope, mws []middleware, h HandlerFunc) HandlerFunc {
	m := h
	for i := len(mws) - 1; i >= 0; i-- {
		if mws[i].scope&scope != 0 {
			m = mws[i].m(m)
		}
	}
	return m
}

func applyRouteMiddleware(mws []middleware, base HandlerFunc) (self, all HandlerFunc) {
	self, all = base, base
	for i := len(mws) - 1; i >= 0; i-- {
		if mws[i].scope&RouteHandler != 0 {
			all = mws[i].m(all)
			if !mws[i].g {
				self = mws[i].m(self)
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
