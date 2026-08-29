// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"log/slog"
	"slices"
	"time"
)

// TrailingSlashOption controls whether a route matches a path whose trailing slash differs
// from the one it was registered with.
type TrailingSlashOption uint8

const (
	// ExactSlash matches the path exactly as registered. /foo and /foo/ are distinct routes.
	ExactSlash TrailingSlashOption = iota
	// RelaxedSlash matches the path with or without its trailing slash. An exactly registered
	// variant always wins over a relaxed match.
	RelaxedSlash

	slashOptionSentinel
)

// HandlerScope selects which handlers a middleware wraps.
type HandlerScope uint8

const (
	// RouteHandler wraps handlers registered for a route.
	RouteHandler HandlerScope = 1 << iota
	// NoRouteHandler wraps the handler used when an intercepted request matches no route.
	NoRouteHandler
	// RuleHandler is the scope of an interception rule lookup. No middleware runs in it.
	RuleHandler

	// AllHandlers wraps every handler.
	AllHandlers = RouteHandler | NoRouteHandler
)

// Option configures a [Proxy].
type Option interface {
	applyProxy(sealedOption) error
}

// RouteOption configures a [Route].
type RouteOption interface {
	applyRoute(sealedOption) error
}

// MatcherOption identifies a route by its matchers, for lookup and deletion.
type MatcherOption interface {
	applyMatcher(sealedOption) error
}

type sealedOption struct {
	proxy *Proxy
	cfg   *Config
	route *Route
}

type optionFunc func(sealedOption) error

func (o optionFunc) applyProxy(s sealedOption) error   { return o(s) }
func (o optionFunc) applyRoute(s sealedOption) error   { return o(s) }
func (o optionFunc) applyMatcher(s sealedOption) error { return o(s) }

// WithCA sets the certificate authority used to mint leaf certificates for intercepted
// authorities. Without it the proxy can only tunnel.
func WithCA(ca *CA) Option {
	return optionFunc(func(s sealedOption) error {
		if ca == nil {
			return fmt.Errorf("%w: certificate authority cannot be nil", ErrInvalidConfig)
		}
		s.cfg.ca = ca
		return nil
	})
}

// WithIntercept marks the given authorities for interception. Each pattern is an authority
// with no path, using the same syntax as the authority half of a route pattern.
//
//	edge.WithIntercept("api.stripe.com", "+{sub}.corp.internal", "localhost:8080")
//
// Rules are evaluated most specific first, so a static authority beats a parameter, which
// beats a wildcard. Registering a route implicitly adds an intercept rule for its authority.
func WithIntercept(patterns ...string) Option {
	return optionFunc(func(s sealedOption) error {
		s.cfg.rules = append(s.cfg.rules, ruleSpec{action: Intercept, patterns: slices.Clone(patterns)})
		return nil
	})
}

// WithTunnel marks the given authorities for end to end tunneling, carving exceptions out of
// broader intercept rules.
//
//	edge.New(
//	    edge.WithIntercept("+{sub}.stripe.com"),
//	    edge.WithTunnel("checkout.stripe.com"),
//	)
//
// checkout.stripe.com tunnels because a static authority is more specific than a wildcard.
func WithTunnel(patterns ...string) Option {
	return optionFunc(func(s sealedOption) error {
		s.cfg.rules = append(s.cfg.rules, ruleSpec{action: Tunnel, patterns: slices.Clone(patterns)})
		return nil
	})
}

// WithReject refuses connections to the given authorities. Explicit proxy clients get
// 403 Forbidden; transparent connections are closed.
func WithReject(patterns ...string) Option {
	return optionFunc(func(s sealedOption) error {
		s.cfg.rules = append(s.cfg.rules, ruleSpec{action: Reject, patterns: slices.Clone(patterns)})
		return nil
	})
}

// WithDefaultAction sets what happens to an authority matched by no rule. It defaults to
// [Tunnel], which keeps traffic the proxy was not asked about opaque to it.
func WithDefaultAction(action Action) Option {
	return optionFunc(func(s sealedOption) error {
		switch action {
		case Tunnel, Intercept, Reject:
			s.cfg.defaultAction = action
			return nil
		default:
			return fmt.Errorf("%w: unknown default action", ErrInvalidConfig)
		}
	})
}

// WithNoRouteHandler sets the handler called for an intercepted request that matches no
// route. It defaults to [DefaultNoRouteHandler], which forwards the request unchanged.
func WithNoRouteHandler(handler HandlerFunc) Option {
	return optionFunc(func(s sealedOption) error {
		if handler == nil {
			return fmt.Errorf("%w: no route handler cannot be nil", ErrInvalidConfig)
		}
		s.proxy.noRoute = handler
		return nil
	})
}

// WithErrorHandler sets the handler that turns a handler error into a response. It defaults
// to [DefaultErrorHandler], which answers 502 Bad Gateway.
func WithErrorHandler(handler ErrorHandler) Option {
	return optionFunc(func(s sealedOption) error {
		if handler == nil {
			return fmt.Errorf("%w: error handler cannot be nil", ErrInvalidConfig)
		}
		s.proxy.onError = handler
		return nil
	})
}

// WithMiddleware registers middleware for every handler scope. Middleware runs in
// registration order, outermost first.
func WithMiddleware(m ...MiddlewareFunc) Option {
	return WithMiddlewareFor(AllHandlers, m...)
}

// WithMiddlewareFor registers middleware for the given scopes only.
func WithMiddlewareFor(scope HandlerScope, m ...MiddlewareFunc) Option {
	return optionFunc(func(s sealedOption) error {
		for i, fn := range m {
			if fn == nil {
				return fmt.Errorf("%w: middleware at index %d is nil", ErrInvalidConfig, i)
			}
			s.proxy.mws = append(s.proxy.mws, middleware{m: fn, scope: scope, g: true})
		}
		return nil
	})
}

// WithRouteMiddleware registers middleware for a single route, applied after the proxy-wide
// middleware.
func WithRouteMiddleware(m ...MiddlewareFunc) RouteOption {
	return optionFunc(func(s sealedOption) error {
		for i, fn := range m {
			if fn == nil {
				return fmt.Errorf("%w: middleware at index %d is nil", ErrInvalidConfig, i)
			}
			s.route.mws = append(s.route.mws, middleware{m: fn, scope: RouteHandler})
		}
		return nil
	})
}

// WithName names a route so it can be looked up with [Proxy.Name]. Names are unique.
func WithName(name string) RouteOption {
	return optionFunc(func(s sealedOption) error {
		if name == "" {
			return fmt.Errorf("%w: route name cannot be empty", ErrInvalidConfig)
		}
		s.route.name = name
		return nil
	})
}

// WithAnnotation attaches an arbitrary value to a route, readable with [Route.Annotation].
func WithAnnotation(key, value any) RouteOption {
	return optionFunc(func(s sealedOption) error {
		if s.route.annots == nil {
			s.route.annots = make(map[any]any, 1)
		}
		s.route.annots[key] = value
		return nil
	})
}

// WithTrailingSlash configures trailing slash handling, proxy-wide or for a single route.
// A route setting overrides the proxy default.
func WithTrailingSlash(opt TrailingSlashOption) interface {
	Option
	RouteOption
} {
	return optionFunc(func(s sealedOption) error {
		if opt >= slashOptionSentinel {
			return fmt.Errorf("%w: unknown trailing slash option", ErrInvalidConfig)
		}
		if s.route != nil {
			s.route.handleSlash = opt
			return nil
		}
		s.cfg.handleSlash = opt
		return nil
	})
}

// WithMergeSlashes collapses consecutive slashes before matching. The request itself is
// never rewritten: what goes upstream is the target the client sent, byte for byte.
func WithMergeSlashes(enable bool) Option {
	return optionFunc(func(s sealedOption) error {
		s.cfg.mergeSlash = enable
		return nil
	})
}

// WithCollapseDotSegments resolves "." and ".." segments before matching. As with
// [WithMergeSlashes] the forwarded request is left untouched. A ".." escaping above the root
// makes the request match no route.
func WithCollapseDotSegments(enable bool) Option {
	return optionFunc(func(s sealedOption) error {
		s.cfg.collapseDots = enable
		return nil
	})
}

// WithRegexpParam enables regular expression constraints on pattern parameters. It is off by
// default: a regexp runs on every candidate segment during a lookup, and an expression with
// pathological backtracking turns a request into a denial of service.
func WithRegexpParam(enable bool) Option {
	return optionFunc(func(s sealedOption) error {
		s.cfg.allowRegexp = enable
		return nil
	})
}

// WithMaxRouteParams bounds how many parameters a pattern may declare. It defaults to 255.
func WithMaxRouteParams(n uint8) Option {
	return optionFunc(func(s sealedOption) error {
		if n == 0 {
			return fmt.Errorf("%w: max route params must be greater than zero", ErrInvalidConfig)
		}
		s.cfg.maxParams = int(n)
		return nil
	})
}

// WithMaxRouteParamKeyBytes bounds the length of a parameter name. It defaults to 255.
func WithMaxRouteParamKeyBytes(n uint8) Option {
	return optionFunc(func(s sealedOption) error {
		if n == 0 {
			return fmt.Errorf("%w: max route param key bytes must be greater than zero", ErrInvalidConfig)
		}
		s.cfg.maxParamKeyBytes = int(n)
		return nil
	})
}

// WithMaxRouteMatchers bounds how many matchers a route may carry, implicit scheme and port
// matchers included. It defaults to 255.
func WithMaxRouteMatchers(n uint8) Option {
	return optionFunc(func(s sealedOption) error {
		s.cfg.maxMatchers = int(n)
		return nil
	})
}

// WithTransport configures how the proxy reaches upstream servers.
func WithTransport(t *Transport) Option {
	return optionFunc(func(s sealedOption) error {
		if t == nil {
			return fmt.Errorf("%w: transport cannot be nil", ErrInvalidConfig)
		}
		s.cfg.transport = t
		return nil
	})
}

// WithOriginalDestination tells the proxy how to recover the address a transparently
// redirected connection was headed to. Use [OriginalDestinationSocket] on Linux, where the
// redirect is done by netfilter and the original address survives in the socket.
//
// Without it, transparent mode works only for clients that send a TLS server name or a Host
// header, and the upstream is reached by resolving that name again.
func WithOriginalDestination(fn OriginalDestination) Option {
	return optionFunc(func(s sealedOption) error {
		if fn == nil {
			return fmt.Errorf("%w: original destination resolver cannot be nil", ErrInvalidConfig)
		}
		s.cfg.originalDst = fn
		return nil
	})
}

// WithPacketOriginalDestination tells the proxy how to recover the address a redirected
// datagram was headed to. It is the UDP counterpart of [WithOriginalDestination], used to
// place QUIC connections.
//
// Without it a QUIC connection is placed by the server name in its ClientHello, on port 443.
// That covers HTTP/3 as it is deployed, and is wrong for an origin reached on another port.
func WithPacketOriginalDestination(fn PacketOriginalDestination) Option {
	return optionFunc(func(s sealedOption) error {
		if fn == nil {
			return fmt.Errorf("%w: packet original destination resolver cannot be nil", ErrInvalidConfig)
		}
		s.cfg.packetOriginalDst = fn
		return nil
	})
}

// WithLogger sets the logger used for connection level errors the proxy cannot report to a
// handler. It defaults to [slog.Default].
func WithLogger(l *slog.Logger) Option {
	return optionFunc(func(s sealedOption) error {
		if l == nil {
			return fmt.Errorf("%w: logger cannot be nil", ErrInvalidConfig)
		}
		s.cfg.logger = l
		return nil
	})
}

// WithReadHeaderTimeout bounds how long the proxy waits for a client to send its request
// headers. Zero disables the timeout. It defaults to 10s.
func WithReadHeaderTimeout(d time.Duration) Option {
	return optionFunc(func(s sealedOption) error {
		if d < 0 {
			return fmt.Errorf("%w: read header timeout cannot be negative", ErrInvalidConfig)
		}
		s.cfg.server.readHeaderTimeout = d
		return nil
	})
}

// WithIdleTimeout bounds how long an idle keep-alive connection is kept open. Zero disables
// the timeout. It defaults to 90s.
func WithIdleTimeout(d time.Duration) Option {
	return optionFunc(func(s sealedOption) error {
		if d < 0 {
			return fmt.Errorf("%w: idle timeout cannot be negative", ErrInvalidConfig)
		}
		s.cfg.server.idleTimeout = d
		return nil
	})
}

// WithTunnelIdleTimeout bounds how long a tunneled connection may stay silent in both
// directions before it is closed. Zero disables the timeout, which is the default: a tunnel
// can legitimately carry a long-lived stream the proxy knows nothing about.
func WithTunnelIdleTimeout(d time.Duration) Option {
	return optionFunc(func(s sealedOption) error {
		if d < 0 {
			return fmt.Errorf("%w: tunnel idle timeout cannot be negative", ErrInvalidConfig)
		}
		s.cfg.server.tunnelIdleTimeout = d
		return nil
	})
}

// WithMaxHeaderBytes bounds the size of a request header block. It defaults to 1 MiB.
func WithMaxHeaderBytes(n int) Option {
	return optionFunc(func(s sealedOption) error {
		if n <= 0 {
			return fmt.Errorf("%w: max header bytes must be greater than zero", ErrInvalidConfig)
		}
		s.cfg.server.maxHeaderBytes = n
		return nil
	})
}

// WithMatcher attaches a [Matcher] to a route, narrowing it beyond its pattern and method.
// A route with matchers is evaluated before one without at the same pattern.
func WithMatcher(m Matcher) interface {
	RouteOption
	MatcherOption
} {
	return optionFunc(func(s sealedOption) error {
		if m == nil {
			return fmt.Errorf("%w: matcher cannot be nil", ErrInvalidMatcher)
		}
		s.route.matchers = append(s.route.matchers, m)
		return nil
	})
}

// WithMatchers attaches several matchers to a route. All must match.
func WithMatchers(matchers ...Matcher) interface {
	RouteOption
	MatcherOption
} {
	return optionFunc(func(s sealedOption) error {
		for i, m := range matchers {
			if m == nil {
				return fmt.Errorf("%w: matcher at index %d is nil", ErrInvalidMatcher, i)
			}
			s.route.matchers = append(s.route.matchers, m)
		}
		return nil
	})
}

// WithScheme narrows a route to one scheme, http or https. A route pattern carries a
// hostname and a path and nothing else, so this is how the scheme is expressed.
//
// A route with no scheme matches both, which is almost always what a proxy wants: the
// authority and the path say what the traffic is, the scheme only says how it was carried.
func WithScheme(scheme string) interface {
	RouteOption
	MatcherOption
} {
	return optionFunc(func(s sealedOption) error {
		m, err := MatchScheme(scheme)
		if err != nil {
			return err
		}
		s.route.matchers = append(s.route.matchers, m)
		return nil
	})
}

// WithPort narrows a route to one port. A route with no port matches every port, and the
// port compared against is always explicit: a request that carries none is given the default
// for its scheme before the lookup, so 443 matches a plain https:// target.
//
// This is the usual way to tell apart services that share a host, which is what local test
// environments are made of:
//
//	p.MustHandle([]string{"GET"}, "localhost/api", api, edge.WithPort("8080"))
//	p.MustHandle([]string{"GET"}, "localhost/", ui, edge.WithPort("3000"))
func WithPort(port string) interface {
	RouteOption
	MatcherOption
} {
	return optionFunc(func(s sealedOption) error {
		m, err := MatchPort(port)
		if err != nil {
			return err
		}
		s.route.matchers = append(s.route.matchers, m)
		return nil
	})
}

// WithMatchersPriority orders routes that share a pattern. Higher runs first. It defaults to
// the number of matchers on the route, so the most constrained route is tried first.
func WithMatchersPriority(priority uint) RouteOption {
	return optionFunc(func(s sealedOption) error {
		s.route.priority = priority
		return nil
	})
}

type ruleSpec struct {
	patterns []string
	action   Action
}

type serverConfig struct {
	readHeaderTimeout    time.Duration
	readTimeout          time.Duration
	writeTimeout         time.Duration
	idleTimeout          time.Duration
	tunnelIdleTimeout    time.Duration
	maxHeaderBytes       int
	maxConcurrentStreams uint32
}

func defaultServerConfig() serverConfig {
	return serverConfig{
		readHeaderTimeout:    10 * time.Second,
		idleTimeout:          90 * time.Second,
		maxHeaderBytes:       1 << 20,
		maxConcurrentStreams: 250,
	}
}
