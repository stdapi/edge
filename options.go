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

// TrailingSlashOption controls whether an entry matches a path whose trailing slash differs
// from the one it was registered with.
type TrailingSlashOption uint8

const (
	// ExactSlash matches the path exactly as registered. /foo and /foo/ are distinct entries.
	ExactSlash TrailingSlashOption = iota
	// RelaxedSlash matches the path with or without its trailing slash. An exactly registered
	// variant always wins over a relaxed match.
	RelaxedSlash

	slashOptionSentinel
)

// ProxyOption configures a [Proxy].
type ProxyOption interface {
	applyProxy(sealedOption) error
}

// EntryOption configures one entry. An option that only makes sense for some kinds is refused
// on the others, at registration, with [ErrInvalidConfig].
type EntryOption interface {
	applyEntry(sealedOption) error
}

// MatcherOption identifies an entry by its matchers, for lookup and deletion.
type MatcherOption interface {
	applyMatcher(sealedOption) error
}

// sealedOption carries what an option may reach. entry is non-nil exactly when the option is
// being applied to one, which is how an option usable in both places tells them apart. proxy
// is always set, so the configuration is always reachable through it.
type sealedOption struct {
	proxy *Proxy
	entry *entry
}

type optionFunc func(sealedOption) error

func (o optionFunc) applyProxy(s sealedOption) error   { return o(s) }
func (o optionFunc) applyEntry(s sealedOption) error   { return o(s) }
func (o optionFunc) applyMatcher(s sealedOption) error { return o(s) }

// onlyKinds refuses an option on an entry whose kind it does not describe. The handler
// signature is what fixes the kind, so an option that cannot apply is a mistake worth
// reporting rather than a setting that quietly does nothing.
func onlyKinds(s sealedOption, name string, kinds ...Kind) error {
	if s.entry == nil || slices.Contains(kinds, s.entry.kind) {
		return nil
	}
	return fmt.Errorf("%w: %s does not apply to a %s entry", ErrInvalidConfig, name, s.entry.kind)
}

// onlyPerMessage refuses a matcher on an entry keyed on an authority alone. Admission selects
// on the kind and the port, before anything has been read that a matcher could look at, so a
// matcher there would be a written policy narrower than the one enforced. A [Matcher] also
// reads a request, which an admission does not have.
func onlyPerMessage(s sealedOption, name string) error {
	if s.entry == nil || s.entry.kind.perMessage() {
		return nil
	}
	return fmt.Errorf("%w: %s narrows a request, and a %s entry admits a connection before any request exists",
		ErrInvalidConfig, name, s.entry.kind)
}

// WithCA sets the certificate authority used to mint leaf certificates for the authorities the
// proxy terminates. Every admitted connection is terminated, so anything carried over TLS
// needs one.
func WithCA(ca *CA) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		if ca == nil {
			return fmt.Errorf("%w: certificate authority cannot be nil", ErrInvalidConfig)
		}
		s.proxy.cfg.ca = ca
		return nil
	})
}

// WithProxyAuth requires clients of the explicit forward proxy to authenticate. A refused
// request is answered with 407, carrying the challenges the authenticator offers, or with 403
// when it offers none. The check runs before the authority is resolved, so an unauthenticated
// client learns nothing about what the proxy admits.
//
// A transparently redirected client does not know a proxy exists and can carry no proxy
// credentials, so this has no effect on the transparent listeners.
func WithProxyAuth(a ProxyAuthenticator) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		if a == nil {
			return fmt.Errorf("%w: proxy authenticator cannot be nil", ErrInvalidConfig)
		}
		s.proxy.cfg.proxyAuth = a
		return nil
	})
}

// WithErrorHandler sets the handler that turns an [HTTP] handler error into a response. It
// defaults to [DefaultErrorHandler], which answers 502 Bad Gateway. A handler of another kind
// has no response to write, so its error is logged instead.
func WithErrorHandler(handler ErrorHandler) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		if handler == nil {
			return fmt.Errorf("%w: error handler cannot be nil", ErrInvalidConfig)
		}
		s.proxy.onError = handler
		return nil
	})
}

// WithMiddleware registers middleware, proxy-wide or on a single entry depending on where it
// is passed. Middleware runs in registration order, outermost first, and the proxy-wide ones
// wrap the entry's.
//
// The kind a middleware wraps is its own signature, so a proxy-wide registration only reaches
// the entries of that kind, and one passed to an entry of another kind is refused.
//
//	edge.New(edge.WithCA(ca), edge.WithMiddleware(logHTTP))          // every HTTP entry
//	p.Add("api.test/v1", h, edge.WithMiddleware(retry))              // this one only
func WithMiddleware(m ...any) interface {
	ProxyOption
	EntryOption
} {
	return optionFunc(func(s sealedOption) error {
		for i, fn := range m {
			kind, ok := middlewareKind(fn)
			if !ok {
				return fmt.Errorf("%w: middleware at index %d is not a func(edge.T) edge.T for any handler kind",
					ErrInvalidConfig, i)
			}
			// entry is set exactly when the option is applied to one, which is what tells
			// the two placements apart.
			if s.entry != nil {
				if kind != s.entry.kind {
					return fmt.Errorf("%w: middleware at index %d wraps a %s handler, not a %s one",
						ErrInvalidConfig, i, kind, s.entry.kind)
				}
				s.entry.mws = append(s.entry.mws, middleware{m: fn, kind: kind})
				continue
			}
			s.proxy.mws = append(s.proxy.mws, middleware{m: fn, kind: kind})
		}
		return nil
	})
}

// middlewareKind reports which kind of handler m wraps. A middleware is a function from a
// handler signature to itself, so the signature names the kind.
func middlewareKind(m any) (Kind, bool) {
	switch m.(type) {
	case Middleware[HTTP]:
		return KindHTTP, true
	case Middleware[GRPC]:
		return KindGRPC, true
	case Middleware[WebSocket]:
		return KindWebSocket, true
	case Middleware[TCP]:
		return KindTCP, true
	case Middleware[QUIC]:
		return KindQUIC, true
	case Middleware[UDP]:
		return KindUDP, true
	default:
		return 0, false
	}
}

// WithName names an entry so it can be looked up with [Proxy.Named]. Names are unique across
// every kind.
func WithName(name string) EntryOption {
	return optionFunc(func(s sealedOption) error {
		if name == "" {
			return fmt.Errorf("%w: entry name cannot be empty", ErrInvalidConfig)
		}
		s.entry.name = name
		return nil
	})
}

// WithAnnotation attaches an arbitrary value to an entry, readable with [Entry.Annotation].
func WithAnnotation(key, value any) EntryOption {
	return optionFunc(func(s sealedOption) error {
		if s.entry.annots == nil {
			s.entry.annots = make(map[any]any, 1)
		}
		s.entry.annots[key] = value
		return nil
	})
}

// WithTrailingSlash configures trailing slash handling, proxy-wide or for a single entry. An
// entry setting overrides the proxy default. Only a kind carrying a path has a trailing slash
// to handle.
func WithTrailingSlash(opt TrailingSlashOption) interface {
	ProxyOption
	EntryOption
} {
	return optionFunc(func(s sealedOption) error {
		if opt >= slashOptionSentinel {
			return fmt.Errorf("%w: unknown trailing slash option", ErrInvalidConfig)
		}
		if s.entry != nil {
			if err := onlyKinds(s, "WithTrailingSlash", KindHTTP, KindGRPC, KindWebSocket); err != nil {
				return err
			}
			s.entry.handleSlash = opt
			return nil
		}
		s.proxy.cfg.handleSlash = opt
		return nil
	})
}

// WithRegexpParam enables regular expression constraints on pattern parameters. It is off by
// default: a regexp runs on every candidate segment during a lookup, and an expression with
// pathological backtracking turns a request into a denial of service.
func WithRegexpParam(enable bool) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		s.proxy.cfg.allowRegexp = enable
		return nil
	})
}

// WithRejectECH refuses every connection offering the TLS Encrypted Client Hello extension,
// and every TLS connection whose ClientHello the proxy cannot read. ECH hides the real server
// name, so the visible name no longer says where the connection goes, and a connection the
// proxy cannot place is one it cannot terminate correctly. Chrome offers the extension on most
// connections by default, as a decoy, so enabling this refuses a stock Chrome client. It is
// off by default.
func WithRejectECH(enable bool) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		s.proxy.cfg.rejectECH = enable
		return nil
	})
}

// WithNameVerification checks the name a client sends, the server name of a TLS or QUIC
// handshake or the Host of a plaintext request, against the proxy's own resolution of it, on
// a redirected connection and on a CONNECT to an address literal. The name is confirmed
// when that destination is among the resolved addresses. [VerifyLoose] matches an unconfirmed
// name on its destination alone and [VerifyReject] refuses it, before the handshake or with a
// 403 on the request. The default is [VerifyOff], the name is trusted as sent, and a client
// can then reach any address under a permitted name.
//
// The proxy's resolver and the client's can answer differently, and the name then fails
// confirmation. Under [VerifyLoose] a rule on the address admits the connection, and
// [WithNameResolver] can point the check at the resolver the clients use.
//
// A name is resolved at most once per connection. A CONNECT to a hostname has no destination
// the name could disagree with, so it is not verified.
func WithNameVerification(mode NameVerification) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		if mode >= verifySentinel {
			return fmt.Errorf("%w: unknown name verification mode", ErrInvalidConfig)
		}
		s.proxy.cfg.verifyNames = mode
		return nil
	})
}

// WithNameResolver sets the resolver used by [WithNameVerification]. It defaults to
// [net.DefaultResolver].
func WithNameResolver(r NameResolver) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		if r == nil {
			return fmt.Errorf("%w: name resolver cannot be nil", ErrInvalidConfig)
		}
		s.proxy.cfg.resolver = r
		return nil
	})
}

// WithMaxPatternParams bounds how many parameters a pattern may declare. It defaults to 255.
func WithMaxPatternParams(n uint8) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		if n == 0 {
			return fmt.Errorf("%w: max pattern params must be greater than zero", ErrInvalidConfig)
		}
		s.proxy.cfg.maxParams = int(n)
		return nil
	})
}

// WithMaxPatternParamKeyBytes bounds the length of a parameter name. It defaults to 255.
func WithMaxPatternParamKeyBytes(n uint8) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		if n == 0 {
			return fmt.Errorf("%w: max pattern param key bytes must be greater than zero", ErrInvalidConfig)
		}
		s.proxy.cfg.maxParamKeyBytes = int(n)
		return nil
	})
}

// WithMaxMatchers bounds how many matchers an entry may carry, the implicit scheme and method
// matchers included. It defaults to 255.
func WithMaxMatchers(n uint8) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		s.proxy.cfg.maxMatchers = int(n)
		return nil
	})
}

// WithTransport configures how the proxy reaches upstream servers.
func WithTransport(t *Transport) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		if t == nil {
			return fmt.Errorf("%w: transport cannot be nil", ErrInvalidConfig)
		}
		s.proxy.cfg.transport = t
		return nil
	})
}

// WithLogger sets the logger used for connection level errors the proxy cannot report to a
// handler. It defaults to [slog.Default].
func WithLogger(l *slog.Logger) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		if l == nil {
			return fmt.Errorf("%w: logger cannot be nil", ErrInvalidConfig)
		}
		s.proxy.cfg.logger = l
		return nil
	})
}

// WithReadHeaderTimeout bounds how long the proxy waits for a client to send its request
// headers. Zero disables the timeout. It defaults to 10s.
func WithReadHeaderTimeout(d time.Duration) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		if d < 0 {
			return fmt.Errorf("%w: read header timeout cannot be negative", ErrInvalidConfig)
		}
		s.proxy.cfg.server.readHeaderTimeout = d
		return nil
	})
}

// WithIdleTimeout bounds how long an idle keep-alive connection is kept open. Zero disables
// the timeout. It defaults to 90s.
func WithIdleTimeout(d time.Duration) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		if d < 0 {
			return fmt.Errorf("%w: idle timeout cannot be negative", ErrInvalidConfig)
		}
		s.proxy.cfg.server.idleTimeout = d
		return nil
	})
}

// WithSniffTimeout bounds how long the proxy waits for a redirected plaintext connection to
// say what it is before serving it as a byte stream. A protocol whose server speaks first
// sends nothing until then, so the wait is what tells it apart from a slow HTTP client. It
// defaults to 1s.
func WithSniffTimeout(d time.Duration) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		if d < 0 {
			return fmt.Errorf("%w: sniff timeout cannot be negative", ErrInvalidConfig)
		}
		s.proxy.cfg.server.sniffTimeout = d
		return nil
	})
}

// WithMaxHeaderBytes bounds the size of a request header block. It defaults to 1 MiB.
func WithMaxHeaderBytes(n int) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		if n <= 0 {
			return fmt.Errorf("%w: max header bytes must be greater than zero", ErrInvalidConfig)
		}
		s.proxy.cfg.server.maxHeaderBytes = n
		return nil
	})
}

// WithMaxFrameBytes bounds one WebSocket frame the proxy will buffer to hand a handler. A peer
// sending a larger one is closed with 1009, the status RFC 6455 reserves for it. It defaults
// to 1 MiB.
func WithMaxFrameBytes(n int) ProxyOption {
	return optionFunc(func(s sealedOption) error {
		if n <= 0 {
			return fmt.Errorf("%w: max frame bytes must be greater than zero", ErrInvalidConfig)
		}
		s.proxy.cfg.server.maxFrameBytes = n
		return nil
	})
}

// WithMatcher attaches a [Matcher] to an entry, narrowing it beyond its pattern. An entry with
// matchers is evaluated before one without at the same pattern.
func WithMatcher(m Matcher) interface {
	EntryOption
	MatcherOption
} {
	return optionFunc(func(s sealedOption) error {
		if err := onlyPerMessage(s, "WithMatcher"); err != nil {
			return err
		}
		if m == nil {
			return fmt.Errorf("%w: matcher cannot be nil", ErrInvalidMatcher)
		}
		s.entry.matchers = append(s.entry.matchers, m)
		return nil
	})
}

// WithMatchers attaches several matchers to an entry. All must match.
func WithMatchers(matchers ...Matcher) interface {
	EntryOption
	MatcherOption
} {
	return optionFunc(func(s sealedOption) error {
		if err := onlyPerMessage(s, "WithMatchers"); err != nil {
			return err
		}
		for i, m := range matchers {
			if m == nil {
				return fmt.Errorf("%w: matcher at index %d is nil", ErrInvalidMatcher, i)
			}
			s.entry.matchers = append(s.entry.matchers, m)
		}
		return nil
	})
}

// WithMethods narrows an entry to the given request methods. It is a matcher like any other,
// which is what lets several handlers share one path and differ only by method: the methods
// are part of what identifies the entry.
//
// An entry with no method matcher answers every method.
func WithMethods(methods ...string) interface {
	EntryOption
	MatcherOption
} {
	return optionFunc(func(s sealedOption) error {
		if err := onlyKinds(s, "WithMethods", KindHTTP, KindGRPC, KindWebSocket); err != nil {
			return err
		}
		m, err := MatchMethods(methods...)
		if err != nil {
			return err
		}
		s.entry.matchers = append(s.entry.matchers, m)
		return nil
	})
}

// WithScheme narrows an entry to one scheme, http or https. A pattern carries a hostname and
// a path and nothing else, so this is how the scheme is expressed.
//
// An entry with no scheme matches both, which is almost always what a proxy wants: the
// authority and the path say what the traffic is, the scheme only says how it was carried.
func WithScheme(scheme string) interface {
	EntryOption
	MatcherOption
} {
	return optionFunc(func(s sealedOption) error {
		if err := onlyKinds(s, "WithScheme", KindHTTP, KindGRPC, KindWebSocket); err != nil {
			return err
		}
		m, err := MatchScheme(scheme)
		if err != nil {
			return err
		}
		s.entry.matchers = append(s.entry.matchers, m)
		return nil
	})
}

// WithMatchersPriority orders entries that share a pattern. Higher runs first. It defaults to
// the number of matchers on it, so the most constrained one is tried first.
func WithMatchersPriority(priority uint) EntryOption {
	return optionFunc(func(s sealedOption) error {
		s.entry.priority = priority
		return nil
	})
}
