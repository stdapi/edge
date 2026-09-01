// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"iter"
	"net/http"
	"net/netip"
	"net/textproto"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"

	"github.com/fox-toolkit/edge/internal/netutil"
	"golang.org/x/net/http/httpguts"
)

// Matcher narrows an interceptor beyond its pattern and method. Every matcher on an interceptor must
// match for the interceptor to be selected. An interceptor carrying matchers is evaluated before one
// without at the same pattern, so an interceptor with no matcher is the fallback.
//
// Match must be free of side effects and must not retain the [RequestContext], whose
// lifetime ends when Match returns.
type Matcher interface {
	// Match reports whether the request satisfies this matcher.
	Match(c RequestContext) bool
	// Equal reports whether matcher is this matcher. It identifies an interceptor for lookup and
	// deletion, so it must be a value comparison, not identity.
	Equal(matcher Matcher) bool
}

func compileAnchoredRegexp(expr string) (*regexp.Regexp, error) {
	if expr == "" {
		return nil, fmt.Errorf("%w: empty expression", ErrInvalidMatcher)
	}
	// A source that is invalid on its own can still balance inside the wrapper, such as
	// "a)|(?:", and defeat the anchoring, so it must compile standalone first.
	if _, err := syntax.Parse(expr, syntax.Perl); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMatcher, err)
	}
	re, err := regexp.Compile("^(?:" + expr + ")$")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMatcher, err)
	}
	if re.NumSubexp() > 0 {
		return nil, fmt.Errorf("%w: capture group, use (?:...) instead", ErrInvalidMatcher)
	}
	return re, nil
}

// SchemeMatcher matches the scheme of the request target. Attach one with [WithScheme].
type SchemeMatcher struct {
	scheme string
}

// MatchScheme returns a [SchemeMatcher] for the given scheme, http or https.
func MatchScheme(scheme string) (SchemeMatcher, error) {
	s := strings.ToLower(scheme)
	if s != "http" && s != "https" {
		return SchemeMatcher{}, fmt.Errorf("%w: unsupported scheme %q, want http or https", ErrInvalidMatcher, scheme)
	}
	return SchemeMatcher{scheme: s}, nil
}

// Scheme returns the scheme this matcher requires.
func (m SchemeMatcher) Scheme() string { return m.scheme }

func (m SchemeMatcher) Match(c RequestContext) bool { return c.Scheme() == m.scheme }

func (m SchemeMatcher) Equal(matcher Matcher) bool {
	other, ok := matcher.(SchemeMatcher)
	return ok && other.scheme == m.scheme
}

func (m SchemeMatcher) String() string { return "scheme=" + m.scheme }

// QueryMatcher matches an exact query parameter value.
type QueryMatcher struct {
	key   string
	value string
}

// MatchQuery returns a [QueryMatcher] for key and value.
func MatchQuery(key, value string) (QueryMatcher, error) {
	if key == "" {
		return QueryMatcher{}, fmt.Errorf("%w: empty query key", ErrInvalidMatcher)
	}
	return QueryMatcher{key: key, value: value}, nil
}

// Key returns the query parameter name.
func (m QueryMatcher) Key() string { return m.key }

// Value returns the value the parameter must have.
func (m QueryMatcher) Value() string { return m.value }

func (m QueryMatcher) Match(c RequestContext) bool {
	v, ok := c.QueryParams()[m.key]
	return ok && len(v) > 0 && v[0] == m.value
}

func (m QueryMatcher) Equal(matcher Matcher) bool {
	other, ok := matcher.(QueryMatcher)
	return ok && other.key == m.key && other.value == m.value
}

func (m QueryMatcher) String() string { return "query:" + m.key + "=" + m.value }

// QueryRegexpMatcher matches a query parameter against an anchored regular expression.
type QueryRegexpMatcher struct {
	re  *regexp.Regexp
	key string
}

// MatchQueryRegexp returns a [QueryRegexpMatcher] for key and expr. The expression is
// anchored and must not contain a capture group.
func MatchQueryRegexp(key, expr string) (QueryRegexpMatcher, error) {
	if key == "" {
		return QueryRegexpMatcher{}, fmt.Errorf("%w: empty query key", ErrInvalidMatcher)
	}
	re, err := compileAnchoredRegexp(expr)
	if err != nil {
		return QueryRegexpMatcher{}, err
	}
	return QueryRegexpMatcher{key: key, re: re}, nil
}

// Key returns the query parameter name.
func (m QueryRegexpMatcher) Key() string { return m.key }

// Value returns the expression the parameter must match.
func (m QueryRegexpMatcher) Value() string { return rawExpr(m.re) }

func (m QueryRegexpMatcher) Match(c RequestContext) bool {
	v, ok := c.QueryParams()[m.key]
	return ok && len(v) > 0 && m.re.MatchString(v[0])
}

func (m QueryRegexpMatcher) Equal(matcher Matcher) bool {
	other, ok := matcher.(QueryRegexpMatcher)
	return ok && other.key == m.key && other.re.String() == m.re.String()
}

func (m QueryRegexpMatcher) String() string { return "query:" + m.key + "~=" + rawExpr(m.re) }

// HeaderMatcher matches an exact request header value.
type HeaderMatcher struct {
	key   string
	value string
}

// MatchHeader returns a [HeaderMatcher] for key and value. The key is canonicalized.
func MatchHeader(key, value string) (HeaderMatcher, error) {
	if key == "" {
		return HeaderMatcher{}, fmt.Errorf("%w: empty header key", ErrInvalidMatcher)
	}
	return HeaderMatcher{key: textproto.CanonicalMIMEHeaderKey(key), value: value}, nil
}

// Key returns the canonicalized header name.
func (m HeaderMatcher) Key() string { return m.key }

// Value returns the value the header must have.
func (m HeaderMatcher) Value() string { return m.value }

func (m HeaderMatcher) Match(c RequestContext) bool {
	v, ok := firstHeader(c.Request().Header, m.key)
	return ok && v == m.value
}

func (m HeaderMatcher) Equal(matcher Matcher) bool {
	other, ok := matcher.(HeaderMatcher)
	return ok && other.key == m.key && other.value == m.value
}

func (m HeaderMatcher) String() string { return "header:" + m.key + "=" + m.value }

// HeaderRegexpMatcher matches a request header against an anchored regular expression.
type HeaderRegexpMatcher struct {
	re  *regexp.Regexp
	key string
}

// MatchHeaderRegexp returns a [HeaderRegexpMatcher] for key and expr. The expression is
// anchored and must not contain a capture group.
func MatchHeaderRegexp(key, expr string) (HeaderRegexpMatcher, error) {
	if key == "" {
		return HeaderRegexpMatcher{}, fmt.Errorf("%w: empty header key", ErrInvalidMatcher)
	}
	re, err := compileAnchoredRegexp(expr)
	if err != nil {
		return HeaderRegexpMatcher{}, err
	}
	return HeaderRegexpMatcher{key: textproto.CanonicalMIMEHeaderKey(key), re: re}, nil
}

// Key returns the canonicalized header name.
func (m HeaderRegexpMatcher) Key() string { return m.key }

// Value returns the expression the header must match.
func (m HeaderRegexpMatcher) Value() string { return rawExpr(m.re) }

func (m HeaderRegexpMatcher) Match(c RequestContext) bool {
	v, ok := firstHeader(c.Request().Header, m.key)
	return ok && m.re.MatchString(v)
}

func (m HeaderRegexpMatcher) Equal(matcher Matcher) bool {
	other, ok := matcher.(HeaderRegexpMatcher)
	return ok && other.key == m.key && other.re.String() == m.re.String()
}

func (m HeaderRegexpMatcher) String() string { return "header:" + m.key + "~=" + rawExpr(m.re) }

// RemoteIPMatcher matches the IP of the client connection against a prefix. It routes by
// which client is talking to the proxy, which is how a shared proxy tells one test runner
// from another.
type RemoteIPMatcher struct {
	prefix netip.Prefix
}

// MatchRemoteIP returns a [RemoteIPMatcher] for a CIDR prefix or a single address.
func MatchRemoteIP(prefix string) (RemoteIPMatcher, error) {
	p, err := netutil.ParsePrefix(prefix)
	if err != nil {
		return RemoteIPMatcher{}, fmt.Errorf("%w: %w", ErrInvalidMatcher, err)
	}
	return RemoteIPMatcher{prefix: p}, nil
}

// Prefix returns the prefix the client address must fall in.
func (m RemoteIPMatcher) Prefix() netip.Prefix { return m.prefix }

func (m RemoteIPMatcher) Match(c RequestContext) bool {
	addr := c.RemoteAddr().Addr()
	return addr.IsValid() && m.prefix.Contains(addr.WithZone(""))
}

func (m RemoteIPMatcher) Equal(matcher Matcher) bool {
	other, ok := matcher.(RemoteIPMatcher)
	return ok && other.prefix == m.prefix
}

func (m RemoteIPMatcher) String() string { return "remoteip=" + m.prefix.String() }

// ProtocolMatcher matches the protocol the client is speaking to the proxy. It is how a
// interceptor targets, say, only the HTTP/3 traffic of an authority.
type ProtocolMatcher struct {
	proto Protocol
}

// MatchProtocol returns a [ProtocolMatcher] for the given protocol.
func MatchProtocol(proto Protocol) (ProtocolMatcher, error) {
	switch proto {
	case HTTP11, HTTP2, HTTP3:
		return ProtocolMatcher{proto: proto}, nil
	default:
		return ProtocolMatcher{}, fmt.Errorf("%w: unknown protocol", ErrInvalidMatcher)
	}
}

// Protocol returns the protocol this matcher requires.
func (m ProtocolMatcher) Protocol() Protocol { return m.proto }

func (m ProtocolMatcher) Match(c RequestContext) bool { return c.Protocol() == m.proto }

func (m ProtocolMatcher) Equal(matcher Matcher) bool {
	other, ok := matcher.(ProtocolMatcher)
	return ok && other.proto == m.proto
}

func (m ProtocolMatcher) String() string { return "proto=" + m.proto.String() }

// MatcherFunc adapts a function to the [Matcher] interface. Two MatcherFunc values are never
// equal, so an interceptor carrying one cannot be identified by its matchers: give it a name with
// [WithName] and delete it with [Proxy.removeInterceptor].
type MatcherFunc func(c RequestContext) bool

func (f MatcherFunc) Match(c RequestContext) bool { return f(c) }

func (f MatcherFunc) Equal(Matcher) bool { return false }

var (
	_ Matcher = SchemeMatcher{}
	_ Matcher = QueryMatcher{}
	_ Matcher = QueryRegexpMatcher{}
	_ Matcher = HeaderMatcher{}
	_ Matcher = HeaderRegexpMatcher{}
	_ Matcher = RemoteIPMatcher{}
	_ Matcher = ProtocolMatcher{}
	_ Matcher = MatcherFunc(nil)
)

// MethodMatcher matches the request method against a set. Attach one with [WithMethods].
type MethodMatcher struct {
	methods []string
}

// MatchMethods returns a [MethodMatcher] for the given methods. An empty set is refused: an
// entry answering no method could never be selected, and answering every method is spelled by
// attaching no matcher at all.
func MatchMethods(methods ...string) (MethodMatcher, error) {
	if len(methods) == 0 {
		return MethodMatcher{}, fmt.Errorf("%w: no method, an entry with no method matcher already answers every method", ErrInvalidMatcher)
	}
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		if !validMethod(m) {
			return MethodMatcher{}, fmt.Errorf("%w: invalid method %q", ErrInvalidMatcher, m)
		}
		if m == http.MethodConnect {
			return MethodMatcher{}, fmt.Errorf("%w: CONNECT establishes a connection, it never reaches an entry", ErrInvalidMatcher)
		}
		out = append(out, m)
	}
	slices.Sort(out)
	return MethodMatcher{methods: slices.Compact(out)}, nil
}

// Methods returns an iterator over the methods this matcher accepts, in lexicographical order.
func (m MethodMatcher) Methods() iter.Seq[string] { return slices.Values(m.methods) }

func (m MethodMatcher) Match(c RequestContext) bool {
	method := c.Method()
	switch len(m.methods) {
	case 1:
		// The common case, and the one worth keeping off slices.Contains.
		return m.methods[0] == method
	default:
		return slices.Contains(m.methods, method)
	}
}

func (m MethodMatcher) Equal(matcher Matcher) bool {
	other, ok := matcher.(MethodMatcher)
	return ok && slices.Equal(other.methods, m.methods)
}

func (m MethodMatcher) String() string { return "method=" + strings.Join(m.methods, ",") }

// validMethod reports whether s is a valid HTTP method token (RFC 9110 section 9).
func validMethod(method string) bool {
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

func isNotToken(r rune) bool { return !httpguts.IsTokenRune(r) }

var (
	_ Matcher = MethodMatcher{}
)
