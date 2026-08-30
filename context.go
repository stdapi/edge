// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/fox-toolkit/edge/internal/stringsutil"
)

// Param is a matched pattern parameter.
type Param struct {
	Key   string
	Value string
}

// RequestContext is the read-only view of a [Context] handed to a [Matcher]. Its lifetime is
// the [Matcher.Match] call; the underlying context is reused once that call returns.
//
// It exposes what the request itself carries and nothing else. A matcher selects one request
// while a connection carries many, so reading the connection here would let an interceptor be
// chosen on state its own request does not describe.
type RequestContext interface {
	// Request returns the request being routed.
	Request() *http.Request
	// Method returns the request method.
	Method() string
	// Scheme returns the scheme of the request target, http or https.
	Scheme() string
	// Host returns the hostname of the request target, without its port.
	Host() string
	// Port returns the port of the request target, always explicit.
	Port() string
	// Authority returns the request target as host:port.
	Authority() string
	// RoutingPath returns the canonical form of the path the client sent, which is the form
	// the tree matched on. Percent-encoded RFC 3986 unreserved characters are decoded, bytes
	// that must be escaped in a path are encoded in place, and every other escape keeps
	// uppercase hex and stays distinct from its decoded form, so %2F never matches /.
	RoutingPath() string
	// QueryParams parses the raw query and caches the result.
	QueryParams() url.Values
	// QueryParam returns the first value for name.
	QueryParam(name string) string
	// Header returns the first request header value for key.
	Header(key string) string
	// RemoteAddr returns the address the request was received from, or the zero value when
	// it carries none.
	RemoteAddr() netip.AddrPort
	// Protocol returns the protocol the request was received over.
	Protocol() Protocol
}

// Context carries an intercepted request through the middleware chain and into the handler.
//
// A Context is not safe for concurrent use and must not outlive the handler: it is returned
// to a pool as soon as the handler returns. Read out of it whatever has to outlive it.
type Context struct {
	req  *http.Request
	sess *Session

	params      *[]string
	skipStack   *skipStack
	interceptor *Interceptor

	tree *iTree // no reset, the context belongs to this tree's pool
	p    *Proxy // no reset

	cachedQueries url.Values

	scheme   string
	host     string
	port     string
	identity string

	scope HandlerScope
}

func (c *Context) reset(sess *Session, r *http.Request, scheme, host, port string) {
	c.req = r
	c.sess = sess
	c.scheme = scheme
	c.host = host
	c.port = port
	c.cachedQueries = nil
	c.interceptor = nil
	c.identity = ""
	c.scope = InterceptorHandler
	*c.params = (*c.params)[:0]
}

func (c *Context) resetForAuthority(sess *Session, scheme, host, port string) {
	c.req = nil
	c.sess = sess
	c.scheme = scheme
	c.host = host
	c.port = port
	c.cachedQueries = nil
	c.interceptor = nil
	c.identity = ""
	// No handler runs on an authority lookup, so there is no scope to report.
	c.scope = 0
	*c.params = (*c.params)[:0]
}

// Request returns the request being proxied. Handlers mutate it in place to change what is
// sent upstream.
func (c *Context) Request() *http.Request { return c.req }

// SetRequest replaces the request the rest of the chain sees, and with it the one sent
// upstream. It is how a middleware hands a substituted request down: the middleware signature
// carries no request of its own.
func (c *Context) SetRequest(r *http.Request) {
	c.cachedQueries = nil
	c.req = r
}

// Method returns the request method, or an empty string outside a served request.
func (c *Context) Method() string {
	if c.req == nil {
		return ""
	}
	return c.req.Method
}

// Scheme returns the scheme of the request target, http or https.
func (c *Context) Scheme() string { return c.scheme }

// Host returns the hostname of the request target, without its port.
func (c *Context) Host() string { return c.host }

// Port returns the port of the request target. It is always explicit, defaulted from the
// scheme when the client did not send one.
func (c *Context) Port() string { return c.port }

// Authority returns the request target as host:port.
func (c *Context) Authority() string { return joinHostPort(c.host, c.port) }

// RoutingPath returns the canonical form of the path the client sent, which is the form the
// tree matched on. See [RequestContext] for what canonical covers. It is recomputed on every
// call, so a handler that rewrites the request reads back what it wrote.
func (c *Context) RoutingPath() string { return routingPath(c.req) }

// routingPath returns the canonical form of the request path used for matching. The request
// is never rewritten to it: a proxy must put back on the wire exactly what the client sent,
// so the canonical form only ever exists inside the lookup.
func routingPath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	u := r.URL
	if u.RawPath == "" {
		// The wire path was the default encoding of Path, which is always canonical.
		return stringsutil.EscapePath(u.Path)
	}
	norm, _ := stringsutil.NormalizeRawPath(u.RawPath, u.Path)
	if norm == "" {
		// RawPath holds a malformed escape or is not an encoding of Path. Like net/url,
		// Path is then the source of truth.
		return stringsutil.EscapePath(u.Path)
	}
	return norm
}

// QueryParams parses the raw query and caches the result.
func (c *Context) QueryParams() url.Values { return c.getQueries() }

// QueryParam returns the first value for name.
func (c *Context) QueryParam(name string) string { return c.getQueries().Get(name) }

func (c *Context) getQueries() url.Values {
	if c.cachedQueries == nil {
		if c.req != nil && c.req.URL != nil {
			c.cachedQueries = c.req.URL.Query()
		} else {
			c.cachedQueries = make(url.Values)
		}
	}
	return c.cachedQueries
}

// Header returns the first request header value for key, or an empty string outside a
// served request.
func (c *Context) Header(key string) string {
	if c.req == nil {
		return ""
	}
	return c.req.Header.Get(key)
}

// RemoteAddr returns the address the request was received from, or the zero value when it
// carries none. Use [Session.RemoteAddr] for the address of the connection, which is the same
// for every request multiplexed on it and which no handler can rewrite.
func (c *Context) RemoteAddr() netip.AddrPort {
	if c.req == nil {
		return netip.AddrPort{}
	}
	ap, err := netip.ParseAddrPort(c.req.RemoteAddr)
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// Protocol returns the protocol the request was received over, or the zero value outside a
// served request. It is not necessarily the protocol used upstream.
func (c *Context) Protocol() Protocol {
	if c.req == nil {
		return 0
	}
	return protoOfRequest(c.req)
}

// Identity returns what the configured [ProxyAuthenticator] reported for this request, or an
// empty string when none did. A request read off an intercepted connection was never
// challenged, so it reports the identity of the CONNECT that opened it.
func (c *Context) Identity() string { return c.identity }

// Session returns the client connection this request arrived on.
func (c *Context) Session() *Session { return c.sess }

// Params returns an iterator over the parameters matched by the current interceptor.
func (c *Context) Params() iter.Seq[Param] {
	return func(yield func(Param) bool) {
		if c.interceptor == nil {
			return
		}
		for i, v := range *c.params {
			if i >= len(c.interceptor.params) {
				return
			}
			if !yield(Param{Key: c.interceptor.params[i], Value: v}) {
				return
			}
		}
	}
}

// Param returns the value matched for the named parameter, or an empty string.
func (c *Context) Param(name string) string {
	if c.interceptor == nil {
		return ""
	}
	for i, v := range *c.params {
		if i < len(c.interceptor.params) && c.interceptor.params[i] == name {
			return v
		}
	}
	return ""
}

// Pattern returns the pattern of the matched interceptor, or an empty string outside of
// [InterceptorHandler] scope.
func (c *Context) Pattern() string {
	if c.interceptor == nil {
		return ""
	}
	return c.interceptor.pattern.str
}

// Interceptor returns the matched [Interceptor], or nil outside of [InterceptorHandler] scope.
func (c *Context) Interceptor() *Interceptor { return c.interceptor }

// Scope returns the handler scope this context is being served in.
func (c *Context) Scope() HandlerScope { return c.scope }

// Proxy returns the [Proxy] serving this request.
func (c *Context) Proxy() *Proxy { return c.p }

// Forward sends the request upstream and returns the response. The response body streams
// from the upstream connection: returning the response from a handler relays it to the
// client without buffering, and reading it consumes it.
//
// The request is sent as the client wrote it, minus the hop-by-hop headers a proxy must not
// relay. Nothing is added: no Via, no X-Forwarded-For, no Accept-Encoding of the proxy's
// own. Anything a handler mutates on [Context.Request] before calling Forward is what the
// upstream sees.
func (c *Context) Forward() (*http.Response, error) {
	return c.ForwardRequest(c.req)
}

// ForwardRequest sends r upstream instead of the request the handler was given. Use it to
// retry, to fan out, or to rewrite the target entirely.
func (c *Context) ForwardRequest(r *http.Request) (*http.Response, error) {
	if r == nil {
		return nil, errors.New("edge: forward a nil request")
	}
	if c.p == nil || c.p.srv == nil || c.p.srv.fwd == nil {
		return nil, errors.New("edge: proxy has no forwarder")
	}

	out, err := c.outboundRequest(r)
	if err != nil {
		return nil, err
	}

	resp, err := c.p.srv.fwd.roundTrip(out, c.upstreamProtocol())
	if err != nil {
		return nil, fmt.Errorf("forward %s %s: %w", out.Method, out.URL.Redacted(), err)
	}

	stripResponseHopByHop(resp)
	return resp, nil
}

// outboundRequest turns the request the proxy received into one the upstream transport can
// send. The target of the original request is preserved byte for byte; only the headers a
// proxy must not relay are removed.
func (c *Context) outboundRequest(r *http.Request) (*http.Request, error) {
	if r.URL == nil {
		return nil, errors.New("edge: forward a request with no URL")
	}

	ctx := r.Context()
	if c.sess != nil && c.sess.upstream.IsValid() {
		// A transparently redirected connection is sent back to the address the client had
		// already resolved, rather than to a fresh resolution of the authority.
		ctx = context.WithValue(ctx, upstreamAddrKey{}, c.sess.upstream)
	}

	out := r.Clone(ctx)
	// A client request carries no RequestURI; net/http panics otherwise.
	out.RequestURI = ""
	out.Close = false

	if out.URL.Scheme == "" {
		out.URL.Scheme = c.scheme
	}
	if out.URL.Host == "" {
		out.URL.Host = c.Authority()
	}
	if out.Host == "" {
		out.Host = r.Host
	}
	if out.Host == "" {
		out.Host = out.URL.Host
	}

	upgrade := upgradeType(r.Header)
	stripHopByHop(out.Header)
	if upgrade != "" {
		// An upgrade is the one case where the connection-scoped headers are the payload:
		// dropping them turns a WebSocket handshake into a plain request.
		out.Header.Set("Connection", "Upgrade")
		out.Header.Set("Upgrade", upgrade)
	}

	return out, nil
}

// upstreamProtocol reports which protocol the proxy should try upstream. It mirrors the
// client, so an app that chose HTTP/3 keeps talking to an origin over HTTP/3 and the
// interception stays invisible in the one place an app can most easily notice it.
func (c *Context) upstreamProtocol() Protocol {
	if c.sess == nil {
		return HTTP11
	}
	return c.sess.Protocol()
}

// onlyRequestContext seals a Context down to [RequestContext] so a [Matcher] cannot reach
// the mutating half of the API.
type onlyRequestContext struct {
	c *Context
}

func (o onlyRequestContext) Request() *http.Request     { return o.c.req }
func (o onlyRequestContext) Method() string             { return o.c.req.Method }
func (o onlyRequestContext) Scheme() string             { return o.c.scheme }
func (o onlyRequestContext) Host() string               { return o.c.host }
func (o onlyRequestContext) Port() string               { return o.c.port }
func (o onlyRequestContext) Authority() string          { return o.c.Authority() }
func (o onlyRequestContext) RoutingPath() string        { return o.c.RoutingPath() }
func (o onlyRequestContext) QueryParams() url.Values    { return o.c.getQueries() }
func (o onlyRequestContext) QueryParam(n string) string { return o.c.getQueries().Get(n) }
func (o onlyRequestContext) Header(k string) string     { return o.c.req.Header.Get(k) }
func (o onlyRequestContext) RemoteAddr() netip.AddrPort { return o.c.RemoteAddr() }
func (o onlyRequestContext) Protocol() Protocol         { return o.c.Protocol() }

var _ RequestContext = onlyRequestContext{}
