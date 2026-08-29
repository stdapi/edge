// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"iter"
	"net"
	"net/http"
	"net/netip"
	"net/url"
)

// Param is a matched pattern parameter.
type Param struct {
	Key   string
	Value string
}

// RequestContext is the read-only view of a [Context] handed to a [Matcher]. Its lifetime is
// the [Matcher.Match] call; the underlying context is reused once that call returns.
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
	// RoutingPath returns the canonical path the tree matches on. Percent-encoded RFC 3986
	// unreserved characters are decoded, bytes that must be escaped in a path are encoded in
	// place, and every other escape keeps uppercase hex and stays distinct from its decoded
	// form, so %2F never matches /. The request itself is never rewritten: what goes upstream
	// is the target the client sent, byte for byte.
	RoutingPath() string
	// QueryParams parses the raw query and caches the result.
	QueryParams() url.Values
	// QueryParam returns the first value for name.
	QueryParam(name string) string
	// Header returns the first request header value for key.
	Header(key string) string
	// RemoteAddr returns the address of the client connection.
	RemoteAddr() net.Addr
	// RemoteIP returns the IP of the client connection, or the zero value if it has none.
	RemoteIP() netip.Addr
	// Protocol returns the protocol the client is speaking to the proxy.
	Protocol() Protocol
	// TLS returns the state of the intercepted TLS connection, or nil for a plaintext one.
	TLS() *tls.ConnectionState
	// Session returns the client connection this request arrived on.
	Session() *Session
}

// Context carries an intercepted request through the middleware chain and into the handler.
//
// A Context is not safe for concurrent use and must not outlive the handler: it is returned
// to a pool as soon as the handler returns. Use [Context.Clone] to keep one around.
type Context struct {
	req  *http.Request
	sess *Session

	params    *[]string
	skipStack *skipStack
	route     *Route
	// Set by matchSlow, read back through onlyRequestContext.
	matcherRoute *Route

	tree *iTree // no reset, the context belongs to this tree's pool
	p    *Proxy // no reset

	cachedQueries url.Values
	cachedPath    string

	scheme string
	host   string
	port   string

	hasPath bool

	scope    HandlerScope
	detached bool
}

func (c *Context) reset(sess *Session, r *http.Request, scheme, host, port string) {
	c.req = r
	c.sess = sess
	c.scheme = scheme
	c.host = host
	c.port = port
	c.cachedQueries = nil
	c.cachedPath = ""
	c.hasPath = false
	c.route = nil
	c.matcherRoute = nil
	c.scope = RouteHandler
	c.detached = false
	*c.params = (*c.params)[:0]
}

func (c *Context) resetForRule(sess *Session, scheme, host, port string) {
	c.req = nil
	c.sess = sess
	c.scheme = scheme
	c.host = host
	c.port = port
	c.cachedQueries = nil
	c.cachedPath = ""
	c.hasPath = false
	c.route = nil
	c.matcherRoute = nil
	c.scope = RuleHandler
	c.detached = false
	*c.params = (*c.params)[:0]
}

// Close releases a [Context] obtained from [Txn.Lookup] back to its pool. It must not be
// called on the context a handler was given: the proxy owns that one.
func (c *Context) Close() { c.release() }

func (c *Context) release() {
	if c.tree == nil || c.detached {
		return
	}
	c.req = nil
	c.sess = nil
	c.route = nil
	c.matcherRoute = nil
	c.cachedQueries = nil
	*c.params = (*c.params)[:0]
	c.tree.pool.Put(c)
}

// Request returns the request being proxied. Handlers mutate it in place to change what is
// sent upstream.
func (c *Context) Request() *http.Request { return c.req }

// SetRequest replaces the request sent upstream.
func (c *Context) SetRequest(r *http.Request) {
	c.cachedQueries = nil
	c.hasPath = false
	c.req = r
}

// Method returns the request method.
func (c *Context) Method() string { return c.req.Method }

// Scheme returns the scheme of the request target, http or https.
func (c *Context) Scheme() string { return c.scheme }

// Host returns the hostname of the request target, without its port.
func (c *Context) Host() string { return c.host }

// Port returns the port of the request target. It is always explicit, defaulted from the
// scheme when the client did not send one.
func (c *Context) Port() string { return c.port }

// Authority returns the request target as host:port.
func (c *Context) Authority() string { return joinHostPort(c.host, c.port) }

// Target returns the full request target of this request.
func (c *Context) Target() Target {
	return Target{Scheme: c.scheme, Host: c.host, Port: c.port}
}

// RoutingPath returns the canonical path the tree matched on. See [RequestContext] for the
// canonical form. The request is never rewritten to it.
func (c *Context) RoutingPath() string {
	if !c.hasPath {
		c.cachedPath = routingPath(c.req)
		c.hasPath = true
	}
	return c.cachedPath
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

// Header returns the first request header value for key.
func (c *Context) Header(key string) string { return c.req.Header.Get(key) }

// RemoteAddr returns the address of the client connection.
func (c *Context) RemoteAddr() net.Addr { return c.sess.remoteAddr }

// RemoteIP returns the IP of the client connection, or the zero value if it has none.
func (c *Context) RemoteIP() netip.Addr {
	if c.sess == nil || c.sess.remoteAddr == nil {
		return netip.Addr{}
	}
	host, _, err := net.SplitHostPort(c.sess.remoteAddr.String())
	if err != nil {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// Protocol returns the protocol the client is speaking to the proxy. It is not necessarily
// the protocol used upstream.
func (c *Context) Protocol() Protocol { return c.sess.proto }

// TLS returns the state of the intercepted TLS connection, or nil for a plaintext one.
func (c *Context) TLS() *tls.ConnectionState { return c.sess.tlsState }

// Session returns the client connection this request arrived on.
func (c *Context) Session() *Session { return c.sess }

// Params returns an iterator over the parameters matched by the current route.
func (c *Context) Params() iter.Seq[Param] {
	return func(yield func(Param) bool) {
		if c.route == nil {
			return
		}
		for i, v := range *c.params {
			if i >= len(c.route.params) {
				return
			}
			if !yield(Param{Key: c.route.params[i], Value: v}) {
				return
			}
		}
	}
}

// Param returns the value matched for the named parameter, or an empty string.
func (c *Context) Param(name string) string {
	if c.route == nil {
		return ""
	}
	for i, v := range *c.params {
		if i < len(c.route.params) && c.route.params[i] == name {
			return v
		}
	}
	return ""
}

// Pattern returns the pattern of the matched route, or an empty string outside of
// [RouteHandler] scope.
func (c *Context) Pattern() string {
	if c.route == nil {
		return ""
	}
	return c.route.pattern.str
}

// Route returns the matched [Route], or nil outside of [RouteHandler] scope.
func (c *Context) Route() *Route { return c.route }

// Scope returns the handler scope this context is being served in.
func (c *Context) Scope() HandlerScope { return c.scope }

// Proxy returns the [Proxy] serving this request.
func (c *Context) Proxy() *Proxy { return c.p }

// Context returns the request context. It is canceled when the client goes away.
func (c *Context) Context() context.Context {
	if c.req != nil {
		return c.req.Context()
	}
	if c.sess != nil && c.sess.ctx != nil {
		return c.sess.ctx
	}
	return context.Background()
}

// Clone returns a deep copy of the Context that stays valid after the handler returns. The
// clone is detached from the pool and its request body is not copied.
func (c *Context) Clone() *Context {
	cp := &Context{
		p:        c.p,
		sess:     c.sess,
		route:    c.route,
		scheme:   c.scheme,
		host:     c.host,
		port:     c.port,
		scope:    c.scope,
		detached: true,
	}
	if c.req != nil {
		cp.req = c.req.Clone(c.req.Context())
	}
	params := make([]string, len(*c.params))
	copy(params, *c.params)
	cp.params = &params
	cp.skipStack = new(skipStack)
	return cp
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
func (o onlyRequestContext) RemoteAddr() net.Addr       { return o.c.RemoteAddr() }
func (o onlyRequestContext) RemoteIP() netip.Addr       { return o.c.RemoteIP() }
func (o onlyRequestContext) Protocol() Protocol         { return o.c.Protocol() }
func (o onlyRequestContext) TLS() *tls.ConnectionState  { return o.c.TLS() }
func (o onlyRequestContext) Session() *Session          { return o.c.sess }

var _ RequestContext = onlyRequestContext{}
