// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"iter"
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
//
// It exposes what the request itself carries and nothing else. A matcher selects one request,
// while a connection carries many, so reading the connection here would let an interceptor be
// chosen on state its request does not describe. It is also what makes a matcher answer the
// same way under [Proxy.Match], which routes a request with no connection behind it.
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
	// RoutingPath returns the canonical form of the path the client sent. Percent-encoded
	// RFC 3986 unreserved characters are decoded, bytes that must be escaped in a path are
	// encoded in place, and every other escape keeps uppercase hex and stays distinct from
	// its decoded form, so %2F never matches /.
	//
	// With [WithMergeSlashes] or [WithCollapseDotSegments] the tree matches on a further
	// normalized form, which this deliberately does not report: what a handler needs to see
	// is what the client asked for. The request itself is never rewritten: what goes upstream
	// is the target the client sent, byte for byte.
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
	cachedPath    string

	scheme string
	host   string
	port   string

	hasPath bool

	scope HandlerScope
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
	c.interceptor = nil
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
	c.cachedPath = ""
	c.hasPath = false
	c.interceptor = nil
	// No handler runs on an authority lookup, so the scope names none.
	c.scope = 0
	*c.params = (*c.params)[:0]
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

// RoutingPath returns the canonical form of the path the client sent, not the further
// normalized form the tree may have matched on. See [RequestContext] for both. The request
// is never rewritten to either.
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

// Header returns the first request header value for key, or an empty string outside a
// served request.
func (c *Context) Header(key string) string {
	if c.req == nil {
		return ""
	}
	return c.req.Header.Get(key)
}

// RemoteAddr returns the address the request was received from, or the zero value when it
// carries none. It reads the request rather than the connection, so a matcher answers the
// same way here and under [Proxy.Match]. Use [Session.RemoteAddr] for the address of the
// connection itself, which no handler can rewrite.
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

// Session returns the client connection this request arrived on.
func (c *Context) Session() *Session { return c.sess }

// Params returns an iterator over the parameters matched by the current route.
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

// Pattern returns the pattern of the matched route, or an empty string outside of
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
