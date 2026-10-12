// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"io"
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

// RequestContext is the read-only view of a request handed to a [RequestMatcher]. It is
// valid during the [RequestMatcher.Match] call and reused once that call returns. It exposes
// the request and nothing of the connection, which serves many requests.
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
	// uppercase hex and stays distinct from its decoded form, so %2F never matches /. An empty
	// path is /, and so is the "*" of an asterisk-form target.
	RoutingPath() string
	// QueryParams parses the raw query and caches the result.
	QueryParams() url.Values
	// QueryParam returns the first value for name.
	QueryParam(name string) string
	// Header returns the first request header value for key.
	Header(key string) string
	// RemoteAddr returns the address the request was received from, or the zero value when
	// it has none.
	RemoteAddr() netip.AddrPort
	// Protocol returns the protocol the request was received over.
	Protocol() Protocol
}

// routeCtx is the state of one routing lookup, what the tree walks with, what it captures and
// what the handler reads back. It is pooled per tree, and the HTTP view lives inside it so
// serving a request allocates nothing.
type routeCtx struct {
	// w is the client writer a 1xx from the origin is relayed to, nil where none may be.
	w    http.ResponseWriter
	req  *http.Request
	sess *Session
	// client is the request as the server read it and body is its body, which a handler may
	// replace on the request. Only dispatch sets them, since a gRPC call routes each message
	// again from the transport while its handler swaps the body.
	client *http.Request
	body   io.ReadCloser

	params    *[]string
	skipStack *skipStack
	entry     *entry

	p *Proxy // no reset, and the only thing the state keeps of the proxy

	cachedQueries url.Values

	// http points back at this state, so a handler is handed &c.http and nothing is
	// allocated to serve a request.
	http HTTPCtx

	relay *infoRelay
	// grpc borrows the same state through http, a call being a request underneath, so
	// serving one allocates nothing either.
	grpc GRPCCtx

	scheme   string
	host     string
	port     string
	identity string
	// expectContinue is set when net/http writes a 100 Continue from the first read of the
	// request body.
	expectContinue bool
}

func (c *routeCtx) reset(sess *Session, r *http.Request, scheme, host, port string) {
	c.req = r
	c.client = nil
	c.body = nil
	c.sess = sess
	c.scheme = scheme
	c.host = host
	c.port = port
	c.cachedQueries = nil
	c.entry = nil
	c.identity = ""
	c.w = nil
	c.expectContinue = false
	c.grpc.reset()
	*c.params = (*c.params)[:0]
}

func (c *routeCtx) resetForAdmission(sess *Session, scheme, host, port string) {
	c.reset(sess, nil, scheme, host, port)
}

// capturedParams copies the parameters captured by the last lookup, for a handler that
// outlives the pooled state the walk used.
func (c *routeCtx) capturedParams() []Param {
	return c.appendParams(nil)
}

// appendParams appends the parameters captured by the last lookup to dst, reusing its storage.
func (c *routeCtx) appendParams(dst []Param) []Param {
	if c.entry == nil || len(*c.params) == 0 {
		return dst[:0]
	}
	n := min(len(*c.params), len(c.entry.params))
	if cap(dst) < n {
		dst = make([]Param, 0, n)
	}
	dst = dst[:0]
	for i := range n {
		dst = append(dst, Param{Key: c.entry.params[i], Value: (*c.params)[i]})
	}
	return dst
}

// routingPath returns the canonical form of the request path used for matching. The request
// is never rewritten to it, since a proxy must put back on the wire exactly what the client
// sent.
func routingPath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	u := r.URL
	if u.RawPath == "" {
		if u.Path == "" || u.Path == "*" {
			// An absolute-form target may have an empty path, and a lookup without one
			// reaches the admission of its authority. The asterisk-form has an empty path
			// too, RFC 9112 section 3.3.
			return "/"
		}
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

func (c *routeCtx) getQueries() url.Values {
	if c.cachedQueries == nil {
		if c.req != nil && c.req.URL != nil {
			c.cachedQueries = c.req.URL.Query()
		} else {
			c.cachedQueries = make(url.Values)
		}
	}
	return c.cachedQueries
}

// onlyRequestContext seals the routing state down to [RequestContext] so a [RequestMatcher]
// cannot reach the mutating half of the API.
type onlyRequestContext struct {
	c *routeCtx
}

func (o onlyRequestContext) Request() *http.Request { return o.c.req }
func (o onlyRequestContext) Method() string {
	if o.c.req == nil {
		return ""
	}
	return o.c.req.Method
}
func (o onlyRequestContext) Scheme() string          { return o.c.scheme }
func (o onlyRequestContext) Host() string            { return o.c.host }
func (o onlyRequestContext) Port() string            { return o.c.port }
func (o onlyRequestContext) Authority() string       { return joinHostPort(o.c.host, o.c.port) }
func (o onlyRequestContext) RoutingPath() string     { return routingPath(o.c.req) }
func (o onlyRequestContext) QueryParams() url.Values { return o.c.getQueries() }
func (o onlyRequestContext) QueryParam(n string) string {
	return o.c.getQueries().Get(n)
}

func (o onlyRequestContext) Header(k string) string {
	if o.c.req == nil {
		return ""
	}
	return o.c.req.Header.Get(k)
}

func (o onlyRequestContext) RemoteAddr() netip.AddrPort {
	if o.c.req == nil {
		return netip.AddrPort{}
	}
	ap, err := netip.ParseAddrPort(o.c.req.RemoteAddr)
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func (o onlyRequestContext) Protocol() Protocol {
	if o.c.req == nil {
		return 0
	}
	return protoOfRequest(o.c.req)
}

var _ RequestContext = onlyRequestContext{}
