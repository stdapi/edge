// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"errors"
	"fmt"
	"iter"
	"net/http"
	"net/netip"
	"net/url"
)

// HTTPCtx carries one intercepted request through the middleware chain and into the handler.
//
// It is not safe for concurrent use and must not outlive the handler: it is returned to a pool
// as soon as the handler returns. Read out of it whatever has to outlive it.
type HTTPCtx struct {
	r *routeCtx
}

// Request returns the request being proxied. Handlers mutate it in place to change what is
// sent upstream.
func (c *HTTPCtx) Request() *http.Request { return c.r.req }

// SetRequest replaces the request the rest of the chain sees, and with it the one sent
// upstream. It is how a middleware hands a substituted request down: the middleware signature
// carries no request of its own.
func (c *HTTPCtx) SetRequest(r *http.Request) {
	c.r.cachedQueries = nil
	c.r.req = r
}

// Method returns the request method, or an empty string outside a served request.
func (c *HTTPCtx) Method() string {
	if c.r.req == nil {
		return ""
	}
	return c.r.req.Method
}

// Scheme returns the scheme of the request target, http or https.
func (c *HTTPCtx) Scheme() string { return c.r.scheme }

// Host returns the hostname of the request target, without its port.
func (c *HTTPCtx) Host() string { return c.r.host }

// Port returns the port of the request target. It is always explicit, defaulted from the
// scheme when the client did not send one.
func (c *HTTPCtx) Port() string { return c.r.port }

// Authority returns the request target as host:port.
func (c *HTTPCtx) Authority() string { return joinHostPort(c.r.host, c.r.port) }

// RoutingPath returns the canonical form of the path the client sent, which is the form the
// tree matched on. See [RequestContext] for what canonical covers. It is recomputed on every
// call, so a handler that rewrites the request reads back what it wrote.
func (c *HTTPCtx) RoutingPath() string { return routingPath(c.r.req) }

// QueryParams parses the raw query and caches the result.
func (c *HTTPCtx) QueryParams() url.Values { return c.r.getQueries() }

// QueryParam returns the first value for name.
func (c *HTTPCtx) QueryParam(name string) string { return c.r.getQueries().Get(name) }

// Header returns the first request header value for key, or an empty string outside a served
// request.
func (c *HTTPCtx) Header(key string) string {
	if c.r.req == nil {
		return ""
	}
	return c.r.req.Header.Get(key)
}

// RemoteAddr returns the address the request was received from, or the zero value when it
// carries none. Use [Session.RemoteAddr] for the address of the connection, which is the same
// for every request multiplexed on it and which no handler can rewrite.
func (c *HTTPCtx) RemoteAddr() netip.AddrPort {
	if c.r.req == nil {
		return netip.AddrPort{}
	}
	ap, err := netip.ParseAddrPort(c.r.req.RemoteAddr)
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// Protocol returns the protocol the request was received over, or the zero value outside a
// served request. It is not necessarily the protocol used upstream.
func (c *HTTPCtx) Protocol() Protocol {
	if c.r.req == nil {
		return 0
	}
	return protoOfRequest(c.r.req)
}

// Identity returns what the configured [ProxyAuthenticator] reported for this request, or an
// empty string when none did. A request read off a terminated connection was never
// challenged, so it reports the identity of whatever established the connection.
func (c *HTTPCtx) Identity() string { return c.r.identity }

// Session returns the client connection this request arrived on.
func (c *HTTPCtx) Session() *Session { return c.r.sess }

// Target returns the authority this request is addressed to.
func (c *HTTPCtx) Target() Target {
	return Target{Scheme: c.r.scheme, Host: c.r.host, Port: c.r.port}
}

// Params returns an iterator over the parameters matched by the current entry.
func (c *HTTPCtx) Params() iter.Seq[Param] {
	return func(yield func(Param) bool) {
		if c.r.entry == nil {
			return
		}
		for i, v := range *c.r.params {
			if i >= len(c.r.entry.params) {
				return
			}
			if !yield(Param{Key: c.r.entry.params[i], Value: v}) {
				return
			}
		}
	}
}

// Param returns the value matched for the named parameter, or an empty string.
func (c *HTTPCtx) Param(name string) string {
	if c.r.entry == nil {
		return ""
	}
	for i, v := range *c.r.params {
		if i < len(c.r.entry.params) && c.r.entry.params[i] == name {
			return v
		}
	}
	return ""
}

// Pattern returns the pattern of the matched entry, or an empty string.
func (c *HTTPCtx) Pattern() string {
	if c.r.entry == nil {
		return ""
	}
	return c.r.entry.pattern.str
}

// Entry returns the matched entry.
func (c *HTTPCtx) Entry() Entry[HTTP] { return Entry[HTTP]{e: c.r.entry} }

// Proxy returns the [Proxy] serving this request.
func (c *HTTPCtx) Proxy() *Proxy { return c.r.p }

// Forward sends the request upstream and returns the response. The response body streams from
// the upstream connection: returning the response from a handler relays it to the client
// without buffering, and reading it consumes it.
//
// The request is sent as the client wrote it, minus the hop-by-hop headers a proxy must not
// relay. Nothing is added: no Via, no X-Forwarded-For, no Accept-Encoding of the proxy's own.
// Anything a handler mutates on [HTTPCtx.Request] before calling Forward is what the upstream
// sees.
func (c *HTTPCtx) Forward() (*http.Response, error) {
	return c.ForwardRequest(c.r.req)
}

// ForwardRequest sends r upstream instead of the request the handler was given. Use it to
// retry, to fan out, or to rewrite the target entirely.
func (c *HTTPCtx) ForwardRequest(r *http.Request) (*http.Response, error) {
	if r == nil {
		return nil, errors.New("edge: forward a nil request")
	}
	if c.r.p == nil || c.r.p.srv == nil || c.r.p.srv.fwd == nil {
		return nil, errors.New("edge: proxy has no forwarder")
	}

	out, err := c.outboundRequest(r)
	if err != nil {
		return nil, err
	}

	var fixed string
	if c.r.sess != nil {
		fixed = c.r.sess.dialAddr()
	}
	resp, err := c.r.p.srv.fwd.roundTrip(out, c.upstreamProtocol(), fixed)
	if err != nil {
		return nil, fmt.Errorf("forward %s %s: %w", out.Method, out.URL.Redacted(), err)
	}

	stripResponseHopByHop(resp)
	return resp, nil
}

// outboundRequest turns the request the proxy received into one the upstream transport can
// send. The target of the original request is preserved byte for byte; only the headers a
// proxy must not relay are removed.
func (c *HTTPCtx) outboundRequest(r *http.Request) (*http.Request, error) {
	if r.URL == nil {
		return nil, errors.New("edge: forward a request with no URL")
	}

	out := r.Clone(r.Context())
	// A client request carries no RequestURI; net/http panics otherwise.
	out.RequestURI = ""
	out.Close = false

	if out.URL.Scheme == "" {
		out.URL.Scheme = c.r.scheme
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
	trailers := headerListContains(r.Header, "Te", "trailers")
	stripHopByHop(out.Header)
	stripPseudoHeaders(out.Header)
	if trailers {
		// Tell an upstream that cares about trailer support that the proxy relays them,
		// and only when the client thought it worth mentioning.
		out.Header.Set("Te", "trailers")
	}
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
// termination stays invisible in the one place an app can most easily notice it.
func (c *HTTPCtx) upstreamProtocol() Protocol {
	if c.r.sess == nil {
		return HTTP11
	}
	return c.r.sess.Protocol()
}
