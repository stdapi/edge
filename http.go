// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"math"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"net/url"
	"strconv"
	"sync/atomic"
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
//
// A TRACE or OPTIONS request with a Max-Forwards of 0 is answered by the proxy without reaching
// the upstream, OPTIONS with an empty 200 and TRACE with a 501. A greater value is sent
// decremented.
func (c *HTTPCtx) ForwardRequest(r *http.Request) (*http.Response, error) {
	if r == nil {
		return nil, errors.New("edge: forward a nil request")
	}
	if c.r.p == nil || c.r.p.srv == nil || c.r.p.srv.fwd == nil {
		return nil, errors.New("edge: proxy has no forwarder")
	}

	hops, limited := maxForwards(r)
	if limited && hops == 0 {
		if r.Method == http.MethodOptions {
			return Status(http.StatusOK), nil
		}
		return Text(http.StatusNotImplemented, http.StatusText(http.StatusNotImplemented)), nil
	}

	ctx := r.Context()
	relay := c.r.infoRelay(ctx)
	if relay != nil {
		ctx = httptrace.WithClientTrace(ctx, &relay.trace)
	}
	out, err := c.outboundRequest(ctx, r)
	if err != nil {
		return nil, err
	}
	if limited {
		out.Header["Max-Forwards"] = []string{strconv.FormatUint(hops-1, 10)}
	}

	var fixed string
	if c.r.sess != nil {
		fixed = c.r.sess.dialAddr()
	}
	var resp *http.Response
	if relay == nil {
		resp, err = c.r.p.srv.fwd.roundTrip(out, c.upstreamProtocol(), fixed)
	} else {
		var started chan struct{}
		if c.r.expectContinue && out.Body != nil && out.Body != http.NoBody {
			started = make(chan struct{})
			out.Body = &continueBody{ReadCloser: out.Body, started: started}
		}
		resp, err = c.r.relayedRoundTrip(relay, out, c.upstreamProtocol(), fixed, started)
	}
	if err != nil {
		return nil, fmt.Errorf("forward %s %s: %w", out.Method, out.URL.Redacted(), err)
	}

	stripResponseHopByHop(resp)
	return resp, nil
}

// outboundRequest turns the request the proxy received into one the upstream transport can
// send. The target of the original request is preserved byte for byte; only the headers a
// proxy must not relay are removed.
func (c *HTTPCtx) outboundRequest(ctx context.Context, r *http.Request) (*http.Request, error) {
	if r.URL == nil {
		return nil, errors.New("edge: forward a request with no URL")
	}

	out := r.Clone(ctx)
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
	if out.Method == http.MethodOptions && out.URL.Opaque == "" && out.URL.Path == "" &&
		out.URL.RawQuery == "" && !out.URL.ForceQuery {
		// RFC 9112 3.2.4, an OPTIONS about the server itself. Every transport writes an empty
		// path as /.
		out.URL.Path = "*"
	}

	upgrade := upgradeType(r.Header)
	if !r.ProtoAtLeast(1, 1) {
		// RFC 9110 7.8, HTTP/1.0 has no upgrade.
		upgrade = ""
	}
	trailers := headerListContains(r.Header, "Te", "trailers")
	stripHopByHop(out.Header)
	stripPseudoHeaders(out.Header)
	if _, ok := out.Header["User-Agent"]; !ok {
		// Every upstream transport writes its own User-Agent unless the field is present.
		out.Header["User-Agent"] = []string{""}
	}
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

// maxForwards returns the Max-Forwards of a TRACE or OPTIONS request, and false for any other
// method or a value that is not 1*DIGIT, which is then forwarded as the client sent it. A
// value past the range of uint64 reads as the maximum.
func maxForwards(r *http.Request) (uint64, bool) {
	if r.Method != http.MethodTrace && r.Method != http.MethodOptions {
		return 0, false
	}
	vv := r.Header["Max-Forwards"]
	if len(vv) != 1 || vv[0] == "" {
		return 0, false
	}
	for i := 0; i < len(vv[0]); i++ {
		if vv[0][i] < '0' || vv[0][i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(vv[0], 10, 64)
	if err != nil {
		return math.MaxUint64, true
	}
	return n, true
}

// infoRelay relays the 1xx responses of one upstream round trip to the client. The round trip
// runs on a goroutine of its own and the handler goroutine writes each 1xx while it waits, so
// the response writer is never written from a transport goroutine.
type infoRelay struct {
	trace  httptrace.ClientTrace
	info   chan informational
	result chan roundTripResult
	// done is closed once the handler stops waiting on a round trip that failed, so a 1xx the
	// transport still reads for it is dropped.
	done    chan struct{}
	run     func()
	fwd     *forwarder
	out     *http.Request
	fixed   string
	pending []informational
	proto   Protocol
}

type informational struct {
	header http.Header
	code   int
}

type roundTripResult struct {
	resp *http.Response
	err  error
	rec  any
}

func newInfoRelay() *infoRelay {
	i := &infoRelay{
		info:   make(chan informational),
		result: make(chan roundTripResult, 1),
		done:   make(chan struct{}),
	}
	i.trace.Got1xxResponse = i.got1xx
	i.run = i.roundTrip
	return i
}

// infoRelay returns the relay of the next round trip, or nil when the client cannot be sent a
// 1xx.
func (c *routeCtx) infoRelay(ctx context.Context) *infoRelay {
	if c.w == nil {
		return nil
	}
	if httptrace.ContextClientTrace(ctx) != nil {
		// WithClientTrace composes the trace it is given with the one already there, and a
		// pooled trace would keep the hooks of this request.
		return newInfoRelay()
	}
	if c.relay == nil {
		c.relay = newInfoRelay()
	}
	return c.relay
}

func (i *infoRelay) got1xx(code int, header textproto.MIMEHeader) error {
	if code == http.StatusContinue || code == http.StatusSwitchingProtocols {
		// The server sends its own 100 when the handler reads the body, and a 101 is a final
		// response.
		return nil
	}
	select {
	case i.info <- informational{code: code, header: http.Header(header).Clone()}:
	case <-i.done:
	}
	return nil
}

func (i *infoRelay) roundTrip() {
	var res roundTripResult
	defer func() {
		res.rec = recover()
		i.result <- res
	}()
	res.resp, res.err = i.fwd.roundTrip(i.out, i.proto, i.fixed)
}

// relayedRoundTrip runs the round trip of out on i and writes each 1xx it reads to the client
// until it ends. A 1xx is written only once started is closed, nil meaning at once.
func (c *routeCtx) relayedRoundTrip(i *infoRelay, out *http.Request, proto Protocol, fixed string, started <-chan struct{}) (*http.Response, error) {
	w := c.w
	i.fwd, i.out, i.proto, i.fixed = c.p.srv.fwd, out, proto, fixed
	go i.run()
	for {
		select {
		case v := <-i.info:
			i.pending = append(i.pending, v)
			if started == nil {
				i.flush(w)
			}
		case <-started:
			started = nil
			i.flush(w)
		case res := <-i.result:
			if started != nil {
				select {
				case <-started:
					started = nil
				default:
				}
			}
			if started == nil {
				i.flush(w)
			}
			// A 1xx that arrived before the first read of the body returned is dropped, as the
			// transport may still be in that read.
			clear(i.pending)
			i.pending = i.pending[:0]
			i.fwd, i.out = nil, nil
			if res.err != nil || res.rec != nil {
				close(i.done)
				if c.relay == i {
					c.relay = nil
				}
			}
			if res.rec != nil {
				panic(res.rec)
			}
			return res.resp, res.err
		}
	}
}

func (i *infoRelay) flush(w http.ResponseWriter) {
	for _, v := range i.pending {
		dst := w.Header()
		for k, vv := range v.header {
			dst[k] = vv
		}
		stripHopByHop(dst)
		w.WriteHeader(v.code)
		// The writer keeps its header map across a 1xx, and the final response must not
		// inherit the fields of this one.
		for k := range v.header {
			delete(dst, k)
		}
	}
	clear(i.pending)
	i.pending = i.pending[:0]
}

// continueBody closes started once the first read of a request body returns. net/http writes
// the 100 Continue of an HTTP/1.1 request from that read, on the goroutine of the transport.
type continueBody struct {
	io.ReadCloser
	started chan struct{}
	read    atomic.Bool
}

func (b *continueBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if !b.read.Load() && b.read.CompareAndSwap(false, true) {
		close(b.started)
	}
	return n, err
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
