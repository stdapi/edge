// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fox-toolkit/edge/internal/simplelru"
)

const maxPools = 1024

// hopByHopHeaders are connection-scoped and must not be forwarded to the next hop.
// See RFC 9110 section 7.6.1.
var hopByHopHeaders = [...]string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authentication-Info",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// forwarder pools upstream connections per scheme, destination and proxy, and the requests
// with neither a fixed destination nor a proxy share one pool per scheme.
type forwarder struct {
	p      *Proxy
	up     *upstreamDialer
	shared struct{ http, https *upstreamPool }
	pools  *simplelru.LRU[poolKey, *upstreamPool]
	mu     sync.Mutex
}

// poolKey includes the proxy, as the key of net/http does, so a request through another
// proxy never reuses a connection.
type poolKey struct {
	scheme, fixed, proxy string
}

type upstreamPool struct {
	h1  *http.Transport
	h2  *http.Transport
	h3  http.RoundTripper
	h2c *http.Transport
	// absolute is set when net/http sends the absolute form to a proxy.
	absolute bool
}

func newUpstreamPool(up *upstreamDialer, scheme, fixed string, proxy *url.URL) *upstreamPool {
	t := up.t
	dial := up.dialRaw
	var via func(*http.Request) (*url.URL, error)
	if fixed != "" || scheme == "https" {
		// net/http offers a proxy the ALPN list meant for the origin, so the tunnel is
		// opened here and the transport is given no proxy of its own. A plaintext request
		// with no fixed destination keeps net/http's handling, absolute form to the proxy.
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return up.dialThrough(ctx, network, cmp.Or(fixed, addr), proxy)
		}
	} else if proxy != nil {
		via = http.ProxyURL(proxy)
	}
	gated := func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil || c == nil {
			return c, err
		}
		return &gatedConn{Conn: c}, nil
	}
	pool := &upstreamPool{h1: t.httpTransport(false, fixed != "", gated, via), absolute: via != nil}
	if t.AllowHTTP2 {
		if scheme == "http" && fixed != "" {
			// The client used h2c with a destination it declared, and no ALPN can ask the
			// origin.
			pool.h2 = t.h2cTransport(dial, true)
		} else {
			pool.h2 = t.httpTransport(true, fixed != "", gated, via)
		}
		if scheme == "http" && fixed == "" {
			// A gRPC call requires HTTP/2 at the origin.
			pool.h2c = t.h2cTransport(func(ctx context.Context, network, addr string) (net.Conn, error) {
				return up.dialThrough(ctx, network, addr, proxy)
			}, false)
		}
	}
	if t.AllowHTTP3 && scheme == "https" {
		pool.h3 = newHTTP3Transport(up, fixed, proxy)
	}
	return pool
}

// gatedConn is a connection a transport of an [upstreamPool] dialed, which may serve HTTP/1.1.
// Go's transport returns it to the pool when a response ends and only then checks whether bytes
// past that end arrived with it, so a request given the connection in between reads them as its
// response.
type gatedConn struct {
	net.Conn
	waiter  atomic.Pointer[chan struct{}]
	reading atomic.Bool
	closed  atomic.Bool
	// alpn is the protocol a connection over TLS negotiated, alpnH1 or alpnH2, once a request
	// reused it.
	alpn atomic.Uint32
}

const (
	alpnH1 = 1 + iota
	alpnH2
)

func (c *gatedConn) Read(b []byte) (int, error) {
	c.reading.Store(true)
	c.wake()
	n, err := c.Conn.Read(b)
	c.reading.Store(false)
	return n, err
}

func (c *gatedConn) Close() error {
	c.closed.Store(true)
	c.wake()
	return c.Conn.Close()
}

// ReadFrom keeps the splice of *net.TCPConn for a request body.
func (c *gatedConn) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := c.Conn.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(struct{ io.Writer }{c.Conn}, r)
}

// CloseWrite forwards the half-close, which the embedded net.Conn does not promote.
func (c *gatedConn) CloseWrite() error { return closeWrite(c.Conn) }

func (c *gatedConn) wake() {
	if w := c.waiter.Load(); w != nil && c.waiter.CompareAndSwap(w, nil) {
		close(*w)
	}
}

// awaitRead returns once a read is in progress or the connection is closed, or once done is.
// The transport reads an idle connection again only when nothing is buffered past the last
// response, and closes it when something is, as long as no request was handed to it.
func (c *gatedConn) awaitRead(done <-chan struct{}) {
	if c.reading.Load() || c.closed.Load() {
		return
	}
	// Read stores its flag before it loads the waiter, and this the reverse, so one of the two
	// finds the other.
	ch := make(chan struct{})
	c.waiter.Store(&ch)
	if c.reading.Load() || c.closed.Load() {
		c.waiter.CompareAndSwap(&ch, nil)
		return
	}
	select {
	case <-ch:
	case <-done:
		c.waiter.CompareAndSwap(&ch, nil)
	}
}

// gateReuse waits, for a request given a reused HTTP/1.1 connection, until the transport has
// refused what it read past the last response, RFC 9112 section 6.3. Bytes still in the socket then
// are read as the response, which in plaintext [tailBody] limits to those behind a response that
// ended where a read of the transport's buffer did.
func gateReuse(info httptrace.GotConnInfo, done <-chan struct{}) {
	if !info.Reused {
		return
	}
	c := info.Conn
	tc, isTLS := c.(*tls.Conn)
	if isTLS {
		c = tc.NetConn()
	}
	g, ok := c.(*gatedConn)
	if !ok {
		return
	}
	if isTLS {
		alpn := g.alpn.Load()
		if alpn == 0 {
			alpn = alpnH1
			if tc.ConnectionState().NegotiatedProtocol == "h2" {
				alpn = alpnH2
			}
			g.alpn.Store(alpn)
		}
		if alpn == alpnH2 {
			return
		}
	}
	g.awaitRead(done)
}

// closeIdle leaves a connection in flight open until [Transport.IdleConnTimeout].
func (u *upstreamPool) closeIdle() {
	u.h1.CloseIdleConnections()
	if u.h2 != nil {
		u.h2.CloseIdleConnections()
	}
	if u.h2c != nil {
		u.h2c.CloseIdleConnections()
	}
	if c, ok := u.h3.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

func (u *upstreamPool) close() {
	u.closeIdle()
	if c, ok := u.h3.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

func newForwarder(p *Proxy) (*forwarder, error) {
	up := newUpstreamDialer(p.cfg.transport)
	f := &forwarder{p: p, up: up}
	f.shared.http = newUpstreamPool(up, "http", "", nil)
	f.shared.https = newUpstreamPool(up, "https", "", nil)
	var err error
	if f.pools, err = simplelru.NewLRU(maxPools, func(_ poolKey, pool *upstreamPool) { pool.closeIdle() }); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *forwarder) close() {
	f.mu.Lock()
	pools := f.pools.Values()
	f.mu.Unlock()
	f.shared.http.close()
	f.shared.https.close()
	for _, pool := range pools {
		pool.close()
	}
	f.up.close()
}

// poolFor returns the pool of req, through the proxy [Transport.Proxy] selects, called with
// req or with the destination alone when the session fixed one.
func (f *forwarder) poolFor(req *http.Request, fixed string) (*upstreamPool, error) {
	scheme := req.URL.Scheme
	var proxy *url.URL
	var err error
	if fixed == "" {
		proxy, err = f.up.selectProxy(req)
	} else {
		proxy, err = f.up.proxyFor(fixed, scheme)
	}
	if err != nil {
		return nil, err
	}
	if fixed == "" && proxy == nil {
		if scheme == "https" {
			return f.shared.https, nil
		}
		return f.shared.http, nil
	}
	key := poolKey{scheme: scheme, fixed: fixed}
	if proxy != nil {
		key.proxy = proxy.String()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if pool, ok := f.pools.Get(key); ok {
		return pool, nil
	}
	if proxy != nil {
		// The key is the URL as it was, so the pool keeps a copy of its own.
		own := *proxy
		proxy = &own
	}
	pool := newUpstreamPool(f.up, scheme, fixed, proxy)
	f.pools.Add(key, pool)
	return pool, nil
}

// roundTrip sends req upstream over the same HTTP version the client used, to the destination
// the session fixed when it fixed one, and returns the response with its body still streaming.
//
// Mirroring matters because the version is one of the few things an application can observe
// about its own connection. A test that asserts it was served over HTTP/2 must not start
// failing because a proxy was inserted, and a client that only speaks HTTP/1.1 must not have
// its request delivered as h2 frames it never asked for.
func (f *forwarder) roundTrip(req *http.Request, proto Protocol, fixed string) (*http.Response, error) {
	pool, err := f.poolFor(req, fixed)
	if err != nil {
		return nil, err
	}
	if pool.absolute && req.URL.Path == "*" {
		// RFC 9112 3.2.4 leaves "*" to the last proxy, and net/http writes an empty path as
		// "/" unless the target is opaque.
		req.URL.Opaque = "//" + req.URL.Host
	}
	switch {
	case proto == HTTP3 && pool.h3 != nil:
		resp, err := f.roundTripH3(pool.h3, req)
		if err == nil && resp.ContentLength > 0 && resp.Body != nil && resp.Body != http.NoBody &&
			bodyAllowed(req.Method, resp.StatusCode) {
			resp.Body = &fullLength{ReadCloser: resp.Body, remaining: resp.ContentLength}
		}
		return resp, err
	case (proto == HTTP2 || proto == HTTP3) && pool.h2c != nil && isGRPCRequest(req):
		return pool.h2c.RoundTrip(req)
	case (proto == HTTP2 || proto == HTTP3) && pool.h2 != nil:
		// Over TLS h2 is reached through ALPN, so an origin that does not offer it is
		// served over HTTP/1.1 by the same transport.
		resp, err := pool.refuseProxyAuth(pool.h2.RoundTrip(req))
		return bufferTail(req.Method, resp, err)
	default:
		if _, ok := req.Header["Te"]; ok {
			// RFC 9110 10.1.4. Only HTTP/1.1 has connection options, an HTTP/2 or HTTP/3
			// transport refuses the request when Connection lists one.
			addConnectionOption(req.Header, "TE")
		}
		resp, err := pool.refuseProxyAuth(pool.h1.RoundTrip(req))
		return bufferTail(req.Method, resp, err)
	}
}

var errResponseHeaderTimeout = errors.New("edge: timeout awaiting the response header")

// roundTripH3 applies [Transport.ResponseHeaderTimeout], which quic-go's transport does not
// have, counted from the end of the request as net/http counts it. Past it the request is
// canceled, which resets its stream with H3_REQUEST_CANCELLED.
func (f *forwarder) roundTripH3(rt http.RoundTripper, req *http.Request) (*http.Response, error) {
	d := f.up.t.ResponseHeaderTimeout
	if d <= 0 {
		return rt.RoundTrip(req)
	}
	ctx, cancel := context.WithCancelCause(req.Context())
	h := &headerTimer{d: d, cancel: cancel}
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: h.wrote})
	resp, err := rt.RoundTrip(req.WithContext(ctx))
	if h.stop() {
		if err == nil {
			_ = resp.Body.Close()
		}
		cancel(errResponseHeaderTimeout)
		return nil, errResponseHeaderTimeout
	}
	if err != nil {
		cancel(err)
		return nil, err
	}
	if resp.Body == nil || resp.Body == http.NoBody {
		cancel(nil)
		return resp, nil
	}
	// The context outlives the round trip. Canceling it resets the stream the body is read from.
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// headerTimer cancels a request whose response header has not arrived d after it was written.
type headerTimer struct {
	timer   *time.Timer
	cancel  context.CancelCauseFunc
	d       time.Duration
	mu      sync.Mutex
	stopped bool
}

func (h *headerTimer) wrote(httptrace.WroteRequestInfo) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.stopped && h.timer == nil {
		h.timer = time.AfterFunc(h.d, func() { h.cancel(errResponseHeaderTimeout) })
	}
}

// stop disarms the timer and reports whether it had already fired.
func (h *headerTimer) stop() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopped = true
	return h.timer != nil && !h.timer.Stop()
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelCauseFunc
}

func (b *cancelOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.cancel(nil)
	return err
}

// refuseProxyAuth fails the 407 of a proxy that was sent the request in absolute form. Its
// challenge is addressed to edge and removed as hop-by-hop, so the client could not answer it.
func (u *upstreamPool) refuseProxyAuth(resp *http.Response, err error) (*http.Response, error) {
	if err != nil || !u.absolute || resp.StatusCode != http.StatusProxyAuthRequired {
		return resp, err
	}
	_ = resp.Body.Close()
	return nil, fmt.Errorf("proxy %w", newRefusal(resp.StatusCode))
}

// h1ReadBuffer is the read buffer of every upstream HTTP/1.1 transport.
const h1ReadBuffer = 4 << 10

func bufferTail(method string, resp *http.Response, err error) (*http.Response, error) {
	if err == nil && resp.ProtoMajor == 1 && resp.TLS == nil && resp.ContentLength >= h1ReadBuffer &&
		bodyAllowed(method, resp.StatusCode) {
		resp.Body = &tailBody{ReadCloser: resp.Body, remaining: resp.ContentLength}
	}
	return resp, err
}

// tailBody has the last byte of a plaintext HTTP/1.1 body read through the transport's buffer. A
// read into a buffer at least as large goes to the socket directly and leaves there the bytes past
// the response, which the transport refuses only once buffered, RFC 9112 section 6.3.
type tailBody struct {
	io.ReadCloser
	remaining int64
}

func (b *tailBody) Read(p []byte) (int, error) {
	if b.remaining >= h1ReadBuffer {
		if int64(len(p)) >= b.remaining {
			p = p[:b.remaining-1]
		} else if len(p) > h1ReadBuffer && b.remaining-int64(len(p)) == h1ReadBuffer {
			// A fill of exactly what is left would end where the body does.
			p = p[:len(p)-1]
		}
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}

// fullLength fails a body that ends before its Content-Length with io.ErrUnexpectedEOF. quic-go
// ends it cleanly, and Go's HTTP/1.1 and HTTP/2 transports fail it.
type fullLength struct {
	io.ReadCloser
	remaining int64
}

func (b *fullLength) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	if err == io.EOF && b.remaining > 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func addConnectionOption(h http.Header, option string) {
	if v := h["Connection"]; len(v) > 0 {
		h["Connection"] = []string{strings.Join(v, ", ") + ", " + option}
		return
	}
	h["Connection"] = []string{option}
}

// stripPseudoHeaders removes the HTTP/2 and HTTP/3 pseudo headers net/http surfaces as
// ordinary ones. A name starting with a colon is not a field name, so a transport asked to send
// one refuses the whole request.
func stripPseudoHeaders(h http.Header) {
	for name := range h {
		if len(name) > 0 && name[0] == ':' {
			delete(h, name)
		}
	}
}

// stripResponseHopByHop removes the connection-scoped headers from a response, except on a
// 101 where Connection and Upgrade are the answer itself, and removes the trailer fields
// Connection lists along with their announcement.
func stripResponseHopByHop(resp *http.Response) {
	if resp.StatusCode != http.StatusSwitchingProtocols {
		if conn := resp.Header["Connection"]; len(resp.Trailer) > 0 && listsAny(conn, resp.Trailer) {
			for _, value := range conn {
				for field := range strings.SplitSeq(value, ",") {
					resp.Trailer.Del(textproto.TrimString(field))
				}
			}
			if resp.Body != nil && resp.Body != http.NoBody {
				resp.Body = &hopTrailers{ReadCloser: resp.Body, resp: resp, conn: conn}
			}
		}
		stripHopByHop(resp.Header)
		return
	}

	upgrade := resp.Header.Get("Upgrade")
	stripHopByHop(resp.Header)
	if upgrade != "" {
		resp.Header.Set("Connection", "Upgrade")
		resp.Header.Set("Upgrade", upgrade)
	}
}

// listsAny reports whether the Connection values conn list a field of h.
func listsAny(conn []string, h http.Header) bool {
	for _, value := range conn {
		for field := range strings.SplitSeq(value, ",") {
			if _, ok := h[textproto.CanonicalMIMEHeaderKey(textproto.TrimString(field))]; ok {
				return true
			}
		}
	}
	return false
}

// hopTrailers removes the trailer fields listed in Connection once the body has ended. The
// transport merges the received trailer section into the response at the end of the body,
// after any field was removed from the announcement.
type hopTrailers struct {
	io.ReadCloser
	resp *http.Response
	conn []string
}

func (b *hopTrailers) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		for _, value := range b.conn {
			for field := range strings.SplitSeq(value, ",") {
				b.resp.Trailer.Del(textproto.TrimString(field))
			}
		}
	}
	return n, err
}

// stripHopByHop removes the connection-scoped headers, including the ones the peer listed in
// its own Connection header.
func stripHopByHop(h http.Header) {
	if h == nil {
		return
	}
	// Read the Connection header before deleting it, it lists the other headers to drop.
	for _, value := range h.Values("Connection") {
		for field := range strings.SplitSeq(value, ",") {
			if field = textproto.TrimString(field); field != "" {
				h.Del(field)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		// Each entry is in canonical form, which Del would compute again.
		delete(h, name)
	}
}

// upgradeType returns the protocol named in the Upgrade header when the peer actually asked
// for an upgrade, and an empty string otherwise.
func upgradeType(h http.Header) string {
	if h == nil {
		return ""
	}
	if !headerListContains(h, "Connection", "upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

// headerListContains reports whether the comma separated header name contains token,
// compared case-insensitively.
func headerListContains(h http.Header, name, token string) bool {
	for _, value := range h.Values(name) {
		for field := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(textproto.TrimString(field), token) {
				return true
			}
		}
	}
	return false
}
