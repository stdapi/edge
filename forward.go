// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"cmp"
	"context"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync"

	"github.com/fox-toolkit/edge/internal/simplelru"
)

const maxDestinationPools = 1024

// hopByHopHeaders are connection-scoped and must not be forwarded to the next hop.
// See RFC 9110 section 7.6.1.
var hopByHopHeaders = [...]string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// forwarder pools upstream connections per destination, and requests with no fixed
// destination share one pool per scheme.
type forwarder struct {
	p      *Proxy
	up     *upstreamDialer
	shared struct{ http, https *upstreamPool }
	fixed  *simplelru.LRU[string, *upstreamPool]
	mu     sync.Mutex
}

type upstreamPool struct {
	h1 *http.Transport
	h2 *http.Transport
	h3 http.RoundTripper
}

func newUpstreamPool(up *upstreamDialer, scheme, fixed string) (*upstreamPool, error) {
	t := up.t
	dial, proxy := t.dialer(), t.Proxy
	if fixed != "" || scheme == "https" {
		// net/http offers a proxy the ALPN list meant for the origin, so the tunnel is
		// opened here and the transport is given no proxy of its own. A plaintext request
		// with no fixed destination keeps net/http's handling, absolute form to the proxy.
		proxy = nil
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return up.dial(ctx, network, cmp.Or(fixed, addr), scheme)
		}
	}
	pool := &upstreamPool{h1: t.httpTransport(false, fixed != "", dial, proxy)}
	if t.AllowHTTP2 {
		if scheme == "http" && fixed != "" {
			// The client used h2c with a destination it declared, and no ALPN can ask the
			// origin.
			pool.h2 = t.h2cTransport(dial)
		} else {
			pool.h2 = t.httpTransport(true, fixed != "", dial, proxy)
		}
	}
	if t.AllowHTTP3 && scheme == "https" {
		rt, err := newHTTP3Transport(up, fixed)
		if err != nil {
			return nil, err
		}
		pool.h3 = rt
	}
	return pool, nil
}

// closeIdle leaves a connection in flight open until [Transport.IdleConnTimeout].
func (u *upstreamPool) closeIdle() {
	u.h1.CloseIdleConnections()
	if u.h2 != nil {
		u.h2.CloseIdleConnections()
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
	var err error
	if f.shared.http, err = newUpstreamPool(up, "http", ""); err != nil {
		return nil, err
	}
	if f.shared.https, err = newUpstreamPool(up, "https", ""); err != nil {
		return nil, err
	}
	if f.fixed, err = simplelru.NewLRU(maxDestinationPools, func(_ string, pool *upstreamPool) { pool.closeIdle() }); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *forwarder) close() {
	f.mu.Lock()
	pools := f.fixed.Values()
	f.mu.Unlock()
	f.shared.http.close()
	f.shared.https.close()
	for _, pool := range pools {
		pool.close()
	}
	f.up.close()
}

func (f *forwarder) poolFor(scheme, fixed string) (*upstreamPool, error) {
	if fixed == "" {
		if scheme == "https" {
			return f.shared.https, nil
		}
		return f.shared.http, nil
	}
	key := scheme + " " + fixed
	f.mu.Lock()
	defer f.mu.Unlock()
	if pool, ok := f.fixed.Get(key); ok {
		return pool, nil
	}
	pool, err := newUpstreamPool(f.up, scheme, fixed)
	if err != nil {
		return nil, err
	}
	f.fixed.Add(key, pool)
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
	pool, err := f.poolFor(req.URL.Scheme, fixed)
	if err != nil {
		return nil, err
	}
	switch {
	case proto == HTTP3 && pool.h3 != nil:
		return pool.h3.RoundTrip(req)
	case (proto == HTTP2 || proto == HTTP3) && pool.h2 != nil:
		// Over TLS h2 is reached through ALPN, so an origin that does not offer it is
		// served over HTTP/1.1 by the same transport.
		return pool.h2.RoundTrip(req)
	default:
		return pool.h1.RoundTrip(req)
	}
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
// 101 where Connection and Upgrade are the whole point of the answer.
func stripResponseHopByHop(resp *http.Response) {
	if resp.StatusCode != http.StatusSwitchingProtocols {
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
		h.Del(name)
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
