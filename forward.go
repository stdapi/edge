// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net/http"
	"net/textproto"
	"strings"
)

// upstreamAddrKey carries a per-request dial override through the shared transport.
type upstreamAddrKey struct{}

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

// forwarder sends requests upstream. It keeps one transport per protocol so the version the
// client chose can be mirrored upstream, and every session shares it so upstream connections
// are pooled across clients.
type forwarder struct {
	p  *Proxy
	h1 *http.Transport
	h2 *http.Transport
	h3 http.RoundTripper
}

func newForwarder(p *Proxy) (*forwarder, error) {
	t := p.cfg.transport
	f := &forwarder{p: p, h1: t.httpTransport(false)}

	if t.AllowHTTP2 {
		f.h2 = t.httpTransport(true)
	}
	if t.AllowHTTP3 {
		rt, err := newHTTP3Transport(t)
		if err != nil {
			return nil, err
		}
		f.h3 = rt
	}
	return f, nil
}

func (f *forwarder) close() {
	f.h1.CloseIdleConnections()
	if f.h2 != nil {
		f.h2.CloseIdleConnections()
	}
	if c, ok := f.h3.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

// roundTrip sends req upstream over the same HTTP version the client used, and returns the
// response with its body still streaming.
//
// Mirroring matters because the version is one of the few things an application can observe
// about its own connection. A test that asserts it was served over HTTP/2 must not start
// failing because a proxy was inserted, and a client that only speaks HTTP/1.1 must not have
// its request delivered as h2 frames it never asked for.
func (f *forwarder) roundTrip(req *http.Request, proto Protocol) (*http.Response, error) {
	switch {
	case proto == HTTP3 && f.h3 != nil && req.URL.Scheme == "https":
		return f.h3.RoundTrip(req)
	case proto >= HTTP2 && f.h2 != nil:
		// h2 is only reachable through ALPN, so an origin that does not offer it is served
		// over HTTP/1.1 by the same transport.
		return f.h2.RoundTrip(req)
	default:
		return f.h1.RoundTrip(req)
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
