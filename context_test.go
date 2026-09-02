// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContext_Accessors(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	p, host, client := interceptingProxy(t, origin)
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	_, port := splitHostPort(originURL.Host)

	type observed struct {
		method, scheme, host, port, authority, routingPath string
		query, header                                      string
		params                                             []Param
		pattern                                            string
		proto                                              Protocol
		hasTLS                                             bool
		remoteAddr                                         string
		kind                                               Kind
	}
	var got observed

	p.MustAdd(host+"/v1/{id}/refunds", func(c *HTTPCtx) (*http.Response, error) {
		got = observed{
			method:      c.Method(),
			scheme:      c.Scheme(),
			host:        c.Host(),
			port:        c.Port(),
			authority:   c.Authority(),
			routingPath: c.RoutingPath(),
			query:       c.QueryParam("limit"),
			header:      c.Header("X-Test-Run"),
			params:      slices.Collect(c.Params()),
			pattern:     c.Pattern(),
			proto:       c.Protocol(),
			hasTLS:      c.Request().TLS != nil,
			remoteAddr:  c.RemoteAddr().Addr().String(),
			kind:        c.Entry().Kind(),
		}

		require.Same(t, p, c.Proxy())
		require.NotNil(t, c.Session())
		require.Equal(t, "ch_1", c.Param("id"))
		require.Empty(t, c.Param("missing"))
		require.NotZero(t, c.Entry())

		// The connection reports the same client as the request it carries.
		require.Equal(t, c.Session().RemoteAddr(), c.RemoteAddr())

		return Text(http.StatusOK, "done"), nil
	}, WithMethods(http.MethodPost))

	req, err := http.NewRequest(http.MethodPost, origin.URL+"/v1/ch_1/refunds?limit=10", nil)
	require.NoError(t, err)
	req.Header.Set("X-Test-Run", "run-42")

	resp, err := client.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, "done", string(body))

	assert.Equal(t, http.MethodPost, got.method)
	assert.Equal(t, "https", got.scheme)
	assert.Equal(t, host, got.host)
	assert.Equal(t, port, got.port)
	assert.Equal(t, joinHostPort(host, port), got.authority)
	assert.Equal(t, "/v1/ch_1/refunds", got.routingPath)
	assert.Equal(t, "10", got.query)
	assert.Equal(t, "run-42", got.header)
	assert.Equal(t, []Param{{Key: "id", Value: "ch_1"}}, got.params)
	assert.Equal(t, host+"/v1/{id}/refunds", got.pattern)
	assert.Equal(t, HTTP11, got.proto)
	assert.True(t, got.hasTLS, "an intercepted TLS connection must report its state")
	assert.Equal(t, "127.0.0.1", got.remoteAddr)
	assert.Equal(t, KindHTTP, got.kind)
}

// A request no entry matches is refused. The permissive default is gone: what passes through
// is a route the caller wrote, so an authority armed by a narrow entry does not quietly open
// every path under it.
func TestContext_UnmatchedRequestIsRefused(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()

	originURL := origin.URL
	p, host, client := interceptingProxy(t, origin)

	// The helper arms the authority with a catch-all. A narrow entry keeps the authority
	// armed while leaving every other path uncovered, which is what this test is about.
	_, err := p.Delete[HTTP](host + "/*{any}")
	require.NoError(t, err)
	p.MustAdd(host+"/registered", noopHandler)

	resp, err := client.Get(originURL + "/anything")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, http.StatusText(http.StatusForbidden)+"\n", string(body), "the client learns the status and nothing else")

	// The catch-all is a route like any other, and writing it restores the old behavior.
	p.MustAdd(host+"/*{any}", forwardHandler)
	resp, err = client.Get(originURL + "/anything")
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, "origin", string(body))
}

func TestContext_SetRequest(t *testing.T) {
	var seen string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	p, authority, client := interceptingProxy(t, origin)
	p.MustAdd(authority+"/old", func(c *HTTPCtx) (*http.Response, error) {
		req := c.Request().Clone(c.Request().Context())
		req.URL.Path = "/new"
		c.SetRequest(req)
		return c.Forward()
	}, WithMethods(http.MethodGet))

	resp, err := client.Get(origin.URL + "/old")
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, "/new", seen, "the handler must be able to retarget the request")
}

func TestContext_RemoteAddrOfAnAddresslessRequest(t *testing.T) {
	rc := &routeCtx{params: new([]string)}
	rc.http.r = rc
	c := &rc.http
	assert.False(t, c.RemoteAddr().IsValid(), "a context with no request has no client address")

	rc.req = httptest.NewRequest(http.MethodGet, "/v1/charges", nil)
	rc.req.RemoteAddr = "/tmp/sock"
	assert.False(t, c.RemoteAddr().IsValid(), "a unix socket has no IP")

	sess := &Session{remoteAddr: &net.UnixAddr{Name: "/tmp/sock", Net: "unix"}}
	assert.False(t, sess.RemoteAddr().IsValid(), "neither does the connection it arrived on")
}

func TestContext_RoutingPathCanonicalization(t *testing.T) {
	cases := []struct{ target, want string }{
		{"/v1/charges", "/v1/charges"},
		// An escaped unreserved character is decoded, an escaped delimiter is not.
		{"/v1/%41", "/v1/A"},
		{"/v1/a%2Fb", "/v1/a%2Fb"},
		// Lowercase hex is normalized so a pattern and a request agree on one form.
		{"/v1/a%2fb", "/v1/a%2Fb"},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.target, nil)
		assert.Equal(t, tc.want, routingPath(req), "routingPath(%q)", tc.target)
	}

	assert.Empty(t, routingPath(nil))
}
