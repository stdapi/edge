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
		remoteIP                                           string
		scope                                              HandlerScope
	}
	var got observed

	p.MustHandle([]string{http.MethodPost}, host+"/v1/{id}/refunds", func(c *Context) (*http.Response, error) {
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
			hasTLS:      c.TLS() != nil,
			remoteIP:    c.RemoteIP().String(),
			scope:       c.Scope(),
		}

		require.Same(t, p, c.Proxy())
		require.NotNil(t, c.Session())
		require.NotNil(t, c.Context())
		require.Equal(t, "ch_1", c.Param("id"))
		require.Empty(t, c.Param("missing"))
		require.Equal(t, Target{Scheme: "https", Host: host, Port: port}, c.Target())
		require.NotNil(t, c.Route())

		return Text(http.StatusOK, "done"), nil
	})

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
	assert.Equal(t, "127.0.0.1", got.remoteIP)
	assert.Equal(t, RouteHandler, got.scope)
}

func TestContext_NoRouteScope(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()

	var scope HandlerScope
	var pattern string
	var route *Route

	originURL := origin.URL
	p, _, client := interceptingProxy(t, origin, WithNoRouteHandler(func(c *Context) (*http.Response, error) {
		scope = c.Scope()
		pattern = c.Pattern()
		route = c.Route()
		return Text(http.StatusOK, "no route"), nil
	}))
	_ = p

	resp, err := client.Get(originURL + "/anything")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	assert.Equal(t, "no route", string(body))
	assert.Equal(t, NoRouteHandler, scope)
	assert.Empty(t, pattern, "there is no pattern outside of a route")
	assert.Nil(t, route)
}

func TestContext_SetRequest(t *testing.T) {
	var seen string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	p, authority, client := interceptingProxy(t, origin)
	p.MustHandle([]string{http.MethodGet}, authority+"/old", func(c *Context) (*http.Response, error) {
		req := c.Request().Clone(c.Context())
		req.URL.Path = "/new"
		c.SetRequest(req)
		return c.Forward()
	})

	resp, err := client.Get(origin.URL + "/old")
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, "/new", seen, "the handler must be able to retarget the request")
}

func TestContext_Clone(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	p, authority, client := interceptingProxy(t, origin)

	kept := make(chan *Context, 1)
	p.MustHandle([]string{http.MethodGet}, authority+"/v1/{id}", func(c *Context) (*http.Response, error) {
		kept <- c.Clone()
		return Text(http.StatusOK, "ok"), nil
	})

	resp, err := client.Get(origin.URL + "/v1/ch_9")
	require.NoError(t, err)
	_ = resp.Body.Close()

	// The clone stays readable after the handler returned and its context went back to the
	// pool, which is what makes it safe to hand to a recorder.
	c := <-kept
	assert.Equal(t, "ch_9", c.Param("id"))
	assert.Equal(t, authority+"/v1/{id}", c.Pattern())
	assert.NotNil(t, c.Request())
	c.Close()
	assert.Equal(t, "ch_9", c.Param("id"), "closing a clone must not recycle it")
}

func TestContext_RemoteIPOfAnAddresslessConnection(t *testing.T) {
	c := &Context{params: new([]string)}
	assert.False(t, c.RemoteIP().IsValid(), "a context with no session has no client address")

	c.sess = &Session{remoteAddr: &net.UnixAddr{Name: "/tmp/sock", Net: "unix"}}
	assert.False(t, c.RemoteIP().IsValid(), "a unix socket has no IP")
}
