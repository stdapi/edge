// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntry_Accessors(t *testing.T) {
	p := testProxy(t)

	type annotationKey struct{}
	e := p.MustAdd("api.stripe.com:8443/v1/{id}/refunds/*{rest}", noopHandler,
		WithName[HTTP]("refunds"), WithAnnotation[HTTP](annotationKey{}, "recorded"),
		WithRelaxedTrailingSlash[HTTP](true), WithScheme[HTTP]("https"), WithMethods[HTTP](http.MethodGet))

	assert.Equal(t, "api.stripe.com:8443/v1/{id}/refunds/*{rest}", e.Pattern())
	assert.Equal(t, "api.stripe.com", e.Host())
	assert.Equal(t, "8443", e.Port())
	assert.Equal(t, "/v1/{id}/refunds/*{rest}", e.Path())
	assert.Equal(t, "refunds", e.Name())
	assert.Equal(t, "recorded", e.Annotation(annotationKey{}))
	assert.Nil(t, e.Annotation("missing"))
	assert.True(t, e.RelaxedTrailingSlash())
	assert.Equal(t, KindHTTP, e.Kind())

	assert.Equal(t, 2, e.ParamsLen())
	assert.Equal(t, []string{"id", "rest"}, slices.Collect(e.Params()))

	// The scheme and the methods are matchers, the two of them.
	assert.Equal(t, 2, e.MatchersLen())
	assert.Equal(t, uint(2), e.MatchersPriority())

	assert.Contains(t, e.String(), "kind:HTTP")
	assert.Contains(t, e.String(), "name:refunds")
	assert.Contains(t, e.String(), "scheme=https")
	assert.Contains(t, e.String(), "method=GET")
	assert.Contains(t, e.String(), "pattern:api.stripe.com:8443/")
}

func TestEntry_HostnameParamsLen(t *testing.T) {
	cases := []struct {
		name          string
		pattern       string
		wantParams    []string
		wantHostCount int
	}{
		{
			name:       "static host and path params",
			pattern:    "a.b.c/users/{id}",
			wantParams: []string{"id"},
		},
		{
			name:       "address range and path params",
			pattern:    "[10.0.0.0/8]:8080/users/{id}",
			wantParams: []string{"id"},
		},
		{
			name:          "host param and slash",
			pattern:       "{sub}.example.com/",
			wantParams:    []string{"sub"},
			wantHostCount: 1,
		},
		{
			name:          "host and path params",
			pattern:       "{a}.{b}.example.com/users/{id}",
			wantParams:    []string{"a", "b", "id"},
			wantHostCount: 2,
		},
		{
			name:          "host and path wildcards",
			pattern:       "+{sub}.example.com/files/+{path}",
			wantParams:    []string{"sub", "path"},
			wantHostCount: 1,
		},
		{
			name:          "regex host param",
			pattern:       "{sub:[a-z]+}.example.com/{id:[0-9]+}",
			wantParams:    []string{"sub", "id"},
			wantHostCount: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testProxy(t, WithRegexpParam(true))
			e, err := p.Add(tc.pattern, noopHandler)
			require.NoError(t, err)
			assert.Equal(t, tc.wantParams, slices.Collect(e.Params()))
			assert.Equal(t, tc.wantHostCount, e.HostnameParamsLen())
		})
	}

	p := testProxy(t)
	e := p.MustAdd[TCP]("{a}.{b}.example.com:443", noopStream)
	assert.Equal(t, []string{"a", "b"}, slices.Collect(e.Params()))
	assert.Equal(t, 2, e.HostnameParamsLen())
	e = p.MustAdd[TCP]("[10.0.0.0/8]:443", noopStream)
	assert.Equal(t, 0, e.HostnameParamsLen())
}

func TestEntry_KindComesFromTheHandler(t *testing.T) {
	p := testProxy(t)

	assert.Equal(t, KindHTTP, p.MustAdd("api.test/v1", noopHandler).Kind())
	assert.Equal(t, KindTCP, p.MustAdd[TCP]("smtp.test:465", noopStream).Kind())
	assert.Equal(t, KindQUIC, p.MustAdd("game.test:443", func(*QUICCtx) error { return nil }).Kind())
	assert.Equal(t, KindUDP, p.MustAdd("[0.0.0.0/0]:53", func(*DatagramCtx) error { return nil }).Kind())
	assert.Equal(t, KindGRPC, p.MustAdd("api.test/pkg.Svc/M", func(*GRPCCtx) error { return nil }).Kind())
	assert.Equal(t, KindWebSocket, p.MustAdd("chat.test/ws", func(*WebSocketCtx) error { return nil }).Kind())

	e := p.MustAdd("other.test/v1", noopHandler)
	assert.NotZero(t, e.Handler(), "the handler comes back with the signature it was given")
}

func TestEntry_MethodsIdentifyAnEntry(t *testing.T) {
	p := testProxy(t)
	get := p.MustAdd("api.test/v1", noopHandler, WithMethods[HTTP](http.MethodGet))
	post := p.MustAdd("api.test/v1", noopHandler, WithMethods[HTTP](http.MethodPost))

	assert.NotEqual(t, get, post)
	assert.Equal(t, 2, p.Len())
	assert.Equal(t, get, lookupHTTP(p, "api.test/v1", mustMethods(http.MethodGet)))
	assert.Equal(t, post, lookupHTTP(p, "api.test/v1", mustMethods(http.MethodPost)))
}

func TestEntry_MiddlewareOfAnotherKindIsRefused(t *testing.T) {
	p := testProxy(t)

	forged := option[TCP](func(s sealedOption) error {
		s.entry.mws = append(s.entry.mws, middleware{m: func(next HTTP) HTTP { return next }, kind: KindHTTP})
		return nil
	})

	_, err := p.Add[TCP]("smtp.test:465", noopStream, forged)
	require.ErrorIs(t, err, ErrInvalidConfig)

	_, err = p.Add[TCP]("smtp.test:465", noopStream, WithMiddleware(func(next TCP) TCP { return next }))
	require.NoError(t, err)
}

func TestEntry_RelaxedTrailingSlashOverridesTheProxyDefault(t *testing.T) {
	zero := Entry[HTTP]{}

	p := testProxy(t, WithRelaxedTrailingSlash[HTTP](true))
	p.MustAdd("api.test/v1/charges", noopHandler)
	p.MustAdd("api.test/v1/refunds", noopHandler, WithRelaxedTrailingSlash[HTTP](false))

	assert.NotEqual(t, zero, match(t, p, http.MethodGet, "https", "api.test:443", "/v1/charges/"))
	assert.Equal(t, zero, match(t, p, http.MethodGet, "https", "api.test:443", "/v1/refunds/"))

	q := testProxy(t)
	q.MustAdd("api.test/v1/charges", noopHandler)
	q.MustAdd("api.test/v1/refunds", noopHandler, WithRelaxedTrailingSlash[HTTP](true))

	assert.Equal(t, zero, match(t, q, http.MethodGet, "https", "api.test:443", "/v1/charges/"))
	assert.NotEqual(t, zero, match(t, q, http.MethodGet, "https", "api.test:443", "/v1/refunds/"))
}

func TestEntry_RelaxedTrailingSlashDefaultIsPerKind(t *testing.T) {
	ws := func(*WebSocketCtx) error { return nil }
	p := testProxy(t, WithRelaxedTrailingSlash[WebSocket](true))
	p.MustAdd("api.test/v1/", noopHandler)
	p.MustAdd[WebSocket]("api.test/chat/", ws)
	p.MustAdd[WebSocket]("api.test/feed/", ws, WithRelaxedTrailingSlash[WebSocket](false))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	e, _ := lookupOn(p, "api.test", "/v1", req, false)
	assert.Nil(t, e)
	e, _ = lookupOn(p, "api.test", "/chat", req, false)
	assert.Equal(t, "api.test/chat/", patternOf(e))
	e, _ = lookupOn(p, "api.test", "/feed", req, false)
	assert.Nil(t, e)
}

func TestEntry_NameLookup(t *testing.T) {
	p := testProxy(t)
	e := p.MustAdd("api.test/v1/charges", noopHandler, WithName[HTTP]("charges"), WithMethods[HTTP](http.MethodGet))

	assert.Equal(t, e, namedHTTP(p, "charges"))
	assert.Zero(t, namedHTTP(p, "nothing"))

	// A name identifies one entry across every kind.
	_, err := p.Add("api.test/v1/refunds", noopHandler, WithName[HTTP]("charges"), WithMethods[HTTP](http.MethodPost))
	var conflict *EntryNameConflictError
	require.ErrorAs(t, err, &conflict)

	// And a lookup under the wrong kind finds nothing, so the handler it returns is always
	// the one the caller asked for.
	_, ok := p.Named[TCP]("charges")
	assert.False(t, ok)
}

func TestEntry_HandlerIsWhatWasRegistered(t *testing.T) {
	p := testProxy(t)

	var seen []string
	mw := func(name string) Middleware[HTTP] {
		return func(next HTTP) HTTP {
			return func(c *HTTPCtx) (*http.Response, error) {
				seen = append(seen, name)
				return next(c)
			}
		}
	}

	e := p.MustAdd("api.test/v1", func(c *HTTPCtx) (*http.Response, error) {
		seen = append(seen, "handler")
		return Status(http.StatusOK), nil
	}, WithMiddleware(mw("entry")))

	_, err := e.Handler()(nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"handler"}, seen, "Handler must return the bare handler")

	seen = nil
	served, _ := e.e.serve.(HTTP)
	require.NotNil(t, served)
	_, err = served(nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"entry", "handler"}, seen)
}

func TestEntry_UpdateReplacesTheHandler(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1", func(c *HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, "first"), nil
	}, WithMethods[HTTP](http.MethodGet))

	updated, err := p.Update("api.test/v1", func(c *HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, "second"), nil
	}, WithMethods[HTTP](http.MethodGet))
	require.NoError(t, err)
	assert.Equal(t, 1, p.Len(), "an update must not add an entry")

	resp, err := updated.Handler()(nil)
	require.NoError(t, err)
	assert.Equal(t, "second", readAll(t, resp))

	_, err = p.Update("api.test/missing", noopHandler, WithMethods[HTTP](http.MethodGet))
	assert.ErrorIs(t, err, ErrEntryNotFound)
}

func TestEntry_Validation(t *testing.T) {
	p := testProxy(t)

	_, err := p.Add("api.test/v1", HTTP(nil))
	assert.ErrorIs(t, err, ErrInvalidEntry, "a nil handler must be refused")

	_, err = p.Add("api.test/v1", noopHandler, WithMethods[HTTP]("BAD METHOD"))
	assert.ErrorIs(t, err, ErrInvalidMatcher)

	_, err = p.Add("api.test/v1", noopHandler, WithMatchersPriority[HTTP](5))
	assert.ErrorIs(t, err, ErrInvalidEntry, "a priority with no matcher has nothing to order")

	_, err = p.Add("", noopHandler)
	assert.ErrorIs(t, err, ErrInvalidEntry)

	// A kind that routes each message needs a path, one that routes a whole connection
	// refuses one.
	_, err = p.Add("api.test", noopHandler)
	assert.Error(t, err)
	_, err = p.Add[TCP]("api.test/v1", noopStream)
	assert.Error(t, err)

	p.MustAdd("api.test/v1", noopHandler)
	_, err = p.Update("api.test/v1", HTTP(nil))
	assert.ErrorIs(t, err, ErrInvalidEntry)
	_, err = p.Update("api.test/v1", noopHandler, WithMatchersPriority[HTTP](5))
	assert.ErrorIs(t, err, ErrInvalidEntry)
	_, err = p.Update("api.test/v\x00", noopHandler)
	assert.ErrorAs(t, err, new(*PatternError))
	_, err = p.Update("api.test/users/j%6Fhn", noopHandler)
	assert.ErrorAs(t, err, new(*PatternError))
	assert.Equal(t, 1, p.Len())
}

func TestEntry_MaxMatchers(t *testing.T) {
	p := testProxy(t, WithMaxMatchers(3))
	a, err := MatchQuery("a", "b")
	require.NoError(t, err)
	b, err := MatchQuery("b", "c")
	require.NoError(t, err)
	c, err := MatchQuery("d", "e")
	require.NoError(t, err)

	_, err = p.Add("api.test/v1", noopHandler, WithRequestMatchers[HTTP](a, b, c))
	require.NoError(t, err)
	_, err = p.Add("api.test/v1", noopHandler, WithRequestMatchers[HTTP](a, b, c), WithMethods[HTTP](http.MethodGet))
	assert.ErrorIs(t, err, ErrTooManyMatchers, "a method counts as a matcher")
	_, err = p.Update("api.test/v1", noopHandler, WithRequestMatchers[HTTP](a, b), WithMethods[HTTP](http.MethodGet), WithScheme[HTTP]("https"))
	assert.ErrorIs(t, err, ErrTooManyMatchers)
	assert.Equal(t, 1, p.Len())
}

func TestEntry_DuplicateMatchers(t *testing.T) {
	q := must(MatchQuery("a", "b"))
	h := must(MatchHeader("c", "d"))
	p := testProxy(t)
	p.MustAdd("api.test/v1", noopHandler, WithRequestMatchers[HTTP](q))

	_, err := p.Add("api.test/v1", noopHandler, WithRequestMatchers[HTTP](q, h, q))
	assert.ErrorIs(t, err, ErrInvalidEntry)
	_, err = p.Add("api.test/v1", noopHandler, WithMethods[HTTP](http.MethodGet), WithMethods[HTTP](http.MethodGet))
	assert.ErrorIs(t, err, ErrInvalidEntry)
	_, err = p.Update("api.test/v1", noopHandler, WithRequestMatchers[HTTP](q, q))
	assert.ErrorIs(t, err, ErrInvalidEntry)
	_, err = p.Delete[HTTP]("api.test/v1", WithRequestMatchers[HTTP](q, q))
	assert.ErrorIs(t, err, ErrInvalidEntry)
	assert.Equal(t, 1, p.Len())
}

func TestEntry_MatcherEvaluatedOncePerLookup(t *testing.T) {
	var calls int
	p := testProxy(t)
	p.MustAdd("a.test/+{a}/x/+{b}", noopHandler, WithRequestMatchers[HTTP](countingMatcher{calls: &calls}))
	path := strings.Repeat("/a/x", 100)
	tree := p.getTree()
	c := tree.allocateContext()
	c.reset(nil, httptest.NewRequest(http.MethodGet, path, nil), "https", "a.test", "443")
	_, n := tree.lookup("a.test", path, c, false)
	assert.Nil(t, n)
	assert.Equal(t, 1, calls)
	_, n = tree.lookup("a.test", path, c, false)
	assert.Nil(t, n)
	assert.Equal(t, 2, calls)
}
