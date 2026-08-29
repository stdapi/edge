// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net/http"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoute_Accessors(t *testing.T) {
	p := testProxy(t)

	type annotationKey struct{}
	rte := p.MustHandle([]string{http.MethodGet}, "api.stripe.com/v1/{id}/refunds/*{rest}", noopHandler,
		WithName("refunds"),
		WithAnnotation(annotationKey{}, "recorded"),
		WithTrailingSlash(RelaxedSlash),
		WithScheme("https"),
		WithPort("8443"),
	)

	assert.Equal(t, "api.stripe.com/v1/{id}/refunds/*{rest}", rte.Pattern())
	assert.Equal(t, "api.stripe.com", rte.Hostname())
	assert.Equal(t, "/v1/{id}/refunds/*{rest}", rte.Path())
	assert.Equal(t, "refunds", rte.Name())
	assert.Equal(t, "recorded", rte.Annotation(annotationKey{}))
	assert.Nil(t, rte.Annotation("missing"))
	assert.Equal(t, RelaxedSlash, rte.TrailingSlashOption())

	assert.Equal(t, []string{http.MethodGet}, slices.Collect(rte.Methods()))
	assert.Equal(t, 2, rte.ParamsLen())
	assert.Equal(t, []string{"id", "rest"}, slices.Collect(rte.Params()))

	assert.Equal(t, 2, rte.MatchersLen())
	assert.Equal(t, uint(2), rte.MatchersPriority())

	assert.Contains(t, rte.String(), "method:GET")
	assert.Contains(t, rte.String(), "name:refunds")
	assert.Contains(t, rte.String(), "scheme=https")
	assert.Contains(t, rte.String(), "port=8443")
}

func TestRoute_NoMethodHasNoConstraint(t *testing.T) {
	p := testProxy(t)
	rte := p.MustHandle(nil, "api.test/v1", noopHandler)

	assert.Empty(t, slices.Collect(rte.Methods()))
	assert.Contains(t, rte.String(), "method:*")
}

func TestRoute_NameLookup(t *testing.T) {
	p := testProxy(t)
	rte := p.MustHandle([]string{http.MethodGet}, "api.test/v1/charges", noopHandler, WithName("charges"))

	assert.Same(t, rte, p.Name("charges"))
	assert.Nil(t, p.Name("nothing"))

	_, err := p.Handle([]string{http.MethodPost}, "api.test/v1/refunds", noopHandler, WithName("charges"))
	var conflict *RouteNameConflictError
	require.ErrorAs(t, err, &conflict, "a name identifies one route")
}

func TestRoute_HandleRunsWithoutMiddleware(t *testing.T) {
	p := testProxy(t)

	var seen []string
	mw := func(name string) MiddlewareFunc {
		return func(next HandlerFunc) HandlerFunc {
			return func(c *Context) (*http.Response, error) {
				seen = append(seen, name)
				return next(c)
			}
		}
	}

	rte, err := p.NewRoute([]string{http.MethodGet}, "api.test/v1", func(c *Context) (*http.Response, error) {
		seen = append(seen, "handler")
		return Status(http.StatusOK), nil
	}, WithRouteMiddleware(mw("route")))
	require.NoError(t, err)

	_, err = rte.Handle(nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"handler"}, seen, "Handle must skip the middleware")

	seen = nil
	_, err = rte.HandleMiddleware(nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"route", "handler"}, seen)
}

func TestRoute_UpdateReplacesTheHandler(t *testing.T) {
	p := testProxy(t)
	p.MustHandle([]string{http.MethodGet}, "api.test/v1", func(c *Context) (*http.Response, error) {
		return Text(http.StatusOK, "first"), nil
	})

	updated, err := p.Update([]string{http.MethodGet}, "api.test/v1", func(c *Context) (*http.Response, error) {
		return Text(http.StatusOK, "second"), nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, p.Len(), "an update must not add a route")

	resp, err := updated.Handle(nil)
	require.NoError(t, err)
	assert.Equal(t, "second", readAll(t, resp))

	_, err = p.Update([]string{http.MethodGet}, "api.test/missing", noopHandler)
	assert.ErrorIs(t, err, ErrRouteNotFound)
}

func TestRoute_NewRouteValidation(t *testing.T) {
	p := testProxy(t)

	_, err := p.NewRoute([]string{http.MethodGet}, "api.test/v1", nil)
	assert.ErrorIs(t, err, ErrInvalidRoute, "a nil handler must be refused")

	_, err = p.NewRoute([]string{"BAD METHOD"}, "api.test/v1", noopHandler)
	assert.ErrorIs(t, err, ErrInvalidRoute)

	_, err = p.NewRoute(nil, "api.test/v1", noopHandler, WithMatchersPriority(5))
	assert.ErrorIs(t, err, ErrInvalidRoute, "a priority with no matcher has nothing to order")

	_, err = p.NewRoute(nil, "", noopHandler)
	assert.ErrorIs(t, err, ErrInvalidRoute)
}

// TestMethodSentinels holds the two properties the method fast path depends on. Both are
// invisible at runtime and silent when broken: a route would match without evaluating the
// matchers that narrow it.
func TestMethodSentinels(t *testing.T) {
	assert.NotEqual(t, noFastMethod, ruleLookupMethod,
		"the fast path compares them, so equal sentinels would match every rule outright")

	for _, s := range []string{noFastMethod, ruleLookupMethod} {
		assert.False(t, validMethod(s), "%q must never be registrable as a method", s)
		assert.NotEmpty(t, s, "an empty sentinel would equal the zero value of methodFast")
	}
}

// TestMethodFastNeverMatchesAnEmptyMethod covers the shape of the bug the sentinels exist
// for: a route that cannot use the fast path must not be claimed by a lookup carrying no
// method, whatever the caller passes.
func TestMethodFastNeverMatchesAnEmptyMethod(t *testing.T) {
	p := testProxy(t, WithRegexpParam(true))

	beta, err := MatchHeader("X-Channel", "beta")
	require.NoError(t, err)

	cases := []struct {
		name  string
		route *Route
	}{
		{name: "many methods", route: p.MustHandle([]string{http.MethodGet, http.MethodPost}, "a.test/many", noopHandler)},
		{name: "with matchers", route: p.MustHandle([]string{http.MethodGet}, "a.test/matched", noopHandler, WithMatcher(beta))},
		{name: "no method", route: p.MustHandle(nil, "a.test/any", noopHandler)},
	}

	c := &Context{params: new([]string)}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotEmpty(t, tc.route.methodFast, "methodFast must never be left at its zero value")
			assert.False(t, tc.route.match("", c) && len(tc.route.matchers) > 0,
				"an empty method must not short circuit the matchers")
		})
	}
}
