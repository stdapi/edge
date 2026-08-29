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

func TestInterceptor_Accessors(t *testing.T) {
	p := testProxy(t)

	type annotationKey struct{}
	rte := p.MustAddInterceptor([]string{http.MethodGet}, "api.stripe.com/v1/{id}/refunds/*{rest}", noopHandler,
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

func TestInterceptor_NoMethodHasNoConstraint(t *testing.T) {
	p := testProxy(t)
	rte := p.MustAddInterceptor(nil, "api.test/v1", noopHandler)

	assert.Empty(t, slices.Collect(rte.Methods()))
	assert.Contains(t, rte.String(), "method:*")
}

func TestInterceptor_NameLookup(t *testing.T) {
	p := testProxy(t)
	rte := p.MustAddInterceptor([]string{http.MethodGet}, "api.test/v1/charges", noopHandler, WithName("charges"))

	assert.Same(t, rte, p.Name("charges"))
	assert.Nil(t, p.Name("nothing"))

	_, err := p.AddInterceptor([]string{http.MethodPost}, "api.test/v1/refunds", noopHandler, WithName("charges"))
	var conflict *InterceptorNameConflictError
	require.ErrorAs(t, err, &conflict, "a name identifies one route")
}

func TestInterceptor_HandleRunsWithoutMiddleware(t *testing.T) {
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

	rte, err := p.newInterceptor([]string{http.MethodGet}, "api.test/v1", func(c *Context) (*http.Response, error) {
		seen = append(seen, "handler")
		return Status(http.StatusOK), nil
	}, WithMiddleware(mw("route")))
	require.NoError(t, err)

	_, err = rte.Handle(nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"handler"}, seen, "Handle must skip the middleware")

	seen = nil
	_, err = rte.HandleMiddleware(nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"route", "handler"}, seen)
}

func TestInterceptor_UpdateReplacesTheHandler(t *testing.T) {
	p := testProxy(t)
	p.MustAddInterceptor([]string{http.MethodGet}, "api.test/v1", func(c *Context) (*http.Response, error) {
		return Text(http.StatusOK, "first"), nil
	})

	updated, err := p.UpdateInterceptor([]string{http.MethodGet}, "api.test/v1", func(c *Context) (*http.Response, error) {
		return Text(http.StatusOK, "second"), nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, p.InterceptorsLen(), "an update must not add a route")

	resp, err := updated.Handle(nil)
	require.NoError(t, err)
	assert.Equal(t, "second", readAll(t, resp))

	_, err = p.UpdateInterceptor([]string{http.MethodGet}, "api.test/missing", noopHandler)
	assert.ErrorIs(t, err, ErrInterceptorNotFound)
}

func TestInterceptor_NewInterceptorValidation(t *testing.T) {
	p := testProxy(t)

	_, err := p.newInterceptor([]string{http.MethodGet}, "api.test/v1", nil)
	assert.ErrorIs(t, err, ErrInvalidInterceptor, "a nil handler must be refused")

	_, err = p.newInterceptor([]string{"BAD METHOD"}, "api.test/v1", noopHandler)
	assert.ErrorIs(t, err, ErrInvalidInterceptor)

	_, err = p.newInterceptor(nil, "api.test/v1", noopHandler, WithMatchersPriority(5))
	assert.ErrorIs(t, err, ErrInvalidInterceptor, "a priority with no matcher has nothing to order")

	_, err = p.newInterceptor(nil, "", noopHandler)
	assert.ErrorIs(t, err, ErrInvalidInterceptor)
}

// TestMethodSentinel holds the two properties the method fast path depends on. Both are
// invisible at runtime and silent when broken: an interceptor would match without evaluating the
// matchers that narrow it.
func TestMethodSentinel(t *testing.T) {
	assert.False(t, validMethod(noFastMethod),
		"%q must never be registrable as a method", noFastMethod)
	assert.NotEmpty(t, noFastMethod,
		"an empty sentinel would equal the zero value of methodFast")
}

// TestMethodFastNeverMatchesAnEmptyMethod covers the shape of the bug the sentinels exist
// for: an interceptor that cannot use the fast path must not be claimed by a lookup carrying no
// method, whatever the caller passes.
func TestMethodFastNeverMatchesAnEmptyMethod(t *testing.T) {
	p := testProxy(t, WithRegexpParam(true))

	beta, err := MatchHeader("X-Channel", "beta")
	require.NoError(t, err)

	cases := []struct {
		name  string
		route *Interceptor
	}{
		{name: "many methods", route: p.MustAddInterceptor([]string{http.MethodGet, http.MethodPost}, "a.test/many", noopHandler)},
		{name: "with matchers", route: p.MustAddInterceptor([]string{http.MethodGet}, "a.test/matched", noopHandler, WithMatcher(beta))},
		{name: "no method", route: p.MustAddInterceptor(nil, "a.test/any", noopHandler)},
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
