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

func TestEntry_Accessors(t *testing.T) {
	p := testProxy(t)

	type annotationKey struct{}
	e := p.MustAdd("api.stripe.com:8443/v1/{id}/refunds/*{rest}", noopHandler,
		WithName[HTTP]("refunds"), WithAnnotation[HTTP](annotationKey{}, "recorded"),
		WithTrailingSlash[HTTP](RelaxedSlash), WithScheme[HTTP]("https"), WithMethods[HTTP](http.MethodGet))

	assert.Equal(t, "api.stripe.com:8443/v1/{id}/refunds/*{rest}", e.Pattern())
	assert.Equal(t, "api.stripe.com", e.Host())
	assert.Equal(t, "8443", e.Port())
	assert.Equal(t, "/v1/{id}/refunds/*{rest}", e.Path())
	assert.Equal(t, "refunds", e.Name())
	assert.Equal(t, "recorded", e.Annotation(annotationKey{}))
	assert.Nil(t, e.Annotation("missing"))
	assert.Equal(t, RelaxedSlash, e.TrailingSlashOption())
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

// The handler signature is what selects the kind, so an entry knows its own without being
// told, and the handler comes back typed.
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

// Two entries on one path differing only by their method are two entries: the methods are
// matchers, and matchers are part of what identifies an entry.
func TestEntry_MethodsIdentifyAnEntry(t *testing.T) {
	p := testProxy(t)
	get := p.MustAdd("api.test/v1", noopHandler, WithMethods[HTTP](http.MethodGet))
	post := p.MustAdd("api.test/v1", noopHandler, WithMethods[HTTP](http.MethodPost))

	assert.NotEqual(t, get, post)
	assert.Equal(t, 2, p.Len())
	assert.Equal(t, get, lookupHTTP(p, "api.test/v1", mustMethods(http.MethodGet)))
	assert.Equal(t, post, lookupHTTP(p, "api.test/v1", mustMethods(http.MethodPost)))
}

// An entry setting overrides the proxy default, and it governs the lookup rather than the
// accessor alone.
func TestEntry_TrailingSlashOverridesTheProxyDefault(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("api.test/v1/charges", noopHandler)
	p.MustAdd("api.test/v1/refunds", noopHandler, WithTrailingSlash[HTTP](RelaxedSlash))

	assert.Equal(t, ExactSlash, lookupHTTP(p, "api.test/v1/charges").TrailingSlashOption())
	assert.Equal(t, RelaxedSlash, lookupHTTP(p, "api.test/v1/refunds").TrailingSlashOption())

	_, err := p.Add("api.test/v1/disputes", noopHandler, WithTrailingSlash[HTTP](TrailingSlashOption(99)))
	require.ErrorIs(t, err, ErrInvalidConfig)
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

// Middleware wraps the handler the proxy runs, and [Entry.Handler] returns what was
// registered, without it.
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
}
