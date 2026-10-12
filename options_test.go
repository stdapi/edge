// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOptions_Defaults(t *testing.T) {
	p, err := New()
	require.NoError(t, err)

	cfg := p.cfg
	assert.Nil(t, cfg.ca)
	assert.Equal(t, 255, cfg.maxParams)
	assert.Equal(t, 255, cfg.maxParamKeyBytes)
	assert.Equal(t, 255, cfg.maxMatchers)
	assert.Equal(t, ExactSlash, cfg.handleSlash)
	assert.False(t, cfg.allowRegexp, "a regexp runs on every candidate segment, so it is opt in")
	assert.NotNil(t, cfg.logger)
	assert.NotNil(t, cfg.transport)
}

func TestOptions_Rejected(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)

	cases := []struct {
		name string
		opt  ProxyOption
	}{
		{"nil CA", WithCA(nil)},
		{"nil error handler", WithErrorHandler(nil)},
		{"nil middleware", WithMiddleware[HTTP](nil)},
		{"nil transport", WithTransport(nil)},
		{"nil logger", WithLogger(nil)},
		{"zero max params", WithMaxPatternParams(0)},
		{"zero max param key bytes", WithMaxPatternParamKeyBytes(0)},
		{"negative read header timeout", WithReadHeaderTimeout(-time.Second)},
		{"negative idle timeout", WithIdleTimeout(-time.Second)},
		{"negative sniff timeout", WithSniffTimeout(-time.Second)},
		{"zero max header bytes", WithMaxHeaderBytes(0)},
		{"unknown trailing slash", WithDefaultTrailingSlash(TrailingSlashOption(99))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(WithCA(ca), tc.opt)
			require.Error(t, err)
			assert.True(t,
				errors.Is(err, ErrInvalidConfig) ||
					errors.Is(err, ErrInvalidMatcher) ||
					errors.Is(err, ErrNoCertificateAuthority),
				"want a config error, got %v", err)
		})
	}
}

func TestOptions_Applied(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)

	p, err := New(
		WithCA(ca),
		WithMaxPatternParams(4),
		WithMaxPatternParamKeyBytes(8),
		WithMaxMatchers(2),
		WithDefaultTrailingSlash(RelaxedSlash),
		WithRegexpParam(true),
		WithLogger(slog.New(slog.DiscardHandler)),
	)
	require.NoError(t, err)

	cfg := p.cfg
	assert.Same(t, ca, cfg.ca)
	assert.Equal(t, 4, cfg.maxParams)
	assert.Equal(t, 8, cfg.maxParamKeyBytes)
	assert.Equal(t, 2, cfg.maxMatchers)
	assert.Equal(t, RelaxedSlash, cfg.handleSlash)
	assert.True(t, cfg.allowRegexp)
}

func TestOptions_LimitsAreEnforced(t *testing.T) {
	ca, _ := GenerateCA()

	t.Run("max params", func(t *testing.T) {
		p, err := New(WithCA(ca), WithMaxPatternParams(2))
		require.NoError(t, err)

		_, err = p.Add("api.test/{a}/{b}", noopHandler, WithMethods[HTTP](http.MethodGet))
		require.NoError(t, err)

		_, err = p.Add("api.test/{a}/{b}/{c}", noopHandler, WithMethods[HTTP](http.MethodGet))
		var pe *PatternError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Error(), "too many parameters")
	})

	t.Run("max param key bytes", func(t *testing.T) {
		p, err := New(WithCA(ca), WithMaxPatternParamKeyBytes(4))
		require.NoError(t, err)

		_, err = p.Add("api.test/{abcde}", noopHandler, WithMethods[HTTP](http.MethodGet))
		var pe *PatternError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Error(), "key too large")
	})

	t.Run("max matchers", func(t *testing.T) {
		p, err := New(WithCA(ca), WithMaxMatchers(1))
		require.NoError(t, err)

		header, err := MatchHeader("X-Channel", "beta")
		require.NoError(t, err)

		_, err = p.Add("api.test/v1", noopHandler, WithScheme[HTTP]("https"), WithRequestMatchers[HTTP](header), WithMethods[HTTP](http.MethodGet))
		require.ErrorIs(t, err, ErrTooManyMatchers)
	})

	t.Run("regexp is off by default", func(t *testing.T) {
		p, err := New(WithCA(ca))
		require.NoError(t, err)

		_, err = p.Add("api.test/{id:[0-9]+}", noopHandler, WithMethods[HTTP](http.MethodGet))
		var pe *PatternError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Error(), "feature not enabled")
	})
}

func TestOptions_RegexpParam(t *testing.T) {
	p := testProxy(t, WithRegexpParam(true))
	p.MustAdd("api.test/v1/{id:ch_[0-9]+}", noopHandler, WithMethods[HTTP](http.MethodGet))

	assert.NotZero(t, match(t, p, http.MethodGet, "https", "api.test:443", "/v1/ch_123"))
	assert.Zero(t, match(t, p, http.MethodGet, "https", "api.test:443", "/v1/re_123"))
}

func TestPatternError_PointsAtTheOffendingSegment(t *testing.T) {
	p := testProxy(t)

	_, err := p.Add("api.test/v1/{}", noopHandler, WithMethods[HTTP](http.MethodGet))
	var pe *PatternError
	require.ErrorAs(t, err, &pe)

	assert.Equal(t, "api.test/v1/{}", pe.Pattern)
	assert.Equal(t, "path", pe.Type)
	assert.Equal(t, "parameter", pe.Reason)

	msg := pe.Error()
	assert.Contains(t, msg, "missing name")
	assert.Contains(t, msg, "api.test/v1/{}")
	assert.Contains(t, msg, "^", "the message must point at the offending segment")

	// The caret sits under the segment it names.
	lines := strings.Split(msg, "\n")
	require.Len(t, lines, 3)
	assert.Equal(t, strings.Index(lines[2], "^")-6, pe.Start)
}

func TestSession_Accessors(t *testing.T) {
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4242}
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}

	sess := newSession(nil, t.Context(), nil, Target{Scheme: "https", Host: "api.test", Port: "443"}, KindHTTP, HTTP2)
	sess.remoteAddr = remote
	sess.localAddr = local

	assert.Positive(t, sess.ID())
	assert.Equal(t, "192.0.2.10:4242", sess.RemoteAddr().String())
	assert.Equal(t, "127.0.0.1:8080", sess.LocalAddr().String())
	assert.Equal(t, "https://api.test:443", sess.Target().String())
	assert.Equal(t, HTTP2, sess.Protocol())
	assert.Nil(t, sess.TLS())
	assert.Nil(t, sess.ClientHello())
	assert.False(t, sess.Transparent())
	assert.False(t, sess.Upstream().IsValid())
	assert.WithinDuration(t, time.Now(), sess.CreatedAt(), time.Minute)
	assert.NotNil(t, sess.Context())
}

func TestProtocol_String(t *testing.T) {
	assert.Equal(t, "HTTP/1.1", HTTP11.String())
	assert.Equal(t, "HTTP/2.0", HTTP2.String())
	assert.Equal(t, "HTTP/3.0", HTTP3.String())
	assert.Equal(t, "unknown", Protocol(0).String())

	assert.Equal(t, "http/1.1", HTTP11.ALPN())
	assert.Equal(t, "h2", HTTP2.ALPN())
	assert.Equal(t, "h3", HTTP3.ALPN())
	assert.Empty(t, Protocol(0).ALPN())
}

func TestTarget_String(t *testing.T) {
	assert.Equal(t, "https://api.test:443", Target{Scheme: "https", Host: "api.test", Port: "443"}.String())
	assert.Equal(t, "api.test:443", Target{Host: "api.test", Port: "443"}.String())
	assert.Equal(t, "[::1]:8080", Target{Host: "::1", Port: "8080"}.Authority())
}

func TestKind_String(t *testing.T) {
	assert.Equal(t, "HTTP", KindHTTP.String())
	assert.Equal(t, "gRPC", KindGRPC.String())
	assert.Equal(t, "WebSocket", KindWebSocket.String())
	assert.Equal(t, "TCP", KindTCP.String())
	assert.Equal(t, "QUIC", KindQUIC.String())
	assert.Equal(t, "UDP", KindUDP.String())
	assert.Equal(t, "unknown", Kind(0).String())
}

func TestOptions_ProxyMiddlewareTakesEveryKind(t *testing.T) {
	var seen []string
	tagHTTP := func(next HTTP) HTTP {
		return func(c *HTTPCtx) (*http.Response, error) {
			seen = append(seen, "http")
			return next(c)
		}
	}
	tagTCP := func(next TCP) TCP {
		return func(c *TCPCtx) error {
			seen = append(seen, "tcp")
			return next(c)
		}
	}

	p := testProxy(t, WithMiddleware(tagHTTP), WithMiddleware(tagTCP))
	e := p.MustAdd("api.test/v1", func(c *HTTPCtx) (*http.Response, error) {
		seen = append(seen, "handler")
		return Status(http.StatusOK), nil
	})

	served, _ := e.e.serve.(HTTP)
	require.NotNil(t, served)
	_, err := served(nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"http", "handler"}, seen)
}

func TestOptions_MiddlewareIsComposable(t *testing.T) {
	var seen []string
	tag := func(name string) Middleware[HTTP] {
		return func(next HTTP) HTTP {
			return func(c *HTTPCtx) (*http.Response, error) {
				seen = append(seen, name)
				return next(c)
			}
		}
	}

	p := testProxy(t, WithMiddleware(tag("proxy")))
	ic := p.MustAdd("api.test/v1", func(c *HTTPCtx) (*http.Response, error) {
		seen = append(seen, "handler")
		return Status(http.StatusOK), nil
	}, WithMiddleware(tag("interceptor")))

	served, _ := ic.e.serve.(HTTP)
	require.NotNil(t, served)
	_, err := served(nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"proxy", "interceptor", "handler"}, seen,
		"the proxy-wide middleware wraps the entry's")
}

func TestOptions_NoEntryRejected(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)

	_, err = New(WithCA(ca), WithNoEntry[HTTP](nil))
	require.ErrorIs(t, err, ErrInvalidConfig)

	for _, opt := range []ProxyOption{
		WithNoEntry(forwardHandler),
		WithNoEntry(func(c *GRPCCtx) error { return c.Forward() }),
		WithNoEntry(func(c *WebSocketCtx) error { return c.Relay() }),
		WithNoEntry(relayQUIC),
	} {
		_, err = New(opt)
		require.ErrorIs(t, err, ErrNoCertificateAuthority)
	}
	_, err = New(WithNoEntry(relayStream), WithNoEntry(forwardDatagram))
	require.NoError(t, err)
}

func TestOptions_NoEntryTakesTheProxyMiddlewareOnly(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	var pattern, entryMW, noEntryMW, params string
	noEntry := func(c *HTTPCtx) (*http.Response, error) {
		pattern = c.Pattern()
		for range c.Params() {
			params += "x"
		}
		return Status(http.StatusTeapot), nil
	}
	mw := func(next HTTP) HTTP {
		return func(c *HTTPCtx) (*http.Response, error) {
			noEntryMW += "g"
			return next(c)
		}
	}
	p := testProxy(t, WithNoEntry(noEntry), WithMiddleware(mw))
	p.cfg.transport.RootCAs = originPool(t, origin)
	host := originHost(originURL)
	p.MustAdd("+{sub}.corp.test/v1", forwardHandler)
	p.MustAdd(host+"/v1", forwardHandler, WithMiddleware(func(next HTTP) HTTP {
		return func(c *HTTPCtx) (*http.Response, error) {
			entryMW += "e"
			return next(c)
		}
	}))

	client := proxyClient(startProxy(t, p), p.cfg.ca.CertPool())
	get := func(target string) int {
		resp, err := client.Get(target)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	assert.Equal(t, http.StatusOK, get(origin.URL+"/v1"))
	assert.Equal(t, "e", entryMW)
	assert.Equal(t, "g", noEntryMW)

	assert.Equal(t, http.StatusTeapot, get(origin.URL+"/v2"))
	assert.Equal(t, http.StatusTeapot, get("https://a.corp.test/v2"))
	assert.Equal(t, "e", entryMW, "the middleware of an entry does not apply")
	assert.Equal(t, "ggg", noEntryMW, "the proxy-wide middleware applies")
	assert.Empty(t, pattern)
	assert.Empty(t, params)
}
