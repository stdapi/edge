// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOptions_Defaults(t *testing.T) {
	p, err := New()
	require.NoError(t, err)

	cfg := p.Config()
	assert.Nil(t, cfg.CA())
	assert.Equal(t, Tunnel, cfg.DefaultAction(), "traffic the proxy was not asked about stays opaque to it")
	assert.Equal(t, 255, cfg.MaxRouteParams())
	assert.Equal(t, 255, cfg.MaxRouteParamKeyBytes())
	assert.Equal(t, 255, cfg.MaxRouteMatchers())
	assert.Equal(t, ExactSlash, cfg.TrailingSlash())
	assert.False(t, cfg.AllowRegexpParam(), "a regexp runs on every candidate segment, so it is opt in")
	assert.NotNil(t, cfg.Logger())
	assert.NotNil(t, cfg.Transport())
}

func TestOptions_Rejected(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)

	cases := []struct {
		name string
		opt  Option
	}{
		{"nil CA", WithCA(nil)},
		{"nil no route handler", WithNoRouteHandler(nil)},
		{"nil error handler", WithErrorHandler(nil)},
		{"nil middleware", WithMiddleware(nil)},
		{"nil transport", WithTransport(nil)},
		{"nil logger", WithLogger(nil)},
		{"nil original destination", WithOriginalDestination(nil)},
		{"nil packet original destination", WithPacketOriginalDestination(nil)},
		{"zero max params", WithMaxRouteParams(0)},
		{"zero max param key bytes", WithMaxRouteParamKeyBytes(0)},
		{"negative read header timeout", WithReadHeaderTimeout(-time.Second)},
		{"negative idle timeout", WithIdleTimeout(-time.Second)},
		{"negative tunnel idle timeout", WithTunnelIdleTimeout(-time.Second)},
		{"zero max header bytes", WithMaxHeaderBytes(0)},
		{"unknown default action", WithDefaultAction(Action(99))},
		{"unknown trailing slash", WithTrailingSlash(TrailingSlashOption(99))},
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
		WithMaxRouteParams(4),
		WithMaxRouteParamKeyBytes(8),
		WithMaxRouteMatchers(2),
		WithTrailingSlash(RelaxedSlash),
		WithRegexpParam(true),
		WithDefaultAction(Intercept),
		WithLogger(slog.New(slog.DiscardHandler)),
		WithOriginalDestination(func(net.Conn) (netip.AddrPort, error) { return netip.AddrPort{}, nil }),
		WithPacketOriginalDestination(func(net.Addr, net.Addr) (netip.AddrPort, error) { return netip.AddrPort{}, nil }),
	)
	require.NoError(t, err)

	cfg := p.Config()
	assert.Same(t, ca, cfg.CA())
	assert.Equal(t, 4, cfg.MaxRouteParams())
	assert.Equal(t, 8, cfg.MaxRouteParamKeyBytes())
	assert.Equal(t, 2, cfg.MaxRouteMatchers())
	assert.Equal(t, RelaxedSlash, cfg.TrailingSlash())
	assert.True(t, cfg.AllowRegexpParam())
	assert.Equal(t, Intercept, cfg.DefaultAction())
}

func TestOptions_LimitsAreEnforced(t *testing.T) {
	ca, _ := GenerateCA()

	t.Run("max params", func(t *testing.T) {
		p, err := New(WithCA(ca), WithMaxRouteParams(2))
		require.NoError(t, err)

		_, err = p.Handle([]string{http.MethodGet}, "api.test/{a}/{b}", noopHandler)
		require.NoError(t, err)

		_, err = p.Handle([]string{http.MethodGet}, "api.test/{a}/{b}/{c}", noopHandler)
		var pe *PatternError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Error(), "too many parameters")
	})

	t.Run("max param key bytes", func(t *testing.T) {
		p, err := New(WithCA(ca), WithMaxRouteParamKeyBytes(4))
		require.NoError(t, err)

		_, err = p.Handle([]string{http.MethodGet}, "api.test/{abcde}", noopHandler)
		var pe *PatternError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Error(), "key too large")
	})

	t.Run("max matchers", func(t *testing.T) {
		p, err := New(WithCA(ca), WithMaxRouteMatchers(1))
		require.NoError(t, err)

		_, err = p.Handle([]string{http.MethodGet}, "api.test/v1", noopHandler,
			WithScheme("https"), WithPort("8443"))
		require.ErrorIs(t, err, ErrTooManyMatchers)
	})

	t.Run("regexp is off by default", func(t *testing.T) {
		p, err := New(WithCA(ca))
		require.NoError(t, err)

		_, err = p.Handle([]string{http.MethodGet}, "api.test/{id:[0-9]+}", noopHandler)
		var pe *PatternError
		require.ErrorAs(t, err, &pe)
		assert.Contains(t, pe.Error(), "feature not enabled")
	})
}

func TestOptions_RegexpParam(t *testing.T) {
	p := testProxy(t, WithRegexpParam(true))
	p.MustHandle([]string{http.MethodGet}, "api.test/v1/{id:ch_[0-9]+}", noopHandler)

	assert.NotNil(t, match(t, p, http.MethodGet, "https", "api.test:443", "/v1/ch_123"))
	assert.Nil(t, match(t, p, http.MethodGet, "https", "api.test:443", "/v1/re_123"))
}

func TestPatternError_PointsAtTheOffendingSegment(t *testing.T) {
	p := testProxy(t)

	_, err := p.Handle([]string{http.MethodGet}, "api.test/v1/{}", noopHandler)
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

	sess := newSession(t.Context(), nil, Target{Scheme: "https", Host: "api.test", Port: "443"}, Intercept, HTTP2)
	sess.remoteAddr = remote
	sess.localAddr = local

	assert.Positive(t, sess.ID())
	assert.Same(t, remote, sess.RemoteAddr())
	assert.Same(t, local, sess.LocalAddr())
	assert.Equal(t, "192.0.2.10", sess.RemoteIP().String())
	assert.Equal(t, "https://api.test:443", sess.Target().String())
	assert.Equal(t, Intercept, sess.Action())
	assert.Equal(t, HTTP2, sess.Protocol())
	assert.Nil(t, sess.TLS())
	assert.Nil(t, sess.ClientHello())
	assert.False(t, sess.Transparent())
	assert.False(t, sess.Upstream().IsValid())
	assert.WithinDuration(t, time.Now(), sess.CreatedAt(), time.Minute)
	assert.NotNil(t, sess.Context())

	assert.Nil(t, sess.Value("k"))
	sess.SetValue("k", "v")
	assert.Equal(t, "v", sess.Value("k"))
	sess.SetValue("k2", 2)
	assert.Equal(t, "v", sess.Value("k"), "an existing value must survive a later write")
	assert.Equal(t, 2, sess.Value("k2"))
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
	assert.True(t, Target{Scheme: "https", Host: "a.test", Port: "443"}.IsDefaultPort())
	assert.True(t, Target{Scheme: "http", Host: "a.test", Port: "80"}.IsDefaultPort())
	assert.False(t, Target{Scheme: "https", Host: "a.test", Port: "8443"}.IsDefaultPort())
}

func TestAction_String(t *testing.T) {
	assert.Equal(t, "tunnel", Tunnel.String())
	assert.Equal(t, "intercept", Intercept.String())
	assert.Equal(t, "reject", Reject.String())
	assert.Equal(t, "unknown", Action(0).String())
}
