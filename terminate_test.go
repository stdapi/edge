// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestTerminatedTarget_PortIsCanonical(t *testing.T) {
	sess := newSession(nil, t.Context(), nil, Target{Scheme: "https", Host: "example.test", Port: "443"}, KindHTTP, HTTP11)
	target, ok := terminatedTarget(&http.Request{Host: "example.test:08443"}, sess)
	require.True(t, ok)
	assert.Equal(t, "8443", target.Port)

	_, ok = terminatedTarget(&http.Request{Host: "example.test:x"}, sess)
	assert.False(t, ok)
}

func TestTerminate_InterceptHTTP2(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin proto %s", r.Proto)
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	var clientProto, clientALPN string
	p.MustAdd(originHost(originURL)+"/h2", func(c *HTTPCtx) (*http.Response, error) {
		clientProto = c.Protocol().String()
		if st := c.Request().TLS; st != nil {
			clientALPN = st.NegotiatedProtocol
		}
		return c.Forward()
	}, WithMethods[HTTP](http.MethodGet))

	addr := startProxy(t, p)
	client := h2Client(addr, ca.CertPool())

	resp, err := client.Get(origin.URL + "/h2")
	if err != nil {
		t.Fatalf("get through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "origin proto HTTP/2.0" {
		t.Fatalf("body = %q, want origin proto HTTP/2.0", body)
	}
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("client saw %s, want HTTP/2.0", resp.Proto)
	}
	if clientProto != "HTTP/2.0" {
		t.Fatalf("handler saw protocol %q, want HTTP/2.0", clientProto)
	}
	if clientALPN != "h2" {
		t.Fatalf("negotiated ALPN = %q, want h2", clientALPN)
	}
}

func TestTerminate_ALPNMirrorsClientOffer(t *testing.T) {
	cases := []struct {
		name       string
		offer      []string
		negotiated string
	}{
		{name: "http/1.1 only", offer: []string{"http/1.1"}, negotiated: "http/1.1"},
		{name: "h2 preferred", offer: []string{"h2", "http/1.1"}, negotiated: "h2"},
		{name: "http/1.1 preferred", offer: []string{"http/1.1", "h2"}, negotiated: "http/1.1"},
		// A client offering only http/1.1 among what it wants still lands on HTTP.
		{name: "http/1.1 behind another", offer: []string{"spdy/3", "http/1.1"}, negotiated: "http/1.1"},
		{name: "no offer", offer: nil, negotiated: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, _ := GenerateCA()
			p, err := New(WithCA(ca))
			if err != nil {
				t.Fatalf("new proxy: %v", err)
			}

			var negotiated string
			p.MustAdd("example.test/", func(c *HTTPCtx) (*http.Response, error) {
				negotiated = c.Request().TLS.NegotiatedProtocol
				return Text(http.StatusOK, "ok"), nil
			})

			addr := startProxy(t, p)

			// The proxy must answer with what the client offered, never with what it would
			// have preferred: an app that speaks only HTTP/1.1 must not end up on h2.
			tr := &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
				TLSClientConfig: &tls.Config{
					RootCAs:    ca.CertPool(),
					MinVersion: tls.VersionTLS12,
					NextProtos: tc.offer,
				},
				TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
			}
			if slices.Contains(tc.offer, "h2") {
				if err := http2.ConfigureTransport(tr); err != nil {
					t.Fatalf("configure h2: %v", err)
				}
				tr.TLSClientConfig.NextProtos = tc.offer
			}
			client := &http.Client{Timeout: 10 * time.Second, Transport: tr}

			resp, err := client.Get("https://example.test/")
			if err != nil {
				t.Fatalf("get through proxy: %v", err)
			}
			_ = resp.Body.Close()

			if negotiated != tc.negotiated {
				t.Fatalf("negotiated ALPN = %q, want %q", negotiated, tc.negotiated)
			}
		})
	}
}
