// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func h2Client(addr string, trust *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
			TLSClientConfig:   &tls.Config{RootCAs: trust, MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		},
	}
}

func TestProxy_InterceptHTTP2(t *testing.T) {
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
	p.MustHandle([]string{http.MethodGet}, originHost(originURL)+"/h2", func(c *Context) (*http.Response, error) {
		clientProto = c.Protocol().String()
		if st := c.TLS(); st != nil {
			clientALPN = st.NegotiatedProtocol
		}
		return c.Forward()
	})

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

func TestProxy_ALPNMirrorsClientOffer(t *testing.T) {
	cases := []struct {
		name       string
		offer      []string
		negotiated string
	}{
		{name: "http/1.1 only", offer: []string{"http/1.1"}, negotiated: "http/1.1"},
		{name: "h2 preferred", offer: []string{"h2", "http/1.1"}, negotiated: "h2"},
		{name: "http/1.1 preferred", offer: []string{"http/1.1", "h2"}, negotiated: "http/1.1"},
		{name: "nothing in common", offer: []string{"spdy/3"}, negotiated: ""},
		{name: "no offer", offer: nil, negotiated: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, _ := GenerateCA()
			p, err := New(WithCA(ca), WithIntercept("example.test"))
			if err != nil {
				t.Fatalf("new proxy: %v", err)
			}

			var negotiated string
			p.MustHandle(nil, "example.test/", func(c *Context) (*http.Response, error) {
				negotiated = c.TLS().NegotiatedProtocol
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

func TestProxy_StreamsWithoutBuffering(t *testing.T) {
	release := make(chan struct{})
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		fmt.Fprint(w, "data: first\n\n")
		_ = rc.Flush()
		<-release
		fmt.Fprint(w, "data: second\n\n")
		_ = rc.Flush()
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	p.MustHandle([]string{http.MethodGet}, originHost(originURL)+"/events", func(c *Context) (*http.Response, error) {
		return c.Forward()
	})

	addr := startProxy(t, p)
	client := proxyClient(addr, ca.CertPool())

	resp, err := client.Get(origin.URL + "/events")
	if err != nil {
		t.Fatalf("get events: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read first event: %v", err)
	}
	// Reaching this before the origin has written the second event proves the proxy is not
	// waiting for the body to end before relaying it.
	if strings.TrimSpace(line) != "data: first" {
		t.Fatalf("first event = %q", line)
	}

	close(release)
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "data: second") {
		t.Fatalf("second event missing from %q", rest)
	}
}

func TestProxy_ForwardsTrailers(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Checksum")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "payload")
		w.Header().Set("X-Checksum", "deadbeef")
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithIntercept(originHost(originURL)), WithTransport(tr))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	addr := startProxy(t, p)
	client := proxyClient(addr, ca.CertPool())

	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "payload" {
		t.Fatalf("body = %q", body)
	}
	if got := resp.Trailer.Get("X-Checksum"); got != "deadbeef" {
		t.Fatalf("trailer X-Checksum = %q, want deadbeef", got)
	}
}
