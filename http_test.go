// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/iotest"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestHTTP_ShortCircuit(t *testing.T) {
	var originHits int
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits++
		fmt.Fprint(w, "should not be reached")
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
	p.MustAdd(originHost(originURL)+"/v1/charges", func(c *HTTPCtx) (*http.Response, error) {
		if c.Request().Header.Get("Idempotency-Key") == "" {
			return Text(http.StatusBadRequest, "missing idempotency key"), nil
		}
		return c.Forward()
	}, WithMethods[HTTP](http.MethodPost))

	addr := startProxy(t, p)
	client := proxyClient(addr, ca.CertPool())

	resp, err := client.Post(origin.URL+"/v1/charges", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "missing idempotency key" {
		t.Fatalf("body = %q", body)
	}
	if originHits != 0 {
		t.Fatalf("origin was reached %d times, want 0", originHits)
	}
}

func TestHTTP_PlainHTTPAbsoluteTarget(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "plain %s", r.URL.Path)
	}))
	defer origin.Close()

	originURL, _ := url.Parse(origin.URL)
	ca, _ := GenerateCA()

	p, err := New(WithCA(ca))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	p.MustAdd(originHost(originURL)+"/hello", func(c *HTTPCtx) (*http.Response, error) {
		if c.Scheme() != "http" {
			return nil, fmt.Errorf("scheme = %q, want http", c.Scheme())
		}
		resp, err := c.Forward()
		if err != nil {
			return nil, err
		}
		body, _ := ReadBody(resp, 0)
		return Rewrite(resp, []byte(strings.ToUpper(string(body)))), nil
	}, WithMethods[HTTP](http.MethodGet))

	addr := startProxy(t, p)
	client := proxyClient(addr, nil)

	resp, err := client.Get(origin.URL + "/hello")
	if err != nil {
		t.Fatalf("get through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "PLAIN /HELLO" {
		t.Fatalf("body = %q, want PLAIN /HELLO", body)
	}
}

func TestHTTP_StreamsWithoutBuffering(t *testing.T) {
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
	p.MustAdd(originHost(originURL)+"/events", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	}, WithMethods[HTTP](http.MethodGet))

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

func TestHTTP_ForwardsTrailers(t *testing.T) {
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

	p, err := New(WithCA(ca), WithTransport(tr))
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	p.MustAdd(originHost(originURL)+"/*{any}", forwardHandler)

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

func TestHTTP_EmptyRequestAnnouncingTrailersEndsUpstream(t *testing.T) {
	o := prefaceOrigin(t, func(_ *rawOrigin, _ *wire, fr *http2.Framer) {
		if _, err := fr.ReadFrame(); err != nil || fr.WriteSettings() != nil || fr.WriteSettingsAck() != nil {
			return
		}
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if end, ok := f.(interface{ StreamEnded() bool }); ok && end.StreamEnded() && writeOK(fr, f.Header().StreamID) != nil {
				return
			}
		}
	})
	p := testProxy(t)
	p.MustAdd("origin.test/*{any}", forwardHandler)
	c := dialDeclared(t, viaRedirected, p, netip.MustParseAddrPort(o.addr))
	_, err := io.WriteString(c, http2.ClientPreface)
	require.NoError(t, err)
	h := newH2Wire(c)
	require.NoError(t, h.fr.WriteSettings())
	h.headers(t, 1, false, hf(":method", "POST"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"),
		hf("content-length", "0"), hf("trailer", "x-checksum"))
	h.headers(t, 1, true, hf("x-checksum", "deadbeef"))
	assert.Equal(t, "ok", string(h.reply(t, 1).body))
}

func TestHTTP_ContentPastAZeroLengthIsMalformed(t *testing.T) {
	for _, version := range []string{viaH2, viaH3} {
		t.Run(version, func(t *testing.T) {
			errs := make(chan error, 1)
			p := testProxy(t)
			p.MustAdd("origin.test/*{any}", func(c *HTTPCtx) (*http.Response, error) {
				resp, err := c.Forward()
				errs <- err
				return resp, err
			})
			if version == viaH3 {
				(&proxyBench{p: p}).dialH3Front(t).roundTrip(t, h3Request("POST", "origin.test", "/", hf("content-length", "0")), h3Data("abcd"))
			} else {
				h := dialH2Wire(t, viaH2C, p, "origin.test")
				h.headers(t, 1, false, hf(":method", "POST"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"),
					hf("content-length", "0"))
				require.NoError(t, h.fr.WriteData(1, true, []byte("abcd")))
				h.reply(t, 1)
			}
			select {
			case err := <-errs:
				require.True(t, errors.Is(err, errMalformedRequest), "forward failed with %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("the handler did not return")
			}
		})
	}
}

func TestHTTP_RequestWithoutContentEndsWithItsHeadersOverHTTP2(t *testing.T) {
	eachDeclaredFront(t, func(t *testing.T, front string) {
		for _, req := range []struct {
			method string
			want   string
			extra  []hpack.HeaderField
		}{
			{method: "GET", want: `HEADERS stream=1 end_stream=true content-length=""`},
			{method: "POST", want: `HEADERS stream=1 end_stream=true content-length="0"`, extra: []hpack.HeaderField{hf("content-length", "0")}},
		} {
			t.Run(req.method, func(t *testing.T) {
				o := prefaceOrigin(t, respondH2)
				got := h2cRequest(t, front, o, req.method, req.extra...)
				assert.Equal(t, "ok", string(got.body))
				require.Equal(t, http2.ClientPreface, o.nextNote(t))
				require.Equal(t, "SETTINGS stream=0 ack=false", o.nextNote(t))
				assert.Equal(t, req.want, o.nextNote(t))
			})
		}
	})
}

func TestHTTP_ZeroLengthEndedByAnEmptyDataFrameEndsWithItsHeadersOverHTTP2(t *testing.T) {
	eachDeclaredFront(t, func(t *testing.T, front string) {
		o := prefaceOrigin(t, respondH2)
		h := h2cStream(t, front, o, false, "POST", hf("content-length", "0"))
		// The response to stream 3 shows the handler of stream 1 started before its DATA frame.
		h.headers(t, 3, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"))
		require.Equal(t, "ok", string(h.reply(t, 3).body))
		require.NoError(t, h.fr.WriteData(1, true, nil))
		assert.Equal(t, "ok", string(h.reply(t, 1).body))
		require.Equal(t, http2.ClientPreface, o.nextNote(t))
		require.Equal(t, "SETTINGS stream=0 ack=false", o.nextNote(t))
		assert.Equal(t, `HEADERS stream=1 end_stream=true content-length=""`, o.nextNote(t))
		assert.Equal(t, `HEADERS stream=3 end_stream=true content-length="0"`, o.nextNote(t))
	})
}

func TestHTTP_ZeroLengthFromHTTP3EndsWithItsHeadersOverHTTP2(t *testing.T) {
	b := newH2OriginBench(t, respondH2)
	got := b.dialH3Front(t).roundTrip(t, h3Request("POST", "origin.test", "/", hf("content-length", "0")))
	require.NoError(t, got.err)
	assert.Equal(t, "ok", string(got.body))
	require.Equal(t, "SETTINGS stream=0 ack=false", b.origin.nextNote(t))
	assert.Equal(t, `HEADERS stream=1 end_stream=true content-length="0"`, b.origin.nextNote(t))
}

func TestHTTP_ZeroLengthEndsWithItsHeadersOverHTTP3(t *testing.T) {
	b := newH3OriginBench(t, func(o *rawOrigin, _ *h3Conn, s *h3Stream) {
		for {
			typ, payload, err := s.next()
			if err != nil {
				o.note(fmt.Sprintf("end %v", err))
				break
			}
			switch typ {
			case h3FrameHeaders:
				fields, _ := qpackFields(payload)
				cl, _ := h2Field(fields, "content-length")
				o.note(fmt.Sprintf("HEADERS content-length=%q", cl))
			case h3FrameData:
				o.note(fmt.Sprintf("DATA len=%d", len(payload)))
			}
		}
		if _, err := s.Write(slices.Concat(h3Headers([]hpack.HeaderField{hf(":status", "200")}), h3Data("ok"))); err == nil {
			_ = s.Close()
		}
	})
	got := b.dialH3Front(t).roundTrip(t, h3Request("POST", "origin.test", "/", hf("content-length", "0")))
	require.NoError(t, got.err)
	assert.Equal(t, "ok", string(got.body))
	assert.Equal(t, `HEADERS content-length="0"`, b.origin.nextNote(t))
	assert.Equal(t, "end EOF", b.origin.nextNote(t), "a DATA frame followed the header section")
}

func TestHTTP_HTTP3TrailerSectionRefusedByQUICGoIsMalformed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field hpack.HeaderField
	}{
		{name: "name with a space", field: hf("x check", "sum")},
		{name: "value with a NUL", field: hf("x-check", "s\x00m")},
		{name: "field not allowed in trailers", field: hf("content-length", "1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newTLSProxyBench(t, always(okReply))
			got := b.dialH3Front(t).roundTrip(t, h3Request("POST", "origin.test", "/"), h3Data("a"), h3Headers([]hpack.HeaderField{tc.field}))
			require.NoError(t, got.err)
			assert.Equal(t, strconv.Itoa(http.StatusBadRequest), got.status())
		})
	}
}

func TestHTTP_AnnouncesTETrailersOverHTTP2(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "te=%s proto=%s", r.Header.Get("Te"), r.Proto)
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
	p.MustAdd(originHost(originURL)+"/*{any}", forwardHandler)

	addr := startProxy(t, p)
	client := h2Client(addr, ca.CertPool())

	req, err := http.NewRequest(http.MethodGet, origin.URL+"/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("TE", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get through proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "te=trailers proto=HTTP/2.0" {
		t.Fatalf("origin saw %q, want te=trailers proto=HTTP/2.0", body)
	}
}

func TestHTTP_HeadHasNoBody(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5")
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("hello"))
		}
	}))
	defer origin.Close()

	_, _, client := interceptingProxy(t, origin)

	resp, err := client.Head(origin.URL + "/")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Empty(t, body)
	assert.Equal(t, "5", resp.Header.Get("Content-Length"))
}

func TestHTTP_NoContentAndNotModified(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/204":
			w.WriteHeader(http.StatusNoContent)
		case "/304":
			w.WriteHeader(http.StatusNotModified)
		}
	}))
	defer origin.Close()

	_, _, client := interceptingProxy(t, origin)

	for _, path := range []string{"/204", "/304"} {
		resp, err := client.Get(origin.URL + path)
		require.NoError(t, err, path)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Empty(t, body, path)
	}
}

func TestHTTP_RequestBodyStreams(t *testing.T) {
	const size = 4 << 20

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "received %d", n)
	}))
	defer origin.Close()

	_, _, client := interceptingProxy(t, origin)

	body := bytes.Repeat([]byte("x"), size)
	resp, err := client.Post(origin.URL+"/upload", "application/octet-stream", bytes.NewReader(body))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	got, _ := io.ReadAll(resp.Body)
	assert.Equal(t, fmt.Sprintf("received %d", size), string(got))
}

func TestHTTP_ContentEncodingIsNotTouched(t *testing.T) {
	var payload bytes.Buffer
	zw := gzip.NewWriter(&payload)
	_, _ = zw.Write([]byte("compressed payload"))
	require.NoError(t, zw.Close())

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			http.Error(w, "proxy dropped or rewrote Accept-Encoding", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(payload.Bytes())
	}))
	defer origin.Close()

	_, _, client := interceptingProxy(t, origin)

	req, err := http.NewRequest(http.MethodGet, origin.URL+"/gz", nil)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	// The client asked for gzip, so it must get gzip: a proxy that decompresses on the way
	// through changes what the application under test observes.
	assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
	raw, _ := io.ReadAll(resp.Body)
	assert.Equal(t, payload.Bytes(), raw)
}

func TestHTTP_HopByHopHeadersAreStripped(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var leaked []string
		for _, h := range []string{"Proxy-Connection", "Keep-Alive", "X-Hop", "Connection"} {
			if r.Header.Get(h) != "" {
				leaked = append(leaked, h)
			}
		}
		fmt.Fprintf(w, "leaked=%s", strings.Join(leaked, ","))
	}))
	defer origin.Close()

	_, _, client := interceptingProxy(t, origin)

	req, _ := http.NewRequest(http.MethodGet, origin.URL+"/", nil)
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "timeout=5")
	// A header named in Connection is hop-by-hop by declaration and must go too.
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "secret")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "leaked=", string(body))
}

func TestHTTP_TETrailersIsAnnouncedForTheProxy(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "te=%s", strings.Join(r.Header.Values("Te"), "|"))
	}))
	defer origin.Close()

	_, _, client := interceptingProxy(t, origin)

	cases := []struct {
		name string
		conn string
		want string
		sent []string
	}{
		{name: "nothing announced", want: "te="},
		{name: "trailers", sent: []string{"trailers"}, want: "te=trailers"},
		{name: "transfer coding only", sent: []string{"gzip"}, want: "te="},
		{name: "trailers among codings", sent: []string{"gzip", "trailers"}, want: "te=trailers"},
		{name: "listed in connection", sent: []string{"trailers"}, conn: "TE", want: "te=trailers"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, origin.URL+"/", nil)
			require.NoError(t, err)
			for _, v := range tc.sent {
				req.Header.Add("TE", v)
			}
			if tc.conn != "" {
				req.Header.Set("Connection", tc.conn)
			}

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			body, _ := io.ReadAll(resp.Body)
			// TE stops at the first hop, so the proxy makes the announcement for itself
			// rather than relaying the client's. A transfer coding it does not implement is
			// not announced at all.
			assert.Equal(t, tc.want, string(body))
		})
	}
}

func TestHTTP_HandlerPanicBecomesAnError(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	defer origin.Close()

	p, authority, client := interceptingProxy(t, origin)
	p.MustAdd(authority+"/boom", func(c *HTTPCtx) (*http.Response, error) {
		panic("handler exploded")
	}, WithMethods[HTTP](http.MethodGet))
	p.MustAdd(authority+"/fine", func(c *HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, "still alive"), nil
	}, WithMethods[HTTP](http.MethodGet))

	resp, err := client.Get(origin.URL + "/boom")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode,
		"a panic is a failure of the proxy, not an answer from the upstream")
	assert.Equal(t, http.StatusText(http.StatusInternalServerError), string(body), "the client learns the status and nothing else")

	// The connection must survive: an application under test should not see a transport
	// failure because a handler had a bug.
	resp, err = client.Get(origin.URL + "/fine")
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, "still alive", string(body))
}

func TestHTTP_PanicReachesTheErrorHandler(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	sentinel := errors.New("boom")

	var got *PanicError
	p, authority, client := interceptingProxy(t, origin, WithErrorHandler(func(c *HTTPCtx, err error) *http.Response {
		got, _ = errors.AsType[*PanicError](err)
		return Status(http.StatusTeapot)
	}))
	p.MustAdd(authority+"/boom", func(c *HTTPCtx) (*http.Response, error) {
		panic(sentinel)
	}, WithMethods[HTTP](http.MethodGet))

	resp, err := client.Get(origin.URL + "/boom")
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusTeapot, resp.StatusCode)
	require.NotZero(t, got)
	assert.Equal(t, sentinel, got.Value)
	assert.ErrorIs(t, got, sentinel, "a panic carrying an error stays reachable through Unwrap")
	assert.Contains(t, got.Stack, "TestHTTP_PanicReachesTheErrorHandler",
		"the first frame captured must be the one that panicked")
}

func TestHTTP_ErrorHandler(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	sentinel := errors.New("upstream refused")

	p, authority, client := interceptingProxy(t, origin, WithErrorHandler(func(c *HTTPCtx, err error) *http.Response {
		if errors.Is(err, sentinel) {
			return Text(http.StatusServiceUnavailable, "handled: "+err.Error())
		}
		return Status(http.StatusBadGateway)
	}))
	p.MustAdd(authority+"/fail", func(c *HTTPCtx) (*http.Response, error) {
		return nil, sentinel
	}, WithMethods[HTTP](http.MethodGet))

	resp, err := client.Get(origin.URL + "/fail")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "handled: upstream refused", string(body))
}

func TestHTTP_MalformedRequestOverEachUpstream(t *testing.T) {
	t.Run("h1", func(t *testing.T) {
		b := newProxyBench(t, always(okReply))
		w := b.dial(t)
		w.send(t, "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 10\r\n\r\nabcd")
		require.NoError(t, w.Conn.(*net.TCPConn).CloseWrite())
		assert.Equal(t, http.StatusBadRequest, w.readResponse(t, "POST").resp.StatusCode)
	})
	t.Run("h3", func(t *testing.T) {
		b := newH3OriginBench(t, func(_ *rawOrigin, _ *h3Conn, s *h3Stream) {
			if s.message(false).err != nil {
				s.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestIncomplete))
				return
			}
			_, _ = s.Write(h3Headers([]hpack.HeaderField{hf(":status", "200")}))
			_ = s.Close()
		})
		h := b.dialH3Front(t)
		got := h.roundTrip(t, h3Request("POST", "origin.test", "/", hf("content-length", "10")), h3Data("abcd"))
		require.NoError(t, got.err)
		assert.Equal(t, "400", got.status())
	})
}

func TestHTTP_MalformedRequestReachesTheErrorHandler(t *testing.T) {
	o := newRawOrigin(t, always(okReply))
	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(o.addr)
	got := make(chan error, 1)
	p := testProxy(t, WithTransport(tr), WithErrorHandler(func(_ *HTTPCtx, err error) *http.Response {
		got <- err
		return Status(http.StatusTeapot)
	}))
	p.MustAdd("origin.test/*{any}", forwardHandler)
	w := dialWire(t, startProxy(t, p))
	w.send(t, "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 10\r\n\r\nabcd")
	require.NoError(t, w.Conn.(*net.TCPConn).CloseWrite())
	assert.Equal(t, http.StatusTeapot, w.readResponse(t, "POST").resp.StatusCode)
	err := <-got
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "malformed")
}

func TestHTTP_ClientCancelIsNotMalformed(t *testing.T) {
	o := newRawOrigin(t, func(o *rawOrigin, w *wire) {
		req, err := http.ReadRequest(w.br)
		if err != nil {
			return
		}
		o.note(req.Method)
		_, _ = io.ReadAll(req.Body)
	})
	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(o.addr)
	got := make(chan error, 1)
	p := testProxy(t, WithTransport(tr), WithErrorHandler(func(_ *HTTPCtx, err error) *http.Response {
		got <- err
		return Status(http.StatusTeapot)
	}))
	p.MustAdd("origin.test/*{any}", forwardHandler)
	h := dialH2(t, startProxy(t, p))
	h.headers(t, 1, false, hf(":method", "POST"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"),
		hf("content-length", "10"))
	require.NoError(t, h.fr.WriteData(1, false, []byte("abcd")))
	require.Equal(t, "POST", o.nextNote(t))
	require.NoError(t, h.fr.WriteRSTStream(1, http2.ErrCodeCancel))
	select {
	case err := <-got:
		assert.NotErrorIs(t, err, errMalformedRequest)
	case <-time.After(5 * time.Second):
		t.Fatal("the forward did not fail")
	}
}

func TestHTTP_FailedBodyOfTheHandlerIsBadGateway(t *testing.T) {
	b := newProxyBench(t, always(okReply))
	b.p.MustAdd("origin.test/own", func(c *HTTPCtx) (*http.Response, error) {
		r := c.Request()
		r.Body = io.NopCloser(io.MultiReader(strings.NewReader("ab"), iotest.ErrReader(errors.New("handler body failed"))))
		r.ContentLength = 10
		return c.Forward()
	})
	got := b.exchange(t, "POST", "POST http://origin.test/own HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 2\r\n\r\nok")
	assert.Equal(t, http.StatusBadGateway, got.resp.StatusCode)
}

func TestHTTP_MiddlewareOrder(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer origin.Close()

	var order []string
	record := func(name string) Middleware[HTTP] {
		return func(next HTTP) HTTP {
			return func(c *HTTPCtx) (*http.Response, error) {
				order = append(order, "→"+name)
				resp, err := next(c)
				order = append(order, "←"+name)
				return resp, err
			}
		}
	}

	p, authority, client := interceptingProxy(t, origin, WithMiddleware(record("outer"), record("inner")))
	p.MustAdd(authority+"/x", func(c *HTTPCtx) (*http.Response, error) {
		order = append(order, "handler")
		return Status(http.StatusOK), nil
	}, WithMiddleware(record("interceptor")), WithMethods[HTTP](http.MethodGet))

	resp, err := client.Get(origin.URL + "/x")
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, []string{"→outer", "→inner", "→interceptor", "handler", "←interceptor", "←inner", "←outer"}, order)
}

func TestHTTP_NoInterceptorForwardsUnchanged(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin got %s", r.URL.Path)
	}))
	defer origin.Close()

	p, authority, client := interceptingProxy(t, origin)
	p.MustAdd(authority+"/known", func(c *HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, "handled"), nil
	}, WithMethods[HTTP](http.MethodGet))

	resp, err := client.Get(origin.URL + "/unknown")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "origin got /unknown", string(body))
}

func TestHTTP_RawPathIsPreserved(t *testing.T) {
	var seen string
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.RequestURI
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)

	var routed string
	p.MustAdd(originHost(originURL)+"/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		routed = c.RoutingPath()
		return c.Forward()
	}, WithMethods[HTTP](http.MethodGet))
	client := proxyClient(startProxy(t, p), ca.CertPool())

	cases := []struct{ wire, wantRouted string }{
		{"/v1/charges", "/v1/charges"},
		// %2F stays encoded on the wire and is never matched as a path separator.
		{"/files/a%2Fb?q=1%2B2", "/files/a%2Fb"},
		{"/v1%2fcharges", "/v1%2Fcharges"},
		// An escaped unreserved character is decoded for matching, not on the wire.
		{"/v1/%63harges", "/v1/charges"},
		{"/v1/%2e%2e/charges", "/v1/../charges"},
		// Nothing collapses a dot segment or a double slash, in either direction.
		{"//v1/./sub/../charges", "//v1/./sub/../charges"},
		{"/v1/charges;x=1", "/v1/charges;x=1"},
	}

	for _, tc := range cases {
		seen, routed = "", ""
		resp, err := client.Get(origin.URL + tc.wire)
		require.NoError(t, err, tc.wire)
		_ = resp.Body.Close()

		assert.Equal(t, tc.wire, seen, "the request target must reach the origin byte for byte")
		assert.Equal(t, tc.wantRouted, routed, "routing form of %q", tc.wire)
	}
}

func TestConformanceProxy(t *testing.T) {
	runConformance(t, proxyConformance)
}

// wire reads HTTP/1.1 messages off a connection and keeps every byte it read, so a message is
// checked as it crossed the wire.
type wire struct {
	net.Conn
	br  *bufio.Reader
	rec bytes.Buffer
	// originForm rewrites every absolute-form request line sent to origin-form.
	originForm bool
}

func newWire(c net.Conn) *wire {
	w := &wire{Conn: c}
	w.br = bufio.NewReader(io.TeeReader(c, &w.rec))
	return w
}

func dialWire(t *testing.T, addr string) *wire {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second)))
	return newWire(c)
}

func (w *wire) consumed() int { return w.rec.Len() - w.br.Buffered() }

func (w *wire) headFrom(start int) string {
	raw := w.rec.Bytes()[start:]
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return string(raw[:i+4])
	}
	return string(raw)
}

// absoluteTarget matches the method, the scheme and the authority of an absolute-form request
// line.
var absoluteTarget = regexp.MustCompile(`(?m)^([A-Z]+) https?://[^/?# \r\n]*/?`)

func (w *wire) send(t *testing.T, s string) {
	t.Helper()
	if w.originForm {
		s = absoluteTarget.ReplaceAllString(s, "${1} /")
	}
	_, err := io.WriteString(w.Conn, s)
	require.NoError(t, err)
}

type wireRequest struct {
	req  *http.Request
	head string
	body []byte
}

func (w *wire) readRequest() (wireRequest, error) {
	start := w.consumed()
	req, err := http.ReadRequest(w.br)
	if err != nil {
		return wireRequest{}, err
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return wireRequest{}, err
	}
	return wireRequest{head: w.headFrom(start), req: req, body: body}, nil
}

type wireResponse struct {
	resp *http.Response
	err  error
	head string
	body []byte
}

func (w *wire) readResponse(t *testing.T, method string) wireResponse {
	t.Helper()
	start := w.consumed()
	resp, err := http.ReadResponse(w.br, &http.Request{Method: method})
	require.NoError(t, err)
	body, berr := io.ReadAll(resp.Body)
	return wireResponse{head: w.headFrom(start), resp: resp, body: body, err: berr}
}

// readHead reads a header section and nothing past it, for an answer to CONNECT whose
// framing fields the client must ignore.
func (w *wire) readHead(t *testing.T) string {
	t.Helper()
	start := w.consumed()
	for {
		line, err := w.br.ReadString('\n')
		require.NoError(t, err)
		if line == "\r\n" {
			return w.headFrom(start)
		}
	}
}

func (w *wire) wantClosed(t *testing.T) {
	t.Helper()
	require.NoError(t, w.SetReadDeadline(time.Now().Add(3*time.Second)))
	rest, err := io.ReadAll(w.br)
	require.NoError(t, err, "the connection must be closed")
	require.Empty(t, string(rest))
}

func fieldValues(head, name string) []string {
	lines := strings.Split(strings.TrimSuffix(head, "\r\n\r\n"), "\r\n")
	var out []string
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(k, name) {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}

func startLine(head string) string {
	line, _, _ := strings.Cut(head, "\r\n")
	return line
}

func headStatus(t *testing.T, head string) int {
	t.Helper()
	_, rest, _ := strings.Cut(startLine(head), " ")
	code, _, _ := strings.Cut(rest, " ")
	n, err := strconv.Atoi(code)
	require.NoError(t, err, head)
	return n
}

type rawOrigin struct {
	got      chan wireRequest
	notes    chan string
	ends     chan struct{}
	addr     string
	n        atomic.Int32
	accepted atomic.Int32
}

func newRawOrigin(t *testing.T, serve func(o *rawOrigin, w *wire)) *rawOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	o := &rawOrigin{
		addr:  ln.Addr().String(),
		got:   make(chan wireRequest, 16),
		notes: make(chan string, 16),
		ends:  make(chan struct{}, 16),
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			o.accepted.Add(1)
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func() {
				defer func() {
					_ = c.Close()
					select {
					case o.ends <- struct{}{}:
					default:
					}
				}()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				serve(o, newWire(c))
			}()
		}
	}()
	return o
}

func (o *rawOrigin) next(t *testing.T) wireRequest {
	t.Helper()
	select {
	case r := <-o.got:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("the origin received no request")
		return wireRequest{}
	}
}

func (o *rawOrigin) none(t *testing.T) {
	t.Helper()
	select {
	case r := <-o.got:
		t.Fatalf("the origin received %q", r.head)
	case <-time.After(300 * time.Millisecond):
	}
}

func (o *rawOrigin) note(s string) { o.notes <- s }

func (o *rawOrigin) nextNote(t *testing.T) string {
	t.Helper()
	select {
	case s := <-o.notes:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("the origin recorded nothing")
		return ""
	}
}

func (o *rawOrigin) ended(t *testing.T) {
	t.Helper()
	select {
	case <-o.ends:
	case <-time.After(3 * time.Second):
		t.Fatal("the connection to the origin is still open")
	}
}

// n counts the requests across connections, from zero.
func replyEach(reply func(n int, r wireRequest) string) func(*rawOrigin, *wire) {
	return func(o *rawOrigin, w *wire) {
		for {
			r, err := w.readRequest()
			if err != nil {
				return
			}
			o.got <- r
			if _, err := io.WriteString(w, reply(int(o.n.Add(1))-1, r)); err != nil {
				return
			}
		}
	}
}

func always(reply string) func(*rawOrigin, *wire) {
	return replyEach(func(int, wireRequest) string { return reply })
}

const okReply = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

type proxyBench struct {
	p      *Proxy
	origin *rawOrigin
	trust  *x509.CertPool
	addr   string
	front  proxyFront
}

// A proxyFront is how a client of a proxyBench reaches origin.test. On every front but
// frontExplicit the request lines are sent in origin-form.
type proxyFront string

const (
	frontExplicit      proxyFront = "explicit"
	frontConnect       proxyFront = "connect"
	frontRedirected    proxyFront = viaRedirected
	frontConnectTLS    proxyFront = "connect-tls"
	frontRedirectedTLS proxyFront = "redirected-tls"
)

var proxyFronts = []proxyFront{frontExplicit, frontConnect, frontRedirected, frontConnectTLS, frontRedirectedTLS}

func eachProxyFront(t *testing.T, run func(t *testing.T, front proxyFront)) {
	t.Helper()
	for _, front := range proxyFronts {
		t.Run(string(front), func(t *testing.T) { run(t, front) })
	}
}

func (f proxyFront) secure() bool { return f == frontConnectTLS || f == frontRedirectedTLS }

func (f proxyFront) scheme() string {
	if f.secure() {
		return "https"
	}
	return "http"
}

func newProxyBench(t *testing.T, serve func(*rawOrigin, *wire)) *proxyBench {
	t.Helper()
	return newProxyBenchOn(t, frontExplicit, serve)
}

// newProxyBenchOn is newProxyBench served on front, the origin behind TLS on a secure front.
func newProxyBenchOn(t *testing.T, front proxyFront, serve func(*rawOrigin, *wire)) *proxyBench {
	t.Helper()
	return newProxyBenchWith(t, front, DefaultTransport(), serve, forwardHandler, nil)
}

// newProxyBenchWith is newProxyBenchOn with tr, whose dialer and roots it sets, with handler for
// origin.test, and with every connection to the origin passed through wrap when wrap is not nil.
func newProxyBenchWith(t *testing.T, front proxyFront, tr *Transport, serve func(*rawOrigin, *wire), handler func(*HTTPCtx) (*http.Response, error), wrap func(net.Conn) net.Conn) *proxyBench {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	var o *rawOrigin
	if front.secure() {
		originCA, err := GenerateCA()
		require.NoError(t, err)
		cert, err := originCA.Leaf("origin.test")
		require.NoError(t, err)
		o = newTLSOrigin(t, *cert, serve)
		tr.RootCAs = poolOf(originCA)
	} else {
		o = newRawOrigin(t, serve)
	}
	tr.DialContext = pinnedDialer(o.addr)
	if wrap != nil {
		dial := tr.DialContext
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return wrap(c), nil
		}
	}
	p := testProxyWithCA(t, ca, WithTransport(tr))
	p.MustAdd("origin.test/*{any}", handler)
	b := &proxyBench{p: p, origin: o, trust: ca.CertPool(), front: front}
	switch front {
	case frontExplicit, frontConnect, frontConnectTLS:
		b.addr = startProxy(t, p)
	case frontRedirected, frontRedirectedTLS:
		dst := netip.MustParseAddrPort(o.addr)
		b.addr = startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) { return dst, nil })
	default:
		t.Fatalf("unknown front %q", front)
	}
	return b
}

const forgedResponse = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nforged"

// lateConn returns a read that starts with forgedResponse only once a request was written after
// the read began, the schedule in which Go's transport checks for bytes past a response after it
// handed the connection to the next request.
type lateConn struct {
	net.Conn
	mu    sync.Mutex
	wrote chan struct{}
}

func (c *lateConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.mu.Lock()
	if c.wrote != nil {
		close(c.wrote)
		c.wrote = nil
	}
	c.mu.Unlock()
	return n, err
}

func (c *lateConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if c.wrote == nil {
		c.wrote = make(chan struct{})
	}
	wrote := c.wrote
	c.mu.Unlock()
	n, err := c.Conn.Read(b)
	if bytes.HasPrefix(b[:n], []byte(forgedResponse)) {
		select {
		case <-wrote:
		case <-time.After(5 * time.Second):
		}
	}
	return n, err
}

func readAllHandler(c *HTTPCtx) (*http.Response, error) {
	resp, err := c.Forward()
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

// newRefusingBench is a proxy serving origin.test as a byte stream, every dial of which is
// refused.
func newRefusingBench(t *testing.T) *proxyBench {
	t.Helper()
	tr := DefaultTransport()
	tr.DialContext = func(_ context.Context, network, _ string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	p := testProxy(t, WithTransport(tr))
	p.MustAdd("origin.test", relayStream)
	return &proxyBench{p: p, addr: startProxy(t, p)}
}

// dial opens a connection on which the requests of a client of the front reach origin.test.
func (b *proxyBench) dial(t *testing.T) *wire {
	t.Helper()
	var c net.Conn
	switch b.front {
	case frontExplicit, "":
		return dialWire(t, b.addr)
	case frontConnect:
		c = connectRaw(t, b.addr, "origin.test:80")
	case frontConnectTLS:
		c = connectRaw(t, b.addr, "origin.test:443")
	default:
		c = dialWire(t, b.addr).Conn
	}
	require.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second)))
	if b.front.secure() {
		c = tls.Client(c, &tls.Config{ServerName: "origin.test", RootCAs: b.trust, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	}
	w := newWire(c)
	w.originForm = true
	return w
}

func (b *proxyBench) exchange(t *testing.T, method, raw string) wireResponse {
	t.Helper()
	w := b.dial(t)
	w.send(t, raw)
	return w.readResponse(t, method)
}

func (b *proxyBench) forwarded(t *testing.T, method, raw string) (wireRequest, wireResponse) {
	t.Helper()
	resp := b.exchange(t, method, raw)
	return b.origin.next(t), resp
}

func (b *proxyBench) connect(t *testing.T) *wire {
	t.Helper()
	w := dialWire(t, b.addr)
	w.send(t, "CONNECT origin.test:80 HTTP/1.1\r\nHost: origin.test:80\r\n\r\n")
	require.Equal(t, http.StatusOK, headStatus(t, w.readHead(t)))
	return w
}

type h2Wire struct {
	fr  *http2.Framer
	enc *hpack.Encoder
	buf bytes.Buffer
}

func dialH2(t *testing.T, addr string) *h2Wire {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second)))
	_, err = io.WriteString(c, http2.ClientPreface)
	require.NoError(t, err)
	h := newH2Wire(c)
	require.NoError(t, h.fr.WriteSettings())
	return h
}

func newH2Wire(c net.Conn) *h2Wire {
	h := &h2Wire{fr: http2.NewFramer(c, c)}
	h.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	h.enc = hpack.NewEncoder(&h.buf)
	return h
}

func hf(name, value string) hpack.HeaderField { return hpack.HeaderField{Name: name, Value: value} }

func (h *h2Wire) headers(t *testing.T, id uint32, end bool, fields ...hpack.HeaderField) {
	t.Helper()
	h.buf.Reset()
	for _, f := range fields {
		require.NoError(t, h.enc.WriteField(f))
	}
	require.NoError(t, h.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: h.buf.Bytes(), EndHeaders: true, EndStream: end,
	}))
}

// The payload of a DATA frame is copied, the framer reuses its buffer.
func (h *h2Wire) next(t *testing.T, id uint32) any {
	t.Helper()
	for {
		f, err := h.fr.ReadFrame()
		require.NoError(t, err)
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				require.NoError(t, h.fr.WriteSettingsAck())
			}
			continue
		case *http2.PingFrame:
			if !f.IsAck() {
				require.NoError(t, h.fr.WritePing(true, f.Data))
			}
			continue
		case *http2.WindowUpdateFrame:
			continue
		case *http2.GoAwayFrame:
			t.Fatalf("GOAWAY %v", f.ErrCode)
		case *http2.DataFrame:
			if f.StreamID == id {
				return &h2Data{data: bytes.Clone(f.Data()), end: f.StreamEnded()}
			}
			continue
		}
		if f.Header().StreamID == id {
			return f
		}
	}
}

type h2Data struct {
	data []byte
	end  bool
}

type h2Reply struct {
	fields []hpack.HeaderField
	body   []byte
	rst    http2.ErrCode
	reset  bool
}

func (h *h2Wire) reply(t *testing.T, id uint32) h2Reply {
	t.Helper()
	var r h2Reply
	for {
		switch f := h.next(t, id).(type) {
		case *http2.MetaHeadersFrame:
			if r.fields == nil {
				r.fields = f.Fields
			}
			if f.StreamEnded() {
				return r
			}
		case *h2Data:
			r.body = append(r.body, f.data...)
			if f.end {
				return r
			}
		case *http2.RSTStreamFrame:
			r.rst, r.reset = f.ErrCode, true
			return r
		}
	}
}

func h2Field(fields []hpack.HeaderField, name string) (string, bool) {
	for _, f := range fields {
		if f.Name == name {
			return f.Value, true
		}
	}
	return "", false
}

func (h *h2Wire) h2Connect(t *testing.T) []hpack.HeaderField {
	t.Helper()
	h.headers(t, 1, false, hf(":method", "CONNECT"), hf(":authority", "origin.test:80"))
	f, ok := h.next(t, 1).(*http2.MetaHeadersFrame)
	require.True(t, ok, "the answer to CONNECT starts with HEADERS")
	status, _ := h2Field(f.Fields, ":status")
	require.Equal(t, "200", status)
	return f.Fields
}

var plainH2Fronts = []string{viaH2C, viaRedirected, viaUnredirected, viaServeConn}

func eachPlainH2Front(t *testing.T, run func(t *testing.T, front string)) {
	t.Helper()
	for _, front := range plainH2Fronts {
		t.Run(front, func(t *testing.T) { run(t, front) })
	}
}

// prefaceFronts are the fronts on which HTTP/2 starts with the client preface, over plaintext or
// over TLS negotiating h2.
var prefaceFronts = slices.Concat(plainH2Fronts, []string{viaH2, viaConnectH2, viaRedirectedH2})

const viaRedirectedH2CToH1 = "redirected-h2c-h1-upstream"

// h1UpstreamFronts are the HTTP/2 fronts whose requests reach an origin offering HTTP/1.1 alone
// over HTTP/1.1. redirected-h2c-h1-upstream is redirected-h2c under Transport.AllowHTTP2 false,
// without which the proxy uses h2c with the origin.
var h1UpstreamFronts = []string{viaH2C, viaH2, viaConnectH2, viaRedirectedH2, viaRedirectedH2CToH1}

func eachH2Front(t *testing.T, fronts []string, run func(t *testing.T, front string)) {
	t.Helper()
	for _, front := range fronts {
		t.Run(front, func(t *testing.T) { run(t, front) })
	}
}

// h2FrontBench returns a proxyBench whose origin is behind TLS when front gives requests the
// https scheme, and an HTTP/2 connection to front for origin.test.
func h2FrontBench(t *testing.T, front string, serve func(*rawOrigin, *wire)) (*proxyBench, *h2Wire) {
	t.Helper()
	var b *proxyBench
	switch {
	case front == viaRedirectedH2CToH1:
		o := newRawOrigin(t, serve)
		tr := DefaultTransport()
		tr.DialContext = pinnedDialer(o.addr)
		tr.AllowHTTP2 = false
		p := testProxy(t, WithTransport(tr))
		p.MustAdd("origin.test/*{any}", forwardHandler)
		return &proxyBench{p: p, origin: o}, dialH2Wire(t, viaRedirectedH2C, p, "origin.test")
	case frontScheme(front, "http") == "https":
		b = newTLSProxyBench(t, serve)
	default:
		b = newProxyBench(t, serve)
	}
	return b, dialH2Wire(t, front, b.p, "origin.test")
}

// dialPrefaceFront serves p on front and returns a connection to it on which nothing was
// written, opened for a.test when front is TLS.
func dialPrefaceFront(t *testing.T, front string, p *Proxy) net.Conn {
	t.Helper()
	if slices.Contains(plainH2Fronts, front) {
		return dialPlainH2Front(t, front, p, nil)
	}
	return dialH2Front(t, front, startHPACKFront(t, front, p, p.cfg.ca), p.cfg.ca, "a.test")
}

// dialPlainH2Front serves p on front and returns a connection to it on which nothing was
// written. When wrap is set, the proxy reads and writes through it.
func dialPlainH2Front(t *testing.T, front string, p *Proxy, wrap func(net.Conn) net.Conn) net.Conn {
	t.Helper()
	if wrap == nil {
		wrap = func(c net.Conn) net.Conn { return c }
	}
	t.Cleanup(func() { _ = p.Close() })
	var c net.Conn
	if front == viaH2C {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		go func() { _ = p.Serve(wrapListener{Listener: ln, wrap: wrap}) }()
		c, err = net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		require.NoError(t, err)
	} else {
		c = dialTransparentFront(t, front, p, wrap)
	}
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second)))
	return c
}

func prefaceThen(t *testing.T, frames func(fr *http2.Framer) error) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString(http2.ClientPreface)
	require.NoError(t, frames(http2.NewFramer(&b, nil)))
	return b.Bytes()
}

// requestEncoder returns an encoder of GET requests on one HPACK context.
func requestEncoder() func(authority, path string) []byte {
	var b bytes.Buffer
	enc := hpack.NewEncoder(&b)
	return func(authority, path string) []byte {
		b.Reset()
		for _, f := range []hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", authority), hf(":path", path)} {
			_ = enc.WriteField(f)
		}
		return bytes.Clone(b.Bytes())
	}
}

// sendAsync writes b on c without waiting. A write on a pipe returns only once the proxy has
// read all of it.
func sendAsync(c net.Conn, b []byte) { go func() { _, _ = c.Write(b) }() }

// endedCleanly reports whether a read error is a close or a reset of the connection.
func endedCleanly(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, syscall.ECONNRESET)
}

type echoCounts struct {
	served atomic.Int32
	dialed atomic.Int32
}

// hostEcho returns a proxy that answers every request on a.test and b.test with the host it
// was routed on, refuses every upstream dial, and counts both.
func hostEcho(t *testing.T) (*Proxy, *echoCounts) {
	t.Helper()
	n := new(echoCounts)
	tr := DefaultTransport()
	tr.DialContext = func(_ context.Context, network, _ string) (net.Conn, error) {
		n.dialed.Add(1)
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	p := testProxy(t, WithTransport(tr))
	for _, host := range []string{"a.test", "b.test"} {
		p.MustAdd(host+"/*{any}", func(c *HTTPCtx) (*http.Response, error) {
			n.served.Add(1)
			return Text(http.StatusOK, c.Host()), nil
		})
	}
	return p, n
}

func (h *h2Wire) frame(t *testing.T) http2.Frame {
	t.Helper()
	f, err := h.fr.ReadFrame()
	require.NoError(t, err, "no frame before the end of the connection")
	return f
}

// bodies reads until every one of streams has ended and returns their bodies.
func (h *h2Wire) bodies(t *testing.T, streams ...uint32) map[uint32]string {
	t.Helper()
	got := make(map[uint32]string)
	open := len(streams)
	for open > 0 {
		f := h.frame(t)
		if !slices.Contains(streams, f.Header().StreamID) {
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					require.NoError(t, h.fr.WriteSettingsAck())
				}
			case *http2.GoAwayFrame:
				t.Fatalf("GOAWAY %v", f.ErrCode)
			}
			continue
		}
		switch f := f.(type) {
		case *http2.RSTStreamFrame:
			t.Fatalf("stream %d reset with %v", f.StreamID, f.ErrCode)
		case *http2.MetaHeadersFrame:
			if _, ok := got[f.StreamID]; !ok {
				got[f.StreamID] = ""
			}
			if f.StreamEnded() {
				open--
			}
		case *http2.DataFrame:
			got[f.StreamID] += string(f.Data())
			if f.StreamEnded() {
				open--
			}
		}
	}
	return got
}

func isSettings(f http2.Frame) bool {
	sf, ok := f.(*http2.SettingsFrame)
	return ok && !sf.IsAck()
}

const (
	viaConnect         = "connect"
	viaConnectTLSFront = "connect-tls-front"
	viaConnectH2Front  = "connect-h2-front"
	viaSOCKS           = "socks"
	viaSOCKSName       = "socks-name"
)

// declaredFronts are the fronts on which a client declares the destination of its connection.
// The h2c front, an unredirected connection and ServeConn declare none and forward through the
// shared pool, which has no h2c.
var declaredFronts = []string{viaRedirected, viaConnect, viaConnectTLSFront, viaConnectH2Front, viaSOCKS, viaSOCKSName}

func eachDeclaredFront(t *testing.T, run func(t *testing.T, front string)) {
	t.Helper()
	for _, front := range declaredFronts {
		t.Run(front, func(t *testing.T) { run(t, front) })
	}
}

// dialDeclared serves p on front and returns a connection on which nothing was written, headed
// to dst.
func dialDeclared(t *testing.T, front string, p *Proxy, dst netip.AddrPort) net.Conn {
	t.Helper()
	var c net.Conn
	switch front {
	case viaRedirected:
		addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) { return dst, nil })
		var err error
		c, err = net.DialTimeout("tcp", addr, 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })
	case viaConnect:
		c = connectRaw(t, startProxy(t, p), dst.String())
	case viaConnectTLSFront:
		ca, err := GenerateCA()
		require.NoError(t, err)
		addr, pool := startProxyTLS(t, p, ca)
		raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = raw.Close() })
		require.NoError(t, raw.SetDeadline(time.Now().Add(10*time.Second)))
		tc := tls.Client(raw, &tls.Config{ServerName: "127.0.0.1", RootCAs: pool, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
		w := newWire(tc)
		w.send(t, "CONNECT "+dst.String()+" HTTP/1.1\r\nHost: "+dst.String()+"\r\n\r\n")
		require.Equal(t, http.StatusOK, headStatus(t, w.readHead(t)))
		require.Zero(t, w.br.Buffered(), "nothing follows the response to CONNECT")
		c = tc
	case viaConnectH2Front:
		raw, err := net.DialTimeout("tcp", startProxy(t, p), 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = raw.Close() })
		require.NoError(t, raw.SetDeadline(time.Now().Add(10*time.Second)))
		cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
		require.NoError(t, err)
		pr, pw := io.Pipe()
		req, err := http.NewRequest(http.MethodConnect, "http://"+dst.String(), pr)
		require.NoError(t, err)
		resp, err := cc.RoundTrip(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		c = &tunnelConn{r: resp.Body, w: pw}
		t.Cleanup(func() { _ = c.Close() })
	case viaSOCKS, viaSOCKSName:
		addr := socksAddrBytes(dst)
		if front == viaSOCKSName {
			addr = socksNameBytes("localhost", dst.Port())
		}
		w := socksConnect(t, startSOCKS5(t, p), addr)
		w.want(socksGranted4...)
		c = w.conn
	default:
		t.Fatalf("unknown front %q", front)
	}
	require.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second)))
	return c
}

// h2cGet sends a GET for origin.test over HTTP/2 with prior knowledge through front to the origin
// o, and returns the reply.
func h2cGet(t *testing.T, front string, o *rawOrigin) h2Reply {
	t.Helper()
	return h2cRequest(t, front, o, "GET")
}

// h2cRequest is h2cGet with method and extra, in a HEADERS frame that ends the stream.
func h2cRequest(t *testing.T, front string, o *rawOrigin, method string, extra ...hpack.HeaderField) h2Reply {
	t.Helper()
	return h2cStream(t, front, o, true, method, extra...).reply(t, 1)
}

// h2cStream opens stream 1 with the HEADERS frame of h2cRequest, which ends the stream when end
// is true.
func h2cStream(t *testing.T, front string, o *rawOrigin, end bool, method string, extra ...hpack.HeaderField) *h2Wire {
	t.Helper()
	p := testProxy(t)
	for _, host := range []string{"origin.test", "127.0.0.1", "localhost"} {
		p.MustAdd(host+"/*{any}", forwardHandler)
	}
	c := dialDeclared(t, front, p, netip.MustParseAddrPort(o.addr))
	_, err := io.WriteString(c, http2.ClientPreface)
	require.NoError(t, err)
	h := newH2Wire(c)
	require.NoError(t, h.fr.WriteSettings())
	h.headers(t, 1, end, append([]hpack.HeaderField{
		hf(":method", method), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"),
	}, extra...)...)
	return h
}

// prefaceOrigin is a plaintext origin that notes the first 24 octets of each connection, and
// runs answer when they are the client connection preface and closes the connection otherwise.
func prefaceOrigin(t *testing.T, answer func(o *rawOrigin, w *wire, fr *http2.Framer)) *rawOrigin {
	t.Helper()
	return newRawOrigin(t, func(o *rawOrigin, w *wire) {
		preface := make([]byte, len(http2.ClientPreface))
		n, _ := io.ReadFull(w.br, preface)
		o.note(string(preface[:n]))
		if string(preface[:n]) != http2.ClientPreface {
			return
		}
		fr := http2.NewFramer(w.Conn, w.br)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		answer(o, w, fr)
	})
}

// respondH2 notes the first frame it reads, replies to it with an empty SETTINGS frame and its
// acknowledgment, then notes the HEADERS frame and the content-length of every request and
// responds with a 200 and the content "ok".
func respondH2(o *rawOrigin, _ *wire, fr *http2.Framer) {
	f, err := fr.ReadFrame()
	if err != nil {
		o.note(err.Error())
		return
	}
	o.note(fmt.Sprintf("%v stream=%d ack=%t", f.Header().Type, f.Header().StreamID, f.Header().Flags.Has(http2.FlagSettingsAck)))
	if err := fr.WriteSettings(); err != nil || !isSettings(f) || fr.WriteSettingsAck() != nil {
		return
	}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.MetaHeadersFrame:
			cl, _ := h2Field(f.Fields, "content-length")
			o.note(fmt.Sprintf("HEADERS stream=%d end_stream=%t content-length=%q", f.StreamID, f.StreamEnded(), cl))
			if writeOK(fr, f.StreamID) != nil {
				return
			}
		}
	}
}

// noteTrailerH1, noteTrailerH2 and noteTrailerH3 note where the X-Check field of a request
// arrived, in its header section or in its trailer section, and respond with a 200.
func noteTrailerH1(o *rawOrigin, w *wire) {
	r, err := w.readRequest()
	if err != nil {
		o.note(err.Error())
		return
	}
	o.note(fmt.Sprintf("header=%q trailer=%q", r.req.Header.Get("X-Check"), r.req.Trailer.Get("X-Check")))
	_, _ = io.WriteString(w, okReply)
}

func noteTrailerH2(o *rawOrigin, _ *wire, fr *http2.Framer) {
	if _, err := fr.ReadFrame(); err != nil || fr.WriteSettings() != nil || fr.WriteSettingsAck() != nil {
		return
	}
	var sections [][]hpack.HeaderField
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			o.note(err.Error())
			return
		}
		if h, ok := f.(*http2.MetaHeadersFrame); ok {
			sections = append(sections, h.Fields)
		}
		if end, ok := f.(interface{ StreamEnded() bool }); !ok || !end.StreamEnded() {
			continue
		}
		header, _ := h2Field(sections[0], "x-check")
		var trailer string
		if len(sections) > 1 {
			trailer, _ = h2Field(sections[1], "x-check")
		}
		o.note(fmt.Sprintf("header=%q trailer=%q", header, trailer))
		_ = writeOK(fr, f.Header().StreamID)
		sections = nil
	}
}

func noteTrailerH3(o *rawOrigin, _ *h3Conn, s *h3Stream) {
	m := s.message(false)
	header, _ := h2Field(m.fields, "x-check")
	trailer, _ := h2Field(m.trailer, "x-check")
	o.note(fmt.Sprintf("header=%q trailer=%q", header, trailer))
	if _, err := s.Write(slices.Concat(h3Headers([]hpack.HeaderField{hf(":status", "200")}), h3Data("ok"))); err == nil {
		_ = s.Close()
	}
}

func writeOK(fr *http2.Framer, stream uint32) error {
	var block bytes.Buffer
	_ = hpack.NewEncoder(&block).WriteField(hf(":status", "200"))
	return errors.Join(
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: block.Bytes(), EndHeaders: true}),
		fr.WriteData(stream, true, []byte("ok")))
}

// wantGatewayErrorH2 checks that a gateway that received no valid response resets the stream or
// responds with a server error.
func wantGatewayErrorH2(t *testing.T, got h2Reply) {
	t.Helper()
	if got.reset {
		return
	}
	status, _ := h2Field(got.fields, ":status")
	code, err := strconv.Atoi(status)
	require.NoError(t, err, "the stream ended with no status")
	assert.True(t, code >= 500 && code < 600, "the gateway responded %d with %q to an invalid response", code, got.body)
}

func drainOrigin(last string) func(*rawOrigin, *wire) {
	return func(o *rawOrigin, w *wire) {
		b, _ := io.ReadAll(w.br)
		o.note(string(b))
		_, _ = io.WriteString(w, last)
	}
}

// The credentials of the examples of RFC 7617 section 2 and 2.1, and two more.
var authAccepted = map[string]string{
	"Aladdin": "open sesame",
	"test":    "123£",
	"iam":     "my:;self",
	"Ünïcødé": "pässwörd",
}

const (
	authAladdin = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
	authTest    = "Basic dGVzdDoxMjPCow=="
)

func basicCredentials(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// decodeBasic reads credentials of RFC 7617 section 2, the scheme Basic, one or more spaces
// and a token68 whose decoded octets are a user-id and a password split on the first colon.
func decodeBasic(credentials string) (user, pass string, err error) {
	scheme, rest, ok := strings.Cut(credentials, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", "", fmt.Errorf("%q is not the scheme Basic followed by a space", credentials)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimLeft(rest, " "))
	if err != nil {
		return "", "", fmt.Errorf("%q has no base64 token68: %w", credentials, err)
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	if !ok {
		return "", "", fmt.Errorf("%q decodes to %q, without a colon", credentials, raw)
	}
	return user, pass, nil
}

const (
	formRequest    = "request"
	formConnect    = "CONNECT"
	formConnectUDP = "CONNECT-UDP"
)

var authForms = []string{formRequest, formConnect, formConnectUDP}

type refuseAll struct{}

func (refuseAll) Authenticate(*http.Request) (string, bool) { return "", false }
func (refuseAll) Challenges(*http.Request) []string         { return nil }

// authBench serves a proxy requiring credentials on an HTTP/1.1 and h2c front and on an
// HTTP/3 front, with a plaintext origin behind it and a TLS origin on port 443.
type authBench struct {
	*proxyBench
	ca     *CA
	secure *rawOrigin
	creds  chan [2]string
	h3     netip.AddrPort
}

// newAuthBench requires Basic credentials in realm and records every pair the proxy checks.
func newAuthBench(t *testing.T, realm string, serve func(*rawOrigin, *wire)) *authBench {
	t.Helper()
	creds := make(chan [2]string, 64)
	b := newAuthBenchWith(t, BasicAuth(realm, func(user, pass string) bool {
		select {
		case creds <- [2]string{user, pass}:
		default:
		}
		want, ok := authAccepted[user]
		return ok && pass == want
	}), serve)
	b.creds = creds
	return b
}

func newAuthBenchWith(t *testing.T, auth ProxyAuthenticator, serve func(*rawOrigin, *wire)) *authBench {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	cert, err := ca.Leaf("origin.test")
	require.NoError(t, err)
	plain := newRawOrigin(t, serve)
	secure := newTLSOrigin(t, *cert, serve)
	tr := DefaultTransport()
	tr.RootCAs = poolOf(ca)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasSuffix(addr, ":443") {
			return defaultDialer.DialContext(ctx, network, secure.addr)
		}
		return defaultDialer.DialContext(ctx, network, plain.addr)
	}
	p := testProxyWithCA(t, ca, WithTransport(tr), WithProxyAuth(auth))
	p.MustAdd("origin.test/*{any}", forwardHandler)
	b := &authBench{proxyBench: &proxyBench{p: p, origin: plain, addr: startProxy(t, p)}, ca: ca, secure: secure}
	b.h3, _ = startQUICFront(t, p, ca)
	return b
}

// originOf returns the origin a request on front reaches, the TLS one for HTTP/3 whose
// requests take the scheme of their connection.
func (b *authBench) originOf(front string) *rawOrigin {
	if front == viaH3 {
		return b.secure
	}
	return b.origin
}

func (b *authBench) nextCreds(t *testing.T) [2]string {
	t.Helper()
	select {
	case c := <-b.creds:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("the authenticator received no credentials")
		return [2]string{}
	}
}

type authReply struct {
	header http.Header
	status int
}

func (b *authBench) send(t *testing.T, front, form string, extra ...[2]string) authReply {
	t.Helper()
	switch front {
	case viaH2:
		if form == formConnectUDP && !extendedConnectEnabled() {
			t.Skip("run with GODEBUG=http2xconnect=1, Go's HTTP/2 server refuses extended CONNECT without it")
		}
		return b.sendH2(t, form, extra)
	case viaH3:
		return b.sendH3(t, form, extra)
	}
	return b.sendH1(t, form, extra)
}

// sendH1 reads the header section line by line, so a field value the proxy should never have
// sent reaches the assertions.
func (b *authBench) sendH1(t *testing.T, form string, extra [][2]string) authReply {
	t.Helper()
	var head string
	switch form {
	case formRequest:
		head = "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n"
	case formConnect:
		head = "CONNECT origin.test:80 HTTP/1.1\r\nHost: origin.test:80\r\n"
	case formConnectUDP:
		head = "GET " + connectUDPTargetPath("origin.test", "443") + " HTTP/1.1\r\nHost: " + b.addr +
			"\r\nConnection: Upgrade\r\nUpgrade: " + connectUDPUpgrade + "\r\nCapsule-Protocol: ?1\r\n"
	}
	for _, f := range extra {
		head += f[0] + ": " + f[1] + "\r\n"
	}
	w := b.dial(t)
	w.send(t, head+"\r\n")
	got := w.readHead(t)
	r := authReply{status: headStatus(t, got), header: make(http.Header)}
	for _, line := range strings.Split(strings.TrimSuffix(got, "\r\n\r\n"), "\r\n")[1:] {
		k, v, _ := strings.Cut(line, ":")
		r.header.Add(k, strings.TrimSpace(v))
	}
	return r
}

func (b *authBench) sendH2(t *testing.T, form string, extra [][2]string) authReply {
	t.Helper()
	var fields []hpack.HeaderField
	switch form {
	case formRequest:
		fields = []hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/x")}
	case formConnect:
		fields = []hpack.HeaderField{hf(":method", "CONNECT"), hf(":authority", "origin.test:80")}
	case formConnectUDP:
		fields = []hpack.HeaderField{hf(":method", "CONNECT"), hf(":protocol", connectUDPUpgrade), hf(":scheme", "http"),
			hf(":authority", b.addr), hf(":path", connectUDPTargetPath("origin.test", "443")), hf("capsule-protocol", "?1")}
	}
	for _, f := range extra {
		fields = append(fields, hf(strings.ToLower(f[0]), f[1]))
	}
	h := dialH2(t, b.addr)
	h.headers(t, 1, form == formRequest, fields...)
	f, ok := h.next(t, 1).(*http2.MetaHeadersFrame)
	require.True(t, ok, "the answer starts with HEADERS")
	return replyOf(t, f.Fields)
}

func (b *authBench) sendH3(t *testing.T, form string, extra [][2]string) authReply {
	t.Helper()
	var fields []hpack.HeaderField
	switch form {
	case formRequest:
		fields = []hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https"), hf(":authority", "origin.test"), hf(":path", "/x")}
	case formConnect:
		fields = []hpack.HeaderField{hf(":method", "CONNECT"), hf(":authority", "origin.test:443")}
	case formConnectUDP:
		fields = []hpack.HeaderField{hf(":method", "CONNECT"), hf(":protocol", connectUDPUpgrade), hf(":scheme", "https"),
			hf(":authority", b.h3.String()), hf(":path", connectUDPTargetPath("origin.test", "443")), hf("capsule-protocol", "?1")}
	}
	for _, f := range extra {
		fields = append(fields, hf(strings.ToLower(f[0]), f[1]))
	}
	s := h3Open(t, dialQUICFront(t, b.h3, b.ca), form == formRequest, h3Headers(fields))
	return replyOf(t, s.answer(t))
}

func replyOf(t *testing.T, fields []hpack.HeaderField) authReply {
	t.Helper()
	r := authReply{header: make(http.Header)}
	for _, f := range fields {
		if f.Name == ":status" {
			n, err := strconv.Atoi(f.Value)
			require.NoError(t, err)
			r.status = n
			continue
		}
		r.header.Add(f.Name, f.Value)
	}
	return r
}

const (
	h3FrameData     = 0x00
	h3FrameHeaders  = 0x01
	h3FrameSettings = 0x04
	h3FrameGoAway   = 0x07
)

func h3Headers(fields []hpack.HeaderField) []byte {
	var block bytes.Buffer
	enc := qpack.NewEncoder(&block)
	for _, f := range fields {
		_ = enc.WriteField(qpack.HeaderField{Name: f.Name, Value: f.Value})
	}
	return capsuleOf(h3FrameHeaders, block.Bytes())
}

func h3Data(b string) []byte { return capsuleOf(h3FrameData, []byte(b)) }

func qpackFields(block []byte) ([]hpack.HeaderField, error) {
	var fields []hpack.HeaderField
	next := qpack.NewDecoder().Decode(block)
	for {
		f, err := next()
		if errors.Is(err, io.EOF) {
			return fields, nil
		}
		if err != nil {
			return nil, err
		}
		fields = append(fields, hf(f.Name, f.Value))
	}
}

func h3Open(t *testing.T, qc *quic.Conn, end bool, frames ...[]byte) *h3Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	str, err := qc.OpenStreamSync(ctx)
	require.NoError(t, err)
	s := newH3Stream(str)
	s.send(t, frames...)
	if end {
		closeRequest(t, str)
	}
	return s
}

// closeRequest ends the request on str. A server may stop reading a request before its end,
// RFC 9114 sections 4.1 and 4.1.2, and quic-go fails the close once the STOP_SENDING has arrived.
func closeRequest(t *testing.T, str *quic.Stream) {
	t.Helper()
	if err := str.Close(); err != nil {
		se, ok := errors.AsType[*quic.StreamError](context.Cause(str.Context()))
		require.True(t, ok && se.Remote, "the close of the request stream failed with %v", err)
	}
}

type h3Stream struct {
	*quic.Stream
	br *bufio.Reader
}

func newH3Stream(str *quic.Stream) *h3Stream {
	_ = str.SetDeadline(time.Now().Add(10 * time.Second))
	return &h3Stream{Stream: str, br: bufio.NewReader(str)}
}

func (s *h3Stream) send(t *testing.T, frames ...[]byte) {
	t.Helper()
	_, err := s.Write(bytes.Join(frames, nil))
	require.NoError(t, err)
}

func (s *h3Stream) next() (uint64, []byte, error) { return readCapsule(s.br) }

// answer reads the frames of a response up to its first final HEADERS frame.
func (s *h3Stream) answer(t *testing.T) []hpack.HeaderField {
	t.Helper()
	for {
		typ, payload, err := s.next()
		require.NoError(t, err)
		if typ != h3FrameHeaders {
			continue
		}
		fields, err := qpackFields(payload)
		require.NoError(t, err)
		if status, _ := h2Field(fields, ":status"); !strings.HasPrefix(status, "1") {
			return fields
		}
	}
}

// h3Msg is an HTTP/3 message as its frames crossed a stream. err is what ended the stream when
// no FIN did.
type h3Msg struct {
	err     error
	fields  []hpack.HeaderField
	trailer []hpack.HeaderField
	body    []byte
}

func (m h3Msg) status() string {
	v, _ := h2Field(m.fields, ":status")
	return v
}

// message reads a message up to the end of the stream. A response skips its interim
// answers.
func (s *h3Stream) message(response bool) h3Msg {
	var m h3Msg
	for {
		typ, payload, err := s.next()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				m.err = err
			}
			return m
		}
		switch typ {
		case h3FrameHeaders:
			fields, err := qpackFields(payload)
			if err != nil {
				m.err = err
				return m
			}
			status, _ := h2Field(fields, ":status")
			switch {
			case m.fields == nil && response && strings.HasPrefix(status, "1"):
			case m.fields == nil:
				m.fields = fields
			default:
				m.trailer = fields
			}
		case h3FrameData:
			m.body = append(m.body, payload...)
		}
	}
}

func h3ErrCode(err error) (http3.ErrCode, bool) {
	if code, ok := h3ResetCode(err); ok {
		return code, true
	}
	if e, ok := errors.AsType[*quic.ApplicationError](err); ok {
		return http3.ErrCode(e.ErrorCode), true
	}
	return 0, false
}

// h3Conn is a QUIC connection with an HTTP/3 control stream of its own, and the control stream
// of the peer read in the background.
type h3Conn struct {
	*quic.Conn
	ctrl     *quic.SendStream
	settings chan map[uint64]uint64
	goaway   chan uint64
}

func newH3Conn(qc *quic.Conn) (*h3Conn, error) {
	c := &h3Conn{Conn: qc, settings: make(chan map[uint64]uint64, 1), goaway: make(chan uint64, 4)}
	ctrl, err := qc.OpenUniStream()
	if err != nil {
		return nil, err
	}
	c.ctrl = ctrl
	if _, err := ctrl.Write(append([]byte{0x00}, capsuleOf(h3FrameSettings, nil)...)); err != nil {
		return nil, err
	}
	go func() {
		for {
			rs, err := qc.AcceptUniStream(qc.Context())
			if err != nil {
				return
			}
			go c.readUni(rs)
		}
	}()
	return c, nil
}

func (c *h3Conn) readUni(rs *quic.ReceiveStream) {
	br := bufio.NewReader(rs)
	typ, err := quicvarint.Read(br)
	if err != nil || typ != 0x00 {
		_, _ = io.Copy(io.Discard, br)
		return
	}
	for {
		ft, payload, err := readCapsule(br)
		if err != nil {
			return
		}
		r := bytes.NewReader(payload)
		switch ft {
		case h3FrameSettings:
			s := map[uint64]uint64{}
			for r.Len() > 0 {
				id, err1 := quicvarint.Read(r)
				v, err2 := quicvarint.Read(r)
				if err1 != nil || err2 != nil {
					break
				}
				s[id] = v
			}
			c.settings <- s
		case h3FrameGoAway:
			if id, err := quicvarint.Read(r); err == nil {
				c.goaway <- id
			}
		}
	}
}

func (c *h3Conn) sendGoAway(id uint64) error {
	_, err := c.ctrl.Write(capsuleOf(h3FrameGoAway, quicvarint.Append(nil, id)))
	return err
}

func (c *h3Conn) open(t *testing.T, frames ...[]byte) *h3Stream {
	t.Helper()
	s := h3Open(t, c.Conn, false, frames...)
	t.Cleanup(func() {
		s.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		s.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
	})
	return s
}

func (c *h3Conn) roundTrip(t *testing.T, frames ...[]byte) h3Msg {
	t.Helper()
	s := c.open(t, frames...)
	closeRequest(t, s.Stream)
	return s.message(true)
}

func (c *h3Conn) connect(t *testing.T, authority string) *h3Stream {
	t.Helper()
	s := c.open(t, h3Headers([]hpack.HeaderField{hf(":method", "CONNECT"), hf(":authority", authority)}))
	status, _ := h2Field(s.answer(t), ":status")
	require.Regexp(t, "^2[0-9][0-9]$", status)
	return s
}

func h3Request(method, authority, path string, extra ...hpack.HeaderField) []byte {
	return h3Headers(append([]hpack.HeaderField{
		hf(":method", method), hf(":scheme", "https"), hf(":authority", authority), hf(":path", path),
	}, extra...))
}

func (b *proxyBench) dialH3Front(t *testing.T) *h3Conn {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	front, _ := startQUICFront(t, b.p, ca)
	c, err := newH3Conn(dialQUICFront(t, front, ca))
	require.NoError(t, err)
	return c
}

// newTLSOrigin is newRawOrigin behind TLS with cert, offering http/1.1.
func newTLSOrigin(t *testing.T, cert tls.Certificate, serve func(*rawOrigin, *wire)) *rawOrigin {
	t.Helper()
	return newRawOrigin(t, func(o *rawOrigin, w *wire) {
		serve(o, newWire(tls.Server(w.Conn, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})))
	})
}

// newTLSProxyBench is newProxyBench with the origin behind TLS, where the requests of an
// HTTP/3 front go.
func newTLSProxyBench(t *testing.T, serve func(*rawOrigin, *wire)) *proxyBench {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	cert, err := ca.Leaf("origin.test")
	require.NoError(t, err)
	o := newTLSOrigin(t, *cert, serve)
	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(o.addr)
	tr.RootCAs = poolOf(ca)
	p := testProxy(t, WithTransport(tr))
	p.MustAdd("origin.test/*{any}", forwardHandler)
	return &proxyBench{p: p, origin: o, addr: startProxy(t, p)}
}

func newH3OriginBench(t *testing.T, serve func(*rawOrigin, *h3Conn, *h3Stream)) *proxyBench {
	t.Helper()
	return newH3OriginBenchWith(t, DefaultTransport(), serve)
}

// newH3OriginBenchWith is newH3OriginBench forwarding through tr.
func newH3OriginBenchWith(t *testing.T, tr *Transport, serve func(*rawOrigin, *h3Conn, *h3Stream)) *proxyBench {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	cert, err := ca.Leaf("origin.test")
	require.NoError(t, err)
	o := newRawQUIC(t, *cert, serve)
	tr.AllowHTTP3 = true
	tr.DialContext = pinnedDialer(o.addr)
	tr.RootCAs = poolOf(ca)
	p := testProxy(t, WithTransport(tr))
	p.MustAdd("origin.test/*{any}", forwardHandler)
	return &proxyBench{p: p, origin: o, addr: startProxy(t, p)}
}

// newH2OriginBench is newTLSProxyBench with an origin offering h2 alone, which runs answer past
// the client connection preface.
func newH2OriginBench(t *testing.T, answer func(*rawOrigin, *wire, *http2.Framer)) *proxyBench {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	cert, err := ca.Leaf("origin.test")
	require.NoError(t, err)
	o := newRawOrigin(t, func(o *rawOrigin, w *wire) {
		tw := newWire(tls.Server(w.Conn, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"h2"}}))
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(tw.br, preface); err != nil || string(preface) != http2.ClientPreface {
			return
		}
		fr := http2.NewFramer(tw.Conn, tw.br)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		answer(o, tw, fr)
	})
	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(o.addr)
	tr.RootCAs = poolOf(ca)
	p := testProxy(t, WithTransport(tr))
	p.MustAdd("origin.test/*{any}", forwardHandler)
	return &proxyBench{p: p, origin: o, addr: startProxy(t, p)}
}

func h3Reply(frames ...[]byte) func(*rawOrigin, *h3Conn, *h3Stream) {
	return func(_ *rawOrigin, _ *h3Conn, s *h3Stream) {
		s.message(false)
		if _, err := s.Write(bytes.Join(frames, nil)); err == nil {
			_ = s.Close()
		}
	}
}

// cutResponse sends a GET to an HTTP/3 front whose origin, reached over version, sends a
// header section and four bytes of a ten-byte content, then fails once they reached the client.
// It returns what ended the stream to the client.
func cutResponse(t *testing.T, version string) error {
	t.Helper()
	cut := make(chan struct{})
	release := sync.OnceFunc(func() { close(cut) })
	t.Cleanup(release)
	var b *proxyBench
	if version == viaH3 {
		b = newH3OriginBench(t, func(_ *rawOrigin, _ *h3Conn, s *h3Stream) {
			s.message(false)
			_, _ = s.Write(slices.Concat(h3Headers([]hpack.HeaderField{hf(":status", "200"), hf("content-length", "10")}), h3Data("abcd")))
			<-cut
			s.CancelWrite(quic.StreamErrorCode(http3.ErrCodeInternalError))
		})
	} else {
		b = newTLSProxyBench(t, func(o *rawOrigin, w *wire) {
			if _, err := w.readRequest(); err == nil {
				_, _ = io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabcd")
				<-cut
			}
		})
	}
	s := b.dialH3Front(t).open(t, h3Request("GET", "origin.test", "/"))
	require.NoError(t, s.Close())
	var body []byte
	for len(body) < 4 {
		typ, payload, err := s.next()
		require.NoError(t, err, "the stream ended after %q", body)
		if typ == h3FrameData {
			body = append(body, payload...)
		}
	}
	release()
	return s.message(true).err
}

// wantMalformedRequest checks the answer to a malformed request, a stream error with one of
// codes or a response indicating the error.
func wantMalformedRequest(t *testing.T, got h3Msg, codes ...http3.ErrCode) {
	t.Helper()
	if code, reset := h3ErrCode(got.err); reset {
		assert.Contains(t, codes, code)
		return
	}
	status, err := strconv.Atoi(got.status())
	require.NoError(t, err, "the stream ended with %v", got.err)
	assert.True(t, status >= 400 && status < 500, "the answer to a malformed request is a %d", status)
}

// wantMalformedH1 checks the answer to a malformed request over HTTP/1.1, a close with no
// answer or a response indicating the error.
func wantMalformedH1(t *testing.T, w *wire) {
	t.Helper()
	resp, err := http.ReadResponse(w.br, nil)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
	assert.True(t, resp.StatusCode >= 400 && resp.StatusCode < 500, "the answer to a malformed request is a %d", resp.StatusCode)
}

// wantMalformedH2 checks the answer to a malformed request over HTTP/2, a stream error of
// type PROTOCOL_ERROR or a response indicating the error.
func wantMalformedH2(t *testing.T, got h2Reply) {
	t.Helper()
	if got.reset {
		assert.Equal(t, http2.ErrCodeProtocol, got.rst)
		return
	}
	status, _ := h2Field(got.fields, ":status")
	code, err := strconv.Atoi(status)
	require.NoError(t, err, "the stream ended with no status")
	assert.True(t, code >= 400 && code < 500, "the answer to a malformed request is a %d", code)
}

func upstreamConnect(o *rawOrigin, s *h3Stream) bool {
	typ, payload, err := s.next()
	if err != nil || typ != h3FrameHeaders {
		return false
	}
	fields, err := qpackFields(payload)
	if err != nil {
		return false
	}
	o.got <- requestOf(fields)
	return true
}

type authParam struct {
	name, value string
	quoted      bool
}

// parseChallenge reads a challenge of RFC 9110 section 11.3 followed by auth-params, a
// quoted-string unescaped.
func parseChallenge(s string) (string, []authParam, error) {
	token := func(i int) int {
		for i < len(s) && httpguts.IsTokenRune(rune(s[i])) {
			i++
		}
		return i
	}
	ows := func(i int) int {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		return i
	}
	i := token(0)
	if i == 0 {
		return "", nil, errors.New("no auth-scheme")
	}
	scheme := s[:i]
	if i == len(s) {
		return scheme, nil, nil
	}
	if s[i] != ' ' {
		return "", nil, fmt.Errorf("%q after the auth-scheme", s[i])
	}
	for i < len(s) && s[i] == ' ' {
		i++
	}
	var params []authParam
	for {
		j := token(i)
		if j == i {
			return "", nil, fmt.Errorf("no parameter name at %d", i)
		}
		p := authParam{name: s[i:j]}
		i = ows(j)
		if i == len(s) || s[i] != '=' {
			return "", nil, fmt.Errorf("parameter %s has no value", p.name)
		}
		i = ows(i + 1)
		if i < len(s) && s[i] == '"' {
			p.quoted = true
			var v strings.Builder
			for i++; ; i++ {
				if i == len(s) {
					return "", nil, fmt.Errorf("parameter %s ends inside its quoted-string", p.name)
				}
				c := s[i]
				if c == '"' {
					i++
					break
				}
				if c == '\\' {
					i++
					if i == len(s) || !(s[i] == '\t' || s[i] >= ' ' && s[i] != 0x7f) {
						return "", nil, fmt.Errorf("parameter %s has an invalid quoted-pair", p.name)
					}
					c = s[i]
				} else if !(c == '\t' || c >= ' ' && c != 0x7f) {
					return "", nil, fmt.Errorf("parameter %s has the control character %#x", p.name, c)
				}
				v.WriteByte(c)
			}
			p.value = v.String()
		} else {
			j = token(i)
			if j == i {
				return "", nil, fmt.Errorf("parameter %s has an empty value", p.name)
			}
			p.value, i = s[i:j], j
		}
		params = append(params, p)
		i = ows(i)
		if i == len(s) {
			return scheme, params, nil
		}
		if s[i] != ',' {
			return "", nil, fmt.Errorf("%q after parameter %s", s[i], p.name)
		}
		i = ows(i + 1)
	}
}

// challengeOf returns the parameters of the one Basic challenge of the 407 a request without
// credentials gets on front.
func (b *authBench) challengeOf(t *testing.T, front string) []authParam {
	t.Helper()
	got := b.send(t, front, formRequest)
	require.Equal(t, http.StatusProxyAuthRequired, got.status)
	values := got.header.Values(HeaderProxyAuthenticate)
	require.Len(t, values, 1)
	scheme, params, err := parseChallenge(values[0])
	require.NoError(t, err, values[0])
	require.True(t, strings.EqualFold(scheme, "Basic"), values[0])
	return params
}

var allExits = []string{viaH1, viaH2, viaH3}

// newUpstreamBench builds a proxy chained to a raw upstream proxy over HTTP/1.1, reached with
// the credentials of user when it is not nil. The upstream proxy is the origin of the bench.
func newUpstreamBench(t *testing.T, user *url.Userinfo, serve func(*rawOrigin, *wire), opts ...ProxyOption) *proxyBench {
	t.Helper()
	up := newRawOrigin(t, serve)
	return chainedBench(t, up, url.URL{Scheme: "http", User: user, Host: up.addr}, nil, onTCP, opts...)
}

// newExitBench is newUpstreamBench with the upstream proxy reached over exit, answering every
// CONNECT with answer as it crosses HTTP/1.1. Over HTTP/2 and HTTP/3 each header section of
// answer goes in a HEADERS frame and the bytes behind the last one in a DATA frame.
func newExitBench(t *testing.T, exit string, user *url.Userinfo, answer string, opts ...ProxyOption) *proxyBench {
	t.Helper()
	if exit == viaH1 {
		return newUpstreamBench(t, user, upstreamH1(answer, ""), opts...)
	}
	if exit == viaH3 {
		return newH3UpstreamBench(t, user, upstreamH3(answer), opts...)
	}
	ca, err := GenerateCA()
	require.NoError(t, err)
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	up := newRawOrigin(t, upstreamH2(*cert, answer))
	return chainedBench(t, up, url.URL{Scheme: "https", User: user, Host: up.addr}, ca, onTCP, opts...)
}

func newH3UpstreamBench(t *testing.T, user *url.Userinfo, serve func(*rawOrigin, *h3Conn, *h3Stream), opts ...ProxyOption) *proxyBench {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	up := newRawQUIC(t, *cert, serve)
	return chainedBench(t, up, url.URL{Scheme: "https", User: user, Host: up.addr}, ca, onQUIC, opts...)
}

// chainedBench builds a proxy chained through up. A dial to up over the transport it does not
// listen on is refused. edge tries TCP first for a CONNECT and HTTP/3 first for a CONNECT-UDP,
// and another test may listen on the port of the same number.
func chainedBench(t *testing.T, up *rawOrigin, proxy url.URL, ca *CA, listens backListens, opts ...ProxyOption) *proxyBench {
	t.Helper()
	tr := DefaultTransport()
	if listens != onBoth {
		refused := "tcp"
		if listens == onTCP {
			refused = "udp"
		}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network == refused && addr == up.addr {
				return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
			}
			return defaultDialer.DialContext(ctx, network, addr)
		}
	}
	if ca != nil {
		tr.RootCAs = poolOf(ca)
	}
	tr.Proxy = func(*http.Request) (*url.URL, error) {
		u := proxy
		return &u, nil
	}
	p := testProxy(t, append([]ProxyOption{WithTransport(tr)}, opts...)...)
	p.MustAdd("origin.test/*{any}", forwardHandler)
	p.MustAdd("origin.test", relayStream)
	p.MustAdd("[2001:db8::1]", relayStream)
	return &proxyBench{p: p, origin: up, addr: startProxy(t, p)}
}

// upstreamHeads splits an HTTP/1.1 answer into its header sections, up to the first final
// one, and the bytes behind it. tunnel reports a final 2xx.
func upstreamHeads(answer string) (heads [][]hpack.HeaderField, rest string, tunnel bool) {
	for {
		head, after, ok := strings.Cut(answer, "\r\n\r\n")
		if !ok {
			return heads, answer, false
		}
		lines := strings.Split(head, "\r\n")
		code := lines[0][len("HTTP/1.1 "):len("HTTP/1.1 200")]
		fields := []hpack.HeaderField{hf(":status", code)}
		for _, line := range lines[1:] {
			k, v, _ := strings.Cut(line, ":")
			fields = append(fields, hf(strings.ToLower(k), strings.TrimSpace(v)))
		}
		heads, answer = append(heads, fields), after
		if code[0] != '1' {
			return heads, answer, code[0] == '2'
		}
	}
}

// upstreamH1 answers a CONNECT with answer. Behind a 2xx it records the first five bytes of
// the tunnel and replies pong, behind anything else it ends its direction of the connection
// and records what it reads before the proxy closes. Any other request gets reply.
func upstreamH1(answer, reply string) func(*rawOrigin, *wire) {
	_, _, tunnel := upstreamHeads(answer)
	return func(o *rawOrigin, w *wire) {
		for {
			r, err := w.readRequest()
			if err != nil {
				return
			}
			o.got <- r
			if r.req.Method != "CONNECT" {
				if _, err := io.WriteString(w, reply); err != nil {
					return
				}
				continue
			}
			if _, err := io.WriteString(w, answer); err != nil {
				return
			}
			if !tunnel {
				_ = w.Conn.(*net.TCPConn).CloseWrite()
				rest, _ := io.ReadAll(io.LimitReader(w.br, int64(len("\x01ping"))))
				o.note(string(rest))
				return
			}
			buf := make([]byte, len("\x01ping"))
			if _, err := io.ReadFull(w.br, buf); err != nil {
				return
			}
			o.note(string(buf))
			_, _ = io.WriteString(w, "pong")
			return
		}
	}
}

// requestOf is the request a header section of HTTP/2 or HTTP/3 makes, its :authority as the
// request-target.
func requestOf(fields []hpack.HeaderField) wireRequest {
	r := &http.Request{Header: make(http.Header)}
	for _, f := range fields {
		switch {
		case f.Name == ":method":
			r.Method = f.Value
		case f.Name == ":authority":
			r.Host, r.RequestURI = f.Value, f.Value
		case !strings.HasPrefix(f.Name, ":"):
			r.Header.Add(f.Name, f.Value)
		}
	}
	return wireRequest{req: r, head: r.Method + " " + r.RequestURI}
}

func upstreamH2(cert tls.Certificate, answer string) func(*rawOrigin, *wire) {
	heads, rest, tunnel := upstreamHeads(answer)
	return func(o *rawOrigin, w *wire) {
		tc := tls.Server(w.Conn, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
		if _, err := io.ReadFull(tc, make([]byte, len(http2.ClientPreface))); err != nil {
			return
		}
		fr := http2.NewFramer(tc, tc)
		fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		if err := fr.WriteSettings(); err != nil {
			return
		}
		var got []byte
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					_ = fr.WriteSettingsAck()
				}
			case *http2.PingFrame:
				if !f.IsAck() {
					_ = fr.WritePing(true, f.Data)
				}
			case *http2.MetaHeadersFrame:
				o.got <- requestOf(f.Fields)
				for i, head := range heads {
					buf.Reset()
					for _, field := range head {
						_ = enc.WriteField(field)
					}
					end := i == len(heads)-1 && !tunnel && rest == ""
					_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, BlockFragment: buf.Bytes(), EndHeaders: true, EndStream: end})
				}
				if rest != "" {
					_ = fr.WriteData(f.StreamID, !tunnel, []byte(rest))
				}
			case *http2.DataFrame:
				if !tunnel || len(got) >= len("\x01ping") {
					continue
				}
				if got = append(got, f.Data()...); len(got) >= len("\x01ping") {
					o.note(string(got[:len("\x01ping")]))
					_ = fr.WriteData(f.StreamID, true, []byte("pong"))
				}
			}
		}
	}
}

// newRawQUIC is newRawOrigin for HTTP/3, an origin or an upstream proxy. It opens a control
// stream with an empty SETTINGS frame on each connection and serves every request stream.
func newRawQUIC(t *testing.T, cert tls.Certificate, serve func(*rawOrigin, *h3Conn, *h3Stream)) *rawOrigin {
	t.Helper()
	pc, err := loopbackUDP()
	require.NoError(t, err)
	ln, err := quic.Listen(pc, &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{http3.NextProtoH3}, MinVersion: tls.VersionTLS13,
	}, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	o := &rawOrigin{
		addr:  pc.LocalAddr().String(),
		got:   make(chan wireRequest, 16),
		notes: make(chan string, 16),
		ends:  make(chan struct{}, 16),
	}
	var mu sync.Mutex
	var conns []*quic.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.CloseWithError(0, "")
		}
		mu.Unlock()
		_ = pc.Close()
	})
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			o.accepted.Add(1)
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			go func() {
				c, err := newH3Conn(conn)
				if err != nil {
					return
				}
				for {
					str, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go serve(o, c, newH3Stream(str))
				}
			}()
		}
	}()
	return o
}

func upstreamH3(answer string) func(*rawOrigin, *h3Conn, *h3Stream) {
	heads, rest, tunnel := upstreamHeads(answer)
	return func(o *rawOrigin, _ *h3Conn, s *h3Stream) {
		if !upstreamConnect(o, s) {
			return
		}
		for _, head := range heads {
			if _, err := s.Write(h3Headers(head)); err != nil {
				return
			}
		}
		if rest != "" {
			if _, err := s.Write(h3Data(rest)); err != nil {
				return
			}
		}
		if !tunnel {
			_ = s.Close()
			return
		}
		var got []byte
		for len(got) < len("\x01ping") {
			typ, payload, err := s.next()
			if err != nil {
				return
			}
			if typ == h3FrameData {
				got = append(got, payload...)
			}
		}
		o.note(string(got[:len("\x01ping")]))
		if _, err := s.Write(h3Data("pong")); err == nil {
			_ = s.Close()
		}
	}
}

// tunnel opens a tunnel to target through the proxy, with the extra field lines, and writes
// the first bytes of a protocol the proxy relays as a byte stream.
func (b *proxyBench) tunnel(t *testing.T, target, extra string) *wire {
	t.Helper()
	w := dialWire(t, b.addr)
	w.send(t, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n"+extra+"\r\n")
	require.Equal(t, http.StatusOK, headStatus(t, w.readHead(t)))
	w.send(t, "\x01ping")
	return w
}

// connectCredentials sends an https request through the proxy and returns the
// Proxy-Authorization values of the CONNECT the upstream proxy received. sent is false when
// the proxy answered the client with an error and never reached the upstream proxy.
func (b *proxyBench) connectCredentials(t *testing.T) (values []string, sent bool) {
	t.Helper()
	got := b.exchange(t, "GET", "GET https://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	select {
	case r := <-b.origin.got:
		return r.req.Header.Values("Proxy-Authorization"), true
	case <-time.After(300 * time.Millisecond):
	}
	require.Zero(t, b.origin.accepted.Load(), "the proxy reached the upstream proxy and sent no CONNECT")
	require.GreaterOrEqual(t, got.resp.StatusCode, http.StatusBadRequest)
	return nil, false
}

// wantRelayed checks that the reply of the upstream proxy came back behind first, the upstream
// proxy replying once the bytes of the tunnel reached it.
func (b *proxyBench) wantRelayed(t *testing.T, w *wire, first string) {
	t.Helper()
	got := make([]byte, len(first)+len("pong"))
	n, err := io.ReadFull(w.br, got)
	require.NoError(t, err, "the tunnel ended after %q", got[:n])
	assert.Equal(t, first+"pong", string(got))
	assert.Equal(t, "\x01ping", b.origin.nextNote(t))
}

// wantNoTunnel checks that nothing crossed a tunnel that was never formed, ended cleanly or
// reset.
func wantNoTunnel(t *testing.T, w *wire) {
	t.Helper()
	rest, err := io.ReadAll(w.br)
	if err != nil {
		require.ErrorIs(t, err, syscall.ECONNRESET)
	}
	assert.Empty(t, string(rest))
}

var selfLoopFronts = []string{"explicit", "explicit-tls", "connect", "connect-tls", "redirected", "redirected-tls", "socks5", "quic", "quic-chained"}

// selfLoop sends one request through a proxy configured so that forwarding it reaches the proxy
// again, on front, and returns the status the client got and how many times the entry handled
// the request. The dials are bounded, so a loop ends after a few turns and before the sockets
// of the host run out.
func selfLoop(t *testing.T, front string) (int, int32) {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	var dials, handled atomic.Int32
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	bounded := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if dials.Add(1) > 8 {
			return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
		}
		return dialer.DialContext(ctx, network, addr)
	}
	tr := DefaultTransport()
	tr.DialContext = bounded
	tr.RootCAs = poolOf(ca)
	handler := func(c *HTTPCtx) (*http.Response, error) {
		handled.Add(1)
		return c.Forward()
	}

	if front == "quic" || front == "quic-chained" {
		tr.AllowHTTP3 = true
		var self atomic.Pointer[url.URL]
		if front == "quic-chained" {
			tr.Proxy = func(*http.Request) (*url.URL, error) { return self.Load(), nil }
		}
		p := testProxyWithCA(t, ca, WithTransport(tr))
		p.MustAdd("127.0.0.1/*{any}", handler)
		addr, _ := startQUICFront(t, p, ca)
		self.Store(&url.URL{Scheme: "https", Host: addr.String()})
		c, err := newH3Conn(dialQUICFront(t, addr, ca))
		require.NoError(t, err)
		got := c.roundTrip(t, h3Request("GET", addr.String(), "/loop"))
		status, _ := h2Field(got.fields, ":status")
		code, _ := strconv.Atoi(status)
		return code, handled.Load()
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	switch front {
	case "explicit", "connect", "connect-tls":
		tr.Proxy = fixedProxy("http://" + addr)
	case "explicit-tls":
		tr.Proxy = fixedProxy("https://" + addr)
	case "socks5":
		tr.Proxy = fixedProxy("socks5://" + addr)
	case "redirected-tls":
		// A redirect that also catches the connections of the proxy, which then reach its
		// listener with the destination they were dialed to, as SO_ORIGINAL_DST would report it.
		var redirected sync.Map
		tr.DialContext = func(ctx context.Context, network, to string) (net.Conn, error) {
			c, err := bounded(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			dst := netip.MustParseAddrPort(to)
			redirected.Store(addrPort(c.LocalAddr()), dst)
			return natConn{Conn: c, dst: dst}, nil
		}
		ln = originListener{Listener: ln, origin: func(c net.Conn) (netip.AddrPort, error) {
			if dst, ok := redirected.Load(addrPort(c.RemoteAddr())); ok {
				return dst.(netip.AddrPort), nil
			}
			return netip.MustParseAddrPort("192.0.2.1:443"), nil
		}}
	}
	p := testProxyWithCA(t, ca, WithTransport(tr))
	p.MustAdd("origin.test/*{any}", handler)
	p.MustAdd("127.0.0.1/*{any}", handler)
	switch front {
	case "socks5":
		go func() { _ = p.ServeSOCKS5(ln) }()
	case "redirected":
		self := netip.MustParseAddrPort(addr)
		go func() {
			_ = p.ServeTransparent(originListener{Listener: ln, origin: func(net.Conn) (netip.AddrPort, error) { return self, nil }})
		}()
	case "redirected-tls":
		go func() { _ = p.ServeTransparent(ln) }()
	case "explicit-tls":
		cert, err := ca.Leaf("127.0.0.1")
		require.NoError(t, err)
		go func() { _ = p.ServeTLS(ln, *cert) }()
	default:
		go func() { _ = p.Serve(ln) }()
	}
	t.Cleanup(func() { _ = p.Close() })

	var c net.Conn
	req := "GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n"
	switch front {
	case "explicit", "explicit-tls":
		req = "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n"
		c = dialWire(t, addr).Conn
	case "connect":
		c = connectRaw(t, addr, "origin.test:80")
	case "connect-tls":
		c = connectRaw(t, addr, "origin.test:443")
	case "redirected":
		req = "GET /loop HTTP/1.1\r\nHost: " + addr + "\r\n\r\n"
		c = dialWire(t, addr).Conn
	case "redirected-tls":
		c = dialWire(t, addr).Conn
	case "socks5":
		w := socksConnect(t, addr, socksNameBytes("origin.test", 80))
		require.Equal(t, socksGranted4[:2], w.readReply()[:2])
		c = w.conn
	}
	require.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second)))
	switch front {
	case "explicit-tls":
		c = tls.Client(c, &tls.Config{ServerName: "127.0.0.1", RootCAs: ca.CertPool(), NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	case "connect-tls", "redirected-tls":
		c = tls.Client(c, &tls.Config{ServerName: "origin.test", RootCAs: ca.CertPool(), NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	}
	w := newWire(c)
	w.originForm = !strings.HasPrefix(front, "explicit")
	w.send(t, req)
	return w.readResponse(t, "GET").resp.StatusCode, handled.Load()
}

// natConn reports the destination a redirect diverted it from, as the peer address of a
// redirected socket does.
type natConn struct {
	net.Conn
	dst netip.AddrPort
}

func (c natConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.dst) }

// invalidAuthorities are authorities whose host RFC 3986 does not allow.
var invalidAuthorities = []string{"ori\"gin.test", "ori<gin>.test", "ori\\gin.test", "ori{gin}.test", "origin.test\x80", "ori%zzgin.test"}

// proxyConformance lists the requirements HTTP places on a proxy, checked with a raw client in
// front of edge and a raw origin behind it.
var proxyConformance = []conformanceCase{
	// RFC 7617, the Basic scheme.
	{
		id: "rfc7617/2/1", name: "a request without credentials",
		req: "The authentication parameter 'realm' is REQUIRED ([RFC7235], Section 2.2).",
		run: func(t *testing.T) {
			b := newAuthBench(t, "edge", always(okReply))
			for _, front := range allFronts {
				t.Run(front, func(t *testing.T) {
					var realms []string
					for _, p := range b.challengeOf(t, front) {
						if strings.EqualFold(p.name, "realm") {
							realms = append(realms, p.value)
						}
					}
					assert.Equal(t, []string{"edge"}, realms)
				})
			}
		},
	},
	{
		id: "rfc7617/2/2", name: "credentials whose scheme is in another case",
		req: "Note that both scheme and parameter names are matched case-insensitively.",
		run: func(t *testing.T) {
			b := newAuthBench(t, "edge", always(okReply))
			for _, front := range allFronts {
				for _, scheme := range []string{"basic", "BASIC", "bAsIc"} {
					t.Run(front+" "+scheme, func(t *testing.T) {
						got := b.send(t, front, formRequest, [2]string{"Proxy-Authorization", scheme + " QWxhZGRpbjpvcGVuIHNlc2FtZQ=="})
						assert.Equal(t, http.StatusOK, got.status)
						assert.Equal(t, [2]string{"Aladdin", "open sesame"}, b.nextCreds(t))
					})
				}
			}
		},
	},
	{
		id: "rfc7617/2/3", name: "a password with colons in it",
		req: "Furthermore, a user-id containing a colon character is invalid, as the first colon in a user-pass string separates user-id and password from one another; text after the first colon is part of the password.",
		run: func(t *testing.T) {
			b := newAuthBench(t, "edge", always(okReply))
			for _, front := range allFronts {
				t.Run(front, func(t *testing.T) {
					got := b.send(t, front, formRequest, [2]string{"Proxy-Authorization", basicCredentials("iam", "my:;self")})
					assert.Equal(t, http.StatusOK, got.status)
					assert.Equal(t, [2]string{"iam", "my:;self"}, b.nextCreds(t))
				})
			}
		},
	},
	{
		id: "rfc7617/2/4", name: "a CONNECT through an upstream proxy URL with the user-id Aladdin and the password open sesame",
		req: "To receive authorization, the client 1. obtains the user-id and password from the user, 2. constructs the user-pass by concatenating the user-id, a single colon (\":\") character, and the password, 3. encodes the user-pass into an octet sequence (see below for a discussion of character encoding schemes), 4. and obtains the basic-credentials by encoding this octet sequence using Base64 ([RFC4648], Section 4) into a sequence of US-ASCII characters ([RFC0020]).",
		run: func(t *testing.T) {
			for _, exit := range allExits {
				t.Run(exit, func(t *testing.T) {
					b := newExitBench(t, exit, url.UserPassword("Aladdin", "open sesame"), "HTTP/1.1 200 OK\r\n\r\n")
					b.tunnel(t, "origin.test:80", "")
					assert.Equal(t, []string{authAladdin}, b.origin.next(t).req.Header.Values("Proxy-Authorization"))
				})
			}
		},
	},
	{
		id: "rfc7617/2/5", name: "an https request through an upstream proxy URL whose user-id has a colon in it",
		req: "Furthermore, a user-id containing a colon character is invalid, as the first colon in a user-pass string separates user-id and password from one another; text after the first colon is part of the password.",
		run: func(t *testing.T) {
			for _, exit := range allExits {
				t.Run(exit, func(t *testing.T) {
					b := newExitBench(t, exit, url.UserPassword("ali:ce", "pw"), "HTTP/1.1 200 OK\r\n\r\n")
					values, sent := b.connectCredentials(t)
					if !sent {
						return
					}
					for _, v := range values {
						user, pass, err := decodeBasic(v)
						assert.Fail(t, "credentials for a user-id with a colon", "%q, user-id %q, password %q, %v", v, user, pass, err)
					}
				})
			}
		},
	},
	{
		id: "rfc7617/2/6", name: "an https request through an upstream proxy URL whose password has a control character in it",
		req: "The user-id and password MUST NOT contain any control characters (see \"CTL\" in Appendix B.1 of [RFC5234]).",
		run: func(t *testing.T) {
			for _, exit := range allExits {
				t.Run(exit, func(t *testing.T) {
					b := newExitBench(t, exit, url.UserPassword("alice", "pa\x01ss"), "HTTP/1.1 200 OK\r\n\r\n")
					values, sent := b.connectCredentials(t)
					if !sent {
						return
					}
					for _, v := range values {
						user, pass, err := decodeBasic(v)
						assert.Fail(t, "credentials for a password with a control character", "%q, user-id %q, password %q, %v", v, user, pass, err)
					}
				})
			}
		},
	},
	{
		id: "rfc7617/2.1/1", name: "a request without credentials",
		req: "The only allowed value is \"UTF-8\"; it is to be matched case-insensitively (see [RFC2978], Section 2.3).",
		run: func(t *testing.T) {
			b := newAuthBench(t, "edge", always(okReply))
			for _, front := range allFronts {
				t.Run(front, func(t *testing.T) {
					for _, p := range b.challengeOf(t, front) {
						if strings.EqualFold(p.name, "charset") {
							assert.True(t, strings.EqualFold(p.value, "UTF-8"), p.value)
						}
					}
				})
			}
		},
	},
	{
		id: "rfc7617/2.1/2", name: "the user-id test and a password ending in a pound sign",
		req: "For the password, recipients MUST support all characters defined in the \"OpaqueString\" profile defined in Section 4.2 of [RFC7613].",
		run: func(t *testing.T) {
			b := newAuthBench(t, "edge", always(okReply))
			for _, front := range allFronts {
				t.Run(front, func(t *testing.T) {
					got := b.send(t, front, formRequest, [2]string{"Proxy-Authorization", authTest})
					assert.Equal(t, http.StatusOK, got.status)
					assert.Equal(t, [2]string{"test", "123£"}, b.nextCreds(t))
				})
			}
		},
	},
	{
		id: "rfc7617/2.1/3", name: "a user-id outside US-ASCII",
		req: "For the user-id, recipients MUST support all characters defined in the \"UsernameCasePreserved\" profile defined in Section 3.3 of [RFC7613], with the exception of the colon (\":\") character.",
		run: func(t *testing.T) {
			b := newAuthBench(t, "edge", always(okReply))
			for _, front := range allFronts {
				t.Run(front, func(t *testing.T) {
					got := b.send(t, front, formRequest, [2]string{"Proxy-Authorization", basicCredentials("Ünïcødé", "pässwörd")})
					assert.Equal(t, http.StatusOK, got.status)
					assert.Equal(t, [2]string{"Ünïcødé", "pässwörd"}, b.nextCreds(t))
				})
			}
		},
	},

	// RFC 9110 section 6.5, trailer fields.
	{
		id: "rfc9110/6.5.1/1", name: "a chunked response with a trailer field",
		req: "A recipient MUST NOT merge a trailer field into a header section unless the recipient understands the corresponding header field definition and that definition explicitly permits and defines how trailer field values can be safely merged.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always("HTTP/1.1 200 OK\r\nTrailer: X-Check\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Check: sum\r\n\r\n"))
				_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTE: trailers\r\n\r\n")
				require.NoError(t, got.err)
				assert.Equal(t, "ok", string(got.body))
				assert.Empty(t, fieldValues(got.head, "X-Check"), "a trailer field is not a header field")
				assert.Equal(t, "sum", got.resp.Trailer.Get("X-Check"))
			})
		},
	},
	{
		id: "rfc9110/6.5.1/2", name: "a chunked request with a trailer field",
		req: "A recipient MUST NOT merge a trailer field into a header section unless the recipient understands the corresponding header field definition and that definition explicitly permits and defines how trailer field values can be safely merged.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got, _ := b.forwarded(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTrailer: X-Check\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-Check: sum\r\n\r\n")
				assert.Equal(t, "hi", string(got.body))
				assert.Empty(t, fieldValues(got.head, "X-Check"), "a trailer field is not a header field")
			})
		},
	},
	{
		id: "rfc9110/6.5.1/3", name: "a request without TE",
		req: "The presence of the keyword \"trailers\" in the TE header field (Section 10.1.4) of a request indicates that the client is willing to accept trailer fields, on behalf of itself and any downstream clients.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got, _ := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				assert.Empty(t, fieldValues(got.head, "TE"), "no client promised to accept trailers")
			})
		},
	},

	{
		id: "rfc9110/6.5.1/4", name: "an HTTP/2 or HTTP/3 request without content with a trailer field",
		req: "A recipient MUST NOT merge a trailer field into a header section unless the recipient understands the corresponding header field definition and that definition explicitly permits and defines how trailer field values can be safely merged.",
		run: func(t *testing.T) {
			const want = `header="" trailer="sum"`
			request := []hpack.HeaderField{
				hf(":method", "POST"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"),
				hf("content-length", "0"), hf("trailer", "x-check"),
			}
			t.Run("h2-to-h1", func(t *testing.T) {
				eachH2Front(t, h1UpstreamFronts, func(t *testing.T, front string) {
					b, h := h2FrontBench(t, front, noteTrailerH1)
					h.headers(t, 1, false, request...)
					h.headers(t, 1, true, hf("x-check", "sum"))
					assert.Equal(t, "ok", string(h.reply(t, 1).body))
					assert.Equal(t, want, b.origin.nextNote(t))
				})
			})
			t.Run("h2-to-h2", func(t *testing.T) {
				eachDeclaredFront(t, func(t *testing.T, front string) {
					o := prefaceOrigin(t, noteTrailerH2)
					h := h2cStream(t, front, o, false, "POST", request[4:]...)
					h.headers(t, 1, true, hf("x-check", "sum"))
					assert.Equal(t, "ok", string(h.reply(t, 1).body))
					require.Equal(t, http2.ClientPreface, o.nextNote(t))
					assert.Equal(t, want, o.nextNote(t))
				})
			})
			for _, origin := range []string{viaH1, viaH2, viaH3} {
				t.Run("h3-to-"+origin, func(t *testing.T) {
					var b *proxyBench
					switch origin {
					case viaH1:
						b = newTLSProxyBench(t, noteTrailerH1)
					case viaH2:
						b = newH2OriginBench(t, noteTrailerH2)
					default:
						b = newH3OriginBench(t, noteTrailerH3)
					}
					got := b.dialH3Front(t).roundTrip(t, h3Request("POST", "origin.test", "/", request[4:]...), h3Headers([]hpack.HeaderField{hf("x-check", "sum")}))
					require.NoError(t, got.err)
					assert.Equal(t, "ok", string(got.body))
					assert.Equal(t, want, b.origin.nextNote(t))
				})
			}
		},
	},

	{
		id: "rfc9110/6.5.1/5", name: "a request with content and a trailer field",
		req: "A recipient MUST NOT merge a trailer field into a header section unless the recipient understands the corresponding header field definition and that definition explicitly permits and defines how trailer field values can be safely merged.",
		run: func(t *testing.T) {
			const want = `header="" trailer="sum"`
			request := []hpack.HeaderField{
				hf(":method", "POST"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"), hf("trailer", "x-check"),
			}
			t.Run("h1-to-h1", func(t *testing.T) {
				eachProxyFront(t, func(t *testing.T, front proxyFront) {
					b := newProxyBenchOn(t, front, noteTrailerH1)
					got := b.exchange(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTrailer: X-Check\r\n"+
						"Transfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-Check: sum\r\n\r\n")
					assert.Equal(t, "ok", string(got.body))
					assert.Equal(t, want, b.origin.nextNote(t))
				})
			})
			t.Run("h2-to-h1", func(t *testing.T) {
				eachH2Front(t, h1UpstreamFronts, func(t *testing.T, front string) {
					b, h := h2FrontBench(t, front, noteTrailerH1)
					h.headers(t, 1, false, request...)
					require.NoError(t, h.fr.WriteData(1, false, []byte("hi")))
					h.headers(t, 1, true, hf("x-check", "sum"))
					assert.Equal(t, "ok", string(h.reply(t, 1).body))
					assert.Equal(t, want, b.origin.nextNote(t))
				})
			})
			t.Run("h2-to-h2", func(t *testing.T) {
				eachDeclaredFront(t, func(t *testing.T, front string) {
					o := prefaceOrigin(t, noteTrailerH2)
					h := h2cStream(t, front, o, false, "POST", hf("content-length", "2"), hf("trailer", "x-check"))
					require.NoError(t, h.fr.WriteData(1, false, []byte("hi")))
					h.headers(t, 1, true, hf("x-check", "sum"))
					assert.Equal(t, "ok", string(h.reply(t, 1).body))
					require.Equal(t, http2.ClientPreface, o.nextNote(t))
					assert.Equal(t, want, o.nextNote(t))
				})
			})
			for _, origin := range []string{viaH1, viaH2, viaH3} {
				t.Run("h3-to-"+origin, func(t *testing.T) {
					var b *proxyBench
					switch origin {
					case viaH1:
						b = newTLSProxyBench(t, noteTrailerH1)
					case viaH2:
						b = newH2OriginBench(t, noteTrailerH2)
					default:
						b = newH3OriginBench(t, noteTrailerH3)
					}
					got := b.dialH3Front(t).roundTrip(t, h3Request("POST", "origin.test", "/", request[4:]...), h3Data("hi"),
						h3Headers([]hpack.HeaderField{hf("x-check", "sum")}))
					require.NoError(t, got.err)
					assert.Equal(t, "ok", string(got.body))
					assert.Equal(t, want, b.origin.nextNote(t))
				})
			}
		},
	},
	{
		id: "rfc9110/6.5.1/6", name: "an HTTP/2 GET without content with a trailer field, toward an HTTP/1.1 origin",
		req:  "A recipient MUST NOT merge a trailer field into a header section unless the recipient understands the corresponding header field definition and that definition explicitly permits and defines how trailer field values can be safely merged.",
		skip: "net/http reads the body of a GET with a Content-Length of 0 before sending it, and a body that ends there is sent with neither chunked framing nor a Trailer field, so the HTTP/1.1 origin receives no trailer section. edge does not choose the framing of an HTTP/1.1 request.",
	},
	{
		id: "rfc9110/6.5.1/7", name: "an HTTP/2 request with a Content-Length and a trailer field, toward an HTTP/1.1 origin",
		req:  "A recipient MUST NOT merge a trailer field into a header section unless the recipient understands the corresponding header field definition and that definition explicitly permits and defines how trailer field values can be safely merged.",
		skip: "net/http sends a request with a Content-Length without chunked framing, so the HTTP/1.1 origin receives the content and no trailer section. edge keeps the Content-Length the client sent and does not choose the framing of an HTTP/1.1 request.",
	},

	// RFC 9110 section 7, routing.
	{
		id: "rfc9110/7.1/1", name: "GET with an authority-form or an asterisk-form target",
		req: "These forms MUST NOT be used with other methods.",
		run: func(t *testing.T) {
			for _, target := range []string{"origin.test:80", "*"} {
				t.Run(target, func(t *testing.T) {
					eachProxyFront(t, func(t *testing.T, front proxyFront) {
						b := newProxyBenchOn(t, front, always(okReply))
						got := b.exchange(t, "GET", "GET "+target+" HTTP/1.1\r\nHost: origin.test:80\r\n\r\n")
						assert.Contains(t, []int{http.StatusBadRequest, http.StatusMovedPermanently}, got.resp.StatusCode)
						assert.Equal(t, int32(0), b.origin.accepted.Load(), "the request was forwarded with a form its method does not allow")
					})
				})
			}
		},
	},
	{
		id: "rfc9110/7.4/1", name: "a request for a host the certificate of its connection does not cover",
		req: "In particular, a request for an \"https\" resource MUST be rejected unless it has been received over a connection that has been secured via a certificate valid for that target URI's origin, as defined by Section 4.2.2.",
		run: func(t *testing.T) {
			eachTerminatedFront(t, []string{viaH1, viaH1WithoutALPN, viaH2, viaH3}, func(t *testing.T, front, version string) {
				b := newMisdirectBench(t)
				_, get := dialTerminated(t, b, front, version, "origin.test")
				for _, host := range []string{"other.test", "other.test:443", "127.0.0.1"} {
					code, body := get(t, host)
					assert.Equal(t, http.StatusMisdirectedRequest, code, host)
					assert.Equal(t, http.StatusText(http.StatusMisdirectedRequest)+"\n", body, host)
				}
				code, _ := get(t, "origin.test")
				assert.Equal(t, http.StatusOK, code)
				assert.Equal(t, "origin.test", b.origin.next(t).req.Host, "the first request reaching the origin")
			})
		},
	},
	{
		id: "rfc9110/7.4/2", name: "a request for the host of the certificate of its connection, in another case, with a root dot or another port",
		req: "In particular, a request for an \"https\" resource MUST be rejected unless it has been received over a connection that has been secured via a certificate valid for that target URI's origin, as defined by Section 4.2.2.",
		run: func(t *testing.T) {
			eachTerminatedFront(t, []string{viaH1, viaH1WithoutALPN, viaH2, viaH3}, func(t *testing.T, front, version string) {
				b := newMisdirectBench(t)
				_, get := dialTerminated(t, b, front, version, "Origin.Test")
				for _, host := range []string{"origin.test", "ORIGIN.TEST.", "origin.test:8443"} {
					code, _ := get(t, host)
					assert.Equal(t, http.StatusOK, code, host)
					assert.Equal(t, host, b.origin.next(t).req.Host)
				}
			})
		},
	},
	{
		id: "rfc9110/7.4/3", name: "a request on a TLS connection without a server name",
		req: "In particular, a request for an \"https\" resource MUST be rejected unless it has been received over a connection that has been secured via a certificate valid for that target URI's origin, as defined by Section 4.2.2.",
		run: func(t *testing.T) {
			eachTerminatedFront(t, []string{viaH1, viaH1WithoutALPN, viaH2, viaH3}, func(t *testing.T, front, version string) {
				b := newMisdirectBench(t)
				leaf, get := dialTerminated(t, b, front, version, "")
				code, _ := get(t, "other.test")
				assert.Equal(t, http.StatusMisdirectedRequest, code)
				host := leafHost(leaf)
				code, _ = get(t, host)
				assert.Equal(t, http.StatusOK, code, host)
				assert.Equal(t, host, b.origin.next(t).req.Host, "the first request reaching the origin")
			})
		},
	},
	{
		id: "rfc9110/7.6/1", name: "an unregistered method, field and status code",
		req: "Intermediaries are expected to forward messages even when protocol elements are not recognized (e.g., new methods, status codes, or field names) since that preserves extensibility for downstream recipients.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always("HTTP/1.1 299 Unregistered\r\nX-Unknown-Reply: r\r\nContent-Length: 2\r\n\r\nok"))
				got, resp := b.forwarded(t, "FROB", "FROB http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\nX-Unknown-Field: f\r\n\r\n")
				assert.Equal(t, "FROB /x HTTP/1.1", startLine(got.head))
				assert.Equal(t, []string{"f"}, fieldValues(got.head, "X-Unknown-Field"))
				assert.Equal(t, 299, resp.resp.StatusCode)
				assert.Equal(t, []string{"r"}, fieldValues(resp.head, "X-Unknown-Reply"))
			})
		},
	},
	{
		id: "rfc9110/7.6/2", name: "a request whose target is the proxy itself",
		req: "An intermediary MUST NOT forward a message to itself unless it is protected from an infinite request loop.",
		run: func(t *testing.T) {
			for _, front := range selfLoopFronts {
				t.Run(front, func(t *testing.T) {
					status, handled := selfLoop(t, front)
					assert.NotEqual(t, http.StatusOK, status)
					assert.Equal(t, int32(1), handled, "the request came back to the proxy")
				})
			}
		},
	},
	{
		id: "rfc9110/7.6.1/1", name: "a request listing fields in Connection",
		req: "Intermediaries MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header or trailer field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself (or replace it with the intermediary's own control options for the forwarded message).",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got, _ := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n"+
					"Connection: X-Hop-A, keep-alive\r\nconnection: x-hop-b\r\nX-HOP-A: 1\r\nx-hop-b: 2\r\nX-End: 3\r\n\r\n")
				assert.Empty(t, fieldValues(got.head, "Connection"))
				assert.Empty(t, fieldValues(got.head, "X-Hop-A"))
				assert.Empty(t, fieldValues(got.head, "X-Hop-B"))
				assert.Equal(t, []string{"3"}, fieldValues(got.head, "X-End"))
			})
		},
	},
	{
		id: "rfc9110/7.6.1/2", name: "a response listing fields in Connection",
		req: "Intermediaries MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header or trailer field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself (or replace it with the intermediary's own control options for the forwarded message).",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always("HTTP/1.1 200 OK\r\nConnection: X-Hop\r\nX-Hop: 1\r\nX-End: 2\r\nContent-Length: 2\r\n\r\nok"))
				_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				assert.Empty(t, fieldValues(got.head, "Connection"))
				assert.Empty(t, fieldValues(got.head, "X-Hop"))
				assert.Equal(t, []string{"2"}, fieldValues(got.head, "X-End"))
			})
		},
	},
	{
		id: "rfc9110/7.6.1/3", name: "a response trailer field listed in Connection",
		req: "Intermediaries MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header or trailer field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself (or replace it with the intermediary's own control options for the forwarded message).",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always("HTTP/1.1 200 OK\r\nConnection: X-Hop\r\nTrailer: X-Hop, X-Check\r\nTransfer-Encoding: chunked\r\n\r\n"+
					"2\r\nok\r\n0\r\nX-Hop: secret\r\nX-Check: sum\r\n\r\n"))
				_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTE: trailers\r\n\r\n")
				require.NoError(t, got.err)
				assert.Equal(t, "sum", got.resp.Trailer.Get("X-Check"))
				assert.Empty(t, got.resp.Trailer.Values("X-Hop"))
			})
		},
	},
	{
		id: "rfc9110/7.6.1/4", name: "a request trailer field listed in Connection",
		req: "Intermediaries MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header or trailer field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself (or replace it with the intermediary's own control options for the forwarded message).",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got, _ := b.forwarded(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nConnection: X-Hop\r\n"+
					"Trailer: X-Hop\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-Hop: secret\r\n\r\n")
				assert.Empty(t, fieldValues(got.head, "X-Hop"))
				assert.Empty(t, got.req.Trailer.Values("X-Hop"))
			})
		},
	},
	{
		id: "rfc9110/7.6.1/5", name: "a request with Proxy-Connection, Keep-Alive, TE and Upgrade",
		req: "Furthermore, intermediaries SHOULD remove or replace fields that are known to require removal before forwarding, whether or not they appear as a connection-option, after applying those fields' semantics.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got, _ := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n"+
					"Proxy-Connection: keep-alive\r\nKeep-Alive: timeout=5\r\nTE: gzip\r\nUpgrade: h2c\r\n\r\n")
				for _, name := range []string{"Proxy-Connection", "Keep-Alive", "TE", "Upgrade", "Connection"} {
					assert.Empty(t, fieldValues(got.head, name), name)
				}
			})
		},
	},
	{
		id: "rfc9110/7.6.1/6", name: "a response with Proxy-Connection, Keep-Alive and Upgrade",
		req: "Furthermore, intermediaries SHOULD remove or replace fields that are known to require removal before forwarding, whether or not they appear as a connection-option, after applying those fields' semantics.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always("HTTP/1.1 200 OK\r\nProxy-Connection: keep-alive\r\nKeep-Alive: timeout=5\r\nUpgrade: h2c\r\nContent-Length: 2\r\n\r\nok"))
				_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				for _, name := range []string{"Proxy-Connection", "Keep-Alive", "Upgrade"} {
					assert.Empty(t, fieldValues(got.head, name), name)
				}
			})
		},
	},
	{
		id: "rfc9110/7.6.2/1", name: "TRACE with Max-Forwards 0",
		req: "If the received value is zero (0), the intermediary MUST NOT forward the request; instead, the intermediary MUST respond as the final recipient.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got := b.exchange(t, "TRACE", "TRACE http://origin.test/t HTTP/1.1\r\nHost: origin.test\r\nMax-Forwards: 0\r\n\r\n")
				assert.NotZero(t, got.resp.StatusCode)
				b.origin.none(t)
			})
		},
	},
	{
		id: "rfc9110/7.6.2/2", name: "OPTIONS with Max-Forwards 5",
		req: "If the received Max-Forwards value is greater than zero, the intermediary MUST generate an updated Max-Forwards field in the forwarded message with a field value that is the lesser of a) the received value decremented by one (1) or b) the recipient's maximum supported value for Max-Forwards.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got, _ := b.forwarded(t, "OPTIONS", "OPTIONS http://origin.test/o HTTP/1.1\r\nHost: origin.test\r\nMax-Forwards: 5\r\n\r\n")
				assert.Equal(t, []string{"4"}, fieldValues(got.head, "Max-Forwards"))
			})
		},
	},
	{
		id: "rfc9110/7.6.3/1", name: "Via on a forwarded message",
		req:  "A proxy MUST send an appropriate Via header field, as described below, in each message that it forwards.",
		skip: "Edge adds nothing to a forwarded message, no Via and no X-Forwarded-For, so the application under test cannot detect a proxy in front of it, as CLAUDE.md states.",
	},
	{
		id: "rfc9110/7.7/1", name: "an absolute-form target with a fully qualified domain name",
		req: "A proxy MUST NOT change the host name if the target URI contains a fully qualified domain name.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got, _ := b.forwarded(t, "GET", "GET http://Origin.Test.:8080/x HTTP/1.1\r\nHost: Origin.Test.:8080\r\n\r\n")
				assert.Equal(t, []string{"Origin.Test.:8080"}, fieldValues(got.head, "Host"))
			})
		},
	},
	{
		id: "rfc9110/7.7/2", name: "a path and a query the origin may not normalize",
		req: "A proxy MUST NOT modify the \"absolute-path\" and \"query\" parts of the received target URI when forwarding it to the next inbound server except as required by that forwarding protocol.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				const target = "/a/%7Euser/./b/../c//d%2Fe;p=1?q=%2F&x=a+b&&y=%7e"
				got, _ := b.forwarded(t, "GET", "GET http://origin.test"+target+" HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				assert.Equal(t, "GET "+target+" HTTP/1.1", startLine(got.head))
			})
		},
	},
	{
		id: "rfc9110/7.7/3", name: "an absolute-form target with an empty path",
		req: "For example, a proxy forwarding a request to an origin server via HTTP/1.1 will replace an empty path with \"/\" (Section 3.2.1 of [HTTP/1.1]) or \"*\" (Section 3.2.4 of [HTTP/1.1]), depending on the request method.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				w := b.dial(t)
				w.originForm = false
				w.send(t, "GET "+front.scheme()+"://origin.test HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				w.readResponse(t, "GET")
				assert.Equal(t, "GET / HTTP/1.1", startLine(b.origin.next(t).head))
			})
		},
	},
	{
		id: "rfc9110/7.7/4", name: "a response with the no-transform directive",
		req: "A proxy MUST NOT transform the content (Section 6.4) of a response message that contains a no-transform cache directive (Section 5.2.2.6 of [CACHING]).",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				var gz bytes.Buffer
				zw := gzip.NewWriter(&gz)
				_, _ = zw.Write([]byte("compressed content"))
				require.NoError(t, zw.Close())
				b := newProxyBenchOn(t, front, always(fmt.Sprintf("HTTP/1.1 200 OK\r\nCache-Control: no-transform\r\nContent-Encoding: gzip\r\n"+
					"Content-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", gz.Len(), gz.Bytes())))
				_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nAccept-Encoding: gzip\r\n\r\n")
				require.NoError(t, got.err)
				assert.Equal(t, gz.Bytes(), got.body)
				assert.Equal(t, []string{"gzip"}, fieldValues(got.head, "Content-Encoding"))
			})
		},
	},
	{
		id: "rfc9110/7.7/5", name: "a response describing its representation and its origin",
		req: "A proxy SHOULD NOT modify header fields that provide information about the endpoints of the communication chain, the resource state, or the selected representation (other than the content) unless the field's definition specifically allows such modification or the modification is deemed necessary for privacy or security.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				const date = "Mon, 05 Oct 2026 10:00:00 GMT"
				b := newProxyBenchOn(t, front, always("HTTP/1.1 200 OK\r\nServer: origin/1\r\nDate: "+date+"\r\nETag: \"v1\"\r\n"+
					"Last-Modified: "+date+"\r\nContent-Length: 15\r\n\r\n<html>hi</html>"))
				_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				assert.Equal(t, []string{"origin/1"}, fieldValues(got.head, "Server"))
				assert.Equal(t, []string{date}, fieldValues(got.head, "Date"))
				assert.Equal(t, []string{`"v1"`}, fieldValues(got.head, "ETag"))
				assert.Equal(t, []string{date}, fieldValues(got.head, "Last-Modified"))
				assert.Empty(t, fieldValues(got.head, "Content-Type"), "the origin declared no media type")
			})
		},
	},

	// RFC 9110 section 7.8, Upgrade.
	{
		id: "rfc9110/7.8/1", name: "an HTTP/1.0 request asking for an upgrade",
		req: "A server that receives an Upgrade header field in an HTTP/1.0 request MUST ignore that Upgrade field.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got, _ := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.0\r\nHost: origin.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
				assert.Empty(t, fieldValues(got.head, "Upgrade"))
			})
		},
	},
	{
		id: "rfc9110/7.8/2", name: "an upgrade answered with 101",
		req: "A sender of Upgrade MUST also send an \"Upgrade\" connection option in the Connection header field (Section 7.6.1) to inform intermediaries not to forward this field.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, func(o *rawOrigin, w *wire) {
					r, err := w.readRequest()
					if err != nil {
						return
					}
					o.got <- r
					_, _ = io.WriteString(w, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo/1\r\n\r\n")
					_, _ = io.Copy(w, w.br)
				})
				b.p.MustAdd("origin.test", relayStream)

				w := b.dial(t)
				w.send(t, "GET http://origin.test/up HTTP/1.1\r\nHost: origin.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: echo/1\r\n\r\n")
				head := w.readHead(t)
				require.Equal(t, http.StatusSwitchingProtocols, headStatus(t, head))
				assert.Equal(t, []string{"echo/1"}, fieldValues(head, "Upgrade"))
				assert.True(t, headerListContains(http.Header{"Connection": fieldValues(head, "Connection")}, "Connection", "upgrade"))

				got := b.origin.next(t)
				assert.Equal(t, []string{"echo/1"}, fieldValues(got.head, "Upgrade"))
				assert.True(t, headerListContains(http.Header{"Connection": fieldValues(got.head, "Connection")}, "Connection", "upgrade"))

				w.send(t, "ping")
				echo := make([]byte, 4)
				_, err := io.ReadFull(w.br, echo)
				require.NoError(t, err)
				assert.Equal(t, "ping", string(echo))
			})
		},
	},

	// RFC 9110 section 9.3.6, CONNECT.
	{
		id: "rfc9110/9.3.6/1", name: "data on an established tunnel",
		req:  "The CONNECT method requests that the recipient establish a tunnel to the destination origin server identified by the request target and, if successful, thereafter restrict its behavior to blind forwarding of data, in both directions, until the tunnel is closed.",
		skip: "Edge terminates everything it admits and relays nothing it cannot observe, as CLAUDE.md states, so a tunnel is served by the entry that admits its traffic.",
	},
	{
		id: "rfc9110/9.3.6/2", name: "CONNECT to an invalid port",
		req: "A server MUST reject a CONNECT request that targets an empty or invalid port number, typically by responding with a 400 (Bad Request) status code.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			b.p.MustAdd("origin.test", relayStream)
			for _, target := range []string{"origin.test:0", "origin.test:65536", "origin.test:http"} {
				w := b.dial(t)
				w.send(t, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
				assert.Equal(t, http.StatusBadRequest, headStatus(t, w.readHead(t)), target)
			}
			assert.Zero(t, b.origin.accepted.Load())
		},
	},
	{
		id: "rfc9110/9.3.6/3", name: "CONNECT to an empty port",
		req:  "A server MUST reject a CONNECT request that targets an empty or invalid port number, typically by responding with a 400 (Bad Request) status code.",
		skip: "Edge reads a CONNECT target without a port as port 443 on purpose, targetFromConnect in connect.go states it, and a target ending in a colon takes the same path.",
	},
	{
		id: "rfc9110/9.3.6/4", name: "the 2xx answer to CONNECT over HTTP/1.1",
		req: "A server MUST NOT send any Transfer-Encoding or Content-Length header fields in a 2xx (Successful) response to CONNECT.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			w := b.dial(t)
			w.send(t, "CONNECT origin.test:80 HTTP/1.1\r\nHost: origin.test:80\r\n\r\n")
			head := w.readHead(t)
			require.Equal(t, http.StatusOK, headStatus(t, head))
			assert.Empty(t, fieldValues(head, "Content-Length"))
			assert.Empty(t, fieldValues(head, "Transfer-Encoding"))
		},
	},
	{
		id: "rfc9110/9.3.6/5", name: "CONNECT declaring content, tunnel bytes right behind it",
		req: "A CONNECT request message does not have content.  The interpretation of data sent after the header section of the CONNECT request message is specific to the version of HTTP in use.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			const inner = "GET /early HTTP/1.1\r\nHost: origin.test\r\n\r\n"
			w := b.dial(t)
			w.send(t, fmt.Sprintf("CONNECT origin.test:80 HTTP/1.1\r\nHost: origin.test:80\r\nContent-Length: %d\r\n\r\n%s", len(inner), inner))
			require.Equal(t, http.StatusOK, headStatus(t, w.readHead(t)))
			got := w.readResponse(t, "GET")
			assert.Equal(t, "ok", string(got.body))
			assert.Equal(t, "GET /early HTTP/1.1", startLine(b.origin.next(t).head))
		},
	},
	{
		id: "rfc9110/9.3.6/6", name: "each side of a tunnel closing after its last bytes",
		req: "A tunnel is closed when a tunnel intermediary detects that either side has closed its connection: the intermediary MUST attempt to send any outstanding data that came from the closed side to the other side, close both connections, and then discard any remaining data left undelivered.",
		run: func(t *testing.T) {
			b := newProxyBench(t, drainOrigin("last words"))
			b.p.MustAdd("origin.test", relayStream)
			w := b.connect(t)
			w.send(t, "\x01ping")
			require.NoError(t, w.Conn.(*net.TCPConn).CloseWrite())
			assert.Equal(t, "\x01ping", b.origin.nextNote(t))
			rest, err := io.ReadAll(w.br)
			require.NoError(t, err)
			assert.Equal(t, "last words", string(rest))
		},
	},
	{
		id: "rfc9110/9.3.6/7", name: "CONNECT to an authority no entry admits",
		req: "Proxies that support CONNECT SHOULD restrict its use to a limited set of known ports or a configurable list of safe request targets.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			w := b.dial(t)
			w.send(t, "CONNECT elsewhere.test:25 HTTP/1.1\r\nHost: elsewhere.test:25\r\n\r\n")
			assert.Equal(t, http.StatusForbidden, headStatus(t, w.readHead(t)))
			assert.Zero(t, b.origin.accepted.Load())
		},
	},
	{
		id: "rfc9110/9.3.6/8", name: "an https request whose target has no port, through an upstream proxy",
		req: "There is no default port; a client MUST send the port number even if the CONNECT request is based on a URI reference that contains an authority component with an elided port (Section 4.1).",
		run: func(t *testing.T) {
			for _, exit := range allExits {
				t.Run(exit, func(t *testing.T) {
					b := newExitBench(t, exit, nil, "HTTP/1.1 200 OK\r\n\r\n")
					b.dial(t).send(t, "GET https://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
					got := b.origin.next(t).req
					assert.Equal(t, "CONNECT", got.Method)
					assert.Equal(t, "origin.test:443", got.RequestURI)
				})
			}
		},
	},
	{
		id: "rfc9110/9.3.6/9", name: "the first bytes of the tunnel right behind the 200 of the upstream proxy",
		req: "Any 2xx (Successful) response indicates that the sender (and all inbound proxies) will switch to tunnel mode immediately after the response header section; data received after that header section is from the server identified by the request target.",
		run: func(t *testing.T) {
			for _, exit := range allExits {
				t.Run(exit, func(t *testing.T) {
					b := newExitBench(t, exit, nil, "HTTP/1.1 200 Connection established\r\n\r\nbanner")
					w := b.tunnel(t, "origin.test:80", "")
					b.origin.next(t)
					b.wantRelayed(t, w, "banner")
				})
			}
		},
	},
	{
		id: "rfc9110/9.3.6/10", name: "a 2xx other than 200 answering the CONNECT",
		req: "Any 2xx (Successful) response indicates that the sender (and all inbound proxies) will switch to tunnel mode immediately after the response header section; data received after that header section is from the server identified by the request target.",
		run: func(t *testing.T) {
			for _, exit := range allExits {
				t.Run(exit, func(t *testing.T) {
					for _, answer := range []string{"HTTP/1.1 204 No Content\r\n\r\n", "HTTP/1.1 299 Unregistered\r\n\r\n"} {
						t.Run(answer[9:12], func(t *testing.T) {
							b := newExitBench(t, exit, nil, answer)
							w := b.tunnel(t, "origin.test:80", "")
							b.origin.next(t)
							b.wantRelayed(t, w, "")
						})
					}
				})
			}
		},
	},
	{
		id: "rfc9110/9.3.6/11", name: "Content-Length and Transfer-Encoding on the 200 answering the CONNECT",
		req: "A client MUST ignore any Content-Length or Transfer-Encoding header fields received in a successful response to CONNECT.",
		run: func(t *testing.T) {
			// Transfer-Encoding is malformed in HTTP/2 and HTTP/3, RFC 9113 section 8.2.2 and
			// RFC 9114 section 4.2.
			h1 := []string{viaH1}
			cases := []struct {
				name, answer, first string
				exits               []string
			}{
				{"both", "HTTP/1.1 200 Mighty fine indeed\r\nContent-Length: 123\r\nTransfer-Encoding: chunked\r\n\r\n", "", h1},
				{"a length", "HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n", "", allExits},
				{"a length over the first bytes", "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nbanner", "banner", allExits},
				{"an invalid length", "HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n", "", allExits},
				{"two lengths", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", "", allExits},
				{"a coding other than chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", "", h1},
			}
			for _, exit := range allExits {
				t.Run(exit, func(t *testing.T) {
					if exit == viaH3 {
						t.Skip("quic-go rejects an invalid or conflicting Content-Length on the 200 answering the CONNECT and ends the tunnel at the Content-Length it accepts, before edge gets the stream.")
					}
					for _, tc := range cases {
						if !slices.Contains(tc.exits, exit) {
							continue
						}
						t.Run(tc.name, func(t *testing.T) {
							b := newExitBench(t, exit, nil, tc.answer)
							w := b.tunnel(t, "origin.test:80", "")
							b.origin.next(t)
							b.wantRelayed(t, w, tc.first)
						})
					}
				})
			}
		},
	},
	{
		id: "rfc9110/9.3.6/12", name: "a refusal answering the CONNECT, content behind it",
		req: "Any response other than a successful response indicates that the tunnel has not yet been formed.",
		run: func(t *testing.T) {
			// Connection and Transfer-Encoding are malformed in HTTP/2 and HTTP/3, RFC 9113
			// section 8.2.2 and RFC 9114 section 4.2.
			h1 := []string{viaH1}
			cases := []struct {
				name, answer string
				exits        []string
			}{
				{"407 delimited by the close", "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"up\"\r\nConnection: close\r\n\r\nbing", h1},
				{"403 with a length", "HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n\r\nbing", allExits},
				{"502 chunked", "HTTP/1.1 502 Bad Gateway\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbing\r\n0\r\n\r\n", h1},
			}
			for _, exit := range allExits {
				t.Run(exit, func(t *testing.T) {
					for _, tc := range cases {
						if !slices.Contains(tc.exits, exit) {
							continue
						}
						t.Run(tc.name, func(t *testing.T) {
							b := newExitBench(t, exit, nil, tc.answer)
							w := b.tunnel(t, "origin.test:80", "")
							b.origin.next(t)
							wantNoTunnel(t, w)
						})
					}
				})
			}
		},
	},
	{
		id: "rfc9110/9.3.6/13", name: "CONNECT over HTTP/1.1 to a destination that refuses the connection",
		req:  "Any 2xx (Successful) response indicates that the sender (and all inbound proxies) will switch to tunnel mode immediately after the response header section; data received after that header section is from the server identified by the request target.",
		skip: "Edge answers 200 before it dials on purpose, so the client sends the ClientHello whose name routes and a handler may serve the exchange locally, as connectHijack in connect.go records.",
	},
	{
		id: "rfc9110/9.3.6/14", name: "a dial refused after the 200 answering a CONNECT over HTTP/1.1",
		req: "Any 2xx (Successful) response indicates that the sender (and all inbound proxies) will switch to tunnel mode immediately after the response header section; data received after that header section is from the server identified by the request target.",
		run: func(t *testing.T) {
			b := newRefusingBench(t)
			w := b.connect(t)
			w.send(t, "\x01ping")
			_, err := w.br.ReadByte()
			assert.ErrorIs(t, err, syscall.ECONNRESET, "the tunnel ended cleanly where the dial failed")
		},
	},
	{
		id: "rfc9110/9.3.7/1", name: "OPTIONS without Max-Forwards",
		req: "A proxy MUST NOT generate a Max-Forwards header field while forwarding a request unless that request was received with a Max-Forwards field.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got, _ := b.forwarded(t, "OPTIONS", "OPTIONS http://origin.test/o HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				assert.Empty(t, fieldValues(got.head, "Max-Forwards"))
			})
		},
	},

	// RFC 9110 section 10.1.1 and 15.2, Expect and 1xx.
	{
		id: "rfc9110/10.1.1/1", name: "a request expecting 100-continue",
		req: "Upon receiving an HTTP/1.1 (or later) request that has a method, target URI, and complete header section that contains a 100-continue expectation and indicates a request content will follow, a proxy MUST either: * send an immediate response with a final status code, if that status can be determined by examining just the method, target URI, and header fields, or * forward the request toward the origin server by sending a corresponding request-line and header section to the next inbound server.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, func(o *rawOrigin, w *wire) {
					req, err := http.ReadRequest(w.br)
					if err != nil {
						return
					}
					o.got <- wireRequest{head: w.headFrom(0), req: req}
					_, _ = io.WriteString(w, "HTTP/1.1 100 Continue\r\n\r\n")
					body, _ := io.ReadAll(req.Body)
					o.note(string(body))
					_, _ = io.WriteString(w, okReply)
				})
				w := b.dial(t)
				w.send(t, "PUT http://origin.test/up HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n")
				got := b.origin.next(t)
				assert.Equal(t, []string{"100-continue"}, fieldValues(got.head, "Expect"))
				assert.Equal(t, http.StatusContinue, w.readResponse(t, "PUT").resp.StatusCode)
				w.send(t, "hello")
				assert.Equal(t, http.StatusOK, w.readResponse(t, "PUT").resp.StatusCode)
				assert.Equal(t, "hello", b.origin.nextNote(t))
			})
		},
	},
	{
		id: "rfc9110/10.1.4/1", name: "a request announcing trailers in TE",
		req: "A sender of TE MUST also send a \"TE\" connection option within the Connection header field (Section 7.6.1) to inform intermediaries not to forward this field.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got, _ := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTE: trailers\r\nConnection: TE\r\n\r\n")
				require.Equal(t, []string{"trailers"}, fieldValues(got.head, "TE"))
				assert.True(t, headerListContains(http.Header{"Connection": fieldValues(got.head, "Connection")}, "Connection", "te"))
			})
		},
	},
	{
		id: "rfc9110/12.5.5/1", name: "Vary on a forwarded response",
		req:  "A proxy MUST NOT generate \"*\" in a Vary field value.",
		skip: "Vary governs what a cache may reuse, and edge stores no response and generates no Vary of its own.",
	},
	{
		id: "rfc9110/15.2/1", name: "a 103 from the origin before its final answer",
		req: "A proxy MUST forward 1xx responses unless the proxy itself requested the generation of the 1xx response.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always("HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n"+okReply))
				w := b.dial(t)
				w.send(t, "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				early := w.readResponse(t, "GET")
				assert.Equal(t, http.StatusEarlyHints, early.resp.StatusCode)
				assert.Equal(t, []string{"</s.css>; rel=preload"}, fieldValues(early.head, "Link"))
			})
		},
	},
	{
		id: "rfc9110/15.2/2", name: "a 1xx answer to an HTTP/1.0 client",
		req: "Since HTTP/1.0 did not define any 1xx status codes, a server MUST NOT send a 1xx response to an HTTP/1.0 client.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always("HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n"+okReply))
				_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.0\r\nHost: origin.test\r\n\r\n")
				assert.Equal(t, http.StatusOK, got.resp.StatusCode)
			})
		},
	},
	{
		id: "rfc9110/15.2/3", name: "a 103 from the origin to an HTTP/2 client",
		req: "A proxy MUST forward 1xx responses unless the proxy itself requested the generation of the 1xx response.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always("HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n"+okReply))
			h := dialH2(t, b.addr)
			h.headers(t, 1, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"))
			early, ok := h.next(t, 1).(*http2.MetaHeadersFrame)
			require.True(t, ok, "the answer starts with HEADERS")
			status, _ := h2Field(early.Fields, ":status")
			assert.Equal(t, "103", status)
			link, _ := h2Field(early.Fields, "link")
			assert.Equal(t, "</s.css>; rel=preload", link)
			got := h.reply(t, 1)
			status, _ = h2Field(got.fields, ":status")
			assert.Equal(t, "200", status)
			_, ok = h2Field(got.fields, "link")
			assert.False(t, ok, "the final answer kept a field of the 103")
			assert.Equal(t, "ok", string(got.body))
		},
	},
	{
		id: "rfc9110/15.2/4", name: "a 103 from the origin to a request expecting 100-continue",
		req: "A proxy MUST forward 1xx responses unless the proxy itself requested the generation of the 1xx response.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, func(o *rawOrigin, w *wire) {
					for {
						req, err := http.ReadRequest(w.br)
						if err != nil {
							return
						}
						_, _ = io.WriteString(w, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n")
						_, _ = io.ReadAll(req.Body)
						if _, err := io.WriteString(w, okReply); err != nil {
							return
						}
					}
				})
				// The server writes its 100 from the goroutine reading the body, so a 103 written
				// alongside it is a data race the race detector reports within a few exchanges.
				for range 5 {
					w := b.dial(t)
					w.send(t, "POST http://origin.test/up HTTP/1.1\r\nHost: origin.test\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello")
					var codes []int
					for {
						got := w.readResponse(t, "POST")
						codes = append(codes, got.resp.StatusCode)
						if got.resp.StatusCode == http.StatusEarlyHints {
							assert.Equal(t, []string{"</s.css>; rel=preload"}, fieldValues(got.head, "Link"))
						}
						if got.resp.StatusCode >= http.StatusOK {
							break
						}
					}
					assert.Equal(t, []int{http.StatusContinue, http.StatusEarlyHints, http.StatusOK}, codes)
					_ = w.Close()
				}
			})
		},
	},
	{
		id: "rfc9110/15.2/5", name: "a 100 before the 200 answering the CONNECT of an upstream proxy",
		req: "A client MUST be able to parse one or more 1xx responses received prior to a final response, even if the client does not expect one.",
		run: func(t *testing.T) {
			for _, exit := range allExits {
				t.Run(exit, func(t *testing.T) {
					b := newExitBench(t, exit, nil, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n")
					w := b.tunnel(t, "origin.test:80", "")
					b.origin.next(t)
					b.wantRelayed(t, w, "")
				})
			}
		},
	},

	// RFC 9110 section 11, authentication.
	{
		id: "rfc9110/11.2/1", name: "a request without credentials",
		req: "Authentication parameters are name/value pairs, where the name token is matched case-insensitively and each parameter name MUST only occur once per challenge.",
		run: func(t *testing.T) {
			b := newAuthBench(t, "edge", always(okReply))
			for _, front := range allFronts {
				t.Run(front, func(t *testing.T) {
					seen := make(map[string]bool)
					for _, p := range b.challengeOf(t, front) {
						name := strings.ToLower(p.name)
						assert.False(t, seen[name], "parameter %s twice", name)
						seen[name] = true
					}
				})
			}
		},
	},
	{
		id: "rfc9110/11.4/1", name: "a request without credentials, with a wrong password or with credentials that do not decode",
		req: "Likewise, upon receipt of a request that omits proxy credentials or contains invalid or partial proxy credentials, a proxy that requires authentication SHOULD generate a 407 (Proxy Authentication Required) response that contains a Proxy-Authenticate header field with at least one (possibly new) challenge applicable to the proxy.",
		run: func(t *testing.T) {
			b := newAuthBench(t, "edge", always(okReply))
			cases := []struct{ name, value string }{
				{"none", ""},
				{"a wrong password", basicCredentials("Aladdin", "open sesame!")},
				{"another scheme", "Bearer QWxhZGRpbjpvcGVuIHNlc2FtZQ=="},
				{"no token68", "Basic"},
				{"a token68 that is no base64", "Basic !!!!"},
				{"a user-pass without a colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("Aladdin"))},
			}
			for _, front := range allFronts {
				for _, tc := range cases {
					t.Run(front+" "+tc.name, func(t *testing.T) {
						var extra [][2]string
						if tc.value != "" {
							extra = append(extra, [2]string{"Proxy-Authorization", tc.value})
						}
						got := b.send(t, front, formRequest, extra...)
						assert.Equal(t, http.StatusProxyAuthRequired, got.status)
						assert.NotEmpty(t, got.header.Values(HeaderProxyAuthenticate))
					})
				}
			}
			b.origin.none(t)
			b.secure.none(t)
		},
	},
	{
		id: "rfc9110/11.4/2", name: "credentials with three spaces between the scheme and the token68",
		req: "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]",
		run: func(t *testing.T) {
			b := newAuthBench(t, "edge", always(okReply))
			for _, front := range allFronts {
				t.Run(front, func(t *testing.T) {
					got := b.send(t, front, formRequest, [2]string{"Proxy-Authorization", "Basic   QWxhZGRpbjpvcGVuIHNlc2FtZQ=="})
					assert.Equal(t, http.StatusOK, got.status)
					assert.Equal(t, [2]string{"Aladdin", "open sesame"}, b.nextCreds(t))
				})
			}
		},
	},
	{
		id: "rfc9110/11.5/1", name: "a realm with a quote, a backslash, a tab or a control character in it",
		req: "For historical reasons, a sender MUST only generate the quoted-string syntax.",
		run: func(t *testing.T) {
			for _, realm := range []string{"edge", `a "quoted" \realm`, "tab\there", "ctl\x01here"} {
				t.Run(strconv.Quote(realm), func(t *testing.T) {
					if strings.ContainsFunc(realm, func(r rune) bool { return r < ' ' && r != '\t' }) {
						assert.Panics(t, func() { BasicAuth(realm, nil) })
						return
					}
					b := newAuthBench(t, realm, always(okReply))
					for _, front := range allFronts {
						t.Run(front, func(t *testing.T) {
							got := b.send(t, front, formRequest)
							require.Equal(t, http.StatusProxyAuthRequired, got.status)
							values := got.header.Values(HeaderProxyAuthenticate)
							require.Len(t, values, 1, "the 407 lost its challenge")
							_, params, err := parseChallenge(values[0])
							require.NoError(t, err, values[0])
							for _, p := range params {
								if strings.EqualFold(p.name, "realm") {
									assert.True(t, p.quoted, values[0])
									assert.Equal(t, realm, p.value)
								}
							}
						})
					}
				})
			}
		},
	},
	{
		id: "rfc9110/11.6.1/1", name: "a 401 from the origin with challenges on two field lines",
		req: "A proxy forwarding a response MUST NOT modify any WWW-Authenticate header fields in that response.",
		run: func(t *testing.T) {
			challenges := []string{
				`Basic realm="simple", Newauth realm="apps", type=1, title="Login to \"apps\""`,
				`Digest realm="weirdorealm", nonce="12345"`,
			}
			b := newAuthBench(t, "edge", always("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: "+challenges[0]+
				"\r\nWWW-Authenticate: "+challenges[1]+"\r\nContent-Length: 0\r\n\r\n"))
			for _, front := range allFronts {
				t.Run(front, func(t *testing.T) {
					got := b.send(t, front, formRequest, [2]string{"Proxy-Authorization", authAladdin})
					assert.Equal(t, http.StatusUnauthorized, got.status)
					assert.Equal(t, challenges, got.header.Values("WWW-Authenticate"))
				})
			}
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: "+challenges[0]+
					"\r\nWWW-Authenticate: "+challenges[1]+"\r\nContent-Length: 0\r\n\r\n"))
				_, got := b.forwarded(t, "GET", "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				assert.Equal(t, http.StatusUnauthorized, got.resp.StatusCode)
				assert.Equal(t, challenges, fieldValues(got.head, "WWW-Authenticate"))
			})
		},
	},
	{
		id: "rfc9110/11.6.2/1", name: "Authorization and Proxy-Authorization on one request",
		req: "A proxy forwarding a request MUST NOT modify any Authorization header fields in that request.",
		run: func(t *testing.T) {
			const authorization = `Digest username="digest", realm="weirdorealm", nonce="12345", uri="/x", response="304c55b19dbcb9c7e7a3354abd11ba1b"`
			b := newAuthBench(t, "edge", always(okReply))
			for _, front := range allFronts {
				t.Run(front, func(t *testing.T) {
					b.send(t, front, formRequest, [2]string{"Proxy-Authorization", authAladdin}, [2]string{"Authorization", authorization})
					got := b.originOf(front).next(t)
					assert.Equal(t, []string{authorization}, fieldValues(got.head, "Authorization"))
				})
			}
		},
	},
	{
		id: "rfc9110/11.6.2/2", name: "an absolute-form request with Authorization through an upstream proxy",
		req: "A proxy forwarding a request MUST NOT modify any Authorization header fields in that request.",
		run: func(t *testing.T) {
			const authorization = `Digest username="digest", realm="weirdorealm", nonce="12345", uri="/x", response="304c55b19dbcb9c7e7a3354abd11ba1b"`
			b := newUpstreamBench(t, nil, upstreamH1("", okReply))
			got, _ := b.forwarded(t, "GET", "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\nAuthorization: "+authorization+"\r\n\r\n")
			assert.Equal(t, []string{authorization}, fieldValues(got.head, "Authorization"))
		},
	},
	{
		id: "rfc9110/11.6.2/3", name: "a request with Authorization",
		req: "A proxy forwarding a request MUST NOT modify any Authorization header fields in that request.",
		run: func(t *testing.T) {
			const authorization = `Digest username="digest", realm="weirdorealm", nonce="12345", uri="/x", response="304c55b19dbcb9c7e7a3354abd11ba1b"`
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got, _ := b.forwarded(t, "GET", "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\nAuthorization: "+authorization+"\r\n\r\n")
				assert.Equal(t, []string{authorization}, fieldValues(got.head, "Authorization"))
			})
		},
	},
	{
		id: "rfc9110/11.6.3/1", name: "Authentication-Info on a response",
		req: "A proxy forwarding a response is not allowed to modify the field value in any way.",
		run: func(t *testing.T) {
			const info = `rspauth="d3c62c8ba8a2c4b0bbe1fc4ec8db93d8", cnonce="0a4f113b", nc=00000001, qop=auth`
			b := newAuthBench(t, "edge", always("HTTP/1.1 200 OK\r\nAuthentication-Info: "+info+"\r\nContent-Length: 2\r\n\r\nok"))
			for _, front := range allFronts {
				t.Run(front, func(t *testing.T) {
					got := b.send(t, front, formRequest, [2]string{"Proxy-Authorization", authAladdin})
					assert.Equal(t, http.StatusOK, got.status)
					assert.Equal(t, []string{info}, got.header.Values("Authentication-Info"))
				})
			}
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always("HTTP/1.1 200 OK\r\nAuthentication-Info: "+info+"\r\nContent-Length: 2\r\n\r\nok"))
				_, got := b.forwarded(t, "GET", "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				assert.Equal(t, http.StatusOK, got.resp.StatusCode)
				assert.Equal(t, []string{info}, fieldValues(got.head, "Authentication-Info"))
			})
		},
	},
	{
		id: "rfc9110/11.7.1/1", name: "a request without credentials on every front and in every form",
		req: "A proxy MUST send at least one Proxy-Authenticate header field in each 407 (Proxy Authentication Required) response that it generates.",
		run: func(t *testing.T) {
			b := newAuthBench(t, "edge", always(okReply))
			for _, front := range allFronts {
				for _, form := range authForms {
					t.Run(front+" "+form, func(t *testing.T) {
						got := b.send(t, front, form)
						assert.Equal(t, http.StatusProxyAuthRequired, got.status)
						assert.NotEmpty(t, got.header.Values(HeaderProxyAuthenticate))
					})
				}
			}
			b.origin.none(t)
			b.secure.none(t)
		},
	},
	{
		id: "rfc9110/11.7.1/2", name: "a request without credentials to a proxy whose authenticator offers no challenge",
		req: "A proxy MUST send at least one Proxy-Authenticate header field in each 407 (Proxy Authentication Required) response that it generates.",
		run: func(t *testing.T) {
			b := newAuthBenchWith(t, refuseAll{}, always(okReply))
			for _, front := range allFronts {
				for _, form := range authForms {
					t.Run(front+" "+form, func(t *testing.T) {
						got := b.send(t, front, form)
						if got.status == http.StatusProxyAuthRequired {
							assert.NotEmpty(t, got.header.Values(HeaderProxyAuthenticate), "a 407 without a challenge")
						}
						assert.GreaterOrEqual(t, got.status, http.StatusBadRequest)
					})
				}
			}
			b.origin.none(t)
			b.secure.none(t)
		},
	},
	{
		id: "rfc9110/11.7.1/3", name: "a 407 with a challenge from an upstream proxy",
		req: "Unlike WWW-Authenticate, the Proxy-Authenticate header field applies only to the next outbound client on the response chain.",
		run: func(t *testing.T) {
			b := newUpstreamBench(t, nil, upstreamH1("", "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"upstream\"\r\nContent-Length: 0\r\n\r\n"))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.Empty(t, fieldValues(got.head, "Proxy-Authenticate"))
		},
	},
	{
		id: "rfc9110/11.7.2/1", name: "a request with Proxy-Authorization forwarded to the origin",
		req: "When multiple proxies are used in a chain, the Proxy-Authorization header field is consumed by the first inbound proxy that was expecting to receive credentials.",
		run: func(t *testing.T) {
			b := newAuthBench(t, "edge", always(okReply))
			for _, front := range allFronts {
				t.Run(front, func(t *testing.T) {
					b.send(t, front, formRequest, [2]string{"Proxy-Authorization", authAladdin})
					got := b.originOf(front).next(t)
					assert.Empty(t, fieldValues(got.head, "Proxy-Authorization"))
				})
			}
		},
	},
	{
		id: "rfc9110/11.7.2/2", name: "a request with Proxy-Authorization through an upstream proxy",
		req: "When multiple proxies are used in a chain, the Proxy-Authorization header field is consumed by the first inbound proxy that was expecting to receive credentials.",
		run: func(t *testing.T) {
			auth := WithProxyAuth(BasicAuth("edge", func(user, pass string) bool { return user == "Aladdin" && pass == "open sesame" }))
			own := url.UserPassword("edge", "upstream")
			for _, exit := range allExits {
				t.Run(exit, func(t *testing.T) {
					b := newExitBench(t, exit, own, "HTTP/1.1 200 OK\r\n\r\n", auth)
					b.tunnel(t, "origin.test:80", "Proxy-Authorization: "+authAladdin+"\r\n")
					assert.Equal(t, []string{basicCredentials("edge", "upstream")}, b.origin.next(t).req.Header.Values("Proxy-Authorization"))
				})
			}
			t.Run("absolute-form", func(t *testing.T) {
				b := newUpstreamBench(t, own, upstreamH1("", okReply), auth)
				got, _ := b.forwarded(t, "GET", "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\nProxy-Authorization: "+authAladdin+"\r\n\r\n")
				assert.Equal(t, []string{basicCredentials("edge", "upstream")}, fieldValues(got.head, "Proxy-Authorization"))
			})
		},
	},
	{
		id: "rfc9110/11.7.3/1", name: "Proxy-Authentication-Info from an upstream proxy",
		req: "However, unlike Authentication-Info, the Proxy-Authentication-Info header field applies only to the next outbound client on the response chain.",
		run: func(t *testing.T) {
			b := newUpstreamBench(t, url.UserPassword("Aladdin", "open sesame"), upstreamH1("",
				"HTTP/1.1 200 OK\r\nProxy-Authentication-Info: rspauth=\"d3c62c8ba8a2c4b0bbe1fc4ec8db93d8\"\r\nContent-Length: 2\r\n\r\nok"))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.Equal(t, http.StatusOK, got.resp.StatusCode)
			assert.Empty(t, fieldValues(got.head, "Proxy-Authentication-Info"))
		},
	},

	// RFC 9110 section 15.5.8, 407 Proxy Authentication Required.
	{
		id: "rfc9110/15.5.8/1", name: "a 407 from an upstream proxy to a forwarded request",
		req: "The proxy MUST send a Proxy-Authenticate header field (Section 11.7.1) containing a challenge applicable to that proxy for the request.",
		run: func(t *testing.T) {
			b := newUpstreamBench(t, nil, upstreamH1("", "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"upstream\"\r\nContent-Length: 0\r\n\r\n"))
			_, got := b.forwarded(t, "GET", "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			if got.resp.StatusCode == http.StatusProxyAuthRequired {
				assert.NotEmpty(t, fieldValues(got.head, "Proxy-Authenticate"), "a 407 without a challenge")
			}
		},
	},

	// RFC 9112 section 3.2, the request target.
	{
		id: "rfc9112/3.2/1", name: "a request with two Host field lines",
		req: "A server MUST respond with a 400 (Bad Request) status code to any HTTP/1.1 request message that lacks a Host header field and to any request message that contains more than one Host header field line or a Host header field with an invalid field value.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got := b.exchange(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nHost: other.test\r\n\r\n")
				assert.Equal(t, http.StatusBadRequest, got.resp.StatusCode)
				b.origin.none(t)
			})
		},
	},
	{
		id: "rfc9112/3.2/2", name: "an absolute-form target with userinfo",
		req: "If the target URI includes an authority component, then a client MUST send a field value for Host that is identical to that authority component, excluding any userinfo subcomponent and its \"@\" delimiter (Section 4.2 of [HTTP]).",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				w := b.dial(t)
				w.originForm = false
				w.send(t, "GET "+front.scheme()+"://user:secret@origin.test:8080/x HTTP/1.1\r\nHost: origin.test:8080\r\n\r\n")
				w.readResponse(t, "GET")
				got := b.origin.next(t)
				assert.Equal(t, []string{"origin.test:8080"}, fieldValues(got.head, "Host"))
				assert.NotContains(t, got.head, "secret")
			})
		},
	},
	{
		id: "rfc9112/3.2/3", name: "a tunnel to an IPv6 literal through an upstream proxy",
		req: "If the target URI includes an authority component, then a client MUST send a field value for Host that is identical to that authority component, excluding any userinfo subcomponent and its \"@\" delimiter (Section 4.2 of [HTTP]).",
		run: func(t *testing.T) {
			b := newUpstreamBench(t, nil, upstreamH1("HTTP/1.1 200 OK\r\n\r\n", ""))
			w := b.tunnel(t, "[2001:db8::1]:80", "")
			assert.Equal(t, []string{"[2001:db8::1]:80"}, fieldValues(b.origin.next(t).head, "Host"))
			b.wantRelayed(t, w, "")
		},
	},
	{
		id: "rfc9112/3.2/4", name: "a request without Host",
		req: "A server MUST respond with a 400 (Bad Request) status code to any HTTP/1.1 request message that lacks a Host header field and to any request message that contains more than one Host header field line or a Host header field with an invalid field value.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got := b.exchange(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nX-Pad: 1\r\n\r\n")
				assert.Equal(t, http.StatusBadRequest, got.resp.StatusCode)
			})
		},
	},
	{
		id: "rfc9112/3.2/5", name: "a Host with an invalid field value",
		req: "A server MUST respond with a 400 (Bad Request) status code to any HTTP/1.1 request message that lacks a Host header field and to any request message that contains more than one Host header field line or a Host header field with an invalid field value.",
		run: func(t *testing.T) {
			hosts := []string{"origin .test", "origin.test/x", "origin.test:8o", "user@origin.test", "origin.test:80:80",
				"[origin.test]", "origin.test]", "[::1]x", "[::1]:80:80"}
			for _, host := range hosts {
				t.Run(strconv.Quote(host), func(t *testing.T) {
					// The explicit front receives the absolute-form, whose Host net/http replaces before edge reads it, as rfc9112/3.2.2/1 checks.
					for _, front := range proxyFronts[1:] {
						t.Run(string(front), func(t *testing.T) {
							b := newProxyBenchOn(t, front, always(okReply))
							got := b.exchange(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
							assert.Equal(t, http.StatusBadRequest, got.resp.StatusCode)
						})
					}
				})
			}
		},
	},
	{
		id: "rfc9112/3.2/6", name: "a request-target in a form its method does not allow",
		req: "Recipients of an invalid request-line SHOULD respond with either a 400 (Bad Request) error or a 301 (Moved Permanently) redirect with the request-target properly encoded.",
		run: func(t *testing.T) {
			for _, line := range []string{"GET origin.test:80", "GET *"} {
				t.Run(line, func(t *testing.T) {
					eachProxyFront(t, func(t *testing.T, front proxyFront) {
						b := newProxyBenchOn(t, front, always(okReply))
						got := b.exchange(t, "GET", line+" HTTP/1.1\r\nHost: origin.test:80\r\n\r\n")
						assert.Contains(t, []int{http.StatusBadRequest, http.StatusMovedPermanently}, got.resp.StatusCode)
					})
				})
			}
		},
	},
	{
		id: "rfc9112/3.2/7", name: "a request-target with a space",
		req: "Recipients of an invalid request-line SHOULD respond with either a 400 (Bad Request) error or a 301 (Moved Permanently) redirect with the request-target properly encoded.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got := b.exchange(t, "GET", "GET http://origin.test/a b HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				assert.Contains(t, []int{http.StatusBadRequest, http.StatusMovedPermanently}, got.resp.StatusCode)
			})
		},
	},
	{
		id: "rfc9112/3.2/8", name: "an absolute-form target whose host RFC 3986 does not allow",
		req: "Recipients of an invalid request-line SHOULD respond with either a 400 (Bad Request) error or a 301 (Moved Permanently) redirect with the request-target properly encoded.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				b.p.MustAdd("+{any}/*{any}", forwardHandler)
				w := b.dial(t)
				w.originForm = false
				w.send(t, "GET "+front.scheme()+"://ori\"gin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				got := w.readResponse(t, "GET")
				assert.Contains(t, []int{http.StatusBadRequest, http.StatusMovedPermanently}, got.resp.StatusCode)
				assert.Equal(t, int32(0), b.origin.accepted.Load(), "the proxy forwarded an invalid request-line")
			})
		},
	},
	{
		id: "rfc9112/3.2.2/1", name: "an absolute-form target with a Host that disagrees",
		req: "A proxy that forwards such a request MUST generate a new Host field value based on the received request-target rather than forward the received Host field value.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				w := b.dial(t)
				w.originForm = false
				w.send(t, "GET "+front.scheme()+"://origin.test/abs HTTP/1.1\r\nHost: other.test\r\n\r\n")
				w.readResponse(t, "GET")
				assert.Equal(t, []string{"origin.test"}, fieldValues(b.origin.next(t).head, "Host"))
			})
		},
	},
	{
		id: "rfc9112/3.2.2/2", name: "a request and an OPTIONS with an empty path, through an upstream proxy",
		req: "When making a request to a proxy, other than a CONNECT or server-wide OPTIONS request (as detailed below), a client MUST send the target URI in \"absolute-form\" as the request-target.",
		run: func(t *testing.T) {
			for _, tc := range []struct{ method, target, host string }{
				{"GET", "http://origin.test/a/%7Eb?q=1", "origin.test"},
				{"OPTIONS", "http://origin.test:8001", "origin.test:8001"},
			} {
				t.Run(tc.method, func(t *testing.T) {
					b := newUpstreamBench(t, nil, upstreamH1("", okReply))
					got, _ := b.forwarded(t, tc.method, tc.method+" "+tc.target+" HTTP/1.1\r\nHost: "+tc.host+"\r\n\r\n")
					assert.Equal(t, tc.method+" "+tc.target+" HTTP/1.1", startLine(got.head))
				})
			}
		},
	},
	{
		id: "rfc9112/3.2.2/3", name: "an absolute-form request with a port through an upstream proxy",
		req: "A client MUST send a Host header field in an HTTP/1.1 request even if the request-target is in the absolute-form, since this allows the Host information to be forwarded through ancient HTTP/1.0 proxies that might not have implemented Host.",
		run: func(t *testing.T) {
			b := newUpstreamBench(t, nil, upstreamH1("", okReply))
			got, _ := b.forwarded(t, "GET", "GET http://origin.test:8080/x HTTP/1.1\r\nHost: origin.test:8080\r\n\r\n")
			assert.Equal(t, []string{"origin.test:8080"}, fieldValues(got.head, "Host"))
		},
	},
	{
		id: "rfc9112/3.2.2/4", name: "an absolute-form request where origin-form is expected",
		req: "A server MUST accept the absolute-form in requests even though most HTTP/1.1 clients will only send the absolute-form to a proxy.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				w := b.dial(t)
				w.originForm = false
				w.send(t, "GET "+front.scheme()+"://origin.test/abs?q=1 HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				assert.Equal(t, http.StatusOK, w.readResponse(t, "GET").resp.StatusCode)
				assert.Equal(t, "GET /abs?q=1 HTTP/1.1", startLine(b.origin.next(t).head))
			})
		},
	},
	{
		id: "rfc9112/3.2.3/1", name: "a CONNECT to an IPv6 literal through an upstream proxy",
		req: "When making a CONNECT request to establish a tunnel through one or more proxies, a client MUST send only the host and port of the tunnel destination as the request-target.",
		run: func(t *testing.T) {
			b := newUpstreamBench(t, nil, upstreamH1("HTTP/1.1 200 OK\r\n\r\n", ""))
			w := b.tunnel(t, "[2001:db8::1]:80", "")
			assert.Equal(t, "CONNECT [2001:db8::1]:80 HTTP/1.1", startLine(b.origin.next(t).head))
			b.wantRelayed(t, w, "")
		},
	},
	{
		id: "rfc9112/3.2.4/1", name: "OPTIONS with an absolute-form target and an empty path",
		req: "If a proxy receives an OPTIONS request with an absolute-form of request-target in which the URI has an empty path and no query component, then the last proxy on the request chain MUST send a request-target of \"*\" when it forwards the request to the indicated origin server.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				w := b.dial(t)
				w.originForm = false
				w.send(t, "OPTIONS "+front.scheme()+"://origin.test:8001 HTTP/1.1\r\nHost: origin.test:8001\r\n\r\n")
				w.readResponse(t, "OPTIONS")
				got := b.origin.next(t)
				assert.Equal(t, "OPTIONS * HTTP/1.1", startLine(got.head))
				assert.Equal(t, []string{"origin.test:8001"}, fieldValues(got.head, "Host"))
			})
		},
	},
	{
		id: "rfc9112/3.2.4/2", name: "an OPTIONS with an asterisk-form target",
		req: "When a client wishes to request OPTIONS for the server as a whole, as opposed to a specific named resource of that server, the client MUST send only \"*\" (%x2A) as the request-target.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got := b.exchange(t, "OPTIONS", "OPTIONS * HTTP/1.1\r\nHost: origin.test:8001\r\n\r\n")
				require.Equal(t, http.StatusOK, got.resp.StatusCode)
				if front == frontExplicit {
					// The request is about the proxy, and net/http responds to it.
					assert.Empty(t, got.body)
					assert.Equal(t, int32(0), b.origin.accepted.Load())
					return
				}
				assert.Equal(t, "ok", string(got.body))
				fwd := b.origin.next(t)
				assert.Equal(t, "OPTIONS * HTTP/1.1", startLine(fwd.head))
				assert.Equal(t, []string{"origin.test:8001"}, fieldValues(fwd.head, "Host"))
			})
		},
	},

	// RFC 9112 section 4, the status line.
	{
		id: "rfc9112/4/1", name: "a 200 without a reason phrase answering the CONNECT of an upstream proxy",
		req: "A client SHOULD ignore the reason-phrase content because it is not a reliable channel for information (it might be translated for a given locale, overwritten by intermediaries, or discarded when the message is forwarded via other versions of HTTP).",
		run: func(t *testing.T) {
			b := newUpstreamBench(t, nil, upstreamH1("HTTP/1.1 200 \r\n\r\n", ""))
			w := b.tunnel(t, "origin.test:80", "")
			b.origin.next(t)
			b.wantRelayed(t, w, "")
		},
	},

	// RFC 9112 section 5.1, field line parsing.
	{
		id: "rfc9112/5.1/1", name: "a request with whitespace before the colon of a trailer field",
		req: "A server MUST reject, with a response status code of 400 (Bad Request), any received request message that contains whitespace between a header field name and colon.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				w := b.dial(t)
				w.send(t, "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nX-Trailer : 1\r\n\r\n")
				got := w.readResponse(t, "POST")
				assert.Equal(t, http.StatusBadRequest, got.resp.StatusCode)
			})
		},
	},

	// RFC 9112 section 6, the message body.
	{
		id: "rfc9112/6.1/1", name: "a chunked request",
		req: "A sender MUST NOT apply the chunked transfer coding more than once to a message body (i.e., chunking an already chunked message is not allowed).",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got, _ := b.forwarded(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")
				assert.Equal(t, "abcde", string(got.body))
			})
		},
	},
	{
		id: "rfc9112/6.1/2", name: "a chunked response",
		req: "A sender MUST NOT apply the chunked transfer coding more than once to a message body (i.e., chunking an already chunked message is not allowed).",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"))
				_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				require.NoError(t, got.err)
				assert.Equal(t, "abcde", string(got.body))
			})
		},
	},
	{
		id: "rfc9112/6.1/3", name: "a request with a transfer coding the proxy does not implement",
		req: "A server that receives a request message with a transfer coding it does not understand SHOULD respond with 501 (Not Implemented).",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got := b.exchange(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n")
				assert.Equal(t, http.StatusNotImplemented, got.resp.StatusCode)
				b.origin.none(t)
			})
		},
	},
	{
		id: "rfc9112/6.1/4", name: "a 204 from the origin declaring a transfer coding",
		req: "A server MUST NOT send a Transfer-Encoding header field in any response with a status code of 1xx (Informational) or 204 (No Content).",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always("HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n"))
				_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				assert.Equal(t, http.StatusNoContent, got.resp.StatusCode)
				assert.Empty(t, fieldValues(got.head, "Transfer-Encoding"))
			})
		},
	},
	{
		id: "rfc9112/6.1/5", name: "a chunked origin response to an HTTP/1.0 client",
		req: "A server MUST NOT send a response containing Transfer-Encoding unless the corresponding request indicates HTTP/1.1 (or later minor revisions).",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"))
				_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.0\r\nHost: origin.test\r\n\r\n")
				require.NoError(t, got.err)
				assert.Empty(t, fieldValues(got.head, "Transfer-Encoding"))
				assert.Equal(t, "hello", string(got.body))
			})
		},
	},
	{
		id: "rfc9112/6.1/6", name: "a request with Transfer-Encoding and Content-Length",
		req:  "Regardless, the server MUST close the connection after responding to such a request to avoid the potential attacks.",
		skip: "net/http drops the Content-Length of a request that also has Transfer-Encoding and keeps the connection open, before edge gets the request.",
	},
	{
		id: "rfc9112/6.1/7", name: "an HTTP/1.0 request with Transfer-Encoding",
		req:  "A server or client that receives an HTTP/1.0 message containing a Transfer-Encoding header field MUST treat the message as if the framing is faulty, even if a Content-Length is present, and close the connection after processing the message.",
		skip: "net/http ignores Transfer-Encoding on an HTTP/1.0 request and frames it by its Content-Length, before edge gets the request.",
	},
	{
		id: "rfc9112/6.3/1", name: "a 304 declaring a Content-Length",
		req: "Any response to a HEAD request and any response with a 1xx (Informational), 204 (No Content), or 304 (Not Modified) status code is always terminated by the first empty line after the header fields, regardless of the header fields present in the message, and thus cannot contain a message body or trailer section.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, replyEach(func(n int, _ wireRequest) string {
					if n == 0 {
						return "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nContent-Length: 10\r\n\r\n"
					}
					return okReply
				}))
				w := b.dial(t)
				w.send(t, "GET http://origin.test/a HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				assert.Equal(t, http.StatusNotModified, w.readResponse(t, "GET").resp.StatusCode)
				w.send(t, "GET http://origin.test/b HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				got := w.readResponse(t, "GET")
				assert.Equal(t, "ok", string(got.body))
			})
		},
	},
	{
		id: "rfc9112/6.3/2", name: "a request with Transfer-Encoding and Content-Length",
		req: "An intermediary that chooses to forward the message MUST first remove the received Content-Length field and process the Transfer-Encoding (as described below) prior to forwarding the message downstream.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got, _ := b.forwarded(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n")
				assert.NotEqual(t, []string{"4"}, fieldValues(got.head, "Content-Length"))
				assert.Equal(t, "hi", string(got.body))
			})
		},
	},
	{
		id: "rfc9112/6.3/3", name: "a response with Transfer-Encoding and Content-Length",
		req: "An intermediary that chooses to forward the message MUST first remove the received Content-Length field and process the Transfer-Encoding (as described below) prior to forwarding the message downstream.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"))
				_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				require.NoError(t, got.err)
				assert.Empty(t, fieldValues(got.head, "Content-Length"))
				assert.Equal(t, "ok", string(got.body))
			})
		},
	},
	{
		id: "rfc9112/6.3/4", name: "a request whose final transfer coding is not chunked",
		req:  "If a Transfer-Encoding header field is present in a request and the chunked transfer coding is not the final encoding, the message body length cannot be determined reliably; the server MUST respond with the 400 (Bad Request) status code and then close the connection.",
		skip: "net/http answers a request whose final transfer coding is not chunked with a 501 before edge gets the request.",
	},
	{
		id: "rfc9112/6.3/5", name: "a response with an invalid Content-Length",
		req: "If it is in a response message received by a proxy, the proxy MUST close the connection to the server, discard the received response, and send a 502 (Bad Gateway) response to the client.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always("HTTP/1.1 200 OK\r\nContent-Length: 2, 3\r\n\r\nok"))
				_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				assert.Equal(t, http.StatusBadGateway, got.resp.StatusCode)
				assert.NotEqual(t, "ok", string(got.body))
				b.origin.ended(t)
			})
		},
	},
	{
		id: "rfc9112/6.3/6", name: "a request with an invalid Content-Length",
		req: "If the unrecoverable error is in a request message, the server MUST respond with a 400 (Bad Request) status code and then close the connection.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				w := b.dial(t)
				w.send(t, "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 1x\r\n\r\nx")
				assert.Equal(t, http.StatusBadRequest, w.readResponse(t, "POST").resp.StatusCode)
				w.wantClosed(t)
				b.origin.none(t)
			})
		},
	},
	{
		id: "rfc9112/6.3/7", name: "a response shorter than its Content-Length",
		req: "If the sender closes the connection or the recipient times out before the indicated number of octets are received, the recipient MUST consider the message to be incomplete and close the connection.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, func(o *rawOrigin, w *wire) {
					if r, err := w.readRequest(); err == nil {
						o.got <- r
						_, _ = io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")
					}
				})
				_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				assert.ErrorIs(t, got.err, io.ErrUnexpectedEOF)
				assert.Equal(t, "short", string(got.body))
			})
		},
	},
	{
		id: "rfc9112/6.3/8", name: "a response delimited by the close of the connection",
		req: "Otherwise, this is a response message without a declared message body length, so the message body length is determined by the number of octets received prior to the server closing the connection.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, func(o *rawOrigin, w *wire) {
					if r, err := w.readRequest(); err == nil {
						o.got <- r
						_, _ = io.WriteString(w, "HTTP/1.1 200 OK\r\n\r\nall of it")
					}
				})
				_, got := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				require.NoError(t, got.err)
				assert.Equal(t, "all of it", string(got.body))
			})
		},
	},
	{
		id: "rfc9112/6.3/9", name: "a forged response behind the end of a response",
		req: "A client MUST NOT process, cache, or forward such extra data as a separate response, since such behavior would be vulnerable to cache poisoning.",
		run: func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				size    int
				handler func(*HTTPCtx) (*http.Response, error)
			}{
				{"5 bytes", 5, forwardHandler},
				{"8200 bytes", 8200, forwardHandler},
				{"45000 bytes read by the handler", 45000, readAllHandler},
			} {
				t.Run(tc.name, func(t *testing.T) {
					first := strings.Repeat("a", tc.size)
					eachProxyFront(t, func(t *testing.T, front proxyFront) {
						b := newProxyBenchWith(t, front, DefaultTransport(), replyEach(func(n int, _ wireRequest) string {
							if n == 0 {
								return "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(tc.size) + "\r\n\r\n" + first + forgedResponse
							}
							return "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond"
						}), tc.handler, func(c net.Conn) net.Conn { return &lateConn{Conn: c} })
						w := b.dial(t)
						w.send(t, "GET http://origin.test/1 HTTP/1.1\r\nHost: origin.test\r\n\r\n")
						assert.Equal(t, first, string(w.readResponse(t, "GET").body))
						w.send(t, "GET http://origin.test/2 HTTP/1.1\r\nHost: origin.test\r\n\r\n")
						assert.Equal(t, "second", string(w.readResponse(t, "GET").body))
					})
				})
			}
		},
	},

	// RFC 9112 section 7.1, chunked.
	{
		id: "rfc9112/7.1/1", name: "a chunk size past 64 bits",
		req: "Therefore, recipients MUST anticipate potentially large hexadecimal numerals and prevent parsing errors due to integer conversion overflows or precision loss due to integer representation.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got := b.exchange(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n\r\n1fffffffffffffffff\r\nhi\r\n0\r\n\r\n")
				assert.GreaterOrEqual(t, got.resp.StatusCode, 400)
				b.origin.none(t)
			})
		},
	},
	{
		id: "rfc9112/7.1.1/1", name: "chunk extensions",
		req: "A recipient MUST ignore unrecognized chunk extensions.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				got, _ := b.forwarded(t, "POST", "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n\r\n"+
					"2;ext=1\r\nhi\r\n3;q=\"a b\"\r\nyou\r\n0;last\r\n\r\n")
				assert.Equal(t, "hiyou", string(got.body))
			})
		},
	},

	// RFC 9112 section 8, incomplete messages.
	{
		id: "rfc9112/8/1", name: "the upstream proxy closing inside the header section of its 200",
		req: "A client that receives an incomplete response message, which can occur when a connection is closed prematurely or when decoding a supposedly chunked transfer coding fails, MUST record the message as incomplete.",
		run: func(t *testing.T) {
			b := newUpstreamBench(t, nil, upstreamH1("HTTP/1.1 200 OK\r\nX-Pad: 1\r\n", ""))
			w := b.tunnel(t, "origin.test:80", "")
			b.origin.next(t)
			wantNoTunnel(t, w)
			assert.Empty(t, b.origin.nextNote(t), "bytes of the tunnel reached the upstream proxy")
		},
	},
	{
		id: "rfc9112/8/2", name: "a request whose client closes before its Content-Length",
		req: "A server that receives an incomplete request message, usually due to a canceled request or a triggered timeout exception, MAY send an error response prior to closing the connection.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				w := b.dial(t)
				w.send(t, "POST http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 10\r\n\r\nabcd")
				require.NoError(t, closeWrite(w.Conn))
				wantMalformedH1(t, w)
			})
		},
	},

	// RFC 9112 section 9.6, tear-down.
	{
		id: "rfc9112/9.6/1", name: "a request with close and one pipelined behind it",
		req: "A server that receives a \"close\" connection option MUST initiate closure of the connection (see below) after it sends the final response to the request that contained the \"close\" connection option.  The server SHOULD send a \"close\" connection option in its final response on that connection.  The server MUST NOT process any further requests received on that connection.",
		run: func(t *testing.T) {
			eachProxyFront(t, func(t *testing.T, front proxyFront) {
				b := newProxyBenchOn(t, front, always(okReply))
				w := b.dial(t)
				w.send(t, "GET http://origin.test/a HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n"+
					"GET http://origin.test/b HTTP/1.1\r\nHost: origin.test\r\n\r\n")
				got := w.readResponse(t, "GET")
				assert.Equal(t, "ok", string(got.body))
				assert.True(t, got.resp.Close)
				w.wantClosed(t)
				assert.Equal(t, "GET /a HTTP/1.1", startLine(b.origin.next(t).head))
				b.origin.none(t)
			})
		},
	},

	// RFC 9113 sections 3.3 and 3.4, HTTP/2 with prior knowledge and the connection preface.
	{
		id: "rfc9113/3.3/1", name: "the connection preface and an empty SETTINGS frame, then nothing",
		req: "Likewise, the server MUST send a connection preface (Section 3.4).",
		run: func(t *testing.T) {
			eachPlainH2Front(t, func(t *testing.T, front string) {
				p, _ := hostEcho(t)
				c := dialPlainH2Front(t, front, p, nil)
				sendAsync(c, prefaceThen(t, func(fr *http2.Framer) error { return fr.WriteSettings() }))
				assert.True(t, isSettings(newH2Wire(c).frame(t)), "the first frame is the server connection preface")
			})
		},
	},
	{
		id: "rfc9113/3.3/2", name: "the connection preface, an empty SETTINGS frame and a request, read one octet at a time",
		req: "Likewise, the server MUST send a connection preface (Section 3.4).",
		run: func(t *testing.T) {
			eachPlainH2Front(t, func(t *testing.T, front string) {
				p, _ := hostEcho(t)
				c := dialPlainH2Front(t, front, p, asOctets)
				block := requestEncoder()
				sendAsync(c, prefaceThen(t, func(fr *http2.Framer) error {
					return errors.Join(fr.WriteSettings(), fr.WriteHeaders(http2.HeadersFrameParam{
						StreamID: 1, BlockFragment: block("a.test", "/"), EndHeaders: true, EndStream: true,
					}))
				}))
				h := newH2Wire(c)
				assert.True(t, isSettings(h.frame(t)), "the first frame is the server connection preface")
				assert.Equal(t, map[uint32]string{1: "a.test"}, h.bodies(t, 1))
			})
		},
	},
	{
		id: "rfc9113/3.3/3", name: "the connection preface over TLS from a client that offered no ALPN",
		req: "This only affects the establishment of HTTP/2 connections over cleartext TCP; HTTP/2 connections over TLS MUST use protocol negotiation in TLS [TLS-ALPN].",
		run: func(t *testing.T) {
			for _, front := range []string{"connect", viaRedirected} {
				t.Run(front, func(t *testing.T) {
					p, ca := newTLSProxy(t)
					var conn net.Conn
					if front == "connect" {
						conn = connectRaw(t, startProxy(t, p), tlsName+":443")
					} else {
						conn = dialWire(t, startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
							return netip.MustParseAddrPort("192.0.2.1:443"), nil
						})).Conn
					}
					require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
					tc := tls.Client(conn, &tls.Config{ServerName: tlsName, RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12})
					require.NoError(t, tc.Handshake())
					require.Empty(t, tc.ConnectionState().NegotiatedProtocol)
					_, err := tc.Write(prefaceThen(t, func(fr *http2.Framer) error { return fr.WriteSettings() }))
					require.NoError(t, err)
					head := make([]byte, 9)
					if _, err := io.ReadFull(tc, head); err == nil {
						assert.NotEqual(t, byte(http2.FrameSettings), head[3], "the proxy answered in HTTP/2 on a connection that negotiated no protocol")
					}
				})
			}
		},
	},
	{
		id: "rfc9113/3.3/4", name: "a connection preface stalled past the sniff timeout",
		req:  "Likewise, the server MUST send a connection preface (Section 3.4).",
		skip: "A redirected plaintext connection whose first line has not arrived within WithSniffTimeout is served as a byte stream, so a stalled preface reaches a stream entry on the destination, and is closed when none admits it.",
	},
	{
		id: "rfc9113/3.4/1", name: "the connection preface, an empty SETTINGS frame and a request in one write",
		req: "The server connection preface consists of a potentially empty SETTINGS frame (Section 6.5) that MUST be the first frame the server sends in the HTTP/2 connection.",
		run: func(t *testing.T) {
			eachH2Front(t, prefaceFronts, func(t *testing.T, front string) {
				p, _ := hostEcho(t)
				c := dialPrefaceFront(t, front, p)
				block := requestEncoder()
				sendAsync(c, prefaceThen(t, func(fr *http2.Framer) error {
					return errors.Join(fr.WriteSettings(), fr.WriteHeaders(http2.HeadersFrameParam{
						StreamID: 1, BlockFragment: block("a.test", "/"), EndHeaders: true, EndStream: true,
					}))
				}))
				h := newH2Wire(c)
				assert.True(t, isSettings(h.frame(t)), "the first frame is the server connection preface")
				assert.Equal(t, map[uint32]string{1: "a.test"}, h.bodies(t, 1))
			})
		},
	},
	{
		id: "rfc9113/3.4/2", name: "the connection preface and a SETTINGS frame, then nothing",
		req: "The SETTINGS frames received from a peer as part of the connection preface MUST be acknowledged (see Section 6.5.3) after sending the connection preface.",
		run: func(t *testing.T) {
			eachH2Front(t, prefaceFronts, func(t *testing.T, front string) {
				p, _ := hostEcho(t)
				c := dialPrefaceFront(t, front, p)
				sendAsync(c, prefaceThen(t, func(fr *http2.Framer) error {
					return fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
				}))
				h := newH2Wire(c)
				require.True(t, isSettings(h.frame(t)), "the first frame is the server connection preface")
				for {
					if f, ok := h.frame(t).(*http2.SettingsFrame); ok && f.IsAck() {
						return
					}
				}
			})
		},
	},
	{
		id: "rfc9113/3.4/3", name: "the connection preface, a SETTINGS frame and requests to two authorities in one write",
		req: "To avoid unnecessary latency, clients are permitted to send additional frames to the server immediately after sending the client connection preface, without waiting to receive the server connection preface.",
		run: func(t *testing.T) {
			eachPlainH2Front(t, func(t *testing.T, front string) {
				p, _ := hostEcho(t)
				c := dialPlainH2Front(t, front, p, nil)
				block := requestEncoder()
				sendAsync(c, prefaceThen(t, func(fr *http2.Framer) error {
					return errors.Join(fr.WriteSettings(),
						fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block("a.test", "/"), EndHeaders: true, EndStream: true}),
						fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: block("b.test", "/"), EndHeaders: true, EndStream: true}))
				}))
				assert.Equal(t, map[uint32]string{1: "a.test", 3: "b.test"}, newH2Wire(c).bodies(t, 1, 3))
			})
		},
	},
	{
		id: "rfc9113/3.4/4", name: "the connection preface followed by a request in place of SETTINGS",
		req: "Clients and servers MUST treat an invalid connection preface as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.  A GOAWAY frame (Section 6.8) MAY be omitted in this case, since an invalid preface indicates that the peer is not using HTTP/2.",
		run: func(t *testing.T) {
			eachH2Front(t, prefaceFronts, func(t *testing.T, front string) {
				p, n := hostEcho(t)
				c := dialPrefaceFront(t, front, p)
				block := requestEncoder()
				sendAsync(c, prefaceThen(t, func(fr *http2.Framer) error {
					return fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block("a.test", "/"), EndHeaders: true, EndStream: true})
				}))
				h := newH2Wire(c)
				for {
					f, err := h.fr.ReadFrame()
					if err != nil {
						require.True(t, endedCleanly(err), "the connection ends after HTTP/2 frames, got %v", err)
						break
					}
					switch f := f.(type) {
					case *http2.GoAwayFrame:
						assert.Equal(t, http2.ErrCodeProtocol, f.ErrCode, "GOAWAY %v", f.ErrCode)
					case *http2.MetaHeadersFrame, *http2.DataFrame:
						t.Fatalf("a response on stream %d", f.Header().StreamID)
					}
				}
				assert.Zero(t, n.served.Load(), "the request reached its handler")
				assert.Zero(t, n.dialed.Load(), "an upstream connection was dialed")
			})
		},
	},
	{
		id: "rfc9113/3.4/5", name: "the 24 octets of the connection preface with SM altered, then SETTINGS and a request",
		req:  "Clients and servers MUST treat an invalid connection preface as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.  A GOAWAY frame (Section 6.8) MAY be omitted in this case, since an invalid preface indicates that the peer is not using HTTP/2.",
		skip: "net/http serves HTTP/2 over plaintext only on the exact 24 octets and reads anything else as HTTP/1.1, here a request PRI * HTTP/2.0 that edge answers 400 before net/http closes the connection, with no frame sent and nothing routed.",
	},

	// RFC 9113 sections 3.3 and 3.4 toward the origin, HTTP/2 with prior knowledge from edge.
	{
		id: "rfc9113/3.3/5", name: "an HTTP/2 request to a TLS origin selecting no application protocol or http/1.1",
		req:  "This only affects the establishment of HTTP/2 connections over cleartext TCP; HTTP/2 connections over TLS MUST use protocol negotiation in TLS [TLS-ALPN].",
		skip: "net/http uses HTTP/2 over TLS only when ALPN selects h2, and sends such an origin an HTTP/1.1 request.",
	},
	{
		id: "rfc9113/3.4/6", name: "an HTTP/2 request over cleartext to an origin answering in HTTP/2",
		req: "This sequence MUST be followed by a SETTINGS frame (Section 6.5), which MAY be empty.  The client sends the client connection preface as the first application data octets of a connection.",
		run: func(t *testing.T) {
			eachDeclaredFront(t, func(t *testing.T, front string) {
				o := prefaceOrigin(t, respondH2)
				got := h2cGet(t, front, o)
				require.Equal(t, http2.ClientPreface, o.nextNote(t), "the first octets of the connection")
				assert.Equal(t, "SETTINGS stream=0 ack=false", o.nextNote(t), "the frame after the preface")
				assert.Equal(t, "ok", string(got.body))
			})
		},
	},
	{
		id: "rfc9113/3.4/7", name: "the SETTINGS frame of the connection preface of an h2c origin",
		req:  "The SETTINGS frames received from a peer as part of the connection preface MUST be acknowledged (see Section 6.5.3) after sending the connection preface.",
		skip: "Go's HTTP/2 transport acknowledges the SETTINGS frame of the origin's preface after sending its own.",
	},
	{
		id: "rfc9113/3.4/8", name: "an HTTP/1.1 origin answering the connection preface with a 200 response",
		req:  "Clients and servers MUST treat an invalid connection preface as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.  A GOAWAY frame (Section 6.8) MAY be omitted in this case, since an invalid preface indicates that the peer is not using HTTP/2.",
		skip: "Go's HTTP/2 transport reads the status line as a frame header past its maximum frame size, fails the request and closes the connection with no GOAWAY.",
	},
	{
		id: "rfc9113/3.4/9", name: "an h2c origin closing its connection after reading the connection preface",
		req:  "Clients and servers MUST treat an invalid connection preface as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.  A GOAWAY frame (Section 6.8) MAY be omitted in this case, since an invalid preface indicates that the peer is not using HTTP/2.",
		skip: "Go's HTTP/2 transport fails the request with an unexpected EOF and closes the connection with no GOAWAY.",
	},
	{
		id: "rfc9113/3.4/10", name: "an h2c origin answering the connection preface with a response and no SETTINGS frame",
		req:  "Clients and servers MUST treat an invalid connection preface as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.  A GOAWAY frame (Section 6.8) MAY be omitted in this case, since an invalid preface indicates that the peer is not using HTTP/2.",
		skip: "Go's HTTP/2 transport fails the connection with PROTOCOL_ERROR on the HEADERS frame, writes its GOAWAY to the buffered writer of the connection and closes the connection without flushing it, so the GOAWAY reaches the origin only when another write flushed it first.",
	},
	{
		id: "rfc9113/3.4/11", name: "an h2c origin answering the connection preface with a SETTINGS frame with the ACK flag, then a response",
		req:  "Clients and servers MUST treat an invalid connection preface as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.  A GOAWAY frame (Section 6.8) MAY be omitted in this case, since an invalid preface indicates that the peer is not using HTTP/2.",
		skip: "Go's HTTP/2 transport takes any SETTINGS frame for the server connection preface, and one with the ACK flag for the acknowledgment of its own SETTINGS frame, and edge relays the response. Whether a SETTINGS frame with the ACK flag is the potentially empty SETTINGS frame of the server connection preface is left open.",
	},
	{
		id: "rfc9113/6.5/1", name: "an h2c origin answering the connection preface with a SETTINGS frame on stream 1",
		req:  "If an endpoint receives a SETTINGS frame whose Stream Identifier field is anything other than 0x00, the endpoint MUST respond with a connection error (Section 5.4.1) of type PROTOCOL_ERROR.",
		skip: "Go's HTTP/2 transport fails the connection with PROTOCOL_ERROR and closes it, and edge responds with a 502.",
	},
	{
		id: "rfc9113/6.5/2", name: "an h2c origin answering the connection preface with a SETTINGS frame with the ACK flag and a setting",
		req:  "Receipt of a SETTINGS frame with the ACK flag set and a length field value other than 0 MUST be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR.",
		skip: "Go's HTTP/2 transport fails the connection with FRAME_SIZE_ERROR and closes it, and edge responds with a 502.",
	},
	{
		id: "rfc9113/6.5/3", name: "an h2c origin answering the connection preface with a SETTINGS frame of 5 octets",
		req:  "A SETTINGS frame with a length other than a multiple of 6 octets MUST be treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR.",
		skip: "Go's HTTP/2 transport fails the connection with FRAME_SIZE_ERROR and closes it, and edge responds with a 502.",
	},
	{
		id: "rfc9113/6.5.2/1", name: "an h2c origin answering the connection preface with SETTINGS_ENABLE_PUSH set to 2",
		req:  "Any value other than 0 or 1 MUST be treated as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.",
		skip: "Go's HTTP/2 transport fails the connection with PROTOCOL_ERROR and closes it, and edge responds with a 502.",
	},
	{
		id: "rfc9113/6.5.2/2", name: "an h2c origin answering the connection preface with SETTINGS_ENABLE_PUSH set to 1, then a response",
		req:  "A client MUST treat receipt of a SETTINGS frame with SETTINGS_ENABLE_PUSH set to 1 as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.",
		skip: "Go's HTTP/2 transport ignores SETTINGS_ENABLE_PUSH from a server, acknowledges the frame and keeps the connection, and edge relays the response.",
	},
	{
		id: "rfc9113/6.5.2/3", name: "an h2c origin answering the connection preface with SETTINGS_MAX_FRAME_SIZE set to 100",
		req:  "Values outside this range MUST be treated as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.",
		skip: "Go's HTTP/2 transport fails the connection with PROTOCOL_ERROR and closes it, and edge responds with a 502.",
	},
	{
		id: "rfc9113/6.5.2/4", name: "an h2c origin answering the connection preface with SETTINGS_INITIAL_WINDOW_SIZE set to 2^31",
		req:  "Values above the maximum flow-control window size of 2^31-1 MUST be treated as a connection error (Section 5.4.1) of type FLOW_CONTROL_ERROR.",
		skip: "Go's HTTP/2 transport fails the connection with FLOW_CONTROL_ERROR and closes it, and edge responds with a 502.",
	},
	{
		id: "rfc9113/6.5.3/1", name: "an h2c origin reading the connection preface and writing nothing",
		req:  "If the sender of a SETTINGS frame does not receive an acknowledgment within a reasonable amount of time, it MAY issue a connection error (Section 5.4.1) of type SETTINGS_TIMEOUT.",
		skip: "Go's HTTP/2 transport waits for the SETTINGS frame of the origin only before an extended CONNECT and sends any other request at once, and DefaultTransport sets no ResponseHeaderTimeout, so the client of edge waits for the response until the origin closes the connection.",
	},
	{
		id: "rfc9110/15.6.3/1", name: "an HTTP/1.1 origin answering the connection preface with a 200 response",
		req: "The 502 (Bad Gateway) status code indicates that the server, while acting as a gateway or proxy, received an invalid response from an inbound server it accessed while attempting to fulfill the request.",
		run: func(t *testing.T) {
			eachDeclaredFront(t, func(t *testing.T, front string) {
				o := newRawOrigin(t, func(_ *rawOrigin, w *wire) {
					line, err := w.br.ReadString('\n')
					if err != nil {
						return
					}
					answer := okReply
					if line == "PRI * HTTP/2.0\r\n" {
						answer = "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npreface"
					}
					if _, err := io.WriteString(w, answer); err == nil {
						_, _ = io.Copy(io.Discard, w.br)
					}
				})
				wantGatewayErrorH2(t, h2cGet(t, front, o))
			})
		},
	},
	{
		id: "rfc9110/15.6.3/2", name: "an h2c origin closing its connection after reading the connection preface",
		req: "The 502 (Bad Gateway) status code indicates that the server, while acting as a gateway or proxy, received an invalid response from an inbound server it accessed while attempting to fulfill the request.",
		run: func(t *testing.T) {
			eachDeclaredFront(t, func(t *testing.T, front string) {
				o := prefaceOrigin(t, func(_ *rawOrigin, w *wire, fr *http2.Framer) {
					if _, err := fr.ReadFrame(); err == nil && closeWrite(w.Conn) == nil {
						_, _ = io.Copy(io.Discard, w.br)
					}
				})
				wantGatewayErrorH2(t, h2cGet(t, front, o))
			})
		},
	},
	{
		id: "rfc9110/15.6.3/3", name: "an h2c origin answering the connection preface with a response and no SETTINGS frame",
		req: "The 502 (Bad Gateway) status code indicates that the server, while acting as a gateway or proxy, received an invalid response from an inbound server it accessed while attempting to fulfill the request.",
		run: func(t *testing.T) {
			eachDeclaredFront(t, func(t *testing.T, front string) {
				o := prefaceOrigin(t, func(_ *rawOrigin, _ *wire, fr *http2.Framer) {
					for {
						f, err := fr.ReadFrame()
						if err != nil {
							return
						}
						if _, ok := f.(*http2.MetaHeadersFrame); ok && writeOK(fr, f.Header().StreamID) != nil {
							return
						}
					}
				})
				wantGatewayErrorH2(t, h2cGet(t, front, o))
			})
		},
	},

	// RFC 9113, the HTTP/2 front.
	{
		id: "rfc9113/8.2.2/1", name: "an HTTP/1.1 response with connection-specific fields to an HTTP/2 client",
		req: "An intermediary transforming an HTTP/1.x message to HTTP/2 MUST remove connection-specific header fields as discussed in Section 7.6.1 of [HTTP], or their messages will be treated by other HTTP/2 endpoints as malformed (Section 8.1.1).",
		run: func(t *testing.T) {
			eachH2Front(t, h1UpstreamFronts, func(t *testing.T, front string) {
				_, h := h2FrontBench(t, front, always("HTTP/1.1 200 OK\r\nConnection: X-Hop\r\nX-Hop: 1\r\nKeep-Alive: timeout=5\r\n"+
					"Proxy-Connection: keep-alive\r\nUpgrade: h2c\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"))
				h.headers(t, 1, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"))
				got := h.reply(t, 1)
				require.False(t, got.reset, "stream reset with %v", got.rst)
				assert.Equal(t, "ok", string(got.body))
				// net/http's HTTP/2 server drops Connection and Transfer-Encoding whatever edge forwards.
				for _, name := range []string{"connection", "x-hop", "keep-alive", "proxy-connection", "upgrade", "transfer-encoding"} {
					_, ok := h2Field(got.fields, name)
					assert.False(t, ok, name)
				}
			})
		},
	},
	{
		id: "rfc9113/8.1.1/1", name: "a request whose stream ends before its Content-Length",
		req: "Malformed requests or responses that are detected MUST be treated as a stream error (Section 5.4.2) of type PROTOCOL_ERROR.  For malformed requests, a server MAY send an HTTP response prior to closing or resetting the stream.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				_, h := h2FrontBench(t, front, drainOrigin(""))
				h.headers(t, 1, false, hf(":method", "POST"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"),
					hf("content-length", "10"))
				require.NoError(t, h.fr.WriteData(1, true, []byte("abcd")))
				wantMalformedH2(t, h.reply(t, 1))
			})
		},
	},
	{
		id: "rfc9113/8.1.1/2", name: "a request with a Content-Length of 0 and a DATA frame",
		req: "Intermediaries that process HTTP requests or responses (i.e., any intermediary not acting as a tunnel) MUST NOT forward a malformed request or response.  Malformed requests or responses that are detected MUST be treated as a stream error (Section 5.4.2) of type PROTOCOL_ERROR.",
		run: func(t *testing.T) {
			eachH2Front(t, h1UpstreamFronts, func(t *testing.T, front string) {
				b, h := h2FrontBench(t, front, func(o *rawOrigin, w *wire) {
					req, err := http.ReadRequest(w.br)
					if err != nil {
						return
					}
					o.note(req.Method + " " + req.RequestURI)
					if _, err := io.ReadAll(req.Body); err != nil {
						return
					}
					_, _ = io.WriteString(w, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok")
				})
				h.headers(t, 1, false, hf(":method", "POST"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"),
					hf("content-length", "0"))
				// The response to stream 3 shows the handler of stream 1 started before its DATA frame.
				h.headers(t, 3, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/next"))
				require.Equal(t, "ok", string(h.reply(t, 3).body))
				require.NoError(t, h.fr.WriteData(1, true, []byte("abcd")))
				wantMalformedH2(t, h.reply(t, 1))
				for range b.origin.accepted.Load() {
					b.origin.ended(t)
				}
				var got []string
				for len(b.origin.notes) > 0 {
					got = append(got, <-b.origin.notes)
				}
				assert.Equal(t, []string{"GET /next"}, got, "the requests the origin received")
			})
		},
	},
	{
		id: "rfc9113/8.1.1/3", name: "a request with a Content-Length that is no decimal and no content",
		req: "A request or response is also malformed if the value of a content-length header field does not equal the sum of the DATA frame payload lengths that form the content, unless the message is defined as having no content.",
		run: func(t *testing.T) {
			eachH2Front(t, h1UpstreamFronts, func(t *testing.T, front string) {
				for _, end := range []string{"headers", "empty data"} {
					t.Run(end, func(t *testing.T) {
						b, h := h2FrontBench(t, front, always(okReply))
						h.headers(t, 1, end == "headers", hf(":method", "POST"), hf(":scheme", "http"), hf(":authority", "origin.test"),
							hf(":path", "/"), hf("content-length", "abc"))
						if end == "empty data" {
							require.NoError(t, h.fr.WriteData(1, true, nil))
						}
						wantMalformedH2(t, h.reply(t, 1))
						h.headers(t, 3, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/next"))
						require.Equal(t, "ok", string(h.reply(t, 3).body))
						assert.Equal(t, "GET /next HTTP/1.1", startLine(b.origin.next(t).head))
					})
				}
			})
		},
	},
	{
		id: "rfc9113/8.3/1", name: "a request with a pseudo-header field in its trailer section",
		req: "Pseudo-header fields MUST NOT appear in a trailer section.  Endpoints MUST treat a request or response that contains undefined or invalid pseudo-header fields as malformed (Section 8.1.1).",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				_, h := h2FrontBench(t, front, drainOrigin(""))
				h.headers(t, 1, false, hf(":method", "POST"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"))
				require.NoError(t, h.fr.WriteData(1, false, []byte("a")))
				h.headers(t, 1, true, hf(":path", "/"))
				wantMalformedH2(t, h.reply(t, 1))
			})
		},
	},
	{
		id: "rfc9113/8.3/2", name: "a request with an :authority whose host RFC 3986 does not allow",
		req: "Endpoints MUST treat a request or response that contains undefined or invalid pseudo-header fields as malformed (Section 8.1.1).",
		run: func(t *testing.T) {
			eachH2Front(t, h1UpstreamFronts, func(t *testing.T, front string) {
				b, h := h2FrontBench(t, front, always(okReply))
				b.p.MustAdd("+{any}/*{any}", forwardHandler)
				for i, authority := range invalidAuthorities {
					t.Run(strconv.Quote(authority), func(t *testing.T) {
						id := uint32(2*i + 1)
						h.headers(t, id, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", authority), hf(":path", "/"))
						wantMalformedH2(t, h.reply(t, id))
					})
				}
				assert.Equal(t, int32(0), b.origin.accepted.Load(), "the proxy forwarded a malformed request")
			})
		},
	},
	{
		id: "rfc9113/8.3.1/1", name: "a request whose Host differs from :authority",
		req: "The recipient of an HTTP/2 request MUST NOT use the Host header field to determine the target URI if \":authority\" is present.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				p, _ := hostEcho(t)
				h := dialH2Wire(t, front, p, "a.test")
				h.headers(t, 1, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "a.test"), hf(":path", "/"),
					hf("host", "b.test"))
				got := h.reply(t, 1)
				if status, _ := h2Field(got.fields, ":status"); got.reset || status != "200" {
					wantMalformedH2(t, got)
					return
				}
				assert.Equal(t, "a.test", string(got.body))
			})
		},
	},
	{
		id: "rfc9113/8.3.1/2", name: "a request forwarded over HTTP/1.1",
		req: "An intermediary that needs to generate a Host header field (which might be necessary to construct an HTTP/1.1 request) MUST use the value from the \":authority\" pseudo-header field as the value of the Host field, unless the intermediary also changes the request target.",
		run: func(t *testing.T) {
			eachH2Front(t, h1UpstreamFronts, func(t *testing.T, front string) {
				b, h := h2FrontBench(t, front, always(okReply))
				h.headers(t, 1, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test:8080"), hf(":path", "/x"))
				h.reply(t, 1)
				got := b.origin.next(t)
				assert.Equal(t, "GET /x HTTP/1.1", startLine(got.head))
				assert.Equal(t, []string{"origin.test:8080"}, fieldValues(got.head, "Host"))
			})
		},
	},
	{
		id: "rfc9113/8.5/1", name: "CONNECT on a stream, a request inside",
		req: "Once this connection is successfully established, the proxy sends a HEADERS frame containing a 2xx-series status code to the client, as defined in Section 9.3.6 of [HTTP].",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			h := dialH2(t, b.addr)
			fields := h.h2Connect(t)
			_, ok := h2Field(fields, "content-length")
			assert.False(t, ok, "a 2xx answer to CONNECT has no content-length")

			require.NoError(t, h.fr.WriteData(1, false, []byte("GET /in HTTP/1.1\r\nHost: origin.test\r\n\r\n")))
			var data []byte
			for !bytes.HasSuffix(data, []byte("\r\n\r\nok")) {
				f, ok := h.next(t, 1).(*h2Data)
				require.True(t, ok, "only DATA follows the 2xx on a CONNECT stream")
				data = append(data, f.data...)
			}
			resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "GET /in HTTP/1.1", startLine(b.origin.next(t).head))
		},
	},
	{
		id: "rfc9113/8.5/2", name: "END_STREAM from the client on a stream tunnel",
		req: "A proxy that receives a DATA frame with the END_STREAM flag set sends the attached data with the FIN bit set on the last TCP segment.",
		run: func(t *testing.T) {
			b := newProxyBench(t, drainOrigin("pong"))
			b.p.MustAdd("origin.test", relayStream)
			h := dialH2(t, b.addr)
			h.h2Connect(t)
			require.NoError(t, h.fr.WriteData(1, true, []byte("\x01ping")))
			assert.Equal(t, "\x01ping", b.origin.nextNote(t))
			got := h.reply(t, 1)
			require.False(t, got.reset, "stream reset with %v", got.rst)
			assert.Equal(t, "pong", string(got.body))
		},
	},
	{
		id: "rfc9113/8.5/3", name: "FIN from the origin while the client is still sending",
		req:  "A proxy that receives a TCP segment with the FIN bit set sends a DATA frame with the END_STREAM flag set.",
		skip: "net/http gives a handler no way to end its half of an HTTP/2 stream while it reads the other, so h2Stream.CloseWrite is a no-op on HTTP/2.",
	},
	{
		id: "rfc9113/8.5/4", name: "a TCP reset from the origin",
		req: "A proxy treats any error in the TCP connection, which includes receiving a TCP segment with the RST bit set, as a stream error (Section 5.4.2) of type CONNECT_ERROR.",
		run: func(t *testing.T) {
			b := newProxyBench(t, func(o *rawOrigin, w *wire) {
				buf := make([]byte, 5)
				if _, err := io.ReadFull(w.br, buf); err != nil {
					return
				}
				o.note(string(buf))
				_ = w.Conn.(*net.TCPConn).SetLinger(0)
			})
			b.p.MustAdd("origin.test", relayStream)
			h := dialH2(t, b.addr)
			h.h2Connect(t)
			require.NoError(t, h.fr.WriteData(1, false, []byte("\x01ping")))
			assert.Equal(t, "\x01ping", b.origin.nextNote(t))
			got := h.reply(t, 1)
			require.True(t, got.reset, "the stream ended with END_STREAM")
			// net/http resets the stream of an aborted handler with INTERNAL_ERROR and cannot
			// send CONNECT_ERROR.
			assert.Contains(t, []http2.ErrCode{http2.ErrCodeConnect, http2.ErrCodeInternal}, got.rst)
		},
	},
	{
		id: "rfc9113/8.5/5", name: "RST_STREAM from the client on a stream tunnel",
		req: "Correspondingly, a proxy MUST send a TCP segment with the RST bit set if it detects an error with the stream or the HTTP/2 connection.",
		run: func(t *testing.T) {
			b := newProxyBench(t, func(o *rawOrigin, w *wire) {
				buf := make([]byte, 5)
				if _, err := io.ReadFull(w.br, buf); err != nil {
					return
				}
				o.note(string(buf))
				_, err := w.br.ReadByte()
				o.note(fmt.Sprint(errors.Is(err, syscall.ECONNRESET)))
			})
			b.p.MustAdd("origin.test", relayStream)
			h := dialH2(t, b.addr)
			h.h2Connect(t)
			require.NoError(t, h.fr.WriteData(1, false, []byte("\x01ping")))
			assert.Equal(t, "\x01ping", b.origin.nextNote(t))
			require.NoError(t, h.fr.WriteRSTStream(1, http2.ErrCodeCancel))
			assert.Equal(t, "true", b.origin.nextNote(t), "the origin read a FIN where a reset was due")
		},
	},
	{
		id: "rfc9113/8.5/6", name: "HEADERS on a stream tunnel",
		req:  "Frame types other than DATA or stream management frames (RST_STREAM, WINDOW_UPDATE, and PRIORITY) MUST NOT be sent on a connected stream and MUST be treated as a stream error (Section 5.4.2) if received.",
		skip: "net/http reads a HEADERS frame on a CONNECT stream as its trailer section and ends the request body cleanly, before edge gets the frame.",
	},
	{
		id: "rfc9113/8.5/7", name: "CONNECT over HTTP/2 to a destination that refuses the connection",
		req:  "Once this connection is successfully established, the proxy sends a HEADERS frame containing a 2xx-series status code to the client, as defined in Section 9.3.6 of [HTTP].",
		skip: "Edge answers 200 before it dials on purpose, so the client sends the ClientHello whose name routes and a handler may serve the exchange locally, as connectHijack in connect.go records.",
	},
	{
		id: "rfc9113/8.5/8", name: "a dial refused after the 200 answering a CONNECT over HTTP/2",
		req: "A proxy treats any error in the TCP connection, which includes receiving a TCP segment with the RST bit set, as a stream error (Section 5.4.2) of type CONNECT_ERROR.",
		run: func(t *testing.T) {
			b := newRefusingBench(t)
			h := dialH2(t, b.addr)
			h.h2Connect(t)
			require.NoError(t, h.fr.WriteData(1, false, []byte("\x01ping")))
			got := h.reply(t, 1)
			require.True(t, got.reset, "the stream ended with END_STREAM")
			// net/http resets the stream of an aborted handler with INTERNAL_ERROR and cannot
			// send CONNECT_ERROR.
			assert.Contains(t, []http2.ErrCode{http2.ErrCodeConnect, http2.ErrCodeInternal}, got.rst)
		},
	},

	{
		id: "rfc9113/9.1.1/1", name: "requests for two origins on one HTTP/2 connection",
		req: "A server that does not wish clients to reuse connections can indicate that it is not authoritative for a request by sending a 421 (Misdirected Request) status code in response to the request (see Section 15.5.20 of [HTTP]).",
		run: func(t *testing.T) {
			eachTerminatedFront(t, []string{viaH2}, func(t *testing.T, front, version string) {
				b := newMisdirectBench(t)
				_, get := dialTerminated(t, b, front, version, "origin.test")
				for _, host := range []string{"origin.test", "other.test", "origin.test"} {
					want := http.StatusOK
					if host == "other.test" {
						want = http.StatusMisdirectedRequest
					}
					code, _ := get(t, host)
					assert.Equal(t, want, code, host)
				}
				assert.Equal(t, "origin.test", b.origin.next(t).req.Host)
				assert.Equal(t, "origin.test", b.origin.next(t).req.Host)
			})
		},
	},

	// RFC 9114, the HTTP/3 front.
	{
		id: "rfc9114/4.1/1", name: "a HEADERS frame after the trailer section of a request",
		req:  "Receipt of an invalid sequence of frames MUST be treated as a connection error of type H3_FRAME_UNEXPECTED.  In particular, a DATA frame before any HEADERS frame, or a HEADERS or DATA frame after the trailing HEADERS frame, is considered invalid.",
		skip: "quic-go fails the request body on a frame after the trailer section and leaves the connection open, and edge answers 400 once the body fails.",
	},
	{
		id: "rfc9114/4.1.1/1", name: "an origin failing after part of its response",
		req: "When a server abandons a response after partial processing, it SHOULD abort its response stream with the error code H3_REQUEST_CANCELLED.",
		run: func(t *testing.T) {
			for _, origin := range []string{viaH1, viaH3} {
				t.Run(origin, func(t *testing.T) {
					code, reset := h3ResetCode(cutResponse(t, origin))
					require.True(t, reset, "the response ended with a FIN")
					assert.Equal(t, http3.ErrCodeRequestCanceled, code)
				})
			}
		},
	},
	{
		id: "rfc9114/4.1.2/1", name: "a request whose DATA exceed its Content-Length",
		req:  "Intermediaries that process HTTP requests or responses (i.e., any intermediary not acting as a tunnel) MUST NOT forward a malformed request or response.",
		skip: "Edge streams a request body to the origin as its DATA frames arrive, so the origin reads a request complete at its Content-Length before the frame that makes it malformed.",
	},
	{
		id: "rfc9114/4.1.2/2", name: "a request whose stream ends before its Content-Length",
		req:  "Intermediaries that process HTTP requests or responses (i.e., any intermediary not acting as a tunnel) MUST NOT forward a malformed request or response.",
		skip: "Edge streams a request body to the origin as its DATA frames arrive, so the origin reads the header section and the first bytes of content before the end of the stream makes the request malformed.",
	},
	{
		id: "rfc9114/4.1.2/3", name: "a request with a pseudo-header field in its trailer section",
		req:  "Intermediaries that process HTTP requests or responses (i.e., any intermediary not acting as a tunnel) MUST NOT forward a malformed request or response.",
		skip: "Edge streams a request body to the origin as its DATA frames arrive, so the origin reads the header section and the content before the trailer section that makes the request malformed.",
	},
	{
		id: "rfc9114/4.1.2/4", name: "a response from an HTTP/1.1 origin shorter than its Content-Length",
		req: "Intermediaries that process HTTP requests or responses (i.e., any intermediary not acting as a tunnel) MUST NOT forward a malformed request or response.",
		run: func(t *testing.T) {
			_, reset := h3ErrCode(cutResponse(t, viaH1))
			assert.True(t, reset, "the response ended with a FIN")
		},
	},
	{
		id: "rfc9114/4.1.2/5", name: "a request whose stream ends before its Content-Length",
		req: "Malformed requests or responses that are detected MUST be treated as a stream error of type H3_MESSAGE_ERROR.  For malformed requests, a server MAY send an HTTP response indicating the error prior to closing or resetting the stream.",
		run: func(t *testing.T) {
			b := newTLSProxyBench(t, always(okReply))
			h := b.dialH3Front(t)
			got := h.roundTrip(t, h3Request("POST", "origin.test", "/", hf("content-length", "10")), h3Data("abcd"))
			wantMalformedRequest(t, got, http3.ErrCodeMessageError, http3.ErrCodeRequestIncomplete)
		},
	},
	{
		id: "rfc9114/4.1.2/8", name: "a request with a Content-Length of 0 and a DATA frame",
		req: "Malformed requests or responses that are detected MUST be treated as a stream error of type H3_MESSAGE_ERROR.  For malformed requests, a server MAY send an HTTP response indicating the error prior to closing or resetting the stream.",
		run: func(t *testing.T) {
			for _, origin := range []string{viaH1, viaH3} {
				t.Run(origin, func(t *testing.T) {
					var b *proxyBench
					if origin == viaH3 {
						b = newH3OriginBench(t, h3Reply(h3Headers([]hpack.HeaderField{hf(":status", "200")}), h3Data("ok")))
					} else {
						b = newTLSProxyBench(t, always(okReply))
					}
					got := b.dialH3Front(t).roundTrip(t, h3Request("POST", "origin.test", "/", hf("content-length", "0")), h3Data("abcd"))
					wantMalformedRequest(t, got, http3.ErrCodeMessageError)
					assert.Zero(t, b.origin.accepted.Load(), "the proxy reached the origin")
				})
			}
		},
	},
	{
		id: "rfc9114/4.2/1", name: "an HTTP/1.1 response with connection-specific fields to an HTTP/3 client",
		req: "An intermediary transforming an HTTP/1.x message to HTTP/3 MUST remove connection-specific header fields as discussed in Section 7.6.1 of [HTTP], or their messages will be treated by other HTTP/3 endpoints as malformed.",
		run: func(t *testing.T) {
			b := newTLSProxyBench(t, always("HTTP/1.1 200 OK\r\nConnection: X-Hop\r\nX-Hop: 1\r\nKeep-Alive: timeout=5\r\n"+
				"Proxy-Connection: keep-alive\r\nUpgrade: h2c\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n"))
			h := b.dialH3Front(t)
			got := h.roundTrip(t, h3Request("GET", "origin.test", "/"))
			require.NoError(t, got.err)
			assert.Equal(t, "ok", string(got.body))
			for _, name := range []string{"connection", "x-hop", "keep-alive", "proxy-connection", "upgrade", "transfer-encoding"} {
				_, ok := h2Field(got.fields, name)
				assert.False(t, ok, name)
			}
		},
	},
	{
		id: "rfc9114/4.2/3", name: "a request with an uppercase field name in its trailer section",
		req: "A request or response containing uppercase characters in field names MUST be treated as malformed.",
		run: func(t *testing.T) {
			// A request with content and a Content-Length can be complete upstream before its trailer
			// section, as rfc9114/4.1.2/3 records.
			for _, tc := range []struct {
				name    string
				content string
				extra   []hpack.HeaderField
			}{
				{name: "without content", extra: []hpack.HeaderField{hf("content-length", "0")}},
				{name: "content of unknown length", content: "a"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					b := newTLSProxyBench(t, always(okReply))
					got := b.dialH3Front(t).roundTrip(t,
						h3Request("POST", "origin.test", "/", append(tc.extra, hf("trailer", "x-check"))...),
						h3Data(tc.content), h3Headers([]hpack.HeaderField{hf("X-Check", "sum")}))
					wantMalformedRequest(t, got, http3.ErrCodeMessageError)
				})
			}
		},
	},
	{
		id: "rfc9114/4.2/2", name: "an HTTP/2 response with connection-specific fields to an HTTP/3 client",
		req:  "An endpoint MUST NOT generate an HTTP/3 field section containing connection-specific fields; any message containing connection-specific fields MUST be treated as malformed.",
		skip: "Go's HTTP/2 transport drops the Connection field of a response before edge reads it, where RFC 9113 makes the response malformed, so a field Connection listed reaches the client.",
	},
	{
		id: "rfc9114/4.3/1", name: "a request with a pseudo-header field in its trailer section",
		req: "Pseudo-header fields MUST NOT appear in trailer sections.  Endpoints MUST treat a request or response that contains undefined or invalid pseudo-header fields as malformed.",
		run: func(t *testing.T) {
			b := newTLSProxyBench(t, always(okReply))
			h := b.dialH3Front(t)
			got := h.roundTrip(t, h3Request("POST", "origin.test", "/"), h3Data("a"), h3Headers([]hpack.HeaderField{hf(":path", "/")}))
			wantMalformedRequest(t, got, http3.ErrCodeMessageError)
		},
	},
	{
		id: "rfc9114/4.3/2", name: "a request with an :authority whose host RFC 3986 does not allow",
		req: "Endpoints MUST treat a request or response that contains undefined or invalid pseudo-header fields as malformed.",
		run: func(t *testing.T) {
			b := newTLSProxyBench(t, always(okReply))
			b.p.MustAdd("+{any}/*{any}", forwardHandler)
			h := b.dialH3Front(t)
			for _, authority := range invalidAuthorities {
				t.Run(strconv.Quote(authority), func(t *testing.T) {
					wantMalformedRequest(t, h.roundTrip(t, h3Request("GET", authority, "/")), http3.ErrCodeMessageError)
				})
			}
			assert.Equal(t, int32(0), b.origin.accepted.Load(), "the proxy forwarded a malformed request")
		},
	},
	{
		id: "rfc9114/4.3.1/1", name: "a request for an http URI over HTTP/3",
		req:  "\":scheme\":  Contains the scheme portion of the target URI (Section 3.1 of [URI]).",
		skip: "quic-go exposes no :scheme to a handler, so edge takes the scheme of the connection, as CLAUDE.md records, and a request for an http URI goes out over TLS.",
	},
	{
		id: "rfc9114/4.3.1/2", name: "a request forwarded over HTTP/1.1",
		req: "An intermediary that converts an HTTP/3 request to HTTP/1.1 MUST create a Host field if one is not present in a request by copying the value of the :authority pseudo-header field.",
		run: func(t *testing.T) {
			b := newTLSProxyBench(t, always(okReply))
			h := b.dialH3Front(t)
			h.roundTrip(t, h3Request("GET", "origin.test:8443", "/x"))
			got := b.origin.next(t)
			assert.Equal(t, "GET /x HTTP/1.1", startLine(got.head))
			assert.Equal(t, []string{"origin.test:8443"}, fieldValues(got.head, "Host"))
		},
	},
	{
		id: "rfc9114/4.3.1/3", name: "a request without :scheme",
		req:  "All HTTP/3 requests MUST include exactly one value for the :method, :scheme, and :path pseudo-header fields, unless the request is a CONNECT request; see Section 4.4.",
		skip: "quic-go accepts a request without :scheme and exposes none to a handler, so edge has no way to find the request malformed and forwards it.",
	},
	{
		id: "rfc9114/4.4/1", name: "CONNECT over HTTP/3 to an authority without a port",
		req:  "A CONNECT request that does not conform to these restrictions is malformed.",
		skip: "Edge reads a CONNECT target without a port as port 443 on purpose, targetFromConnect in connect.go records it.",
	},
	{
		id: "rfc9114/4.4/2", name: "CONNECT on a stream, a request inside",
		req: "Once this connection is successfully established, the proxy sends a HEADERS frame containing a 2xx series status code to the client, as defined in Section 15.3 of [HTTP].",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			h := b.dialH3Front(t)
			s := h.connect(t, "origin.test:80")
			s.send(t, h3Data("GET /in HTTP/1.1\r\nHost: origin.test\r\n\r\n"))
			var data []byte
			for !bytes.HasSuffix(data, []byte("\r\n\r\nok")) {
				typ, payload, err := s.next()
				require.NoError(t, err)
				require.Equal(t, uint64(h3FrameData), typ, "only DATA follows the 2xx on a CONNECT stream")
				data = append(data, payload...)
			}
			resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "GET /in HTTP/1.1", startLine(b.origin.next(t).head))
		},
	},
	{
		id: "rfc9114/4.4/3", name: "CONNECT over HTTP/3 to a destination that refuses the connection",
		req:  "Once this connection is successfully established, the proxy sends a HEADERS frame containing a 2xx series status code to the client, as defined in Section 15.3 of [HTTP].",
		skip: "Edge answers 200 before it dials on purpose, so the client sends the ClientHello whose name routes and a handler may serve the exchange locally, as connectHijack in connect.go records.",
	},
	{
		id: "rfc9114/4.4/4", name: "HEADERS on a stream tunnel",
		req:  "Once the CONNECT method has completed, only DATA frames are permitted to be sent on the stream.  Extension frames MAY be used if specifically permitted by the definition of the extension.  Receipt of any other known frame type MUST be treated as a connection error of type H3_FRAME_UNEXPECTED.",
		skip: "quic-go reads a HEADERS frame on a CONNECT stream as its trailer section and leaves the connection open, before edge gets the frame.",
	},
	{
		id: "rfc9114/4.4/5", name: "FIN from the client on a stream tunnel",
		req: "When the client ends the request stream (that is, the receive stream at the proxy enters the \"Data Recvd\" state), the proxy will set the FIN bit on its connection to the TCP server.",
		run: func(t *testing.T) {
			b := newProxyBench(t, drainOrigin("pong"))
			b.p.MustAdd("origin.test", relayStream)
			h := b.dialH3Front(t)
			s := h.connect(t, "origin.test:80")
			s.send(t, h3Data("\x01ping"))
			require.NoError(t, s.Close())
			assert.Equal(t, "\x01ping", b.origin.nextNote(t))
			got := s.message(true)
			require.NoError(t, got.err)
			assert.Equal(t, "pong", string(got.body))
		},
	},
	{
		id: "rfc9114/4.4/6", name: "FIN from the origin while the client is still sending",
		req: "When the proxy receives a packet with the FIN bit set, it will close the send stream that it sends to the client.",
		run: func(t *testing.T) {
			b := newProxyBench(t, func(o *rawOrigin, w *wire) {
				buf := make([]byte, 5)
				if _, err := io.ReadFull(w.br, buf); err != nil {
					return
				}
				_, _ = io.WriteString(w, "pong")
				_ = w.Conn.(*net.TCPConn).CloseWrite()
				rest, _ := io.ReadAll(w.br)
				o.note(string(rest))
			})
			b.p.MustAdd("origin.test", relayStream)
			h := b.dialH3Front(t)
			s := h.connect(t, "origin.test:80")
			s.send(t, h3Data("\x01ping"))
			require.NoError(t, s.SetReadDeadline(time.Now().Add(3*time.Second)))
			got := s.message(true)
			require.NoError(t, got.err, "the stream to the client was not closed after %q", got.body)
			assert.Equal(t, "pong", string(got.body))
			s.send(t, h3Data("more"))
			require.NoError(t, s.Close())
			assert.Equal(t, "more", b.origin.nextNote(t))
		},
	},
	{
		id: "rfc9114/4.4/7", name: "a TCP reset from the origin",
		req: "A proxy treats any error in the TCP connection, which includes receiving a TCP segment with the RST bit set, as a stream error of type H3_CONNECT_ERROR.",
		run: func(t *testing.T) {
			b := newProxyBench(t, func(o *rawOrigin, w *wire) {
				buf := make([]byte, 5)
				if _, err := io.ReadFull(w.br, buf); err != nil {
					return
				}
				o.note(string(buf))
				_ = w.Conn.(*net.TCPConn).SetLinger(0)
			})
			b.p.MustAdd("origin.test", relayStream)
			h := b.dialH3Front(t)
			s := h.connect(t, "origin.test:80")
			s.send(t, h3Data("\x01ping"))
			assert.Equal(t, "\x01ping", b.origin.nextNote(t))
			got := s.message(true)
			code, reset := h3ErrCode(got.err)
			require.True(t, reset, "the stream ended with a FIN")
			assert.Equal(t, http3.ErrCodeConnectError, code)
		},
	},
	{
		id: "rfc9114/4.4/8", name: "STOP_SENDING from the client on a stream tunnel",
		req: "If the proxy detects that the client has reset the stream or aborted reading from the stream, it MUST close the TCP connection.",
		run: func(t *testing.T) {
			b := newProxyBench(t, func(o *rawOrigin, w *wire) {
				buf := make([]byte, 5)
				if _, err := io.ReadFull(w.br, buf); err != nil {
					return
				}
				o.note(string(buf))
				// Enough data that the proxy writes to the stream after the client aborted
				// reading it.
				_, err := w.Write(make([]byte, 8<<20))
				var ne net.Error
				o.note(fmt.Sprint(err != nil && !(errors.As(err, &ne) && ne.Timeout())))
			})
			b.p.MustAdd("origin.test", relayStream)
			h := b.dialH3Front(t)
			s := h.connect(t, "origin.test:80")
			s.send(t, h3Data("\x01ping"))
			assert.Equal(t, "\x01ping", b.origin.nextNote(t))
			s.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			assert.Equal(t, "true", b.origin.nextNote(t), "the connection to the origin stayed open")
		},
	},
	{
		id: "rfc9114/4.4/9", name: "a reset from the client, the other direction",
		req: "If the stream is reset or reading is aborted by the client, a proxy SHOULD perform the same operation on the other direction in order to ensure that both directions of the stream are cancelled.",
		run: func(t *testing.T) {
			b := newProxyBench(t, func(o *rawOrigin, w *wire) {
				buf := make([]byte, 5)
				if _, err := io.ReadFull(w.br, buf); err != nil {
					return
				}
				o.note(string(buf))
				_, _ = w.br.ReadByte()
			})
			b.p.MustAdd("origin.test", relayStream)
			h := b.dialH3Front(t)
			s := h.connect(t, "origin.test:80")
			s.send(t, h3Data("\x01ping"))
			assert.Equal(t, "\x01ping", b.origin.nextNote(t))
			s.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			_, err := io.ReadAll(s.br)
			_, reset := h3ErrCode(err)
			assert.True(t, reset, "the proxy ended its direction with a FIN")
		},
	},
	{
		id: "rfc9114/4.4/10", name: "a reset from the client on a stream tunnel",
		req: "In all these cases, if the underlying TCP implementation permits it, the proxy SHOULD send a TCP segment with the RST bit set.",
		run: func(t *testing.T) {
			b := newProxyBench(t, func(o *rawOrigin, w *wire) {
				buf := make([]byte, 5)
				if _, err := io.ReadFull(w.br, buf); err != nil {
					return
				}
				o.note(string(buf))
				_, err := w.br.ReadByte()
				o.note(fmt.Sprint(errors.Is(err, syscall.ECONNRESET)))
			})
			b.p.MustAdd("origin.test", relayStream)
			h := b.dialH3Front(t)
			s := h.connect(t, "origin.test:80")
			s.send(t, h3Data("\x01ping"))
			assert.Equal(t, "\x01ping", b.origin.nextNote(t))
			s.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			assert.Equal(t, "true", b.origin.nextNote(t), "the origin read a FIN where a reset was due")
		},
	},
	{
		id: "rfc9114/4.4/11", name: "CONNECT over HTTP/3 to an authority no entry admits",
		req: "Since CONNECT creates a tunnel to an arbitrary server, proxies that support CONNECT SHOULD restrict its use to a set of known ports or a list of safe request targets; see Section 9.3.6 of [HTTP] for more details.",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			h := b.dialH3Front(t)
			s := h.open(t, h3Headers([]hpack.HeaderField{hf(":method", "CONNECT"), hf(":authority", "elsewhere.test:25")}))
			assert.Equal(t, "403", s.message(true).status())
			assert.Zero(t, b.origin.accepted.Load())
		},
	},
	{
		id: "rfc9114/5.2/1", name: "a shutdown with a request in flight",
		req: "Servers SHOULD send a GOAWAY frame when the closing of a connection is known in advance, even if the advance notice is small, so that the remote peer can know whether or not a request has been partially processed.",
		run: func(t *testing.T) {
			b := newTLSProxyBench(t, func(o *rawOrigin, w *wire) {
				r, err := w.readRequest()
				if err != nil {
					return
				}
				o.got <- r
				_, _ = io.Copy(io.Discard, w.br)
			})
			h := b.dialH3Front(t)
			s := h.open(t, h3Request("GET", "origin.test", "/slow"))
			require.NoError(t, s.Close())
			b.origin.next(t)
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			go func() { _ = b.p.Shutdown(ctx) }()
			select {
			case id := <-h.goaway:
				assert.Zero(t, id%4, "the GOAWAY identifier is a client-initiated bidirectional stream ID")
				assert.Greater(t, id, uint64(s.StreamID()), "the request in flight is past the GOAWAY")
			case <-time.After(3 * time.Second):
				t.Fatal("no GOAWAY")
			}
		},
	},
	{
		id: "rfc9114/5.2/2", name: "a second GOAWAY from the client with a larger identifier",
		req:  "Receiving a GOAWAY containing a larger identifier than previously received MUST be treated as a connection error of type H3_ID_ERROR.",
		skip: "quic-go ignores a GOAWAY from a client, and edge never reads the control stream.",
	},
	{
		id: "rfc9114/7.1/1", name: "a SETTINGS frame with a byte past its last setting",
		req:  "A frame payload that contains additional bytes after the identified fields or a frame payload that terminates before the end of the identified fields MUST be treated as a connection error of type H3_FRAME_ERROR.",
		skip: "quic-go closes the connection with H3_CLOSED_CRITICAL_STREAM, and edge never reads the control stream.",
	},
	{
		id: "rfc9114/7.1/2", name: "a request stream ending inside a DATA frame",
		req:  "When a stream terminates cleanly, if the last frame on the stream was truncated, this MUST be treated as a connection error of type H3_FRAME_ERROR.",
		skip: "quic-go ends the request body cleanly where the stream ends inside a DATA frame and leaves the connection open, so edge forwards the content it received, or answers 400 when that content falls short of its Content-Length.",
	},
	{
		id: "rfc9114/7.2.3/1", name: "CANCEL_PUSH from the client for a push never promised",
		req:  "If a server receives a CANCEL_PUSH frame for a push ID that has not yet been mentioned by a PUSH_PROMISE frame, this MUST be treated as a connection error of type H3_ID_ERROR.",
		skip: "quic-go ignores CANCEL_PUSH, and edge never reads the control stream.",
	},
	{
		id: "rfc9114/7.2.4.1/1", name: "SETTINGS with a setting HTTP/2 defined",
		req:  "Setting identifiers that were defined in [HTTP/2] where there is no corresponding HTTP/3 setting have also been reserved (Section 11.2.2).  These reserved settings MUST NOT be sent, and their receipt MUST be treated as a connection error of type H3_SETTINGS_ERROR.",
		skip: "quic-go ignores the settings 0x00 and 0x02 to 0x05, and edge never reads the control stream.",
	},
	{
		id: "rfc9114/7.2.5/1", name: "PUSH_PROMISE from the client",
		req:  "A client MUST NOT send a PUSH_PROMISE frame.  A server MUST treat the receipt of a PUSH_PROMISE frame as a connection error of type H3_FRAME_UNEXPECTED.",
		skip: "quic-go skips PUSH_PROMISE as a frame of unknown type, on the control stream and on a request stream, before edge gets it.",
	},
	{
		id: "rfc9114/9/1", name: "a reserved frame type before SETTINGS on the control stream",
		req:  "However, where a known frame type is required to be in a specific location, such as the SETTINGS frame as the first frame of the control stream (see Section 6.2.1), an unknown frame type does not satisfy that requirement and SHOULD be treated as an error.",
		skip: "quic-go skips a frame of unknown type ahead of SETTINGS and leaves the connection open, and edge never reads the control stream.",
	},

	// RFC 9114, HTTP/3 toward the origin.
	{
		id: "rfc9114/4.1.1/2", name: "an HTTP/3 origin resetting its stream after part of the response",
		req: "However, if a stream is cancelled after receiving a partial response, the response SHOULD NOT be used.",
		run: func(t *testing.T) {
			_, reset := h3ErrCode(cutResponse(t, viaH3))
			assert.True(t, reset, "the partial response ended with a FIN")
		},
	},
	{
		id: "rfc9114/4.1.2/6", name: "an HTTP/3 response with an uppercase field name",
		req: "Intermediaries that process HTTP requests or responses (i.e., any intermediary not acting as a tunnel) MUST NOT forward a malformed request or response.",
		run: func(t *testing.T) {
			b := newH3OriginBench(t, h3Reply(h3Headers([]hpack.HeaderField{hf(":status", "200"), hf("X-Upper", "1")}), h3Data("ok")))
			h := b.dialH3Front(t)
			got := h.roundTrip(t, h3Request("GET", "origin.test", "/"))
			if _, reset := h3ErrCode(got.err); reset {
				return
			}
			status, err := strconv.Atoi(got.status())
			require.NoError(t, err)
			assert.GreaterOrEqual(t, status, 500, "the malformed response was forwarded")
		},
	},
	{
		id: "rfc9114/4.1.2/7", name: "an HTTP/3 response shorter than its Content-Length",
		req: "Intermediaries that process HTTP requests or responses (i.e., any intermediary not acting as a tunnel) MUST NOT forward a malformed request or response.",
		run: func(t *testing.T) {
			b := newH3OriginBench(t, h3Reply(h3Headers([]hpack.HeaderField{hf(":status", "200"), hf("content-length", "10")}), h3Data("abcd")))
			h := b.dialH3Front(t)
			got := h.roundTrip(t, h3Request("GET", "origin.test", "/"))
			if got.status() == "" {
				return
			}
			_, reset := h3ErrCode(got.err)
			assert.True(t, reset, "the response ended with a FIN after %q", got.body)
		},
	},

	// RFC 9114, CONNECT through an upstream proxy over HTTP/3.
	{
		id: "rfc9114/4.1.1/3", name: "a 403 from the upstream proxy answering the CONNECT",
		req: "Client SHOULD use the error code H3_REQUEST_CANCELLED to cancel requests.",
		run: func(t *testing.T) {
			b := newH3UpstreamBench(t, nil, func(o *rawOrigin, _ *h3Conn, s *h3Stream) {
				if _, _, err := s.next(); err != nil {
					return
				}
				_, _ = s.Write(h3Headers([]hpack.HeaderField{hf(":status", "403")}))
				if _, err := io.Copy(io.Discard, s.br); err != nil {
					code, _ := h3ErrCode(err)
					o.note(fmt.Sprintf("%#x", uint64(code)))
					return
				}
				o.note("FIN")
			})
			b.tunnel(t, "origin.test:80", "")
			assert.Contains(t, []string{"FIN", fmt.Sprintf("%#x", uint64(http3.ErrCodeRequestCanceled))}, b.origin.nextNote(t))
		},
	},
	{
		id: "rfc9114/4.1.1/4", name: "a CONNECT reset by the upstream proxy with H3_REQUEST_CANCELLED",
		req: "Only idempotent actions such as GET, PUT, or DELETE can be safely retried; a client SHOULD NOT automatically retry a request with a non-idempotent method unless it has some means to know that the request semantics are idempotent independent of the method or some means to detect that the original request was never applied.",
		run: func(t *testing.T) {
			b := newH3UpstreamBench(t, nil, func(o *rawOrigin, _ *h3Conn, s *h3Stream) {
				if !upstreamConnect(o, s) {
					return
				}
				s.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
				s.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			})
			b.tunnel(t, "origin.test:80", "")
			b.origin.next(t)
			b.origin.none(t)
		},
	},
	{
		id: "rfc9114/4.1.1/5", name: "a CONNECT answered with DATA before HEADERS",
		req: "Only idempotent actions such as GET, PUT, or DELETE can be safely retried; a client SHOULD NOT automatically retry a request with a non-idempotent method unless it has some means to know that the request semantics are idempotent independent of the method or some means to detect that the original request was never applied.",
		run: func(t *testing.T) {
			b := newH3UpstreamBench(t, nil, func(o *rawOrigin, _ *h3Conn, s *h3Stream) {
				if upstreamConnect(o, s) {
					_, _ = s.Write(h3Data("x"))
				}
			})
			b.tunnel(t, "origin.test:80", "")
			b.origin.next(t)
			b.origin.none(t)
		},
	},
	{
		id: "rfc9114/4.1.1/6", name: "a CONNECT answered with an uppercase field name",
		req: "Only idempotent actions such as GET, PUT, or DELETE can be safely retried; a client SHOULD NOT automatically retry a request with a non-idempotent method unless it has some means to know that the request semantics are idempotent independent of the method or some means to detect that the original request was never applied.",
		run: func(t *testing.T) {
			b := newH3UpstreamBench(t, nil, func(o *rawOrigin, _ *h3Conn, s *h3Stream) {
				if upstreamConnect(o, s) {
					_, _ = s.Write(h3Headers([]hpack.HeaderField{hf(":status", "200"), hf("X-Upper", "1")}))
				}
			})
			b.tunnel(t, "origin.test:80", "")
			b.origin.next(t)
			b.origin.none(t)
		},
	},
	{
		id: "rfc9114/4.4/12", name: "the CONNECT sent to an upstream proxy",
		req: "A CONNECT request MUST be constructed as follows:\n\n*  The :method pseudo-header field is set to \"CONNECT\"\n\n*  The :scheme and :path pseudo-header fields are omitted\n\n*  The :authority pseudo-header field contains the host and port to connect to (equivalent to the authority-form of the request-target of CONNECT requests; see Section 7.1 of [HTTP]).",
		run: func(t *testing.T) {
			b := newH3UpstreamBench(t, nil, func(o *rawOrigin, _ *h3Conn, s *h3Stream) {
				_, payload, err := s.next()
				if err != nil {
					return
				}
				fields, _ := qpackFields(payload)
				var pseudo []string
				for _, f := range fields {
					if strings.HasPrefix(f.Name, ":") {
						pseudo = append(pseudo, f.Name+" "+f.Value)
					}
				}
				o.note(strings.Join(pseudo, ", "))
			})
			b.tunnel(t, "origin.test:80", "")
			pseudo := strings.Split(b.origin.nextNote(t), ", ")
			assert.ElementsMatch(t, []string{":method CONNECT", ":authority origin.test:80"}, pseudo)
		},
	},
	{
		id: "rfc9114/4.4/13", name: "HEADERS from the upstream proxy after the 200 answering the CONNECT",
		req:  "Once the CONNECT method has completed, only DATA frames are permitted to be sent on the stream.  Extension frames MAY be used if specifically permitted by the definition of the extension.  Receipt of any other known frame type MUST be treated as a connection error of type H3_FRAME_UNEXPECTED.",
		skip: "quic-go reads a HEADERS frame after the response on a request stream as its trailer section and leaves the connection open, before edge gets the frame.",
	},
	{
		id: "rfc9114/4.4/14", name: "FIN from the client on a tunnel through an upstream proxy",
		req:  "TCP connections that remain half closed in a single direction are not invalid, but are often handled poorly by servers, so clients SHOULD NOT close a stream for sending while they still expect to receive data from the target of the CONNECT.",
		skip: "Edge mirrors the half-close of its client on the stream to the upstream proxy, as h3StreamConn.CloseWrite in chain.go does, so the stream closes for sending while data from the target may still come.",
	},
	{
		id: "rfc9114/4.4/15", name: "a dial refused after the 200 answering a CONNECT over HTTP/3",
		req: "A proxy treats any error in the TCP connection, which includes receiving a TCP segment with the RST bit set, as a stream error of type H3_CONNECT_ERROR.",
		run: func(t *testing.T) {
			b := newRefusingBench(t)
			h := b.dialH3Front(t)
			s := h.connect(t, "origin.test:80")
			s.send(t, h3Data("\x01ping"))
			got := s.message(true)
			code, reset := h3ErrCode(got.err)
			require.True(t, reset, "the stream ended with a FIN")
			assert.Equal(t, http3.ErrCodeConnectError, code)
		},
	},
	{
		id: "rfc9114/5.2/3", name: "a CONNECT after a GOAWAY from the upstream proxy",
		req: "Endpoints MUST NOT initiate new requests or promise new pushes on the connection after receipt of a GOAWAY frame from the peer.",
		run: func(t *testing.T) {
			b := newH3UpstreamBench(t, nil, func(o *rawOrigin, c *h3Conn, s *h3Stream) {
				if _, _, err := s.next(); err != nil {
					return
				}
				o.note(c.RemoteAddr().String())
				_ = c.sendGoAway(uint64(s.StreamID()) + 4)
				_, _ = s.Write(h3Headers([]hpack.HeaderField{hf(":status", "200")}))
				for {
					typ, payload, err := s.next()
					if err != nil {
						return
					}
					if typ == h3FrameData {
						_, _ = s.Write(capsuleOf(h3FrameData, payload))
					}
				}
			})
			w := b.tunnel(t, "origin.test:80", "")
			first := b.origin.nextNote(t)
			echo := make([]byte, 5)
			_, err := io.ReadFull(w.br, echo)
			require.NoError(t, err)
			b.tunnel(t, "origin.test:80", "")
			assert.NotEqual(t, first, b.origin.nextNote(t), "the second CONNECT went on the connection that sent GOAWAY")
		},
	},

	// RFC 9931 section 8, CONNECT over HTTP/1.1.
	{
		id: "rfc9931/8/1", name: "bytes from the client waiting while the upstream proxy refuses the CONNECT",
		req: "Proxy clients that send CONNECT requests on behalf of untrusted TCP clients MUST do one or both of the following: 1. Wait for a 2xx (Successful) response before forwarding any TCP payload data. 2. Send a \"Connection: close\" request header.",
		run: func(t *testing.T) {
			b := newUpstreamBench(t, nil, upstreamH1("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"up\"\r\nContent-Length: 0\r\n\r\n", ""))
			b.tunnel(t, "origin.test:80", "")
			if !b.origin.next(t).req.Close {
				assert.Empty(t, b.origin.nextNote(t), "bytes of the tunnel reached the upstream proxy")
			}
		},
	},
}

func TestHTTP_NoUserAgentIsAdded(t *testing.T) {
	b := newProxyBench(t, always(okReply))
	got, _ := b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	assert.NotContains(t, strings.ToLower(got.head), "user-agent")

	got, _ = b.forwarded(t, "GET", "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\nUser-Agent: curl/8.0\r\n\r\n")
	assert.Contains(t, got.head, "User-Agent: curl/8.0\r\n")
}

func TestHTTP_CutBodyIsNotEndedCleanly(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "partial")
		_ = http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	}))
	defer origin.Close()

	_, _, client := interceptingProxy(t, origin)

	resp, err := client.Get(origin.URL + "/")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	assert.Equal(t, "partial", string(body))
	assert.Error(t, err, "the body read as complete")
}

func TestHTTP_EarlyHintsReachAnHTTP3Client(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</s.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Del("Link")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()
	p, _, _ := interceptingProxy(t, origin)
	ca, err := GenerateCA()
	require.NoError(t, err)
	front, _ := startQUICFront(t, p, ca)
	h3 := &http3.Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			return dialQUICFront(t, front, ca), nil
		},
	}
	defer func() { _ = h3.Close() }()

	var codes []int
	var links []string
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
		codes = append(codes, code)
		links = append(links, h.Get("Link"))
		return nil
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace),
		http.MethodGet, origin.URL+"/", nil)
	require.NoError(t, err)
	resp, err := h3.RoundTrip(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	assert.Equal(t, []int{http.StatusEarlyHints}, codes)
	assert.Equal(t, []string{"</s.css>; rel=preload"}, links)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Values("Link"), "the final answer kept a field of the 103")
	assert.Equal(t, "ok", string(body))
}

func TestHTTP_AsteriskFormNeverReachesAnAdmission(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	p.MustAdd("origin.test", relayStream)
	p.MustAdd("origin.test/", okHandler)
	front, _ := startQUICFront(t, p, ca)
	h3 := &http3.Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			return dialQUICFront(t, front, ca), nil
		},
	}
	defer func() { _ = h3.Close() }()

	resp, err := h3.RoundTrip(&http.Request{
		Method: http.MethodOptions,
		URL:    &url.URL{Scheme: "https", Host: "origin.test", Path: "*"},
		Header: http.Header{},
	})
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "ok", string(body))

	w := newWire(connectRaw(t, startProxy(t, p), "origin.test:80"))
	require.NoError(t, w.SetDeadline(time.Now().Add(10*time.Second)))
	w.send(t, "OPTIONS * HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	got := w.readResponse(t, http.MethodOptions)
	assert.Equal(t, http.StatusOK, got.resp.StatusCode)
	assert.Equal(t, "ok", string(got.body), "net/http responded to OPTIONS * in the tunnel itself")
}

func TestHTTP_OptionsWithAnEmptyPathOverEveryVersion(t *testing.T) {
	asServer := func(c *HTTPCtx) (*http.Response, error) {
		r := c.Request().Clone(c.Request().Context())
		r.Method = http.MethodOptions
		r.URL.Path, r.URL.RawPath = "", ""
		return c.ForwardRequest(r)
	}

	t.Run("HTTP/2", func(t *testing.T) {
		origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s %s %s", r.Method, r.RequestURI, r.Proto)
		}))
		origin.Config.DisableGeneralOptionsHandler = true
		origin.EnableHTTP2 = true
		origin.StartTLS()
		defer origin.Close()

		p, host, client := interceptingProxy(t, origin)
		p.MustAdd(host+"/options", asServer)
		client.Transport.(*http.Transport).ForceAttemptHTTP2 = true

		resp, err := client.Get(origin.URL + "/options")
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		assert.Equal(t, "OPTIONS * HTTP/2.0", string(body))
	})

	t.Run("HTTP/1.1 to another proxy", func(t *testing.T) {
		o := newRawOrigin(t, always(okReply))
		tr := DefaultTransport()
		tr.DialContext = pinnedDialer(o.addr)
		tr.Proxy = func(*http.Request) (*url.URL, error) { return &url.URL{Scheme: "http", Host: "next.test:3128"}, nil }
		p := testProxy(t, WithTransport(tr))
		p.MustAdd("origin.test/*{any}", forwardHandler)
		w := dialWire(t, startProxy(t, p))
		w.send(t, "OPTIONS http://origin.test HTTP/1.1\r\nHost: origin.test\r\n\r\n")
		w.readResponse(t, "OPTIONS")
		assert.Equal(t, "OPTIONS http://origin.test HTTP/1.1", startLine(o.next(t).head), "only the last proxy sends *")
	})

	t.Run("HTTP/3", func(t *testing.T) {
		originCA, err := GenerateCA(WithCASubject("edge h3 origin CA"))
		require.NoError(t, err)
		origin := h3Origin(t, originCA)
		proxyCA, err := GenerateCA()
		require.NoError(t, err)
		upstream := DefaultTransport()
		upstream.AllowHTTP3 = true
		upstream.RootCAs = poolOf(originCA)
		p, err := New(WithCA(proxyCA), WithTransport(upstream))
		require.NoError(t, err)
		p.MustAdd(h3Authority+"/options", asServer)

		tr := dialQUICTo(startQUICRedirected(t, p, origin), poolOf(proxyCA))
		defer func() { _ = tr.Close() }()
		req, err := http.NewRequest(http.MethodGet, "https://"+h3Authority+"/options", nil)
		require.NoError(t, err)
		resp, err := tr.RoundTrip(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		assert.Contains(t, string(body), "origin method=OPTIONS path=* proto=HTTP/3")
	})
}

func BenchmarkForwardWithBody(b *testing.B) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	ca, err := GenerateCA()
	require.NoError(b, err)
	p, err := New(WithCA(ca))
	require.NoError(b, err)
	p.MustAdd("127.0.0.1/*{any}", forwardHandler)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(b, err)
	go func() { _ = p.Serve(ln) }()
	defer func() { _ = p.Close() }()
	client := proxyClient(ln.Addr().String(), nil)
	payload := strings.Repeat("x", 512)

	b.ReportAllocs()
	for b.Loop() {
		resp, err := client.Post(origin.URL+"/up", "text/plain", strings.NewReader(payload))
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}
