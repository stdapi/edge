// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stdapi/edge/internal/quicsniff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestTerminatedTarget_PortIsCanonical(t *testing.T) {
	sess := newSession(nil, t.Context(), nil, Target{Scheme: "https", Host: "example.test", Port: "443"}, KindHTTP, HTTP11)
	target, ok := terminatedTarget(&http.Request{Host: "example.test:08443"}, sess)
	require.True(t, ok)
	assert.Equal(t, "8443", target.Port)

	_, ok = terminatedTarget(&http.Request{Host: "example.test:x"}, sess)
	assert.False(t, ok)
}

func TestTerminatedTarget_RootDotIsDropped(t *testing.T) {
	sess := newSession(nil, t.Context(), nil, Target{Scheme: "https", Host: "example.test", Port: "443"}, KindHTTP, HTTP11)
	target, ok := terminatedTarget(&http.Request{Host: "Other.Test.:8443"}, sess)
	require.True(t, ok)
	assert.Equal(t, "other.test", target.Host)
}

func TestTerminate_RequestIsRoutedOnItsHostAndDialedToTheDestination(t *testing.T) {
	for _, front := range []proxyFront{frontConnect, frontRedirected} {
		t.Run(string(front), func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			tr := DefaultTransport()
			o := newRawOrigin(t, always(okReply))
			dialed := make(chan string, 4)
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialed <- addr
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, o.addr)
			}
			p := testProxyWithCA(t, ca, WithTransport(tr))
			p.MustAdd("origin.test/*{any}", okHandler)
			p.MustAdd("other.test/*{any}", forwardHandler)
			b := &proxyBench{p: p, origin: o, trust: ca.CertPool(), front: front}
			destination := "origin.test:80"
			switch front {
			case frontConnect:
				b.addr = startProxy(t, p)
			default:
				dst := netip.MustParseAddrPort(o.addr)
				b.addr = startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) { return dst, nil })
				destination = o.addr
			}

			w := b.dial(t)
			w.send(t, "GET /first HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			assert.Equal(t, "ok", string(w.readResponse(t, "GET").body))
			w.send(t, "GET /second HTTP/1.1\r\nHost: other.test\r\n\r\n")
			assert.Equal(t, http.StatusOK, w.readResponse(t, "GET").resp.StatusCode)

			got := o.next(t)
			assert.Equal(t, "GET /second HTTP/1.1", startLine(got.head))
			assert.Equal(t, []string{"other.test"}, fieldValues(got.head, "Host"))
			assert.Equal(t, destination, <-dialed)
		})
	}
}

func TestTerminate_AbsoluteFormTakesTheSchemeOfTheConnection(t *testing.T) {
	for _, front := range proxyFronts[1:] {
		t.Run(string(front), func(t *testing.T) {
			other := "https"
			if front.secure() {
				other = "http"
			}
			b := newProxyBenchOn(t, front, always(okReply))
			w := b.dial(t)
			w.originForm = false
			w.send(t, "GET "+other+"://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			require.Equal(t, http.StatusOK, w.readResponse(t, "GET").resp.StatusCode)
			assert.Equal(t, "GET /x HTTP/1.1", startLine(b.origin.next(t).head))
		})
	}
}

func TestTerminate_HTTP2RequestTakesTheSchemeOfTheConnection(t *testing.T) {
	eachH2Front(t, []string{viaConnectH2, viaRedirectedH2}, func(t *testing.T, front string) {
		b, h := h2FrontBench(t, front, always(okReply))
		b.p.MustAdd("origin.test/*{any}", func(*HTTPCtx) (*http.Response, error) {
			return Text(http.StatusOK, "http"), nil
		}, WithScheme[HTTP]("http"))
		h.headers(t, 1, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/x"))
		assert.Equal(t, "ok", string(h.reply(t, 1).body))
		assert.Equal(t, "GET /x HTTP/1.1", startLine(b.origin.next(t).head))
	})
}

func TestTerminate_PlaintextStreamTargetDropsTheRootDot(t *testing.T) {
	p, err := New()
	require.NoError(t, err)
	p.MustAdd[TCP]("origin.test", func(c *TCPCtx) error {
		_, err := io.WriteString(c.Client(), c.Target().Host)
		return err
	})
	conn := connectRaw(t, startProxy(t, p), "origin.test:80")
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: origin.test.\r\n\r\n")
	require.NoError(t, err)
	got, _ := io.ReadAll(conn)
	assert.Equal(t, "origin.test", string(got))
}

func TestTerminate_StreamRefusedPastTheHandshakeSendsCloseNotify(t *testing.T) {
	p, ca := newTLSProxy(t)
	rec := &recordingConn{Conn: connectRaw(t, startProxy(t, p), tlsName+":443")}
	require.NoError(t, rec.SetDeadline(time.Now().Add(5*time.Second)))
	tc := tls.Client(rec, &tls.Config{ServerName: tlsName, RootCAs: ca.CertPool(), MaxVersion: tls.VersionTLS12, MinVersion: tls.VersionTLS12})
	require.NoError(t, tc.Handshake())
	_, err := io.WriteString(tc, "hello\n")
	require.NoError(t, err)
	_, _ = io.ReadAll(tc)
	assert.Equal(t, byte(tlsAlert), rec.lastRecord())
}

func TestTerminate_SessionCloseEndsAStalledClient(t *testing.T) {
	for _, tc := range []struct {
		name            string
		tlsFront, inner bool
	}{
		{"tls front", true, false},
		{"tls tunnel", false, true},
		{"tls front and tunnel", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			p, err := New(WithCA(ca))
			require.NoError(t, err)
			full := make(chan struct{})
			p.MustAdd[TCP](tlsDB, func(c *TCPCtx) error {
				writeUntilFull(c.Client())
				close(full)
				<-c.Context().Done()
				return nil
			})

			var raw net.Conn
			if tc.tlsFront {
				raw, err = tls.Dial("tcp", startTLSFront(t, p, ca, "http/1.1").String(), &tls.Config{RootCAs: ca.CertPool()})
			} else {
				raw, err = net.Dial("tcp", startProxy(t, p))
			}
			require.NoError(t, err)
			t.Cleanup(func() { _ = raw.Close() })
			_, err = fmt.Fprintf(raw, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", tlsDB, tlsDB)
			require.NoError(t, err)
			resp, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: http.MethodConnect})
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var client io.Writer = raw
			if tc.inner {
				inner := tls.Client(raw, &tls.Config{ServerName: tlsDB, RootCAs: ca.CertPool()})
				require.NoError(t, inner.Handshake())
				client = inner
			}
			_, err = client.Write([]byte{0})
			require.NoError(t, err)
			sess := waitForSessions(t, p, 1)[0]
			<-full

			start := time.Now()
			_ = sess.Close()
			assert.Less(t, time.Since(start), alertWriteTimeout+alertWriteTimeout/2, "Close outlived its deadline")
			assert.Eventually(t, func() bool { return len(slices.Collect(p.Sessions())) == 0 },
				alertWriteTimeout, 10*time.Millisecond, "the session outlived its close")
		})
	}
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

func TestTerminate_PrefaceWithoutH2IsRefused(t *testing.T) {
	for _, alpn := range [][]string{{"http/1.1"}, nil} {
		t.Run(fmt.Sprint(alpn), func(t *testing.T) {
			p, ca := newTLSProxy(t)
			conn := connectRaw(t, startProxy(t, p), tlsName+":443")
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			tc := tls.Client(conn, &tls.Config{ServerName: tlsName, RootCAs: ca.CertPool(), NextProtos: alpn, MinVersion: tls.VersionTLS12})
			require.NoError(t, tc.Handshake())
			_, err := io.WriteString(tc, http2.ClientPreface)
			require.NoError(t, err)
			resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.True(t, resp.Close)
		})
	}
}

func TestTerminate_RefusedClientHelloAlert(t *testing.T) {
	withSNI := captureClientHello(t, &tls.Config{ServerName: tlsName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	withoutSNI := captureClientHello(t, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	unknown := captureClientHello(t, &tls.Config{ServerName: "unknown.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	// The extensions block claims one byte more than it has, inside a well framed message.
	malformed := func() []byte {
		msg := handshakeFromRecords(withSNI)
		body := msg[4:]
		sidEnd := 35 + int(body[34])
		csEnd := sidEnd + 2 + int(binary.BigEndian.Uint16(body[sidEnd:]))
		extAt := 4 + csEnd + 1 + int(body[csEnd])
		out := slices.Clone(msg)
		binary.BigEndian.PutUint16(out[extAt:], binary.BigEndian.Uint16(out[extAt:])+1)
		return records(out, tls.VersionTLS10)
	}()
	interleaved := func() []byte {
		raw := records(handshakeFromRecords(withSNI), tls.VersionTLS10, 64)
		return slices.Concat(raw[:5+64], []byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00}, raw[5+64:])
	}()
	mismatch := &fakeResolver{addrs: map[string][]netip.Addr{tlsName: addrsOf("192.0.2.1"), tlsDB: addrsOf("192.0.2.1")}}
	redirected := func(net.Conn) (netip.AddrPort, error) { return netip.MustParseAddrPort("127.0.0.1:443"), nil }
	dial := func(t *testing.T, addr string) net.Conn {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	starttls := func(t *testing.T, c net.Conn) net.Conn {
		require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
		_, err := io.WriteString(c, "STARTTLS\n")
		require.NoError(t, err)
		ok := make([]byte, len("OK\n"))
		_, err = io.ReadFull(c, ok)
		require.NoError(t, err)
		return c
	}

	cases := []struct {
		open  func(t *testing.T) net.Conn
		name  string
		hello []byte
		alert byte
	}{
		{name: "no certificate authority", hello: withSNI, alert: alertInternalError, open: func(t *testing.T) net.Conn {
			p, err := New()
			require.NoError(t, err)
			p.MustAdd[TCP](tlsName, relayStream)
			return connectRaw(t, startProxy(t, p), tlsName+":443")
		}},
		{name: "an Encrypted Client Hello offer", hello: echClientHello(t, tlsName, "secret.test"), alert: alertHandshakeFailure, open: func(t *testing.T) net.Conn {
			p, _ := newTLSProxy(t, WithRejectECH(true))
			return connectRaw(t, startProxy(t, p), tlsName+":443")
		}},
		{name: "a ClientHello that does not parse", hello: malformed, alert: alertDecodeError, open: func(t *testing.T) net.Conn {
			p, _ := newTLSProxy(t, WithRejectECH(true))
			return connectRaw(t, startProxy(t, p), tlsName+":443")
		}},
		{name: "a ClientHello that does not parse, without a destination", hello: malformed, alert: alertDecodeError, open: func(t *testing.T) net.Conn {
			p, _ := newTLSProxy(t)
			return dial(t, startTransparent(t, p))
		}},
		{name: "a ClientHello split by a record of another type", hello: interleaved, alert: alertDecodeError, open: func(t *testing.T) net.Conn {
			p, _ := newTLSProxy(t, WithRejectECH(true))
			return connectRaw(t, startProxy(t, p), tlsName+":443")
		}},
		{name: "a server name no entry admits", hello: unknown, alert: alertUnrecognizedName, open: func(t *testing.T) net.Conn {
			p, _ := newTLSProxy(t)
			return connectRaw(t, startProxy(t, p), tlsName+":443")
		}},
		{name: "a server name no entry admits through a CONNECT over HTTP/2", hello: unknown, alert: alertUnrecognizedName, open: func(t *testing.T) net.Conn {
			p, ca := newTLSProxy(t)
			return h2Connect(t, startTLSFront(t, p, ca, "h2"), ca, tlsName+":443")
		}},
		{name: "a server name no entry admits through a CONNECT over HTTP/3", hello: unknown, alert: alertUnrecognizedName, open: func(t *testing.T) net.Conn {
			p, ca := newTLSProxy(t)
			front, _ := startQUICFront(t, p, ca)
			return h3Connect(t, front, ca, tlsName+":443")
		}},
		{name: "a server name that does not resolve to the destination", hello: withSNI, alert: alertUnrecognizedName, open: func(t *testing.T) net.Conn {
			p, _ := newTLSProxy(t, WithNameVerification(VerifyReject), WithNameResolver(mismatch))
			return dial(t, startTransparentRedirected(t, p, redirected))
		}},
		{name: "no server name and a destination no entry admits", hello: withoutSNI, alert: alertMissingExtension, open: func(t *testing.T) net.Conn {
			p, _ := newTLSProxy(t)
			return dial(t, startTransparentRedirected(t, p, redirected))
		}},
		{name: "no server name and no destination", hello: withoutSNI, alert: alertMissingExtension, open: func(t *testing.T) net.Conn {
			p, _ := newTLSProxy(t)
			return dial(t, startTransparent(t, p))
		}},
		{name: "StartTLS without a certificate authority", hello: withSNI, alert: alertInternalError, open: func(t *testing.T) net.Conn {
			p, err := New()
			require.NoError(t, err)
			p.MustAdd[TCP](tlsDB, startTLSLine)
			return starttls(t, connectRaw(t, startProxy(t, p), tlsDB+":5432"))
		}},
		{name: "StartTLS with a server name that does not resolve to the destination", hello: withSNI, alert: alertUnrecognizedName, open: func(t *testing.T) net.Conn {
			p, _ := newTLSProxy(t, WithNameVerification(VerifyReject), WithNameResolver(mismatch))
			p.MustAdd[TCP]("127.0.0.1", startTLSLine)
			return starttls(t, dial(t, startTransparentRedirected(t, p, redirected)))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.open(t)
			require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
			_, err := c.Write(tc.hello)
			require.NoError(t, err)
			head := make([]byte, 7)
			_, err = io.ReadFull(c, head)
			require.NoError(t, err)
			assert.Equal(t, []byte{tlsAlert, 0x03, 0x03, 0x00, 0x02, 0x02, tc.alert}, head)
			_, err = c.Read(make([]byte, 1))
			assert.ErrorIs(t, err, io.EOF)
		})
	}
}

func TestTerminate_RefusedClientHelloAlertBeforeUnreadBytes(t *testing.T) {
	unknown := captureClientHello(t, &tls.Config{ServerName: "unknown.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	withoutSNI := captureClientHello(t, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	// More than the peek reads, so the bytes past it are still unread when the proxy refuses.
	trailing := make([]byte, 2*clientHelloPeekSize)
	cases := []struct {
		open  func(t *testing.T) net.Conn
		name  string
		hello []byte
		alert byte
	}{
		{name: "a CONNECT", hello: unknown, alert: alertUnrecognizedName, open: func(t *testing.T) net.Conn {
			p, _ := newTLSProxy(t)
			return connectRaw(t, startProxy(t, p), tlsName+":443")
		}},
		{name: "a redirected connection", hello: withoutSNI, alert: alertMissingExtension, open: func(t *testing.T) net.Conn {
			p, _ := newTLSProxy(t)
			c, err := net.DialTimeout("tcp", startTransparent(t, p), 5*time.Second)
			require.NoError(t, err)
			t.Cleanup(func() { _ = c.Close() })
			return c
		}},
		{name: "StartTLS", hello: unknown, alert: alertInternalError, open: func(t *testing.T) net.Conn {
			p, err := New()
			require.NoError(t, err)
			p.MustAdd[TCP](tlsDB, startTLSLine)
			c := connectRaw(t, startProxy(t, p), tlsDB+":5432")
			require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
			_, err = io.WriteString(c, "STARTTLS\n")
			require.NoError(t, err)
			_, err = io.ReadFull(c, make([]byte, len("OK\n")))
			require.NoError(t, err)
			return c
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.open(t)
			require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
			_, _ = c.Write(append(slices.Clone(tc.hello), trailing...))
			time.Sleep(200 * time.Millisecond)
			head := make([]byte, 7)
			_, err := io.ReadFull(c, head)
			require.NoError(t, err)
			assert.Equal(t, []byte{tlsAlert, 0x03, 0x03, 0x00, 0x02, 0x02, tc.alert}, head)
			_, err = c.Read(make([]byte, 1))
			assert.ErrorIs(t, err, io.EOF)
		})
	}
}

func TestTerminate_RequestHostIsVerifiedOverTLS(t *testing.T) {
	versions := []string{viaH1, viaH1WithoutALPN, viaH2, viaH3}
	for _, tc := range []struct {
		name       string
		resolvesTo string
		mode       NameVerification
		byName     bool
	}{
		{name: "confirmed under VerifyReject", mode: VerifyReject, resolvesTo: "127.0.0.1", byName: true},
		{name: "confirmed under VerifyLoose", mode: VerifyLoose, resolvesTo: "127.0.0.1", byName: true},
		{name: "dropped under VerifyLoose", mode: VerifyLoose, resolvesTo: "10.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, version := range versions {
				// The SOCKS5 front declares a hostname, so no destination stands against the name.
				fronts := []string{viaRedirected, viaConnect, viaConnectTLSFront, viaConnectH2Front, viaSOCKS}
				if version == viaH3 {
					fronts = []string{viaTransparentQUIC, viaConnectUDPLiteral}
				}
				for _, front := range fronts {
					t.Run(version+"-"+front, func(t *testing.T) {
						ca, err := GenerateCA()
						require.NoError(t, err)
						originCA, err := GenerateCA()
						require.NoError(t, err)
						cert, err := originCA.Leaf("api.example.test")
						require.NoError(t, err)
						o := newTLSOrigin(t, *cert, always(okReply))
						tr := DefaultTransport()
						tr.DialContext = pinnedDialer(o.addr)
						tr.InsecureSkipVerify = true
						resolver := &fakeResolver{addrs: map[string][]netip.Addr{"api.example.test": addrsOf(tc.resolvesTo)}}
						p := testProxyWithCA(t, ca, WithTransport(tr), WithNameVerification(tc.mode), WithNameResolver(resolver))
						var byName, byAddr atomic.Int32
						p.MustAdd("api.example.test/*{any}", func(c *HTTPCtx) (*http.Response, error) {
							byName.Add(1)
							return c.Forward()
						})
						p.MustAdd("127.0.0.1/*{any}", func(c *HTTPCtx) (*http.Response, error) {
							byAddr.Add(1)
							return c.Forward()
						})

						b := &proxyBench{p: p, origin: o, trust: ca.CertPool()}
						_, get := dialTerminated(t, b, front, version, "Api.Example.Test")
						code, _ := get(t, "api.example.test")
						assert.Equal(t, http.StatusOK, code)
						assert.Equal(t, "api.example.test", b.origin.next(t).req.Host)
						if tc.byName {
							assert.EqualValues(t, 1, byName.Load())
							assert.Zero(t, byAddr.Load())
						} else {
							assert.Zero(t, byName.Load(), "a name that does not resolve to the destination routed the request")
							assert.EqualValues(t, 1, byAddr.Load())
						}
						assert.EqualValues(t, 1, resolver.calls.Load(), "the server name is resolved once per connection")
					})
				}
			}
		})
	}
}

func TestConformanceTLS(t *testing.T) {
	runConformance(t, tlsConformance)
}

const (
	tlsName     = "origin.test"
	tlsUpstream = "upstream.test"
	tlsDB       = "db.test"
	tlsAlert    = 0x15
)

// preferredName matches the preferred name syntax of RFC 1123 section 2.1.
var preferredName = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)

// newTLSProxy returns a proxy and its certificate authority, with an entry on tlsName that
// the proxy answers itself.
func newTLSProxy(t *testing.T, opts ...ProxyOption) (*Proxy, *CA) {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(append([]ProxyOption{WithCA(ca)}, opts...)...)
	require.NoError(t, err)
	p.MustAdd(tlsName+"/*{any}", func(*HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, "routed"), nil
	})
	return p, ca
}

// upstreamProxy returns a proxy forwarding requests and relaying streams for tlsUpstream to
// the origin at addr, and upgrading a stream for tlsDB after an SSLRequest, trusting the
// certificates roots issued.
func upstreamProxy(t *testing.T, addr string, roots *x509.CertPool, opts ...ProxyOption) (*Proxy, *CA) {
	t.Helper()
	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(addr)
	tr.RootCAs = roots
	p, ca := newTLSProxy(t, append([]ProxyOption{WithTransport(tr)}, opts...)...)
	p.MustAdd(tlsUpstream+"/*{any}", forwardHandler)
	p.MustAdd[TCP](tlsUpstream, relayStream)
	p.MustAdd[TCP](tlsDB, startTLSRelay)
	return p, ca
}

// redirectedConn serves one connection with p as a redirected connection whose destination
// is unknown, so that its server name alone places it. A write on a pipe reaches the proxy
// as a read of its own.
func redirectedConn(t *testing.T, p *Proxy) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	go func() { _ = p.ServeConn(server) }()
	t.Cleanup(func() {
		_ = client.Close()
		_ = p.Close()
	})
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	return client
}

// helloConn writes the first write of a TLS client, its ClientHello, as the writes frame
// returns.
type helloConn struct {
	net.Conn
	frame func(records []byte) [][]byte
	done  bool
}

func (c *helloConn) Write(b []byte) (int, error) {
	if c.done {
		return c.Conn.Write(b)
	}
	c.done = true
	for _, part := range c.frame(b) {
		if _, err := c.Conn.Write(part); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// records frames the handshake message msg in records of the given fragment sizes under
// version, the last record taking what remains.
func records(msg []byte, version uint16, sizes ...int) []byte {
	var out []byte
	for len(msg) > 0 {
		n := len(msg)
		if len(sizes) > 0 {
			n, sizes = min(sizes[0], n), sizes[1:]
		}
		out = append(out, tlsHandshakeRecord, byte(version>>8), byte(version))
		out = binary.BigEndian.AppendUint16(out, uint16(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

func eachRecord(raw []byte) [][]byte {
	var out [][]byte
	for len(raw) >= 5 {
		n := 5 + int(binary.BigEndian.Uint16(raw[3:5]))
		out = append(out, raw[:n])
		raw = raw[n:]
	}
	return out
}

// spliceHello returns the ClientHello in raw with suite placed first among its cipher suites
// and an extension of type ext with data appended, every length rewritten, in records of
// at most 2^14 bytes.
func spliceHello(t *testing.T, raw []byte, suite, ext uint16, data []byte) []byte {
	t.Helper()
	msg := handshakeFromRecords(raw)
	require.NotNil(t, msg)
	body := msg[4:]
	sidEnd := 35 + int(body[34])
	csLen := int(binary.BigEndian.Uint16(body[sidEnd:]))
	compEnd := sidEnd + 2 + csLen + 1 + int(body[sidEnd+2+csLen])
	extLen := int(binary.BigEndian.Uint16(body[compEnd:]))
	added := binary.BigEndian.AppendUint16(nil, ext)
	added = binary.BigEndian.AppendUint16(added, uint16(len(data)))
	added = append(added, data...)

	b := append([]byte(nil), body[:sidEnd]...)
	b = binary.BigEndian.AppendUint16(b, uint16(csLen+2))
	b = binary.BigEndian.AppendUint16(b, suite)
	b = append(b, body[sidEnd+2:compEnd]...)
	b = binary.BigEndian.AppendUint16(b, uint16(extLen+len(added)))
	b = append(b, body[compEnd+2:compEnd+2+extLen]...)
	b = append(b, added...)
	msg = append([]byte{0x01, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...)
	sizes := make([]int, len(msg)/16384+1)
	for i := range sizes {
		sizes[i] = 16384
	}
	return records(msg, tls.VersionTLS10, sizes...)
}

// withExtension returns the ClientHello message msg with an extension of type ext and data
// appended, every length rewritten.
func withExtension(t *testing.T, msg []byte, ext uint16, data []byte) []byte {
	t.Helper()
	need := func(n int) {
		if len(msg) < 4+n {
			t.Fatalf("a ClientHello of %d bytes is cut short", len(msg))
		}
	}
	need(35)
	body := msg[4:]
	sidEnd := 35 + int(body[34])
	need(sidEnd + 2)
	csLen := int(binary.BigEndian.Uint16(body[sidEnd:]))
	need(sidEnd + 3 + csLen)
	compEnd := sidEnd + 2 + csLen + 1 + int(body[sidEnd+2+csLen])
	need(compEnd + 2)
	extLen := int(binary.BigEndian.Uint16(body[compEnd:]))
	need(compEnd + 2 + extLen)

	b := slices.Clone(body[:compEnd])
	b = binary.BigEndian.AppendUint16(b, uint16(extLen+4+len(data)))
	b = append(b, body[compEnd+2:compEnd+2+extLen]...)
	b = binary.BigEndian.AppendUint16(b, ext)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	b = append(b, data...)
	return append([]byte{0x01, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...)
}

// helloWithECH is a ClientHello for tlsName with an encrypted_client_hello extension of data,
// in one record.
func helloWithECH(t *testing.T, data []byte) []byte {
	t.Helper()
	msg := handshakeFromRecords(captureClientHello(t, &tls.Config{ServerName: tlsName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}))
	require.NotNil(t, msg)
	return records(withExtension(t, msg, extensionECH, data), tls.VersionTLS10)
}

// firstRecord reads the first record the proxy writes on c and returns its content type,
// with the description of an alert. A connection closed before any record returns zero.
func firstRecord(t *testing.T, c net.Conn) (typ, alert byte) {
	t.Helper()
	head := make([]byte, 5)
	if _, err := io.ReadFull(c, head); err != nil {
		if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
			t.Fatal("the proxy neither answered nor closed the connection")
		}
		return 0, 0
	}
	if head[0] != tlsAlert {
		return head[0], 0
	}
	body := make([]byte, 2)
	_, err := io.ReadFull(c, body)
	require.NoError(t, err)
	return head[0], body[1]
}

// recordingConn keeps every byte read through it, so the records a TLS client received can
// be read back.
type recordingConn struct {
	net.Conn
	got []byte
}

func (c *recordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.got = append(c.got, b[:n]...)
	return n, err
}

// lastRecord returns the content type of the last record read, zero when none was.
func (c *recordingConn) lastRecord() byte {
	raw, last := c.got, byte(0)
	for len(raw) >= 5 {
		last = raw[0]
		raw = raw[min(len(raw), 5+int(binary.BigEndian.Uint16(raw[3:5]))):]
	}
	return last
}

// originHello is the server name and the extension types of the ClientHello a TLS origin
// received, and how its handshake ended.
type originHello struct {
	err  error
	name string
	exts []uint16
}

// tlsOrigin serves TLS with cert, the configuration changed by edit, and reports every
// handshake. Once a handshake completes serve runs, or a request is answered "origin".
func tlsOrigin(t *testing.T, cert *tls.Certificate, edit func(*tls.Config), serve func(*tls.Conn)) (string, <-chan originHello) {
	t.Helper()
	return tlsOriginAfter(t, nil, cert, edit, serve)
}

// upgradingOrigin is tlsOrigin behind a Postgres SSLRequest it answers with S.
func upgradingOrigin(t *testing.T, cert *tls.Certificate) (string, <-chan originHello) {
	t.Helper()
	return tlsOriginAfter(t, func(c net.Conn) error {
		var req [8]byte
		if _, err := io.ReadFull(c, req[:]); err != nil || req != sslRequest {
			return errors.New("not an SSLRequest")
		}
		_, err := c.Write([]byte{'S'})
		return err
	}, cert, nil, nil)
}

func tlsOriginAfter(t *testing.T, prelude func(net.Conn) error, cert *tls.Certificate, edit func(*tls.Config), serve func(*tls.Conn)) (string, <-chan originHello) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	hellos := make(chan originHello, 8)
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
	if serve == nil {
		serve = func(tc *tls.Conn) {
			if _, err := http.ReadRequest(bufio.NewReader(tc)); err == nil {
				_, _ = io.WriteString(tc, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\norigin")
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				if prelude != nil && prelude(c) != nil {
					return
				}
				var name string
				var exts []uint16
				cfg := &tls.Config{
					Certificates: []tls.Certificate{*cert},
					MinVersion:   tls.VersionTLS12,
					GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
						name, exts = chi.ServerName, slices.Clone(chi.Extensions)
						return nil, nil
					},
				}
				if edit != nil {
					edit(cfg)
				}
				tc := tls.Server(c, cfg)
				err := tc.Handshake()
				hellos <- originHello{name: name, exts: exts, err: err}
				if err == nil {
					serve(tc)
				}
			}()
		}
	}()
	return ln.Addr().String(), hellos
}

func nextHello(t *testing.T, hellos <-chan originHello) originHello {
	t.Helper()
	select {
	case h := <-hellos:
		return h
	case <-time.After(5 * time.Second):
		t.Fatal("the origin received no ClientHello")
		return originHello{}
	}
}

// presented terminates authority through a CONNECT on the HTTP/1.1 front at addr, sending
// the server name sni, and returns the chain the proxy presented.
func presented(t *testing.T, addr, authority, sni string) []*x509.Certificate {
	t.Helper()
	conn := connectRaw(t, addr, authority)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	require.NoError(t, tc.Handshake())
	return tc.ConnectionState().PeerCertificates
}

// routedOver sends a request for tlsName on the terminated connection c and returns the
// response body.
func routedOver(t *testing.T, c net.Conn) string {
	t.Helper()
	w := newWire(c)
	w.send(t, "GET / HTTP/1.1\r\nHost: "+tlsName+"\r\n\r\n")
	got := w.readResponse(t, http.MethodGet)
	require.NoError(t, got.err)
	return string(got.body)
}

// refusedUpstream sends a request for host on tc and checks that no answer of the origin
// reaches the client, a 502 over HTTP/1.1 and a closed stream otherwise.
func refusedUpstream(t *testing.T, tc *tls.Conn, host string) {
	t.Helper()
	w := newWire(tc)
	if tc.ConnectionState().NegotiatedProtocol == "http/1.1" {
		w.send(t, "GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
		assert.Equal(t, http.StatusBadGateway, w.readResponse(t, http.MethodGet).resp.StatusCode)
		return
	}
	// A byte stream the origin refused may have its failed end before the client writes.
	_, _ = io.WriteString(tc, "GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
	got, _ := io.ReadAll(w.br)
	assert.Empty(t, string(got))
}

// quicHandshake dials addr over QUIC with cfg and returns how the handshake ended.
func quicHandshake(t *testing.T, addr netip.AddrPort, cfg *tls.Config) error {
	t.Helper()
	pc, err := loopbackUDP()
	require.NoError(t, err)
	tr := &quic.Transport{Conn: pc}
	t.Cleanup(func() {
		_ = tr.Close()
		_ = pc.Close()
	})
	conn, err := tr.Dial(t.Context(), net.UDPAddrFromAddrPort(addr), cfg, &quic.Config{HandshakeIdleTimeout: time.Second})
	if err == nil {
		_ = conn.CloseWithError(0, "")
	}
	return err
}

// quicAlert returns the TLS alert a QUIC peer closed the connection with, RFC 9001 section
// 4.8.
func quicAlert(err error) (byte, bool) {
	te, ok := errors.AsType[*quic.TransportError](err)
	if !ok || !te.Remote || te.ErrorCode < 0x100 || te.ErrorCode > 0x1ff {
		return 0, false
	}
	return byte(te.ErrorCode - 0x100), true
}

// startTLSLine answers a line with OK, terminates the TLS the client sends next and writes
// "tls" on it.
func startTLSLine(c *TCPCtx) error {
	line := make([]byte, len("STARTTLS\n"))
	if _, err := io.ReadFull(c.Client(), line); err != nil {
		return err
	}
	if _, err := io.WriteString(c.Client(), "OK\n"); err != nil {
		return err
	}
	if err := c.StartTLS(); err != nil {
		return err
	}
	_, err := io.WriteString(c.Client(), "tls\n")
	return err
}

// startTLSRelay dials the origin, relays an SSLRequest and the answer of the origin, then
// terminates the TLS the client sends next and relays the rest.
func startTLSRelay(c *TCPCtx) error {
	up, err := c.Dial()
	if err != nil {
		return err
	}
	if _, err := relaySSLRequest(c.Client(), up); err != nil {
		return err
	}
	if err := c.StartTLS(); err != nil {
		return err
	}
	return c.Relay()
}

// upgradedClient opens a stream to tlsDB through a CONNECT on the HTTP/1.1 front at addr and
// returns the TLS client it starts there after an SSLRequest, its handshake done.
func upgradedClient(t *testing.T, addr string, ca *CA) *tls.Conn {
	t.Helper()
	conn := connectRaw(t, addr, tlsDB+":5432")
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	return startTLSClient(t, conn, clientTLSConfig(ca, tlsDB))
}

// h2StreamConn is a stream of an h2Raw connection as a net.Conn. Close stops a blocked
// read and leaves the stream as it is.
type h2StreamConn struct {
	c      *h2Raw
	events chan h2Event
	done   chan struct{}
	rest   []byte
	once   sync.Once
	id     uint32
}

func (s *h2StreamConn) Read(b []byte) (int, error) {
	for len(s.rest) == 0 {
		select {
		case ev := <-s.events:
			if ev.err != nil {
				return 0, ev.err
			}
			s.rest = ev.data
		case <-s.done:
			return 0, net.ErrClosed
		}
	}
	n := copy(b, s.rest)
	s.rest = s.rest[n:]
	return n, nil
}

func (s *h2StreamConn) Write(b []byte) (int, error) {
	if err := s.c.data(s.id, b, false); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (s *h2StreamConn) Close() error {
	s.once.Do(func() { close(s.done) })
	return nil
}

func (*h2StreamConn) LocalAddr() net.Addr              { return emptyAddr{} }
func (*h2StreamConn) RemoteAddr() net.Addr             { return emptyAddr{} }
func (*h2StreamConn) SetDeadline(time.Time) error      { return nil }
func (*h2StreamConn) SetReadDeadline(time.Time) error  { return nil }
func (*h2StreamConn) SetWriteDeadline(time.Time) error { return nil }

// h2Connect sends a CONNECT to authority on an HTTP/2 connection to the front at front and
// returns its stream once the proxy granted it.
func h2Connect(t *testing.T, front netip.AddrPort, ca *CA, authority string) net.Conn {
	t.Helper()
	c := dialH2Raw(t, front.String(), ca)
	id, events := c.open(t, []hpack.HeaderField{hf(":method", http.MethodConnect), hf(":authority", authority)})
	select {
	case ev := <-events:
		require.NotNil(t, ev.head, "the answer to CONNECT starts with HEADERS, %v", ev.err)
		require.Equal(t, "200", ev.head.PseudoValue("status"))
	case <-time.After(5 * time.Second):
		t.Fatal("no answer to the CONNECT")
	}
	s := &h2StreamConn{c: c, id: id, events: events, done: make(chan struct{})}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// h3Connect sends a CONNECT to authority on an HTTP/3 connection to the front at front and
// returns its stream once the proxy granted it.
func h3Connect(t *testing.T, front netip.AddrPort, ca *CA, authority string) net.Conn {
	t.Helper()
	h3 := &http3.Transport{}
	t.Cleanup(func() { _ = h3.Close() })
	cc := h3.NewClientConn(dialQUICFront(t, front, ca))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	str, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodConnect, "https://"+authority, nil)
	require.NoError(t, err)
	require.NoError(t, str.SendRequestHeader(req))
	require.NoError(t, str.SetReadDeadline(time.Now().Add(5*time.Second)))
	resp, err := str.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return streamConn{str}
}

// tlsFronts are the ways a TLS client reaches p, each returning the client end of a
// connection to host on which the proxy terminates TLS.
var tlsFronts = []struct {
	dial func(t *testing.T, p *Proxy, host string) net.Conn
	name string
}{
	{name: "a transparent connection", dial: func(t *testing.T, p *Proxy, _ string) net.Conn {
		c, err := net.DialTimeout("tcp", startTransparent(t, p), 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { _ = c.Close() })
		require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
		return c
	}},
	{name: "a CONNECT", dial: func(t *testing.T, p *Proxy, host string) net.Conn {
		c := connectRaw(t, startProxy(t, p), host+":443")
		require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
		return c
	}},
}

// quicFronts are the ways a QUIC client reaches a proxy terminating HTTP/3 for h3Authority,
// each returning the socket of the client, the address it writes to and the certificate
// authority of the proxy.
var quicFronts = []struct {
	open func(t *testing.T, opts ...ProxyOption) (net.PacketConn, net.Addr, *CA)
	name string
}{
	{name: "QUIC", open: func(t *testing.T, opts ...ProxyOption) (net.PacketConn, net.Addr, *CA) {
		p, ca := newTLSProxy(t, opts...)
		p.MustAdd(h3Authority+"/*{any}", okHandler)
		addr := startQUIC(t, p)
		pc, err := loopbackUDP()
		require.NoError(t, err)
		t.Cleanup(func() { _ = pc.Close() })
		return pc, net.UDPAddrFromAddrPort(addr), ca
	}},
	{name: "a CONNECT-UDP tunnel", open: func(t *testing.T, opts ...ProxyOption) (net.PacketConn, net.Addr, *CA) {
		_, ca, front, origin := masqueProxy(t, opts...)
		pc, _, err := openTunnel(t, masqueClient(t, front, ca), front, fmt.Sprintf("%s:%d", h3Authority, origin.Port()), nil)
		require.NoError(t, err)
		return pc, net.UDPAddrFromAddrPort(origin), ca
	}},
	{name: "a redirected QUIC connection", open: func(t *testing.T, opts ...ProxyOption) (net.PacketConn, net.Addr, *CA) {
		p, ca := newTLSProxy(t, opts...)
		p.MustAdd(h3Authority+"/*{any}", okHandler)
		addr := startQUICRedirected(t, p, netip.MustParseAddrPort("127.0.0.1:443"))
		pc, err := loopbackUDP()
		require.NoError(t, err)
		t.Cleanup(func() { _ = pc.Close() })
		return pc, net.UDPAddrFromAddrPort(addr), ca
	}},
}

// quicHandshakeOver dials the address to through pc with cfg and returns how the handshake
// ended. The transport is left open, and the front that opened pc closes it.
func quicHandshakeOver(t *testing.T, pc net.PacketConn, to net.Addr, cfg *tls.Config) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := (&quic.Transport{Conn: pc}).Dial(ctx, to, cfg, &quic.Config{DisablePathMTUDiscovery: true, HandshakeIdleTimeout: 2 * time.Second})
	if err == nil {
		_ = conn.CloseWithError(0, "")
	}
	return err
}

// tlsConformance lists the requirements TLS and the certificate profile place on a proxy
// terminating TLS, checked with a client in front of edge and an origin behind it.
var tlsConformance = []conformanceCase{
	// RFC 5280 section 4.1.2.2, serial number.
	{
		id: "rfc5280/4.1.2.2/1", name: "a leaf the proxy mints",
		req: "The serial number MUST be a positive integer assigned by the CA to each certificate.",
		run: func(t *testing.T) {
			p, _ := newTLSProxy(t)
			leaf := presented(t, startProxy(t, p), tlsName+":443", tlsName)[0]
			assert.Positive(t, leaf.SerialNumber.Sign())
		},
	},
	{
		id: "rfc5280/4.1.2.2/2", name: "two leaves the proxy mints",
		req: "It MUST be unique for each certificate issued by a given CA (i.e., the issuer name and serial number identify a unique certificate).",
		run: func(t *testing.T) {
			p, ca := newTLSProxy(t)
			p.MustAdd("other.test/*{any}", noopHandler)
			addr := startProxy(t, p)
			first := presented(t, addr, tlsName+":443", tlsName)[0]
			second := presented(t, addr, "other.test:443", "other.test")[0]
			assert.NotEqual(t, first.SerialNumber, second.SerialNumber)
			assert.NotEqual(t, ca.Certificate().SerialNumber, first.SerialNumber)
		},
	},
	{
		id: "rfc5280/4.1.2.2/3", name: "the serial number of a minted leaf",
		req: "Conforming CAs MUST NOT use serialNumber values longer than 20 octets.",
		run: func(t *testing.T) {
			p, _ := newTLSProxy(t)
			leaf := presented(t, startProxy(t, p), tlsName+":443", tlsName)[0]
			// The DER integer has one more octet when the high bit of the first is set.
			assert.LessOrEqual(t, (leaf.SerialNumber.BitLen()+8)/8, 20)
		},
	},

	// RFC 5280 section 4.2.1.2, subject key identifier.
	{
		id: "rfc5280/4.2.1.2/1", name: "a leaf the proxy mints",
		req: "To assist applications in identifying the appropriate end entity certificate, this extension SHOULD be included in all end entity certificates.",
		run: func(t *testing.T) {
			p, _ := newTLSProxy(t)
			leaf := presented(t, startProxy(t, p), tlsName+":443", tlsName)[0]
			assert.NotEmpty(t, leaf.SubjectKeyId)
		},
	},

	// RFC 5280 section 4.2.1.6, subject alternative name.
	{
		id: "rfc5280/4.2.1.6/1", name: "a leaf for a name the authority never verified",
		req:  "Because the subject alternative name is considered to be definitively bound to the public key, all parts of the subject alternative name MUST be verified by the CA.",
		skip: "edge mints a leaf for any name an entry admits, which is the interception it exists for",
		run: func(t *testing.T) {
			p, _ := newTLSProxy(t)
			conn := connectRaw(t, startProxy(t, p), tlsName+":443")
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			err := tls.Client(conn, &tls.Config{ServerName: tlsName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}).Handshake()
			assert.Error(t, err, "the proxy presented a leaf for a name it did not verify")
		},
	},
	{
		id: "rfc5280/4.2.1.6/2", name: "a CONNECT to a host with a trailing dot and no server name",
		req: "The name MUST be in the \"preferred name syntax\", as specified by Section 3.5 of [RFC1034] and as modified by Section 2.1 of [RFC1123].",
		run: func(t *testing.T) {
			p, _ := newTLSProxy(t)
			p.MustAdd("127.0.0.1/*{any}", noopHandler)
			addr := startProxy(t, p)
			for _, tc := range []struct{ name, authority string }{
				{name: "the trailing dot of a name", authority: tlsName + ".:443"},
				{name: "the trailing dot of an address", authority: "127.0.0.1.:443"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					leaf := presented(t, addr, tc.authority, "")[0]
					for _, name := range leaf.DNSNames {
						assert.Regexp(t, preferredName, name)
					}
				})
			}
		},
	},
	{
		id: "rfc5280/4.2.1.6/3", name: "a server name outside the preferred name syntax and an entry on every name",
		req: "The name MUST be in the \"preferred name syntax\", as specified by Section 3.5 of [RFC1034] and as modified by Section 2.1 of [RFC1123].",
		run: func(t *testing.T) {
			p, _ := newTLSProxy(t)
			p.MustAdd("+{any}/*{any}", noopHandler)
			addr := startProxy(t, p)
			for _, sni := range []string{"under_score.test", "-leading.test", "exa mple.test"} {
				t.Run(sni, func(t *testing.T) {
					conn := connectRaw(t, addr, tlsName+":443")
					require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
					tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
					if tc.Handshake() != nil {
						return
					}
					for _, name := range tc.ConnectionState().PeerCertificates[0].DNSNames {
						assert.Regexp(t, preferredName, name)
					}
				})
			}
		},
	},

	// RFC 5280 section 4.2.1.12, extended key usage.
	{
		id: "rfc5280/4.2.1.12/1", name: "a leaf the proxy presents as a TLS server",
		req: "If the extension is present, then the certificate MUST only be used for one of the purposes indicated.",
		run: func(t *testing.T) {
			p, _ := newTLSProxy(t)
			leaf := presented(t, startProxy(t, p), tlsName+":443", tlsName)[0]
			if len(leaf.ExtKeyUsage) > 0 {
				assert.True(t, slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) || slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny),
					"extended key usage %v", leaf.ExtKeyUsage)
			}
		},
	},

	// RFC 6066 section 3, server name indication.
	{
		id: "rfc6066/3/1", name: "a server name no entry admits",
		req: "If the server understood the ClientHello extension but does not recognize the server name, the server SHOULD take one of two actions: either abort the handshake by sending a fatal-level unrecognized_name(112) alert or continue the handshake.",
		run: func(t *testing.T) {
			hello := captureClientHello(t, &tls.Config{ServerName: "unknown.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
			check := func(t *testing.T, c net.Conn) {
				_, err := c.Write(hello)
				require.NoError(t, err)
				typ, alert := firstRecord(t, c)
				if typ != tlsHandshakeRecord {
					assert.Equal(t, [2]byte{tlsAlert, 112}, [2]byte{typ, alert})
				}
			}
			t.Run("connect", func(t *testing.T) {
				p, _ := newTLSProxy(t)
				check(t, connectRaw(t, startProxy(t, p), tlsName+":443"))
			})
			t.Run("transparent", func(t *testing.T) {
				p, _ := newTLSProxy(t)
				check(t, redirectedConn(t, p))
			})
			t.Run("quic", func(t *testing.T) {
				p, _ := newTLSProxy(t)
				err := quicHandshake(t, startQUIC(t, p), &tls.Config{ServerName: "unknown.test", InsecureSkipVerify: true, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13})
				if err != nil {
					alert, ok := quicAlert(err)
					assert.True(t, ok, "the handshake ended without an alert, %v", err)
					assert.Equal(t, byte(112), alert)
				}
			})
		},
	},
	{
		id: "rfc6066/3/2", name: "a CONNECT to an address with a trailing dot",
		req: "Literal IPv4 and IPv6 addresses are not permitted in \"HostName\".",
		run: func(t *testing.T) {
			originCA, err := GenerateCA()
			require.NoError(t, err)
			cert, err := originCA.Leaf("127.0.0.1")
			require.NoError(t, err)
			origin, hellos := tlsOrigin(t, cert, nil, nil)
			_, port, _ := net.SplitHostPort(origin)
			authority := "127.0.0.1.:" + port

			tr := DefaultTransport()
			tr.DialContext = pinnedDialer(origin)
			tr.RootCAs = originCA.CertPool()
			p, _ := newTLSProxy(t, WithTransport(tr))
			p.MustAdd("127.0.0.1/*{any}", forwardHandler)
			p.MustAdd[TCP]("127.0.0.1", relayStream)
			addr := startProxy(t, p)

			for _, alpn := range []string{"http/1.1", "x-test"} {
				t.Run(alpn, func(t *testing.T) {
					conn := connectRaw(t, addr, authority)
					require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
					tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}, MinVersion: tls.VersionTLS12})
					require.NoError(t, tc.Handshake())
					_, err := io.WriteString(tc, "GET / HTTP/1.1\r\nHost: "+authority+"\r\n\r\n")
					require.NoError(t, err)
					h := nextHello(t, hellos)
					_, perr := netip.ParseAddr(h.name)
					assert.Error(t, perr, "the origin received the server name %q", h.name)
				})
			}
		},
	},
	{
		id: "rfc6066/3/3", name: "the server name the proxy sends to the origin",
		req: "It is RECOMMENDED that clients include an extension of type \"server_name\" in the client hello whenever they locate a server by a supported name type.",
		run: func(t *testing.T) {
			originCA, err := GenerateCA()
			require.NoError(t, err)
			for _, alpn := range []string{"http/1.1", "x-test"} {
				t.Run(alpn, func(t *testing.T) {
					cert, err := originCA.Leaf(tlsUpstream)
					require.NoError(t, err)
					origin, hellos := tlsOrigin(t, cert, nil, nil)
					p, ca := upstreamProxy(t, origin, originCA.CertPool())
					conn := connectRaw(t, startProxy(t, p), tlsUpstream+":443")
					require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
					tc := tls.Client(conn, &tls.Config{ServerName: tlsUpstream, RootCAs: ca.CertPool(), NextProtos: []string{alpn}, MinVersion: tls.VersionTLS12})
					require.NoError(t, tc.Handshake())
					_, err = io.WriteString(tc, "GET / HTTP/1.1\r\nHost: "+tlsUpstream+"\r\n\r\n")
					require.NoError(t, err)
					h := nextHello(t, hellos)
					require.NoError(t, h.err)
					assert.Equal(t, tlsUpstream, h.name)
				})
			}
			t.Run("STARTTLS", func(t *testing.T) {
				cert, err := originCA.Leaf(tlsDB)
				require.NoError(t, err)
				origin, hellos := upgradingOrigin(t, cert)
				p, ca := upstreamProxy(t, origin, originCA.CertPool())
				upgradedClient(t, startProxy(t, p), ca)
				h := nextHello(t, hellos)
				require.NoError(t, h.err)
				assert.Equal(t, tlsDB, h.name)
			})
		},
	},

	// RFC 7301 section 3.2, protocol selection.
	{
		id: "rfc7301/3.2/1", name: "two offers of h2 and http/1.1 in opposite orders",
		req:  "In that case, the server SHOULD select the most highly preferred protocol that it supports and that is also advertised by the client.",
		skip: "edge selects in the order of the client offer, the mirror of the client that TestTerminate_ALPNMirrorsClientOffer checks",
		run: func(t *testing.T) {
			p, ca := newTLSProxy(t)
			addr := startProxy(t, p)
			var selected []string
			for _, offer := range [][]string{{"h2", "http/1.1"}, {"http/1.1", "h2"}} {
				conn := connectRaw(t, addr, tlsName+":443")
				require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				tc := tls.Client(conn, &tls.Config{ServerName: tlsName, RootCAs: ca.CertPool(), NextProtos: offer, MinVersion: tls.VersionTLS12})
				require.NoError(t, tc.Handshake())
				selected = append(selected, tc.ConnectionState().NegotiatedProtocol)
			}
			assert.Equal(t, selected[0], selected[1], "the selection followed the order of the offer")
		},
	},
	{
		id: "rfc7301/3.2/2", name: "an offer with no protocol the authority admits",
		req: "In the event that the server supports no protocols that the client advertises, then the server SHALL respond with a fatal \"no_application_protocol\" alert.",
		run: func(t *testing.T) {
			hello := captureClientHello(t, &tls.Config{ServerName: tlsName, InsecureSkipVerify: true, NextProtos: []string{"x-test"}, MinVersion: tls.VersionTLS12})
			check := func(t *testing.T, c net.Conn) {
				require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
				_, err := c.Write(hello)
				require.NoError(t, err)
				typ, alert := firstRecord(t, c)
				assert.Equal(t, [2]byte{tlsAlert, 120}, [2]byte{typ, alert})
			}
			t.Run("connect", func(t *testing.T) {
				p, _ := newTLSProxy(t)
				check(t, connectRaw(t, startProxy(t, p), tlsName+":443"))
			})
			t.Run("the TLS front", func(t *testing.T) {
				p, ca := newTLSProxy(t)
				addr, _ := startProxyTLS(t, p, ca)
				c, err := net.DialTimeout("tcp", addr, 5*time.Second)
				require.NoError(t, err)
				t.Cleanup(func() { _ = c.Close() })
				check(t, c)
			})
			t.Run("the HTTP/3 front", func(t *testing.T) {
				p, ca := newTLSProxy(t)
				addr, _ := startQUICFront(t, p, ca)
				err := quicHandshake(t, addr, &tls.Config{ServerName: tlsName, InsecureSkipVerify: true, NextProtos: []string{"x-test"}, MinVersion: tls.VersionTLS13})
				alert, ok := quicAlert(err)
				assert.True(t, ok, "the handshake ended without an alert, %v", err)
				assert.Equal(t, byte(120), alert)
			})
		},
	},
	{
		id: "rfc7301/3.2/3", name: "a QUIC offer with no protocol the authority admits",
		req: "In the event that the server supports no protocols that the client advertises, then the server SHALL respond with a fatal \"no_application_protocol\" alert.",
		run: func(t *testing.T) {
			p, _ := newTLSProxy(t)
			err := quicHandshake(t, startQUIC(t, p), &tls.Config{ServerName: tlsName, InsecureSkipVerify: true, NextProtos: []string{"x-test"}, MinVersion: tls.VersionTLS13})
			alert, ok := quicAlert(err)
			assert.True(t, ok, "the handshake ended without an alert, %v", err)
			assert.Equal(t, byte(120), alert)
		},
	},
	{
		id: "rfc7301/3.2/4", name: "a client that negotiated http/1.1 and sends the HTTP/2 preface",
		req: "The server SHALL NOT respond with a selected protocol and subsequently use a different protocol for application data exchange.",
		run: func(t *testing.T) {
			p, ca := newTLSProxy(t)
			conn := connectRaw(t, startProxy(t, p), tlsName+":443")
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			tc := tls.Client(conn, &tls.Config{ServerName: tlsName, RootCAs: ca.CertPool(), NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
			require.NoError(t, tc.Handshake())
			require.Equal(t, "http/1.1", tc.ConnectionState().NegotiatedProtocol)
			_, err := io.WriteString(tc, http2.ClientPreface)
			require.NoError(t, err)
			require.NoError(t, http2.NewFramer(tc, nil).WriteSettings())
			head := make([]byte, 9)
			if _, err := io.ReadFull(tc, head); err == nil {
				assert.NotEqual(t, byte(http2.FrameSettings), head[3], "the proxy answered in HTTP/2 on a connection that negotiated http/1.1")
			}
		},
	},
	{
		id: "rfc7301/3.2/5", name: "a client that negotiated h2 and sends an HTTP/1.1 request",
		req: "The server SHALL NOT respond with a selected protocol and subsequently use a different protocol for application data exchange.",
		run: func(t *testing.T) {
			p, ca := newTLSProxy(t)
			conn := connectRaw(t, startProxy(t, p), tlsName+":443")
			require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			tc := tls.Client(conn, &tls.Config{ServerName: tlsName, RootCAs: ca.CertPool(), NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
			require.NoError(t, tc.Handshake())
			require.Equal(t, "h2", tc.ConnectionState().NegotiatedProtocol)
			_, err := io.WriteString(tc, "GET / HTTP/1.1\r\nHost: "+tlsName+"\r\n\r\n")
			require.NoError(t, err)
			head := make([]byte, 8)
			if _, err := io.ReadFull(tc, head); err == nil {
				assert.NotEqual(t, "HTTP/1.1", string(head), "the proxy answered in HTTP/1.1 on a connection that negotiated h2")
			}
		},
	},

	// RFC 8813 section 3, the key usage of an elliptic curve key, added to RFC 5480 section 3.
	{
		id: "rfc8813/3/1", name: "a leaf the proxy mints for an ECDSA key",
		req: "If the keyUsage extension is present in a certificate that indicates id-ecPublicKey in SubjectPublicKeyInfo, then the following values MUST NOT be present: keyEncipherment; and dataEncipherment.",
		run: func(t *testing.T) {
			p, _ := newTLSProxy(t)
			leaf := presented(t, startProxy(t, p), tlsName+":443", tlsName)[0]
			require.Equal(t, x509.ECDSA, leaf.PublicKeyAlgorithm)
			assert.Zero(t, leaf.KeyUsage&x509.KeyUsageKeyEncipherment, "keyEncipherment")
			assert.Zero(t, leaf.KeyUsage&x509.KeyUsageDataEncipherment, "dataEncipherment")
		},
	},

	// RFC 9525 section 6, verifying the identity of the origin.
	{
		id: "rfc9525/6.1.1/1", name: "a redirected connection to an origin with a certificate for its address only",
		req: "Unless an application defines a process for authenticating intermediate identifiers in a way that then allows them to be used as a reference identifier (for example, see [SMTP-TLS]), any intermediate values are not reference identifiers and MUST NOT be treated as such.",
		run: func(t *testing.T) {
			originCA, err := GenerateCA()
			require.NoError(t, err)
			cert, err := originCA.Leaf("127.0.0.1")
			require.NoError(t, err)
			origin, hellos := tlsOrigin(t, cert, nil, nil)
			p, ca := upstreamProxy(t, origin, originCA.CertPool())
			addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
				return netip.ParseAddrPort(origin)
			})
			for _, alpn := range []string{"http/1.1", "x-test"} {
				t.Run(alpn, func(t *testing.T) {
					c, err := net.DialTimeout("tcp", addr, 5*time.Second)
					require.NoError(t, err)
					t.Cleanup(func() { _ = c.Close() })
					require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
					tc := tls.Client(c, &tls.Config{ServerName: tlsUpstream, RootCAs: ca.CertPool(), NextProtos: []string{alpn}, MinVersion: tls.VersionTLS12})
					require.NoError(t, tc.Handshake())
					refusedUpstream(t, tc, tlsUpstream)
					assert.Error(t, nextHello(t, hellos).err, "the origin was verified against its address")
				})
			}
		},
	},
	{
		id: "rfc9525/6.6/1", name: "an origin with a certificate for another name",
		req: "If the client is an automated application, then it SHOULD terminate the communication attempt with a bad certificate error and log the error appropriately.",
		run: func(t *testing.T) {
			originCA, err := GenerateCA()
			require.NoError(t, err)
			cert, err := originCA.Leaf("other.test")
			require.NoError(t, err)
			origin, hellos := tlsOrigin(t, cert, nil, nil)
			p, ca := upstreamProxy(t, origin, originCA.CertPool())
			addr := startProxy(t, p)
			for _, alpn := range []string{"http/1.1", "x-test"} {
				t.Run(alpn, func(t *testing.T) {
					conn := connectRaw(t, addr, tlsUpstream+":443")
					require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
					tc := tls.Client(conn, &tls.Config{ServerName: tlsUpstream, RootCAs: ca.CertPool(), NextProtos: []string{alpn}, MinVersion: tls.VersionTLS12})
					require.NoError(t, tc.Handshake())
					refusedUpstream(t, tc, tlsUpstream)
					assert.ErrorContains(t, nextHello(t, hellos).err, "bad certificate")
				})
			}
		},
	},
	{
		id: "rfc9525/6.6/2", name: "an origin with a certificate for another name from an authority the proxy does not trust",
		req: "The application MAY provide a configuration setting to disable this behavior, but it MUST NOT disable this security control by default.",
		run: func(t *testing.T) {
			originCA, err := GenerateCA()
			require.NoError(t, err)
			cert, err := originCA.Leaf("other.test")
			require.NoError(t, err)
			skipping := DefaultTransport()
			skipping.InsecureSkipVerify = true
			for _, tc := range []struct {
				name     string
				opts     []ProxyOption
				answered bool
			}{
				{name: "the default of New"},
				{name: "a transport skipping verification", opts: []ProxyOption{WithTransport(skipping)}, answered: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					for _, alpn := range []string{"http/1.1", "x-test"} {
						t.Run(alpn, func(t *testing.T) {
							origin, hellos := tlsOrigin(t, cert, nil, nil)
							p, ca := newTLSProxy(t, tc.opts...)
							p.MustAdd("127.0.0.1/*{any}", forwardHandler)
							p.MustAdd[TCP]("127.0.0.1", relayStream)
							conn := connectRaw(t, startProxy(t, p), origin)
							require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
							c := tls.Client(conn, &tls.Config{ServerName: "127.0.0.1", RootCAs: ca.CertPool(), NextProtos: []string{alpn}, MinVersion: tls.VersionTLS12})
							require.NoError(t, c.Handshake())
							if !tc.answered {
								refusedUpstream(t, c, origin)
								assert.Error(t, nextHello(t, hellos).err)
								return
							}
							w := newWire(c)
							w.send(t, "GET / HTTP/1.1\r\nHost: "+origin+"\r\n\r\n")
							got := w.readResponse(t, http.MethodGet)
							require.NoError(t, got.err)
							assert.Equal(t, "origin", string(got.body))
						})
					}
				})
			}
		},
	},

	// RFC 9846 section 4.5.1, the certificate message.
	{
		id: "rfc9846/4.5.1/1", name: "the chain the proxy presents",
		req: "The sender's certificate MUST come in the first CertificateEntry in the list.",
		run: func(t *testing.T) {
			p, _ := newTLSProxy(t)
			chain := presented(t, startProxy(t, p), tlsName+":443", tlsName)
			require.NotEmpty(t, chain)
			assert.False(t, chain[0].IsCA)
			assert.NoError(t, chain[0].VerifyHostname(tlsName))
		},
	},
	{
		id: "rfc9846/4.5.1/2", name: "the chain the proxy presents",
		req: "Each following certificate SHOULD directly certify the one immediately preceding it.",
		run: func(t *testing.T) {
			p, _ := newTLSProxy(t)
			chain := presented(t, startProxy(t, p), tlsName+":443", tlsName)
			for i := 1; i < len(chain); i++ {
				assert.NoError(t, chain[i-1].CheckSignatureFrom(chain[i]), "certificate %d", i)
			}
		},
	},

	// RFC 9846 section 4.5.1.2, certificate selection.
	{
		id: "rfc9846/4.5.1.2/1", name: "a leaf the proxy mints",
		req: "That is, the digitalSignature bit MUST be set if the Key Usage extension is present, and the public key (with associated restrictions) MUST be compatible with some supported signature scheme.",
		run: func(t *testing.T) {
			p, _ := newTLSProxy(t)
			leaf := presented(t, startProxy(t, p), tlsName+":443", tlsName)[0]
			if leaf.KeyUsage != 0 {
				assert.NotZero(t, leaf.KeyUsage&x509.KeyUsageDigitalSignature, "digitalSignature")
			}
			// The signature schemes of RFC 9846 section 4.2.3 that crypto/tls implements.
			switch k := leaf.PublicKey.(type) {
			case *ecdsa.PublicKey:
				assert.Contains(t, []string{"P-256", "P-384", "P-521"}, k.Curve.Params().Name)
			case *rsa.PublicKey, ed25519.PublicKey:
			default:
				t.Errorf("a %T key matches no signature scheme", k)
			}
		},
	},

	// RFC 9846 section 5.1, the record layer.
	{
		id: "rfc9846/5.1/1", name: "a ClientHello under each record version",
		req: "This field is deprecated and MUST be ignored for all purposes.",
		run: func(t *testing.T) {
			for _, version := range []uint16{0x0300, tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
				t.Run(fmt.Sprintf("%#04x", version), func(t *testing.T) {
					p, ca := newTLSProxy(t)
					conn := &helloConn{Conn: redirectedConn(t, p), frame: func(b []byte) [][]byte {
						return [][]byte{records(handshakeFromRecords(b), version)}
					}}
					tc := tls.Client(conn, &tls.Config{ServerName: tlsName, RootCAs: ca.CertPool(), NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
					require.NoError(t, tc.Handshake())
					assert.Equal(t, "routed", routedOver(t, tc))
				})
			}
		},
	},

	// RFC 9846 section 6, the alert protocol.
	{
		id: "rfc9846/6/1", name: "a client that aborts its handshake with ech_required",
		req:  "Upon receiving an error alert, the TLS implementation SHOULD indicate an error to the application and MUST NOT allow any further data to be sent or received on the connection.",
		skip: "crypto/tls decides it and departs, a received alert fails the reads alone and a write after it is still encrypted and sent, as rfc9846/6.2/2 records",
	},
	{
		id: "rfc9846/6.1/1", name: "a terminated connection the proxy closes",
		req: "Each party MUST send a \"close_notify\" alert before closing its write side of the connection, unless it has already sent some error alert.",
		run: func(t *testing.T) {
			p, ca := newTLSProxy(t)
			p.MustAdd[TCP]("stream.test", func(c *TCPCtx) error {
				_, err := io.WriteString(c.Client(), "bye")
				return err
			})
			addr := startProxy(t, p)
			// TLS 1.2 leaves the content type of an alert record readable on the wire.
			open := func(t *testing.T, name string, alpn ...string) (*tls.Conn, *recordingConn) {
				rec := &recordingConn{Conn: connectRaw(t, addr, name+":443")}
				require.NoError(t, rec.SetDeadline(time.Now().Add(5*time.Second)))
				tc := tls.Client(rec, &tls.Config{ServerName: name, RootCAs: ca.CertPool(), NextProtos: alpn, MaxVersion: tls.VersionTLS12, MinVersion: tls.VersionTLS12})
				require.NoError(t, tc.Handshake())
				return tc, rec
			}
			t.Run("a response that closes the connection", func(t *testing.T) {
				tc, rec := open(t, tlsName, "http/1.1")
				_, err := io.WriteString(tc, "GET / HTTP/1.1\r\nHost: "+tlsName+"\r\nConnection: close\r\n\r\n")
				require.NoError(t, err)
				got, _ := io.ReadAll(tc)
				require.Contains(t, string(got), "routed")
				assert.Equal(t, byte(tlsAlert), rec.lastRecord())
			})
			t.Run("a stream handler that returns", func(t *testing.T) {
				tc, rec := open(t, "stream.test", "x-test")
				got, _ := io.ReadAll(tc)
				require.Equal(t, "bye", string(got))
				assert.Equal(t, byte(tlsAlert), rec.lastRecord())
			})
			t.Run("a connection refused past the handshake", func(t *testing.T) {
				tc, rec := open(t, tlsName)
				_, err := tc.Write([]byte{0x00, 0x01, 0x02, 0x03})
				require.NoError(t, err)
				_, _ = io.ReadAll(tc)
				assert.Equal(t, byte(tlsAlert), rec.lastRecord())
			})
		},
	},
	{
		id: "rfc9846/6.1/2", name: "the origin closes its write side of a terminated stream",
		req: "Each party MUST send a \"close_notify\" alert before closing its write side of the connection, unless it has already sent some error alert.  This does not have any effect on its read side of the connection.",
		run: func(t *testing.T) {
			// On TLS 1.3 the close_notify half-closes at once. TLS 1.2 has none, a peer closes
			// on a close_notify, so it comes once the other direction ended. The type of the
			// record is read on TLS 1.2 alone, where it is not encrypted.
			for _, version := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
				t.Run(tls.VersionName(version), func(t *testing.T) {
					originCA, err := GenerateCA()
					require.NoError(t, err)
					cert, err := originCA.Leaf(tlsUpstream)
					require.NoError(t, err)
					rest := make(chan string, 1)
					origin, _ := tlsOrigin(t, cert, nil, func(tc *tls.Conn) {
						_, _ = io.WriteString(tc, "hi")
						_ = tc.CloseWrite()
						got, _ := io.ReadAll(tc)
						rest <- string(got)
					})
					p, ca := upstreamProxy(t, origin, originCA.CertPool())
					rec := &recordingConn{Conn: connectRaw(t, startProxy(t, p), tlsUpstream+":443")}
					require.NoError(t, rec.SetDeadline(time.Now().Add(5*time.Second)))
					tc := tls.Client(rec, &tls.Config{ServerName: tlsUpstream, RootCAs: ca.CertPool(), NextProtos: []string{"x-test"}, MaxVersion: version, MinVersion: version})
					require.NoError(t, tc.Handshake())

					got := make([]byte, 2)
					_, err = io.ReadFull(tc, got)
					require.NoError(t, err)
					assert.Equal(t, "hi", string(got))
					if version == tls.VersionTLS13 {
						_, err = tc.Read(make([]byte, 1))
						require.ErrorIs(t, err, io.EOF, "the origin's half-close did not reach the client")
					}

					_, err = io.WriteString(tc, "after")
					require.NoError(t, err)
					require.NoError(t, tc.CloseWrite())
					select {
					case got := <-rest:
						assert.Equal(t, "after", got)
					case <-time.After(5 * time.Second):
						t.Fatal("the origin never read the end of the stream")
					}
					_, err = io.ReadAll(tc)
					require.NoError(t, err)
					if version == tls.VersionTLS12 {
						assert.Equal(t, byte(tlsAlert), rec.lastRecord())
					}
				})
			}
		},
	},
	{
		id: "rfc9846/6.2/1", name: "a ClientHello the proxy refuses",
		req: "Whenever an implementation encounters a fatal error condition, it SHOULD send an appropriate fatal alert and MUST close the connection without sending or receiving any additional data.",
		run: func(t *testing.T) {
			t.Run("an Encrypted Client Hello offer", func(t *testing.T) {
				p, _ := newTLSProxy(t, WithRejectECH(true))
				c := connectRaw(t, startProxy(t, p), tlsName+":443")
				require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
				_, err := c.Write(echClientHello(t, tlsName, "secret.test"))
				require.NoError(t, err)
				typ, _ := firstRecord(t, c)
				assert.Equal(t, byte(tlsAlert), typ)
			})
			t.Run("a server name that does not resolve to the destination", func(t *testing.T) {
				r := &fakeResolver{addrs: map[string][]netip.Addr{tlsName: addrsOf("192.0.2.1")}}
				p, _ := newTLSProxy(t, WithNameVerification(VerifyReject), WithNameResolver(r))
				addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
					return netip.MustParseAddrPort("127.0.0.1:443"), nil
				})
				c, err := net.DialTimeout("tcp", addr, 5*time.Second)
				require.NoError(t, err)
				t.Cleanup(func() { _ = c.Close() })
				require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
				_, err = c.Write(captureClientHello(t, &tls.Config{ServerName: tlsName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}))
				require.NoError(t, err)
				typ, _ := firstRecord(t, c)
				assert.Equal(t, byte(tlsAlert), typ)
			})
		},
	},
	{
		id: "rfc9846/6.2/2", name: "a client offering http/1.1 that aborts its handshake with ech_required",
		req:  "Upon transmission or receipt of a fatal alert message, both parties MUST immediately close the connection.",
		skip: "net/http and crypto/tls decide it. The HTTP/1.1 server answers a read that failed on the alert with a 400, which crypto/tls encrypts and sends before its close_notify, through a CONNECT and a transparent connection, and with crypto/tls and net/http alone. With h2 the SETTINGS of the server may be written after the alert, in an order x/net and crypto/tls decide",
	},

	// RFC 9846 section 9, compliance requirements.
	{
		id: "rfc9846/9.2/1", name: "a ClientHello without a server name and no destination",
		req: "Servers requiring this extension SHOULD respond to a ClientHello lacking a \"server_name\" extension by terminating the connection with a \"missing_extension\" alert.",
		run: func(t *testing.T) {
			p, _ := newTLSProxy(t)
			c := redirectedConn(t, p)
			_, err := c.Write(captureClientHello(t, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}))
			require.NoError(t, err)
			typ, alert := firstRecord(t, c)
			assert.Equal(t, [2]byte{tlsAlert, 109}, [2]byte{typ, alert})
		},
	},
	{
		id: "rfc9846/9.3/1", name: "a ClientHello fragmented across records and writes",
		req: "A middlebox which terminates a TLS connection MUST behave as a compliant TLS server (to the original client), including having a certificate which the client is willing to accept, and also as a compliant TLS client (to the original server), including verifying the original server's certificate.",
		run: func(t *testing.T) {
			ones := func(n int) []int {
				s := make([]int, n)
				for i := range s {
					s[i] = 1
				}
				return s
			}
			frames := []struct {
				frame func(msg []byte) [][]byte
				name  string
			}{
				{name: "the body across two records", frame: func(m []byte) [][]byte { return [][]byte{records(m, tls.VersionTLS10, 64)} }},
				{name: "the handshake header across two records", frame: func(m []byte) [][]byte { return [][]byte{records(m, tls.VersionTLS10, 2)} }},
				{name: "one byte per record", frame: func(m []byte) [][]byte { return [][]byte{records(m, tls.VersionTLS10, ones(len(m))...)} }},
				{name: "each record in its own write", frame: func(m []byte) [][]byte { return eachRecord(records(m, tls.VersionTLS10, 64, 64)) }},
				{name: "a record header apart from its body", frame: func(m []byte) [][]byte {
					raw := records(m, tls.VersionTLS10)
					return [][]byte{raw[:5], raw[5:]}
				}},
			}
			// A ClientHello the peek cannot read is placed on the CONNECT destination or the
			// decided entry, and the handshake completes anyway. Rejecting Encrypted Client
			// Hello refuses it, so the handshake fails when the peek does.
			entries := []struct {
				dial   func(t *testing.T, p *Proxy, ca *CA) net.Conn
				name   string
				server string
				reject bool
			}{
				{name: "a redirected connection", server: tlsName, dial: func(t *testing.T, p *Proxy, _ *CA) net.Conn {
					return redirectedConn(t, p)
				}},
				{name: "a CONNECT over HTTP/3", server: tlsName, reject: true, dial: func(t *testing.T, p *Proxy, ca *CA) net.Conn {
					front, _ := startQUICFront(t, p, ca)
					return h3Connect(t, front, ca, tlsName+":443")
				}},
				{name: "a CONNECT over HTTP/2", server: tlsName, reject: true, dial: func(t *testing.T, p *Proxy, ca *CA) net.Conn {
					return h2Connect(t, startTLSFront(t, p, ca, "h2"), ca, tlsName+":443")
				}},
				{name: "a CONNECT over HTTP/1.1", server: tlsName, reject: true, dial: func(t *testing.T, p *Proxy, _ *CA) net.Conn {
					return connectRaw(t, startProxy(t, p), tlsName+":443")
				}},
				{name: "a SOCKS5 CONNECT", server: tlsName, reject: true, dial: func(t *testing.T, p *Proxy, _ *CA) net.Conn {
					w := socksConnect(t, startSOCKS5(t, p), socksNameBytes(tlsName, 443))
					require.Equal(t, byte(0), w.readReply()[1])
					return w.conn
				}},
				{name: "STARTTLS", server: tlsDB, reject: true, dial: func(t *testing.T, p *Proxy, _ *CA) net.Conn {
					p.MustAdd[TCP](tlsDB, startTLSLine)
					conn := connectRaw(t, startProxy(t, p), tlsDB+":5432")
					require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
					_, err := io.WriteString(conn, "STARTTLS\n")
					require.NoError(t, err)
					ok := make([]byte, len("OK\n"))
					_, err = io.ReadFull(conn, ok)
					require.NoError(t, err)
					require.Equal(t, "OK\n", string(ok))
					return conn
				}},
			}
			for _, f := range frames {
				frame := func(b []byte) [][]byte { return f.frame(handshakeFromRecords(b)) }
				t.Run(f.name, func(t *testing.T) {
					for _, e := range entries {
						t.Run(e.name, func(t *testing.T) {
							t.Parallel()
							p, ca := newTLSProxy(t, WithRejectECH(e.reject))
							conn := e.dial(t, p, ca)
							require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
							ctx, cancel := context.WithTimeout(t.Context(), time.Second)
							defer cancel()
							tc := tls.Client(&helloConn{Conn: conn, frame: frame}, &tls.Config{ServerName: e.server, RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12})
							assert.NoError(t, tc.HandshakeContext(ctx))
						})
					}
				})
			}
		},
	},
	{
		id: "rfc9846/9.3/2", name: "a ClientHello with an unknown extension and cipher suite",
		req: "A server receiving a ClientHello MUST correctly ignore all unrecognized cipher suites, extensions, and other parameters.",
		run: func(t *testing.T) {
			hello := spliceHello(t, captureClientHello(t, &tls.Config{ServerName: tlsName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}), 0x1a1a, 0x1a1a, []byte{0xab, 0xcd})
			for _, reject := range []bool{false, true} {
				t.Run(fmt.Sprintf("rejecting ECH %t", reject), func(t *testing.T) {
					p, _ := newTLSProxy(t, WithRejectECH(reject))
					c := redirectedConn(t, p)
					_, err := c.Write(hello)
					require.NoError(t, err)
					typ, _ := firstRecord(t, c)
					assert.Equal(t, byte(tlsHandshakeRecord), typ, "the proxy did not answer the ClientHello")
				})
			}
		},
	},
	{
		id: "rfc9846/9.3/3", name: "a client verifying the leaf the proxy presents",
		req: "A middlebox which terminates a TLS connection MUST behave as a compliant TLS server (to the original client), including having a certificate which the client is willing to accept, and also as a compliant TLS client (to the original server), including verifying the original server's certificate.",
		run: func(t *testing.T) {
			p, ca := newTLSProxy(t)
			p.MustAdd("127.0.0.1/*{any}", noopHandler)
			p.MustAdd("[::1]/*{any}", noopHandler)
			addr := startProxy(t, p)
			cases := []struct {
				name, authority string
				cfg             *tls.Config
			}{
				{name: "a name and its server name", authority: tlsName + ":443", cfg: &tls.Config{ServerName: tlsName}},
				{name: "an IPv4 address", authority: "127.0.0.1:443", cfg: &tls.Config{ServerName: "127.0.0.1"}},
				{name: "an IPv6 address", authority: "[::1]:443", cfg: &tls.Config{ServerName: "::1"}},
				{name: "a name without a server name", authority: tlsName + ":443", cfg: &tls.Config{
					InsecureSkipVerify: true,
					VerifyConnection: func(cs tls.ConnectionState) error {
						inter := x509.NewCertPool()
						for _, c := range cs.PeerCertificates[1:] {
							inter.AddCert(c)
						}
						_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: tlsName, Roots: ca.CertPool(), Intermediates: inter})
						return err
					},
				}},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					tc.cfg.RootCAs = ca.CertPool()
					tc.cfg.MinVersion = tls.VersionTLS12
					conn := connectRaw(t, addr, tc.authority)
					require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
					assert.NoError(t, tls.Client(conn, tc.cfg).Handshake())
				})
			}
			t.Run("a name once a CONNECT reached it with a trailing dot", func(t *testing.T) {
				p, ca := newTLSProxy(t)
				addr := startProxy(t, p)
				presented(t, addr, tlsName+".:443", "")
				conn := connectRaw(t, addr, tlsName+":443")
				require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				assert.NoError(t, tls.Client(conn, &tls.Config{ServerName: tlsName, RootCAs: ca.CertPool(), MinVersion: tls.VersionTLS12}).Handshake())
			})
		},
	},
	{
		id: "rfc9846/9.3/4", name: "an origin with a certificate from an authority the proxy does not trust",
		req: "A middlebox which terminates a TLS connection MUST behave as a compliant TLS server (to the original client), including having a certificate which the client is willing to accept, and also as a compliant TLS client (to the original server), including verifying the original server's certificate.",
		run: func(t *testing.T) {
			originCA, err := GenerateCA()
			require.NoError(t, err)
			trusted, err := GenerateCA()
			require.NoError(t, err)
			cert, err := originCA.Leaf(tlsUpstream)
			require.NoError(t, err)
			origin, hellos := tlsOrigin(t, cert, nil, nil)
			p, ca := upstreamProxy(t, origin, trusted.CertPool())
			addr := startProxy(t, p)
			for _, alpn := range []string{"http/1.1", "x-test"} {
				t.Run(alpn, func(t *testing.T) {
					conn := connectRaw(t, addr, tlsUpstream+":443")
					require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
					tc := tls.Client(conn, &tls.Config{ServerName: tlsUpstream, RootCAs: ca.CertPool(), NextProtos: []string{alpn}, MinVersion: tls.VersionTLS12})
					require.NoError(t, tc.Handshake())
					refusedUpstream(t, tc, tlsUpstream)
					assert.Error(t, nextHello(t, hellos).err)
				})
			}
			t.Run("STARTTLS", func(t *testing.T) {
				cert, err := originCA.Leaf(tlsDB)
				require.NoError(t, err)
				origin, hellos := upgradingOrigin(t, cert)
				p, ca := upstreamProxy(t, origin, trusted.CertPool())
				refusedUpstream(t, upgradedClient(t, startProxy(t, p), ca), tlsUpstream)
				assert.Error(t, nextHello(t, hellos).err)
			})
		},
	},
	{
		id: "rfc9846/9.3/5", name: "an offer of Encrypted Client Hello on a stream the proxy relays to a TLS origin",
		req: "In particular, it MUST generate its own ClientHello containing only parameters it understands, and it MUST generate a fresh ServerHello random value, rather than forwarding the endpoint's value.",
		run: func(t *testing.T) {
			originCA, err := GenerateCA()
			require.NoError(t, err)
			cert, err := originCA.Leaf(tlsUpstream)
			require.NoError(t, err)
			for _, f := range tlsFronts {
				t.Run(f.name, func(t *testing.T) {
					origin, hellos := tlsOrigin(t, cert, nil, nil)
					p, ca := upstreamProxy(t, origin, originCA.CertPool())
					err := tls.Client(f.dial(t, p, tlsUpstream), &tls.Config{
						ServerName:                     "secret.test",
						RootCAs:                        ca.CertPool(),
						NextProtos:                     []string{"x-test"},
						MinVersion:                     tls.VersionTLS13,
						EncryptedClientHelloConfigList: echConfigList(t, tlsUpstream),
					}).Handshake()
					require.ErrorAs(t, err, new(*tls.ECHRejectionError))
					h := nextHello(t, hellos)
					require.NoError(t, h.err)
					assert.Equal(t, tlsUpstream, h.name)
					assert.NotContains(t, h.exts, uint16(extensionECH))
				})
			}
		},
	},
	{
		id: "rfc9846/9.3/6", name: "an offer of Encrypted Client Hello over QUIC on a connection the proxy relays to an origin",
		req:  "In particular, it MUST generate its own ClientHello containing only parameters it understands, and it MUST generate a fresh ServerHello random value, rather than forwarding the endpoint's value.",
		skip: "no ClientHello toward the origin can be observed. The CONNECTION_CLOSE of the client with ech_required arrives with its Finished, and the handler of a QUIC entry ran for none of 20 such clients",
	},

	// RFC 9846 appendix E.5, security restrictions related to backward compatibility.
	{
		id: "rfc9846/E.5/1", name: "a peer offering TLS 1.1 at most",
		req: "The security of SSL 2.0 [SSL2], SSL 3.0 [RFC6101], TLS 1.0 [RFC2246], and TLS 1.1 [RFC4346] are considered insufficient for the reasons enumerated in [RFC6176], [RFC7568], and [RFC8996] and they MUST NOT be negotiated for any reason.",
		run: func(t *testing.T) {
			old := &tls.Config{ServerName: tlsName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
			t.Run("a client through a CONNECT", func(t *testing.T) {
				p, _ := newTLSProxy(t)
				conn := connectRaw(t, startProxy(t, p), tlsName+":443")
				require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				assert.ErrorContains(t, tls.Client(conn, old.Clone()).Handshake(), "protocol version")
			})
			t.Run("a client of the TLS front", func(t *testing.T) {
				p, ca := newTLSProxy(t)
				addr, _ := startProxyTLS(t, p, ca)
				conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				require.NoError(t, err)
				t.Cleanup(func() { _ = conn.Close() })
				require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				assert.ErrorContains(t, tls.Client(conn, old.Clone()).Handshake(), "protocol version")
			})
			t.Run("an origin", func(t *testing.T) {
				originCA, err := GenerateCA()
				require.NoError(t, err)
				cert, err := originCA.Leaf(tlsUpstream)
				require.NoError(t, err)
				origin, hellos := tlsOrigin(t, cert, func(c *tls.Config) {
					c.MinVersion, c.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
				}, nil)
				p, ca := upstreamProxy(t, origin, originCA.CertPool())
				conn := connectRaw(t, startProxy(t, p), tlsUpstream+":443")
				require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				tc := tls.Client(conn, &tls.Config{ServerName: tlsUpstream, RootCAs: ca.CertPool(), NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
				require.NoError(t, tc.Handshake())
				refusedUpstream(t, tc, tlsUpstream)
				assert.Error(t, nextHello(t, hellos).err, "the proxy negotiated TLS 1.1 with the origin")
			})
		},
	},

	// RFC 9849 section 7, server behavior.
	{
		id: "rfc9849/7/1", name: "an encrypted_client_hello extension of an undefined type, on a TCP connection without a destination an entry admits or on any QUIC connection",
		req: "If ECHClientHello.type is not a valid ECHClientHelloType, then the server MUST abort with an \"illegal_parameter\" alert.",
		run: func(t *testing.T) {
			// A server without ECH may also ignore the extension, RFC 9846 section 4.1.2, and
			// RFC 9846 section 6.2 permits a close without any alert.
			for _, f := range tlsFronts {
				if f.name != "a transparent connection" {
					continue
				}
				t.Run(f.name, func(t *testing.T) {
					p, _ := newTLSProxy(t)
					c := f.dial(t, p, tlsName)
					_, err := c.Write(helloWithECH(t, []byte{0x02}))
					require.NoError(t, err)
					typ, alert := firstRecord(t, c)
					if typ != 0 && typ != tlsHandshakeRecord {
						assert.Equal(t, [2]byte{tlsAlert, 47}, [2]byte{typ, alert})
					}
				})
			}
			t.Run("a connection redirected to a destination nothing admits", func(t *testing.T) {
				p, _ := newTLSProxy(t)
				addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
					return netip.MustParseAddrPort("192.0.2.1:443"), nil
				})
				c, err := net.DialTimeout("tcp", addr, 5*time.Second)
				require.NoError(t, err)
				t.Cleanup(func() { _ = c.Close() })
				require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
				_, err = c.Write(helloWithECH(t, []byte{0x02}))
				require.NoError(t, err)
				typ, alert := firstRecord(t, c)
				if typ != 0 {
					assert.Equal(t, [2]byte{tlsAlert, 47}, [2]byte{typ, alert})
				}
			})
			for _, f := range quicFronts {
				t.Run(f.name, func(t *testing.T) {
					pc, to, _ := f.open(t)
					a := newQUICAttempt(t, quicsniff.Version1, h3Authority)
					a.hello = withExtension(t, a.hello, extensionECH, []byte{0x02})
					got := quicAnswer(t, pc, to, a)
					if slices.Contains(got.types, 0x1c) {
						assert.Equal(t, uint64(0x100+47), got.closeCode, "RFC 9001 section 4.8")
					} else {
						assert.Contains(t, got.types, uint64(0x06), "the Initial has no CRYPTO frame")
					}
				})
			}
		},
	},
	{
		id: "rfc9849/7/2", name: "an encrypted_client_hello extension of an undefined type, on a CONNECT or a redirected TCP connection whose destination an entry admits",
		req:  "If ECHClientHello.type is not a valid ECHClientHelloType, then the server MUST abort with an \"illegal_parameter\" alert.",
		skip: "crypto/tls decides it, parsing the extension before it looks for ECH keys, and aborts with illegal_parameter (47)",
	},
	{
		id: "rfc9849/7/3", name: "an encrypted_client_hello extension of type inner",
		req:  "A shared mode server which receives a ClientHello with ECHClientHello.type of inner MUST abort with an \"illegal_parameter\" alert, because such a ClientHello should never be received directly from the network.",
		skip: "the sentence binds a shared mode server, and edge has no ECH keys and plays neither role. Without keys crypto/tls answers as the backend server of section 7.2, through a CONNECT with a ServerHello whose random ends in the accept_confirmation of that section, and on QUIC and in a CONNECT-UDP tunnel with an Initial of the server handshake",
	},

	// RFC 9849 section 7.1, client-facing server.
	{
		id: "rfc9849/7.1/1", name: "an offer of Encrypted Client Hello under a configuration the proxy does not have",
		req: "Otherwise, if all candidate ECHConfig values fail to decrypt the extension, the client-facing server MUST ignore the extension and proceed with the connection using ClientHelloOuter with the following modifications:",
		run: func(t *testing.T) {
			for _, f := range tlsFronts {
				t.Run(f.name, func(t *testing.T) {
					p, _ := newTLSProxy(t)
					c := f.dial(t, p, tlsName)
					_, err := c.Write(echClientHello(t, tlsName, "secret.test"))
					require.NoError(t, err)
					typ, _ := firstRecord(t, c)
					assert.Equal(t, byte(tlsHandshakeRecord), typ, "the proxy did not answer the ClientHelloOuter")
				})
			}
			for _, f := range quicFronts {
				t.Run(f.name, func(t *testing.T) {
					pc, to, _ := f.open(t)
					a := newQUICAttemptWith(t, quicsniff.Version1, &tls.Config{
						ServerName:                     "secret.test",
						NextProtos:                     []string{"h3"},
						MinVersion:                     tls.VersionTLS13,
						CurvePreferences:               []tls.CurveID{tls.X25519},
						EncryptedClientHelloConfigList: echConfigList(t, h3Authority),
					})
					got := quicAnswer(t, pc, to, a)
					assert.NotContains(t, got.types, uint64(0x1c), "the proxy closed the connection with %#x", got.closeCode)
					assert.Contains(t, got.types, uint64(0x06), "the Initial has no CRYPTO frame")
				})
			}
		},
	},
	{
		id: "rfc9849/7.1/2", name: "a GREASE encrypted_client_hello extension",
		req: "Otherwise, if all candidate ECHConfig values fail to decrypt the extension, the client-facing server MUST ignore the extension and proceed with the connection using ClientHelloOuter with the following modifications:",
		run: func(t *testing.T) {
			for _, f := range tlsFronts {
				t.Run(f.name, func(t *testing.T) {
					p, _ := newTLSProxy(t)
					c := f.dial(t, p, tlsName)
					_, err := c.Write(helloWithECH(t, greaseECH(t)))
					require.NoError(t, err)
					typ, _ := firstRecord(t, c)
					assert.Equal(t, byte(tlsHandshakeRecord), typ, "the proxy did not answer the ClientHello")
				})
			}
			for _, f := range quicFronts {
				t.Run(f.name, func(t *testing.T) {
					pc, to, _ := f.open(t)
					a := newQUICAttempt(t, quicsniff.Version1, h3Authority)
					a.hello = withExtension(t, a.hello, extensionECH, greaseECH(t))
					got := quicAnswer(t, pc, to, a)
					assert.NotContains(t, got.types, uint64(0x1c), "the proxy closed the connection with %#x", got.closeCode)
					assert.Contains(t, got.types, uint64(0x06), "the Initial has no CRYPTO frame")
				})
			}
		},
	},
	{
		id: "rfc9849/7.1/3", name: "an encrypted_client_hello extension of type outer cut short",
		req:  "Otherwise, if all candidate ECHConfig values fail to decrypt the extension, the client-facing server MUST ignore the extension and proceed with the connection using ClientHelloOuter with the following modifications:",
		skip: "crypto/tls decides it, parsing the extension before it looks for ECH keys, and aborts with decode_error (50), the alert RFC 9846 section 6 gives a message that does not parse. A transparent connection and QUIC get decode_error from edge, whose parse of the ClientHello fails the same way",
	},
	{
		id: "rfc9849/7.1/4", name: "an offer of Encrypted Client Hello on a transparent connection to a proxy rejecting it",
		req:  "Otherwise, if all candidate ECHConfig values fail to decrypt the extension, the client-facing server MUST ignore the extension and proceed with the connection using ClientHelloOuter with the following modifications:",
		skip: "edge departs under WithRejectECH, which refuses every ClientHello with the extension, an offer and GREASE alike, with handshake_failure (40) before the handshake (checkECH in ech.go, from peekClientHello in terminate.go)",
	},
	{
		id: "rfc9849/7.1/5", name: "an offer of Encrypted Client Hello through a CONNECT to a proxy rejecting it",
		req:  "Otherwise, if all candidate ECHConfig values fail to decrypt the extension, the client-facing server MUST ignore the extension and proceed with the connection using ClientHelloOuter with the following modifications:",
		skip: "edge departs under WithRejectECH, which refuses every ClientHello with the extension, an offer and GREASE alike, with handshake_failure (40) before the handshake (checkECH in ech.go, from peekClientHello in terminate.go)",
	},
	{
		id: "rfc9849/7.1/6", name: "an offer of Encrypted Client Hello over QUIC to a proxy rejecting it",
		req:  "Otherwise, if all candidate ECHConfig values fail to decrypt the extension, the client-facing server MUST ignore the extension and proceed with the connection using ClientHelloOuter with the following modifications:",
		skip: "edge departs under WithRejectECH, which refuses every ClientHello with the extension, an offer and GREASE alike, with CONNECTION_CLOSE 0x128, the handshake_failure of RFC 9001 section 4.8 (quicDemux.place in quicdemux.go)",
	},
	{
		id: "rfc9849/7.1/7", name: "an offer of Encrypted Client Hello in a CONNECT-UDP tunnel to a proxy rejecting it",
		req:  "Otherwise, if all candidate ECHConfig values fail to decrypt the extension, the client-facing server MUST ignore the extension and proceed with the connection using ClientHelloOuter with the following modifications:",
		skip: "edge departs under WithRejectECH, which refuses every ClientHello with the extension, an offer and GREASE alike, with CONNECTION_CLOSE 0x128, the handshake_failure of RFC 9001 section 4.8 (quicDemux.place in quicdemux.go)",
	},

	// RFC 9849 section 8.1.1, misconfiguration and deployment concerns.
	{
		id: "rfc9849/8.1.1/1", name: "an offer of Encrypted Client Hello whose public name an entry admits",
		req: "In order to ensure that the retry mechanism works successfully, servers SHOULD ensure that every endpoint which might receive a TLS connection is provisioned with an appropriate certificate for the public name.",
		run: func(t *testing.T) {
			// crypto/tls verifies the leaf for the public name before it reports the rejection.
			for _, f := range tlsFronts {
				t.Run(f.name, func(t *testing.T) {
					p, ca := newTLSProxy(t)
					err := tls.Client(f.dial(t, p, tlsName), &tls.Config{
						ServerName:                     "secret.test",
						RootCAs:                        ca.CertPool(),
						MinVersion:                     tls.VersionTLS13,
						EncryptedClientHelloConfigList: echConfigList(t, tlsName),
					}).Handshake()
					assert.ErrorAs(t, err, new(*tls.ECHRejectionError))
				})
			}
			for _, f := range quicFronts {
				t.Run(f.name, func(t *testing.T) {
					pc, to, ca := f.open(t)
					err := quicHandshakeOver(t, pc, to, &tls.Config{
						ServerName:                     "secret.test",
						RootCAs:                        ca.CertPool(),
						NextProtos:                     []string{"h3"},
						MinVersion:                     tls.VersionTLS13,
						EncryptedClientHelloConfigList: echConfigList(t, h3Authority),
					})
					var rejected *tls.ECHRejectionError
					assert.True(t, errors.As(err, &rejected), "%v", err)
				})
			}
		},
	},
}

const (
	viaTransparentQUIC   = "transparent-quic"
	viaConnectUDP        = "connect-udp"
	viaConnectUDPLiteral = "connect-udp-literal"
	viaH1WithoutALPN     = "h1-without-alpn"
)

// eachTerminatedFront runs run on every front on which edge terminates the connection of a
// client negotiating one of versions.
func eachTerminatedFront(t *testing.T, versions []string, run func(t *testing.T, front, version string)) {
	t.Helper()
	for _, version := range versions {
		fronts := declaredFronts
		if version == viaH3 {
			fronts = []string{viaTransparentQUIC, viaConnectUDP}
		}
		for _, front := range fronts {
			t.Run(version+"-"+front, func(t *testing.T) { run(t, front, version) })
		}
	}
}

// newMisdirectBench is a proxy admitting origin.test, other.test, localhost and 127.0.0.1, with
// every request forwarded to one origin behind TLS.
func newMisdirectBench(t *testing.T) *proxyBench {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	originCA, err := GenerateCA()
	require.NoError(t, err)
	cert, err := originCA.Leaf("origin.test")
	require.NoError(t, err)
	o := newTLSOrigin(t, *cert, always(okReply))
	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(o.addr)
	tr.InsecureSkipVerify = true
	resolver := &fakeResolver{addrs: map[string][]netip.Addr{"origin.test": {netip.MustParseAddr("127.0.0.1")}}}
	p := testProxyWithCA(t, ca, WithTransport(tr), WithNameResolver(resolver))
	for _, host := range []string{"origin.test", "other.test", "localhost", "127.0.0.1"} {
		p.MustAdd(host+"/*{any}", forwardHandler)
	}
	return &proxyBench{p: p, origin: o, trust: ca.CertPool()}
}

// dialTerminated opens a connection to the origin of b through front for version, with sni as the
// server name unless empty, and returns the certificate edge presented and a function that sends
// a GET for host on that connection and returns the status and the content of the response.
func dialTerminated(t *testing.T, b *proxyBench, front, version, sni string) (*x509.Certificate, func(t *testing.T, host string) (int, string)) {
	t.Helper()
	dst := netip.MustParseAddrPort(b.origin.addr)
	cfg := &tls.Config{ServerName: sni, RootCAs: b.trust, InsecureSkipVerify: sni == "", MinVersion: tls.VersionTLS12}
	if version == viaH3 {
		qc := dialTerminatedQUIC(t, b.p, front, dst, cfg)
		c, err := newH3Conn(qc)
		require.NoError(t, err)
		return qc.ConnectionState().TLS.PeerCertificates[0], func(t *testing.T, host string) (int, string) {
			t.Helper()
			got := c.roundTrip(t, h3Request("GET", host, "/"))
			require.NoError(t, got.err)
			return parseStatus(t, got.status()), string(got.body)
		}
	}

	alpn := map[string]string{viaH1: "http/1.1", viaH2: "h2"}[version]
	if alpn != "" {
		cfg.NextProtos = []string{alpn}
	}
	tc := tls.Client(dialDeclared(t, front, b.p, dst), cfg)
	require.NoError(t, tc.Handshake())
	require.Equal(t, alpn, tc.ConnectionState().NegotiatedProtocol)
	leaf := tc.ConnectionState().PeerCertificates[0]
	if version == viaH2 {
		_, err := io.WriteString(tc, http2.ClientPreface)
		require.NoError(t, err)
		h := newH2Wire(tc)
		require.NoError(t, h.fr.WriteSettings())
		id := uint32(1)
		return leaf, func(t *testing.T, host string) (int, string) {
			t.Helper()
			h.headers(t, id, true, hf(":method", "GET"), hf(":scheme", "https"), hf(":authority", host), hf(":path", "/"))
			got := h.reply(t, id)
			id += 2
			require.False(t, got.reset, "stream reset with %v", got.rst)
			status, _ := h2Field(got.fields, ":status")
			return parseStatus(t, status), string(got.body)
		}
	}
	w := newWire(tc)
	return leaf, func(t *testing.T, host string) (int, string) {
		t.Helper()
		w.send(t, "GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
		got := w.readResponse(t, "GET")
		require.NoError(t, got.err)
		return got.resp.StatusCode, string(got.body)
	}
}

// dialTerminatedQUIC opens a QUIC connection negotiating h3 to dst through front.
func dialTerminatedQUIC(t *testing.T, p *Proxy, front string, dst netip.AddrPort, cfg *tls.Config) *quic.Conn {
	t.Helper()
	cfg = cfg.Clone()
	cfg.NextProtos = []string{http3.NextProtoH3}
	cfg.MinVersion = tls.VersionTLS13
	qcfg := &quic.Config{MaxIdleTimeout: 10 * time.Second, HandshakeIdleTimeout: 3 * time.Second}
	var pc net.PacketConn
	to := dst
	switch front {
	case viaTransparentQUIC:
		to = startQUICRedirected(t, p, dst)
		udp, err := loopbackUDP()
		require.NoError(t, err)
		t.Cleanup(func() { _ = udp.Close() })
		pc = udp
	case viaConnectUDP, viaConnectUDPLiteral:
		frontCA, err := GenerateCA()
		require.NoError(t, err)
		addr, _ := startQUICFront(t, p, frontCA)
		target := fmt.Sprintf("origin.test:%d", dst.Port())
		if front == viaConnectUDPLiteral {
			target = dst.String()
		}
		mc, _, err := openTunnel(t, masqueClient(t, addr, frontCA), addr, target, nil)
		require.NoError(t, err)
		pc = mc
		qcfg.DisablePathMTUDiscovery = true
	default:
		t.Fatalf("unknown front %q", front)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	qc, err := quic.Dial(ctx, pc, net.UDPAddrFromAddrPort(to), cfg, qcfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	return qc
}

func parseStatus(t *testing.T, status string) int {
	t.Helper()
	code, err := strconv.Atoi(status)
	require.NoError(t, err, "status %q", status)
	return code
}

// leafHost returns the host a certificate minted by a [CA] is valid for.
func leafHost(leaf *x509.Certificate) string {
	if len(leaf.DNSNames) > 0 {
		return leaf.DNSNames[0]
	}
	return leaf.IPAddresses[0].String()
}

func TestLeafCovers(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	for _, tc := range []struct {
		leaf, host string
		want       bool
	}{
		{leaf: "origin.test", host: "origin.test", want: true},
		{leaf: "Origin.Test.", host: "origin.test", want: true},
		{leaf: "origin.test", host: "other.test"},
		{leaf: "origin.test", host: "www.origin.test"},
		{leaf: "origin.test", host: "127.0.0.1"},
		{leaf: "127.0.0.1", host: "127.0.0.1", want: true},
		{leaf: "127.0.0.1", host: "::ffff:127.0.0.1", want: true},
		{leaf: "::ffff:127.0.0.1", host: "127.0.0.1", want: true},
		{leaf: "127.0.0.1", host: "127.0.0.2"},
		{leaf: "127.0.0.1", host: "localhost"},
		{leaf: "2001:db8::1", host: "2001:db8::1", want: true},
		{leaf: "2001:db8::1", host: "2001:db8:0:0::1", want: true},
		{leaf: "fe80::1", host: "fe80::1%eth0"},
	} {
		cert, err := ca.Leaf(tc.leaf)
		require.NoError(t, err)
		assert.Equal(t, tc.want, leafCovers(cert.Leaf, tc.host), "%s for %s", tc.leaf, tc.host)
	}
}

func TestTerminate_ClientHelloAfterTheSniffTimeoutFailsVisibly(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithSniffTimeout(200*time.Millisecond))
	require.NoError(t, err)
	read := make(chan error, 1)
	p.MustAdd[TCP]("svc.test:443", func(c *TCPCtx) error {
		_, rerr := c.Client().Read(make([]byte, 1))
		read <- rerr
		return rerr
	})
	conn := connectRaw(t, startProxy(t, p), "svc.test:443")
	time.Sleep(400 * time.Millisecond)
	// The record header of a ClientHello and the start of its handshake message.
	_, err = conn.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00})
	require.NoError(t, err)
	select {
	case rerr := <-read:
		require.ErrorIs(t, rerr, errLateClientHello)
	case <-time.After(3 * time.Second):
		t.Fatal("the handler never read")
	}
	assert.Equal(t, "RST", peerEnd(conn, 3*time.Second))
}

func TestTerminate_SilentClientSpeaksPlaintextAfterTheSniffTimeout(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithSniffTimeout(200*time.Millisecond))
	require.NoError(t, err)
	got := make(chan string, 1)
	p.MustAdd[TCP]("svc.test:25", func(c *TCPCtx) error {
		line, rerr := bufio.NewReader(c.Client()).ReadString('\n')
		got <- line
		return rerr
	})
	conn := connectRaw(t, startProxy(t, p), "svc.test:25")
	time.Sleep(400 * time.Millisecond)
	// A first byte of 0x16 that is no TLS record header.
	_, err = conn.Write([]byte("\x16 EHLO client\n"))
	require.NoError(t, err)
	select {
	case line := <-got:
		assert.Equal(t, "\x16 EHLO client\n", line)
	case <-time.After(3 * time.Second):
		t.Fatal("the handler never read")
	}
}

func TestTerminate_UnresolvedHostInsideAConnectIsANameThatDoesNotMatch(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithNameVerification(VerifyReject), WithNameResolver(&fakeResolver{err: errors.New("no such host")}))
	require.NoError(t, err)
	p.MustAdd("svc.test/*{any}", func(*HTTPCtx) (*http.Response, error) { return Text(200, "ok"), nil })
	p.MustAdd("127.0.0.1/*{any}", func(*HTTPCtx) (*http.Response, error) { return Text(200, "ok"), nil })
	conn := connectRaw(t, startProxy(t, p), "127.0.0.1:8080")
	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: svc.test:8080\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.True(t, resp.Close)
}

func TestTerminate_PlaintextFirstRequestHeaderTimeoutGets408AndTheNormalEnd(t *testing.T) {
	p := testProxy(t, WithReadHeaderTimeout(500*time.Millisecond))
	p.MustAdd("plain.test/", okHandler)
	conn, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_, err = fmt.Fprintf(conn, "CONNECT plain.test:80 HTTP/1.1\r\nHost: plain.test:80\r\n\r\n")
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: plain.te")
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	resp, err = http.ReadResponse(br, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusRequestTimeout, resp.StatusCode)
	assert.True(t, resp.Close)
	_, err = io.ReadAll(br)
	assert.NoError(t, err, "the normal end of the connection")
}

func TestTerminate_408EndsNormallyUnderTrickledBytes(t *testing.T) {
	p := testProxy(t, WithReadHeaderTimeout(500*time.Millisecond))
	p.MustAdd("plain.test/", okHandler)
	conn, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_, err = fmt.Fprintf(conn, "CONNECT plain.test:80 HTTP/1.1\r\nHost: plain.test:80\r\n\r\n")
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: plain.te")
	require.NoError(t, err)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
				if _, err := conn.Write([]byte("x")); err != nil {
					return
				}
			}
		}
	}()
	time.Sleep(800 * time.Millisecond)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	b, err := io.ReadAll(br)
	t.Logf("read %q, end %v", b, err)
	if err != nil {
		t.Errorf("the end after the 408 is %v", err)
	}
}

func TestTerminate_RefusalAfterTheHandshakeReadsUntilTheClientEnds(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	p.MustAdd("svc.test/", noopHandler)
	raw := connectRaw(t, startProxy(t, p), "svc.test:443")
	tc := tls.Client(raw, &tls.Config{ServerName: "svc.test", RootCAs: ca.CertPool()})
	require.NoError(t, tc.Handshake())
	// Not HTTP, so the stream is refused, with more behind it than the sniff reads.
	go func() { _, _ = tc.Write(make([]byte, 128<<10)) }()
	require.NoError(t, tc.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, err = io.Copy(io.Discard, tc)
	require.NoError(t, err, "the refusal after the handshake wrote no close_notify")
	time.Sleep(50 * time.Millisecond)
	_, err = raw.Write(make([]byte, 64))
	require.NoError(t, err)
	require.Equal(t, "FIN", peerEnd(raw, 2*time.Second), "the refusal closed the socket before the client ended")
}

func TestTerminate_DrainEndOfAFreshConnectionResetsNothing(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	p.MustAdd("allowed.test/", okHandler)
	client, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer client.Close()
	_, err = io.WriteString(client, "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
	require.NoError(t, err)
	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tc := tls.Client(client, &tls.Config{RootCAs: ca.CertPool(), ServerName: "allowed.test", NextProtos: []string{"http/1.1"}})
	require.NoError(t, tc.Handshake())
	time.Sleep(100 * time.Millisecond)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	}()
	_ = tc.SetReadDeadline(time.Now().Add(4 * time.Second))
	_, err = tc.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF, "close_notify expected")
	// The client keeps its socket open past the discard bound of the proxy.
	time.Sleep(2 * alertWriteTimeout)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, err = client.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF, "the normal end of the connection was reset")
}

func TestTerminate_ClientResetAfterTheSniffTimeoutReachesTheOriginAsAReset(t *testing.T) {
	originAddr, upstream := oneConnOrigin(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithSniffTimeout(100*time.Millisecond))
	require.NoError(t, err)
	done := make(chan error, 1)
	p.MustAdd[TCP](originAddr, func(c *TCPCtx) error {
		up, err := c.Dial()
		if err != nil {
			done <- err
			return err
		}
		_, _, err = Relay(c.Client(), up)
		done <- err
		return err
	})
	conn := connectRaw(t, startProxy(t, p), originAddr)
	var up net.Conn
	select {
	case up = <-upstream:
	case <-time.After(3 * time.Second):
		t.Fatal("no upstream connection")
	}
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, conn.(*net.TCPConn).SetLinger(0))
	require.NoError(t, conn.Close())
	require.Equal(t, "RST", peerEnd(up, 2*time.Second))
	select {
	case err = <-done:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("the relay outlived both legs")
	}
}

func TestTerminate_ClientResetInsideTheFirstRequestHeaderFailsTheConnection(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithSniffTimeout(2*time.Second))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	p.MustAdd("reset.test/", okHandler)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	server, err := ln.Accept()
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- p.ServeConn(server) }()
	_, err = client.Write([]byte("GET / HTTP/1.1\r\nHo"))
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, client.(*net.TCPConn).SetLinger(0))
	require.NoError(t, client.Close())
	select {
	case err = <-done:
		require.ErrorIs(t, err, syscall.ECONNRESET)
	case <-time.After(5 * time.Second):
		t.Fatal("ServeConn did not return")
	}
}

func TestTerminate_TimeoutInsideTheClientHelloGetsNoAlert(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run("reject ECH "+strconv.FormatBool(reject), func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			p, err := New(WithCA(ca), WithRejectECH(reject), WithReadHeaderTimeout(300*time.Millisecond))
			require.NoError(t, err)
			t.Cleanup(func() { _ = p.Close() })
			p.MustAdd("reset.test/", okHandler)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			client, err := net.Dial("tcp", ln.Addr().String())
			require.NoError(t, err)
			defer client.Close()
			server, err := ln.Accept()
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() { done <- p.ServeConn(server) }()
			// A record header announcing a ClientHello of 256 bytes, one of them sent.
			_, err = client.Write([]byte{0x16, 0x03, 0x01, 0x01, 0x00, 0x01})
			require.NoError(t, err)
			_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
			got, err := io.ReadAll(client)
			require.Empty(t, got)
			require.ErrorIs(t, err, syscall.ECONNRESET)
			select {
			case err = <-done:
				require.True(t, isTimeout(err), "%v", err)
			case <-time.After(3 * time.Second):
				t.Fatal("ServeConn did not return")
			}
		})
	}
}
