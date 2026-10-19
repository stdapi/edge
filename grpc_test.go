// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func grpcDo(t *testing.T, client *http.Client, target string, payload []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(string(payload)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// grpcStatus reads the trailers, so read the body first.
func grpcStatus(resp *http.Response) (code, msg string) {
	if v := resp.Trailer.Get("Grpc-Status"); v != "" {
		return v, resp.Trailer.Get("Grpc-Message")
	}
	return resp.Header.Get("Grpc-Status"), resp.Header.Get("Grpc-Message")
}

// grpcHoldingOrigin holds a call until release is closed or the client cancels, counting the
// cancellations. reached is closed once the call arrived. With answerFirst the headers and one
// message are sent before holding.
func grpcHoldingOrigin(t *testing.T, release <-chan struct{}, answerFirst bool) (*httptest.Server, <-chan struct{}, *atomic.Int64) {
	t.Helper()
	var canceled atomic.Int64
	reached := make(chan struct{})
	arrived := sync.OnceFunc(func() { close(reached) })
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		arrived()
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		if answerFirst {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(grpcPayload("one"))
			_ = http.NewResponseController(w).Flush()
		}
		select {
		case <-release:
		case <-r.Context().Done():
			canceled.Add(1)
			return
		}
		_, _ = w.Write(grpcPayload("two"))
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	}))
	t.Cleanup(origin.Close)
	return origin, reached, &canceled
}

func grpcProxy(t *testing.T, origin *httptest.Server, opts ...ProxyOption) (*Proxy, string, *http.Client) {
	t.Helper()
	p, host, client := interceptingProxy(t, origin, opts...)
	_, err := p.Delete[HTTP](host + "/*{any}")
	require.NoError(t, err)
	return p, host, client
}

func grpcH2Proxy(t *testing.T, origin *httptest.Server) (*Proxy, string, *http.Client) {
	t.Helper()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	return p, originHost(originURL), h2Client(startProxy(t, p), ca.CertPool())
}

func TestKindGRPC_CutResetsTheHTTP11UpstreamOfAnHTTP2Client(t *testing.T) {
	originCA, err := GenerateCA()
	require.NoError(t, err)
	leaf, err := originCA.Leaf("127.0.0.1")
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	ended := make(chan string, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		c := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{*leaf}, NextProtos: []string{"http/1.1"}})
		if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\nTransfer-Encoding: chunked\r\n\r\n")
		msg := grpcPayload("one")
		_, _ = fmt.Fprintf(c, "%x\r\n%s\r\n", len(msg), msg)
		ended <- peerEnd(raw, 5*time.Second)
	}()
	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.RootCAs = originCA.CertPool()
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd("127.0.0.1/pkg.Svc/Hold", func(c *GRPCCtx) error { return c.Open() })
	client := h2Client(startProxy(t, p), ca.CertPool())
	pr, pw := io.Pipe()
	defer pw.Close()
	req, err := http.NewRequest(http.MethodPost, "https://"+ln.Addr().String()+"/pkg.Svc/Hold", pr)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/grpc")
	go func() { _, _ = pw.Write(grpcPayload("hello")) }()
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 2, resp.ProtoMajor)
	_, err = resp.Body.Read(make([]byte, 1))
	require.NoError(t, err)
	go func() { _ = p.Close() }()
	got := <-ended
	t.Logf("origin read %s", got)
	require.Equal(t, "RST", got, "the HTTP/1.1 origin of a gRPC call the cut ended read a clean end")
}

func TestKindGRPC_SendSubstitutesTheMessage(t *testing.T) {
	var (
		mu       sync.Mutex
		received []string
	)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		src := &msgSource{r: strings.NewReader(string(body)), max: defaultMaxMessageBytes}
		for {
			payload, _, err := src.next()
			if err != nil {
				break
			}
			mu.Lock()
			received = append(received, string(payload))
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		_, _ = w.Write(body)
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	}))
	t.Cleanup(origin.Close)
	p, host, client := grpcProxy(t, origin)

	p.MustAdd(host+"/pkg.Svc/Method", func(c *GRPCCtx) error {
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		src := MergeMessages(c.Outbound(), c.Inbound())
		for {
			m, rerr := src.ReadMessage()
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			if rerr != nil {
				return rerr
			}
			replacement := "edited"
			if m.Inbound() {
				replacement = "rewritten"
			}
			if serr := m.Send([]byte(replacement)); serr != nil {
				return serr
			}
		}
	})

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Method", grpcPayload("hello"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"edited"}, received, "the origin got the replacement")
	assert.Equal(t, grpcPayload("rewritten"), body, "the client got the replacement")
	assert.Equal(t, "0", resp.Trailer.Get("Grpc-Status"))
}

func TestKindGRPC_ReplyAnswersThePeerTheMessageCameFrom(t *testing.T) {
	var (
		mu       sync.Mutex
		received []string
	)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		src := &msgSource{r: r.Body, max: defaultMaxMessageBytes}
		record := func() bool {
			payload, _, err := src.next()
			if err != nil {
				return false
			}
			mu.Lock()
			received = append(received, string(payload))
			mu.Unlock()
			return true
		}
		if !record() {
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(grpcPayload("answer"))
		_ = http.NewResponseController(w).Flush()
		for record() {
		}
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	t.Cleanup(origin.Close)
	p, host, client := grpcH2Proxy(t, origin)

	p.MustAdd(host+"/pkg.Svc/Stream", func(c *GRPCCtx) error {
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		out, in := c.Outbound(), c.Inbound()
		m, rerr := out.ReadMessage()
		if rerr != nil {
			return rerr
		}
		if ferr := m.Forward(); ferr != nil {
			return ferr
		}
		if m, rerr = in.ReadMessage(); rerr != nil {
			return rerr
		}
		if ferr := m.Forward(); ferr != nil {
			return ferr
		}
		if perr := m.Reply([]byte("ack")); perr != nil {
			return perr
		}
		if m, rerr = out.ReadMessage(); rerr != nil {
			return rerr
		}
		if perr := m.Reply([]byte("pong")); perr != nil {
			return perr
		}
		if _, rerr = out.ReadMessage(); !errors.Is(rerr, io.EOF) {
			return rerr
		}
		if _, rerr = in.ReadMessage(); !errors.Is(rerr, io.EOF) {
			return rerr
		}
		return nil
	})

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Stream", grpcPayload("hello", "second"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"hello", "ack"}, received, "the reply to a response message reached the origin, the request message replied to did not")
	assert.Equal(t, grpcPayload("answer", "pong"), body, "the reply to a request message reached the client")
	assert.Equal(t, "0", resp.Trailer.Get("Grpc-Status"))
}

func TestKindGRPC_FailAfterOpenEndsTheCallOnItsStatus(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	origin, _, canceled := grpcHoldingOrigin(t, release, true)
	p, host, client := grpcProxy(t, origin)

	p.MustAdd(host+"/pkg.Svc/Watch", func(c *GRPCCtx) error {
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		_ = c.CloseSend()
		m, rerr := c.Inbound().ReadMessage()
		if rerr != nil {
			return rerr
		}
		if ferr := m.Forward(); ferr != nil {
			return ferr
		}
		return c.Fail(CodeResourceExhausted, "quota")
	})

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Watch", grpcPayload("hello"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, grpcPayload("one"), body, "what was forwarded before Fail reached the client")
	code, msg := grpcStatus(resp)
	assert.Equal(t, "8", code)
	assert.Equal(t, "quota", msg)
	assert.Eventually(t, func() bool { return canceled.Load() == 1 }, 3*time.Second, 10*time.Millisecond,
		"the origin was canceled")
}

func TestKindGRPC_FailBeforeTheOriginAnsweredIsTrailersOnly(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	origin, reached, canceled := grpcHoldingOrigin(t, release, false)
	p, host, client := grpcProxy(t, origin)

	p.MustAdd(host+"/pkg.Svc/Watch", func(c *GRPCCtx) error {
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		_ = c.CloseSend()
		<-reached
		return c.Fail(CodePermissionDenied, "policy")
	})

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Watch", grpcPayload("hello"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Empty(t, body)
	assert.Equal(t, "7", resp.Header.Get("Grpc-Status"), "the status travels in the headers")
	assert.Equal(t, "policy", resp.Header.Get("Grpc-Message"))
	assert.Eventually(t, func() bool { return canceled.Load() == 1 }, 3*time.Second, 10*time.Millisecond,
		"the origin was canceled")
}

func TestKindGRPC_FailAfterTheOriginFailedReadsAsTheStatus(t *testing.T) {
	origin, _ := grpcEchoOrigin(t)
	p, host, client := grpcProxy(t, origin)
	origin.Close()

	var readErr, replyErr error
	p.MustAdd(host+"/pkg.Svc/Method", func(c *GRPCCtx) error {
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		m, rerr := c.Outbound().ReadMessage()
		if rerr != nil {
			return rerr
		}
		_, readErr = c.Inbound().ReadMessage()
		replyErr = m.Reply([]byte("answer"))
		return c.Fail(CodePermissionDenied, "policy")
	})

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Method", grpcPayload("hello"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	require.Error(t, readErr)
	assert.ErrorIs(t, replyErr, readErr, "the send toward the client reports the origin failure")
	assert.Empty(t, body)
	assert.Equal(t, "7", resp.Header.Get("Grpc-Status"))
	assert.Equal(t, "policy", resp.Header.Get("Grpc-Message"))
}

func TestKindGRPC_FailAfterAFailedForwardReadsAsTheStatus(t *testing.T) {
	origin, _ := grpcEchoOrigin(t)
	p, host, client := grpcProxy(t, origin)
	origin.Close()

	p.MustAdd(host+"/pkg.Svc/Method", func(c *GRPCCtx) error {
		if ferr := c.Forward(); ferr != nil {
			return c.Fail(CodePermissionDenied, "origin down")
		}
		return nil
	})

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Method", grpcPayload("hello"))
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, "7", resp.Header.Get("Grpc-Status"))
	assert.Equal(t, "origin down", resp.Header.Get("Grpc-Message"))
}

func TestKindGRPC_ClientGoneMidResponseLeavesTheTrailersToTheHandler(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		blob := strings.Repeat("x", 4<<10)
		for range 16 {
			_, _ = w.Write(grpcPayload(blob))
			_ = rc.Flush()
		}
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	}))
	t.Cleanup(origin.Close)
	p, host, client := grpcProxy(t, origin)

	done, gone, drained := make(chan struct{}), make(chan struct{}), make(chan struct{})
	p.MustAdd(host+"/pkg.Svc/Get", func(c *GRPCCtx) error {
		defer close(done)
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		first, rerr := c.Outbound().ReadMessage()
		if rerr != nil {
			return rerr
		}
		if ferr := first.Forward(); ferr != nil {
			return ferr
		}
		_ = c.CloseSend()
		in := c.Inbound()
		for n := 0; ; n++ {
			m, merr := in.ReadMessage()
			if merr != nil {
				break
			}
			if n == 0 {
				if ferr := m.Forward(); ferr != nil {
					return ferr
				}
			}
		}
		close(drained)
		<-gone
		// The sends fail once the client is gone, which is what ends the copy early.
		tail := make([]byte, 32<<10)
		for range 100 {
			if serr := first.Reply(tail); serr != nil {
				break
			}
		}
		resp, rerr := c.Response()
		if rerr != nil {
			return rerr
		}
		for range 10000 {
			resp.Trailer.Set("X-Trail", "edited")
		}
		return nil
	})

	ctx, cancel := context.WithCancel(t.Context())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin.URL+"/pkg.Svc/Get",
		strings.NewReader(string(grpcPayload("hello"))))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := client.Do(req)
	require.NoError(t, err)
	_, err = io.ReadFull(resp.Body, make([]byte, 10))
	require.NoError(t, err)
	<-drained
	cancel()
	_ = resp.Body.Close()
	close(gone)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler stuck")
	}
}

func TestKindGRPC_FailAfterInboundEndedRewritesTheStatus(t *testing.T) {
	origin, _ := grpcEchoOrigin(t)
	p, host, client := grpcProxy(t, origin)

	var originStatus string
	p.MustAdd(host+"/pkg.Svc/Get", func(c *GRPCCtx) error {
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		src := MergeMessages(c.Outbound(), c.Inbound())
		for {
			m, rerr := src.ReadMessage()
			if errors.Is(rerr, io.EOF) {
				break
			}
			if rerr != nil {
				return rerr
			}
			if ferr := m.Forward(); ferr != nil {
				return ferr
			}
		}
		resp, rerr := c.Response()
		if rerr != nil {
			return rerr
		}
		originStatus = resp.Trailer.Get("Grpc-Status")
		return c.Fail(CodeNotFound, "hidden")
	})

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Get", grpcPayload("hello"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, grpcPayload("hello"), body)
	assert.Equal(t, "0", originStatus, "the handler read the status the origin sent")
	code, msg := grpcStatus(resp)
	assert.Equal(t, "5", code, "the client reads the status the handler set")
	assert.Equal(t, "hidden", msg)
}

func TestKindGRPC_ReturnWithInboundPendingEndsOnInternal(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	origin, _, canceled := grpcHoldingOrigin(t, release, true)
	p, host, client := grpcProxy(t, origin)

	p.MustAdd(host+"/pkg.Svc/Watch", func(c *GRPCCtx) error {
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		_ = c.CloseSend()
		m, rerr := c.Inbound().ReadMessage()
		if rerr != nil {
			return rerr
		}
		return m.Forward()
	})

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Watch", grpcPayload("hello"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, grpcPayload("one"), body)
	code, _ := grpcStatus(resp)
	assert.Equal(t, "13", code)
	assert.Eventually(t, func() bool { return canceled.Load() == 1 }, 3*time.Second, 10*time.Millisecond,
		"the origin was canceled")
}

// forwardFirst forwards the first request message and returns, and reports its return on
// returned.
func forwardFirst(returned chan<- struct{}) GRPC {
	return func(c *GRPCCtx) error {
		defer func() { returned <- struct{}{} }()
		if err := c.Open(); err != nil {
			return err
		}
		m, err := c.Outbound().ReadMessage()
		if err != nil {
			return err
		}
		return m.Forward()
	}
}

func TestKindGRPC_ReturnAfterTheOneMessageEndsOnTheOriginStatus(t *testing.T) {
	origin := httptest.NewUnstartedServer(grpcEchoHandler(nil))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	t.Cleanup(origin.Close)
	p, host, client := grpcProxy(t, origin)
	p.MustAdd(host+"/pkg.Svc/Unary", forwardFirst(make(chan struct{}, 1)))

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Unary", grpcPayload("hello"))
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)

	assert.Equal(t, grpcPayload("hello"), body)
	code, msg := grpcStatus(resp)
	assert.Equal(t, "0", code, msg)
}

func TestKindGRPC_RequestMessagesAfterTheReturnReachTheOrigin(t *testing.T) {
	returned := make(chan struct{}, 1)
	b := newGRPCBench(t, streamOrigin(t), forwardFirst(returned))
	c := b.client(t)
	id := c.call("/pkg.Svc/Method")
	c.data(id, false, lpm(0, "one"))
	<-returned
	var r grpcResult
	c.awaitData(id, &r, len(lpm(0, "one")))
	c.data(id, false, lpm(0, "two"))
	c.awaitData(id, &r, len(lpm(0, "one"))+len(lpm(0, "two")))
	c.data(id, true, nil)
	for !r.done() {
		c.step(id, &r)
	}

	call := b.origin.call(t)
	require.NoError(t, call.readErr)
	assert.Equal(t, append(lpm(0, "one"), lpm(0, "two")...), call.body)
	assert.False(t, r.reset)
	assert.Equal(t, "0", grpcStatusOf(r))
}

func TestKindGRPC_WrappedRequestBodyEndsWithTheCall(t *testing.T) {
	for _, shape := range []endShape{{forwardCall, "Forward"}, {openCall, "Open"}} {
		t.Run(shape.name, func(t *testing.T) {
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.ReadFull(r.Body, make([]byte, len(grpcPayload("one"))))
				w.Header().Set("Content-Type", "application/grpc")
				w.Header().Set("Trailer", "Grpc-Status")
				_, _ = w.Write(grpcPayload("ok"))
				w.Header().Set("Grpc-Status", "0")
			}))
			origin.EnableHTTP2 = true
			origin.StartTLS()
			t.Cleanup(origin.Close)
			p, host, client := grpcH2Proxy(t, origin)
			p.MustAdd(host+"/pkg.Svc/Method", func(c *GRPCCtx) error {
				req := c.Request().Clone(c.Context())
				req.Body = io.NopCloser(c.Request().Body)
				c.SetRequest(req)
				return shape.h(c)
			})

			// The client keeps its request stream open past its one message.
			pr, pw := io.Pipe()
			t.Cleanup(func() { _ = pw.Close() })
			go func() { _, _ = pw.Write(grpcPayload("one")) }()
			req, err := http.NewRequest(http.MethodPost, origin.URL+"/pkg.Svc/Method", pr)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/grpc")
			status := make(chan string, 1)
			go func() {
				resp, err := client.Do(req)
				if err != nil {
					status <- err.Error()
					return
				}
				_, _ = io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				code, _ := grpcStatus(resp)
				status <- code
			}()
			select {
			case got := <-status:
				assert.Equal(t, "0", got)
			case <-time.After(5 * time.Second):
				t.Fatal("the call waited for the end of the request stream of the client")
			}
		})
	}
}

func TestKindGRPC_RequestCutAfterTheReturnResetsTheOrigin(t *testing.T) {
	cuts := []struct {
		cut  func(c *grpcClient, id uint32)
		name string
	}{
		{func(c *grpcClient, id uint32) { c.data(id, true, lpm(0, "two")[:6]) }, "inside a message"},
		{func(c *grpcClient, id uint32) { require.NoError(t, c.fr.WriteRSTStream(id, http2.ErrCodeCancel)) }, "by a reset"},
	}
	for _, tc := range cuts {
		t.Run(tc.name, func(t *testing.T) {
			returned := make(chan struct{}, 1)
			b := newGRPCBench(t, streamOrigin(t), forwardFirst(returned))
			c := b.client(t)
			id := c.call("/pkg.Svc/Method")
			c.data(id, false, lpm(0, "one"))
			<-returned
			var r grpcResult
			c.awaitData(id, &r, len(lpm(0, "one")))
			tc.cut(c, id)
			assert.Error(t, b.origin.call(t).readErr, "the origin read a complete call the client cut short")
		})
	}
}

func TestKindGRPC_RequestMessageAfterTheReturnIsRefusedOrBounded(t *testing.T) {
	t.Run("refused by the tree", func(t *testing.T) {
		returned := make(chan struct{}, 1)
		b := newGRPCBench(t, streamOrigin(t), forwardFirst(returned))
		c := b.client(t)
		id := c.call("/pkg.Svc/Method")
		c.data(id, false, lpm(0, "one"))
		<-returned
		var r grpcResult
		c.awaitData(id, &r, len(lpm(0, "one")))
		_, err := b.p.Delete[GRPC](b.host + "/*{method}")
		require.NoError(t, err)
		c.data(id, true, lpm(0, "two"))
		for !r.done() {
			c.step(id, &r)
		}

		call := b.origin.call(t)
		assert.Equal(t, lpm(0, "one"), call.body)
		assert.Error(t, call.readErr)
		assert.Equal(t, "14", r.trailer("grpc-status"))
	})
	t.Run("over the bound", func(t *testing.T) {
		returned := make(chan struct{}, 1)
		b := newGRPCBench(t, streamOrigin(t), forwardFirst(returned), WithMaxMessageBytes(8))
		c := b.client(t)
		id := c.call("/pkg.Svc/Method")
		c.data(id, false, lpm(0, "one"))
		<-returned
		var r grpcResult
		c.awaitData(id, &r, len(lpm(0, "one")))
		c.data(id, true, lpm(0, "123456789"))
		for !r.done() {
			c.step(id, &r)
		}

		call := b.origin.call(t)
		assert.Equal(t, lpm(0, "one"), call.body)
		assert.Error(t, call.readErr)
		assert.Equal(t, "8", r.trailer("grpc-status"))
	})
}

func TestKindGRPC_OriginEndingFirstEndsTheCallAfterTheReturn(t *testing.T) {
	o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
		src := &msgSource{r: r.Body, max: defaultMaxMessageBytes}
		payload, flag, err := src.next()
		o.calls <- originCall{readErr: err}
		answerOK(w, appendGRPCFrame(nil, flag, payload))
	})
	returned := make(chan struct{}, 1)
	b := newGRPCBench(t, o, forwardFirst(returned))
	c := b.client(t)
	id := c.call("/pkg.Svc/Method")
	c.data(id, false, lpm(0, "one"))
	r := c.await(id)

	require.NoError(t, o.call(t).readErr)
	assert.Equal(t, lpm(0, "one"), r.data)
	assert.Equal(t, "0", grpcStatusOf(r))
}

func TestKindGRPC_ReturnFromAMergeWithAReadPendingEndsOnInternal(t *testing.T) {
	h := func(c *GRPCCtx) error {
		if err := c.Open(); err != nil {
			return err
		}
		src := MergeMessages(c.Outbound(), c.Inbound())
		for {
			m, err := src.ReadMessage()
			if err != nil {
				return err
			}
			if err := m.Forward(); err != nil {
				return err
			}
			if m.Inbound() {
				return nil
			}
		}
	}
	b := newGRPCBench(t, streamOrigin(t), h)
	c := b.client(t)
	id := c.call("/pkg.Svc/Method")
	c.data(id, false, lpm(0, "one"))
	r := c.await(id)

	assert.Equal(t, lpm(0, "one"), r.data)
	assert.Equal(t, "13", grpcStatusOf(r))
	assert.Error(t, b.origin.call(t).readErr, "the origin read a request stream the client never ended")
}

func TestKindGRPC_StatusOfTheProxyResetsTheRequestStream(t *testing.T) {
	ends := []struct {
		end  func(c *GRPCCtx) error
		name string
		code string
	}{
		{func(c *GRPCCtx) error { return c.Fail(CodeResourceExhausted, "quota") }, "Fail", "8"},
		{func(c *GRPCCtx) error { return errors.New("handler failed") }, "error", "2"},
	}
	for _, tc := range ends {
		t.Run(tc.name, func(t *testing.T) {
			b := newGRPCBench(t, streamOrigin(t), func(c *GRPCCtx) error {
				if err := c.Open(); err != nil {
					return err
				}
				m, err := c.Outbound().ReadMessage()
				if err != nil {
					return err
				}
				if err := m.Forward(); err != nil {
					return err
				}
				return tc.end(c)
			})
			c := b.client(t)
			id := c.call("/pkg.Svc/Method")
			c.data(id, false, lpm(0, "one"))
			r := c.await(id)

			assert.Equal(t, tc.code, grpcStatusOf(r))
			assert.Error(t, b.origin.call(t).readErr, "the origin read a request stream the client never ended")
		})
	}
}

func TestKindGRPC_ErrorAfterOpenReachesTheClient(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	origin, _, _ := grpcHoldingOrigin(t, release, true)
	p, host, client := grpcProxy(t, origin)

	p.MustAdd(host+"/pkg.Svc/Watch", func(c *GRPCCtx) error {
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		_ = c.CloseSend()
		m, rerr := c.Inbound().ReadMessage()
		if rerr != nil {
			return rerr
		}
		if ferr := m.Forward(); ferr != nil {
			return ferr
		}
		return errors.New("boom")
	})

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Watch", grpcPayload("hello"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, grpcPayload("one"), body)
	code, msg := grpcStatus(resp)
	assert.Equal(t, "2", code)
	assert.Equal(t, "Unknown", msg, "the reason stays in the log")
}

func TestKindGRPC_ForwardAfterAReadIsRefused(t *testing.T) {
	origin, received := grpcEchoOrigin(t)
	p, host, client := grpcProxy(t, origin)

	var forwardErr error
	p.MustAdd(host+"/pkg.Svc/Method", func(c *GRPCCtx) error {
		if _, rerr := c.Outbound().ReadMessage(); rerr != nil {
			return rerr
		}
		forwardErr = c.Forward()
		return forwardErr
	})

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Method", grpcPayload("first", "second"))
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	assert.EqualError(t, forwardErr, "edge: request stream already read")
	assert.Equal(t, int64(0), received.Load(), "the origin was never reached")
	assert.Equal(t, "2", resp.Header.Get("Grpc-Status"))
}

func TestKindGRPC_ResponseGivesTheOriginHeadersAndTrailers(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("X-Origin", "yes")
		w.Header().Set("Trailer", "Grpc-Status, X-Trail")
		_, _ = w.Write(body)
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(http.TrailerPrefix+"X-Trail", "sent")
	}))
	t.Cleanup(origin.Close)
	p, host, client := grpcProxy(t, origin)

	var (
		beforeOpen   error
		originHeader string
		originTrail  string
	)
	p.MustAdd(host+"/pkg.Svc/Get", func(c *GRPCCtx) error {
		_ = c.Outbound()
		_, beforeOpen = c.Response()
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		src := MergeMessages(c.Outbound(), c.Inbound())
		for {
			m, rerr := src.ReadMessage()
			if errors.Is(rerr, io.EOF) {
				break
			}
			if rerr != nil {
				return rerr
			}
			if ferr := m.Forward(); ferr != nil {
				return ferr
			}
		}
		resp, rerr := c.Response()
		if rerr != nil {
			return rerr
		}
		originHeader = resp.Header.Get("X-Origin")
		originTrail = resp.Trailer.Get("X-Trail")
		resp.Trailer.Set("X-Trail", "edited")
		return nil
	})

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Get", grpcPayload("hello"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.ErrorIs(t, beforeOpen, errNotOpened)
	assert.Equal(t, "yes", originHeader)
	assert.Equal(t, "sent", originTrail)
	assert.Equal(t, grpcPayload("hello"), body)
	assert.Equal(t, "yes", resp.Header.Get("X-Origin"))
	assert.Equal(t, "0", resp.Trailer.Get("Grpc-Status"))
	assert.Equal(t, "edited", resp.Trailer.Get("X-Trail"), "the trailer as the handler left it")
}

func TestKindGRPC_SendSaysTheCompressedFlag(t *testing.T) {
	origin, received := grpcEchoOrigin(t)
	p, host, client := grpcProxy(t, origin)

	p.MustAdd(host+"/pkg.Svc/Stream", func(c *GRPCCtx) error {
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		src := MergeMessages(c.Outbound(), c.Inbound())
		for {
			m, rerr := src.ReadMessage()
			if rerr != nil {
				return nil
			}
			var serr error
			switch {
			case string(m.Bytes()) == "zip" && !m.Inbound(), string(m.Bytes()) == "raw" && m.Inbound():
				serr = m.Send(m.Bytes())
			case string(m.Bytes()) == "raw" && !m.Inbound(), string(m.Bytes()) == "zip" && m.Inbound():
				serr = m.SendCompressed(m.Bytes())
			default:
				serr = m.Forward()
			}
			if serr != nil {
				return serr
			}
		}
	})

	var payload []byte
	payload = appendGRPCMessage(payload, true, []byte("zip"))
	payload = appendGRPCMessage(payload, false, []byte("raw"))
	payload = appendGRPCMessage(payload, true, []byte("kept"))
	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Stream", payload)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	// The origin echoes what the handler sent, and the handler flips each flag again on the
	// way back.
	var want []byte
	want = appendGRPCMessage(want, true, []byte("zip"))
	want = appendGRPCMessage(want, false, []byte("raw"))
	want = appendGRPCMessage(want, true, []byte("kept"))
	assert.Equal(t, want, body)
	assert.Equal(t, int64(3), received.Load())
	assert.Equal(t, "0", resp.Trailer.Get("Grpc-Status"))
}

func TestKindGRPC_MessageOverTheBoundEndsOnResourceExhausted(t *testing.T) {
	origin, received := grpcEchoOrigin(t)
	p, host, client := grpcProxy(t, origin, WithMaxMessageBytes(8))

	var sendErr error
	p.MustAdd(host+"/pkg.Svc/Method", func(c *GRPCCtx) error {
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		m, rerr := c.Outbound().ReadMessage()
		if rerr != nil {
			return rerr
		}
		sendErr = m.Send(make([]byte, 9))
		return m.Forward()
	})

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Method", grpcPayload("123456789"))
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	code, _ := grpcStatus(resp)
	assert.Equal(t, "8", code, "a request message over the bound")
	assert.Equal(t, int64(0), received.Load())

	resp = grpcDo(t, client, origin.URL+"/pkg.Svc/Method", grpcPayload("abc"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.ErrorIs(t, sendErr, errMessageTooLarge, "a message the handler sends over the bound")
	assert.Equal(t, grpcPayload("abc"), body)
	assert.Equal(t, "0", resp.Trailer.Get("Grpc-Status"))
}

func TestKindGRPC_MessageAcrossDataFrames(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		full := grpcPayload("abcdefghij", "k")
		for _, cut := range [][]byte{full[:3], full[3:8], full[8:15], full[15:]} {
			_, _ = w.Write(cut)
			_ = rc.Flush()
			time.Sleep(5 * time.Millisecond)
		}
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	t.Cleanup(origin.Close)
	p, host, client := grpcH2Proxy(t, origin)

	var seen []string
	var proto string
	p.MustAdd(host+"/pkg.Svc/Stream", func(c *GRPCCtx) error {
		proto = c.Request().Proto
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		_ = c.CloseSend()
		in := c.Inbound()
		for {
			m, rerr := in.ReadMessage()
			if rerr != nil {
				return nil
			}
			seen = append(seen, string(m.Bytes()))
			if ferr := m.Forward(); ferr != nil {
				return ferr
			}
		}
	})

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Stream", nil)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, "HTTP/2.0", proto)
	assert.Equal(t, "HTTP/2.0", resp.Proto)
	assert.Equal(t, []string{"abcdefghij", "k"}, seen)
	assert.Equal(t, grpcPayload("abcdefghij", "k"), body)
	assert.Equal(t, "0", resp.Trailer.Get("Grpc-Status"))
}

func TestMsgSource_ReadsAcrossShortReads(t *testing.T) {
	payload := grpcPayload("hello", "", "world!")
	src := &msgSource{r: iotest.OneByteReader(strings.NewReader(string(payload))), max: defaultMaxMessageBytes}
	var got []string
	for {
		b, _, err := src.next()
		if err != nil {
			require.ErrorIs(t, err, io.EOF)
			break
		}
		got = append(got, string(b))
	}
	assert.Equal(t, []string{"hello", "", "world!"}, got)
}

func TestParseGRPCTimeout(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"1S", time.Second, true},
		{"100m", 100 * time.Millisecond, true},
		{"5u", 5 * time.Microsecond, true},
		{"7n", 7 * time.Nanosecond, true},
		{"2M", 2 * time.Minute, true},
		{"1H", time.Hour, true},
		{"0S", 0, true},
		{"99999999H", time.Duration(math.MaxInt64), true},
		{"", 0, false},
		{"S", 0, false},
		{"1X", 0, false},
		{"1.5S", 0, false},
		{"-1S", 0, false},
		{"123456789S", 0, false},
	}
	for _, tc := range cases {
		got, ok := parseGRPCTimeout(tc.in)
		assert.Equal(t, tc.ok, ok, tc.in)
		assert.Equal(t, tc.want, got, tc.in)
	}
}

func TestDecodeBinaryMetadata(t *testing.T) {
	got, err := DecodeBinaryMetadata("aGk=")
	require.NoError(t, err)
	assert.Equal(t, []byte("hi"), got, "padded")

	got, err = DecodeBinaryMetadata("aGk")
	require.NoError(t, err)
	assert.Equal(t, []byte("hi"), got, "unpadded")

	_, err = DecodeBinaryMetadata("!!!")
	assert.Error(t, err)
}

func TestKindGRPC_CallInTheClearIsForwardedOverHTTP2(t *testing.T) {
	seen := new(recorder)
	origin := h2cOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.add(fmt.Sprintf("%s tls=%t", r.Proto, r.TLS != nil))
		src := &msgSource{r: r.Body, max: defaultMaxMessageBytes}
		payload, _, err := src.next()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(appendGRPCMessage(nil, false, payload))
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	}))
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	host := originHost(originURL)

	p := testProxy(t)
	p.MustAdd(host+"/pkg.Svc/Method", func(c *GRPCCtx) error { return c.Forward() })
	client := h2cTunnelClient(t, startProxy(t, p), originURL.Host)

	resp := grpcDo(t, client, origin.URL+"/pkg.Svc/Method", grpcPayload("hello"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "HTTP/2.0", resp.Proto)
	assert.Equal(t, grpcPayload("hello"), body)
	assert.Equal(t, "0", resp.Trailer.Get("Grpc-Status"))
	assert.Equal(t, []string{"HTTP/2.0 tls=false"}, seen.all())
}

func TestKindGRPC_CallToAPlaintextOriginIsForwardedOverHTTP2(t *testing.T) {
	seen := new(recorder)
	origin := h2cOnlyOrigin(t, grpcEchoHandler(seen))
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca)
	p.MustAdd(originHost(originURL)+"/pkg.Svc/Method", func(c *GRPCCtx) error { return c.Forward() })
	plain := startProxy(t, p)
	secure, trust := startProxyTLS(t, p, ca)

	fronts := []struct {
		client *http.Client
		name   string
	}{
		{name: "h2c", client: h2cFrontClient(plain)},
		{name: "h2", client: &http.Client{Timeout: 10 * time.Second, Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				d := tls.Dialer{Config: &tls.Config{RootCAs: trust, ServerName: "127.0.0.1", NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12}}
				return d.DialContext(ctx, "tcp", secure)
			},
		}}},
	}
	for _, f := range fronts {
		t.Run(f.name, func(t *testing.T) {
			before := len(seen.all())
			resp := grpcDo(t, f.client, origin.URL+"/pkg.Svc/Method", grpcPayload("hello"))
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			_ = resp.Body.Close()

			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, grpcPayload("hello"), body)
			assert.Equal(t, "0", resp.Trailer.Get("Grpc-Status"))
			assert.Equal(t, []string{"HTTP/2.0"}, seen.all()[before:])
		})
	}
}

func TestKindGRPC_CallToAPlaintextHTTP11OriginFails(t *testing.T) {
	origin := httptest.NewUnstartedServer(grpcEchoHandler(nil))
	origin.Config.Protocols = new(http.Protocols)
	origin.Config.Protocols.SetHTTP1(true)
	origin.Start()
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	p := testProxy(t)
	p.MustAdd(originHost(originURL)+"/pkg.Svc/Method", func(c *GRPCCtx) error { return c.Forward() })

	resp := grpcDo(t, h2cFrontClient(startProxy(t, p)), origin.URL+"/pkg.Svc/Method", grpcPayload("hello"))
	_, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	code, _ := grpcStatus(resp)
	assert.Equal(t, "14", code)
}

func TestKindGRPC_HTTP11CallToTheProxyIsForwardedOverHTTP11(t *testing.T) {
	seen := new(recorder)
	origin := h2cOrigin(t, grpcEchoHandler(seen))
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	p := testProxy(t)
	p.MustAdd(originHost(originURL)+"/pkg.Svc/Method", func(c *GRPCCtx) error { return c.Forward() })

	resp := grpcDo(t, proxyClient(startProxy(t, p), nil), origin.URL+"/pkg.Svc/Method", grpcPayload("hello"))
	_, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []string{"HTTP/1.1"}, seen.all())
}

func TestKindGRPC_HTTP3CallToTheProxyIsForwarded(t *testing.T) {
	cases := []struct {
		name       string
		allowHTTP3 bool
		want       string
	}{
		{name: "h2 origin", want: "HTTP/2.0"},
		{name: "h3 origin with AllowHTTP3", allowHTTP3: true, want: "HTTP/3.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			cert := selfSignedFor(t, ca, "origin.test")
			seen := new(recorder)

			var addr string
			if tc.allowHTTP3 {
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				require.NoError(t, err)
				srv := &http3.Server{
					Handler:   grpcEchoHandler(seen),
					TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}),
				}
				go func() { _ = srv.Serve(pc) }()
				t.Cleanup(func() {
					_ = srv.Close()
					_ = pc.Close()
				})
				addr = pc.LocalAddr().String()
			} else {
				origin := httptest.NewUnstartedServer(grpcEchoHandler(seen))
				origin.EnableHTTP2 = true
				origin.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
				origin.StartTLS()
				t.Cleanup(origin.Close)
				addr = origin.Listener.Addr().String()
			}

			tr := DefaultTransport()
			tr.AllowHTTP3 = tc.allowHTTP3
			tr.DialContext = pinnedDialer(addr)
			tr.RootCAs = poolOf(ca)
			p := testProxyWithCA(t, ca, WithTransport(tr))
			p.MustAdd("origin.test/pkg.Svc/Method", forwardCall)
			front, _ := startQUICFront(t, p, ca)
			h3 := &http3.Transport{
				Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
					return dialQUICFront(t, front, ca), nil
				},
			}
			t.Cleanup(func() { _ = h3.Close() })

			client := &http.Client{Timeout: 10 * time.Second, Transport: h3}
			resp := grpcDo(t, client, "https://origin.test/pkg.Svc/Method", grpcPayload("hello"))
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			_ = resp.Body.Close()

			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "HTTP/3.0", resp.Proto)
			assert.Equal(t, grpcPayload("hello"), body)
			assert.Equal(t, "0", resp.Trailer.Get("Grpc-Status"))
			assert.Equal(t, []string{tc.want}, seen.all())
		})
	}
}

func TestKindGRPC_CallOnTheHTTP3FrontIsForwarded(t *testing.T) {
	cases := []struct {
		run  func(t *testing.T)
		name string
	}{
		{name: "server streaming forwards each message as written", run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				release := make(chan struct{})
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					w.Header().Set("Content-Type", "application/grpc")
					w.WriteHeader(http.StatusOK)
					rc := http.NewResponseController(w)
					_, _ = w.Write(lpm(0, "one"))
					_ = rc.Flush()
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
					_, _ = w.Write(lpm(0, "two"))
					w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
				})
				b := newGRPCBench(t, o, h)
				c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Watch")
				c.send(lpm(0, "x"))
				require.NoError(t, c.str.Close())
				assert.Equal(t, lpm(0, "one"), c.read(len(lpm(0, "one"))))
				close(release)
				body, err := c.rest()
				require.NoError(t, err)
				assert.Equal(t, lpm(0, "two"), body)
				code, _ := c.status()
				assert.Equal(t, "0", code)
			})
		}},
		{name: "client streaming forwards each message as written", run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				got := make(chan []byte, 3)
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					for range 3 {
						m := make([]byte, len(lpm(0, "m0")))
						if _, err := io.ReadFull(r.Body, m); err != nil {
							return
						}
						got <- m
					}
					_, _ = io.Copy(io.Discard, r.Body)
					answerOK(w, lpm(0, "done"))
				})
				b := newGRPCBench(t, o, h)
				c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Upload")
				for i := range 3 {
					c.send(lpm(0, fmt.Sprintf("m%d", i)))
					select {
					case m := <-got:
						assert.Equal(t, lpm(0, fmt.Sprintf("m%d", i)), m)
					case <-time.After(5 * time.Second):
						t.Fatalf("message %d did not reach the origin", i)
					}
				}
				require.NoError(t, c.str.Close())
				body, err := c.rest()
				require.NoError(t, err)
				assert.Equal(t, lpm(0, "done"), body)
				code, _ := c.status()
				assert.Equal(t, "0", code)
			})
		}},
		{name: "bidirectional streaming, each message sent once the previous one came back", run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, streamOrigin(t), h)
				c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Chat")
				for _, n := range []int{27182, 8, 1828, 45904} {
					msg := lpm(0, strings.Repeat("p", n))
					c.send(msg)
					assert.Equal(t, msg, c.read(len(msg)))
				}
				require.NoError(t, c.str.Close())
				body, err := c.rest()
				require.NoError(t, err)
				assert.Empty(t, body)
				code, _ := c.status()
				assert.Equal(t, "0", code)
			})
		}},
		{name: "Fail before Open answers trailers-only", run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(c *GRPCCtx) error { return c.Fail(CodeUnknown, specialStatusMessage) })
			c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Method")
			_, _ = c.str.Write(lpm(0, "x"))
			_ = c.str.Close()
			resp := c.response()
			body, err := c.rest()
			require.NoError(t, err)
			assert.Empty(t, body)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "application/grpc", resp.Header.Get("Content-Type"))
			assert.Equal(t, "2", resp.Header.Get("Grpc-Status"))
			assert.Equal(t, "%09%0Atest with whitespace%0D%0Aand Unicode BMP %E2%98%BA and non-BMP %F0%9F%98%88%09%0A", resp.Header.Get("Grpc-Message"))
			assert.Empty(t, resp.Trailer)
			b.origin.noCall(t)
		}},
		{name: "Fail after Open ends the call on its status in the trailers", run: func(t *testing.T) {
			release := make(chan struct{})
			b := newGRPCBench(t, streamOrigin(t), func(c *GRPCCtx) error {
				if err := c.Open(); err != nil {
					return err
				}
				m, err := c.Outbound().ReadMessage()
				if err != nil {
					return err
				}
				if err := m.Forward(); err != nil {
					return err
				}
				m, err = c.Inbound().ReadMessage()
				if err != nil {
					return err
				}
				if err := m.Forward(); err != nil {
					return err
				}
				ferr := c.Fail(CodeResourceExhausted, "quota")
				select {
				case <-release:
				case <-time.After(5 * time.Second):
				}
				return ferr
			})
			c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Chat")
			c.send(lpm(0, "one"))
			assert.Equal(t, lpm(0, "one"), c.read(len(lpm(0, "one"))))
			assert.Error(t, b.origin.call(t).readErr, "Fail did not cancel the origin")
			close(release)
			body, err := c.rest()
			require.NoError(t, err)
			assert.Empty(t, body)
			code, msg := c.status()
			assert.Equal(t, "8", code)
			assert.Equal(t, "quota", msg)
			assert.Empty(t, c.response().Header.Get("Grpc-Status"))
		}},
		{name: "the client cancels the call", run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, streamOrigin(t), h)
				c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Chat")
				c.send(lpm(0, "one"))
				c.read(len(lpm(0, "one")))
				c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
				c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
				assert.Error(t, b.origin.call(t).readErr, "the origin read a request stream the client never ended")
			})
		}},
		{name: "the client resets its request stream and keeps reading", run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, streamOrigin(t), h)
				c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Chat")
				c.send(lpm(0, "one"))
				c.read(len(lpm(0, "one")))
				c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
				assert.Error(t, b.origin.call(t).readErr, "the origin read a request stream the client never ended")
				body, err := c.rest()
				require.NoError(t, err)
				assert.Empty(t, body)
				code, msg := c.status()
				assert.Equal(t, "1", code)
				assert.Equal(t, "Canceled", msg)
			})
		}},
		{name: "the client resets its request stream before the origin answers", run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				reached := make(chan struct{})
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					close(reached)
					o.record(r)
				})
				b := newGRPCBench(t, o, h)
				c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Chat")
				c.send(lpm(0, "one"))
				select {
				case <-reached:
				case <-time.After(5 * time.Second):
					t.Fatal("the origin received no call")
				}
				c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
				assert.Error(t, b.origin.call(t).readErr, "the origin read a request stream the client never ended")
				body, err := c.rest()
				require.NoError(t, err)
				assert.Empty(t, body)
				code, msg := c.status()
				assert.Equal(t, "1", code)
				assert.Equal(t, "Canceled", msg)
			})
		}},
		{name: "a complete answer to a request still open stops the client with H3_NO_ERROR", run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, trailersOnlyOrigin(t, "12"), h)
				c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Chat")
				c.send(lpm(0, "one"))
				body, err := c.rest()
				require.NoError(t, err)
				assert.Empty(t, body)
				assert.Equal(t, "12", c.response().Header.Get("Grpc-Status"))
				assert.Empty(t, c.response().Trailer)
				assert.Equal(t, http3.ErrCodeNoError, stopSending(t, c.str, lpm(0, "two")))
			})
		}},
		{name: "a handler reading the request stream alone returns once the origin answered", run: func(t *testing.T) {
			b := newGRPCBench(t, trailersOnlyOrigin(t, "12"), func(c *GRPCCtx) error {
				if err := c.Open(); err != nil {
					return err
				}
				for {
					m, err := c.Outbound().ReadMessage()
					if errors.Is(err, io.EOF) {
						return nil
					}
					if err != nil {
						return err
					}
					if err := m.Forward(); err != nil {
						return err
					}
				}
			})
			c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Chat")
			c.send(lpm(0, "one"))
			body, err := c.rest()
			require.NoError(t, err)
			assert.Empty(t, body)
			assert.Equal(t, "12", c.response().Header.Get("Grpc-Status"))
			assert.Empty(t, c.response().Trailer)
		}},
		{name: "a handler reading the request stream alone returns once the origin stopped reading it", run: func(t *testing.T) {
			returned := make(chan error, 1)
			o := newGRPCOrigin(t, func(_ *grpcOrigin, w http.ResponseWriter, _ *http.Request) {
				answerOK(w, lpm(0, "r"))
			})
			b := newGRPCBench(t, o, outboundOnly(returned))
			c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Chat")
			c.send(lpm(0, "one"))
			select {
			case err := <-returned:
				require.Error(t, err)
				assert.NotErrorIs(t, err, io.EOF)
			case <-time.After(5 * time.Second):
				t.Fatal("the handler did not return")
			}
			body, err := c.rest()
			require.NoError(t, err)
			assert.Equal(t, lpm(0, "r"), body)
			code, _ := c.status()
			assert.Equal(t, "0", code)
		}},
		{name: "a handler reading the request stream alone relays a reset of the origin", run: func(t *testing.T) {
			returned := make(chan error, 1)
			o := newGRPCOrigin(t, func(_ *grpcOrigin, w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/grpc")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(lpm(0, "r"))
				_ = http.NewResponseController(w).Flush()
				panic(http.ErrAbortHandler)
			})
			b := newGRPCBench(t, o, outboundOnly(returned))
			c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Chat")
			c.send(lpm(0, "one"))
			select {
			case err := <-returned:
				require.Error(t, err)
				assert.NotErrorIs(t, err, io.EOF)
			case <-time.After(5 * time.Second):
				t.Fatal("the handler did not return")
			}
			_, err := c.str.ReadResponse()
			if err == nil {
				_, err = io.ReadAll(c.str)
			}
			code, ok := h3ResetCode(err)
			require.True(t, ok, "the response ended with %v", err)
			assert.Equal(t, http3.ErrCodeRequestCanceled, code)
		}},
		{name: "a message forwarded after the origin answered is dropped", run: func(t *testing.T) {
			b := newGRPCBench(t, trailersOnlyOrigin(t, "12"), func(c *GRPCCtx) error {
				m, err := c.Outbound().ReadMessage()
				if err != nil {
					return err
				}
				if err := c.Open(); err != nil {
					return err
				}
				if _, err := c.Inbound().ReadMessage(); !errors.Is(err, io.EOF) {
					return fmt.Errorf("inbound: %w", err)
				}
				return m.Forward()
			})
			c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Method")
			c.send(lpm(0, "x"))
			require.NoError(t, c.str.Close())
			body, err := c.rest()
			require.NoError(t, err)
			assert.Empty(t, body)
			assert.Equal(t, "12", c.response().Header.Get("Grpc-Status"))
			assert.Empty(t, c.response().Trailer)
		}},
		{name: "a message forwarded once the origin stopped reading fails", run: func(t *testing.T) {
			ended := make(chan struct{})
			o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
				defer close(ended)
				m := make([]byte, len(lpm(0, "m1")))
				if _, err := io.ReadFull(r.Body, m); err != nil {
					return
				}
				answerOK(w, lpm(0, "r"))
			})
			forwarded := make(chan error, 1)
			b := newGRPCBench(t, o, func(c *GRPCCtx) error {
				failed := func(err error) error {
					forwarded <- fmt.Errorf("the handler ended before the second message: %w", err)
					return err
				}
				if err := c.Open(); err != nil {
					return failed(err)
				}
				m, err := c.Outbound().ReadMessage()
				if err != nil {
					return failed(err)
				}
				if err := m.Forward(); err != nil {
					return failed(err)
				}
				r, err := c.Inbound().ReadMessage()
				if err != nil {
					return failed(err)
				}
				if err := r.Forward(); err != nil {
					return failed(err)
				}
				<-ended
				// The transport receives the end of the stream after the origin handler returns.
				time.Sleep(100 * time.Millisecond)
				if m, err = c.Outbound().ReadMessage(); err != nil {
					return failed(err)
				}
				forwarded <- m.Forward()
				if _, err := c.Inbound().ReadMessage(); !errors.Is(err, io.EOF) {
					return fmt.Errorf("inbound: %w", err)
				}
				return nil
			})
			c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Chat")
			c.send(lpm(0, "m1"))
			assert.Equal(t, lpm(0, "r"), c.read(len(lpm(0, "r"))))
			c.send(lpm(0, "m2"))
			body, err := c.rest()
			require.NoError(t, err)
			assert.Empty(t, body)
			assert.ErrorIs(t, <-forwarded, errOriginStopped)
			code, msg := c.status()
			assert.Equal(t, "0", code, msg)
		}},
		{name: "a send toward an origin that reset the call fails", run: func(t *testing.T) {
			type result struct{ inbound, send, outbound error }
			results := make(chan result, 1)
			o := newGRPCOrigin(t, func(_ *grpcOrigin, w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/grpc")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(lpm(0, "one"))
				_ = http.NewResponseController(w).Flush()
				panic(http.ErrAbortHandler)
			})
			b := newGRPCBench(t, o, func(c *GRPCCtx) error {
				if err := c.Open(); err != nil {
					return err
				}
				m, err := c.Outbound().ReadMessage()
				if err != nil {
					return err
				}
				if err := m.Forward(); err != nil {
					return err
				}
				var res result
				for {
					in, err := c.Inbound().ReadMessage()
					if err != nil {
						res.inbound = err
						break
					}
					_ = in.Forward()
				}
				// The transport closes the request stream from a goroutine of its own.
				time.Sleep(50 * time.Millisecond)
				res.send = m.Send([]byte("again"))
				_, res.outbound = c.Outbound().ReadMessage()
				results <- res
				return res.inbound
			})
			c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Chat")
			c.send(lpm(0, "x"))
			c.send(lpm(0, "y"))
			select {
			case res := <-results:
				assert.Error(t, res.inbound)
				assert.Error(t, res.send)
				assert.NotErrorIs(t, res.outbound, io.EOF)
			case <-time.After(5 * time.Second):
				t.Fatal("the handler did not return")
			}
			_, err := c.str.ReadResponse()
			if err == nil {
				_, err = io.ReadAll(c.str)
			}
			code, ok := h3ResetCode(err)
			require.True(t, ok, "the response ended with %v", err)
			assert.Equal(t, http3.ErrCodeRequestCanceled, code)
		}},
		{name: "Fail after a trailers-only answer ends the call on its status alone", run: func(t *testing.T) {
			b := newGRPCBench(t, trailersOnlyOrigin(t, "12"), func(c *GRPCCtx) error {
				if err := c.Open(); err != nil {
					return err
				}
				if _, err := c.Inbound().ReadMessage(); !errors.Is(err, io.EOF) {
					return fmt.Errorf("inbound: %w", err)
				}
				return c.Fail(CodeAborted, "aborted")
			})
			c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Method")
			c.send(lpm(0, "x"))
			require.NoError(t, c.str.Close())
			body, err := c.rest()
			require.NoError(t, err)
			assert.Empty(t, body)
			resp := c.response()
			assert.Equal(t, "10", resp.Header.Get("Grpc-Status"))
			assert.Equal(t, "aborted", resp.Header.Get("Grpc-Message"))
			assert.Empty(t, resp.Trailer)
		}},
		{name: "a message sent after a trailers-only answer moves its status to the trailers", run: func(t *testing.T) {
			b := newGRPCBench(t, trailersOnlyOrigin(t, "12"), func(c *GRPCCtx) error {
				m, err := c.Outbound().ReadMessage()
				if err != nil {
					return err
				}
				if err := c.Open(); err != nil {
					return err
				}
				if _, err := c.Inbound().ReadMessage(); !errors.Is(err, io.EOF) {
					return fmt.Errorf("inbound: %w", err)
				}
				return m.Reply([]byte("r"))
			})
			c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Method")
			c.send(lpm(0, "x"))
			require.NoError(t, c.str.Close())
			body, err := c.rest()
			require.NoError(t, err)
			assert.Equal(t, lpm(0, "r"), body)
			resp := c.response()
			assert.Empty(t, resp.Header.Get("Grpc-Status"))
			assert.Equal(t, "application/grpc", resp.Header.Get("Content-Type"))
			assert.NotEmpty(t, resp.Header.Get("Date"))
			assert.Equal(t, "12", resp.Trailer.Get("Grpc-Status"))
			assert.Empty(t, resp.Trailer.Get("Date"))
		}},
		{name: "the origin resets the stream after one message", run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					w.Header().Set("Content-Type", "application/grpc")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(lpm(0, "one"))
					_ = http.NewResponseController(w).Flush()
					panic(http.ErrAbortHandler)
				})
				b := newGRPCBench(t, o, h)
				c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Watch")
				c.send(lpm(0, "x"))
				require.NoError(t, c.str.Close())
				_, err := c.str.ReadResponse()
				if err == nil {
					_, err = io.ReadAll(c.str)
				}
				var h3err *http3.Error
				require.ErrorAs(t, err, &h3err)
				assert.True(t, h3err.Remote)
				assert.Equal(t, http3.ErrCodeRequestCanceled, h3err.ErrorCode)
			})
		}},
		{name: "a message over the bound ends on RESOURCE_EXHAUSTED", run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(c *GRPCCtx) error {
				if err := c.Open(); err != nil {
					return err
				}
				_, err := c.Outbound().ReadMessage()
				return err
			}, WithMaxMessageBytes(8))
			c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Method")
			_, _ = c.str.Write(lpm(0, "123456789"))
			_ = c.str.Close()
			body, err := c.rest()
			require.NoError(t, err)
			assert.Empty(t, body)
			code, _ := c.status()
			assert.Equal(t, "8", code)
		}},
		{name: "the entry deleted mid-call refuses the next message", run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, streamOrigin(t), h)
				c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Chat")
				c.send(lpm(0, "one"))
				assert.Equal(t, lpm(0, "one"), c.read(len(lpm(0, "one"))))
				_, err := b.p.Delete[GRPC](b.host + "/*{method}")
				require.NoError(t, err)
				_, _ = c.str.Write(lpm(0, "two"))
				_ = c.str.Close()
				body, err := c.rest()
				require.NoError(t, err)
				assert.Empty(t, body)
				code, msg := c.status()
				assert.Equal(t, "14", code)
				assert.Equal(t, "Unavailable", msg)
			})
		}},
		{name: "the entry deleted mid-call stops a client still sending with H3_NO_ERROR", run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, streamOrigin(t), h)
				c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Chat")
				c.send(lpm(0, "one"))
				assert.Equal(t, lpm(0, "one"), c.read(len(lpm(0, "one"))))
				_, err := b.p.Delete[GRPC](b.host + "/*{method}")
				require.NoError(t, err)
				c.send(lpm(0, "two"))
				body, err := c.rest()
				require.NoError(t, err)
				assert.Empty(t, body)
				code, _ := c.status()
				assert.Equal(t, "14", code)
				assert.Equal(t, http3.ErrCodeNoError, stopSending(t, c.str, lpm(0, "three")))
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

func TestKindGRPC_CompleteAnswerToARequestStillOpenOverHTTP2(t *testing.T) {
	eachMode(t, func(t *testing.T, h GRPC) {
		b := newGRPCBench(t, trailersOnlyOrigin(t, "12"), h)
		c := b.client(t)
		id := c.call("/pkg.Svc/Chat")
		c.data(id, false, lpm(0, "one"))
		r := c.await(id)
		require.True(t, r.ended, "the stream was reset with %v", r.rst)
		assert.True(t, r.endOnBlock)
		assert.Equal(t, "12", grpcStatusOf(r))
		for !r.reset {
			c.step(id, &r)
		}
		assert.Equal(t, http2.ErrCodeNo, r.rst)
	})
}

func TestKindGRPC_HandlerReadingTheRequestStreamAloneOverHTTP2(t *testing.T) {
	returned := make(chan error, 1)
	o := newGRPCOrigin(t, func(_ *grpcOrigin, w http.ResponseWriter, _ *http.Request) {
		answerOK(w, lpm(0, "r"))
	})
	b := newGRPCBench(t, o, outboundOnly(returned))
	c := b.client(t)
	id := c.call("/pkg.Svc/Chat")
	c.data(id, false, lpm(0, "one"))
	select {
	case err := <-returned:
		require.Error(t, err)
		assert.NotErrorIs(t, err, io.EOF)
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not return")
	}
	r := c.await(id)
	require.True(t, r.ended, "the stream was reset with %v", r.rst)
	assert.Equal(t, lpm(0, "r"), r.data)
	assert.Equal(t, "0", grpcStatusOf(r))
}

func TestKindGRPC_RequestStreamResetReachesAnHTTP3Origin(t *testing.T) {
	cases := []struct {
		h      GRPC
		name   string
		answer bool
		want   string
	}{
		{h: forwardCall, name: "Forward ends on the answer of the origin", answer: true, want: "10"},
		{h: openCall, name: "Open ends on CANCELLED without waiting for the origin", want: "1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reset := make(chan error, 1)
			b := newH3OriginGRPCBench(t, tc.h, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/grpc")
				w.WriteHeader(http.StatusOK)
				rc := http.NewResponseController(w)
				_ = rc.Flush()
				buf := make([]byte, 64<<10)
				for {
					n, err := r.Body.Read(buf)
					if n > 0 {
						_, _ = w.Write(buf[:n])
						_ = rc.Flush()
					}
					if err != nil {
						reset <- err
						if tc.answer {
							w.Header().Set(http.TrailerPrefix+"Grpc-Status", "10")
							return
						}
						<-r.Context().Done()
						return
					}
				}
			})
			c := b.h3Call(t, b.h3Client(t), "/pkg.Svc/Chat")
			c.send(lpm(0, "one"))
			assert.Equal(t, lpm(0, "one"), c.read(len(lpm(0, "one"))))
			c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			select {
			case err := <-reset:
				code, ok := h3ResetCode(err)
				require.True(t, ok, "the origin read %v", err)
				assert.Equal(t, http3.ErrCodeRequestCanceled, code)
			case <-time.After(5 * time.Second):
				t.Fatal("the origin read no reset")
			}
			body, err := c.rest()
			require.NoError(t, err)
			assert.Empty(t, body)
			code, _ := c.status()
			assert.Equal(t, tc.want, code)
		})
	}
}

func TestKindGRPC_StatusOfAllocs(t *testing.T) {
	err := errors.New("handler failed")
	allocs := testing.AllocsPerRun(100, func() { _ = statusOf(err) })
	assert.Zero(t, allocs)
}

func TestKindGRPC_GateReadToItsEndAllocs(t *testing.T) {
	msg := lpm(0, "hello")
	rd := new(bytes.Reader)
	body := io.NopCloser(rd)
	admit := func() bool { return true }
	end := new(callEnd)
	g := new(messageGate)
	buf := make([]byte, 64)
	allocs := testing.AllocsPerRun(100, func() {
		rd.Reset(msg)
		*g = messageGate{r: body, admit: admit, end: end}
		for {
			if _, err := g.Read(buf); err != nil {
				break
			}
		}
	})
	assert.Zero(t, allocs)
}

func TestKindGRPC_HTTP3CallInterceptedOnUDPIsForwarded(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	seen := new(recorder)
	origin := httptest.NewUnstartedServer(grpcEchoHandler(seen))
	origin.EnableHTTP2 = true
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedFor(t, ca, "origin.test")}}
	origin.StartTLS()
	t.Cleanup(origin.Close)

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(origin.Listener.Addr().String())
	tr.RootCAs = poolOf(ca)
	resolver := &fakeResolver{addrs: map[string][]netip.Addr{"origin.test": {netip.MustParseAddr("127.0.0.1")}}}
	destination := netip.MustParseAddrPort("127.0.0.1:443")

	fronts := []struct {
		dial func(t *testing.T, p *Proxy) http.RoundTripper
		name string
	}{
		{name: "transparent", dial: func(t *testing.T, p *Proxy) http.RoundTripper {
			h3 := dialQUICTo(startQUICRedirected(t, p, destination), poolOf(ca))
			t.Cleanup(func() { _ = h3.Close() })
			return h3
		}},
		{name: "CONNECT-UDP", dial: func(t *testing.T, p *Proxy) http.RoundTripper {
			front, _ := startQUICFront(t, p, ca)
			pconn, _, err := openTunnel(t, masqueClient(t, front, ca), front, "origin.test:443", nil)
			require.NoError(t, err)
			inner, _ := innerH3(t, pconn, destination, "origin.test", ca)
			return inner
		}},
	}
	for _, f := range fronts {
		t.Run(f.name, func(t *testing.T) {
			p := testProxyWithCA(t, ca, WithTransport(tr), WithNameResolver(resolver))
			p.MustAdd("origin.test/pkg.Svc/Method", forwardCall)
			client := &http.Client{Timeout: 10 * time.Second, Transport: f.dial(t, p)}
			before := len(seen.all())
			resp := grpcDo(t, client, "https://origin.test/pkg.Svc/Method", grpcPayload("hello"))
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			_ = resp.Body.Close()

			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "HTTP/3.0", resp.Proto)
			assert.Equal(t, grpcPayload("hello"), body)
			assert.Equal(t, "0", resp.Trailer.Get("Grpc-Status"))
			assert.Equal(t, []string{"HTTP/2.0"}, seen.all()[before:])
		})
	}
}

func TestKindGRPC_CallToAPlaintextOriginThroughAnUpstreamProxyIsTunneled(t *testing.T) {
	seen := new(recorder)
	origin := h2cOnlyOrigin(t, grpcEchoHandler(seen))
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	requests := new(recorder)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil {
					requests.add(err.Error())
					return
				}
				requests.add(req.Method + " " + req.RequestURI)
				if req.Method != http.MethodConnect {
					return
				}
				up, err := net.Dial("tcp", req.RequestURI)
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
				go func() { _, _ = io.Copy(up, br) }()
				_, _ = io.Copy(conn, up)
			}()
		}
	}()

	tr := DefaultTransport()
	tr.Proxy = fixedProxy("http://" + ln.Addr().String())
	p := testProxy(t, WithTransport(tr))
	p.MustAdd(originHost(originURL)+"/pkg.Svc/Method", func(c *GRPCCtx) error { return c.Forward() })

	resp := grpcDo(t, h2cFrontClient(startProxy(t, p)), origin.URL+"/pkg.Svc/Method", grpcPayload("hello"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, grpcPayload("hello"), body)
	assert.Equal(t, []string{"HTTP/2.0"}, seen.all())
	assert.Equal(t, []string{"CONNECT " + originURL.Host}, requests.all())
}

// grpcEchoHandler echoes every message, recording the protocol of each call on seen when it is
// given one.
func grpcEchoHandler(seen *recorder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			seen.add(r.Proto)
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		rc := http.NewResponseController(w)
		_ = rc.EnableFullDuplex()
		w.WriteHeader(http.StatusOK)
		src := &msgSource{r: r.Body, max: defaultMaxMessageBytes}
		for {
			payload, flag, err := src.next()
			if err != nil {
				break
			}
			_, _ = w.Write(appendGRPCFrame(nil, flag, payload))
			_ = rc.Flush()
		}
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
}

// lpm frames a Length-Prefixed-Message by hand, so the peers share no parser with the proxy.
func lpm(flag byte, payload string) []byte {
	b := []byte{flag, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(len(payload)))
	return append(b, payload...)
}

type originCall struct {
	header    http.Header
	readErr   error
	method    string
	path      string
	authority string
	proto     string
	body      []byte
}

type grpcOrigin struct {
	srv   *httptest.Server
	calls chan originCall
}

func newGRPCOrigin(t *testing.T, h func(o *grpcOrigin, w http.ResponseWriter, r *http.Request)) *grpcOrigin {
	t.Helper()
	o := &grpcOrigin{calls: make(chan originCall, 8)}
	o.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h(o, w, r)
	}))
	o.srv.EnableHTTP2 = true
	o.srv.StartTLS()
	t.Cleanup(o.srv.Close)
	return o
}

func echoOrigin(t *testing.T) *grpcOrigin {
	t.Helper()
	return newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
		call := o.record(r)
		answerOK(w, call.body)
	})
}

func (o *grpcOrigin) record(r *http.Request) originCall {
	call := originCall{
		header: r.Header.Clone(), method: r.Method, path: r.URL.RequestURI(),
		authority: r.Host, proto: r.Proto,
	}
	call.body, call.readErr = io.ReadAll(r.Body)
	o.calls <- call
	return call
}

func (o *grpcOrigin) call(t *testing.T) originCall {
	t.Helper()
	select {
	case c := <-o.calls:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("the origin received no call")
		return originCall{}
	}
}

func (o *grpcOrigin) noCall(t *testing.T) {
	t.Helper()
	select {
	case c := <-o.calls:
		t.Fatalf("the origin received a call to %s", c.path)
	default:
	}
}

// answer flushes each chunk, so each leaves the origin in a DATA frame of its own.
func answer(w http.ResponseWriter, header, trailer []string, chunks ...[]byte) {
	h := w.Header()
	h.Set("Content-Type", "application/grpc")
	for i := 0; i+1 < len(header); i += 2 {
		h.Add(header[i], header[i+1])
	}
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	for _, c := range chunks {
		_, _ = w.Write(c)
		_ = rc.Flush()
	}
	for i := 0; i+1 < len(trailer); i += 2 {
		h.Add(http.TrailerPrefix+trailer[i], trailer[i+1])
	}
}

func answerOK(w http.ResponseWriter, chunks ...[]byte) {
	answer(w, nil, []string{"Grpc-Status", "0"}, chunks...)
}

type grpcBench struct {
	p         *Proxy
	origin    *grpcOrigin
	pool      *x509.CertPool
	ca        *CA
	proxyAddr string
	host      string
	authority string
}

func newGRPCBench(t *testing.T, origin *grpcOrigin, h GRPC, opts ...ProxyOption) *grpcBench {
	t.Helper()
	u, err := url.Parse(origin.srv.URL)
	require.NoError(t, err)
	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin.srv)
	p, err := New(append([]ProxyOption{WithCA(ca), WithTransport(tr)}, opts...)...)
	require.NoError(t, err)
	b := &grpcBench{p: p, origin: origin, pool: ca.CertPool(), ca: ca, host: originHost(u), authority: u.Host}
	if h != nil {
		p.MustAdd(b.host+"/*{method}", h)
	}
	b.proxyAddr = startProxy(t, p)
	return b
}

// newH3OriginGRPCBench is newGRPCBench with an origin served over HTTP/3 alone, reached under
// the name origin.test.
func newH3OriginGRPCBench(t *testing.T, h GRPC, origin http.HandlerFunc) *grpcBench {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	cert := selfSignedFor(t, ca, "origin.test")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http3.Server{
		Handler:   origin,
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}),
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = pc.Close()
	})
	tr := DefaultTransport()
	tr.AllowHTTP3 = true
	tr.DialContext = pinnedDialer(pc.LocalAddr().String())
	tr.RootCAs = poolOf(ca)
	p := testProxyWithCA(t, ca, WithTransport(tr))
	p.MustAdd("origin.test/*{method}", h)
	return &grpcBench{p: p, ca: ca, host: "origin.test", authority: "origin.test"}
}

// grpcClient writes its own frames. The rows depend on DATA frame boundaries a net/http
// client chooses itself.
type grpcClient struct {
	t         *testing.T
	fr        *http2.Framer
	enc       *hpack.Encoder
	authority string
	buf       bytes.Buffer
	next      uint32
}

func (b *grpcBench) client(t *testing.T) *grpcClient {
	t.Helper()
	raw := connectRaw(t, b.proxyAddr, b.authority)
	tc := tls.Client(raw, &tls.Config{ServerName: b.host, RootCAs: b.pool, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	require.NoError(t, tc.Handshake())
	require.Equal(t, "h2", tc.ConnectionState().NegotiatedProtocol)
	require.NoError(t, tc.SetDeadline(time.Now().Add(10*time.Second)))
	_, err := io.WriteString(tc, http2.ClientPreface)
	require.NoError(t, err)
	c := &grpcClient{t: t, fr: http2.NewFramer(tc, tc), authority: b.authority, next: 1}
	c.enc = hpack.NewEncoder(&c.buf)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	c.fr.MaxHeaderListSize = 1 << 20
	require.NoError(t, c.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 30}))
	require.NoError(t, c.fr.WriteWindowUpdate(0, 1<<30))
	// A request body past 65535 bytes waits for the windows of the proxy's SETTINGS.
	for {
		f, err := c.fr.ReadFrame()
		require.NoError(t, err)
		if s, ok := f.(*http2.SettingsFrame); ok && !s.IsAck() {
			require.NoError(t, c.fr.WriteSettingsAck())
			return c
		}
	}
}

func (c *grpcClient) callFields(path, ct string, extra ...string) []hpack.HeaderField {
	f := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: path},
		{Name: ":authority", Value: c.authority},
		{Name: "te", Value: "trailers"},
		{Name: "content-type", Value: ct},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		f = append(f, hpack.HeaderField{Name: extra[i], Value: extra[i+1]})
	}
	return f
}

func (c *grpcClient) open(fields []hpack.HeaderField, end bool) uint32 {
	c.t.Helper()
	c.buf.Reset()
	for _, f := range fields {
		require.NoError(c.t, c.enc.WriteField(f))
	}
	id := c.next
	c.next += 2
	require.NoError(c.t, c.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: c.buf.Bytes(), EndHeaders: true, EndStream: end,
	}))
	return id
}

func (c *grpcClient) call(path string, extra ...string) uint32 {
	c.t.Helper()
	return c.open(c.callFields(path, "application/grpc", extra...), false)
}

func (c *grpcClient) data(id uint32, end bool, b []byte) {
	c.t.Helper()
	require.NoError(c.t, c.fr.WriteData(id, end, b))
}

func (c *grpcClient) unary(path string, body []byte, extra ...string) grpcResult {
	c.t.Helper()
	id := c.call(path, extra...)
	c.data(id, true, body)
	return c.await(id)
}

type grpcResult struct {
	blocks     [][]hpack.HeaderField
	data       []byte
	frames     int
	rst        http2.ErrCode
	reset      bool
	ended      bool
	endOnBlock bool
}

func field(block []hpack.HeaderField, name string) (string, bool) {
	for _, f := range block {
		if f.Name == name {
			return f.Value, true
		}
	}
	return "", false
}

func (r *grpcResult) header(name string) string {
	if len(r.blocks) == 0 {
		return ""
	}
	v, _ := field(r.blocks[0], name)
	return v
}

// trailer reads the last block, and a Trailers-Only response has a single block.
func (r *grpcResult) trailer(name string) string {
	if len(r.blocks) < 2 {
		return ""
	}
	v, _ := field(r.blocks[len(r.blocks)-1], name)
	return v
}

func (r *grpcResult) done() bool { return r.ended || r.reset }

func (c *grpcClient) step(id uint32, r *grpcResult) {
	c.t.Helper()
	f, err := c.fr.ReadFrame()
	require.NoError(c.t, err)
	switch f := f.(type) {
	case *http2.SettingsFrame:
		if !f.IsAck() {
			require.NoError(c.t, c.fr.WriteSettingsAck())
		}
	case *http2.PingFrame:
		if !f.IsAck() {
			require.NoError(c.t, c.fr.WritePing(true, f.Data))
		}
	case *http2.GoAwayFrame:
		c.t.Fatalf("GOAWAY %v", f.ErrCode)
	case *http2.MetaHeadersFrame:
		if f.StreamID == id {
			r.blocks = append(r.blocks, f.Fields)
			if f.StreamEnded() {
				r.ended, r.endOnBlock = true, true
			}
		}
	case *http2.DataFrame:
		if f.StreamID == id {
			r.data = append(r.data, f.Data()...)
			if len(f.Data()) > 0 {
				r.frames++
			}
			r.ended = f.StreamEnded()
		}
	case *http2.RSTStreamFrame:
		if f.StreamID == id {
			r.reset, r.rst = true, f.ErrCode
		}
	}
}

func (c *grpcClient) await(id uint32) grpcResult {
	c.t.Helper()
	var r grpcResult
	for !r.done() {
		c.step(id, &r)
	}
	return r
}

func (c *grpcClient) awaitData(id uint32, r *grpcResult, n int) {
	c.t.Helper()
	for len(r.data) < n && !r.done() {
		c.step(id, r)
	}
	require.Len(c.t, r.data, n)
}

func (b *grpcBench) h3Client(t *testing.T) *http3.ClientConn {
	t.Helper()
	front, _ := startQUICFront(t, b.p, b.ca)
	tr := &http3.Transport{DisableCompression: true}
	t.Cleanup(func() { _ = tr.Close() })
	return tr.NewClientConn(dialQUICFront(t, front, b.ca))
}

// h3Call drives a request stream directly. A round trip cannot reset one direction of a call.
type h3Call struct {
	t    *testing.T
	str  *http3.RequestStream
	resp *http.Response
}

func (b *grpcBench) h3Call(t *testing.T, cc *http3.ClientConn, path string) *h3Call {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	str, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	require.NoError(t, str.SetDeadline(time.Now().Add(10*time.Second)))
	req, err := http.NewRequest(http.MethodPost, "https://"+b.authority+path, http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	require.NoError(t, str.SendRequestHeader(req))
	return &h3Call{t: t, str: str}
}

func (c *h3Call) send(b []byte) {
	c.t.Helper()
	_, err := c.str.Write(b)
	require.NoError(c.t, err)
}

func (c *h3Call) response() *http.Response {
	c.t.Helper()
	if c.resp == nil {
		resp, err := c.str.ReadResponse()
		require.NoError(c.t, err)
		c.resp = resp
	}
	return c.resp
}

func (c *h3Call) read(n int) []byte {
	c.t.Helper()
	c.response()
	b := make([]byte, n)
	_, err := io.ReadFull(c.str, b)
	require.NoError(c.t, err)
	return b
}

func (c *h3Call) rest() ([]byte, error) {
	c.t.Helper()
	c.response()
	return io.ReadAll(c.str)
}

func (c *h3Call) status() (code, msg string) {
	return grpcStatus(c.response())
}

func forwardCall(c *GRPCCtx) error { return c.Forward() }

func openCall(c *GRPCCtx) error {
	if err := c.Open(); err != nil {
		return err
	}
	src := MergeMessages(c.Outbound(), c.Inbound())
	for {
		m, err := src.ReadMessage()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := m.Forward(); err != nil {
			return err
		}
	}
}

// grpcModes are the two framing paths a relayed call takes, the gate of Forward and the
// message readers of Open.
var grpcModes = []struct {
	h    GRPC
	name string
}{
	{forwardCall, "Forward"},
	{openCall, "Open"},
}

func eachMode(t *testing.T, run func(t *testing.T, h GRPC)) {
	t.Helper()
	for _, m := range grpcModes {
		t.Run(m.name, func(t *testing.T) { run(t, m.h) })
	}
}

// outboundOnly opens the call and forwards the request messages without reading the response,
// and reports the error that ended its loop.
func outboundOnly(returned chan<- error) GRPC {
	return func(c *GRPCCtx) error {
		if err := c.Open(); err != nil {
			return err
		}
		for {
			m, err := c.Outbound().ReadMessage()
			if err == nil {
				err = m.Forward()
			}
			if err != nil {
				returned <- err
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
		}
	}
}

// trailersOnlyOrigin answers every call with a trailers-only response of status code, without
// reading the request.
func trailersOnlyOrigin(t *testing.T, code string) *grpcOrigin {
	t.Helper()
	return newGRPCOrigin(t, func(_ *grpcOrigin, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", code)
		w.WriteHeader(http.StatusOK)
	})
}

// streamOrigin echoes each chunk as it arrives, so a test can wait for one message before
// sending the next.
func streamOrigin(t *testing.T) *grpcOrigin {
	t.Helper()
	return newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		call := originCall{header: r.Header.Clone(), path: r.URL.RequestURI()}
		buf := make([]byte, 64<<10)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				call.body = append(call.body, buf[:n]...)
				_, _ = w.Write(buf[:n])
				_ = rc.Flush()
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				call.readErr = err
				select {
				case <-r.Context().Done():
				case <-time.After(5 * time.Second):
				}
				o.calls <- call
				return
			}
		}
		o.calls <- call
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
}

func grpcStatusOf(r grpcResult) string {
	if len(r.blocks) == 1 {
		return r.header("grpc-status")
	}
	return r.trailer("grpc-status")
}

func TestConformanceGRPC(t *testing.T) {
	runConformance(t, grpcConformance)
}

const specialStatusMessage = "\t\ntest with whitespace\r\nand Unicode BMP ☺ and non-BMP 😈\t\n"

// grpcConformance lists the requirements of the gRPC over HTTP/2 protocol and of the status
// code document, checked by a client and an origin scripted around the proxy.
var grpcConformance = []conformanceCase{
	{
		id: "grpc/requests/1", name: "a Call-Definition with every optional field, then one without any",
		req: "**Call-Definition** → Method Scheme Path [Authority] TE [Timeout] Content-Type [Message-Type] [Message-Encoding] [Message-Accept-Encoding] [User-Agent]",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, echoOrigin(t), h)
				c := b.client(t)
				full := c.callFields("/pkg.Svc/Method", "application/grpc+proto",
					"grpc-timeout", "1S", "grpc-message-type", "pkg.Request", "grpc-encoding", "identity",
					"grpc-accept-encoding", "gzip,identity", "user-agent", "grpc-go/1.2.3")
				id := c.open(full, false)
				c.data(id, true, lpm(0, "hello"))
				r := c.await(id)
				require.Equal(t, "0", grpcStatusOf(r))
				call := b.origin.call(t)
				assert.Equal(t, "POST", call.method)
				assert.Equal(t, "/pkg.Svc/Method", call.path)
				assert.Equal(t, b.authority, call.authority)
				assert.Equal(t, "HTTP/2.0", call.proto)
				assert.Equal(t, http.Header{
					"Te":                   {"trailers"},
					"Content-Type":         {"application/grpc+proto"},
					"Grpc-Timeout":         {"1S"},
					"Grpc-Message-Type":    {"pkg.Request"},
					"Grpc-Encoding":        {"identity"},
					"Grpc-Accept-Encoding": {"gzip,identity"},
					"User-Agent":           {"grpc-go/1.2.3"},
				}, call.header)
				assert.Equal(t, lpm(0, "hello"), call.body)

				r = c.unary("/pkg.Svc/Method", nil)
				require.Equal(t, "0", grpcStatusOf(r))
				call = b.origin.call(t)
				assert.Equal(t, http.Header{"Te": {"trailers"}, "Content-Type": {"application/grpc"}}, call.header, "the proxy added a field")
			})
		},
	},
	{
		id: "grpc/requests/2", name: "a call to the method in another case",
		req: "**Path** is case-sensitive.",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), nil)
			b.p.MustAdd(b.host+"/pkg.Svc/Method", forwardCall)
			c := b.client(t)
			r := c.unary("/pkg.svc/method", lpm(0, "x"))
			assert.Equal(t, "200", r.header(":status"))
			assert.Equal(t, "7", grpcStatusOf(r))
			b.origin.noCall(t)
			r = c.unary("/pkg.Svc/Method", lpm(0, "x"))
			assert.Equal(t, "0", grpcStatusOf(r))
			assert.Equal(t, "/pkg.Svc/Method", b.origin.call(t).path)
		},
	},
	{
		id: "grpc/requests/3", name: "a call without te",
		req: "**TE** → \"te\" \"trailers\"  ; Used to detect incompatible proxies",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, echoOrigin(t), h)
				c := b.client(t)
				fields := c.callFields("/pkg.Svc/Method", "application/grpc")
				fields = append(fields[:4], fields[5:]...)
				id := c.open(fields, false)
				c.data(id, true, lpm(0, "x"))
				c.await(id)
				assert.Empty(t, b.origin.call(t).header.Values("Te"), "the proxy announced trailers the client did not")
			})
		},
	},
	{
		id: "grpc/requests/4", name: "grpc-timeout in each unit, at most 8 digits, and malformed",
		req: "**TimeoutValue** → {_positive integer as ASCII string of at most 8 digits_}",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(c *GRPCCtx) error {
				d, ok := c.Timeout()
				return c.Respond(CodeOK, fmt.Sprintf("%d %t", int64(d), ok))
			})
			c := b.client(t)
			for v, want := range map[string]string{
				"2H":         fmt.Sprintf("%d true", int64(2*time.Hour)),
				"2M":         fmt.Sprintf("%d true", int64(2*time.Minute)),
				"2S":         fmt.Sprintf("%d true", int64(2*time.Second)),
				"2m":         fmt.Sprintf("%d true", int64(2*time.Millisecond)),
				"2u":         fmt.Sprintf("%d true", int64(2*time.Microsecond)),
				"2n":         "2 true",
				"12345678S":  fmt.Sprintf("%d true", int64(12345678*time.Second)),
				"99999999H":  fmt.Sprintf("%d true", int64(math.MaxInt64)),
				"123456789S": "0 false",
				"2s":         "0 false",
				"2":          "0 false",
				"S":          "0 false",
				"-2S":        "0 false",
				"+2S":        "0 false",
				"2.5S":       "0 false",
			} {
				r := c.unary("/pkg.Svc/Method", nil, "grpc-timeout", v)
				assert.Equal(t, want, r.header("grpc-message"), "grpc-timeout %q", v)
			}
		},
	},
	{
		id: "grpc/requests/5", name: "a call without grpc-timeout",
		req: "If **Timeout** is omitted a server should assume an infinite timeout.",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(c *GRPCCtx) error {
				d, ok := c.Timeout()
				_, deadline := c.Context().Deadline()
				return c.Respond(CodeOK, fmt.Sprintf("%d %t %t", int64(d), ok, deadline))
			})
			r := b.client(t).unary("/pkg.Svc/Method", nil)
			assert.Equal(t, "0 false false", r.header("grpc-message"))
		},
	},
	{
		id: "grpc/requests/6", name: "the order of the request fields",
		req:  "Additionally implementations should send **Timeout** immediately after the reserved headers and they should send the **Call-Definition** headers before sending **Custom-Metadata**.",
		skip: "the fields of a forwarded call are encoded by net/http's HTTP/2 transport, which edge delegates the upstream request to",
	},
	{
		id: "grpc/requests/7", name: "each gRPC content type and its neighbours, with a gRPC and an HTTP entry on the path",
		req: "**Content-Type** → \"content-type\" \"application/grpc\" [(\"+proto\" / \"+json\" / {_custom_})]",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), nil)
			b.p.MustAdd(b.host+"/pkg.Svc/Method", func(c *GRPCCtx) error { return c.Respond(CodeOK, "grpc") })
			b.p.MustAdd(b.host+"/pkg.Svc/Method", func(c *HTTPCtx) (*http.Response, error) { return Status(http.StatusTeapot), nil })
			c := b.client(t)
			for ct, grpc := range map[string]bool{
				"application/grpc":               true,
				"Application/gRPC":               true,
				"application/grpc+proto":         true,
				"application/grpc+json":          true,
				"application/grpc+thrift":        true,
				"application/grpc;charset=utf-8": true,
				"application/grpc-web":           false,
				"application/grpcx":              false,
				"application/json":               false,
			} {
				id := c.open(c.callFields("/pkg.Svc/Method", ct), false)
				c.data(id, true, lpm(0, "x"))
				r := c.await(id)
				if grpc {
					assert.Equal(t, "grpc", r.header("grpc-message"), "content type %q", ct)
				} else {
					assert.Equal(t, "418", r.header(":status"), "content type %q", ct)
				}
			}
			b.origin.noCall(t)
		},
	},
	{
		id: "grpc/requests/8", name: "a call that is not gRPC on a path only a gRPC entry serves",
		req: "If **Content-Type** does not begin with \"application/grpc\", gRPC servers SHOULD respond with HTTP status of 415 (Unsupported Media Type).  This will prevent other HTTP/2 clients from interpreting a gRPC error response, which uses status 200 (OK), as successful.",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), forwardCall)
			c := b.client(t)
			for _, ct := range []string{"application/json", "application/grpc-web"} {
				id := c.open(c.callFields("/pkg.Svc/Method", ct), false)
				c.data(id, true, lpm(0, "x"))
				r := c.await(id)
				assert.NotEqual(t, "200", r.header(":status"), "content type %q", ct)
				assert.Empty(t, grpcStatusOf(r), "content type %q", ct)
			}
			b.origin.noCall(t)
		},
	},
	{
		id: "grpc/requests/9", name: "a compressed message under grpc-encoding, in both directions",
		req: "A **Compressed-Flag** value of 1 indicates that the binary octet sequence of **Message** is compressed using the mechanism declared by the **Message-Encoding** header.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w, []string{"Grpc-Encoding", "gzip", "Grpc-Accept-Encoding", "gzip"}, []string{"Grpc-Status", "0"}, call.body)
				})
				b := newGRPCBench(t, o, h)
				msg := lpm(1, "\x1f\x8b not gzip, the proxy never inflates")
				r := b.client(t).unary("/pkg.Svc/Method", msg, "grpc-encoding", "gzip", "grpc-accept-encoding", "gzip,identity")
				call := o.call(t)
				assert.Equal(t, "gzip", call.header.Get("Grpc-Encoding"))
				assert.Equal(t, "gzip,identity", call.header.Get("Grpc-Accept-Encoding"))
				assert.Equal(t, msg, call.body)
				assert.Equal(t, "gzip", r.header("grpc-encoding"))
				assert.Equal(t, "gzip", r.header("grpc-accept-encoding"))
				assert.Equal(t, msg, r.data)
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "grpc/requests/10", name: "a compressed message without grpc-encoding",
		req: "If the **Message-Encoding** header is omitted then the **Compressed-Flag** must be 0.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := echoOrigin(t)
				b := newGRPCBench(t, o, h)
				msg := lpm(1, "abc")
				r := b.client(t).unary("/pkg.Svc/Method", msg)
				assert.Equal(t, msg, o.call(t).body, "the endpoint decides on the flag")
				assert.Equal(t, msg, r.data)
			})
		},
	},
	{
		id: "grpc/requests/11", name: "a message whose flag is neither 0 nor 1",
		req: "**Compressed-Flag** → 0 / 1   ; encoded as 1 byte unsigned integer",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := echoOrigin(t)
				b := newGRPCBench(t, o, h)
				msg := lpm(2, "abc")
				b.client(t).unary("/pkg.Svc/Method", msg)
				if body := o.call(t).body; len(body) > 0 {
					assert.Equal(t, msg, body, "the origin read a flag the client did not send")
				}
			})
		},
	},
	{
		id: "grpc/requests/12", name: "messages compressed with a context each",
		req:  "Compression contexts are NOT maintained over message boundaries, implementations must create a new context for each message in the stream.",
		skip: "edge never decompresses a message, CLAUDE.md states that a body is never decompressed by the proxy",
	},
	{
		id: "grpc/requests/13", name: "custom_metadata, ASCII and binary values, padded and unpadded, echoed in headers and trailers",
		req: "**Custom-Metadata** → Binary-Header / ASCII-Header",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w,
						[]string{"X-Grpc-Test-Echo-Initial", r.Header.Get("X-Grpc-Test-Echo-Initial")},
						[]string{
							"Grpc-Status", "0",
							"X-Grpc-Test-Echo-Trailing-Bin", r.Header.Get("X-Grpc-Test-Echo-Trailing-Bin"),
							"X-Padded-Bin", "AQI=", "X-Unpadded-Bin", "AQI",
						},
						call.body)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, ""),
					"x-grpc-test-echo-initial", "test_initial_metadata_value",
					"x-grpc-test-echo-trailing-bin", "q6ur",
					"x-padded-bin", "AQI=", "x-unpadded-bin", "AQI")
				call := o.call(t)
				assert.Equal(t, "test_initial_metadata_value", call.header.Get("X-Grpc-Test-Echo-Initial"))
				assert.Equal(t, "q6ur", call.header.Get("X-Grpc-Test-Echo-Trailing-Bin"))
				assert.Equal(t, "AQI=", call.header.Get("X-Padded-Bin"))
				assert.Equal(t, "AQI", call.header.Get("X-Unpadded-Bin"))
				assert.Equal(t, "test_initial_metadata_value", r.header("x-grpc-test-echo-initial"))
				assert.Equal(t, "q6ur", r.trailer("x-grpc-test-echo-trailing-bin"))
				assert.Equal(t, "AQI=", r.trailer("x-padded-bin"))
				assert.Equal(t, "AQI", r.trailer("x-unpadded-bin"))
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "grpc/requests/14", name: "binary values padded and unpadded, decoded by DecodeBinaryMetadata",
		req: "Implementations MUST accept padded and un-padded values and should emit un-padded values.",
		run: func(t *testing.T) {
			for v, want := range map[string][]byte{
				"AQI=": {1, 2}, "AQI": {1, 2}, "AQID": {1, 2, 3}, "AQIDBA==": {1, 2, 3, 4}, "AQIDBA": {1, 2, 3, 4},
			} {
				got, err := DecodeBinaryMetadata(v)
				require.NoError(t, err, v)
				assert.Equal(t, want, got, v)
			}
		},
	},
	{
		id: "grpc/requests/15", name: "two binary values joined with a comma, decoded by DecodeBinaryMetadata",
		req:  "Implementations must split **Binary-Header**s on \",\" before decoding the Base64-encoded values.",
		skip: "DecodeBinaryMetadata decodes one value and the caller splits a field",
	},
	{
		id: "grpc/requests/16", name: "a metadata key sent three times, in both directions",
		req: "**Custom-Metadata** header order is not guaranteed to be preserved except for values with duplicate header names.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w, []string{"X-Dup", "c", "X-Dup", "b", "X-Dup", "a"}, []string{"Grpc-Status", "0"}, call.body)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, ""), "x-dup", "a", "x-dup", "b", "x-dup", "c")
				assert.Equal(t, []string{"a", "b", "c"}, o.call(t).header.Values("X-Dup"))
				var got []string
				for _, f := range r.blocks[0] {
					if f.Name == "x-dup" {
						got = append(got, f.Value)
					}
				}
				assert.Equal(t, []string{"c", "b", "a"}, got)
			})
		},
	},
	{
		id: "grpc/requests/17", name: "metadata under a grpc- key the protocol does not list, in both directions",
		req: "Header names starting with \"grpc-\" but not listed here are reserved for future GRPC use and should not be used by applications as **Custom-Metadata**.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w, []string{"Grpc-Future-Header", "h"}, []string{"Grpc-Status", "0", "Grpc-Future-Trailer", "t"}, call.body)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, ""), "grpc-future-request", "q")
				assert.Equal(t, "q", o.call(t).header.Get("Grpc-Future-Request"))
				assert.Equal(t, "h", r.header("grpc-future-header"))
				assert.Equal(t, "t", r.trailer("grpc-future-trailer"))
			})
		},
	},
	{
		id: "grpc/requests/18", name: "a metadata value outside ASCII-Value that HTTP accepts",
		req: "Implementations must not error due to receiving an invalid **ASCII-Value** that's a valid **field-value** in HTTP, but the precise behavior is not strictly defined: they may throw the value away or accept the value.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := echoOrigin(t)
				b := newGRPCBench(t, o, h)
				const v = "tab\tand obs-text \xc3\xa9"
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"), "x-odd", v)
				assert.Equal(t, "0", grpcStatusOf(r))
				if got := o.call(t).header.Values("X-Odd"); len(got) > 0 {
					assert.Equal(t, []string{v}, got)
				}
			})
		},
	},
	{
		id: "grpc/requests/19", name: "request headers past 8 KiB",
		req:  "Servers may limit the size of **Request-Headers**, with a default of 8 KiB suggested.",
		skip: "the bound on a request header block is WithMaxHeaderBytes, the same for every kind",
	},
	{
		id: "grpc/requests/20", name: "empty_unary, a message of zero bytes in both directions",
		req: "**Message** → \\*{binary octet}",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := echoOrigin(t)
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, ""))
				assert.Equal(t, lpm(0, ""), o.call(t).body)
				assert.Equal(t, lpm(0, ""), r.data)
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "grpc/requests/21", name: "the client half-closes with an empty DATA frame while the response streams",
		req: "In scenarios where the **Request** stream needs to be closed but no data remains to be sent implementations MUST send an empty DATA frame with this flag set.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/grpc")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(lpm(0, "first"))
					_ = http.NewResponseController(w).Flush()
					if call := o.record(r); call.readErr == nil {
						w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
					}
				})
				b := newGRPCBench(t, o, h)
				c := b.client(t)
				id := c.call("/pkg.Svc/Method")
				var r grpcResult
				c.awaitData(id, &r, len(lpm(0, "first")))
				c.data(id, true, nil)
				for !r.done() {
					c.step(id, &r)
				}
				call := o.call(t)
				assert.NoError(t, call.readErr)
				assert.Empty(t, call.body)
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "grpc/requests/22", name: "a request stream that ends inside its second message",
		req: "In some cases it is possible that the framing of the message stream has become corrupt and the RPC runtime will choose to use an **RST_STREAM** frame to indicate this state to its peer.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := echoOrigin(t)
				b := newGRPCBench(t, o, h)
				c := b.client(t)
				id := c.call("/pkg.Svc/Method")
				c.data(id, false, lpm(0, "one"))
				cut := lpm(0, "two")[:6]
				c.data(id, true, cut)
				c.await(id)
				if call := o.call(t); call.readErr == nil {
					assert.Equal(t, slices.Concat(lpm(0, "one"), cut), call.body, "the origin read a complete call the client cut short")
				}
			})
		},
	},
	{
		id: "grpc/responses/12", name: "a response stream that ends inside its second message, then an OK status",
		req: "In some cases it is possible that the framing of the message stream has become corrupt and the RPC runtime will choose to use an **RST_STREAM** frame to indicate this state to its peer.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				cut := lpm(0, "two")[:6]
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					answerOK(w, lpm(0, "one"), cut)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				if !r.reset && grpcStatusOf(r) == "0" {
					assert.Equal(t, slices.Concat(lpm(0, "one"), cut), r.data, "the client read a complete call the origin cut short")
				}
			})
		},
	},
	{
		id: "grpc/data-frames/1", name: "client_streaming, four messages in one DATA frame, in both directions",
		req: "DATA frame boundaries have no relation to **Length-Prefixed-Message** boundaries and implementations should make no assumptions about their alignment.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := echoOrigin(t)
				b := newGRPCBench(t, o, h)
				body := slices.Concat(lpm(0, "a"), lpm(0, "bb"), lpm(0, ""), lpm(0, "ccc"))
				r := b.client(t).unary("/pkg.Svc/Method", body)
				assert.Equal(t, body, o.call(t).body)
				assert.Equal(t, body, r.data)
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "grpc/data-frames/2", name: "one message cut inside its prefix and its payload, in both directions",
		req: "DATA frame boundaries have no relation to **Length-Prefixed-Message** boundaries and implementations should make no assumptions about their alignment.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				msg := lpm(0, "hello")
				cuts := [][]byte{msg[:1], msg[1:3], msg[3:6], msg[6:]}
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					answerOK(w, cuts...)
				})
				b := newGRPCBench(t, o, h)
				c := b.client(t)
				id := c.call("/pkg.Svc/Method")
				for _, cut := range cuts {
					c.data(id, false, cut)
				}
				c.data(id, true, nil)
				r := c.await(id)
				assert.Equal(t, msg, o.call(t).body)
				assert.Equal(t, msg, r.data)
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "grpc/data-frames/3", name: "large_unary, 271828 bytes up and 314159 bytes down",
		req: "DATA frame boundaries have no relation to **Length-Prefixed-Message** boundaries and implementations should make no assumptions about their alignment.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				down := lpm(0, strings.Repeat("d", 314159-5))
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					answerOK(w, down)
				})
				b := newGRPCBench(t, o, h)
				c := b.client(t)
				up := lpm(0, strings.Repeat("u", 271828-5))
				id := c.call("/pkg.Svc/Method")
				for chunk := range slices.Chunk(up, 16384) {
					c.data(id, false, chunk)
				}
				c.data(id, true, nil)
				r := c.await(id)
				assert.Equal(t, up, o.call(t).body)
				assert.Equal(t, down, r.data)
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "statuscodes/1", name: "a message past WithMaxMessageBytes, in each direction",
		req: "Sent or received message was larger than configured limit | RESOURCE_EXHAUSTED | Both",
		run: func(t *testing.T) {
			big := lpm(0, strings.Repeat("x", 17))
			o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
				call := o.record(r)
				if r.Header.Get("X-Big") != "" {
					answerOK(w, big)
					return
				}
				answerOK(w, call.body)
			})
			b := newGRPCBench(t, o, openCall, WithMaxMessageBytes(16))
			c := b.client(t)
			r := c.unary("/pkg.Svc/Method", big)
			assert.Equal(t, "8", grpcStatusOf(r), "a request message past the bound")
			r = c.unary("/pkg.Svc/Method", lpm(0, "small"), "x-big", "1")
			assert.Equal(t, "8", grpcStatusOf(r), "a response message past the bound")
			assert.Empty(t, r.data)
		},
	},
	{
		id: "grpc/responses/1", name: "server_streaming, headers, four messages and trailers",
		req: "For responses end-of-stream is indicated by the presence of the END_STREAM flag on the last received HEADERS frame that carries **Trailers**.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				msgs := [][]byte{lpm(0, strings.Repeat("a", 31415)), lpm(0, strings.Repeat("b", 9)), lpm(0, strings.Repeat("c", 2653)), lpm(0, strings.Repeat("d", 58979))}
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					answer(w, []string{"X-Initial", "i"}, []string{"Grpc-Status", "0", "Trace-Proto-Bin", "jher831yy13JHy3hc"}, msgs...)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "go"))
				require.Len(t, r.blocks, 2)
				assert.Equal(t, "200", r.header(":status"))
				assert.Equal(t, "application/grpc", r.header("content-type"))
				assert.Equal(t, "i", r.header("x-initial"))
				_, early := field(r.blocks[0], "grpc-status")
				assert.False(t, early, "the status arrived with the headers")
				assert.Equal(t, slices.Concat(msgs...), r.data)
				assert.True(t, r.endOnBlock, "the stream did not end on the trailers")
				assert.Equal(t, "0", r.trailer("grpc-status"))
				assert.Equal(t, "jher831yy13JHy3hc", r.trailer("trace-proto-bin"))
			})
		},
	},
	{
		id: "grpc/responses/2", name: "Respond with a message and an OK status",
		req: "Status must be sent in **Trailers** even if the status code is OK.",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(c *GRPCCtx) error { return c.Respond(CodeOK, "", []byte("a")) })
			r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
			require.Len(t, r.blocks, 2)
			_, early := field(r.blocks[0], "grpc-status")
			assert.False(t, early, "the status arrived with the headers")
			assert.Equal(t, lpm(0, "a"), r.data)
			assert.True(t, r.endOnBlock)
			assert.Equal(t, "0", r.trailer("grpc-status"))
			b.origin.noCall(t)
		},
	},
	{
		id: "grpc/responses/3", name: "unimplemented_method, the origin answers Trailers-Only",
		req: "**Response-Headers** & **Trailers-Only** are each delivered in a single HTTP2 HEADERS frame block. Most responses are expected to have both headers and trailers but **Trailers-Only** is permitted for calls that produce an immediate error.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					w.Header().Set("Content-Type", "application/grpc")
					w.Header().Set("Grpc-Status", "12")
					w.Header().Set("Grpc-Message", "unknown method")
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/grpc.testing.TestService/UnimplementedCall", lpm(0, ""))
				require.Len(t, r.blocks, 1, "a Trailers-Only response became headers and trailers")
				assert.True(t, r.endOnBlock)
				assert.Empty(t, r.data)
				assert.Equal(t, "200", r.header(":status"))
				assert.Equal(t, "12", r.header("grpc-status"))
				assert.Equal(t, "unknown method", r.header("grpc-message"))
			})
		},
	},
	{
		id: "grpc/responses/4", name: "Fail before Open answers Trailers-Only",
		req: "**Trailers-Only** → HTTP-Status Content-Type Trailers",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(c *GRPCCtx) error { return c.Fail(CodeNotFound, "missing") })
			r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
			require.Len(t, r.blocks, 1)
			assert.True(t, r.endOnBlock)
			assert.Empty(t, r.data)
			assert.Equal(t, "200", r.header(":status"))
			assert.Equal(t, "application/grpc", r.header("content-type"))
			assert.Equal(t, "5", r.header("grpc-status"))
			assert.Equal(t, "missing", r.header("grpc-message"))
			b.origin.noCall(t)
		},
	},
	{
		id: "grpc/responses/5", name: "special_status_message, a status message with whitespace, Unicode and a percent",
		req: "The value portion of **Status-Message** is conceptually a Unicode string description of the error, physically encoded as UTF-8 followed by percent-encoding.",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(c *GRPCCtx) error {
				if c.Request().Header.Get("X-Percent") != "" {
					return c.Fail(CodeUnknown, "100% done ~")
				}
				return c.Fail(CodeUnknown, specialStatusMessage)
			})
			c := b.client(t)
			r := c.unary("/pkg.Svc/Method", nil)
			assert.Equal(t, "2", r.header("grpc-status"))
			assert.Equal(t, "%09%0Atest with whitespace%0D%0Aand Unicode BMP %E2%98%BA and non-BMP %F0%9F%98%88%09%0A", r.header("grpc-message"))
			r = c.unary("/pkg.Svc/Method", nil, "x-percent", "1")
			assert.Equal(t, "100%25 done ~", r.header("grpc-message"))
		},
	},
	{
		id: "grpc/responses/6", name: "the origin's status message with broken percent-encodings",
		req: "When decoding invalid values, implementations MUST NOT error or throw away the message.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				const msg = "bad %zz, cut %E2%98 and 100%"
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w, nil, []string{"Grpc-Status", "13", "Grpc-Message", msg}, call.body)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				assert.Equal(t, "13", r.trailer("grpc-status"))
				assert.Equal(t, msg, r.trailer("grpc-message"))
			})
		},
	},
	{
		id: "grpc/responses/7", name: "the origin ends on a status with details",
		req: "**Status-Details** → \"grpc-status-details-bin\" {base64 encoded value} ; See notes below.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w, nil, []string{"Grpc-Status", "9", "Grpc-Message", "precondition", "Grpc-Status-Details-Bin", "CAkSDHByZWNvbmRpdGlvbg"}, call.body)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				assert.Equal(t, "9", r.trailer("grpc-status"))
				assert.Equal(t, "CAkSDHByZWNvbmRpdGlvbg", r.trailer("grpc-status-details-bin"))
			})
		},
	},
	{
		id: "grpc/responses/8", name: "Fail after the origin ended on a status with details",
		req: "If it contains a status code field, it MUST NOT contradict the **Status** header.",
		run: func(t *testing.T) {
			o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
				call := o.record(r)
				answer(w, nil, []string{"Grpc-Status", "9", "Grpc-Status-Details-Bin", "CAkSDHByZWNvbmRpdGlvbg"}, call.body)
			})
			b := newGRPCBench(t, o, func(c *GRPCCtx) error {
				if err := openCall(c); err != nil {
					return err
				}
				return c.Fail(CodeAborted, "aborted")
			})
			r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
			assert.Equal(t, lpm(0, "x"), r.data)
			require.Len(t, r.blocks, 2)
			assert.Equal(t, "10", r.trailer("grpc-status"))
			_, details := field(r.blocks[1], "grpc-status-details-bin")
			assert.False(t, details, "the details of the origin contradict the status of the proxy")
		},
	},
	{
		id: "grpc/responses/9", name: "Status-Details on an OK status",
		req:  "**Status-Details** is allowed only if **Status** is not OK.",
		skip: "edge sends grpc-status-details-bin only when relaying it, and the consumer verifies it",
	},
	{
		id: "grpc/responses/10", name: "the origin answers 200 and omits the status",
		req: "Implementations should expect broken deployments to send non-200 HTTP status codes in responses as well as a variety of non-GRPC content-types and to omit **Status** & **Status-Message**. Implementations must synthesize a **Status** & **Status-Message** to propagate to the application layer when this occurs.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w, nil, nil, call.body)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				assert.NotEqual(t, "0", grpcStatusOf(r), "the proxy made a call without a status succeed")
			})
		},
	},
	{
		id: "grpc/responses/11", name: "the origin answers 503 in HTML, which the status mapping reads as UNAVAILABLE",
		req: "Implementations should expect broken deployments to send non-200 HTTP status codes in responses as well as a variety of non-GRPC content-types and to omit **Status** & **Status-Message**. Implementations must synthesize a **Status** & **Status-Message** to propagate to the application layer when this occurs.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = io.WriteString(w, "<html>Service Unavailable</html>")
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				assert.Equal(t, "503", r.header(":status"))
				assert.Contains(t, []string{"", "14"}, grpcStatusOf(r), "the status the client reads contradicts the 503 of the origin")
			})
		},
	},
	{
		id: "grpc/responses/13", name: "response headers past 8 KiB",
		req:  "Clients may limit the size of **Response-Headers**, **Trailers**, and **Trailers-Only**, with a default of 8 KiB each suggested.",
		skip: "the bound on a response header block from the origin is net/http's transport, which edge delegates the upstream request to",
	},
	{
		id: "grpc/errors/1", name: "the entry is deleted between two messages of a call",
		req: "When an application or runtime error occurs during an RPC a **Status** and **Status-Message** are delivered in **Trailers**.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, streamOrigin(t), h)
				c := b.client(t)
				id := c.call("/pkg.Svc/Method")
				c.data(id, false, lpm(0, "one"))
				var r grpcResult
				c.awaitData(id, &r, len(lpm(0, "one")))
				_, err := b.p.Delete[GRPC](b.host + "/*{method}")
				require.NoError(t, err)
				c.data(id, true, lpm(0, "two"))
				for !r.done() {
					c.step(id, &r)
				}
				assert.Equal(t, lpm(0, "one"), r.data)
				require.Len(t, r.blocks, 2)
				assert.True(t, r.endOnBlock)
				assert.Equal(t, "14", r.trailer("grpc-status"))
				assert.Equal(t, "Unavailable", r.trailer("grpc-message"))
			})
		},
	},
	{
		id: "grpc/errors/2", name: "cancel_after_first_response, the client resets the stream with CANCEL",
		req: "Mapped to call cancellation when sent by a client.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, streamOrigin(t), h)
				c := b.client(t)
				id := c.call("/pkg.Svc/Method")
				c.data(id, false, lpm(0, "one"))
				var r grpcResult
				c.awaitData(id, &r, len(lpm(0, "one")))
				require.NoError(t, c.fr.WriteRSTStream(id, http2.ErrCodeCancel))
				assert.Error(t, b.origin.call(t).readErr, "the origin read a request stream the client never ended")
			})
		},
	},
	{
		id: "grpc/errors/3", name: "the origin resets the stream with INTERNAL_ERROR after one message",
		req: "RPC runtime implementations should interpret RST_STREAM as immediate full-closure of the stream and should propagate an error up to the calling application layer.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					w.Header().Set("Content-Type", "application/grpc")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(lpm(0, "one"))
					_ = http.NewResponseController(w).Flush()
					panic(http.ErrAbortHandler)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				if !r.reset {
					assert.Contains(t, []string{"", "13"}, grpcStatusOf(r), "INTERNAL_ERROR(2) maps to INTERNAL")
				}
			})
		},
	},
	{
		id: "interop/ping_pong", name: "four messages, each sent once the previous one came back",
		req: "This test verifies that full duplex bidi is supported.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, streamOrigin(t), h)
				c := b.client(t)
				id := c.call("/pkg.Svc/Method")
				var r grpcResult
				var want []byte
				for _, n := range []int{27182, 8, 1828, 45904} {
					msg := lpm(0, strings.Repeat("p", n))
					want = append(want, msg...)
					c.data(id, false, msg)
					c.awaitData(id, &r, len(want))
				}
				c.data(id, true, nil)
				for !r.done() {
					c.step(id, &r)
				}
				assert.Equal(t, want, r.data)
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "grpc/connection/1", name: "the origin closes its connection after one message",
		req: "Some data transmitted (e.g., request metadata written to TCP connection) before connection breaks |\tUNAVAILABLE | Client",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					w.Header().Set("Content-Type", "application/grpc")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(lpm(0, "one"))
					_ = http.NewResponseController(w).Flush()
					o.srv.CloseClientConnections()
					<-r.Context().Done()
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				if !r.reset {
					assert.Equal(t, "14", grpcStatusOf(r))
				}
			})
		},
	},
	{
		id: "grpc/connection/2", name: "the connection to the origin fails",
		req:  "If a detectable connection failure occurs on the client all calls will be closed with an UNAVAILABLE status.",
		skip: "edge is the client of the origin, grpc/connection/1 checks the same failure",
	},
	{
		id: "grpc/connection/3", name: "GOAWAY from either peer",
		req:  "Clients should consider any stream initiated after the last successfully accepted stream as UNAVAILABLE and retry the call elsewhere.",
		skip: "GOAWAY is sent and read by net/http's HTTP/2 server and transport on each connection edge terminates",
	},
	{
		id: "grpc/connection/4", name: "PING from either peer",
		req:  "Both clients and servers can send a PING frame that the peer must respond to by precisely echoing what they received.",
		skip: "PING is answered by net/http's HTTP/2 server and transport on each connection edge terminates",
	},
	{
		id: "grpc/security/1", name: "the TLS version of each connection",
		req:  "The HTTP2 specification mandates the use of TLS 1.2 or higher when TLS is used with HTTP2.",
		skip: "TLS is negotiated by crypto/tls on both connections",
	},
	{
		id: "grpc/retries/1", name: "a call that cannot be proven to have started",
		req:  "Calls that cannot be proven to have started will not be retried.",
		skip: "a forwarded call is retried only by net/http's HTTP/2 transport, which edge delegates the upstream request to",
	},
	{
		id: "statuscodes/2", name: "status_code_and_message, Fail with every code of the table",
		req: "The value portion of **Status** is a decimal-encoded integer as an ASCII string, without any leading zeros.",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(c *GRPCCtx) error {
				n, err := strconv.Atoi(c.Request().Header.Get("X-Code"))
				if err != nil {
					return err
				}
				return c.Fail(Code(n), "test status message")
			})
			c := b.client(t)
			for n := range 17 {
				r := c.unary("/pkg.Svc/Method", lpm(0, ""), "x-code", strconv.Itoa(n))
				assert.Equal(t, strconv.Itoa(n), grpcStatusOf(r))
				assert.Equal(t, "test status message", r.header("grpc-message"))
			}
		},
	},
	{
		id: "statuscodes/3", name: "the origin ends on a code outside the table",
		req: "gRPC libraries that encounter values outside this range must either propagate them directly or convert them to UNKNOWN.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w, nil, []string{"Grpc-Status", "42", "Grpc-Message", "future"}, call.body)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				assert.Contains(t, []string{"42", "2"}, r.trailer("grpc-status"))
			})
		},
	},
	{
		id: "statuscodes/4", name: "the handler panics",
		req: "Server side application throws an exception (or does something other than returning a Status code to terminate an RPC) |\tUNKNOWN | Server",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(*GRPCCtx) error { panic("boom") })
			r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
			assert.Equal(t, "2", grpcStatusOf(r))
		},
	},
	{
		id: "statuscodes/5", name: "a call no entry matches",
		req:  "Method not found at server\t| UNIMPLEMENTED | Server",
		skip: "edge refuses a unit no entry matches with 403 on purpose, CLAUDE.md states that nothing passes by default",
	},
	{
		id: "statuscodes/6", name: "a deadline that expires in the proxy",
		req:  "Deadline expires before server returns status\t| DEADLINE_EXCEEDED | Both",
		skip: "edge forwards grpc-timeout to the origin and sets no deadline of its own, grpc/requests/5 checks it",
	},
	{
		id: "statuscodes/7", name: "a message the endpoint cannot decompress",
		req:  "Could not decompress, but compression algorithm supported (Client -> Server)\t| INTERNAL | Server",
		skip: "edge never decompresses a message, CLAUDE.md states that a body is never decompressed by the proxy",
	},
	{
		id: "statuscodes/8", name: "a payload the endpoint cannot parse, or a cardinality it does not expect",
		req:  "Error parsing request proto\t| INTERNAL | Server",
		skip: "edge never decodes a payload and has no notion of a method's cardinality, the endpoints decide both",
	},
	{
		id: "statuscodes/9", name: "credentials the server refuses",
		req:  "Incorrect Auth metadata ( Credentials failed to get metadata, Incompatible credentials set on channel and call, Invalid host set in `:authority` metadata, etc.) | UNAUTHENTICATED | Both",
		skip: "edge authenticates the proxy connection with WithProxyAuth before any call exists, the call metadata is the origin's to check",
	},
	{
		id: "statuscodes/10", name: "a flow-control violation or a keepalive timeout",
		req:  "Flow-control protocol violation |\tINTERNAL | Both",
		skip: "flow control and keepalive are net/http's HTTP/2 server and transport",
	},
	{
		id: "statuscodes/11", name: "a status the client cannot parse",
		req:  "Error parsing returned status\t| UNKNOWN | Client",
		skip: "edge never parses the status of the origin, statuscodes/3 checks that it crosses",
	},
	{
		id: "statuscodes/12", name: "the proxy shuts down during a call",
		req:  "Server shutting down\t| UNAVAILABLE | Server",
		skip: "a shutdown sends GOAWAY through net/http's HTTP/2 server or closes the connection, and the client maps the latter to UNAVAILABLE",
	},
}

func TestKindGRPC_MessagesAreGatedAfterForwardReturns(t *testing.T) {
	o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		time.Sleep(300 * time.Millisecond)
		_ = o.record(r)
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
	b := newGRPCBench(t, o, forwardCall)
	r := b.client(t).unary("/pkg.Svc/Method", bytes.Repeat(lpm(0, ""), 10000))
	assert.Equal(t, "0", grpcStatusOf(r))
}

func TestKindGRPC_OpenCallEnds(t *testing.T) {
	m1, m2, big := lpm(0, "m1"), lpm(0, "m2"), lpm(0, strings.Repeat("b", 2*endMaxMessage))
	both := slices.Concat(m1, m2)
	answers := func(r *endRun, data []byte) []byte {
		if r.echoes() {
			return data
		}
		return []byte{}
	}

	natural := []endRow{
		{
			name:   "the client half-closes",
			origin: originEcho,
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				if r.echoes() {
					r.call.read(t, len(m1))
				}
				r.call.send(m2)
				r.call.closeSend()
				return r.call.result(t), true
			},
			want: func(*endRun) endWant {
				return endWant{data: both, code: "0", origin: []string{"m1", "m2"}, originEnd: originEOF}
			},
		},
		{
			name:   "the client resets the call",
			origin: originEcho,
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				if r.echoes() {
					r.call.read(t, len(m1))
				}
				r.call.reset()
				if r.fx.cell.client != HTTP3 {
					return endResult{}, false
				}
				return r.call.result(t), true
			},
			want: func(r *endRun) endWant {
				return endWant{data: answers(r, m1), code: "1", anyForm: !r.echoes(), origin: []string{"m1"}, originEnd: originCut}
			},
		},
		{
			name:   "the origin answers with trailers only",
			origin: originTrailersOnly,
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				if !r.duplex() {
					r.call.closeSend()
				}
				return r.call.result(t), true
			},
			want: func(*endRun) endWant {
				return endWant{data: []byte{}, code: "12", trailersOnly: true}
			},
		},
		{
			name:   "the origin ends while the request stream is open",
			origin: originAnswerFirst,
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				// Only an origin reached over HTTP/2 ends a read of Outbound before Inbound is asked
				// for, as the godoc of GRPCCtx.Outbound documents.
				if !r.duplex() || r.shape == "OutboundOnly" && r.fx.cell.origin != HTTP2 {
					r.waitGot(t, "m1")
					r.call.closeSend()
				}
				return r.call.result(t), true
			},
			want: func(r *endRun) endWant {
				w := endWant{data: lpm(0, "r"), code: "0", origin: []string{"m1"}}
				if r.duplex() && r.shape == "OutboundOnly" && r.fx.cell.origin == HTTP2 {
					w.returned = errOriginStopped
				}
				return w
			},
		},
		{
			name:   "the origin resets the call",
			origin: originReset,
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				if r.echoes() {
					r.call.read(t, len(m1))
				}
				close(r.release)
				r.call.closeSend()
				return r.call.result(t), true
			},
			want: func(r *endRun) endWant {
				w := endWant{reset: true, origin: []string{"m1"}}
				if r.echoes() {
					w.data = m1
				} else if r.fx.cell.origin == HTTP3 {
					// The RESET_STREAM of the origin may discard its response before the proxy reads it.
					w.alt = &endWant{data: []byte{}, code: "14", trailersOnly: true}
				}
				return w
			},
		},
		{
			name:   "the tree refuses the call",
			origin: originEcho,
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				if r.echoes() {
					r.call.read(t, len(m1))
				}
				_, err := r.fx.p.Delete[GRPC](r.pattern)
				require.NoError(t, err)
				r.call.send(m2)
				if !r.duplex() {
					r.call.closeSend()
				}
				return r.call.result(t), true
			},
			want: func(r *endRun) endWant {
				return endWant{data: answers(r, m1), code: "14", trailersOnly: !r.duplex(), anyForm: r.duplex() && !r.echoes(), origin: []string{"m1"}, originEnd: originCut}
			},
		},
		{
			name:   "a request message over the bound",
			origin: originEcho,
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				if r.echoes() {
					r.call.read(t, len(m1))
				}
				r.call.send(big)
				if !r.duplex() || r.shape == "Forward" {
					r.call.closeSend()
				}
				return r.call.result(t), true
			},
			want: func(r *endRun) endWant {
				if r.shape == "Forward" {
					return endWant{data: slices.Concat(m1, big), code: "0", origin: []string{"m1", string(big[5:])}, originEnd: originEOF}
				}
				return endWant{data: answers(r, m1), code: "8", trailersOnly: !r.duplex(), anyForm: r.duplex() && !r.echoes(), origin: []string{"m1"}, originEnd: originCut}
			},
		},
		{
			name:   "a response message over the bound",
			origin: originBig,
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.call.closeSend()
				return r.call.result(t), true
			},
			want: func(r *endRun) endWant {
				switch {
				case (r.shape == "Merge" || r.shape == "TwoGoroutines") && !r.duplex():
					return endWant{data: []byte{}, origin: []string{"m1"}, originEnd: originEOF, defect: defectH1Status}
				case r.shape == "Merge" || r.shape == "TwoGoroutines":
					return endWant{data: []byte{}, code: "8", origin: []string{"m1"}, originEnd: originEOF}
				}
				return endWant{data: big, code: "0", origin: []string{"m1"}, originEnd: originEOF}
			},
		},
		{
			name:   "the origin answers with a response that is not gRPC",
			origin: originNotGRPC,
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				if !r.duplex() {
					r.call.closeSend()
				}
				return r.call.result(t), true
			},
			want: func(*endRun) endWant {
				return endWant{data: []byte("nope"), status: http.StatusNotFound}
			},
		},
		{
			name:   "a request message sent after the response started reaches the origin",
			only:   func(c endCell) bool { return c.client == HTTP11 },
			origin: originEchoAtOnce,
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				if r.shape != "OutboundOnly" {
					r.call.read(t, len(m1))
				}
				r.call.send(m2)
				r.call.closeSend()
				return r.call.result(t), true
			},
			want: func(*endRun) endWant {
				return endWant{data: both, code: "0", origin: []string{"m1", "m2"}, originEnd: originEOF}
			},
		},
		{
			name:   "the origin ends while the client still sends its request",
			only:   func(c endCell) bool { return c.client == HTTP11 },
			origin: originAnswerFirst,
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				switch r.shape {
				case "OutboundOnly":
					// Only an origin reached over HTTP/2 ends a read of Outbound before Inbound
					// is asked for, as the godoc of GRPCCtx.Outbound documents.
					r.call.closeSend()
				}
				ended := make(chan endResult, 1)
				go func() { ended <- r.call.result(t) }()
				select {
				case res := <-ended:
					return res, true
				case <-time.After(3 * time.Second):
					t.Error("the call did not end while the client held its request stream open")
					r.call.closeSend()
					return <-ended, true
				}
			},
			want: func(*endRun) endWant {
				return endWant{data: lpm(0, "r"), code: "0", origin: []string{"m1"}}
			},
		},
		{
			name:   "the proxy closes",
			own:    true,
			origin: originEcho,
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				if r.echoes() {
					r.call.read(t, len(m1))
				}
				require.NoError(t, r.fx.p.Close())
				if !r.duplex() {
					// The HTTP/1.1 client returns once its request body ends.
					r.call.closeSend()
				}
				return r.call.result(t), true
			},
			want: func(*endRun) endWant {
				return endWant{reset: true, origin: []string{"m1"}, originEnd: originCut}
			},
		},
		{
			name:   "the proxy shuts down",
			own:    true,
			origin: originEcho,
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				if r.echoes() {
					r.call.read(t, len(m1))
				}
				shut := make(chan error, 1)
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					shut <- r.fx.p.Shutdown(ctx)
				}()
				r.call.send(m2)
				r.call.closeSend()
				res := r.call.result(t)
				select {
				case err := <-shut:
					assert.NoError(t, err)
				case <-time.After(10 * time.Second):
					t.Error("Shutdown did not return")
				}
				return res, true
			},
			want: func(*endRun) endWant {
				return endWant{data: both, code: "0", origin: []string{"m1", "m2"}, originEnd: originEOF}
			},
		},
		{
			name:   "the proxy shuts down past its deadline",
			own:    true,
			origin: originEcho,
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				if r.echoes() {
					r.call.read(t, len(m1))
				}
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				assert.ErrorIs(t, r.fx.p.Shutdown(ctx), context.DeadlineExceeded)
				if !r.duplex() {
					// The HTTP/1.1 client returns once its request body ends.
					r.call.closeSend()
				}
				return r.call.result(t), true
			},
			want: func(*endRun) endWant {
				return endWant{reset: true, origin: []string{"m1"}, originEnd: originCut}
			},
		},
	}

	sendAndEnd := func(t *testing.T, r *endRun) (endResult, bool) {
		r.call.send(m1)
		r.call.closeSend()
		return r.call.result(t), true
	}
	sendThenResult := func(t *testing.T, r *endRun) (endResult, bool) {
		r.call.send(m1)
		if !r.duplex() {
			r.call.closeSend()
		}
		return r.call.result(t), true
	}
	single := []endRow{
		{
			name:   "Fail after the origin answered",
			origin: originHold(true),
			handler: func(r *endRun) GRPC {
				return func(c *GRPCCtx) error {
					if err := c.Open(); err != nil {
						return err
					}
					m, err := c.Outbound().ReadMessage()
					if err != nil {
						return err
					}
					if err := m.Forward(); err != nil {
						return err
					}
					in, err := c.Inbound().ReadMessage()
					if err != nil {
						return err
					}
					if err := in.Forward(); err != nil {
						return err
					}
					_ = c.Fail(CodeResourceExhausted, "quota")
					if err := m.Forward(); err == nil {
						r.problem("a message forwarded toward the origin after Fail was accepted")
					}
					return nil
				}
			},
			script: sendThenResult,
			want: func(*endRun) endWant {
				return endWant{data: m1, code: "8", msg: "quota", origin: []string{"m1"}, originEnd: originCanceled}
			},
		},
		{
			name:   "Fail before the origin answered",
			origin: originHold(false),
			handler: func(r *endRun) GRPC {
				return func(c *GRPCCtx) error {
					if err := c.Open(); err != nil {
						return err
					}
					m, err := c.Outbound().ReadMessage()
					if err != nil {
						return err
					}
					if err := m.Forward(); err != nil {
						return err
					}
					select {
					case <-r.got:
					case <-time.After(5 * time.Second):
						r.problem("the origin did not read m1")
					}
					return c.Fail(CodePermissionDenied, "policy")
				}
			},
			script: sendThenResult,
			want: func(*endRun) endWant {
				return endWant{data: []byte{}, code: "7", msg: "policy", trailersOnly: true, origin: []string{"m1"}, originEnd: originCanceled}
			},
		},
		{
			name:   "Fail after Inbound ended replaces the status of the origin",
			origin: originEcho,
			handler: func(*endRun) GRPC {
				return func(c *GRPCCtx) error {
					if err := openCall(c); err != nil {
						return err
					}
					return c.Fail(CodeNotFound, "hidden")
				}
			},
			script: sendAndEnd,
			want: func(*endRun) endWant {
				return endWant{data: m1, code: "5", msg: "hidden", origin: []string{"m1"}, originEnd: originEOF}
			},
		},
		{
			name:   "the handler returns an error after Open",
			origin: originHold(true),
			handler: func(*endRun) GRPC {
				return func(c *GRPCCtx) error {
					if err := c.Open(); err != nil {
						return err
					}
					m, err := c.Outbound().ReadMessage()
					if err != nil {
						return err
					}
					if err := m.Forward(); err != nil {
						return err
					}
					if _, err := c.Response(); err != nil {
						return err
					}
					return errors.New("edge test: handler failure")
				}
			},
			script: sendThenResult,
			want: func(r *endRun) endWant {
				if !r.duplex() {
					return endWant{data: []byte{}, origin: []string{"m1"}, originEnd: originCanceled, defect: defectH1Status}
				}
				return endWant{data: []byte{}, code: "2", origin: []string{"m1"}, originEnd: originCanceled}
			},
		},
		{
			name:   "the handler returns nil with Inbound pending",
			origin: originHold(true),
			handler: func(*endRun) GRPC {
				return func(c *GRPCCtx) error {
					if err := c.Open(); err != nil {
						return err
					}
					m, err := c.Outbound().ReadMessage()
					if err != nil {
						return err
					}
					if err := m.Forward(); err != nil {
						return err
					}
					if err := c.CloseSend(); err != nil {
						return err
					}
					in, err := c.Inbound().ReadMessage()
					if err != nil {
						return err
					}
					return in.Forward()
				}
			},
			script: sendThenResult,
			want: func(*endRun) endWant {
				return endWant{data: m1, code: "13", origin: []string{"m1"}, originEnd: originCanceled}
			},
		},
		{
			name:   "a reply toward the client before the origin answered fails",
			origin: originRelease,
			handler: func(r *endRun) GRPC {
				return func(c *GRPCCtx) error {
					if err := c.Open(); err != nil {
						return err
					}
					m, err := c.Outbound().ReadMessage()
					if err != nil {
						return err
					}
					if err := m.Reply([]byte("early")); err == nil {
						r.problem("a reply before the origin answered was accepted")
					}
					if err := m.Forward(); err != nil {
						return err
					}
					close(r.release)
					return nil
				}
			},
			script: sendAndEnd,
			want: func(*endRun) endWant {
				return endWant{data: m1, code: "0", origin: []string{"m1"}, originEnd: originEOF}
			},
		},
		{
			name:   "Outbound read to its end before Open is half-closed at the return",
			origin: originEcho,
			handler: func(*endRun) GRPC {
				return func(c *GRPCCtx) error {
					out := c.Outbound()
					for {
						if _, err := out.ReadMessage(); errors.Is(err, io.EOF) {
							break
						} else if err != nil {
							return err
						}
					}
					return c.Open()
				}
			},
			script: sendAndEnd,
			want: func(*endRun) endWant {
				return endWant{data: []byte{}, code: "0", origin: []string{}, originEnd: originEOF}
			},
		},
		{
			name:   "a read of Outbound after the end of Inbound ends",
			origin: originAnswerFirst,
			handler: func(r *endRun) GRPC {
				return func(c *GRPCCtx) error {
					if err := c.Open(); err != nil {
						return err
					}
					out := c.Outbound()
					m, err := out.ReadMessage()
					if err != nil {
						return err
					}
					if err := m.Forward(); err != nil {
						return err
					}
					if err := forwardMessages(c.Inbound()); err != nil {
						return err
					}
					if m, err := out.ReadMessage(); err == nil {
						r.problem(fmt.Sprintf("the read of Outbound after the end of Inbound returned %q", m.Bytes()))
					} else if !errors.Is(err, io.EOF) {
						r.problem(fmt.Sprintf("the read of Outbound after the end of Inbound returned %v", err))
					}
					return nil
				}
			},
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(both)
				if !r.duplex() {
					r.call.closeSend()
				}
				return r.call.result(t), true
			},
			want: func(*endRun) endWant {
				return endWant{data: lpm(0, "r"), code: "0", origin: []string{"m1"}}
			},
		},
		{
			name:   "an error returned after CloseSend with a read of Inbound pending",
			origin: originHeadersThenHold,
			handler: func(*endRun) GRPC {
				return func(c *GRPCCtx) error {
					if err := c.Open(); err != nil {
						return err
					}
					src := MergeMessages(c.Outbound(), c.Inbound())
					m, err := src.ReadMessage()
					if err != nil {
						return err
					}
					if err := m.Forward(); err != nil {
						return err
					}
					if _, err := c.Response(); err != nil {
						return err
					}
					// The pump of Inbound reaches its read of the response body.
					time.Sleep(20 * time.Millisecond)
					if err := c.CloseSend(); err != nil {
						return err
					}
					return errors.New("edge test: handler failure")
				}
			},
			script: sendThenResult,
			want: func(r *endRun) endWant {
				if !r.duplex() {
					return endWant{data: []byte{}, origin: []string{"m1"}, originEnd: originCanceled, defect: defectH1Status}
				}
				return endWant{data: []byte{}, code: "2", origin: []string{"m1"}, originEnd: originCanceled}
			},
		},
		{
			name:   "a send toward an origin that stopped reading fails and the call ends on its answer with no message",
			only:   func(c endCell) bool { return c.origin == HTTP3 },
			origin: originStopThenAnswer,
			handler: func(r *endRun) GRPC {
				return func(c *GRPCCtx) error {
					defer close(r.release)
					if err := c.Open(); err != nil {
						return err
					}
					src := MergeMessages(c.Outbound(), c.Inbound())
					for {
						m, err := src.ReadMessage()
						if err != nil {
							return err
						}
						start := time.Now()
						err = m.Forward()
						if d := time.Since(start); d > time.Second {
							r.problem(fmt.Sprintf("a send toward an origin that stopped reading took %v", d))
						}
						if err != nil {
							return err
						}
					}
				}
			},
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				// The transport learns that the origin stopped reading on a write that follows.
				for range 250 {
					select {
					case <-r.release:
						return r.call.result(t), true
					case <-time.After(20 * time.Millisecond):
						r.call.send(m2)
					}
				}
				t.Error("the handler did not return")
				return r.call.result(t), true
			},
			want: func(*endRun) endWant {
				return endWant{data: []byte{}, code: "11", trailersOnly: true, origin: []string{"m1"}}
			},
		},
		{
			name:   "a send toward an origin that stopped reading fails and an answer with messages ends on Internal",
			only:   func(c endCell) bool { return c.origin == HTTP3 },
			origin: originStopThenAnswerMessage,
			handler: func(r *endRun) GRPC {
				return func(c *GRPCCtx) error {
					defer close(r.release)
					if err := c.Open(); err != nil {
						return err
					}
					src := MergeMessages(c.Outbound(), c.Inbound())
					for {
						m, err := src.ReadMessage()
						if err != nil {
							return err
						}
						start := time.Now()
						err = m.Forward()
						if d := time.Since(start); d > time.Second {
							r.problem(fmt.Sprintf("a send toward an origin that stopped reading took %v", d))
						}
						if err != nil {
							return err
						}
					}
				}
			},
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				// The transport learns that the origin stopped reading on a write that follows.
				for range 250 {
					select {
					case <-r.release:
						return r.call.result(t), true
					case <-time.After(20 * time.Millisecond):
						r.call.send(m2)
					}
				}
				t.Error("the handler did not return")
				return r.call.result(t), true
			},
			want: func(*endRun) endWant {
				return endWant{code: "13", origin: []string{"m1"}}
			},
		},
		{
			name:   "a request replaced by the handler is relayed until the origin ends",
			only:   func(c endCell) bool { return c.client == HTTP11 },
			origin: originAnswerFirst,
			handler: func(*endRun) GRPC {
				return func(c *GRPCCtx) error {
					c.SetRequest(replacedRequest(c.Request()))
					return c.Open()
				}
			},
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				return r.resultWithin(t, 3*time.Second), true
			},
			want: func(*endRun) endWant {
				return endWant{data: lpm(0, "r"), code: "0", origin: []string{"m1"}}
			},
		},
		{
			name:   "a request replaced by the handler ends once the origin ended",
			only:   func(c endCell) bool { return c.client != HTTP11 },
			origin: originAnswerFirst,
			handler: func(*endRun) GRPC {
				return func(c *GRPCCtx) error {
					c.SetRequest(replacedRequest(c.Request()))
					return openCall(c)
				}
			},
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				return r.resultWithin(t, 3*time.Second), true
			},
			want: func(*endRun) endWant {
				return endWant{data: lpm(0, "r"), code: "0", origin: []string{"m1"}}
			},
		},
		{
			name:   "a request stream of the handler that never ends ends with the call",
			origin: originAnswerFirst,
			handler: func(r *endRun) GRPC {
				return func(c *GRPCCtx) error {
					pr, pw := io.Pipe()
					go func() { _, _ = pw.Write(lpm(0, "m1")) }()
					go func() {
						<-r.release
						_ = pw.Close()
					}()
					in := c.Request()
					c.SetRequest((&http.Request{Method: in.Method, URL: in.URL, Header: in.Header, Host: in.Host, Body: pr, ContentLength: -1}).WithContext(in.Context()))
					return c.Open()
				}
			},
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				defer close(r.release)
				r.waitGot(t, "m1")
				ended := make(chan endResult, 1)
				go func() { ended <- r.call.result(t) }()
				select {
				case res := <-ended:
					return res, true
				case <-time.After(3 * time.Second):
					t.Error("the call did not end within 3s")
					r.release <- struct{}{}
					return <-ended, true
				}
			},
			want: func(*endRun) endWant {
				return endWant{data: lpm(0, "r"), code: "0", origin: []string{"m1"}}
			},
		},
		{
			name:   "a Fail while another goroutine reads Outbound ends the call",
			only:   func(c endCell) bool { return c.client == HTTP11 },
			origin: originAnswerFirstAnnounced,
			handler: func(*endRun) GRPC {
				return func(c *GRPCCtx) error {
					if err := c.Open(); err != nil {
						return err
					}
					failed := make(chan struct{})
					go func() {
						defer close(failed)
						_, _ = c.Inbound().ReadMessage()
						_ = c.Fail(CodeAborted, "stop")
					}()
					err := forwardMessages(c.Outbound())
					<-failed
					return err
				}
			},
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				return r.resultWithin(t, 3*time.Second), true
			},
			want: func(*endRun) endWant {
				return endWant{data: []byte{}, code: "10", msg: "stop", origin: []string{"m1"}}
			},
		},
		{
			name: "the context of the request stays live after Fail",
			// An origin that ended the call first would have the handler return before Fail.
			origin: originHoldAnnounced,
			handler: func(r *endRun) GRPC {
				return func(c *GRPCCtx) error {
					if err := c.Open(); err != nil {
						return err
					}
					if err := forwardMessages(c.Outbound()); err != nil {
						return err
					}
					select {
					case <-r.got:
					case <-time.After(5 * time.Second):
						r.problem("the origin did not read m1")
					}
					if err := c.Fail(CodeAborted, "stop"); err != nil {
						return err
					}
					time.Sleep(100 * time.Millisecond)
					if err := c.Context().Err(); err != nil {
						r.problem(fmt.Sprintf("the context of the request ended at Fail: %v", err))
					}
					return nil
				}
			},
			script: sendAndEnd,
			want: func(*endRun) endWant {
				return endWant{data: []byte{}, code: "10", msg: "stop", anyForm: true, origin: []string{"m1"}}
			},
		},
		{
			name:   "a read of Outbound in progress at Fail ends without the context",
			origin: originAnswerFirstAnnounced,
			handler: func(r *endRun) GRPC {
				return func(c *GRPCCtx) error {
					if err := c.Open(); err != nil {
						return err
					}
					out := c.Outbound()
					m, err := out.ReadMessage()
					if err != nil {
						return err
					}
					if err := m.Forward(); err != nil {
						return err
					}
					read := make(chan error, 1)
					go func() {
						_, err := out.ReadMessage()
						read <- err
					}()
					select {
					case <-r.got:
					case <-time.After(5 * time.Second):
						r.problem("the origin did not read m1")
					}
					if err := c.Fail(CodeAborted, "stop"); err != nil {
						return err
					}
					select {
					case <-read:
					case <-time.After(3 * time.Second):
						r.problem("a read of Outbound in progress did not end at Fail")
						return nil
					}
					if err := c.Context().Err(); err != nil {
						r.problem(fmt.Sprintf("the context of the request ended at Fail: %v", err))
					}
					return nil
				}
			},
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				return r.resultWithin(t, 5*time.Second), true
			},
			want: func(*endRun) endWant {
				return endWant{data: []byte{}, code: "10", msg: "stop", anyForm: true, origin: []string{"m1"}}
			},
		},
		{
			name:   "a nil return after the half-close and before the answer ends at once",
			origin: originHold(false),
			handler: func(r *endRun) GRPC {
				return func(c *GRPCCtx) error {
					if err := c.Open(); err != nil {
						return err
					}
					_ = c.Inbound()
					if err := forwardMessages(c.Outbound()); err != nil {
						return err
					}
					select {
					case <-r.got:
					case <-time.After(5 * time.Second):
						r.problem("the origin did not read m1")
					}
					// The transport closes the request stream it has sent to its end.
					time.Sleep(50 * time.Millisecond)
					return nil
				}
			},
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.call.closeSend()
				start := time.Now()
				res := r.call.result(t)
				if d := time.Since(start); d > 2*time.Second {
					t.Errorf("the client read the end of the call after %v", d)
				}
				return res, true
			},
			want: func(*endRun) endWant {
				return endWant{data: []byte{}, code: "13", trailersOnly: true, origin: []string{"m1"}, originEnd: originCanceled}
			},
		},
		{
			name:   "a nil return after the origin stopped reading ends at once",
			only:   func(c endCell) bool { return c.origin == HTTP3 },
			origin: originStopThenHold,
			handler: func(r *endRun) GRPC {
				return func(c *GRPCCtx) error {
					defer close(r.release)
					if err := c.Open(); err != nil {
						return err
					}
					_ = c.Inbound()
					_ = forwardMessages(c.Outbound())
					return nil
				}
			},
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.waitGot(t, "m1")
				for range 250 {
					select {
					case <-r.release:
						start := time.Now()
						res := r.call.result(t)
						if d := time.Since(start); d > 2*time.Second {
							t.Errorf("the client read the end of the call after %v", d)
						}
						return res, true
					case <-time.After(20 * time.Millisecond):
						r.call.send(m2)
					}
				}
				t.Error("the handler did not return")
				return r.call.result(t), true
			},
			want: func(*endRun) endWant {
				return endWant{data: []byte{}, code: "13", trailersOnly: true, origin: []string{"m1"}, originEnd: originCanceled}
			},
		},
		{
			name:   "a read of Outbound pending at the return and its relay",
			only:   func(c endCell) bool { return c.client != HTTP11 },
			origin: originEcho,
			handler: func(r *endRun) GRPC {
				return func(c *GRPCCtx) error {
					if err := c.Open(); err != nil {
						return err
					}
					src := MergeMessages(c.Outbound(), c.Inbound())
					for range 2 {
						m, err := src.ReadMessage()
						if err != nil {
							return err
						}
						if err := m.Forward(); err != nil {
							return err
						}
					}
					<-r.release
					// The pump of Outbound reads m2, and the relay that follows the return m3.
					time.Sleep(10 * time.Millisecond)
					return nil
				}
			},
			script: func(t *testing.T, r *endRun) (endResult, bool) {
				r.call.send(m1)
				r.call.read(t, len(m1))
				r.call.send(m2)
				r.call.send(lpm(0, "m3"))
				close(r.release)
				return r.call.result(t), true
			},
			want: func(*endRun) endWant {
				return endWant{code: "13"}
			},
		},
	}

	for _, cell := range endCells {
		t.Run(cell.String(), func(t *testing.T) {
			t.Parallel()
			fx := newEndFixture(t, cell)
			for _, row := range natural {
				if row.only != nil && !row.only(cell) {
					continue
				}
				for _, s := range endShapes {
					t.Run(row.name+"/"+s.name, func(t *testing.T) {
						f := fx
						if row.own {
							f = newEndFixture(t, cell)
						}
						f.run(t, &row, s.name, func(*endRun) GRPC { return s.h })
					})
				}
			}
			for _, row := range single {
				if row.only != nil && !row.only(cell) {
					continue
				}
				t.Run(row.name, func(t *testing.T) {
					fx.run(t, &row, "", row.handler)
				})
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			assert.NoError(t, fx.p.Shutdown(ctx), "a call of the cell did not end")
		})
	}
}

func TestKindGRPC_OpenCallToAnUnreachableOriginEndsOnUnavailable(t *testing.T) {
	m1 := lpm(0, "m1")
	afterAnswer := func(c *GRPCCtx) error {
		if err := c.Open(); err != nil {
			return err
		}
		_ = c.Inbound()
		m, err := c.Outbound().ReadMessage()
		if err != nil {
			return err
		}
		_, _ = c.Response()
		return m.Forward()
	}
	shapes := append(slices.Clip(endShapes), endShape{afterAnswer, "SendAfterTheAnswer"})
	for _, client := range []Protocol{HTTP2, HTTP3} {
		fx := newUnreachableEndFixture(t, client)
		for _, s := range shapes {
			t.Run(map[Protocol]string{HTTP2: "client h2", HTTP3: "client h3"}[client]+"/"+s.name, func(t *testing.T) {
				for range 3 {
					path := "/end.Svc/R" + strconv.FormatInt(fx.next.Add(1), 10)
					fx.p.MustAdd("origin.test"+path, s.h)
					var call endCall
					if client == HTTP3 {
						call = fx.h3Call(t, path)
					} else {
						call = fx.h2Call(t, path)
					}
					call.send(m1)
					res := call.result(t)
					assert.Equal(t, "14", res.code, "grpc-status")
				}
			})
		}
	}
}

func TestKindGRPC_HTTP11CallEndsItsConnection(t *testing.T) {
	fx := newEndFixture(t, endCell{HTTP11, HTTP11})
	openAndForwardOne := func(c *GRPCCtx) error {
		if err := c.Open(); err != nil {
			return err
		}
		m, err := c.Outbound().ReadMessage()
		if err != nil {
			return err
		}
		return m.Forward()
	}
	// The status the proxy sets is lost where defectH1Status applies.
	codes := map[string]string{
		"Forward": "0", "OpenOnly": "0", "FailAfterTheAnswer": "", "ErrorAfterTheAnswer": "",
		"CloseSendThenInbound": "0", "FailBeforeOpen": "7",
	}
	shapes := []endShape{
		{forwardCall, "Forward"},
		{func(c *GRPCCtx) error { return c.Open() }, "OpenOnly"},
		{func(c *GRPCCtx) error {
			if err := openAndForwardOne(c); err != nil {
				return err
			}
			_, _ = c.Inbound().ReadMessage()
			return c.Fail(CodeAborted, "stop")
		}, "FailAfterTheAnswer"},
		{func(c *GRPCCtx) error {
			if err := openAndForwardOne(c); err != nil {
				return err
			}
			_, _ = c.Inbound().ReadMessage()
			return errors.New("edge test: handler failure")
		}, "ErrorAfterTheAnswer"},
		{func(c *GRPCCtx) error {
			if err := openAndForwardOne(c); err != nil {
				return err
			}
			if err := c.CloseSend(); err != nil {
				return err
			}
			return forwardMessages(c.Inbound())
		}, "CloseSendThenInbound"},
		{func(c *GRPCCtx) error {
			if _, err := c.Outbound().ReadMessage(); err != nil {
				return err
			}
			return c.Fail(CodePermissionDenied, "no")
		}, "FailBeforeOpen"},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			path := "/end.Svc/R" + strconv.FormatInt(fx.next.Add(1), 10)
			r := &endRun{
				fx: fx, row: &endRow{origin: originAnswerFirst},
				got: make(chan string, 16), obs: make(chan endObs, 1), proto: make(chan string, 1),
				returned: make(chan error, 1), release: make(chan struct{}),
			}
			fx.runs.Store(path, r)
			defer fx.runs.Delete(path)
			fx.p.MustAdd("origin.test"+path, s.h)
			defer func() { _, _ = fx.p.Delete[GRPC]("origin.test" + path) }()

			tc, br := rawH1Call(t, fx, path)
			_, err := tc.Write(chunk(lpm(0, "m1")))
			require.NoError(t, err)
			require.NoError(t, tc.SetReadDeadline(time.Now().Add(5*time.Second)))
			resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodPost})
			require.NoError(t, err)
			_, err = io.ReadAll(resp.Body)
			require.NoError(t, err, "the response ends while the client keeps its request open")
			assert.True(t, resp.Close, "the response announces the end of its connection")
			code, _ := grpcStatus(resp)
			assert.Equal(t, codes[s.name], code, "grpc-status")

			require.NoError(t, tc.SetReadDeadline(time.Now().Add(time.Second)))
			n, err := tc.Read(make([]byte, 1))
			var ne net.Error
			assert.Zero(t, n, "bytes after the response")
			assert.Error(t, err, "the connection ended after the call")
			assert.False(t, errors.As(err, &ne) && ne.Timeout(), "the connection ended after the call: %v", err)
		})
	}
}

// rawH1Call opens a call over HTTP/1.1 inside a CONNECT and leaves its chunked request body
// open.
func rawH1Call(t *testing.T, fx *endFixture, path string) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	raw := connectRaw(t, fx.addr, "origin.test:443")
	tc := tls.Client(raw, &tls.Config{ServerName: "origin.test", RootCAs: fx.ca.CertPool(), NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	require.NoError(t, tc.Handshake())
	_, err := io.WriteString(tc, "POST "+path+" HTTP/1.1\r\nHost: origin.test\r\nContent-Type: application/grpc\r\nTe: trailers\r\nTransfer-Encoding: chunked\r\n\r\n")
	require.NoError(t, err)
	return tc, bufio.NewReader(tc)
}

func chunk(b []byte) []byte {
	return []byte(strconv.FormatInt(int64(len(b)), 16) + "\r\n" + string(b) + "\r\n")
}

func newUnreachableEndFixture(t *testing.T, client Protocol) *endFixture {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	dead := ln.Addr().String()
	require.NoError(t, ln.Close())
	fx := &endFixture{ca: ca, cell: endCell{client: client, origin: HTTP2}}
	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(dead)
	tr.RootCAs = poolOf(ca)
	fx.p = testProxyWithCA(t, ca, WithTransport(tr), WithMaxMessageBytes(endMaxMessage))
	if client == HTTP3 {
		fx.h3, _ = startQUICFront(t, fx.p, ca)
	} else {
		fx.addr = startProxy(t, fx.p)
	}
	return fx
}

const endMaxMessage = 1 << 10

type endCell struct{ client, origin Protocol }

var endCells = []endCell{
	{HTTP11, HTTP11}, {HTTP2, HTTP11}, {HTTP2, HTTP2}, {HTTP3, HTTP11}, {HTTP3, HTTP2}, {HTTP3, HTTP3},
}

func (c endCell) String() string {
	short := map[Protocol]string{HTTP11: "h1", HTTP2: "h2", HTTP3: "h3"}
	return "client " + short[c.client] + " origin " + short[c.origin]
}

type endShape struct {
	h    GRPC
	name string
}

var endShapes = []endShape{
	{forwardCall, "Forward"},
	{func(c *GRPCCtx) error { return c.Open() }, "OpenOnly"},
	{forwardOutbound, "OutboundOnly"},
	{openCall, "Merge"},
	{forwardApart, "TwoGoroutines"},
}

func forwardMessages(r *MessageReader) error {
	for {
		m, err := r.ReadMessage()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := m.Forward(); err != nil {
			return err
		}
	}
}

func forwardOutbound(c *GRPCCtx) error {
	if err := c.Open(); err != nil {
		return err
	}
	return forwardMessages(c.Outbound())
}

func forwardApart(c *GRPCCtx) error {
	if err := c.Open(); err != nil {
		return err
	}
	ended := make(chan error, 2)
	go func() { ended <- forwardMessages(c.Outbound()) }()
	go func() { ended <- forwardMessages(c.Inbound()) }()
	err := <-ended
	if next := <-ended; err == nil {
		err = next
	}
	return err
}

type endRow struct {
	origin  func(r *endRun, w http.ResponseWriter, req *http.Request)
	handler func(r *endRun) GRPC
	script  func(t *testing.T, r *endRun) (endResult, bool)
	want    func(r *endRun) endWant
	only    func(c endCell) bool
	name    string
	own     bool
}

type originEnd uint8

const (
	originUnchecked originEnd = iota
	originEOF
	originCut
	originCanceled
)

// Defects of the current code. A row with a defect asserts the current behavior.
const (
	defectH1Status = "on an HTTP/1.1 client, the status the proxy sets is lost when no message reached the client and the origin announced no trailer"
)

type endWant struct {
	alt          *endWant
	returned     error
	defect       string
	data         []byte
	origin       []string
	code         string
	msg          string
	status       int
	originEnd    originEnd
	trailersOnly bool
	// anyForm leaves the form of the status unchecked, for a call cut while the response of the
	// origin may still be on its way.
	anyForm bool
	reset   bool
}

type endResult struct {
	data         []byte
	code, msg    string
	status       int
	trailersOnly bool
	reset        bool
}

type endObs struct {
	err      error
	msgs     []string
	canceled bool
}

type endRun struct {
	fx       *endFixture
	row      *endRow
	call     endCall
	got      chan string
	obs      chan endObs
	proto    chan string
	returned chan error
	release  chan struct{}
	shape    string
	pattern  string
	problems []string
	mu       sync.Mutex
}

func (r *endRun) duplex() bool { return r.fx.cell.client != HTTP11 }

// echoes reports whether a response message reaches the client before the request stream ends.
func (r *endRun) echoes() bool { return r.duplex() && r.shape != "OutboundOnly" }

func (r *endRun) problem(s string) {
	r.mu.Lock()
	r.problems = append(r.problems, s)
	r.mu.Unlock()
}

// resultWithin reads the end of the call while the client keeps its request open, and ends the
// request if the call does not end within d.
func (r *endRun) resultWithin(t *testing.T, d time.Duration) endResult {
	t.Helper()
	ended := make(chan endResult, 1)
	go func() { ended <- r.call.result(t) }()
	select {
	case res := <-ended:
		return res
	case <-time.After(d):
		t.Errorf("the call did not end within %v while the client kept its request open", d)
		r.call.closeSend()
		return <-ended
	}
}

func replacedRequest(in *http.Request) *http.Request {
	return (&http.Request{Method: in.Method, URL: in.URL, Header: in.Header, Host: in.Host, Body: in.Body, ContentLength: in.ContentLength}).WithContext(in.Context())
}

func (r *endRun) waitGot(t *testing.T, want string) {
	t.Helper()
	select {
	case m := <-r.got:
		assert.Equal(t, want, m)
	case <-time.After(5 * time.Second):
		t.Errorf("the origin did not read %s", want)
	}
}

func (r *endRun) readRequest(req *http.Request, each func(m []byte)) endObs {
	src := &msgSource{r: req.Body, max: 1 << 20}
	var obs endObs
	obs.msgs = []string{}
	for {
		payload, flag, err := src.next()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				obs.err = err
			}
			return obs
		}
		obs.msgs = append(obs.msgs, string(payload))
		r.got <- string(payload)
		if each != nil {
			each(lpm(flag, string(payload)))
		}
	}
}

type endFixture struct {
	p    *Proxy
	ca   *CA
	addr string
	h3   netip.AddrPort
	runs sync.Map
	next atomic.Int64
	cell endCell
}

func newEndFixture(t *testing.T, cell endCell) *endFixture {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	cert := selfSignedFor(t, ca, "origin.test")
	fx := &endFixture{ca: ca, cell: cell}
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		v, ok := fx.runs.Load(req.URL.Path)
		if !ok {
			http.NotFound(w, req)
			return
		}
		r := v.(*endRun)
		r.proto <- req.Proto
		_ = http.NewResponseController(w).EnableFullDuplex()
		r.row.origin(r, w, req)
	})
	var addr string
	if cell.origin == HTTP3 {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		srv := &http3.Server{
			Handler:   h,
			TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}),
		}
		go func() { _ = srv.Serve(pc) }()
		t.Cleanup(func() {
			_ = srv.Close()
			_ = pc.Close()
		})
		addr = pc.LocalAddr().String()
	} else {
		srv := httptest.NewUnstartedServer(h)
		srv.EnableHTTP2 = cell.origin == HTTP2
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		addr = srv.Listener.Addr().String()
	}
	tr := DefaultTransport()
	tr.AllowHTTP3 = cell.origin == HTTP3
	tr.DialContext = pinnedDialer(addr)
	tr.RootCAs = poolOf(ca)
	fx.p = testProxyWithCA(t, ca, WithTransport(tr), WithMaxMessageBytes(endMaxMessage))
	if cell.client == HTTP3 {
		fx.h3, _ = startQUICFront(t, fx.p, ca)
	} else {
		fx.addr = startProxy(t, fx.p)
	}
	return fx
}

func (fx *endFixture) run(t *testing.T, row *endRow, shape string, handler func(*endRun) GRPC) {
	path := "/end.Svc/R" + strconv.FormatInt(fx.next.Add(1), 10)
	r := &endRun{
		fx: fx, row: row, shape: shape, pattern: "origin.test" + path,
		got: make(chan string, 16), obs: make(chan endObs, 1), proto: make(chan string, 1),
		returned: make(chan error, 1), release: make(chan struct{}),
	}
	fx.runs.Store(path, r)
	defer fx.runs.Delete(path)
	h := handler(r)
	fx.p.MustAdd(r.pattern, func(c *GRPCCtx) error {
		err := h(c)
		r.returned <- err
		return err
	})
	defer func() { _, _ = fx.p.Delete[GRPC](r.pattern) }()

	switch fx.cell.client {
	case HTTP11:
		r.call = fx.h1Call(t, path)
	case HTTP2:
		r.call = fx.h2Call(t, path)
	default:
		r.call = fx.h3Call(t, path)
	}
	res, read := row.script(t, r)
	want := row.want(r)
	if want.defect != "" {
		t.Logf("known defect: %s", want.defect)
	}
	if want.alt != nil && res.reset != want.reset {
		want.data, want.code, want.trailersOnly, want.reset = want.alt.data, want.alt.code, want.alt.trailersOnly, want.alt.reset
	}

	if read {
		if want.data != nil {
			assert.Equal(t, want.data, res.data, "response messages")
		}
		assert.Equal(t, want.reset, res.reset, "reset of the response")
		if !want.reset {
			status := want.status
			if status == 0 {
				status = http.StatusOK
			}
			assert.Equal(t, status, res.status, "HTTP status")
			assert.Equal(t, want.code, res.code, "grpc-status")
			if want.msg != "" {
				assert.Equal(t, want.msg, res.msg, "grpc-message")
			}
			if !want.anyForm {
				assert.Equal(t, want.trailersOnly, res.trailersOnly, "trailers-only")
			}
		}
	}

	select {
	case proto := <-r.proto:
		assert.Equal(t, map[Protocol]string{HTTP11: "HTTP/1.1", HTTP2: "HTTP/2.0", HTTP3: "HTTP/3.0"}[fx.cell.origin], proto, "protocol at the origin")
	case <-time.After(5 * time.Second):
		t.Error("the origin received no call")
	}
	if want.origin != nil || want.originEnd != originUnchecked {
		select {
		case obs := <-r.obs:
			if want.origin != nil {
				assert.Equal(t, want.origin, obs.msgs, "messages the origin read")
			}
			switch want.originEnd {
			case originEOF:
				assert.NoError(t, obs.err, "the read of the request stream at the origin")
				assert.False(t, obs.canceled, "the origin was canceled")
			case originCut:
				assert.Error(t, obs.err, "the read of the request stream at the origin")
			case originCanceled:
				assert.True(t, obs.canceled, "the origin was canceled")
			}
		case <-time.After(5 * time.Second):
			t.Error("the origin did not end its read of the request stream")
		}
	}
	var returned error
	select {
	case returned = <-r.returned:
		if want.returned != nil {
			assert.ErrorIs(t, returned, want.returned, "the error the handler returned")
		}
	case <-time.After(5 * time.Second):
		t.Error("the handler did not return")
	}
	r.mu.Lock()
	assert.Empty(t, r.problems)
	r.mu.Unlock()
	if t.Failed() {
		t.Logf("response %+v, handler returned %v", res, returned)
	}
}

func originEcho(r *endRun, w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Trailer", "Grpc-Status")
	rc := http.NewResponseController(w)
	var held []byte
	obs := r.readRequest(req, func(m []byte) {
		if !r.duplex() {
			held = append(held, m...)
			return
		}
		_, _ = w.Write(m)
		_ = rc.Flush()
	})
	r.obs <- obs
	if obs.err != nil {
		panic(http.ErrAbortHandler)
	}
	_, _ = w.Write(held)
	w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
}

// originEchoAtOnce is originEcho answering each message as it arrives, on every client.
func originEchoAtOnce(r *endRun, w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Trailer", "Grpc-Status")
	rc := http.NewResponseController(w)
	obs := r.readRequest(req, func(m []byte) {
		_, _ = w.Write(m)
		_ = rc.Flush()
	})
	r.obs <- obs
	if obs.err != nil {
		panic(http.ErrAbortHandler)
	}
	w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
}

func originTrailersOnly(_ *endRun, w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", "12")
	w.WriteHeader(http.StatusOK)
}

func originAnswerFirst(r *endRun, w http.ResponseWriter, req *http.Request) {
	src := &msgSource{r: req.Body, max: 1 << 20}
	payload, _, err := src.next()
	if err != nil {
		r.obs <- endObs{err: err}
		panic(http.ErrAbortHandler)
	}
	r.got <- string(payload)
	r.obs <- endObs{msgs: []string{string(payload)}}
	answerOK(w, lpm(0, "r"))
}

func originReset(r *endRun, w http.ResponseWriter, req *http.Request) {
	src := &msgSource{r: req.Body, max: 1 << 20}
	payload, flag, err := src.next()
	if err != nil {
		r.obs <- endObs{err: err}
		panic(http.ErrAbortHandler)
	}
	r.got <- string(payload)
	r.obs <- endObs{msgs: []string{string(payload)}}
	w.Header().Set("Content-Type", "application/grpc")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(lpm(flag, string(payload)))
	_ = http.NewResponseController(w).Flush()
	select {
	case <-r.release:
	case <-time.After(5 * time.Second):
	}
	panic(http.ErrAbortHandler)
}

func originBig(r *endRun, w http.ResponseWriter, req *http.Request) {
	obs := r.readRequest(req, nil)
	r.obs <- obs
	if obs.err != nil {
		panic(http.ErrAbortHandler)
	}
	answerOK(w, lpm(0, strings.Repeat("b", 2*endMaxMessage)))
}

func originNotGRPC(_ *endRun, w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "nope")
}

// originHold reads the first message, echoes it when answer is set, reads the rest of the
// request and waits for the proxy to cancel it.
func originHold(answer bool) func(r *endRun, w http.ResponseWriter, req *http.Request) {
	return func(r *endRun, w http.ResponseWriter, req *http.Request) {
		src := &msgSource{r: req.Body, max: 1 << 20}
		payload, flag, err := src.next()
		if err != nil {
			r.obs <- endObs{err: err}
			panic(http.ErrAbortHandler)
		}
		r.got <- string(payload)
		if answer {
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(lpm(flag, string(payload)))
			_ = http.NewResponseController(w).Flush()
		}
		obs := endObs{msgs: []string{string(payload)}}
		for err == nil {
			_, _, err = src.next()
		}
		if !errors.Is(err, io.EOF) {
			obs.err = err
		}
		select {
		case <-req.Context().Done():
			obs.canceled = true
		case <-time.After(5 * time.Second):
		}
		r.obs <- obs
	}
}

// originHoldAnnounced is originHold answering, its trailer announced.
func originHoldAnnounced(r *endRun, w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Trailer", "Grpc-Status")
	originHold(true)(r, w, req)
}

// originHeadersThenHold answers headers with no message, reads the request to its end and
// waits for the proxy to cancel it.
func originHeadersThenHold(r *endRun, w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/grpc")
	w.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(w).Flush()
	obs := r.readRequest(req, nil)
	select {
	case <-req.Context().Done():
		obs.canceled = true
	case <-time.After(5 * time.Second):
	}
	r.obs <- obs
}

// originAnswerFirstAnnounced is originAnswerFirst announcing its trailer.
func originAnswerFirstAnnounced(r *endRun, w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Trailer", "Grpc-Status")
	originAnswerFirst(r, w, req)
}

// originStopThenHold reads the first message, stops reading the request and waits for the
// proxy to cancel it.
func originStopThenHold(r *endRun, w http.ResponseWriter, req *http.Request) {
	src := &msgSource{r: req.Body, max: 1 << 20}
	payload, _, err := src.next()
	if err != nil {
		r.obs <- endObs{err: err}
		panic(http.ErrAbortHandler)
	}
	r.got <- string(payload)
	_ = req.Body.Close()
	obs := endObs{msgs: []string{string(payload)}}
	select {
	case <-req.Context().Done():
		obs.canceled = true
	case <-time.After(5 * time.Second):
	}
	r.obs <- obs
}

// originStopThenAnswer reads the first message, stops reading the request and answers with
// a trailers-only response once the handler has returned.
func originStopThenAnswer(r *endRun, w http.ResponseWriter, req *http.Request) {
	src := &msgSource{r: req.Body, max: 1 << 20}
	payload, _, err := src.next()
	if err != nil {
		r.obs <- endObs{err: err}
		panic(http.ErrAbortHandler)
	}
	r.got <- string(payload)
	_ = req.Body.Close()
	select {
	case <-r.release:
	case <-time.After(5 * time.Second):
	}
	r.obs <- endObs{msgs: []string{string(payload)}}
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", "11")
	w.WriteHeader(http.StatusOK)
}

// originStopThenAnswerMessage is originStopThenAnswer with a message before the status.
func originStopThenAnswerMessage(r *endRun, w http.ResponseWriter, req *http.Request) {
	src := &msgSource{r: req.Body, max: 1 << 20}
	payload, _, err := src.next()
	if err != nil {
		r.obs <- endObs{err: err}
		panic(http.ErrAbortHandler)
	}
	r.got <- string(payload)
	_ = req.Body.Close()
	select {
	case <-r.release:
	case <-time.After(5 * time.Second):
	}
	r.obs <- endObs{msgs: []string{string(payload)}}
	answer(w, nil, []string{"Grpc-Status", "11"}, lpm(0, "r"))
}

func originRelease(r *endRun, w http.ResponseWriter, req *http.Request) {
	src := &msgSource{r: req.Body, max: 1 << 20}
	payload, flag, err := src.next()
	if err != nil {
		r.obs <- endObs{err: err}
		panic(http.ErrAbortHandler)
	}
	r.got <- string(payload)
	select {
	case <-r.release:
	case <-time.After(5 * time.Second):
	}
	obs := endObs{msgs: []string{string(payload)}}
	for err == nil {
		_, _, err = src.next()
	}
	if !errors.Is(err, io.EOF) {
		obs.err = err
	}
	r.obs <- obs
	answerOK(w, lpm(flag, string(payload)))
}

type endCall interface {
	send(b []byte)
	closeSend()
	reset()
	read(t *testing.T, n int)
	result(t *testing.T) endResult
}

type endH1 struct {
	pw     *io.PipeWriter
	cancel context.CancelFunc
	resp   chan *http.Response
	err    error
	r      *http.Response
	data   []byte
}

func (fx *endFixture) h1Call(t *testing.T, path string) endCall {
	t.Helper()
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://origin.test"+path, pr)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	tr := &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: fx.addr}),
		TLSClientConfig: &tls.Config{RootCAs: fx.ca.CertPool(), MinVersion: tls.VersionTLS12},
	}
	t.Cleanup(tr.CloseIdleConnections)
	c := &endH1{pw: pw, cancel: cancel, resp: make(chan *http.Response, 1)}
	go func() {
		resp, err := tr.RoundTrip(req)
		if err != nil {
			c.err = err
		}
		c.resp <- resp
	}()
	return c
}

func (c *endH1) send(b []byte) { _, _ = c.pw.Write(b) }

func (c *endH1) closeSend() { _ = c.pw.Close() }

func (c *endH1) reset() {
	c.cancel()
	_ = c.pw.CloseWithError(errors.New("edge test: client reset"))
}

func (c *endH1) response(t *testing.T) *http.Response {
	t.Helper()
	if c.r == nil {
		select {
		case c.r = <-c.resp:
		case <-time.After(10 * time.Second):
			t.Fatal("no response")
		}
	}
	return c.r
}

func (c *endH1) read(t *testing.T, n int) {
	t.Helper()
	resp := c.response(t)
	require.NotNil(t, resp, "%v", c.err)
	b := make([]byte, n)
	_, err := io.ReadFull(resp.Body, b)
	require.NoError(t, err)
	c.data = append(c.data, b...)
}

func (c *endH1) result(t *testing.T) endResult {
	t.Helper()
	resp := c.response(t)
	if resp == nil {
		return endResult{data: c.data, reset: true}
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	res := endResult{data: append(c.data, b...), status: resp.StatusCode, reset: err != nil}
	if res.data == nil {
		res.data = []byte{}
	}
	res.code, res.msg = grpcStatus(resp)
	res.trailersOnly = resp.Trailer.Get("Grpc-Status") == "" && resp.Header.Get("Grpc-Status") != ""
	return res
}

type endH2 struct {
	c       *grpcClient
	conn    net.Conn
	connErr error
	res     grpcResult
	id      uint32
}

func (fx *endFixture) h2Call(t *testing.T, path string) endCall {
	t.Helper()
	raw := connectRaw(t, fx.addr, "origin.test:443")
	tc := tls.Client(raw, &tls.Config{ServerName: "origin.test", RootCAs: fx.ca.CertPool(), NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	require.NoError(t, tc.Handshake())
	require.Equal(t, "h2", tc.ConnectionState().NegotiatedProtocol)
	require.NoError(t, tc.SetDeadline(time.Now().Add(10*time.Second)))
	_, err := io.WriteString(tc, http2.ClientPreface)
	require.NoError(t, err)
	c := &grpcClient{t: t, fr: http2.NewFramer(tc, tc), authority: "origin.test:443", next: 1}
	c.enc = hpack.NewEncoder(&c.buf)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	c.fr.MaxHeaderListSize = 1 << 20
	require.NoError(t, c.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 30}))
	require.NoError(t, c.fr.WriteWindowUpdate(0, 1<<30))
	return &endH2{c: c, conn: tc, id: c.call(path)}
}

func (c *endH2) send(b []byte) { _ = c.c.fr.WriteData(c.id, false, b) }

func (c *endH2) closeSend() { _ = c.c.fr.WriteData(c.id, true, nil) }

func (c *endH2) reset() { _ = c.c.fr.WriteRSTStream(c.id, http2.ErrCodeCancel) }

func (c *endH2) step() bool {
	f, err := c.c.fr.ReadFrame()
	if err != nil {
		c.connErr = err
		return false
	}
	switch f := f.(type) {
	case *http2.SettingsFrame:
		if !f.IsAck() {
			_ = c.c.fr.WriteSettingsAck()
		}
	case *http2.PingFrame:
		if !f.IsAck() {
			_ = c.c.fr.WritePing(true, f.Data)
		}
	case *http2.MetaHeadersFrame:
		if f.StreamID == c.id {
			c.res.blocks = append(c.res.blocks, f.Fields)
			if f.StreamEnded() {
				c.res.ended, c.res.endOnBlock = true, true
			}
		}
	case *http2.DataFrame:
		if f.StreamID == c.id {
			c.res.data = append(c.res.data, f.Data()...)
			c.res.ended = f.StreamEnded()
		}
	case *http2.RSTStreamFrame:
		if f.StreamID == c.id {
			c.res.reset, c.res.rst = true, f.ErrCode
		}
	}
	return true
}

func (c *endH2) read(t *testing.T, n int) {
	t.Helper()
	for len(c.res.data) < n && !c.res.done() && c.step() {
	}
	require.Len(t, c.res.data, n, "%v", c.connErr)
}

func (c *endH2) result(*testing.T) endResult {
	for !c.res.done() && c.step() {
	}
	_ = c.conn.Close()
	res := endResult{data: c.res.data, reset: c.res.reset || c.connErr != nil}
	if res.data == nil {
		res.data = []byte{}
	}
	res.status, _ = strconv.Atoi(c.res.header(":status"))
	res.trailersOnly = len(c.res.blocks) == 1 && c.res.endOnBlock
	res.code = grpcStatusOf(c.res)
	if res.trailersOnly {
		res.msg = c.res.header("grpc-message")
	} else {
		res.msg = c.res.trailer("grpc-message")
	}
	return res
}

type endH3 struct {
	str  *http3.RequestStream
	resp *http.Response
	err  error
	data []byte
}

func (fx *endFixture) h3Call(t *testing.T, path string) endCall {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tr := &http3.Transport{DisableCompression: true}
	t.Cleanup(func() { _ = tr.Close() })
	str, err := tr.NewClientConn(dialQUICFront(t, fx.h3, fx.ca)).OpenRequestStream(ctx)
	require.NoError(t, err)
	require.NoError(t, str.SetDeadline(time.Now().Add(10*time.Second)))
	req, err := http.NewRequest(http.MethodPost, "https://origin.test"+path, http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	require.NoError(t, str.SendRequestHeader(req))
	return &endH3{str: str}
}

func (c *endH3) send(b []byte) { _, _ = c.str.Write(b) }

func (c *endH3) closeSend() { _ = c.str.Close() }

func (c *endH3) reset() { c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled)) }

func (c *endH3) response() *http.Response {
	if c.resp == nil && c.err == nil {
		c.resp, c.err = c.str.ReadResponse()
	}
	return c.resp
}

func (c *endH3) read(t *testing.T, n int) {
	t.Helper()
	require.NotNil(t, c.response(), "%v", c.err)
	b := make([]byte, n)
	_, err := io.ReadFull(c.str, b)
	require.NoError(t, err)
	c.data = append(c.data, b...)
}

func (c *endH3) result(*testing.T) endResult {
	resp := c.response()
	if resp == nil {
		return endResult{data: c.data, reset: true}
	}
	b, err := io.ReadAll(c.str)
	res := endResult{data: append(c.data, b...), status: resp.StatusCode, reset: err != nil}
	if res.data == nil {
		res.data = []byte{}
	}
	res.code, res.msg = grpcStatus(resp)
	res.trailersOnly = resp.Trailer.Get("Grpc-Status") == "" && resp.Header.Get("Grpc-Status") != ""
	return res
}

var grpcCallShapes = []struct {
	h    GRPC
	name string
}{
	{forwardCall, "Forward"},
	{func(c *GRPCCtx) error { return c.Open() }, "OpenOnly"},
	{openCall, "Merge"},
}

func grpcCaller(tb testing.TB, h GRPC, h1 bool) func(body []byte) error {
	tb.Helper()
	ca, err := GenerateCA()
	require.NoError(tb, err)
	leaf, err := ca.Leaf("origin.test")
	require.NoError(tb, err)
	origin := httptest.NewUnstartedServer(grpcEchoHandler(nil))
	origin.EnableHTTP2 = true
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}}
	origin.StartTLS()
	tb.Cleanup(origin.Close)
	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(origin.Listener.Addr().String())
	tr.RootCAs = poolOf(ca)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(tb, err)
	p.MustAdd("origin.test/pkg.Svc/Chat", h)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(tb, err)
	go func() { _ = p.Serve(ln) }()
	tb.Cleanup(func() { _ = p.Close() })
	client := h2Client(ln.Addr().String(), ca.CertPool())
	if h1 {
		client = proxyClient(ln.Addr().String(), ca.CertPool())
	}
	tb.Cleanup(client.CloseIdleConnections)
	rd := new(bytes.Reader)
	return func(body []byte) error {
		rd.Reset(body)
		req, err := http.NewRequest(http.MethodPost, "https://origin.test/pkg.Svc/Chat", rd)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/grpc")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		n, err := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		switch {
		case err != nil:
			return err
		case n != int64(len(body)):
			return fmt.Errorf("echoed %d bytes of %d", n, len(body))
		case resp.Trailer.Get("Grpc-Status") != "0":
			return fmt.Errorf("grpc-status %q", resp.Trailer.Get("Grpc-Status"))
		}
		return nil
	}
}

func BenchmarkKindGRPC_CallOverHTTP11(b *testing.B) {
	for _, s := range grpcCallShapes {
		for _, n := range []int{1, 100} {
			b.Run(s.name+"/"+strconv.Itoa(n), func(b *testing.B) {
				call := grpcCaller(b, s.h, true)
				var body []byte
				for range n {
					body = append(body, lpm(0, "hello")...)
				}
				b.ReportAllocs()
				for b.Loop() {
					if err := call(body); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkKindGRPC_Call(b *testing.B) {
	for _, s := range grpcCallShapes {
		for _, n := range []int{1, 100} {
			b.Run(s.name+"/"+strconv.Itoa(n), func(b *testing.B) {
				call := grpcCaller(b, s.h, false)
				var body []byte
				for range n {
					body = append(body, lpm(0, "hello")...)
				}
				b.ReportAllocs()
				for b.Loop() {
					if err := call(body); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func TestKindGRPC_CallAllocs(t *testing.T) {
	ceilings := map[string]float64{"Forward": 250, "OpenOnly": 265, "Merge": 279}
	body := lpm(0, "hello")
	for _, s := range grpcCallShapes {
		t.Run(s.name, func(t *testing.T) {
			call := grpcCaller(t, s.h, false)
			allocs := testing.AllocsPerRun(200, func() {
				if err := call(body); err != nil {
					t.Fatal(err)
				}
			})
			assert.LessOrEqual(t, allocs, ceilings[s.name])
		})
	}
}

func TestCallPipe_MatchesIOPipe(t *testing.T) {
	type pipe struct {
		r          io.Reader
		w          io.Writer
		closeRead  func(error)
		closeWrite func(error)
	}
	errA, errB := errors.New("a"), errors.New("b")
	obs := func(n int, err error) string { return fmt.Sprintf("%d %v", n, err) }
	read := func(p pipe, n int) string {
		b := make([]byte, n)
		n, err := p.r.Read(b)
		return fmt.Sprintf("%q %v", b[:n], err)
	}
	write := func(p pipe, s string) string { return obs(p.w.Write([]byte(s))) }
	writing := func(p pipe, s string) <-chan string {
		done := make(chan string, 1)
		go func() { done <- write(p, s) }()
		return done
	}
	cases := []struct {
		script func(p pipe) []string
		name   string
	}{
		{name: "a write is read in pieces", script: func(p pipe) []string {
			done := writing(p, "hello")
			return []string{read(p, 2), read(p, 2), read(p, 2), <-done}
		}},
		{name: "the reader closes during a write", script: func(p pipe) []string {
			done := writing(p, "hello")
			first := read(p, 1)
			p.closeRead(nil)
			return []string{first, <-done, read(p, 1), write(p, "x")}
		}},
		{name: "the reader closes with an error", script: func(p pipe) []string {
			done := writing(p, "hello")
			first := read(p, 1)
			p.closeRead(errA)
			return []string{first, <-done, read(p, 1), write(p, "x")}
		}},
		{name: "the writer closes", script: func(p pipe) []string {
			p.closeWrite(nil)
			return []string{read(p, 1), write(p, "x")}
		}},
		{name: "the writer closes with an error", script: func(p pipe) []string {
			p.closeWrite(errA)
			return []string{read(p, 1), write(p, "x")}
		}},
		{name: "both ends close", script: func(p pipe) []string {
			p.closeWrite(errA)
			p.closeRead(errB)
			return []string{read(p, 1), write(p, "x")}
		}},
		{name: "the first error of an end is kept", script: func(p pipe) []string {
			p.closeRead(errA)
			p.closeRead(errB)
			return []string{write(p, "x")}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pr, pw := io.Pipe()
			want := tc.script(pipe{
				r: pr, w: pw,
				closeRead:  func(err error) { _ = pr.CloseWithError(err) },
				closeWrite: func(err error) { _ = pw.CloseWithError(err) },
			})
			cp := new(callPipe)
			cp.init()
			got := tc.script(pipe{r: cp, w: cp, closeRead: cp.closeRead, closeWrite: cp.closeWrite})
			assert.Equal(t, want, got)
		})
	}
}

// customRun registers a run of fx with its own origin and returns it with its path.
func customRun(fx *endFixture, origin func(r *endRun, w http.ResponseWriter, req *http.Request)) (*endRun, string) {
	path := "/end.Svc/R" + strconv.FormatInt(fx.next.Add(1), 10)
	r := &endRun{
		fx: fx, row: &endRow{origin: origin},
		got: make(chan string, 16), obs: make(chan endObs, 16), proto: make(chan string, 16),
		returned: make(chan error, 16), release: make(chan struct{}),
	}
	fx.runs.Store(path, r)
	return r, path
}

// countStacks counts the goroutines with a stack that contains sub.
func countStacks(sub string) int {
	buf := make([]byte, 1<<22)
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), sub)
}

// readGRPCResponse reads the response of a raw HTTP/1.1 call and its gRPC status.
func readGRPCResponse(t *testing.T, tc *tls.Conn, br *bufio.Reader, d time.Duration) (*http.Response, string, error) {
	_ = tc.SetReadDeadline(time.Now().Add(d))
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodPost})
	if err != nil {
		return nil, "", err
	}
	_, err = io.ReadAll(resp.Body)
	code, _ := grpcStatus(resp)
	return resp, code, err
}

func TestKindGRPC_HTTP11CallNeverOpenedLeavesNoReader(t *testing.T) {
	fx := newEndFixture(t, endCell{HTTP11, HTTP11})
	before := countStacks("h1Reader).run")
	const calls = 10
	for i := range calls {
		_, path := customRun(fx, originAnswerFirst)
		var h GRPC
		switch i % 2 {
		case 0:
			h = func(c *GRPCCtx) error {
				if _, err := c.Outbound().ReadMessage(); err != nil {
					return err
				}
				return c.Fail(CodePermissionDenied, "no")
			}
		default:
			h = func(c *GRPCCtx) error {
				_ = c.Outbound()
				return c.Forward()
			}
		}
		fx.p.MustAdd("origin.test"+path, h)
		tc, br := rawH1Call(t, fx, path)
		_, err := tc.Write(chunk(lpm(0, "m1")))
		require.NoError(t, err)
		_, err = tc.Write([]byte("0\r\n\r\n"))
		require.NoError(t, err)
		_, _, err = readGRPCResponse(t, tc, br, 5*time.Second)
		require.NoError(t, err)
		_ = tc.Close()
	}
	time.Sleep(500 * time.Millisecond)
	after := countStacks("h1Reader).run")
	if after > before {
		t.Errorf("%d h1Reader goroutines left after %d calls ended", after-before, calls)
	}
}

func TestKindGRPC_HTTP11ForwardOfAReplacedBodyEndsWhileTheClientSends(t *testing.T) {
	fx := newEndFixture(t, endCell{HTTP11, HTTP11})
	_, path := customRun(fx, func(r *endRun, w http.ResponseWriter, req *http.Request) {
		obs := r.readRequest(req, nil)
		r.obs <- obs
		answerOK(w, lpm(0, "r"))
	})
	fx.p.MustAdd("origin.test"+path, func(c *GRPCCtx) error {
		req := c.Request().Clone(c.Context())
		req.Body = io.NopCloser(bytes.NewReader(lpm(0, "rewritten")))
		req.ContentLength = -1
		c.SetRequest(req)
		return c.Forward()
	})
	tc, br := rawH1Call(t, fx, path)
	_, err := tc.Write(chunk(lpm(0, "m1")))
	require.NoError(t, err)
	_, _, err = readGRPCResponse(t, tc, br, 4*time.Second)
	require.NoError(t, err, "the call ends while the client keeps its request open")
}

func TestKindGRPC_HTTP11ForwardToAnUnreachableOriginEndsWhileTheClientSends(t *testing.T) {
	fx := newUnreachableEndFixture(t, HTTP11)
	path := "/end.Svc/R1"
	fx.p.MustAdd("origin.test"+path, forwardCall)
	tc, br := rawH1Call(t, fx, path)
	_, err := tc.Write(chunk(lpm(0, "m1")))
	require.NoError(t, err)
	_, code, err := readGRPCResponse(t, tc, br, 4*time.Second)
	require.NoError(t, err, "the call ends while the client keeps its request open")
	require.Equal(t, "14", code)
}

func TestKindGRPC_HTTP11CallThatReadItsBodyKeepsItsConnection(t *testing.T) {
	seen := new(recorder)
	origin := h2cOrigin(t, grpcEchoHandler(seen))
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	p := testProxy(t)
	p.MustAdd(originHost(originURL)+"/pkg.Svc/Method", func(c *GRPCCtx) error { return c.Forward() })
	client := proxyClient(startProxy(t, p), nil)
	for i := range 3 {
		var reused bool
		ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin.URL+"/pkg.Svc/Method", bytes.NewReader(grpcPayload("hello")))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/grpc")
		resp, err := client.Do(req)
		require.NoError(t, err)
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.Equal(t, "0", resp.Trailer.Get("Grpc-Status"))
		require.False(t, resp.Close, "call %d announced the close of its connection", i)
		require.Equal(t, i > 0, reused, "call %d", i)
	}
}
