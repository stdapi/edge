// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
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

// Send replaces the message in its direction, toward the origin and toward the client.
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

// Reply answers the peer a message came from. On a response message it goes to the origin as
// a request message, on a request message it goes to the client and the origin sees nothing.
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

// Fail on an open call ends it on the status the handler chose. What was forwarded before
// stays, the client reads the status in the trailers, and the origin is canceled.
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

// Fail before the origin answered is a trailers-only response with the handler's status.
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

// A status the handler sets after the origin failed on its own is the one the client reads,
// and a send toward the client reports the failure.
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

// A status the handler sets after a failed Forward is the one the client reads.
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

// A client that leaves mid-response ends the copy toward it early. The handler still runs
// and may write the trailers of the response, which the proxy then leaves alone.
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

// Once Inbound ended, the origin's status is readable on the response and Fail replaces it.
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

// A handler that returns while Inbound is still running ended the call without a status, and
// the client reads Internal.
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

// A unary handler that forwards the one request message and returns leaves the end of the
// request stream to the proxy, and the client reads the response of the origin.
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

// The request messages a client sends after the handler returned reach the origin, and the
// response streams back meanwhile.
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

// A request stream the client cuts after the handler returned is reset toward the origin.
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

// A request message sent after the handler returned is still decided on the tree and bounded.
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

// An origin that ends the call before the client ends its request stream ends it for the
// client as well, after the handler returned.
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

// A handler that returns from a merge while a read of Outbound is pending ends the call on
// Internal, and the request stream is not read twice at once.
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

// An error returned after Open reaches the client as the status it maps to.
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

// Forward refuses a call whose request stream was read, and the origin is not reached.
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

// Response gives the origin's headers once it answered and its trailers once Inbound ended.
// Trailers left in it when the handler returns are what the client reads.
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

// Send clears the compressed flag and SendCompressed sets it, whatever the flag of the message
// read. Forward keeps it.
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

// A message over WithMaxMessageBytes is refused in both directions, and a call it ends
// reports ResourceExhausted.
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

// A message is read in full whatever the DATA frames it crossed, the origin here flushing
// inside the header, inside the payload and between two messages, over HTTP/2 on both sides.
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

// A gRPC call in the clear reaches an h2c origin over HTTP/2. The client spoke HTTP/2 with
// prior knowledge to a destination it declared, and no ALPN could have asked the origin.
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
