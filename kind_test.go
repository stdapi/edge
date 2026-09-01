// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A datagram is its own unit, so a handler sees each one, in both directions, and dropping one
// is something it may do.
func TestKindUDP_HandlerSeesEveryDatagramBothWays(t *testing.T) {
	origin := udpEchoOrigin(t)

	var out, in atomic.Int64
	p, err := New()
	require.NoError(t, err)
	p.MustAdd("[0.0.0.0/0]:"+fmt.Sprint(origin.Port()), func(d *DatagramCtx) error {
		if d.Inbound() {
			in.Add(1)
			return d.Forward()
		}
		out.Add(1)
		if strings.HasPrefix(string(d.Bytes()), "drop") {
			return d.Drop()
		}
		return d.Send([]byte("seen:" + string(d.Bytes())))
	})

	_, proxyAddr := startTProxyQUIC(t, p, origin)

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))

	_, err = client.WriteTo([]byte("hello"), net.UDPAddrFromAddrPort(proxyAddr))
	require.NoError(t, err)

	buf := make([]byte, 256)
	n, _, err := client.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "seen:hello", string(buf[:n]), "the handler rewrote the datagram on its way out")

	// A dropped datagram never reaches the origin, so nothing comes back for it.
	_, err = client.WriteTo([]byte("drop-me"), net.UDPAddrFromAddrPort(proxyAddr))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
	_, _, err = client.ReadFrom(buf)
	require.Error(t, err, "a dropped datagram has no answer")

	assert.Equal(t, int64(2), out.Load(), "both datagrams reached the handler")
	assert.Equal(t, int64(1), in.Load(), "the answer to the one forwarded did too")
}

// A datagram flow is admitted per datagram, so removing the entry stops it at the next one
// rather than at the next flow.
func TestKindUDP_DeleteStopsTheFlowAtTheNextDatagram(t *testing.T) {
	origin := udpEchoOrigin(t)

	p, err := New()
	require.NoError(t, err)
	pattern := "[0.0.0.0/0]:" + fmt.Sprint(origin.Port())
	p.MustAdd(pattern, forwardDatagram)

	_, proxyAddr := startTProxyQUIC(t, p, origin)

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, err = client.WriteTo([]byte("first"), net.UDPAddrFromAddrPort(proxyAddr))
	require.NoError(t, err)
	buf := make([]byte, 256)
	n, _, err := client.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "first", string(buf[:n]))

	_, err = p.Delete[UDP](pattern)
	require.NoError(t, err)

	// The flow is still open, and the next datagram is refused on it.
	_, err = client.WriteTo([]byte("second"), net.UDPAddrFromAddrPort(proxyAddr))
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
	_, _, err = client.ReadFrom(buf)
	require.Error(t, err, "the entry is gone, so the next datagram is not carried")
}

// Past the 101 the unit is the frame, and a handler sees each one in both directions.
func TestKindWebSocket_HandlerSeesFrames(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("origin hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()

		// Read one frame and answer with one of its own, unmasked as a server must.
		r2 := &wsReader{r: brw, max: 1 << 20}
		f, rerr := r2.read()
		if rerr != nil {
			return
		}
		w2 := &wsWriter{w: conn}
		_ = w2.write(NewFrame(OpText, []byte("echo:"+string(f.Payload()))))
		time.Sleep(200 * time.Millisecond)
	}))
	defer origin.Close()
	originURL, _ := url.Parse(origin.URL)

	var pings, seen atomic.Int64
	p := testProxy(t)
	p.MustAdd(originHost(originURL)+"/ws", func(c *WebSocketCtx) error {
		assert.Equal(t, originHost(originURL), c.Target().Host)
		src := MergeFrames(c.Outbound(), c.Inbound())
		for {
			f, err := src.ReadFrame()
			if err != nil {
				return nil
			}
			if f.Opcode() == OpPing {
				pings.Add(1)
				continue
			}
			seen.Add(1)
			if werr := f.Forward(); werr != nil {
				return werr
			}
		}
	})

	raw, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	_, err = fmt.Fprintf(raw, "GET %s/ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		origin.URL, originURL.Host)
	require.NoError(t, err)

	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	// A ping the handler swallows, then a text frame it lets through.
	cw := &wsWriter{w: raw, mask: true}
	require.NoError(t, cw.write(NewFrame(OpPing, nil)))
	require.NoError(t, cw.write(NewFrame(OpText, []byte("hi"))))

	require.NoError(t, raw.SetReadDeadline(time.Now().Add(3*time.Second)))
	cr := &wsReader{r: br, max: 1 << 20}
	got, err := cr.read()
	require.NoError(t, err)
	assert.Equal(t, OpText, got.Opcode())
	assert.Equal(t, "echo:hi", string(got.Payload()))

	assert.Equal(t, int64(1), pings.Load(), "the ping was swallowed rather than relayed")
	assert.GreaterOrEqual(t, seen.Load(), int64(2), "the text frame and the answer went through")
}

// A gRPC entry and an HTTP entry can name the same path, and the content type is what tells
// them apart.
func TestKindGRPC_ContentTypeSelectsTheEntry(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		_, _ = w.Write(body)
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer origin.Close()

	p, host, client := interceptingProxy(t, origin)
	_, err := p.Delete[HTTP](host + "/*{any}")
	require.NoError(t, err)

	var httpHits, grpcHits atomic.Int64
	p.MustAdd(host+"/pkg.Svc/Method", func(c *HTTPCtx) (*http.Response, error) {
		httpHits.Add(1)
		return Text(http.StatusOK, "plain http"), nil
	})
	var messages atomic.Int64
	p.MustAdd(host+"/pkg.Svc/Method", func(c *GRPCCtx) error {
		grpcHits.Add(1)
		assert.Equal(t, "pkg.Svc", c.Service())
		assert.Equal(t, "Method", c.Method())
		if err := c.Open(); err != nil {
			return err
		}
		src := MergeMessages(c.Outbound(), c.Inbound())
		for {
			m, err := src.ReadMessage()
			if err != nil {
				return nil
			}
			messages.Add(1)
			if werr := m.Forward(); werr != nil {
				return werr
			}
		}
	})

	// A plain request on the same path takes the HTTP entry.
	resp, err := client.Get(origin.URL + "/pkg.Svc/Method")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, "plain http", string(body))
	assert.Equal(t, int64(1), httpHits.Load())
	assert.Equal(t, int64(0), grpcHits.Load())

	// The same path with a gRPC content type takes the gRPC entry.
	var payload []byte
	payload = appendGRPCMessage(payload, false, []byte("ping"))
	req, err := http.NewRequest(http.MethodPost, origin.URL+"/pkg.Svc/Method", strings.NewReader(string(payload)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/grpc+proto")

	resp, err = client.Do(req)
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, int64(1), grpcHits.Load())
	assert.Equal(t, payload, body, "the messages the callback passed on are what the client reads")
	assert.GreaterOrEqual(t, messages.Load(), int64(1))
}

// A failed call never reaches the server and comes back as a status, which is how a gRPC
// client reads an error at all.
func TestKindGRPC_FailAnswersWithoutTheServer(t *testing.T) {
	var reached atomic.Int64
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
	}))
	defer origin.Close()

	p, host, client := interceptingProxy(t, origin)
	_, err := p.Delete[HTTP](host + "/*{any}")
	require.NoError(t, err)

	p.MustAdd(host+"/pkg.Svc/Method", func(c *GRPCCtx) error {
		return c.Fail(Unavailable, "upstream flaky")
	})

	req, err := http.NewRequest(http.MethodPost, origin.URL+"/pkg.Svc/Method", strings.NewReader(""))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "a gRPC failure is a 200 carrying a status")
	assert.Equal(t, "14", resp.Header.Get("Grpc-Status"))
	assert.Equal(t, "upstream flaky", resp.Header.Get("Grpc-Message"))
	assert.Equal(t, int64(0), reached.Load(), "the server was never reached")
}

// A stream entry sees the bytes in the clear and can rewrite them, TLS having been terminated
// on both sides.
func TestKindTCP_HandlerRewritesTheStream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 64)
				n, rerr := c.Read(buf)
				if rerr != nil {
					return
				}
				_, _ = c.Write([]byte("origin saw " + string(buf[:n])))
			}()
		}
	}()

	p := testProxy(t)
	p.MustAdd[TCP](ln.Addr().String(), func(c *TCPCtx) error {
		up, derr := c.Dial()
		if derr != nil {
			return derr
		}
		buf := make([]byte, 64)
		n, rerr := c.Client().Read(buf)
		if rerr != nil {
			return rerr
		}
		if _, werr := up.Write([]byte(strings.ToUpper(string(buf[:n])))); werr != nil {
			return werr
		}
		answer := make([]byte, 128)
		n, rerr = up.Read(answer)
		if rerr != nil {
			return rerr
		}
		_, werr := c.Client().Write(answer[:n])
		return werr
	})

	conn := connectRaw(t, startProxy(t, p), ln.Addr().String())
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "origin saw HELLO", string(buf[:n]))
}

// A handler can answer the sender of a datagram directly, the origin never seeing it.
func TestKindUDP_ReplyAnswersWithoutTheOrigin(t *testing.T) {
	origin := udpEchoOrigin(t)

	p, err := New()
	require.NoError(t, err)
	p.MustAdd("[0.0.0.0/0]:"+fmt.Sprint(origin.Port()), func(d *DatagramCtx) error {
		if !d.Inbound() && string(d.Bytes()) == "blocked" {
			return d.Reply([]byte("nx"))
		}
		return d.Forward()
	})

	_, proxyAddr := startTProxyQUIC(t, p, origin)

	client, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))

	_, err = client.WriteTo([]byte("blocked"), net.UDPAddrFromAddrPort(proxyAddr))
	require.NoError(t, err)
	buf := make([]byte, 256)
	n, _, err := client.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "nx", string(buf[:n]), "the answer is the handler's, not the origin's echo")

	// Nothing else comes back: the datagram was answered locally, never forwarded.
	require.NoError(t, client.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
	_, _, err = client.ReadFrom(buf)
	require.Error(t, err)

	// The flow still forwards what the handler lets through.
	require.NoError(t, client.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, err = client.WriteTo([]byte("hello"), net.UDPAddrFromAddrPort(proxyAddr))
	require.NoError(t, err)
	n, _, err = client.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf[:n]))
}

// A frame handler can answer the peer that sent a frame, the other peer never seeing it.
func TestKindWebSocket_ReplyAnswersThePinger(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("origin hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()

		// The first frame the origin sees must be the text one, the ping being absorbed by
		// the proxy.
		r2 := &wsReader{r: brw, max: 1 << 20}
		f, rerr := r2.read()
		if rerr != nil {
			return
		}
		w2 := &wsWriter{w: conn}
		_ = w2.write(NewFrame(OpText, []byte("origin:"+f.Opcode().String())))
		time.Sleep(200 * time.Millisecond)
	}))
	defer origin.Close()
	originURL, _ := url.Parse(origin.URL)

	p := testProxy(t)
	p.MustAdd(originHost(originURL)+"/ws", func(c *WebSocketCtx) error {
		src := MergeFrames(c.Outbound(), c.Inbound())
		for {
			f, err := src.ReadFrame()
			if err != nil {
				return nil
			}
			if !f.Inbound() && f.Opcode() == OpPing {
				if rerr := f.Reply(NewFrame(OpPong, f.Payload())); rerr != nil {
					return rerr
				}
				continue
			}
			if werr := f.Forward(); werr != nil {
				return werr
			}
		}
	})

	raw, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	_, err = fmt.Fprintf(raw, "GET %s/ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		origin.URL, originURL.Host)
	require.NoError(t, err)

	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	cw := &wsWriter{w: raw, mask: true}
	require.NoError(t, cw.write(NewFrame(OpPing, []byte("k"))))
	require.NoError(t, cw.write(NewFrame(OpText, []byte("hi"))))

	require.NoError(t, raw.SetReadDeadline(time.Now().Add(3*time.Second)))
	cr := &wsReader{r: br, max: 1 << 20}

	pong, err := cr.read()
	require.NoError(t, err)
	assert.Equal(t, OpPong, pong.Opcode(), "the proxy answered the ping itself")
	assert.Equal(t, "k", string(pong.Payload()))

	echoed, err := cr.read()
	require.NoError(t, err)
	assert.Equal(t, "origin:text", string(echoed.Payload()), "the origin never saw the ping")
}

// The request messages are readable before the call is opened, so a handler can decide on the
// first one and fail without the origin ever being touched.
func TestKindGRPC_DecideOnTheFirstMessage(t *testing.T) {
	var reached atomic.Int64
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		_, _ = w.Write(body)
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer origin.Close()

	p, host, client := interceptingProxy(t, origin)
	_, err := p.Delete[HTTP](host + "/*{any}")
	require.NoError(t, err)

	p.MustAdd(host+"/pkg.Svc/Method", func(c *GRPCCtx) error {
		m, rerr := c.Outbound().ReadMessage()
		if rerr != nil {
			return rerr
		}
		if string(m.Bytes()) == "forbidden" {
			return c.Fail(PermissionDenied, "policy")
		}
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		if ferr := m.Forward(); ferr != nil {
			return ferr
		}
		src := MergeMessages(c.Outbound(), c.Inbound())
		for {
			mm, merr := src.ReadMessage()
			if merr != nil {
				return nil
			}
			if ferr := mm.Forward(); ferr != nil {
				return ferr
			}
		}
	})

	call := func(msg string) *http.Response {
		var payload []byte
		payload = appendGRPCMessage(payload, false, []byte(msg))
		req, rerr := http.NewRequest(http.MethodPost, origin.URL+"/pkg.Svc/Method", strings.NewReader(string(payload)))
		require.NoError(t, rerr)
		req.Header.Set("Content-Type", "application/grpc")
		resp, derr := client.Do(req)
		require.NoError(t, derr)
		return resp
	}

	resp := call("forbidden")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, "7", resp.Header.Get("Grpc-Status"))
	assert.Equal(t, int64(0), reached.Load(), "the failed call never reached the origin")

	resp = call("hello")
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var want []byte
	want = appendGRPCMessage(want, false, []byte("hello"))
	assert.Equal(t, want, body, "the message read before opening was forwarded after")
	assert.Equal(t, int64(1), reached.Load())
}

// DialTo opens the stream's far side somewhere else than the client asked, with the same
// transport the proxy dials with.
func TestKindTCP_DialToReroutesTheStream(t *testing.T) {
	lineEcho := func(prefix string) string {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				go func() {
					defer func() { _ = c.Close() }()
					buf := make([]byte, 256)
					n, rerr := c.Read(buf)
					if rerr != nil {
						return
					}
					_, _ = c.Write([]byte(prefix + string(buf[:n])))
				}()
			}
		}()
		return ln.Addr().String()
	}
	asked := lineEcho("asked:")
	other := lineEcho("other:")

	p := testProxy(t)
	p.MustAdd[TCP](asked, func(c *TCPCtx) error {
		up, derr := c.DialTo(c.Context(), other)
		if derr != nil {
			return derr
		}
		_, _, rerr := Relay(c.Client(), up)
		return rerr
	})

	conn := connectRaw(t, startProxy(t, p), asked)
	_, err := conn.Write([]byte("ping"))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "other:ping", string(buf[:n]), "the stream went where the handler dialed")
}

// grpcEchoOrigin answers a call with the messages it received and an OK status in the
// trailers, counting how many messages reached it.
func grpcEchoOrigin(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var received atomic.Int64
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		src := &msgSource{r: strings.NewReader(string(body))}
		for {
			if _, _, err := src.next(); err != nil {
				break
			}
			received.Add(1)
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		_, _ = w.Write(body)
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	}))
	t.Cleanup(origin.Close)
	return origin, &received
}

func grpcPayload(msgs ...string) []byte {
	var payload []byte
	for _, m := range msgs {
		payload = appendGRPCMessage(payload, false, []byte(m))
	}
	return payload
}

// A handler that opens the call, pumps the request stream and returns leaves the response to
// the proxy: a direction it never took a reader for is relayed unchanged, trailers included.
func TestKindGRPC_UntakenInboundIsRelayed(t *testing.T) {
	origin, received := grpcEchoOrigin(t)
	p, host, client := interceptingProxy(t, origin)
	_, err := p.Delete[HTTP](host + "/*{any}")
	require.NoError(t, err)

	var forwarded atomic.Int64
	p.MustAdd(host+"/pkg.Svc/Stream", func(c *GRPCCtx) error {
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		out := c.Outbound()
		for {
			m, rerr := out.ReadMessage()
			if rerr != nil {
				return nil
			}
			forwarded.Add(1)
			if ferr := m.Forward(); ferr != nil {
				return ferr
			}
		}
	})

	payload := grpcPayload("one", "two", "three")
	req, err := http.NewRequest(http.MethodPost, origin.URL+"/pkg.Svc/Stream", strings.NewReader(string(payload)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := client.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, int64(3), forwarded.Load())
	assert.Equal(t, int64(3), received.Load(), "every request message reached the origin")
	assert.Equal(t, payload, body, "the response the handler never touched came through unchanged")
	assert.Equal(t, "0", resp.Trailer.Get("Grpc-Status"), "the trailers followed the body")
}

// CloseSend ends the request stream before the client is done with it, and the origin sees
// only what went through before.
func TestKindGRPC_CloseSendStopsTheRequestStream(t *testing.T) {
	origin, received := grpcEchoOrigin(t)
	p, host, client := interceptingProxy(t, origin)
	_, err := p.Delete[HTTP](host + "/*{any}")
	require.NoError(t, err)

	p.MustAdd(host+"/pkg.Svc/Stream", func(c *GRPCCtx) error {
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		m, rerr := c.Outbound().ReadMessage()
		if rerr != nil {
			return rerr
		}
		if ferr := m.Forward(); ferr != nil {
			return ferr
		}
		if cerr := c.CloseSend(); cerr != nil {
			return cerr
		}
		in := c.Inbound()
		for {
			mm, ierr := in.ReadMessage()
			if ierr != nil {
				return nil
			}
			if ferr := mm.Forward(); ferr != nil {
				return ferr
			}
		}
	})

	req, err := http.NewRequest(http.MethodPost, origin.URL+"/pkg.Svc/Stream",
		strings.NewReader(string(grpcPayload("one", "two", "three"))))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := client.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, int64(1), received.Load(), "the origin saw the one message forwarded before the half-close")
	assert.Equal(t, grpcPayload("one"), body)
	assert.Equal(t, "0", resp.Trailer.Get("Grpc-Status"))
}

// There is no response to carry a message into before the origin answered, so a reply toward
// the client is refused rather than parked on a pipe nobody reads yet.
func TestKindGRPC_ReplyBeforeTheOriginAnsweredIsRefused(t *testing.T) {
	origin, _ := grpcEchoOrigin(t)
	p, host, client := interceptingProxy(t, origin)
	_, err := p.Delete[HTTP](host + "/*{any}")
	require.NoError(t, err)

	replyErr := make(chan error, 1)
	p.MustAdd(host+"/pkg.Svc/Method", func(c *GRPCCtx) error {
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		m, rerr := c.Outbound().ReadMessage()
		if rerr != nil {
			return rerr
		}
		replyErr <- m.Reply([]byte("early"))
		return m.Forward()
	})

	req, err := http.NewRequest(http.MethodPost, origin.URL+"/pkg.Svc/Method",
		strings.NewReader(string(grpcPayload("hello"))))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := client.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	require.Error(t, <-replyErr, "the reply had nowhere to go yet")
	assert.Equal(t, grpcPayload("hello"), body, "the call itself completed as forwarded")
}

// A handler that reads the response stream and returns before the origin answered cancels the
// call, and the client reads it as canceled.
func TestKindGRPC_ReturnBeforeTheAnswerCancelsTheCall(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", "0")
	}))
	defer origin.Close()

	p, host, client := interceptingProxy(t, origin)
	_, err := p.Delete[HTTP](host + "/*{any}")
	require.NoError(t, err)

	p.MustAdd(host+"/pkg.Svc/Method", func(c *GRPCCtx) error {
		if oerr := c.Open(); oerr != nil {
			return oerr
		}
		_ = c.Inbound()
		return nil
	})

	req, err := http.NewRequest(http.MethodPost, origin.URL+"/pkg.Svc/Method",
		strings.NewReader(string(grpcPayload("hello"))))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/grpc")
	resp, err := client.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	assert.Equal(t, "1", resp.Header.Get("Grpc-Status"), "the proxy canceled the call")
}

// grpcStreamingOrigin answers a call with one message at once, then a second one when release
// is closed, then an OK status.
func grpcStreamingOrigin(t *testing.T, release <-chan struct{}) *httptest.Server {
	t.Helper()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_, _ = w.Write(grpcPayload("one"))
		_ = rc.Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write(grpcPayload("two"))
		_ = rc.Flush()
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	}))
	t.Cleanup(origin.Close)
	return origin
}

// A call keeps its handler, but every message is checked against the tree as it arrives.
// Deleting the entry mid-stream refuses the next message and ends the call on a status the
// client can read, however the handler chose to serve it.
func TestKindGRPC_DeleteReachesTheCallAtItsNextMessage(t *testing.T) {
	handlers := map[string]GRPC{
		"forward": func(c *GRPCCtx) error { return c.Forward() },
		"readers": func(c *GRPCCtx) error {
			if err := c.Open(); err != nil {
				return err
			}
			src := MergeMessages(c.Outbound(), c.Inbound())
			for {
				m, err := src.ReadMessage()
				if err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					}
					return err
				}
				if ferr := m.Forward(); ferr != nil {
					return ferr
				}
			}
		},
	}

	for name, handler := range handlers {
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			origin := grpcStreamingOrigin(t, release)
			p, host, client := interceptingProxy(t, origin)
			_, err := p.Delete[HTTP](host + "/*{any}")
			require.NoError(t, err)
			p.MustAdd(host+"/pkg.Svc/Stream", handler)

			req, err := http.NewRequest(http.MethodPost, origin.URL+"/pkg.Svc/Stream",
				strings.NewReader(string(grpcPayload("hello"))))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/grpc")
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			first := make([]byte, len(grpcPayload("one")))
			_, err = io.ReadFull(resp.Body, first)
			require.NoError(t, err)
			assert.Equal(t, grpcPayload("one"), first, "the first message passes while the entry stands")

			_, err = p.Delete[GRPC](host + "/pkg.Svc/Stream")
			require.NoError(t, err)
			close(release)

			rest, err := io.ReadAll(resp.Body)
			require.NoError(t, err, "the body ends cleanly on the refusal")
			assert.Empty(t, rest, "the message that arrived after the delete is refused")
			assert.Equal(t, "14", resp.Trailer.Get("Grpc-Status"), "the client reads Unavailable")
		})
	}
}
