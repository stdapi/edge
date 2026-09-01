// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bufio"
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
		return c.Relay(OnFrame(func(f *FrameCtx) error {
			if f.Opcode() == OpPing {
				pings.Add(1)
				return f.Drop()
			}
			seen.Add(1)
			return f.Forward()
		}))
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
		return c.Forward(OnMessage(func(m *GRPCMessage) error {
			messages.Add(1)
			return m.Forward()
		}))
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
