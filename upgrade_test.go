// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

// upgradeOrigin answers an Upgrade request with 101 and then echoes whatever it is sent,
// which is the shape every WebSocket handshake ends up in once the framing is stripped.
func upgradeOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(upgradeHandler(t))
	t.Cleanup(srv.Close)
	return srv
}

// plainUpgradeOrigin is upgradeOrigin without TLS, which is what a redirected plaintext
// connection and an absolute-form proxy request reach.
func plainUpgradeOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(upgradeHandler(t))
	t.Cleanup(srv.Close)
	return srv
}

func upgradeHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "echo") {
			http.Error(w, "expected an upgrade", http.StatusBadRequest)
			return
		}

		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("origin hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()

		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		if err := brw.Flush(); err != nil {
			return
		}
		_, _ = io.Copy(conn, brw)
	}
}

func TestProxy_ProtocolUpgrade(t *testing.T) {
	origin := upgradeOrigin(t)
	originURL, _ := url.Parse(origin.URL)

	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)

	var sawUpgrade string
	var pipeTLS atomic.Bool
	// Past the 101 the connection is a byte stream, and a stream entry is what serves it.
	p.MustAdd[TCP](originHost(originURL), func(c *TCPCtx) error {
		pipeTLS.Store(c.TLS() != nil)
		return c.Relay()
	})
	p.MustAdd(originHost(originURL)+"/ws", func(c *HTTPCtx) (*http.Response, error) {
		sawUpgrade = c.Request().Header.Get("Upgrade")
		return c.Forward()
	}, WithMethods[HTTP](http.MethodGet))

	addr := startProxy(t, p)

	// Reaching the tunnel by hand: an upgrade is not something an http.Client exposes.
	raw, err := dialThroughProxy(t, addr, originURL.Host, ca)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	_, err = raw.Write([]byte("GET /ws HTTP/1.1\r\nHost: " + originURL.Host + "\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n"))
	require.NoError(t, err)

	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	assert.Equal(t, "echo", resp.Header.Get("Upgrade"))
	assert.Equal(t, "echo", sawUpgrade, "the handler must still see the upgrade request")

	_, err = raw.Write([]byte("ping\n"))
	require.NoError(t, err)

	line, err := br.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "ping\n", line, "bytes must flow both ways once upgraded")
	assert.True(t, pipeTLS.Load(), "the pipe reports the handshake of the connection it was cut from")
}

// dialThroughProxy opens a CONNECT tunnel to authority and completes the TLS handshake the
// proxy intercepts, returning the plaintext side of it.
func dialThroughProxy(t *testing.T, proxyAddr, authority string, ca *CA) (*tls.Conn, error) {
	t.Helper()

	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}

	if _, err := raw.Write([]byte("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n")); err != nil {
		return nil, err
	}
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Zero(t, br.Buffered(), "the proxy must not send anything past the CONNECT response")

	host, _ := splitHostPort(authority)
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: host,
		RootCAs:    ca.CertPool(),
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

const upgradeRequest = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n"

func TestUpgrade_TransparentPlaintextPipeIsListedAndClosed(t *testing.T) {
	origin := plainUpgradeOrigin(t)
	originURL, _ := url.Parse(origin.URL)
	originAddr, err := netip.ParseAddrPort(originURL.Host)
	require.NoError(t, err)

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)
	p := testProxy(t, WithTransport(tr))
	p.MustAdd[TCP]("ws.example.test", relayStream)
	p.MustAdd("ws.example.test/ws", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	}, WithMethods[HTTP](http.MethodGet))

	addr := startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
		return originAddr, nil
	})

	raw, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	_, err = fmt.Fprintf(raw, upgradeRequest, "/ws", "ws.example.test")
	require.NoError(t, err)

	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	sessions := waitForSessions(t, p, 2)
	i := slices.IndexFunc(sessions, func(s *Session) bool { return s.Kind() == KindTCP })
	require.GreaterOrEqual(t, i, 0, "the connection is HTTP, the pipe is the stream")
	pipe := sessions[i]
	assert.Equal(t, "ws.example.test", pipe.Target().Host)
	assert.True(t, pipe.Transparent())

	require.NoError(t, pipe.Close())
	_, _ = raw.Write([]byte("ping\n"))
	_, err = br.ReadString('\n')
	assert.Error(t, err, "the pipe is cut, nothing echoes back")
	waitForSessions(t, p, 0)
}

func TestUpgrade_HostDivergesFromTheConnectAuthority(t *testing.T) {
	origin := plainUpgradeOrigin(t)
	originURL, _ := url.Parse(origin.URL)

	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)

	p := testProxy(t, WithTransport(tr))
	p.MustAdd("a.example.test/*{rest}", noopHandler)
	p.MustAdd[TCP]("b.example.test", relayStream)
	p.MustAdd("b.example.test/ws", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	}, WithMethods[HTTP](http.MethodGet))

	raw := connectRaw(t, startProxy(t, p), "a.example.test:80")
	br := bufio.NewReader(raw)
	_, err := io.WriteString(raw, "GET / HTTP/1.1\r\nHost: a.example.test\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	_, err = fmt.Fprintf(raw, upgradeRequest, "/ws", "b.example.test")
	require.NoError(t, err)
	resp, err = http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	// The connection and the pipe, each reporting the authority it talks to.
	sessions := waitForSessions(t, p, 2)
	hosts := make([]string, 0, 2)
	for _, s := range sessions {
		hosts = append(hosts, s.Target().Host)
	}
	slices.Sort(hosts)
	assert.Equal(t, []string{"a.example.test", "b.example.test"}, hosts)

	// The pipe is a stream past the 101, so what admits it is the stream entry on the host
	// its request named, not the one the connection was opened for.
	_, err = p.Delete[TCP]("b.example.test")
	require.NoError(t, err)

	var closed int
	for s := range p.Sessions() {
		if !p.Admits(s.Target(), s.Kind()) {
			require.NoError(t, s.Close())
			closed++
		}
	}
	assert.Equal(t, 1, closed, "the pipe is swept while its connection stays allowed")
	assert.Equal(t, true, p.Admits(target("a.example.test:80"), KindHTTP))
}

func TestUpgrade_RefusedWhenTheRouteGoesAwayFirst(t *testing.T) {
	origin := upgradeOrigin(t)
	originURL, _ := url.Parse(origin.URL)
	pattern := originHost(originURL) + "/ws"

	ca, _ := GenerateCA()
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)

	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	p.MustAdd[TCP](originHost(originURL), relayStream)
	p.MustAdd(pattern, func(c *HTTPCtx) (*http.Response, error) {
		resp, ferr := c.Forward()
		if ferr != nil {
			return nil, ferr
		}
		// Between the upstream 101 and the splice, which is the window the re-check covers.
		// What the 101 switches to is a stream, so withdrawing the stream entry is what
		// leaves the upgrade with nothing to serve it.
		if _, derr := p.Delete[TCP](originHost(originURL)); derr != nil {
			return nil, derr
		}
		_, derr := p.Delete[HTTP](pattern, WithMethods[HTTP](http.MethodGet))
		return resp, derr
	}, WithMethods[HTTP](http.MethodGet))

	raw, err := dialThroughProxy(t, startProxy(t, p), originURL.Host, ca)
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	_, err = fmt.Fprintf(raw, upgradeRequest, "/ws", originURL.Host)
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(raw), nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "the client never sees the 101")
	// The refusal is written before the hijack, so the client reads an ordinary status and
	// keeps its connection. What matters is that no pipe was left behind: the one session is
	// the terminated connection itself.
	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, KindHTTP, sessions[0].Kind())
}

func TestUpgrade_CloseEndsAPipeOnAFrontConnection(t *testing.T) {
	origin := plainUpgradeOrigin(t)
	originURL, _ := url.Parse(origin.URL)

	p := testProxy(t)
	p.MustAdd[TCP](originHost(originURL), relayStream)
	p.MustAdd(originHost(originURL)+"/ws", func(c *HTTPCtx) (*http.Response, error) {
		return c.Forward()
	}, WithMethods[HTTP](http.MethodGet))

	raw, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	// An absolute-form request, so no CONNECT and no session for the connection it arrives on.
	_, err = fmt.Fprintf(raw, upgradeRequest, origin.URL+"/ws", originURL.Host)
	require.NoError(t, err)

	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	sessions := waitForSessions(t, p, 1)
	assert.Equal(t, originHost(originURL), sessions[0].Target().Host)
	assert.False(t, sessions[0].Transparent())

	require.NoError(t, p.Close())
	_, _ = raw.Write([]byte("ping\n"))
	_, err = br.ReadString('\n')
	assert.Error(t, err, "Close must reach a pipe http.Server no longer owns")
}

func TestUpgrade_SessionCloseEndsAStalledClient(t *testing.T) {
	origin := upgradeOrigin(t)
	originURL, _ := url.Parse(origin.URL)

	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin)
	p, err := New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	full := make(chan struct{})
	p.MustAdd[TCP](originHost(originURL), func(c *TCPCtx) error {
		writeUntilFull(c.Client())
		close(full)
		<-c.Context().Done()
		return nil
	})
	p.MustAdd(originHost(originURL)+"/ws", forwardHandler, WithMethods[HTTP](http.MethodGet))

	raw, err := dialThroughProxy(t, startProxy(t, p), originURL.Host, ca)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	_, err = fmt.Fprintf(raw, upgradeRequest, "/ws", originURL.Host)
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(raw), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	<-full
	sess := tcpSession(t, p)

	start := time.Now()
	_ = sess.Close()
	assert.Less(t, time.Since(start), alertWriteTimeout, "Close blocked on the client")
	assertSessionEnded(t, p, sess)
	assert.Eventually(t, func() bool { return len(slices.Collect(p.Sessions())) == 0 },
		alertWriteTimeout, 10*time.Millisecond, "the pipe outlived its close")
}

func TestUpgrade_ReachesTheNoEntryTCPHandler(t *testing.T) {
	origin, _ := wsOrigin(t, nil)
	p := testProxy(t, WithNoEntry(forwardHandler), WithNoEntry(relayStream))

	resp := wsUpgrade(t, startProxy(t, p), origin, "")
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	require.Equal(t, KindTCP, waitForSessions(t, p, 1)[0].Kind())
}

func TestUpgrade_StreamOutlivesTheClientHalfClose(t *testing.T) {
	origin := plainUpgradeOrigin(t)
	originURL, _ := url.Parse(origin.URL)

	alive := make(chan error, 1)
	p := testProxy(t)
	p.MustAdd[TCP](originHost(originURL), func(c *TCPCtx) error {
		up, err := c.Dial()
		if err != nil {
			return err
		}
		b, err := io.ReadAll(c.Client())
		if err != nil {
			return err
		}
		alive <- c.Context().Err()
		if _, err := up.Write(b); err != nil {
			return err
		}
		_, err = io.CopyN(c.Client(), up, int64(len(b)))
		return err
	})
	p.MustAdd(originHost(originURL)+"/ws", forwardHandler, WithMethods[HTTP](http.MethodGet))

	raw, err := net.Dial("tcp", startProxy(t, p))
	require.NoError(t, err)
	defer func() { _ = raw.Close() }()

	_, err = fmt.Fprintf(raw, upgradeRequest, origin.URL+"/ws", originURL.Host)
	require.NoError(t, err)
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	_, err = raw.Write([]byte("ping\n"))
	require.NoError(t, err)
	require.NoError(t, raw.(*net.TCPConn).CloseWrite())

	require.NoError(t, raw.SetReadDeadline(time.Now().Add(5*time.Second)))
	line, err := br.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "ping\n", line, "the origin's bytes reach a client that half-closed")
	select {
	case err := <-alive:
		assert.NoError(t, err, "the context ended with the half-close of the client")
	default:
		t.Fatal("the handler never read the end of the client stream")
	}
}

func TestUpgrade_WebSocketMergedReaderEndsOnTheConnection(t *testing.T) {
	errs := make(chan error, 2)
	ws := openWS(t, wsConf{handler: func(c *WebSocketCtx) error {
		src := MergeFrames(c.Outbound(), c.Inbound())
		for {
			f, err := src.ReadFrame()
			if err != nil {
				errs <- err
				return err
			}
			if f.Opcode() == OpClose && !f.Inbound() {
				errs <- c.Context().Err()
			}
			if err := f.Forward(); err != nil {
				return err
			}
		}
	}})
	cross(ws.origin, ws.client, 0x88, closePayload(1000, ""))
	cross(ws.client, ws.origin, 0x88, closePayload(1000, ""))
	require.NoError(t, ws.origin.conn.Close())

	next := func() error {
		select {
		case err := <-errs:
			return err
		case <-time.After(3 * time.Second):
			return errors.New("the handler reported nothing")
		}
	}
	assert.NoError(t, next(), "the context ended with the client hop")
	assert.ErrorIs(t, next(), io.EOF, "the merged reader ended on the context")
}

// stalledPeer never reads what it is sent. A write blocks until a write deadline is set.
type stalledPeer struct {
	net.Conn
	wake      chan struct{}
	deadlines []time.Time
	mu        sync.Mutex
	once      sync.Once
}

func (c *stalledPeer) Write([]byte) (int, error) {
	c.mu.Lock()
	set := len(c.deadlines) > 0 && !c.deadlines[len(c.deadlines)-1].IsZero()
	c.mu.Unlock()
	if !set {
		<-c.wake
	}
	return 0, os.ErrDeadlineExceeded
}

func (c *stalledPeer) SetWriteDeadline(d time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, d)
	c.mu.Unlock()
	if !d.IsZero() {
		c.once.Do(func() { close(c.wake) })
	}
	return nil
}

func (c *stalledPeer) Close() error {
	c.once.Do(func() { close(c.wake) })
	return nil
}

// stalledPipe stands for the connection toward an origin that stopped reading, which has no
// write deadline. A write blocks until the pipe is closed.
type stalledPipe struct {
	closed chan struct{}
	once   sync.Once
}

func (p *stalledPipe) Read([]byte) (int, error) { <-p.closed; return 0, net.ErrClosed }

func (p *stalledPipe) Write([]byte) (int, error) { <-p.closed; return 0, net.ErrClosed }

func (p *stalledPipe) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func TestUpgrade_WebSocketCloseTowardTheOriginIsBounded(t *testing.T) {
	t.Parallel()
	client := &stalledPeer{wake: make(chan struct{})}
	origin := &stalledPipe{closed: make(chan struct{})}
	wc := &WebSocketCtx{ctx: context.Background(), cancel: func(error) {}}
	wc.setHops(client, bytes.NewReader((wsFrame{head: 0x81, payload: []byte("x")}).bytes()), origin)

	done := make(chan error, 1)
	go func() {
		_, err := wc.Outbound().ReadFrame()
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, errFrameMask)
	case <-time.After(wsCloseTimeout + 2*time.Second):
		_ = origin.Close()
		t.Fatal("the Close toward an origin that stopped reading is not bounded")
	}
}

type discardPipe struct{}

func (discardPipe) Read([]byte) (int, error)    { return 0, io.EOF }
func (discardPipe) Write(b []byte) (int, error) { return len(b), nil }
func (discardPipe) Close() error                { return nil }

func TestUpgrade_WebSocketCloseOnAFailureIsBounded(t *testing.T) {
	client := &stalledPeer{wake: make(chan struct{})}
	wc := &WebSocketCtx{ctx: context.Background(), cancel: func(error) {}}
	// Unmasked, which fails the connection toward a client that stopped reading.
	wc.setHops(client, bytes.NewReader((wsFrame{head: 0x81, payload: []byte("x")}).bytes()), discardPipe{})

	done := make(chan error, 1)
	go func() {
		_, err := wc.Outbound().ReadFrame()
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, errFrameMask)
	case <-time.After(time.Second):
		_ = client.Close()
		t.Fatal("the Close toward a peer that stopped reading has no deadline")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	require.NotEmpty(t, client.deadlines)
	assert.True(t, client.deadlines[len(client.deadlines)-1].IsZero(), "the write deadline is left set")
}

// pipeWebSocket returns a WebSocket connection over two pipes, and the ends of the client and
// of the origin.
func pipeWebSocket(t *testing.T) (*WebSocketCtx, net.Conn, net.Conn) {
	ctx, cancel := context.WithCancelCause(t.Context())
	client, clientEnd := net.Pipe()
	origin, originEnd := net.Pipe()
	t.Cleanup(func() {
		cancel(nil)
		_ = clientEnd.Close()
		_ = originEnd.Close()
	})
	wc := &WebSocketCtx{ctx: ctx, cancel: cancel}
	wc.setHops(client, client, origin)
	return wc, clientEnd, originEnd
}

func sendClientFrame(t *testing.T, conn net.Conn) {
	t.Helper()
	go func() {
		_, _ = conn.Write(wsFrame{head: 0x81, payload: []byte("x"), masked: true, key: wsKey}.bytes())
	}()
}

func TestUpgrade_WebSocketMergedReaderEndsWithEOFWhenTheConnectionExpires(t *testing.T) {
	wc, client, _ := pipeWebSocket(t)
	src := MergeFrames(wc.Outbound(), wc.Inbound())
	sendClientFrame(t, client)
	f, err := src.ReadFrame()
	require.NoError(t, err)
	require.False(t, f.Inbound())

	wc.expire()
	_, err = src.ReadFrame()
	assert.ErrorIs(t, err, io.EOF)
}

func TestUpgrade_WebSocketContextEndsWhenAReadEndsTheConnection(t *testing.T) {
	wc, client, _ := pipeWebSocket(t)
	require.NoError(t, client.Close())
	_, err := wc.Outbound().ReadFrame()
	require.ErrorIs(t, err, io.EOF)
	assert.ErrorIs(t, context.Cause(wc.Context()), errSourcesEnded)
}

func TestUpgrade_WebSocketMergeAcrossConnectionsEndsWithTheContext(t *testing.T) {
	c1, client, _ := pipeWebSocket(t)
	c2, _, _ := pipeWebSocket(t)
	src := MergeFrames(c1.Outbound(), c2.Inbound())
	sendClientFrame(t, client)
	_, err := src.ReadFrame()
	require.NoError(t, err)

	c1.expire()
	done := make(chan error, 1)
	go func() {
		_, err := src.ReadFrame()
		done <- err
	}()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("the merged reader outlived its context while the other connection is open")
	}
}

func TestConformanceWebSocket(t *testing.T) {
	runConformance(t, wsConformance)
}

// wsFrame is a frame as it appears on the wire. head is the first byte, FIN, RSV and opcode.
type wsFrame struct {
	payload []byte
	key     [4]byte
	head    byte
	// form is the 7-bit length field, 126 or 127 for the extended forms. Zero on a frame to
	// send picks the minimal form.
	form   byte
	masked bool
}

var wsKey = [4]byte{0x37, 0xfa, 0x21, 0x3d}

func (f wsFrame) bytes() []byte {
	n := len(f.payload)
	form := f.form
	if form == 0 {
		switch {
		case n < 126:
			form = byte(n)
		case n <= 0xffff:
			form = 126
		default:
			form = 127
		}
	}
	b := []byte{f.head, form}
	switch form {
	case 126:
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	case 127:
		b = binary.BigEndian.AppendUint64(b, uint64(n))
	}
	if !f.masked {
		return append(b, f.payload...)
	}
	b[1] |= 0x80
	b = append(b, f.key[:]...)
	for i, c := range f.payload {
		b = append(b, c^f.key[i%4])
	}
	return b
}

func closePayload(code uint16, reason string) []byte {
	return append(binary.BigEndian.AppendUint16(nil, code), reason...)
}

// wsEnd is one raw peer. The client masks what it sends and must receive frames unmasked,
// the origin the reverse.
type wsEnd struct {
	t      *testing.T
	conn   net.Conn
	br     *bufio.Reader
	client bool
}

func (e *wsEnd) frame(head byte, payload []byte) wsFrame {
	return wsFrame{head: head, payload: payload, masked: e.client, key: wsKey}
}

func (e *wsEnd) send(frames ...wsFrame) {
	e.t.Helper()
	var b []byte
	for _, f := range frames {
		b = append(b, f.bytes()...)
	}
	e.write(b)
}

func (e *wsEnd) write(b []byte) {
	e.t.Helper()
	require.NoError(e.t, e.conn.SetWriteDeadline(time.Now().Add(5*time.Second)))
	_, err := e.conn.Write(b)
	require.NoError(e.t, err)
}

func (e *wsEnd) next(wait time.Duration) (wsFrame, error) {
	if err := e.conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return wsFrame{}, err
	}
	var h [2]byte
	if _, err := io.ReadFull(e.br, h[:]); err != nil {
		return wsFrame{}, err
	}
	f := wsFrame{head: h[0], masked: h[1]&0x80 != 0, form: h[1] & 0x7f}
	n := uint64(f.form)
	switch f.form {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(e.br, ext[:]); err != nil {
			return wsFrame{}, err
		}
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(e.br, ext[:]); err != nil {
			return wsFrame{}, err
		}
		n = binary.BigEndian.Uint64(ext[:])
	}
	if n > 1<<24 {
		return wsFrame{}, fmt.Errorf("a frame of %d bytes", n)
	}
	if f.masked {
		if _, err := io.ReadFull(e.br, f.key[:]); err != nil {
			return wsFrame{}, err
		}
	}
	f.payload = make([]byte, n)
	if _, err := io.ReadFull(e.br, f.payload); err != nil {
		return wsFrame{}, err
	}
	if f.masked {
		for i := range f.payload {
			f.payload[i] ^= f.key[i%4]
		}
	}
	return f, nil
}

func (e *wsEnd) read() wsFrame {
	e.t.Helper()
	f, err := e.next(5 * time.Second)
	require.NoError(e.t, err)
	require.Equal(e.t, !e.client, f.masked, "the mask bit of a frame toward the client=%t", e.client)
	return f
}

func (e *wsEnd) want(head byte, payload []byte) wsFrame {
	e.t.Helper()
	f := e.read()
	require.Equal(e.t, fmt.Sprintf("0x%02x", head), fmt.Sprintf("0x%02x", f.head))
	require.True(e.t, bytes.Equal(payload, f.payload), "a payload of %d bytes, want %d", len(f.payload), len(payload))
	return f
}

func (e *wsEnd) wantEnd() []wsFrame {
	e.t.Helper()
	var frames []wsFrame
	for {
		f, err := e.next(5 * time.Second)
		if err != nil {
			require.NotErrorIs(e.t, err, os.ErrDeadlineExceeded, "the connection is still open")
			return frames
		}
		frames = append(frames, f)
	}
}

// wantFailed is the expectation Autobahn writes "Clean close with protocol error code or drop
// TCP", any of codes being accepted in the Close.
func (e *wsEnd) wantFailed(codes ...uint16) {
	e.t.Helper()
	frames := e.wantEnd()
	require.LessOrEqual(e.t, len(frames), 1, "frames arrived on a failed connection")
	if len(frames) == 1 {
		f := frames[0]
		require.Equal(e.t, byte(0x88), f.head, "only a Close may precede the end")
		require.GreaterOrEqual(e.t, len(f.payload), 2)
		require.Contains(e.t, codes, binary.BigEndian.Uint16(f.payload))
	}
}

func (e *wsEnd) wantNoData() {
	e.t.Helper()
	for _, f := range e.wantEnd() {
		require.Equal(e.t, byte(0x88), f.head, "a frame crossed a failed connection")
	}
}

func (e *wsEnd) wantSilent() {
	e.t.Helper()
	_, err := e.next(200 * time.Millisecond)
	require.ErrorIs(e.t, err, os.ErrDeadlineExceeded)
}

// wantNothingBehindTheClose has the client stream frames while the origin sends bad, which
// fails the connection, and checks that no frame reaches the origin after the Close of edge.
func wantNothingBehindTheClose(t *testing.T, bad []byte) {
	t.Helper()
	for range 50 {
		ws := openWS(t, wsConf{})
		burst := bytes.Repeat(ws.client.frame(0x82, make([]byte, 64)).bytes(), 64)
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = ws.client.conn.SetWriteDeadline(time.Now().Add(time.Second))
				if _, err := ws.client.conn.Write(burst); err != nil {
					return
				}
			}
		}()
		ws.origin.read()
		ws.origin.write(bad)
		frames := ws.origin.wantEnd()
		close(stop)
		<-done
		if i := slices.IndexFunc(frames, func(f wsFrame) bool { return f.head == 0x88 }); i >= 0 {
			require.Equal(t, i+1, len(frames), "a frame reached the origin after the Close of edge")
		}
	}
}

func cross(from, to *wsEnd, head byte, payload []byte) {
	from.t.Helper()
	from.send(from.frame(head, payload))
	to.want(head, payload)
}

type wsConf struct {
	handler WebSocket
	// answer returns the head of the origin's answer, a 101 when it returns nothing.
	answer      func(r *http.Request) string
	reqHeader   string
	respHeader  string
	early       []byte
	originEarly []byte
	tls         bool
	proto       string
	maxFrame    int
}

type wsConn struct {
	client *wsEnd
	origin *wsEnd
	// req is the handshake as the origin received it, resp the answer as the client did.
	req  *http.Request
	resp *http.Response
}

type wsOriginHop struct {
	conn net.Conn
	br   *bufio.Reader
	req  *http.Request
}

func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func relayFrames(c *WebSocketCtx) error { return c.Relay() }

func mergeFrames(c *WebSocketCtx) error {
	src := MergeFrames(c.Outbound(), c.Inbound())
	for {
		f, err := src.ReadFrame()
		if err != nil {
			return err
		}
		if err := f.Forward(); err != nil {
			return err
		}
	}
}

// openWS leaves the origin end nil when the origin was never reached.
func openWS(t *testing.T, conf wsConf) *wsConn {
	t.Helper()
	hops := make(chan wsOriginHop, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("origin hijack: %v", err)
			return
		}
		hops <- wsOriginHop{conn: conn, br: brw.Reader, req: r}
		head := ""
		if conf.answer != nil {
			head = conf.answer(r)
		}
		if head == "" {
			head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Accept: " + wsAccept(r.Header.Get("Sec-WebSocket-Key")) + "\r\n" + conf.respHeader + "\r\n"
		}
		_, _ = brw.WriteString(head)
		_, _ = brw.Write(conf.originEarly)
		_ = brw.Flush()
	})

	var origin *httptest.Server
	if conf.tls {
		origin = httptest.NewTLSServer(handler)
	} else {
		origin = httptest.NewServer(handler)
	}
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)

	h := conf.handler
	if h == nil {
		h = relayFrames
	}
	ca, err := GenerateCA()
	require.NoError(t, err)
	host, line := originURL.Host, "GET "+origin.URL+"/ws "
	var opts []ProxyOption
	if conf.maxFrame > 0 {
		opts = append(opts, WithMaxFrameBytes(conf.maxFrame))
	}
	if conf.tls {
		host, line = "ws.example.test", "GET /ws "
		tr := DefaultTransport()
		tr.DialContext = pinnedDialer(originURL.Host)
		tr.InsecureSkipVerify = true
		opts = append(opts, WithTransport(tr))
	}
	p := testProxyWithCA(t, ca, opts...)
	pattern, _ := splitHostPort(host)
	p.MustAdd(pattern+"/ws", h)
	addr := startProxy(t, p)

	var conn net.Conn
	if conf.tls {
		conn, err = dialThroughProxy(t, addr, host+":443", ca)
	} else {
		conn, err = net.DialTimeout("tcp", addr, 5*time.Second)
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	proto := conf.proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	hs := line + proto + "\r\nHost: " + host + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" + conf.reqHeader + "\r\n"
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write(append([]byte(hs), conf.early...))
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Time{}))

	ws := &wsConn{client: &wsEnd{t: t, conn: conn, br: br, client: true}, resp: resp}
	var hop wsOriginHop
	if resp.StatusCode == http.StatusSwitchingProtocols {
		select {
		case hop = <-hops:
		case <-time.After(5 * time.Second):
			t.Fatal("the origin was not reached")
		}
	} else {
		select {
		case hop = <-hops:
		default:
			return ws
		}
	}
	t.Cleanup(func() { _ = hop.conn.Close() })
	ws.origin = &wsEnd{t: t, conn: hop.conn, br: hop.br}
	ws.req = hop.req
	return ws
}

const deflateExtension = "Sec-WebSocket-Extensions: permessage-deflate\r\n"

// badPingHead is the header of a Ping of 126 bytes from the client. Sent without its payload,
// edge refuses it with nothing left unread, so the close reaches the client as a FIN.
var badPingHead = []byte{0x89, 0xfe, 0x00, 0x7e, 0x37, 0xfa, 0x21, 0x3d}

// deflateHello is "Hello" compressed, from RFC 7692 section 7.2.3.1.
var deflateHello = []byte{0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00}

// wsConformance lists the requirements of RFC 6455 and RFC 7692, checked between a raw client
// and a raw origin. A rule an extension could make legal is checked as crossing edge unchanged,
// and a rule on one hop is checked on edge as the endpoint of that hop.
var wsConformance = []conformanceCase{
	{
		id: "rfc6455/4.1/1", name: "the key of the client and the accept of the origin",
		req: "If the response lacks a |Sec-WebSocket-Accept| header field or the |Sec-WebSocket-Accept| contains a value other than the base64-encoded SHA-1 of the concatenation of the |Sec-WebSocket-Key| (as a string, not base64-decoded) with the string \"258EAFA5-E914-47DA-95CA-C5AB0DC85B11\" but ignoring any leading and trailing whitespace, the client MUST _Fail the WebSocket Connection_.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			require.Equal(t, http.StatusSwitchingProtocols, ws.resp.StatusCode)
			assert.Equal(t, "dGhlIHNhbXBsZSBub25jZQ==", ws.req.Header.Get("Sec-WebSocket-Key"))
			assert.Equal(t, "13", ws.req.Header.Get("Sec-WebSocket-Version"))
			assert.True(t, headerListContains(ws.req.Header, "Connection", "upgrade"))
			assert.Equal(t, "websocket", ws.req.Header.Get("Upgrade"))
			assert.Equal(t, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", ws.resp.Header.Get("Sec-WebSocket-Accept"))
			assert.True(t, headerListContains(ws.resp.Header, "Connection", "upgrade"))
			assert.Equal(t, "websocket", ws.resp.Header.Get("Upgrade"))
		},
	},
	{
		id: "rfc6455/4.1/2", name: "a subprotocol offer and the origin's choice",
		req: "If the response includes a |Sec-WebSocket-Protocol| header field and this header field indicates the use of a subprotocol that was not present in the client's handshake (the server has indicated a subprotocol not requested by the client), the client MUST _Fail the WebSocket Connection_.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{
				reqHeader:  "Sec-WebSocket-Protocol: chat, superchat\r\n",
				respHeader: "Sec-WebSocket-Protocol: chat\r\n",
			})
			require.Equal(t, http.StatusSwitchingProtocols, ws.resp.StatusCode)
			assert.Equal(t, "chat, superchat", ws.req.Header.Get("Sec-WebSocket-Protocol"))
			assert.Equal(t, "chat", ws.resp.Header.Get("Sec-WebSocket-Protocol"))
		},
	},
	{
		id: "rfc6455/4.1/3", name: "an extension offer and the origin's acceptance",
		req: "If the response includes a |Sec-WebSocket-Extensions| header field and this header field indicates the use of an extension that was not present in the client's handshake (the server has indicated an extension not requested by the client), the client MUST _Fail the WebSocket Connection_.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{
				reqHeader:  "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n",
				respHeader: "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n",
			})
			require.Equal(t, http.StatusSwitchingProtocols, ws.resp.StatusCode)
			assert.Equal(t, "permessage-deflate; client_max_window_bits", ws.req.Header.Get("Sec-WebSocket-Extensions"))
			assert.Equal(t, "permessage-deflate; server_no_context_takeover", ws.resp.Header.Get("Sec-WebSocket-Extensions"))
		},
	},
	{
		id: "rfc6455/4.1/4", name: "a 403 from the origin",
		req: "If the status code received from the server is not 101, the client handles the response per HTTP [RFC2616] procedures.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{answer: func(*http.Request) string {
				return "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\ndenied"
			}})
			require.Equal(t, http.StatusForbidden, ws.resp.StatusCode)
			body, err := io.ReadAll(io.LimitReader(ws.resp.Body, 6))
			require.NoError(t, err)
			assert.Equal(t, "denied", string(body))
		},
	},
	{
		id: "rfc6455/4.1/5", name: "a frame in the same write as the handshake",
		req: "Once the client's opening handshake has been sent, the client MUST wait for a response from the server before sending any further data.",
		run: func(t *testing.T) {
			early := wsFrame{head: 0x81, payload: []byte("early"), masked: true, key: wsKey}
			ws := openWS(t, wsConf{early: early.bytes()})
			require.Equal(t, http.StatusSwitchingProtocols, ws.resp.StatusCode)
			ws.origin.want(0x81, []byte("early"))
		},
	},
	{
		id: "rfc6455/4.1/6", name: "a handshake inside a CONNECT tunnel to a wss origin",
		req: "_Proxy Usage_: If the client is configured to use a proxy when using the WebSocket Protocol to connect to host /host/ and port /port/, then the client SHOULD connect to that proxy and ask it to open a TCP connection to the host given by /host/ and the port given by /port/.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{tls: true})
			require.Equal(t, http.StatusSwitchingProtocols, ws.resp.StatusCode)
			cross(ws.client, ws.origin, 0x81, []byte("Hello"))
			cross(ws.origin, ws.client, 0x81, []byte("Hello"))
		},
	},
	{
		id: "rfc6455/4.1/7", name: "a handshake toward a wss origin",
		req: "Clients MUST use the Server Name Indication extension in the TLS handshake [RFC6066].",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{tls: true})
			require.Equal(t, http.StatusSwitchingProtocols, ws.resp.StatusCode)
			require.NotNil(t, ws.req.TLS)
			assert.Equal(t, "ws.example.test", ws.req.TLS.ServerName)
		},
	},
	{
		id: "rfc6455/4.2.1/1", name: "a handshake in HTTP/1.0",
		req: "If the server, while reading the handshake, finds that the client did not send a handshake that matches the description below (note that as per [RFC2616], the order of the header fields is not important), including but not limited to any violations of the ABNF grammar specified for the components of the handshake, the server MUST stop processing the client's handshake and return an HTTP response with an appropriate error code (such as 400 Bad Request).",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{proto: "HTTP/1.0", answer: func(r *http.Request) string {
				if r.ProtoAtLeast(1, 1) {
					return ""
				}
				return "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
			}})
			require.NotEqual(t, http.StatusSwitchingProtocols, ws.resp.StatusCode)
		},
	},
	{
		id: "rfc6455/4.2.1/2", name: "a Sec-WebSocket-Version the server does not implement",
		req:  "If this version does not match a version understood by the server, the server MUST abort the WebSocket handshake described in this section and instead send an appropriate HTTP error code (such as 426 Upgrade Required) and a |Sec-WebSocket-Version| header field indicating the version(s) the server is capable of understanding.",
		skip: "the origin validates the handshake edge forwards unchanged, and its refusal reaches the client under rfc6455/4.1/4",
	},
	{
		id: "rfc6455/4.2.2/1", name: "a frame in the same write as the 101",
		req: "At this point, the server may begin sending (and receiving) data.",
		run: func(t *testing.T) {
			early := wsFrame{head: 0x81, payload: []byte("early")}
			ws := openWS(t, wsConf{originEarly: early.bytes()})
			require.Equal(t, http.StatusSwitchingProtocols, ws.resp.StatusCode)
			ws.client.want(0x81, []byte("early"))
		},
	},
	{
		id: "rfc8441/5", name: "an extended CONNECT with :protocol websocket over HTTP/2",
		req:  "The :protocol pseudo-header field MUST be included in the CONNECT request, and it MUST have a value of \"websocket\" to initiate a WebSocket connection on an HTTP/2 stream.",
		skip: "WebSocket is served over HTTP/1.1 only, and edge answers an extended CONNECT for any protocol other than connect-udp with 501, as CLAUDE.md states",
	},
	{
		id: "rfc9220/3", name: "an extended CONNECT with :protocol websocket over HTTP/3",
		req: "If a server advertises support for Extended CONNECT but receives an Extended CONNECT request with a \":protocol\" value that is unknown or is not supported, the server SHOULD respond to the request with a 501 (Not Implemented) status code (Section 15.6.2 of [HTTP]).",
		run: func(t *testing.T) {
			b := newProxyBench(t, always(okReply))
			b.p.MustAdd[WebSocket]("origin.test/chat", func(c *WebSocketCtx) error { return nil })
			h := b.dialH3Front(t)
			select {
			case settings := <-h.settings:
				require.Equal(t, uint64(1), settings[0x08], "the front advertises Extended CONNECT")
			case <-time.After(5 * time.Second):
				t.Fatal("no SETTINGS from the front")
			}
			s := h.open(t, h3Headers([]hpack.HeaderField{hf(":method", "CONNECT"), hf(":protocol", "websocket"), hf(":scheme", "https"),
				hf(":authority", "origin.test"), hf(":path", "/chat"), hf("sec-websocket-version", "13")}))
			assert.Equal(t, "501", s.message(true).status())
			assert.Zero(t, b.origin.accepted.Load())
		},
	},
	{
		id: "rfc6455/5.1/1", name: "an unmasked text frame from the client",
		req: "The server MUST close the connection upon receiving a frame that is not masked.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			ws.client.send(wsFrame{head: 0x81, payload: []byte("Hello")})
			ws.client.wantFailed(1002)
			ws.origin.wantNoData()
		},
	},
	{
		id: "rfc6455/5.1/2", name: "a masked text frame from the origin",
		req: "A client MUST close a connection if it detects a masked frame.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			ws.origin.send(wsFrame{head: 0x81, payload: []byte("Hello"), masked: true, key: wsKey})
			ws.origin.wantFailed(1002)
			ws.client.wantNoData()
		},
	},
	{
		id: "rfc6455/5.1/3", name: "frames from the origin toward the client",
		req: "A server MUST NOT mask any frames that it sends to the client.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			cross(ws.origin, ws.client, 0x81, []byte("Hello"))
			cross(ws.origin, ws.client, 0x89, []byte("Hello"))
		},
	},
	{
		id: "rfc6455/5.1/4", name: "frames from the client toward the origin",
		req: "To avoid confusing network intermediaries (such as intercepting proxies) and for security reasons that are further discussed in Section 10.3, a client MUST mask all frames that it sends to the server (see Section 5.3 for further details).",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			cross(ws.client, ws.origin, 0x81, []byte("Hello"))
			cross(ws.client, ws.origin, 0x88, closePayload(1000, ""))
		},
	},
	{
		id: "rfc6455/5.2/1", name: "text and binary frames of 0 to 65536 bytes",
		req: "If 0-125, that is the payload length.  If 126, the following 2 bytes interpreted as a 16-bit unsigned integer are the payload length.  If 127, the following 8 bytes interpreted as a 64-bit unsigned integer (the most significant bit MUST be 0) are the payload length.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			for _, n := range []int{0, 125, 126, 127, 128, 65535, 65536} {
				form := byte(n)
				switch {
				case n > 0xffff:
					form = 127
				case n > 125:
					form = 126
				}
				payload := bytes.Repeat([]byte("*"), n)
				for _, head := range []byte{0x81, 0x82} {
					ws.client.send(ws.client.frame(head, payload))
					require.Equal(t, form, ws.origin.want(head, payload).form, "%d bytes toward the origin", n)
					ws.origin.send(ws.origin.frame(head, payload))
					require.Equal(t, form, ws.client.want(head, payload).form, "%d bytes toward the client", n)
				}
			}
		},
	},
	{
		id: "rfc6455/5.2/2", name: "a 124-byte frame with an extended length",
		req: "Note that in all cases, the minimal number of bytes MUST be used to encode the length, for example, the length of a 124-byte-long string can't be encoded as the sequence 126, 0, 124.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			payload := bytes.Repeat([]byte("*"), 124)
			for _, form := range []byte{126, 127} {
				f := ws.client.frame(0x82, payload)
				f.form = form
				ws.client.send(f)
				require.Equal(t, byte(124), ws.origin.want(0x82, payload).form, "edge sends the minimal form")
				f = ws.origin.frame(0x82, payload)
				f.form = form
				ws.origin.send(f)
				require.Equal(t, byte(124), ws.client.want(0x82, payload).form, "edge sends the minimal form")
			}
		},
	},
	{
		id: "rfc6455/5.2/3", name: "a 64-bit length with its most significant bit set",
		req: "If 127, the following 8 bytes interpreted as a 64-bit unsigned integer (the most significant bit MUST be 0) are the payload length.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			b := []byte{0x82, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0x05}
			ws.client.write(append(b, wsKey[:]...))
			ws.client.wantFailed(1002, 1009)
			ws.origin.wantNoData()
		},
	},
	{
		id: "rfc6455/5.2/4", name: "RSV bits with no extension negotiated",
		req: "If a nonzero value is received and none of the negotiated extensions defines the meaning of such a nonzero value, the receiving endpoint MUST _Fail the WebSocket Connection_.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			// The heads of Autobahn cases 3.1 to 3.7, RSV 1 to 7 on text, binary, ping and close.
			frames := []wsFrame{
				ws.client.frame(0x91, []byte("a")), ws.client.frame(0xa1, []byte("b")),
				ws.client.frame(0xb1, []byte("c")), ws.client.frame(0xc1, []byte("d")),
				ws.client.frame(0xd2, []byte{0xff}), ws.client.frame(0xe9, []byte("p")),
				ws.client.frame(0xf8, closePayload(1000, "")),
			}
			ws.client.send(frames...)
			for _, f := range frames {
				ws.origin.want(f.head, f.payload)
			}
			cross(ws.origin, ws.client, 0x91, []byte("a"))
		},
	},
	{
		id: "rfc6455/5.2/5", name: "the reserved opcodes 0x3 to 0x7 and 0xB to 0xF",
		req: "If an unknown opcode is received, the receiving endpoint MUST _Fail the WebSocket Connection_.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			for _, head := range []byte{0x83, 0x84, 0x85, 0x86, 0x87, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f} {
				cross(ws.client, ws.origin, head, []byte("x"))
				cross(ws.origin, ws.client, head, []byte("x"))
			}
		},
	},
	{
		id: "rfc6455/5.3/1", name: "two identical frames toward the origin",
		req: "When preparing a masked frame, the client MUST pick a fresh masking key from the set of allowed 32-bit values.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			ws.client.send(ws.client.frame(0x81, []byte("same")), ws.client.frame(0x81, []byte("same")))
			first := ws.origin.want(0x81, []byte("same"))
			second := ws.origin.want(0x81, []byte("same"))
			assert.NotEqual(t, first.key, second.key)
			assert.NotEqual(t, wsKey, first.key, "edge masks with a key of its own")
		},
	},
	{
		id: "rfc6455/5.4/1", name: "a fragmented text message with a Ping between its fragments",
		req: "Message fragments MUST be delivered to the recipient in the order sent by the sender.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			frames := []wsFrame{
				ws.client.frame(0x01, []byte("fragment1")), ws.client.frame(0x89, nil),
				ws.client.frame(0x00, []byte("fragment2")), ws.client.frame(0x80, []byte("fragment3")),
			}
			ws.client.send(frames...)
			for _, f := range frames {
				ws.origin.want(f.head, f.payload)
			}
		},
	},
	{
		id: "rfc6455/5.4/2", name: "a Ping answered while its message is incomplete",
		req: "An endpoint MUST be capable of handling control frames in the middle of a fragmented message.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			cross(ws.client, ws.origin, 0x01, []byte("Hel"))
			cross(ws.client, ws.origin, 0x89, []byte("k"))
			cross(ws.origin, ws.client, 0x8a, []byte("k"))
			cross(ws.client, ws.origin, 0x80, []byte("lo"))
		},
	},
	{
		id: "rfc6455/5.4/3", name: "a Ping of 125 bytes",
		req: "As control frames cannot be fragmented, an intermediary MUST NOT attempt to change the fragmentation of a control frame.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			payload := bytes.Repeat([]byte{0xfe}, 125)
			cross(ws.client, ws.origin, 0x89, payload)
			cross(ws.origin, ws.client, 0x89, payload)
		},
	},
	{
		id: "rfc6455/5.4/4", name: "a fragmented message with RSV2 on every fragment",
		req: "An intermediary MUST NOT change the fragmentation of a message if any reserved bit values are used and the meaning of these values is not known to the intermediary.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			frames := []wsFrame{
				ws.client.frame(0x21, []byte("a")), ws.client.frame(0x20, []byte("b")), ws.client.frame(0xa0, []byte("c")),
			}
			ws.client.send(frames...)
			for _, f := range frames {
				ws.origin.want(f.head, f.payload)
			}
		},
	},
	{
		id: "rfc6455/5.4/5", name: "a compressed message in two fragments under permessage-deflate",
		req: "An intermediary MUST NOT change the fragmentation of any message in the context of a connection where extensions have been negotiated and the intermediary is not aware of the semantics of the negotiated extensions.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{reqHeader: deflateExtension, respHeader: deflateExtension})
			require.Equal(t, "permessage-deflate", ws.resp.Header.Get("Sec-WebSocket-Extensions"))
			// The fragments of RFC 7692 section 7.2.3.1, RSV1 on the first only.
			ws.origin.write([]byte{0x41, 0x03, 0xf2, 0x48, 0xcd, 0x80, 0x04, 0xc9, 0xc9, 0x07, 0x00})
			ws.client.want(0x41, deflateHello[:3])
			ws.client.want(0x80, deflateHello[3:])
			ws.client.send(ws.client.frame(0x41, deflateHello[:3]), ws.client.frame(0x80, deflateHello[3:]))
			ws.origin.want(0x41, deflateHello[:3])
			ws.origin.want(0x80, deflateHello[3:])
		},
	},
	{
		id: "rfc6455/5.4/6", name: "a text fragment followed by a second text frame",
		req: "The fragments of one message MUST NOT be interleaved between the fragments of another message unless an extension has been negotiated that can interpret the interleaving.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			cross(ws.client, ws.origin, 0x01, []byte("a"))
			cross(ws.client, ws.origin, 0x81, []byte("b"))
		},
	},
	{
		id: "rfc6455/5.4/7", name: "a continuation frame with no message to continue",
		req: "A fragmented message consists of a single frame with the FIN bit clear and an opcode other than 0, followed by zero or more frames with the FIN bit clear and the opcode set to 0, and terminated by a single frame with the FIN bit set and an opcode of 0.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			cross(ws.client, ws.origin, 0x80, []byte("x"))
			cross(ws.origin, ws.client, 0x00, []byte("y"))
		},
	},
	{
		id: "rfc6455/5.4/8", name: "fragmented and unfragmented messages",
		req:  "Clients and servers MUST support receiving both fragmented and unfragmented messages.",
		skip: "checked under rfc6455/5.4/1 and rfc6455/5.2/1",
	},
	{
		id: "rfc6455/5.5/1", name: "a Ping of 126 bytes from the client",
		req: "All control frames MUST have a payload length of 125 bytes or less and MUST NOT be fragmented.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			ws.client.send(ws.client.frame(0x89, bytes.Repeat([]byte("*"), 126)))
			ws.client.wantFailed(1002)
			ws.origin.wantNoData()
		},
	},
	{
		id: "rfc6455/5.5/2", name: "a Ping with FIN clear from the origin",
		req: "All control frames MUST have a payload length of 125 bytes or less and MUST NOT be fragmented.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			ws.origin.send(ws.origin.frame(0x09, []byte("p")), ws.origin.frame(0x80, nil))
			ws.origin.wantFailed(1002)
			ws.client.wantNoData()
		},
	},
	{
		id: "rfc6455/5.5/3", name: "a Ping of 126 bytes to a handler merging both readers",
		req: "All control frames MUST have a payload length of 125 bytes or less and MUST NOT be fragmented.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{handler: mergeFrames})
			ws.client.send(ws.client.frame(0x89, bytes.Repeat([]byte("*"), 126)))
			ws.client.wantFailed(1002)
			ws.origin.wantNoData()
		},
	},
	{
		id: "rfc6455/5.5.1/1", name: "a Close from the client",
		req: "If an endpoint receives a Close frame and did not previously send a Close frame, the endpoint MUST send a Close frame in response.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			cross(ws.client, ws.origin, 0x88, closePayload(1000, "bye"))
			cross(ws.origin, ws.client, 0x88, closePayload(1000, "bye"))
			ws.origin.wantSilent()
			require.NoError(t, ws.origin.conn.Close())
			assert.Empty(t, ws.client.wantEnd())
		},
	},
	{
		id: "rfc6455/5.5.1/2", name: "a Close from the client to a handler merging both readers",
		req: "If an endpoint receives a Close frame and did not previously send a Close frame, the endpoint MUST send a Close frame in response.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{handler: mergeFrames})
			cross(ws.client, ws.origin, 0x88, closePayload(1000, "bye"))
			cross(ws.origin, ws.client, 0x88, closePayload(1000, "bye"))
			ws.origin.wantSilent()
			require.NoError(t, ws.origin.conn.Close())
			assert.Empty(t, ws.client.wantEnd())
		},
	},
	{
		id: "rfc6455/5.5.1/3", name: "a Close and a write shutdown from the client",
		req: "If an endpoint receives a Close frame and did not previously send a Close frame, the endpoint MUST send a Close frame in response.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			ws.client.send(ws.client.frame(0x88, closePayload(1000, "")))
			require.NoError(t, ws.client.conn.(*net.TCPConn).CloseWrite())
			ws.origin.want(0x88, closePayload(1000, ""))
			ws.origin.send(ws.origin.frame(0x88, closePayload(1000, "")))
			ws.client.want(0x88, closePayload(1000, ""))
		},
	},
	{
		id: "rfc6455/5.5.1/4", name: "a Close and a write shutdown from the client to a handler merging both readers",
		req: "If an endpoint receives a Close frame and did not previously send a Close frame, the endpoint MUST send a Close frame in response.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{handler: mergeFrames})
			ws.client.send(ws.client.frame(0x88, closePayload(1000, "")))
			require.NoError(t, ws.client.conn.(*net.TCPConn).CloseWrite())
			ws.origin.want(0x88, closePayload(1000, ""))
			ws.origin.send(ws.origin.frame(0x88, closePayload(1000, "")))
			ws.client.want(0x88, closePayload(1000, ""))
		},
	},
	{
		id: "rfc6455/5.5.1/5", name: "a Close from the origin",
		req: "The server MUST close the underlying TCP connection immediately; the client SHOULD wait for the server to close the connection but MAY close the connection at any time after sending and receiving a Close message, e.g., if it has not received a TCP Close from the server in a reasonable time period.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			cross(ws.origin, ws.client, 0x88, closePayload(1001, ""))
			cross(ws.client, ws.origin, 0x88, closePayload(1001, ""))
			ws.origin.wantSilent()
			require.NoError(t, ws.origin.conn.Close())
			assert.Empty(t, ws.client.wantEnd())
		},
	},
	{
		id: "rfc6455/5.5.1/6", name: "a text frame after a Close",
		req: "The application MUST NOT send any more data frames after sending a Close frame.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			ws.client.send(ws.client.frame(0x88, closePayload(1000, "")), ws.client.frame(0x81, []byte("late")))
			ws.origin.want(0x88, closePayload(1000, ""))
			ws.origin.wantSilent()
		},
	},
	{
		id: "rfc6455/5.5.1/7", name: "a Close with a body of one byte",
		req: "If there is a body, the first two bytes of the body MUST be a 2-byte unsigned integer (in network byte order) representing a status code with value /code/ defined in Section 7.4.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			cross(ws.client, ws.origin, 0x88, []byte{0x03})
		},
	},
	{
		id: "rfc6455/5.5.1/8", name: "a Close from the origin to a handler merging both readers",
		req: "The server MUST close the underlying TCP connection immediately; the client SHOULD wait for the server to close the connection but MAY close the connection at any time after sending and receiving a Close message, e.g., if it has not received a TCP Close from the server in a reasonable time period.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{handler: mergeFrames})
			cross(ws.origin, ws.client, 0x88, closePayload(1001, ""))
			cross(ws.client, ws.origin, 0x88, closePayload(1001, ""))
			ws.origin.wantSilent()
			require.NoError(t, ws.origin.conn.Close())
			assert.Empty(t, ws.client.wantEnd())
		},
	},
	{
		id: "rfc6455/5.5.1/9", name: "a masked frame from the origin while the client streams",
		req: "The application MUST NOT send any more data frames after sending a Close frame.",
		run: func(t *testing.T) {
			// No payload, which edge would leave unread and turn its close into a reset.
			wantNothingBehindTheClose(t, (wsFrame{head: 0x81, masked: true, key: wsKey}).bytes())
		},
	},
	{
		id: "rfc6455/5.5.1/10", name: "a frame past the frame limit from the origin while the client streams",
		req: "The application MUST NOT send any more data frames after sending a Close frame.",
		run: func(t *testing.T) {
			wantNothingBehindTheClose(t, binary.BigEndian.AppendUint64([]byte{0x82, 0x7f}, 1<<20+1))
		},
	},
	{
		id: "rfc6455/5.5.2/1", name: "a Ping with a payload",
		req: "Upon receipt of a Ping frame, an endpoint MUST send a Pong frame in response, unless it already received a Close frame.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			cross(ws.client, ws.origin, 0x89, []byte("Hello"))
			cross(ws.origin, ws.client, 0x8a, []byte("Hello"))
		},
	},
	{
		id: "rfc6455/5.5.3/1", name: "an unsolicited Pong",
		req: "A response to an unsolicited Pong frame is not expected.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			cross(ws.client, ws.origin, 0x8a, []byte("beat"))
			ws.client.wantSilent()
		},
	},
	{
		id: "rfc6455/5.5.3/2", name: "ten Pings before any Pong",
		req:  "If an endpoint receives a Ping frame and has not yet sent Pong frame(s) in response to previous Ping frame(s), the endpoint MAY elect to send a Pong frame for only the most recently processed Ping frame.",
		skip: "a choice of the endpoint that answers, and edge relays each Ping to it under rfc6455/5.5.2/1",
	},
	{
		id: "rfc6455/5.8/1", name: "an extension negotiated at the handshake",
		req:  "The endpoints of a connection MUST negotiate the use of any extensions during the opening handshake.",
		skip: "checked under rfc6455/4.1/3",
	},
	{
		id: "rfc6455/6.2/1", name: "a masked text frame read by the handler",
		req: "A server MUST remove masking for data frames received from a client as described in Section 5.3.",
		run: func(t *testing.T) {
			seen := make(chan string, 1)
			ws := openWS(t, wsConf{handler: func(c *WebSocketCtx) error {
				f, err := c.Outbound().ReadFrame()
				if err != nil {
					return err
				}
				seen <- string(f.Payload())
				return f.Forward()
			}})
			cross(ws.client, ws.origin, 0x81, []byte("Hello"))
			assert.Equal(t, "Hello", <-seen)
		},
	},
	{
		id: "rfc6455/7.1.7/1", name: "a text frame behind a Ping of 126 bytes",
		req: "An endpoint MUST NOT continue to attempt to process data (including a responding Close frame) from the remote endpoint after being instructed to _Fail the WebSocket Connection_.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			ws.client.send(ws.client.frame(0x89, bytes.Repeat([]byte("*"), 126)), ws.client.frame(0x81, []byte("after")))
			ws.client.wantFailed(1002)
			ws.origin.wantNoData()
		},
	},
	{
		id: "rfc6455/7.1.7/2", name: "a Ping of 126 bytes from the client, answered with a Close",
		req: "If _The WebSocket Connection is Established_ prior to the point where the endpoint is required to _Fail the WebSocket Connection_, the endpoint SHOULD send a Close frame with an appropriate status code (Section 7.4) before proceeding to _Close the WebSocket Connection_.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			ws.client.write(badPingHead)
			frames := ws.client.wantEnd()
			require.Len(t, frames, 1, "a Close precedes the end")
			assert.Equal(t, byte(0x88), frames[0].head)
		},
	},
	{
		id: "rfc6455/7.2.1/1", name: "the origin drops its TCP connection",
		req: "If at any point the underlying transport layer connection is unexpectedly lost, the client MUST _Fail the WebSocket Connection_.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			cross(ws.client, ws.origin, 0x81, []byte("Hello"))
			require.NoError(t, ws.origin.conn.Close())
			ws.client.wantFailed(1001, 1011)
		},
	},
	{
		id: "rfc6455/7.3/1", name: "a Ping of 126 bytes from the client, seen from the origin",
		req: "In either case, an endpoint initiates a closure by following the procedures to _Start the WebSocket Closing Handshake_ (Section 7.1.2).",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			ws.client.write(badPingHead)
			frames := ws.origin.wantEnd()
			require.Len(t, frames, 1, "a Close precedes the end")
			assert.Equal(t, byte(0x88), frames[0].head)
		},
	},
	{
		id: "rfc6455/7.4.1/1", name: "a Close with the reserved code 1005",
		req: "1005 is a reserved value and MUST NOT be set as a status code in a Close control frame by an endpoint.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			cross(ws.client, ws.origin, 0x88, closePayload(1005, ""))
		},
	},
	{
		id: "rfc6455/7.4.2/1", name: "Close codes of 3000 to 4999",
		req:  "Status codes in the range 3000-3999 are reserved for use by libraries, frameworks, and applications.",
		skip: "edge reads no code it relays, the path is the one of rfc6455/7.4.1/1",
	},
	{
		id: "rfc6455/8.1/1", name: "a text frame of invalid UTF-8",
		req: "When an endpoint is to interpret a byte stream as UTF-8 but finds that the byte stream is not, in fact, a valid UTF-8 stream, that endpoint MUST _Fail the WebSocket Connection_.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			invalid := []byte{0xce, 0xba, 0xe1, 0xbd, 0xb9, 0xcf, 0x83, 0xce, 0xbc, 0xce, 0xb5, 0xed, 0xa0, 0x80}
			cross(ws.client, ws.origin, 0x81, invalid)
			cross(ws.origin, ws.client, 0x81, invalid)
		},
	},
	{
		id: "rfc6455/10.3/1", name: "masking keys toward the origin",
		req:  "Clients MUST choose a new masking key for each frame, using an algorithm that cannot be predicted by end applications that provide data.",
		skip: "checked under rfc6455/5.3/1",
	},
	{
		id: "rfc6455/10.4/1", name: "frames of the frame limit and of one byte more from the client",
		req: "Implementations that have implementation- and/or platform-specific limitations regarding the frame size or total message size after reassembly from multiple frames MUST protect themselves against exceeding those limits.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{maxFrame: 1 << 10})
			cross(ws.client, ws.origin, 0x82, make([]byte, 1<<10))
			// The header alone. A payload left unread would turn the close into a reset.
			b := binary.BigEndian.AppendUint16([]byte{0x82, 0xfe}, 1<<10+1)
			ws.client.write(append(b, wsKey[:]...))
			ws.client.wantFailed(1009)
			ws.origin.wantNoData()
		},
	},
	{
		id: "rfc6455/10.4/2", name: "a frame of one byte past the frame limit from the origin",
		req: "Implementations that have implementation- and/or platform-specific limitations regarding the frame size or total message size after reassembly from multiple frames MUST protect themselves against exceeding those limits.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{})
			ws.origin.write(binary.BigEndian.AppendUint64([]byte{0x82, 0x7f}, 1<<20+1))
			ws.origin.wantFailed(1009)
			ws.client.wantNoData()
		},
	},
	{
		id: "rfc6455/10.4/3", name: "a frame of one byte past the frame limit to a handler merging both readers",
		req: "Implementations that have implementation- and/or platform-specific limitations regarding the frame size or total message size after reassembly from multiple frames MUST protect themselves against exceeding those limits.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{handler: mergeFrames})
			b := binary.BigEndian.AppendUint64([]byte{0x82, 0xff}, 1<<20+1)
			ws.client.write(append(b, wsKey[:]...))
			ws.client.wantFailed(1009)
			ws.origin.wantNoData()
		},
	},
	{
		id: "rfc6455/10.4/4", name: "a message larger than the frame limit in fragments",
		req:  "Such an implementation SHOULD impose a limit on frame sizes and the total message size after reassembly from multiple frames.",
		skip: "edge relays frame by frame and reassembles no message, so the frame limit bounds its memory and the message limit belongs to the endpoint that reassembles",
	},
	{
		id: "rfc7692/5/1", name: "an acceptance of permessage-deflate together with a conflicting extension",
		req:  "A server MUST NOT accept a PMCE extension negotiation offer together with another extension if the PMCE will conflict with the extension on their use of the RSV1 bit.",
		skip: "a rule on the origin's answer and on the client's check of it, both of which edge forwards unchanged under rfc6455/4.1/3",
	},
	{
		id: "rfc7692/5/2", name: "an acceptance of a PMCE the client did not offer",
		req:  "If a server gives an invalid response, such as accepting a PMCE that the client did not offer, the client MUST _Fail the WebSocket Connection_.",
		skip: "a rule on the origin's answer and on the client's check of it, both of which edge forwards unchanged under rfc6455/4.1/3",
	},
	{
		id: "rfc7692/6/1", name: "a compressed message under permessage-deflate",
		req: "An endpoint receiving a compressed message decompresses the concatenation of the compressed data of the frames of the message by following the decompression procedure specified by the PMCE in use.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{reqHeader: deflateExtension, respHeader: deflateExtension})
			// The frame of RFC 7692 section 7.2.3.1, which edge relays compressed.
			ws.origin.write(append([]byte{0xc1, 0x07}, deflateHello...))
			ws.client.want(0xc1, deflateHello)
			cross(ws.client, ws.origin, 0xc1, deflateHello)
		},
	},
	{
		id: "rfc7692/6/2", name: "RSV1 on a Ping under permessage-deflate",
		req: "An endpoint MUST NOT set the \"Per-Message Compressed\" bit of control frames and non-first fragments of a data message.  An endpoint receiving such a frame MUST _Fail the WebSocket Connection_.",
		run: func(t *testing.T) {
			ws := openWS(t, wsConf{reqHeader: deflateExtension, respHeader: deflateExtension})
			cross(ws.client, ws.origin, 0xc9, []byte("p"))
		},
	},
	{
		id: "rfc7692/7/1", name: "a sliding window past 32,768 bytes",
		req:  "An endpoint MUST NOT use an LZ77 sliding window longer than 32,768 bytes.",
		skip: "a rule on the compressor and the decompressor, and edge never decompresses a payload",
	},
}

func TestUpgrade_InsideAnHTTP2Connect(t *testing.T) {
	origin := plainUpgradeOrigin(t)
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.DialContext = pinnedDialer(originURL.Host)
	p := testProxy(t, WithTransport(tr))
	p.MustAdd[TCP]("allowed.test:80", relayStream)
	p.MustAdd("allowed.test/ws", forwardHandler, WithMethods[HTTP](http.MethodGet))

	w, br := h2cConnect(t, startProxy(t, p), "allowed.test:80")
	_, err = fmt.Fprintf(w, upgradeRequest, "/ws", "allowed.test")
	require.NoError(t, err)
	got := make(chan *http.Response, 1)
	go func() {
		resp, rerr := http.ReadResponse(br, nil)
		if rerr == nil {
			got <- resp
		}
	}()
	select {
	case resp := <-got:
		assert.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	case <-time.After(2 * time.Second):
		t.Fatal("the upgrade was not answered")
	}
}
