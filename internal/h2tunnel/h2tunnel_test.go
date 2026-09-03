// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package h2tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// echoServer serves CONNECT by echoing the stream, and hands each request to seen.
func echoServer(t *testing.T, seen func(*http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			seen(r)
		}
		if r.Method != http.MethodConnect {
			http.Error(w, "not a CONNECT", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("X-Refuse") != "" {
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				_ = rc.Flush()
			}
			if err != nil {
				return
			}
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func dial(t *testing.T, srv *httptest.Server) *Conn {
	t.Helper()
	cfg := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	cfg.NextProtos = []string{"h2"}
	tc, err := tls.Dial("tcp", srv.Listener.Addr().String(), cfg)
	require.NoError(t, err)
	require.Equal(t, "h2", tc.ConnectionState().NegotiatedProtocol)
	c, err := Client(tc, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func open(t *testing.T, c *Conn, header http.Header) (*Stream, *Response) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, resp, err := c.Open(ctx, Request{Authority: "origin.test:443", Header: header})
	require.NoError(t, err)
	return s, resp
}

// Streams echo what they carry, several at once, and bytes past the frame size and both
// windows come back intact.
func TestConn_EchoesAcrossWindows(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)

	var wg sync.WaitGroup
	for i := range 4 {
		s, resp := open(t, c, nil)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		payload := make([]byte, (i+1)*(3<<20)/4)
		_, _ = rand.Read(payload)
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := make([]byte, len(payload))
			_, err := io.ReadFull(s, got)
			assert.NoError(t, err)
			assert.True(t, bytes.Equal(payload, got), "the echo differs")
		}()
		n, err := s.Write(payload)
		require.NoError(t, err)
		require.Equal(t, len(payload), n)
	}
	wg.Wait()
}

// A refusal is an answer, with the status the peer chose.
func TestConn_RefusalIsAnAnswer(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	s, resp := open(t, c, http.Header{"X-Refuse": {"1"}})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	body, err := io.ReadAll(s)
	require.NoError(t, err, "ReadAll ends on the EOF of the peer's END_STREAM")
	assert.Equal(t, "refused\n", string(body))
	assert.True(t, c.CanOpen(), "the connection outlives a refused stream")
}

// Ending the proxy-bound direction reaches the peer as the end of its body, and the peer's
// end reaches the reads as EOF once what it sent is drained.
func TestStream_CloseWriteIsTheEndOfTheBody(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	s, _ := open(t, c, nil)
	_, err := s.Write([]byte("last words"))
	require.NoError(t, err)
	require.NoError(t, s.CloseWrite())
	body, err := io.ReadAll(s)
	require.NoError(t, err)
	assert.Equal(t, "last words", string(body))
	_, err = s.Write([]byte("too late"))
	require.Error(t, err)
}

// Closing a stream resets it, which the peer sees on its body, and the connection goes on.
func TestStream_CloseResetsTheStream(t *testing.T) {
	bodyErr := make(chan error, 1)
	srv := echoServer(t, func(r *http.Request) {
		go func() {
			<-r.Context().Done()
			bodyErr <- context.Cause(r.Context())
		}()
	})
	c := dial(t, srv)
	s, _ := open(t, c, nil)
	require.NoError(t, s.Close())
	select {
	case err := <-bodyErr:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the peer did not see the reset")
	}
	_, err := s.Read(make([]byte, 1))
	require.Error(t, err)
	again, resp := open(t, c, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = again.Write([]byte("x"))
	require.NoError(t, err)
}

// A read deadline is a timeout, not the end of the stream.
func TestStream_ReadDeadline(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	s, _ := open(t, c, nil)
	require.NoError(t, s.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, err := s.Read(make([]byte, 1))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.NoError(t, s.SetReadDeadline(time.Time{}))
	_, err = s.Write([]byte("after"))
	require.NoError(t, err)
	buf := make([]byte, 8)
	n, err := s.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "after", string(buf[:n]))
}

// A GOAWAY closes the door to new streams and leaves the open ones alone.
func TestConn_GoAway(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	s, _ := open(t, c, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = srv.Config.Shutdown(ctx) }()
	assert.Eventually(t, func() bool { return !c.CanOpen() }, 5*time.Second, 10*time.Millisecond)
	_, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.ErrorIs(t, err, ErrGoAway)

	_, err = s.Write([]byte("still served"))
	require.NoError(t, err)
	buf := make([]byte, 16)
	n, err := s.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "still served", string(buf[:n]))
}

// The peer going away ends every stream, and Open reports the end.
func TestConn_PeerGone(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	s, _ := open(t, c, nil)
	srv.CloseClientConnections()
	_, err := s.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the connection did not end")
	}
	require.Error(t, c.Err())
	_, _, err = c.Open(context.Background(), Request{Authority: "origin.test:443"})
	require.Error(t, err)
}

// Closing the connection ends its streams.
func TestConn_CloseEndsTheStreams(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	s, _ := open(t, c, nil)
	require.NoError(t, c.Close())
	_, err := s.Read(make([]byte, 1))
	require.ErrorIs(t, err, net.ErrClosed)
	_, err = s.Write([]byte("x"))
	require.ErrorIs(t, err, net.ErrClosed)
}

// An extended CONNECT is refused unless the peer enabled it, and carries its :protocol when
// it did. Go's server enables it behind GODEBUG=http2xconnect=1, read from the environment
// at startup.
func TestConn_ExtendedConnect(t *testing.T) {
	var protocol string
	srv := echoServer(t, func(r *http.Request) { protocol = r.Header.Get(":protocol") })
	c := dial(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := Request{Protocol: "connect-udp", Scheme: "https", Authority: srv.Listener.Addr().String(),
		Path: "/.well-known/masque/udp/192.0.2.1/53/"}
	if !strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1") {
		_, _, err := c.Open(ctx, req)
		require.ErrorIs(t, err, ErrExtendedConnect)
		t.Skip("GODEBUG=http2xconnect=1 is not set, Go's server refuses extended CONNECT")
	}
	s, resp, err := c.Open(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "connect-udp", protocol)
	_, err = s.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 8)
	n, err := s.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf[:n]))
}

// A peer that is not HTTP/2 at all ends the connection with an error rather than a hang.
func TestConn_NotHTTP2(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		_ = conn.Close()
	}()
	nc, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	c, err := Client(nc, 0)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err = c.Open(ctx, Request{Authority: "origin.test:443"})
	require.Error(t, err)
	require.False(t, errors.Is(err, context.DeadlineExceeded))
}

// fakePeer is the server end of a TCP connection, reading the client preface, sending the
// settings the test asks for and answering every HEADERS with 200. What it does past that
// is the test's.
type fakePeer struct {
	fr     *http2.Framer
	enc    *hpack.Encoder
	encBuf bytes.Buffer
	wmu    sync.Mutex
	mu     sync.Mutex
	// connWindow is what the client lets the peer send on the connection.
	connWindow int64
}

func startFakePeer(nc net.Conn, settings ...http2.Setting) (*fakePeer, error) {
	p := &fakePeer{fr: http2.NewFramer(nc, nc), connWindow: defaultWindow}
	p.fr.ReadMetaHeaders = hpack.NewDecoder(hpackTableSize, nil)
	p.enc = hpack.NewEncoder(&p.encBuf)
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(nc, preface); err != nil {
		return nil, err
	}
	return p, p.fr.WriteSettings(settings...)
}

func (p *fakePeer) answer(id uint32) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	p.encBuf.Reset()
	_ = p.enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	return p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: p.encBuf.Bytes(), EndHeaders: true})
}

func (p *fakePeer) writeData(id uint32, b []byte) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	p.mu.Lock()
	p.connWindow -= int64(len(b))
	p.mu.Unlock()
	return p.fr.WriteData(id, false, b)
}

func (p *fakePeer) window() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connWindow
}

func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	server = <-accepted
	require.NotNil(t, server)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return client, server
}

// A peer that stops reading leaves a write stuck on the socket. Close still returns at
// once, and the stuck write with it.
func TestConn_CloseBehindAStuckWrite(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan struct{})
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 24})
		if err != nil {
			return
		}
		_ = peer.fr.WriteWindowUpdate(0, 1<<24)
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
				close(answered)
				return
			}
		}
	}()

	c, err := Client(cli, 0)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, resp, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	<-answered

	wrote := make(chan error, 1)
	go func() {
		_, werr := s.Write(make([]byte, 32<<20))
		wrote <- werr
	}()
	select {
	case <-wrote:
		t.Fatal("the write did not stall, the peer is still reading")
	case <-time.After(300 * time.Millisecond):
	}

	start := time.Now()
	require.NoError(t, c.Close())
	assert.Less(t, time.Since(start), 3*time.Second, "Close waited on the stuck write")
	select {
	case werr := <-wrote:
		require.Error(t, werr)
	case <-time.After(3 * time.Second):
		t.Fatal("the stuck write outlived the connection")
	}
}

// Bytes buffered on a stream the caller closes without reading go back to the connection
// window, so the streams that follow on the connection are not starved.
func TestConn_AbandonedStreamsReturnTheWindow(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 8)
	ready := make(chan *fakePeer, 1)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		if err != nil {
			close(ready)
			return
		}
		ready <- peer
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			switch f := f.(type) {
			case *http2.MetaHeadersFrame:
				_ = peer.answer(f.StreamID)
				answered <- f.StreamID
			case *http2.WindowUpdateFrame:
				if f.StreamID == 0 {
					peer.mu.Lock()
					peer.connWindow += int64(f.Increment)
					peer.mu.Unlock()
				}
			}
		}
	}()

	c, err := Client(cli, 0)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	peer := <-ready
	require.NotNil(t, peer)
	require.Eventually(t, func() bool { return peer.window() == connWindow }, 5*time.Second, 5*time.Millisecond,
		"the client raises the connection window at startup")

	const chunk = 256 << 10
	for range 4 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s, _, oerr := c.Open(ctx, Request{Authority: "origin.test:443"})
		cancel()
		require.NoError(t, oerr)
		id := <-answered
		for sent := 0; sent < chunk; sent += 16384 {
			require.NoError(t, peer.writeData(id, make([]byte, 16384)))
		}
		require.NoError(t, s.Close())
	}
	assert.Eventually(t, func() bool { return peer.window() == connWindow }, 5*time.Second, 10*time.Millisecond,
		"the window was not returned for the bytes the abandoned streams held")
}

// The peer changes SETTINGS_MAX_FRAME_SIZE while streams are opened, which the race detector
// watches.
func TestConn_SettingsWhileOpening(t *testing.T) {
	cli, srv := tcpPair(t)
	stop := make(chan struct{})
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		if err != nil {
			return
		}
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				peer.wmu.Lock()
				_ = peer.fr.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384 + uint32(time.Now().UnixNano()%1000)}) //nolint:gosec // small
				peer.wmu.Unlock()
				time.Sleep(50 * time.Microsecond)
			}
		}()
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
			}
		}
	}()

	c, err := Client(cli, 0)
	require.NoError(t, err)
	defer func() { close(stop); _ = c.Close() }()
	for range 200 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s, _, oerr := c.Open(ctx, Request{Authority: "origin.test:443"})
		cancel()
		require.NoError(t, oerr)
		_ = s.Close()
	}
}

// A read with bytes in hand returns them, and one without honours its deadline, while the
// writer is stuck on a peer that stopped reading.
func TestStream_ReadDeadlineBehindAStuckWriter(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 1)
	ready := make(chan *fakePeer, 1)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 24})
		if err != nil {
			close(ready)
			return
		}
		_ = peer.fr.WriteWindowUpdate(0, 1<<28)
		ready <- peer
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
				answered <- mh.StreamID
				// Nothing reads the socket from here on.
				return
			}
		}
	}()

	c, err := Client(cli, 0)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	peer := <-ready
	require.NotNil(t, peer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	cancel()
	require.NoError(t, err)
	id := <-answered

	// More than half a window, so reading it owes a WINDOW_UPDATE.
	go func() {
		for range 40 {
			if werr := peer.writeData(id, make([]byte, 16384)); werr != nil {
				return
			}
		}
	}()
	go func() { _, _ = s.Write(make([]byte, 64<<20)) }()
	time.Sleep(500 * time.Millisecond)

	require.NoError(t, s.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	buf := make([]byte, 32<<10)
	for {
		start := time.Now()
		_, rerr := s.Read(buf)
		require.Less(t, time.Since(start), 2*time.Second, "a read waited on the stuck writer")
		if rerr != nil {
			require.ErrorIs(t, rerr, os.ErrDeadlineExceeded)
			return
		}
	}
}

// A connection the peer is going away from ends once its last stream ended, at once when
// it has none.
func TestConn_GoAwayEndsWhenDrained(t *testing.T) {
	cli, srv := tcpPair(t)
	goAway := make(chan uint32, 1)
	go func() {
		peer, err := startFakePeer(srv)
		if err != nil {
			return
		}
		go func() {
			last := <-goAway
			peer.wmu.Lock()
			_ = peer.fr.WriteGoAway(last, http2.ErrCodeNo, nil)
			peer.wmu.Unlock()
		}()
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)

	goAway <- s.id
	require.Eventually(t, func() bool { return !c.CanOpen() }, 5*time.Second, 10*time.Millisecond)
	select {
	case <-c.Done():
		t.Fatal("the connection ended with a stream still open on it")
	case <-time.After(100 * time.Millisecond):
	}
	require.NoError(t, s.Close())
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the connection outlived its last stream")
	}
	require.ErrorIs(t, c.Err(), ErrGoAway)
}

// A WINDOW_UPDATE that overflows a stream's send window ends that stream with a
// FLOW_CONTROL_ERROR the peer receives, and the connection goes on.
func TestConn_StreamWindowOverflow(t *testing.T) {
	cli, srv := tcpPair(t)
	overflow := make(chan uint32, 1)
	reset := make(chan http2.ErrCode, 1)
	go func() {
		peer, err := startFakePeer(srv)
		if err != nil {
			return
		}
		go func() {
			id := <-overflow
			peer.wmu.Lock()
			_ = peer.fr.WriteWindowUpdate(id, 1<<31-1)
			_ = peer.fr.WriteWindowUpdate(id, 1<<31-1)
			peer.wmu.Unlock()
		}()
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			switch f := f.(type) {
			case *http2.MetaHeadersFrame:
				_ = peer.answer(f.StreamID)
			case *http2.RSTStreamFrame:
				reset <- f.ErrCode
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)

	overflow <- s.id
	select {
	case code := <-reset:
		assert.Equal(t, http2.ErrCodeFlowControl, code)
	case <-time.After(5 * time.Second):
		t.Fatal("the peer did not receive the reset")
	}
	_, err = s.Read(make([]byte, 1))
	var se http2.StreamError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http2.ErrCodeFlowControl, se.Code)
	require.True(t, c.CanOpen())
	again, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	_ = again.Close()
}

// The frames the read loop owes, WINDOW_UPDATEs, PING acks and SETTINGS acks, go out once
// the writer is free again, however long a peer that stopped reading kept it stuck.
func TestConn_OwedFramesSurviveAStuckWriter(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 1)
	ready := make(chan *fakePeer, 1)
	resume := make(chan struct{})
	var pingAcks, connCredit atomic.Int64
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 24})
		if err != nil {
			close(ready)
			return
		}
		_ = peer.fr.WriteWindowUpdate(0, 1<<28)
		ready <- peer
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
				answered <- mh.StreamID
				break
			}
		}
		// Nothing reads the socket until resume.
		<-resume
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			switch f := f.(type) {
			case *http2.PingFrame:
				if f.IsAck() {
					pingAcks.Add(1)
				}
			case *http2.WindowUpdateFrame:
				if f.StreamID == 0 {
					connCredit.Add(int64(f.Increment))
				}
			}
		}
	}()

	c, err := Client(cli, 0)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	peer := <-ready
	require.NotNil(t, peer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	cancel()
	require.NoError(t, err)
	id := <-answered

	// The writer sticks on the socket, and the peer asks for more than the queue holds.
	go func() { _, _ = s.Write(make([]byte, 64<<20)) }()
	time.Sleep(300 * time.Millisecond)
	for range maxControlFrames - 8 {
		peer.wmu.Lock()
		_ = peer.fr.WritePing(false, [8]byte{1})
		peer.wmu.Unlock()
	}
	for sent := 0; sent < window; sent += 16384 {
		require.NoError(t, peer.writeData(id, make([]byte, 16384)))
	}
	buf := make([]byte, 64<<10)
	for got := 0; got < window; {
		n, rerr := s.Read(buf)
		require.NoError(t, rerr)
		got += n
	}

	close(resume)
	// The credit of the last reads is granted with the next batch, or when the reader waits.
	assert.Eventually(t, func() bool { return connCredit.Load() >= window-creditRefresh }, 10*time.Second, 10*time.Millisecond,
		"the connection credit for what was read never reached the peer")
	assert.Eventually(t, func() bool { return pingAcks.Load() > 0 }, 5*time.Second, 10*time.Millisecond)
}

// A peer that shrinks the header table decodes every CONNECT after the change.
func TestConn_HeaderTableSizeChange(t *testing.T) {
	cli, srv := tcpPair(t)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingHeaderTableSize, Val: 0})
		if err != nil {
			return
		}
		peer.fr.ReadMetaHeaders = hpack.NewDecoder(0, nil)
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s, _, oerr := c.Open(ctx, Request{Authority: "origin.test:443", Header: http.Header{"Capsule-Protocol": {"?1"}}})
		cancel()
		require.NoError(t, oerr)
		require.NoError(t, s.Close())
	}
}

// The peer's concurrent stream limit closes the connection to new streams until one ends.
func TestConn_StreamLimit(t *testing.T) {
	cli, srv := tcpPair(t)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1})
		if err != nil {
			return
		}
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	assert.False(t, c.CanOpen())
	_, _, err = c.Open(ctx, Request{Authority: "origin.test:443"})
	require.ErrorIs(t, err, errTooManyStreams)
	require.NoError(t, s.Close())
	assert.True(t, c.CanOpen())
	again, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	_ = again.Close()
}

// A frame larger than the size the client lets the peer send ends the connection.
func TestConn_OversizeFrameEndsTheConnection(t *testing.T) {
	cli, srv := tcpPair(t)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		if err != nil {
			return
		}
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
				_ = peer.writeData(mh.StreamID, make([]byte, 64<<10))
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the oversize frame was taken")
	}
	_, err = s.Read(make([]byte, 1))
	require.Error(t, err)
	require.NotErrorIs(t, err, io.EOF)
}

// A CONNECT whose headers do not fit a frame fails alone, the connection and its other
// streams go on.
func TestConn_HeadersTooLargeFailAlone(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	s, _ := open(t, c, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := c.Open(ctx, Request{Authority: "origin.test:443", Header: http.Header{"X-Big": {strings.Repeat("x", 2<<20)}}})
	require.ErrorIs(t, err, errHeadersTooLarge)
	require.True(t, c.CanOpen())
	_, err = s.Write([]byte("still here"))
	require.NoError(t, err)
	buf := make([]byte, 16)
	n, err := s.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "still here", string(buf[:n]))
}

// FuzzPeerFrames plays the peer of a connection, its frames built from the fuzz input, one
// frame per record of type, flags, stream ID and payload, and checks that the client neither
// panics nor hangs, whatever the peer sends.
func FuzzPeerFrames(f *testing.F) {
	var seed bytes.Buffer
	fr := http2.NewFramer(&seed, nil)
	_ = fr.WriteWindowUpdate(0, 1<<20)
	_ = fr.WriteData(1, false, []byte("hello"))
	_ = fr.WriteData(1, true, nil)
	_ = fr.WritePing(false, [8]byte{1, 2, 3})
	_ = fr.WriteRSTStream(1, http2.ErrCodeCancel)
	_ = fr.WriteGoAway(1, http2.ErrCodeNo, nil)
	_ = fr.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 1 << 20})
	_ = fr.WriteWindowUpdate(1, 1<<31-1)
	_ = fr.WriteRawFrame(http2.FramePushPromise, 0, 1, []byte{0, 0, 0, 2})
	_ = fr.WriteRawFrame(http2.FrameType(0x42), 0, 0, []byte("unknown"))
	f.Add(seed.Bytes())
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, raw []byte) {
		cli, srv := memPipe()
		t.Cleanup(func() { _ = cli.Close(); _ = srv.Close() })
		answered := make(chan uint32, 1)
		go func() {
			peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
			if err != nil {
				return
			}
			for {
				fr, rerr := peer.fr.ReadFrame()
				if rerr != nil {
					return
				}
				if mh, ok := fr.(*http2.MetaHeadersFrame); ok {
					_ = peer.answer(mh.StreamID)
					select {
					case answered <- mh.StreamID:
					default:
					}
					// The fuzz input follows the answer, frame by frame, however malformed
					// the framer lets a raw frame be.
					in := http2.NewFramer(nil, bytes.NewReader(raw))
					in.AllowIllegalReads = true
					peer.wmu.Lock()
					for {
						f, perr := in.ReadFrame()
						if perr != nil {
							break
						}
						var payload []byte
						if d, ok := f.(*http2.DataFrame); ok {
							payload = d.Data()
						}
						_ = peer.fr.WriteRawFrame(f.Header().Type, f.Header().Flags, f.Header().StreamID, payload)
					}
					_ = peer.fr.WriteRawFrame(http2.FrameData, http2.FlagDataEndStream, mh.StreamID, nil)
					peer.wmu.Unlock()
				}
			}
		}()

		c, err := Client(cli, 0)
		require.NoError(t, err)
		defer func() { _ = c.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s, _, err := c.Open(ctx, Request{Protocol: "connect-udp", Scheme: "https", Authority: "proxy.test", Path: "/.well-known/masque/udp/192.0.2.1/53/"})
		if err != nil {
			return
		}
		_ = s.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = s.Write([]byte("ping"))
		buf := make([]byte, 64<<10)
		for {
			if _, rerr := s.Read(buf); rerr != nil {
				break
			}
		}
		_ = s.Close()
	})
}

// Many streams open, echo and close at once.
func TestConn_ConcurrentStreams(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 8 {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				s, resp, err := c.Open(ctx, Request{Authority: "origin.test:443"})
				cancel()
				if !assert.NoError(t, err) {
					return
				}
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				payload := make([]byte, (i+1)*20<<10)
				_, _ = rand.Read(payload)
				done := make(chan error, 1)
				go func() {
					got := make([]byte, len(payload))
					_, rerr := io.ReadFull(s, got)
					if rerr == nil && !bytes.Equal(payload, got) {
						rerr = errors.New("the echo differs")
					}
					done <- rerr
				}()
				_, err = s.Write(payload)
				assert.NoError(t, err)
				assert.NoError(t, <-done)
				if i%2 == 0 {
					assert.NoError(t, s.Close())
				} else {
					assert.NoError(t, s.CloseWrite())
					_, _ = io.Copy(io.Discard, s)
				}
			}
		}()
	}
	wg.Wait()
	require.True(t, c.CanOpen())
}

// memPipe is a connected pair in memory with a buffer in each direction, so a write never
// waits for a read the way net.Pipe's does. Fuzzing opens one per input, which a TCP pair
// would run the ephemeral ports out with.
func memPipe() (a, b net.Conn) {
	ab, ba := newMemBuf(), newMemBuf()
	return &memConn{r: ba, w: ab}, &memConn{r: ab, w: ba}
}

type memBuf struct {
	mu       sync.Mutex
	cond     *sync.Cond
	buf      []byte
	closed   bool
	deadline time.Time
}

func newMemBuf() *memBuf {
	b := &memBuf{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

type memConn struct {
	r, w *memBuf
}

func (c *memConn) Read(p []byte) (int, error) {
	b := c.r
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.buf) == 0 {
		if b.closed {
			return 0, io.EOF
		}
		if !b.deadline.IsZero() {
			if !time.Now().Before(b.deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			time.AfterFunc(time.Until(b.deadline), b.cond.Broadcast)
		}
		b.cond.Wait()
	}
	n := copy(p, b.buf)
	b.buf = b.buf[n:]
	return n, nil
}

func (c *memConn) Write(p []byte) (int, error) {
	b := c.w
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	b.buf = append(b.buf, p...)
	b.cond.Broadcast()
	return len(p), nil
}

func (c *memConn) Close() error {
	for _, b := range []*memBuf{c.r, c.w} {
		b.mu.Lock()
		b.closed = true
		b.cond.Broadcast()
		b.mu.Unlock()
	}
	return nil
}

func (c *memConn) SetReadDeadline(t time.Time) error {
	c.r.mu.Lock()
	c.r.deadline = t
	c.r.cond.Broadcast()
	c.r.mu.Unlock()
	return nil
}

func (c *memConn) LocalAddr() net.Addr              { return emptyAddr{} }
func (c *memConn) RemoteAddr() net.Addr             { return emptyAddr{} }
func (c *memConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

type emptyAddr struct{}

func (emptyAddr) Network() string { return "mem" }
func (emptyAddr) String() string  { return "mem" }

// Headers that do not fit a frame are refused before anything reaches the encoder, so the
// next CONNECT on the connection still shares its table with the peer.
func TestConn_OversizeHeadersLeaveTheEncoderIntact(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := c.Open(ctx, Request{Authority: "origin.test:443",
		Header: http.Header{"X-Poison": {"pv"}, "X-Big": {strings.Repeat("x", 2<<20)}}})
	require.ErrorIs(t, err, errHeadersTooLarge)
	s, resp, err := c.Open(ctx, Request{Authority: "origin.test:443", Header: http.Header{"X-Poison": {"pv"}}})
	require.NoError(t, err, "the connection did not survive the header block that was never sent")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = s.Close()
}

// DATA past the peer's END_STREAM is a stream error, RFC 9113 section 5.1, and never reaches
// the reader.
func TestStream_DataAfterEndStreamIsAnError(t *testing.T) {
	cli, srv := tcpPair(t)
	reset := make(chan http2.ErrCode, 1)
	go func() {
		peer, err := startFakePeer(srv)
		if err != nil {
			return
		}
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			switch f := f.(type) {
			case *http2.MetaHeadersFrame:
				_ = peer.answer(f.StreamID)
				peer.wmu.Lock()
				_ = peer.fr.WriteData(f.StreamID, true, []byte("a"))
				_ = peer.fr.WriteData(f.StreamID, false, []byte("b"))
				peer.wmu.Unlock()
			case *http2.RSTStreamFrame:
				reset <- f.ErrCode
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	body, err := io.ReadAll(s)
	require.NoError(t, err)
	assert.Equal(t, "a", string(body), "bytes past END_STREAM reached the reader")
	select {
	case code := <-reset:
		assert.Equal(t, http2.ErrCodeStreamClosed, code)
	case <-time.After(5 * time.Second):
		t.Fatal("the peer was not told")
	}
	require.True(t, c.CanOpen())
}

// stuckPeer answers n streams, then stops reading its socket, and returns the streams
// once the client's writer is stuck on it, the first of them filling the socket.
func stuckPeer(t *testing.T, n int) (*Conn, []*Stream) {
	return silentPeer(t, n, true)
}

// silentPeer answers n streams, then stops reading its socket. With fill, the first stream
// fills the socket so the client's writer is stuck before it returns.
func silentPeer(t *testing.T, n int, fill bool) (*Conn, []*Stream) {
	t.Helper()
	cli, srv := tcpPair(t)
	answered := make(chan struct{}, n)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 24})
		if err != nil {
			return
		}
		_ = peer.fr.WriteWindowUpdate(0, 1<<28)
		seen := 0
		for seen < n {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
				answered <- struct{}{}
				seen++
			}
		}
		// Nothing reads the socket from here on.
	}()
	conn, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	streams := make([]*Stream, 0, n)
	for range n {
		s, _, oerr := conn.Open(ctx, Request{Authority: "origin.test:443"})
		require.NoError(t, oerr)
		<-answered
		streams = append(streams, s)
	}
	if fill {
		go func() { _, _ = streams[0].Write(make([]byte, 64<<20)) }()
		time.Sleep(300 * time.Millisecond)
	}
	return conn, streams
}

// An Open behind a writer stuck on a peer that stopped reading returns when its context
// ends, not when the writer does.
func TestConn_OpenHonoursItsContextBehindAStuckWriter(t *testing.T) {
	c, _ := stuckPeer(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), time.Second, "Open outlived its context behind the stuck writer")
}

// A write behind a stuck writer returns at its deadline.
func TestStream_WriteDeadlineBehindAStuckWriter(t *testing.T) {
	_, streams := stuckPeer(t, 2)
	s := streams[1]
	require.NoError(t, s.SetWriteDeadline(time.Now().Add(200*time.Millisecond)))
	start := time.Now()
	_, err := s.Write([]byte("late"))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	assert.Less(t, time.Since(start), time.Second, "Write outlived its deadline behind the stuck writer")
}

// The peer may not send more than the connection window the client advertised, whatever
// the streams' own windows add up to.
func TestConn_ConnectionWindowIsEnforced(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 8)
	ready := make(chan *fakePeer, 1)
	go func() {
		peer, err := startFakePeer(srv)
		if err != nil {
			close(ready)
			return
		}
		ready <- peer
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
				answered <- mh.StreamID
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	peer := <-ready
	require.NotNil(t, peer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range connWindow/window + 1 {
		_, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
		if err != nil {
			// The connection ended on the first stream past the window.
			break
		}
		id := <-answered
		for sent := 0; sent < window; sent += 16384 {
			if werr := peer.writeData(id, make([]byte, 16384)); werr != nil {
				break
			}
		}
	}
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the client took more stream windows than the connection window holds")
	}
	var ce http2.ConnectionError
	require.ErrorAs(t, c.Err(), &ce)
	assert.Equal(t, http2.ErrCodeFlowControl, http2.ErrCode(ce))
}

// A peer that stops answering is found out by the keepalive PING, and one that answers
// keeps the connection.
func TestConn_KeepAlive(t *testing.T) {
	for _, answers := range []bool{false, true} {
		t.Run(map[bool]string{false: "silent", true: "answering"}[answers], func(t *testing.T) {
			cli, srv := tcpPair(t)
			var pings atomic.Int32
			go func() {
				peer, err := startFakePeer(srv)
				if err != nil {
					return
				}
				for {
					f, rerr := peer.fr.ReadFrame()
					if rerr != nil {
						return
					}
					if p, ok := f.(*http2.PingFrame); ok && !p.IsAck() {
						pings.Add(1)
						if answers {
							peer.wmu.Lock()
							_ = peer.fr.WritePing(true, p.Data)
							peer.wmu.Unlock()
						}
					}
				}
			}()
			c, err := Client(cli, 100*time.Millisecond)
			require.NoError(t, err)
			defer func() { _ = c.Close() }()
			select {
			case <-c.settingsSeen:
			case <-time.After(5 * time.Second):
				t.Fatal("no SETTINGS")
			}
			if !answers {
				select {
				case <-c.Done():
					require.ErrorIs(t, c.Err(), errKeepAlive)
				case <-time.After(5 * time.Second):
					t.Fatal("the silent peer was not found out")
				}
				assert.EqualValues(t, 1, pings.Load(), "one PING, then the connection ends")
				return
			}
			time.Sleep(600 * time.Millisecond)
			require.NoError(t, c.Err(), "an answering peer keeps the connection")
			assert.GreaterOrEqual(t, pings.Load(), int32(3))
		})
	}
}

// A stream error the peer's HEADERS provoke ends that stream alone, the other streams on the
// connection go on.
func TestConn_StreamErrorFromHeadersEndsTheStreamAlone(t *testing.T) {
	cli, srv := tcpPair(t)
	go func() {
		peer, err := startFakePeer(srv)
		if err != nil {
			return
		}
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				if mh.StreamID == 1 {
					_ = peer.answer(mh.StreamID)
					continue
				}
				// No :status at all, which the framer lets through.
				peer.wmu.Lock()
				peer.encBuf.Reset()
				_ = peer.enc.WriteField(hpack.HeaderField{Name: "x-foo", Value: "bar"})
				_ = peer.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: mh.StreamID, BlockFragment: peer.encBuf.Bytes(), EndHeaders: true})
				peer.wmu.Unlock()
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	_, _, err = c.Open(ctx, Request{Authority: "origin.test:443"})
	var se http2.StreamError
	require.ErrorAs(t, err, &se, "the answer without a status is a stream error")
	require.NoError(t, c.Err(), "the connection ended on one stream's HEADERS")
	_, err = first.Write([]byte("still here"))
	require.NoError(t, err)
}

// A write past its deadline sends nothing and keeps the windows it never used.
func TestStream_PastDeadlineWriteKeepsTheWindow(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	s, _ := open(t, c, nil)
	var conn, stream int64
	c.onLoop(func() { conn, stream = c.sendWindow, s.sendWindow })
	require.NoError(t, s.SetWriteDeadline(time.Now().Add(-time.Second)))
	for range 100 {
		_, err := s.Write(make([]byte, 1000))
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	}
	require.NoError(t, s.SetWriteDeadline(time.Time{}))
	_, err := s.Write([]byte("drain"))
	require.NoError(t, err)
	var connNow, streamNow int64
	c.onLoop(func() { connNow, streamNow = c.sendWindow, s.sendWindow })
	assert.Equal(t, conn-5, connNow, "the connection send window lost what the skipped frames took")
	assert.Equal(t, stream-5, streamNow, "the stream send window lost what the skipped frames took")
}

// A write the deadline cuts while its frame is on the wire ends the stream, a byte stream
// that lost track of what left cannot go on.
func TestStream_WriteDeadlineRaceEndsTheStream(t *testing.T) {
	_, streams := silentPeer(t, 1, false)
	s := streams[0]
	require.NoError(t, s.SetWriteDeadline(time.Now().Add(300*time.Millisecond)))
	_, err := s.Write(make([]byte, 8<<20))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.NoError(t, s.SetWriteDeadline(time.Time{}))
	_, err = s.Write([]byte("more"))
	require.Error(t, err)
	require.NotErrorIs(t, err, os.ErrDeadlineExceeded, "the stream went on after a frame it lost track of")
}

// A peer whose frames keep arriving is alive, whether or not it answers the PING.
func TestConn_KeepAliveCountsTraffic(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 1)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		if err != nil {
			return
		}
		go func() {
			for {
				f, rerr := peer.fr.ReadFrame()
				if rerr != nil {
					return
				}
				if mh, ok := f.(*http2.MetaHeadersFrame); ok {
					_ = peer.answer(mh.StreamID)
					answered <- mh.StreamID
				}
			}
		}()
		id := <-answered
		// Long enough for a PING to go out, short enough for the traffic to resume before
		// the ack is due.
		time.Sleep(400 * time.Millisecond)
		for {
			if werr := peer.writeData(id, []byte("tick")); werr != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	// The period leaves the reader room under a loaded machine.
	c, err := Client(cli, 300*time.Millisecond)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	go func() { _, _ = io.Copy(io.Discard, s) }()
	time.Sleep(2 * time.Second)
	require.NoError(t, c.Err(), "the connection ended under live traffic")
}

// Once the stream IDs run out the connection is retired, its streams go on and the next
// one is refused the way a GOAWAY refuses it.
func TestConn_StreamIDExhaustionRetiresTheConnection(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	c.onLoop(func() { c.nextID = 1<<31 - 1 })
	last, _ := open(t, c, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.ErrorIs(t, err, ErrGoAway)
	require.False(t, c.CanOpen())
	require.NoError(t, c.Err(), "the connection ended on the exhausted IDs")
	_, err = last.Write([]byte("still here"))
	require.NoError(t, err)
}

// onLoop runs fn on the serve goroutine and returns once it ran, or at once when the
// connection ended.
func (c *Conn) onLoop(fn func()) {
	done := make(chan struct{})
	if c.send(msg{kind: msgFunc, fn: func() { fn(); close(done) }}) {
		<-done
	}
}

// writeHeaders writes any header block, what answer cannot.
func (p *fakePeer) writeHeaders(id uint32, end bool, fields ...hpack.HeaderField) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	p.encBuf.Reset()
	for _, f := range fields {
		_ = p.enc.WriteField(f)
	}
	return p.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      id,
		BlockFragment: p.encBuf.Bytes(),
		EndHeaders:    true,
		EndStream:     end,
	})
}

// peerOn starts a fake peer on srv that runs onHeaders for every HEADERS it reads.
func peerOn(srv net.Conn, onHeaders func(p *fakePeer, id uint32), settings ...http2.Setting) {
	go func() {
		p, err := startFakePeer(srv, settings...)
		if err != nil {
			return
		}
		for {
			f, rerr := p.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok && onHeaders != nil {
				onHeaders(p, mh.StreamID)
			}
		}
	}()
}

// openAsync runs Open on a goroutine and hands back the error it ends with.
func openAsync(c *Conn, req Request) <-chan error {
	ch := make(chan error, 1)
	go func() {
		_, _, err := c.Open(context.Background(), req)
		ch <- err
	}()
	return ch
}

// DATA before the answer is a stream error, RFC 9113 section 8.1, and its END_STREAM never
// leaves Open waiting for an answer that cannot come.
func TestConn_DataBeforeTheAnswerIsAStreamError(t *testing.T) {
	cli, srv := tcpPair(t)
	peerOn(srv, func(p *fakePeer, id uint32) {
		p.wmu.Lock()
		defer p.wmu.Unlock()
		_ = p.fr.WriteData(id, true, []byte("early"))
	}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})

	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	select {
	case err := <-openAsync(c, Request{Authority: "origin.test:443"}):
		require.Error(t, err, "DATA before HEADERS must not read as an answer")
	case <-time.After(2 * time.Second):
		t.Fatal("Open never returned: DATA before HEADERS half-closed a stream nothing ever answers")
	}
}

// A 1xx with END_STREAM is a stream error, the answer cannot come after it.
func TestConn_InformationalWithEndStreamIsAStreamError(t *testing.T) {
	cli, srv := tcpPair(t)
	peerOn(srv, func(p *fakePeer, id uint32) {
		_ = p.writeHeaders(id, true, hpack.HeaderField{Name: ":status", Value: "103"})
	}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})

	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	select {
	case err := <-openAsync(c, Request{Authority: "origin.test:443"}):
		require.Error(t, err, "a 1xx with END_STREAM must not read as an answer")
	case <-time.After(2 * time.Second):
		t.Fatal("Open never returned: a 1xx with END_STREAM left the stream open with nothing to answer it")
	}
}

// DATA on a stream the client ended is refunded in one WINDOW_UPDATE due, however many
// frames a peer that stopped reading sends, so nothing grows behind the stuck socket.
func TestConn_CreditOnAnEndedStreamQueuesNoControlFrame(t *testing.T) {
	const flood = 4000
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 4)
	release := make(chan struct{})
	go func() {
		p, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 24})
		if err != nil {
			return
		}
		_ = p.fr.WriteWindowUpdate(0, 1<<28)
		seen := 0
		for seen < 2 {
			f, rerr := p.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = p.answer(mh.StreamID)
				answered <- mh.StreamID
				seen++
			}
		}
		// Nothing reads the socket from here on, so the client's writer sticks.
		<-release
		one := []byte{0}
		for range flood {
			p.wmu.Lock()
			werr := p.fr.WriteData(3, false, one)
			p.wmu.Unlock()
			if werr != nil {
				return
			}
		}
	}()

	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var streams []*Stream
	for range 2 {
		s, _, oerr := c.Open(ctx, Request{Authority: "origin.test:443"})
		require.NoError(t, oerr)
		<-answered
		streams = append(streams, s)
	}
	// Fill the socket so the writer is stuck and nothing drains the control queue.
	go func() { _, _ = streams[0].Write(make([]byte, 64<<20)) }()
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, streams[1].Close())
	close(release)
	time.Sleep(time.Second)

	var queued int
	c.onLoop(func() { queued = len(c.control) })
	assert.LessOrEqual(t, queued, maxControlFrames,
		"the peer queued %d control frames behind a socket that takes none, past the bound of %d", queued, maxControlFrames)
}

// A read deadline wakes every pending Read, as net.Conn says of a blocked call.
func TestStream_ReadDeadlineWakesEveryPendingRead(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	s, _ := open(t, c, nil)
	t.Cleanup(func() { _ = s.Close() })

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.Read(make([]byte, 1))
		}()
	}
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, s.SetReadDeadline(time.Now().Add(-time.Second)))

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a pending Read outlived a deadline already past: readReady wakes one reader, not every one")
	}
}

// rawPeer answers every HEADERS with 200 without validating what it decodes.
func rawPeer(srv net.Conn, seen chan<- []hpack.HeaderField) {
	go func() {
		fr := http2.NewFramer(srv, srv)
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(srv, preface); err != nil {
			return
		}
		if err := fr.WriteSettings(); err != nil {
			return
		}
		dec := hpack.NewDecoder(hpackTableSize, nil)
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			hf, ok := f.(*http2.HeadersFrame)
			if !ok {
				continue
			}
			fields, derr := dec.DecodeFull(hf.HeaderBlockFragment())
			if derr == nil {
				select {
				case seen <- fields:
				default:
				}
			}
			buf.Reset()
			_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			_ = fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: hf.StreamID, BlockFragment: buf.Bytes(), EndHeaders: true,
			})
		}
	}()
}

// A field value holding CR or LF is refused before anything reaches the wire, RFC 9113
// section 8.2.1.
func TestConn_OpenRefusesAnInvalidHeaderField(t *testing.T) {
	cli, srv := tcpPair(t)
	seen := make(chan []hpack.HeaderField, 1)
	rawPeer(srv, seen)

	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, err = c.Open(ctx, Request{
		Authority: "origin.test:443",
		Header:    http.Header{"X-Bad": {"one\r\nx-smuggled: two"}},
	})
	select {
	case fields := <-seen:
		t.Logf("the peer decoded %v", fields)
	default:
	}
	require.Error(t, err, "a field value holding CR or LF must be refused, RFC 9113 section 8.2.1")
}

// SETTINGS_ENABLE_CONNECT_PROTOCOL takes 0 or 1, RFC 8441 section 3.
func TestConn_EnableConnectProtocolOutOfRangeEndsTheConnection(t *testing.T) {
	cli, srv := tcpPair(t)
	peerOn(srv, nil, http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 2})

	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("SETTINGS_ENABLE_CONNECT_PROTOCOL of 2 was accepted, RFC 8441 section 3 makes it a connection error")
	}
}

// stuckConn is a socket whose writes stick until the write deadline in force passes, so a
// shutdown is bounded only by the deadline it sets.
type stuckConn struct {
	reads    *memBuf
	closedAt chan time.Time
	mu       sync.Mutex
	deadline time.Time
	stick    bool
	inWrite  bool
}

func newStuckConn() *stuckConn {
	return &stuckConn{reads: newMemBuf(), closedAt: make(chan time.Time, 4)}
}

// feed hands bytes to the client's reader.
func (g *stuckConn) feed(b []byte) {
	g.reads.mu.Lock()
	g.reads.buf = append(g.reads.buf, b...)
	g.reads.cond.Broadcast()
	g.reads.mu.Unlock()
}

func (g *stuckConn) Read(p []byte) (int, error) { return (&memConn{r: g.reads, w: g.reads}).Read(p) }

func (g *stuckConn) Write(p []byte) (int, error) {
	g.mu.Lock()
	stick := g.stick
	g.inWrite = stick
	g.mu.Unlock()
	if !stick {
		return len(p), nil
	}
	for {
		g.mu.Lock()
		dl := g.deadline
		g.mu.Unlock()
		g.reads.mu.Lock()
		closed := g.reads.closed
		g.reads.mu.Unlock()
		if closed || (!dl.IsZero() && !time.Now().Before(dl)) {
			return 0, net.ErrClosed
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (g *stuckConn) SetWriteDeadline(t time.Time) error {
	g.mu.Lock()
	g.deadline = t
	g.mu.Unlock()
	return nil
}

func (g *stuckConn) writing() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.inWrite
}

func (g *stuckConn) setStick() {
	g.mu.Lock()
	g.stick = true
	g.mu.Unlock()
}

func (g *stuckConn) Close() error {
	select {
	case g.closedAt <- time.Now():
	default:
	}
	g.reads.mu.Lock()
	g.reads.closed = true
	g.reads.cond.Broadcast()
	g.reads.mu.Unlock()
	return nil
}

func (g *stuckConn) LocalAddr() net.Addr             { return emptyAddr{} }
func (g *stuckConn) RemoteAddr() net.Addr            { return emptyAddr{} }
func (g *stuckConn) SetDeadline(time.Time) error     { return nil }
func (g *stuckConn) SetReadDeadline(time.Time) error { return nil }

// peerWriter feeds frames to the client's read side.
type peerWriter struct{ g *stuckConn }

func (w *peerWriter) Write(p []byte) (int, error) { w.g.feed(p); return len(p), nil }

// The socket is closed within closeTimeout of Close, a write stuck on it cut by the
// deadline Close sets, which nothing raises back.
func TestConn_CloseClosesTheSocketWithinTheBound(t *testing.T) {
	g := newStuckConn()
	c, err := Client(g, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = g.Close() })

	fr := http2.NewFramer(&peerWriter{g: g}, nil)
	require.NoError(t, fr.WriteSettings())
	select {
	case <-c.settingsSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("the client never saw the peer's SETTINGS")
	}
	time.Sleep(100 * time.Millisecond)

	g.setStick()
	// A PING the client owes an ack for, so pump hands a buffer off and the writer sticks.
	require.NoError(t, fr.WritePing(false, [8]byte{1}))
	deadline := time.Now().Add(2 * time.Second)
	for !g.writing() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.True(t, g.writing(), "the write goroutine never got stuck on the socket")

	start := time.Now()
	require.NoError(t, c.Close())
	select {
	case at := <-g.closedAt:
		assert.Less(t, at.Sub(start), 3*time.Second, "the socket was closed %s after Close", at.Sub(start))
	case <-time.After(3 * time.Second):
		t.Fatalf("the socket was still open %s after Close, past closeTimeout of %s", time.Since(start), closeTimeout)
	}
}

// DATA on an idle stream, here an even ID no push ever opened, ends the connection, RFC
// 9113 section 5.1.
func TestConn_DataOnAnIdleStreamEndsTheConnection(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan struct{}, 2)
	peerOn(srv, func(p *fakePeer, id uint32) {
		_ = p.answer(id)
		answered <- struct{}{}
		p.wmu.Lock()
		defer p.wmu.Unlock()
		_ = p.fr.WriteData(2, false, []byte("push"))
	}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})

	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, err = c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	<-answered
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("DATA on the idle even stream 2 was accepted")
	}
}

// RST_STREAM on a stream never opened ends the connection, RFC 9113 section 6.4.
func TestConn_ResetOfAnIdleStreamEndsTheConnection(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan struct{}, 2)
	peerOn(srv, func(p *fakePeer, id uint32) {
		_ = p.answer(id)
		answered <- struct{}{}
		p.wmu.Lock()
		defer p.wmu.Unlock()
		_ = p.fr.WriteRSTStream(101, http2.ErrCodeCancel)
	}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})

	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, err = c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	<-answered
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("RST_STREAM on the idle stream 101 was accepted")
	}
}

// Trailers with a pseudo-header field are a stream error, never a clean end, RFC 9113
// section 8.1.
func TestStream_TrailersWithAPseudoHeaderAreAStreamError(t *testing.T) {
	cli, srv := tcpPair(t)
	peerOn(srv, func(p *fakePeer, id uint32) {
		_ = p.answer(id)
		_ = p.writeHeaders(id, true, hpack.HeaderField{Name: ":method", Value: "GET"})
	}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})

	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	_, rerr := s.Read(make([]byte, 1))
	var se http2.StreamError
	require.ErrorAs(t, rerr, &se, "trailers with a pseudo-header field must not read as a clean end")
	assert.Equal(t, http2.ErrCodeProtocol, se.Code)
}

// The peer's END_STREAM wakes every pending Read with EOF.
func TestStream_EndStreamWakesEveryPendingRead(t *testing.T) {
	cli, srv := tcpPair(t)
	ends := make(chan uint32, 2)
	peerOn(srv, func(p *fakePeer, id uint32) {
		_ = p.answer(id)
		ends <- id
	}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})

	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	<-ends

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.Read(make([]byte, 1))
		}()
	}
	time.Sleep(300 * time.Millisecond)
	c.onLoop(func() {
		if st := c.streams[1]; st != nil {
			c.endRemote(st)
		}
	})

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a pending Read outlived the peer's END_STREAM: endReads signals one reader, not every one")
	}
}

// Read with an empty buffer returns at once, as every net.Conn of the standard library does.
func TestStream_ReadWithAnEmptyBufferReturnsAtOnce(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	s, _ := open(t, c, nil)
	t.Cleanup(func() { _ = s.Close() })

	done := make(chan struct{})
	go func() {
		_, _ = s.Read(nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Read with a zero-length buffer never returned")
	}
}

// A write cut by Close reports what left, as one cut by its deadline does.
func TestStream_WriteCutByCloseReportsWhatLeft(t *testing.T) {
	_, streams := silentPeer(t, 1, false)
	s := streams[0]
	wrote := make(chan writeResult, 1)
	go func() {
		n, err := s.Write(make([]byte, 8<<20))
		wrote <- writeResult{n: n, err: err}
	}()
	time.Sleep(500 * time.Millisecond)
	require.NoError(t, s.Close())
	select {
	case r := <-wrote:
		require.Error(t, r.err)
		assert.Greater(t, r.n, 0, "Write reported 0 bytes though its frames left the socket")
	case <-time.After(3 * time.Second):
		t.Fatal("the write outlived the close")
	}
}

// Everything of the net.Conn API on one stream at once, under the race detector.
func TestStream_ConcurrentAPI(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	s, _ := open(t, c, nil)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	run := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				fn()
			}
		}()
	}
	run(func() { _, _ = s.Read(make([]byte, 4<<10)) })
	run(func() { _, _ = s.Read(make([]byte, 1)) })
	run(func() { _, _ = s.Write([]byte("payload")) })
	run(func() { _, _ = s.Write(make([]byte, 40<<10)) })
	run(func() { _ = s.SetReadDeadline(time.Now().Add(20 * time.Millisecond)) })
	run(func() { _ = s.SetReadDeadline(time.Time{}) })
	run(func() { _ = s.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)) })
	run(func() { _ = s.SetWriteDeadline(time.Time{}) })
	run(func() { _ = s.LocalAddr(); _ = s.RemoteAddr() })

	time.Sleep(700 * time.Millisecond)
	go func() { _ = s.CloseWrite() }()
	go func() { _ = s.Close() }()
	time.Sleep(300 * time.Millisecond)
	close(stop)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a caller was left blocked after the stream was closed")
	}
}

// Many streams opened, used and closed while the connection is closed under them.
func TestConn_StreamsAcrossAClose(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
				cancel()
				if err != nil {
					continue
				}
				go func() { _, _ = s.Write(make([]byte, 8<<10)) }()
				go func() { _, _ = io.Copy(io.Discard, s) }()
				_ = s.SetDeadline(time.Now().Add(50 * time.Millisecond))
				_ = s.Close()
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, c.Close())

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("a caller was left blocked after the connection was closed")
	}
}

// Open cancelled at every moment of its life leaves nothing behind.
func TestConn_OpenCancelledAtEveryMoment(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	for i := range 300 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(i)*20*time.Microsecond)
		s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
		cancel()
		if err == nil {
			_ = s.Close()
		}
	}
	// The connection is still usable and its streams are all accounted for.
	require.NoError(t, c.Err())
	var live int
	c.onLoop(func() { live = len(c.streams) })
	assert.Equal(t, 0, live, "cancelled Opens left streams behind")
	s, resp := open(t, c, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = s.Close()
}

// A second GOAWAY lowering the last stream ID ends the streams above it.
func TestConn_SecondGoAwayLowersTheLastStreamID(t *testing.T) {
	cli, srv := tcpPair(t)
	goAway := make(chan uint32, 2)
	go func() {
		peer, err := startFakePeer(srv)
		if err != nil {
			return
		}
		go func() {
			for last := range goAway {
				peer.wmu.Lock()
				_ = peer.fr.WriteGoAway(last, http2.ErrCodeNo, nil)
				peer.wmu.Unlock()
			}
		}()
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	second, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)

	goAway <- second.id
	require.Eventually(t, func() bool { return !c.CanOpen() }, 5*time.Second, 10*time.Millisecond)
	goAway <- first.id
	_ = second.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, rerr := second.Read(make([]byte, 1))
	require.Error(t, rerr)
	require.NotErrorIs(t, rerr, os.ErrDeadlineExceeded, "the second GOAWAY did not end the stream above its last ID")
	close(goAway)
}

// The resets of a caller's own stream churn never reach the bound for the frames a peer
// provokes, a RST being owed only once the HEADERS is encoded and nothing being encoded
// past outBound.
func TestConn_LocalResetsAreNoPeerFlood(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 1)
	ping := make(chan struct{})
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 24})
		if err != nil {
			return
		}
		_ = peer.fr.WriteWindowUpdate(0, 1<<28)
		go func() {
			<-ping
			peer.wmu.Lock()
			_ = peer.fr.WritePing(false, [8]byte{7})
			peer.wmu.Unlock()
		}()
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
				select {
				case answered <- mh.StreamID:
				default:
				}
				// Nothing reads the socket from here on.
				return
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	cancel()
	require.NoError(t, err)
	<-answered

	// The socket takes nothing from here on, so the writer sticks.
	go func() { _, _ = s.Write(make([]byte, 64<<20)) }()
	time.Sleep(300 * time.Millisecond)

	// A caller's own churn: every Open whose context ends queues a RST_STREAM.
	for range maxControlFrames + 200 {
		octx, ocancel := context.WithTimeout(context.Background(), time.Microsecond)
		_, _, _ = c.Open(octx, Request{Authority: "origin.test:443"})
		ocancel()
		if c.Err() != nil {
			break
		}
	}
	var queued int
	c.onLoop(func() { queued = c.queuedControl })
	t.Logf("queuedControl after the churn: %d (bound %d)", queued, maxControlFrames)

	close(ping)
	select {
	case <-c.Done():
		require.NotErrorIs(t, c.Err(), errControlFlood,
			"the caller's own resets counted as a peer flood and ended the connection")
	case <-time.After(2 * time.Second):
	}
}

// A connection-specific header field is refused before anything reaches the wire, RFC 9113
// section 8.2.2.
func TestConn_OpenRefusesAConnectionSpecificHeader(t *testing.T) {
	cli, srv := tcpPair(t)
	seen := make(chan []hpack.HeaderField, 1)
	rawPeer(srv, seen)
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, _, err := c.Open(ctx, Request{
		Authority: "origin.test:443",
		Header:    http.Header{"Connection": {"keep-alive"}, "Transfer-Encoding": {"chunked"}},
	})
	if err == nil {
		_ = s.Close()
	}
	select {
	case fields := <-seen:
		for _, f := range fields {
			require.NotContains(t, []string{"connection", "transfer-encoding"}, f.Name,
				"a connection-specific header field reached the wire: %v", fields)
		}
	case <-time.After(2 * time.Second):
	}
}

// A CONNECT without an authority is refused, RFC 9113 section 8.5.
func TestConn_OpenRefusesAnEmptyAuthority(t *testing.T) {
	cli, srv := tcpPair(t)
	seen := make(chan []hpack.HeaderField, 1)
	rawPeer(srv, seen)
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, _, err := c.Open(ctx, Request{Authority: ""})
	if err == nil {
		_ = s.Close()
	}
	select {
	case fields := <-seen:
		for _, f := range fields {
			if f.Name == ":authority" {
				require.NotEmpty(t, f.Value, "a CONNECT with an empty :authority reached the wire: %v", fields)
			}
		}
	case <-time.After(2 * time.Second):
	}
	require.Error(t, err, "a CONNECT with no authority must be refused")
}

// A Read past its deadline fails with bytes buffered, as a net.Conn of the standard library
// does.
func TestStream_ReadPastTheDeadlineFailsWithBytesBuffered(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 1)
	ready := make(chan *fakePeer, 1)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		if err != nil {
			close(ready)
			return
		}
		ready <- peer
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
				answered <- mh.StreamID
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	peer := <-ready
	id := <-answered
	require.NoError(t, peer.writeData(id, []byte("buffered")))
	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.chunks) > 0
	}, 3*time.Second, 5*time.Millisecond)

	require.NoError(t, s.SetReadDeadline(time.Now().Add(-time.Second)))
	_, rerr := s.Read(make([]byte, 16))
	require.ErrorIs(t, rerr, os.ErrDeadlineExceeded, "a Read past its deadline returned data")
}

// A peer lowering SETTINGS_MAX_FRAME_SIZE under a queued CONNECT leaves the connection up.
func TestConn_MaxFrameSizeShrinkUnderAQueuedConnect(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 1)
	ready := make(chan *fakePeer, 1)
	go func() {
		peer, err := startFakePeer(srv,
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 24},
			http2.Setting{ID: http2.SettingMaxFrameSize, Val: 1 << 20})
		if err != nil {
			close(ready)
			return
		}
		_ = peer.fr.WriteWindowUpdate(0, 1<<28)
		ready <- peer
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
				select {
				case answered <- mh.StreamID:
				default:
				}
				return
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	peer := <-ready
	require.NotNil(t, peer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	cancel()
	require.NoError(t, err)
	<-answered

	// The socket takes nothing more, so the next CONNECT stays queued.
	go func() { _, _ = s.Write(make([]byte, 64<<20)) }()
	time.Sleep(300 * time.Millisecond)
	big := make(chan error, 1)
	go func() {
		_, _, oerr := c.Open(context.Background(),
			Request{Authority: "origin.test:443", Header: http.Header{"X-Big": {strings.Repeat("x", 100<<10)}}})
		big <- oerr
	}()
	time.Sleep(300 * time.Millisecond)
	peer.wmu.Lock()
	_ = peer.fr.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384})
	peer.wmu.Unlock()

	select {
	case <-c.Done():
		t.Fatalf("the connection ended on one queued CONNECT: %v", c.Err())
	case <-big:
	case <-time.After(3 * time.Second):
	}
}

// A stream error that ends a stream takes no credit of the DATA it never delivered, so the
// connection window survives a flood on a stream the peer ended.
func TestConn_ConnectionWindowSurvivesResetStreams(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 8)
	ready := make(chan *fakePeer, 1)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		if err != nil {
			close(ready)
			return
		}
		ready <- peer
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			switch f := f.(type) {
			case *http2.MetaHeadersFrame:
				_ = peer.answer(f.StreamID)
				answered <- f.StreamID
			case *http2.WindowUpdateFrame:
				if f.StreamID == 0 {
					peer.mu.Lock()
					peer.connWindow += int64(f.Increment)
					peer.mu.Unlock()
				}
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	peer := <-ready
	require.NotNil(t, peer)
	require.Eventually(t, func() bool { return peer.window() == connWindow }, 5*time.Second, 5*time.Millisecond)

	for range 6 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s, _, oerr := c.Open(ctx, Request{Authority: "origin.test:443"})
		cancel()
		require.NoError(t, oerr)
		id := <-answered
		// END_STREAM, then DATA past it: a stream error whose bytes still took the window.
		peer.wmu.Lock()
		_ = peer.fr.WriteData(id, true, nil)
		peer.wmu.Unlock()
		for sent := 0; sent < 128<<10; sent += 16384 {
			if werr := peer.writeData(id, make([]byte, 16384)); werr != nil {
				break
			}
		}
		_ = s.Close()
		require.NoError(t, c.Err())
	}
	assert.Eventually(t, func() bool { return peer.window() == connWindow }, 5*time.Second, 10*time.Millisecond,
		"the connection window was not returned for the DATA the reset streams refused, left at %d", peer.window())
}

// Nothing a peer sends makes serve stop taking messages, whatever the order of a close, a
// reset and a write.
func TestConn_ResetRacingAWriteBlocksNoCaller(t *testing.T) {
	cli, srv := tcpPair(t)
	var resets atomic.Int64
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		if err != nil {
			return
		}
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
				id := mh.StreamID
				go func() {
					time.Sleep(time.Duration(id%7) * time.Millisecond)
					peer.wmu.Lock()
					_ = peer.fr.WriteRSTStream(id, http2.ErrCodeCancel)
					peer.wmu.Unlock()
					resets.Add(1)
				}()
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 25 {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				s, _, oerr := c.Open(ctx, Request{Authority: "origin.test:443"})
				cancel()
				if oerr != nil {
					return
				}
				var inner sync.WaitGroup
				inner.Add(3)
				go func() { defer inner.Done(); _, _ = s.Write(make([]byte, 4<<10)) }()
				go func() { defer inner.Done(); _, _ = s.Read(make([]byte, 1<<10)) }()
				go func() { defer inner.Done(); _ = s.CloseWrite() }()
				inner.Wait()
				_ = s.Close()
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatalf("a caller was left blocked, %d resets seen, conn err %v", resets.Load(), c.Err())
	}
}

// A stream the peer never answers and a connection Close on top of it leave no goroutine
// behind and no caller blocked.
func TestConn_UnansweredOpenAndClose(t *testing.T) {
	cli, srv := tcpPair(t)
	peerOn(srv, nil)
	c, err := Client(cli, 0)
	require.NoError(t, err)
	errs := make(chan error, 4)
	for range 4 {
		go func() {
			_, _, oerr := c.Open(context.Background(), Request{Authority: "origin.test:443"})
			errs <- oerr
		}()
	}
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, c.Close())
	for range 4 {
		select {
		case oerr := <-errs:
			require.Error(t, oerr)
		case <-time.After(3 * time.Second):
			t.Fatal("an Open outlived the connection Close")
		}
	}
	_ = net.ErrClosed
	_ = errors.Is
}

// A stream nothing reads fills its own window and no more, the other streams on the
// connection still receive.
func TestConn_AStalledStreamStarvesNoOther(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 8)
	ready := make(chan *fakePeer, 1)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 24})
		if err != nil {
			close(ready)
			return
		}
		ready <- peer
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			switch f := f.(type) {
			case *http2.MetaHeadersFrame:
				_ = peer.answer(f.StreamID)
				answered <- f.StreamID
			case *http2.WindowUpdateFrame:
				if f.StreamID == 0 {
					peer.mu.Lock()
					peer.connWindow += int64(f.Increment)
					peer.mu.Unlock()
				}
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	peer := <-ready
	require.NotNil(t, peer)
	require.Eventually(t, func() bool { return peer.window() == connWindow }, 5*time.Second, 5*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stalled, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	stalledID := <-answered
	other, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	otherID := <-answered

	// Nothing ever reads the stalled stream, which fills its own window and no more.
	for sent := int64(0); sent < window; sent += 16384 {
		require.NoError(t, peer.writeData(stalledID, make([]byte, 16384)))
	}
	require.NoError(t, peer.writeData(otherID, []byte("still served")))
	require.NoError(t, other.SetReadDeadline(time.Now().Add(3*time.Second)))
	buf := make([]byte, 64)
	n, rerr := other.Read(buf)
	require.NoError(t, rerr, "one stalled stream must not hold the whole connection window")
	assert.Equal(t, "still served", string(buf[:n]))
	_ = stalled
}

// A :status that is not three digits is a stream error, RFC 9113 section 8.3.2.
func TestConn_StatusNotThreeDigitsIsAStreamError(t *testing.T) {
	cli, srv := tcpPair(t)
	peerOn(srv, func(p *fakePeer, id uint32) {
		_ = p.writeHeaders(id, false, hpack.HeaderField{Name: ":status", Value: "+200"})
	}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, resp, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	if err == nil {
		_ = s.Close()
		t.Fatalf(`a :status of "+200" was taken as the answer %d`, resp.StatusCode)
	}
}

// A write deadline set while the write is already blocked ends it.
func TestStream_WriteDeadlineSetWhileBlocked(t *testing.T) {
	_, streams := stuckPeer(t, 2)
	s := streams[1]
	wrote := make(chan error, 1)
	go func() {
		_, werr := s.Write(make([]byte, 8<<20))
		wrote <- werr
	}()
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, s.SetWriteDeadline(time.Now().Add(200*time.Millisecond)))
	select {
	case werr := <-wrote:
		require.ErrorIs(t, werr, os.ErrDeadlineExceeded)
	case <-time.After(3 * time.Second):
		t.Fatal("a deadline set while the write was blocked did not end it")
	}
}

// A read deadline set to a future time while the read is blocked ends it at that time.
func TestStream_ReadDeadlineSetWhileBlocked(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	s, _ := open(t, c, nil)
	t.Cleanup(func() { _ = s.Close() })
	read := make(chan error, 1)
	go func() {
		_, rerr := s.Read(make([]byte, 16))
		read <- rerr
	}()
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, s.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	select {
	case rerr := <-read:
		require.ErrorIs(t, rerr, os.ErrDeadlineExceeded)
	case <-time.After(3 * time.Second):
		t.Fatal("a deadline set while the read was blocked did not end it")
	}
}

// SETTINGS_INITIAL_WINDOW_SIZE driving a send window negative stalls the writes, RFC 9113
// section 6.9.2.
func TestConn_NegativeSendWindowAfterSettings(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 1)
	ready := make(chan *fakePeer, 1)
	var dataAfter atomic.Int64
	shrunk := make(chan struct{})
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: defaultWindow})
		if err != nil {
			close(ready)
			return
		}
		_ = peer.fr.WriteWindowUpdate(0, 1<<28)
		ready <- peer
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			switch f := f.(type) {
			case *http2.MetaHeadersFrame:
				_ = peer.answer(f.StreamID)
				answered <- f.StreamID
			case *http2.DataFrame:
				select {
				case <-shrunk:
					dataAfter.Add(int64(f.Length))
				default:
				}
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	peer := <-ready
	require.NotNil(t, peer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	cancel()
	require.NoError(t, err)
	id := <-answered

	done := make(chan error, 1)
	go func() { _, werr := s.Write(make([]byte, 200<<10)); done <- werr }()
	// Let the first 65535 bytes leave, then take the window away under the write.
	time.Sleep(300 * time.Millisecond)
	peer.wmu.Lock()
	_ = peer.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0})
	peer.wmu.Unlock()
	time.Sleep(300 * time.Millisecond)
	close(shrunk)
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, c.Err(), "the connection did not survive a negative send window")
	assert.Zero(t, dataAfter.Load(), "DATA left on a negative send window")

	// The credit the peer gives back lets the write finish.
	peer.wmu.Lock()
	_ = peer.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	_ = peer.fr.WriteWindowUpdate(id, 1<<20)
	peer.wmu.Unlock()
	select {
	case werr := <-done:
		require.NoError(t, werr)
	case <-time.After(5 * time.Second):
		t.Fatal("the write never resumed once the window came back")
	}
}

// A SETTINGS_INITIAL_WINDOW_SIZE that pushes a send window past 2^31-1 ends the
// connection with FLOW_CONTROL_ERROR, RFC 9113 section 6.9.2.
func TestConn_SettingsOverflowingTheSendWindowEndsTheConnection(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 1)
	ready := make(chan *fakePeer, 1)
	go func() {
		peer, err := startFakePeer(srv)
		if err != nil {
			close(ready)
			return
		}
		ready <- peer
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
				answered <- mh.StreamID
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	peer := <-ready
	require.NotNil(t, peer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err = c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	id := <-answered
	peer.wmu.Lock()
	_ = peer.fr.WriteWindowUpdate(id, 1<<31-1-defaultWindow)
	_ = peer.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1<<31 - 1})
	peer.wmu.Unlock()
	select {
	case <-c.Done():
		var ce http2.ConnectionError
		require.ErrorAs(t, c.Err(), &ce)
		assert.Equal(t, http2.ErrCodeFlowControl, http2.ErrCode(ce))
	case <-time.After(3 * time.Second):
		t.Fatal("SETTINGS pushed a send window past 2^31-1 and the connection went on")
	}
}

// A WINDOW_UPDATE that pushes the connection send window past 2^31-1 ends the connection
// with FLOW_CONTROL_ERROR, RFC 9113 section 6.9.1.
func TestConn_ConnectionSendWindowOverflow(t *testing.T) {
	cli, srv := tcpPair(t)
	goAway := make(chan http2.ErrCode, 1)
	go func() {
		peer, err := startFakePeer(srv)
		if err != nil {
			return
		}
		peer.wmu.Lock()
		_ = peer.fr.WriteWindowUpdate(0, 1<<31-1)
		_ = peer.fr.WriteWindowUpdate(0, 1<<31-1)
		peer.wmu.Unlock()
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if ga, ok := f.(*http2.GoAwayFrame); ok {
				goAway <- ga.ErrCode
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	select {
	case code := <-goAway:
		assert.Equal(t, http2.ErrCodeFlowControl, code)
	case <-time.After(3 * time.Second):
		t.Fatal("the connection send window overflow was not reported")
	}
}

// The padding of a DATA frame is credited back, RFC 9113 section 6.9.1.
func TestConn_PaddingIsCreditedBack(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 1)
	ready := make(chan *fakePeer, 1)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		if err != nil {
			close(ready)
			return
		}
		ready <- peer
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			switch f := f.(type) {
			case *http2.MetaHeadersFrame:
				_ = peer.answer(f.StreamID)
				answered <- f.StreamID
			case *http2.WindowUpdateFrame:
				if f.StreamID == 0 {
					peer.mu.Lock()
					peer.connWindow += int64(f.Increment)
					peer.mu.Unlock()
				}
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	peer := <-ready
	require.NotNil(t, peer)
	require.Eventually(t, func() bool { return peer.window() == connWindow }, 5*time.Second, 5*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	id := <-answered
	go func() { _, _ = io.Copy(io.Discard, s) }()

	// Past creditRefresh, so the batched credit is due whatever the reader consumed.
	const frames = 4000
	for range frames {
		peer.wmu.Lock()
		werr := peer.fr.WriteDataPadded(id, false, []byte("x"), make([]byte, 200))
		peer.wmu.Unlock()
		require.NoError(t, werr)
		peer.mu.Lock()
		peer.connWindow -= 1 + 1 + 200
		peer.mu.Unlock()
	}
	// Everything read and the stream closed, so nothing is owed any more.
	require.NoError(t, s.Close())
	assert.Eventually(t, func() bool { return peer.window() == connWindow }, 5*time.Second, 20*time.Millisecond,
		"the connection window never came back, %d left of %d", peer.window(), connWindow)
}

// RST_STREAM on a stream that ended in both directions is ignored, RFC 9113 section 5.1.
func TestConn_ResetOfAClosedStreamIsIgnored(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 1)
	ready := make(chan *fakePeer, 1)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		if err != nil {
			close(ready)
			return
		}
		ready <- peer
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			if mh, ok := f.(*http2.MetaHeadersFrame); ok {
				_ = peer.answer(mh.StreamID)
				answered <- mh.StreamID
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	peer := <-ready
	require.NotNil(t, peer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	id := <-answered
	require.NoError(t, s.CloseWrite())
	peer.wmu.Lock()
	_ = peer.fr.WriteData(id, true, nil)
	peer.wmu.Unlock()
	_, rerr := io.ReadAll(s)
	require.NoError(t, rerr)
	peer.wmu.Lock()
	_ = peer.fr.WriteRSTStream(id, http2.ErrCodeCancel)
	peer.wmu.Unlock()
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, c.Err(), "a RST_STREAM on a closed stream ended the connection")
}

// Close returns once the socket is closed, a write stuck on it cut by closeTimeout before.
func TestConn_CloseReturnsAfterTheSocketIsClosed(t *testing.T) {
	g := newStuckConn()
	c, err := Client(g, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = g.Close() })

	fr := http2.NewFramer(&peerWriter{g: g}, nil)
	require.NoError(t, fr.WriteSettings())
	select {
	case <-c.settingsSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("the client never saw the peer's SETTINGS")
	}
	time.Sleep(100 * time.Millisecond)

	g.setStick()
	// A PING the client owes an ack for, so the write goroutine sticks on the socket.
	require.NoError(t, fr.WritePing(false, [8]byte{1}))
	deadline := time.Now().Add(2 * time.Second)
	for !g.writing() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.True(t, g.writing(), "the write goroutine never got stuck on the socket")

	start := time.Now()
	require.NoError(t, c.Close())
	returned := time.Since(start)
	select {
	case at := <-g.closedAt:
		assert.GreaterOrEqual(t, returned, at.Sub(start),
			"Close returned %s after it was called, %s before the socket was closed", returned, at.Sub(start)-returned)
	case <-time.After(3 * time.Second):
		t.Fatal("the socket was never closed")
	}
}

// A bufio.Reader over the stream whose deadline is reset at every idle period, the read
// path of a tunnel, picks up where the deadline cut it, losing and repeating nothing.
func TestStream_BufferedReaderAcrossReadDeadlines(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	s, _ := open(t, c, nil)
	t.Cleanup(func() { _ = s.Close() })

	const records = 400
	go func() {
		for i := range records {
			// One record: a two byte length, then that many bytes of the record's index.
			body := make([]byte, 1+i%97)
			for j := range body {
				body[j] = byte(i)
			}
			hdr := []byte{byte(len(body) >> 8), byte(len(body))}
			if _, err := s.Write(append(hdr, body...)); err != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	br := newBufioReader(s)
	deadline := time.Now().Add(30 * time.Second)
	for i := range records {
		var hdr [2]byte
		for {
			_ = s.SetReadDeadline(time.Now().Add(3 * time.Millisecond))
			n, err := io.ReadFull(br, hdr[:])
			if err == nil {
				break
			}
			require.ErrorIs(t, err, os.ErrDeadlineExceeded, "record %d header after %d bytes", i, n)
			require.True(t, time.Now().Before(deadline), "the reader never got past record %d", i)
			// io.ReadFull loses what it read on a short read, so only a clean cut may resume.
			require.Zero(t, n, "a read deadline cut a header in half at record %d", i)
		}
		want := int(hdr[0])<<8 | int(hdr[1])
		body := make([]byte, want)
		for got := 0; got < want; {
			_ = s.SetReadDeadline(time.Now().Add(3 * time.Millisecond))
			n, err := io.ReadFull(br, body[got:])
			got += n
			if err != nil {
				require.ErrorIs(t, err, os.ErrDeadlineExceeded, "record %d body", i)
				require.True(t, time.Now().Before(deadline), "the reader never finished record %d", i)
			}
		}
		for j := range body {
			require.Equal(t, byte(i), body[j], "record %d is not what was written", i)
		}
	}
}

func newBufioReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }

// The credit a stream took is granted back when it ends, padding alone included, whatever
// the batch still held.
func TestConn_PaddingOnlyFramesReturnTheWindow(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 1)
	ready := make(chan *fakePeer, 1)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		if err != nil {
			close(ready)
			return
		}
		ready <- peer
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			switch f := f.(type) {
			case *http2.MetaHeadersFrame:
				_ = peer.answer(f.StreamID)
				answered <- f.StreamID
			case *http2.WindowUpdateFrame:
				if f.StreamID == 0 {
					peer.mu.Lock()
					peer.connWindow += int64(f.Increment)
					peer.mu.Unlock()
				}
			}
		}
	}()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	peer := <-ready
	require.NotNil(t, peer)
	require.Eventually(t, func() bool { return peer.window() == connWindow }, 5*time.Second, 5*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	id := <-answered

	// Padding alone: nothing ever reaches the reader, so the stream ends holding nothing.
	const frames = 100
	for range frames {
		peer.wmu.Lock()
		werr := peer.fr.WriteDataPadded(id, false, nil, make([]byte, 200))
		peer.wmu.Unlock()
		require.NoError(t, werr)
		peer.mu.Lock()
		peer.connWindow -= 201
		peer.mu.Unlock()
	}
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, s.Close())
	assert.Eventually(t, func() bool { return peer.window() == connWindow }, 3*time.Second, 20*time.Millisecond,
		"the connection window is short by %d after the stream that took it ended", connWindow-peer.window())
}

// A trailer section on a connected CONNECT stream is a stream error, RFC 9113 section 8.5.
func TestStream_TrailersOnAConnectedStreamAreAStreamError(t *testing.T) {
	cli, srv := tcpPair(t)
	peerOn(srv, func(p *fakePeer, id uint32) {
		_ = p.answer(id)
		_ = p.writeHeaders(id, true, hpack.HeaderField{Name: "x-trailer", Value: "v"})
	}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})

	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, resp, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, s.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, rerr := s.Read(make([]byte, 1))
	require.Error(t, rerr)
	require.NotErrorIs(t, rerr, os.ErrDeadlineExceeded, "the trailers never arrived, the test proved nothing")
	require.NotErrorIs(t, rerr, io.EOF, "a trailer section on a connected CONNECT stream read as a clean end")
}

// Everything at once against a peer that resets streams, goes away and stops reading, with
// a watchdog on every caller.
func TestConn_EverythingAtOnce(t *testing.T) {
	cli, srv := tcpPair(t)
	go func() {
		peer, err := startFakePeer(srv,
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20},
			http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
		if err != nil {
			return
		}
		_ = peer.fr.WriteWindowUpdate(0, 1<<28)
		n := 0
		for {
			f, rerr := peer.fr.ReadFrame()
			if rerr != nil {
				return
			}
			mh, ok := f.(*http2.MetaHeadersFrame)
			if !ok {
				continue
			}
			n++
			switch n % 4 {
			case 0:
				_ = peer.answer(mh.StreamID)
				peer.wmu.Lock()
				_ = peer.fr.WriteData(mh.StreamID, false, make([]byte, 4096))
				peer.wmu.Unlock()
			case 1:
				_ = peer.answer(mh.StreamID)
				peer.wmu.Lock()
				_ = peer.fr.WriteRSTStream(mh.StreamID, http2.ErrCodeCancel)
				peer.wmu.Unlock()
			case 2:
				peer.wmu.Lock()
				_ = peer.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(1024 * (n % 64))}) //nolint:gosec // small
				peer.wmu.Unlock()
				_ = peer.answer(mh.StreamID)
			default:
				_ = peer.answer(mh.StreamID)
				peer.wmu.Lock()
				_ = peer.fr.WriteData(mh.StreamID, true, []byte("bye"))
				peer.wmu.Unlock()
			}
		}
	}()
	c, err := Client(cli, 50*time.Millisecond)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 30 {
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				s, _, oerr := c.Open(ctx, Request{Protocol: "connect-udp", Scheme: "https",
					Authority: "proxy.test", Path: "/.well-known/masque/udp/192.0.2.1/53/"})
				cancel()
				if oerr != nil {
					continue
				}
				var inner sync.WaitGroup
				inner.Add(4)
				go func() { defer inner.Done(); _, _ = s.Write(make([]byte, 16<<10)) }()
				go func() { defer inner.Done(); _, _ = io.Copy(io.Discard, s) }()
				go func() {
					defer inner.Done()
					_ = s.SetDeadline(time.Now().Add(30 * time.Millisecond))
					_ = s.SetDeadline(time.Time{})
				}()
				go func() { defer inner.Done(); _ = s.CloseWrite() }()
				time.Sleep(time.Millisecond)
				_ = s.Close()
				inner.Wait()
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatalf("a caller was left blocked, conn err %v", c.Err())
	}
}
