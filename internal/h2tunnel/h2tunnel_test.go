// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package h2tunnel

import (
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
	c, err := Client(tc)
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
	require.ErrorIs(t, err, errClosed)
	_, err = s.Write([]byte("x"))
	require.ErrorIs(t, err, errClosed)
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
	c, err := Client(nc)
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

	c, err := Client(cli)
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

	c, err := Client(cli)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	peer := <-ready
	require.NotNil(t, peer)
	require.Eventually(t, func() bool { return peer.window() == window }, 5*time.Second, 5*time.Millisecond,
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
	assert.Eventually(t, func() bool { return peer.window() == window }, 5*time.Second, 10*time.Millisecond,
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

	c, err := Client(cli)
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

	c, err := Client(cli)
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
	c, err := Client(cli)
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
	c, err := Client(cli)
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

	c, err := Client(cli)
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
	for range writeQueue + 64 {
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
	assert.Eventually(t, func() bool { return connCredit.Load() >= window }, 10*time.Second, 10*time.Millisecond,
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
	c, err := Client(cli)
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
	c, err := Client(cli)
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
	c, err := Client(cli)
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
