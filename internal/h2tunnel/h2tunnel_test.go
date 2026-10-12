// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package h2tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
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

	// The writer sticks on the socket, and the peer provokes more control frames than the queue bounds.
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

func TestConn_OpenHonoursItsContextBehindAStuckWriter(t *testing.T) {
	c, _ := stuckPeer(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), time.Second, "Open outlived its context behind the stuck writer")
}

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

func TestStream_TinyFramesCostNoChunkEach(t *testing.T) {
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

	const bytesSent = 200 << 10
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	one := []byte{0}
	for range bytesSent {
		peer.wmu.Lock()
		werr := peer.fr.WriteData(id, false, one)
		peer.wmu.Unlock()
		require.NoError(t, werr)
	}
	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		var buffered int
		for _, chunk := range s.chunks {
			buffered += len(chunk)
		}
		return buffered >= bytesSent
	}, 20*time.Second, 20*time.Millisecond, "the client never buffered every one-byte frame")
	runtime.GC()
	runtime.ReadMemStats(&after)
	var chunks int
	s.mu.Lock()
	chunks = len(s.chunks)
	s.mu.Unlock()
	grew := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("%d bytes of DATA buffered as %d chunks, heap grew by %d bytes (%.1fx)",
		bytesSent, chunks, grew, float64(grew)/float64(bytesSent))
	assert.Less(t, grew, int64(5*bytesSent),
		"%d bytes of stream window cost %d bytes of heap", bytesSent, grew)
}

func TestConn_OneByteFloodBehindAStuckWriter(t *testing.T) {
	c, streams := stuckPeer(t, 1)
	s := streams[0]
	read := make(chan error, 1)
	go func() {
		buf := make([]byte, 1<<10)
		for {
			if _, err := s.Read(buf); err != nil {
				read <- err
				return
			}
		}
	}()
	select {
	case <-read:
	case <-time.After(2 * time.Second):
	}
	var queued, ctl int
	c.onLoop(func() { queued, ctl = c.queuedControl, len(c.control) })
	require.NoError(t, c.Err())
	require.LessOrEqual(t, queued, maxControlFrames, "control frames owed past the bound")
	require.LessOrEqual(t, ctl, maxControlFrames+8, "control queue %d past the bound", ctl)
}

func TestConn_LocalResetsAreNoPeerFlood(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan struct{}, 4)
	ready := make(chan *fakePeer, 1)
	go func() {
		peer, err := startFakePeer(srv, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 24})
		if err != nil {
			close(ready)
			return
		}
		_ = peer.fr.WriteWindowUpdate(0, 1<<28)
		ready <- peer
		seen := 0
		for seen < 3 {
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
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	peer := <-ready
	require.NotNil(t, peer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var streams []*Stream
	for range 3 {
		s, _, oerr := c.Open(ctx, Request{Authority: "origin.test:443"})
		require.NoError(t, oerr)
		<-answered
		streams = append(streams, s)
	}
	var sent int
	c.onLoop(func() {
		for _, s := range streams {
			if s.headersSent {
				sent++
			}
		}
	})
	require.Equal(t, 3, sent, "the HEADERS never left, so no reset is owed and the test proves nothing")

	// The socket takes nothing from here on, so nothing drains the control queue.
	go func() { _, _ = streams[0].Write(make([]byte, 64<<20)) }()
	time.Sleep(300 * time.Millisecond)
	for range maxControlFrames - 2 {
		peer.wmu.Lock()
		_ = peer.fr.WritePing(false, [8]byte{1})
		peer.wmu.Unlock()
	}
	time.Sleep(500 * time.Millisecond)
	require.NoError(t, streams[1].Close())
	require.NoError(t, streams[2].Close())
	time.Sleep(300 * time.Millisecond)
	peer.wmu.Lock()
	_ = peer.fr.WritePing(false, [8]byte{2})
	peer.wmu.Unlock()
	select {
	case <-c.Done():
		require.NotErrorIs(t, c.Err(), errControlFlood,
			"two of the caller's own resets pushed the peer flood bound over")
	case <-time.After(2 * time.Second):
	}
}

func TestConn_ControlFloodEndsWithGoAway(t *testing.T) {
	cli, srv := tcpPair(t)
	gate := newGateConn(cli)
	p := dialPeerOn(t, gate, srv)
	p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 24})
	p.wantSettingsAck()
	p.writeWindowUpdate(0, 1<<28)
	s, _ := p.connect()
	// The writer is held, so nothing serve encodes leaves and every ack stays owed.
	gate.hold()
	go func() { _, _ = s.Write(make([]byte, 64<<20)) }()
	waitStuck(t, p.c)
	// One ack past the bound ends the connection, and every PING was read by then, so
	// the socket closes with a FIN and not a RST that would drop the GOAWAY.
	for range maxControlFrames + 1 {
		p.writePing(false, [8]byte{1})
	}
	select {
	case <-p.c.Done():
	case <-time.After(wantTimeout):
		t.Fatal("the control flood never ended the connection")
	}
	require.ErrorIs(t, p.c.Err(), errControlFlood)
	gate.release()
	p.wantGoAway(http2.ErrCodeEnhanceYourCalm)
	p.wantClosed()
}

func TestStream_TinyFramesKeepTheirOrder(t *testing.T) {
	p := newPeer(t)
	s, id := p.connect()
	const total = 200 << 10
	want := make([]byte, total)
	rnd := mathrand.New(mathrand.NewSource(7)) //nolint:gosec // a test stream
	_, _ = rnd.Read(want)
	go func() {
		off := 0
		for off < total {
			n := 1 + rnd.Intn(200)
			if off+n > total {
				n = total - off
			}
			p.writeData(id, false, want[off:off+n])
			off += n
			if off%(8<<10) < 200 {
				time.Sleep(time.Millisecond)
			}
		}
	}()
	got := make([]byte, 0, total)
	buf := make([]byte, 777)
	require.NoError(t, s.SetReadDeadline(time.Now().Add(20*time.Second)))
	for len(got) < total {
		n, rerr := s.Read(buf)
		require.NoError(t, rerr)
		got = append(got, buf[:n]...)
		if len(got)%3000 < 777 {
			time.Sleep(time.Millisecond)
		}
	}
	require.Equal(t, want, got)
}

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

func TestConn_ConnectionWindowExactAcrossEveryPath(t *testing.T) {
	p := newPeer(t)
	var want int64
	p.c.onLoop(func() { want = p.c.recv.avail + p.c.recv.unsent })
	for round := range 12 {
		s, id := p.connect()
		p.writeData(id, false, make([]byte, 4<<10))
		require.NoError(t, p.fr.WriteDataPadded(id, false, make([]byte, 1<<10), make([]byte, 64)))
		time.Sleep(5 * time.Millisecond)
		switch round % 3 {
		case 0:
			// A local close drops what was buffered.
			require.NoError(t, s.Close())
			p.writeData(id, false, make([]byte, 2<<10))
		case 1:
			// The peer ends the stream, then sends DATA past it.
			p.writeData(id, true, make([]byte, 1<<10))
			time.Sleep(5 * time.Millisecond)
			p.writeData(id, false, make([]byte, 2<<10))
			require.NoError(t, s.Close())
		case 2:
			p.writeRST(id, http2.ErrCodeCancel)
		}
		select {
		case <-s.closed:
		case <-time.After(wantTimeout):
			t.Fatal("the stream did not close")
		}
		time.Sleep(5 * time.Millisecond)
	}
	var got int64
	require.Eventually(t, func() bool {
		p.c.onLoop(func() { got = p.c.recv.avail + p.c.recv.unsent })
		return got == want
	}, wantTimeout, 10*time.Millisecond, "the connection receive window drifted: want %d, got %d", want, got)
}

func TestConn_QuietStreamsHoldNoConnectionWindow(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 1<<10)
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	peer := creditPeer(t, srv, answered, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	require.Eventually(t, func() bool { return peer.window() == connWindow }, wantTimeout, 5*time.Millisecond)

	// What one stream carries, held in the test rather than taken from the implementation,
	// so the bound stands whatever a reader keeps back.
	const quiet = 32<<10 - 1
	const streams = connWindow/quiet + 8
	for n := range streams {
		ctx, cancel := context.WithTimeout(context.Background(), wantTimeout)
		s, _, oerr := c.Open(ctx, Request{Authority: "origin.test:443"})
		cancel()
		require.NoError(t, oerr, "open %d", n)
		id := <-answered
		for off := 0; off < quiet; off += 16384 {
			require.NoError(t, peer.writeData(id, make([]byte, min(16384, quiet-off))))
		}
		// Buffered before the read, so no Read of it waits and grants back what a wait does.
		require.Eventually(t, func() bool { return buffered(s) == quiet }, wantTimeout, time.Millisecond,
			"stream %d never received what the peer sent", n)
		_, rerr := io.ReadFull(s, make([]byte, quiet))
		require.NoError(t, rerr, "stream %d", n)
	}

	require.Eventually(t, func() bool { return peer.window() > connWindow/4 }, wantTimeout, 20*time.Millisecond,
		"the connection window never came back though every stream read everything it received")

	// The connection still carries, on a stream opened after the others went quiet.
	ctx, cancel := context.WithTimeout(context.Background(), wantTimeout)
	fresh, _, oerr := c.Open(ctx, Request{Authority: "origin.test:443"})
	cancel()
	require.NoError(t, oerr)
	require.NoError(t, peer.writeData(<-answered, []byte("x")))
	require.NoError(t, fresh.SetReadDeadline(time.Now().Add(wantTimeout)))
	b := make([]byte, 1)
	_, rerr := io.ReadFull(fresh, b)
	require.NoError(t, rerr)
	require.Equal(t, "x", string(b))
	require.NoError(t, c.Err())
}

// buffered is what the peer delivered on s and no reader has taken.
func buffered(s *Stream) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	for _, chunk := range s.chunks {
		n += len(chunk)
	}
	return n
}

func TestConn_QuietStreamsHoldNoConnectionWindowAfterABuffer(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 1<<10)
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	peer := creditPeer(t, srv, answered, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	require.Eventually(t, func() bool { return peer.window() == connWindow }, wantTimeout, 5*time.Millisecond)

	// Full streams nobody reads, enough of them to take the connection window low.
	for n := 0; peer.window() > connWindow/4; n++ {
		ctx, cancel := context.WithTimeout(context.Background(), wantTimeout)
		s, _, oerr := c.Open(ctx, Request{Authority: "origin.test:443"})
		cancel()
		require.NoError(t, oerr, "buffer %d", n)
		_ = s
		id := <-answered
		for off := 0; off < window; off += 16384 {
			require.NoError(t, peer.writeData(id, make([]byte, 16384)))
		}
		require.Less(t, n, 64, "the connection window never went low")
	}

	// Then the quiet streams, which read everything they receive and stop.
	const quiet = 32<<10 - 1
	for n := range 160 {
		ctx, cancel := context.WithTimeout(context.Background(), wantTimeout)
		s, _, oerr := c.Open(ctx, Request{Authority: "origin.test:443"})
		cancel()
		require.NoError(t, oerr, "quiet %d", n)
		id := <-answered
		for off := 0; off < quiet; off += 16384 {
			require.NoError(t, peer.writeData(id, make([]byte, min(16384, quiet-off))))
		}
		require.Eventually(t, func() bool { return buffered(s) == quiet }, wantTimeout, time.Millisecond,
			"quiet stream %d never received what the peer sent", n)
		_, rerr := io.ReadFull(s, make([]byte, quiet))
		require.NoError(t, rerr, "quiet stream %d", n)
	}
	require.NoError(t, c.Err())
}

// A contract case is one sentence of the net.Conn or io.Reader documentation checked on a
// Stream, the contract the datagram flow of a tunnel relies on through capsulePipe.
type contractCase struct {
	name string
	// req is the requirement in the words of the standard library.
	req string
	run func(t *testing.T)
}

func TestNetConn(t *testing.T) {
	for _, tc := range contract {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t)
		})
	}
}

var contract = []contractCase{
	{
		name: "a read deadline is a timeout, not the end",
		req:  "Read can be made to time out and return an error after a fixed time limit; see SetDeadline and SetReadDeadline. A zero value for t means Read will not time out.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, id := p.connect()
			require.NoError(t, s.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
			_, err := s.Read(make([]byte, 1))
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			require.NoError(t, s.SetReadDeadline(time.Time{}))
			p.writeData(id, false, []byte("after"))
			p.wantRead(s, []byte("after"))
		},
	},
	{
		name: "a Read past its deadline fails with bytes buffered",
		req:  "A deadline is an absolute time after which I/O operations fail instead of blocking.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, id := p.connect()
			p.writeData(id, false, []byte("buffered"))
			require.Eventually(t, func() bool {
				s.mu.Lock()
				defer s.mu.Unlock()
				return len(s.chunks) > 0
			}, wantTimeout, 5*time.Millisecond)
			require.NoError(t, s.SetReadDeadline(time.Now().Add(-time.Second)))
			_, err := s.Read(make([]byte, 16))
			require.ErrorIs(t, err, os.ErrDeadlineExceeded, "a Read past its deadline returned data")
		},
	},
	{
		name: "a read deadline set while a Read is blocked ends it at that time",
		req:  "SetReadDeadline sets the deadline for future Read calls and any currently-blocked Read call.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, _ := p.connect()
			read := make(chan error, 1)
			go func() {
				_, err := s.Read(make([]byte, 16))
				read <- err
			}()
			time.Sleep(200 * time.Millisecond)
			require.NoError(t, s.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
			select {
			case err := <-read:
				require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			case <-time.After(wantTimeout):
				t.Fatal("a deadline set while the read was blocked did not end it")
			}
		},
	},
	{
		name: "a read deadline wakes every pending Read",
		req:  "The deadline applies to all future and pending I/O, not just the immediately following call to Read or Write.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, _ := p.connect()
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
			case <-time.After(wantTimeout):
				t.Fatal("a pending Read outlived a deadline already past")
			}
		},
	},
	{
		name: "the peer's end wakes every pending Read with EOF",
		req:  "When Read encounters an error or end-of-file condition after successfully reading n > 0 bytes, it returns the number of bytes read. ... Callers should always process the n > 0 bytes returned before considering the error err.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, id := p.connect()
			errs := make(chan error, 2)
			for range 2 {
				go func() {
					_, err := s.Read(make([]byte, 1))
					errs <- err
				}()
			}
			time.Sleep(300 * time.Millisecond)
			p.writeData(id, true, nil)
			for range 2 {
				select {
				case err := <-errs:
					require.ErrorIs(t, err, io.EOF)
				case <-time.After(wantTimeout):
					t.Fatal("a pending Read outlived the peer's END_STREAM")
				}
			}
		},
	},
	{
		name: "Read with an empty buffer returns at once",
		req:  "Implementations of Read are discouraged from returning a zero byte count with a nil error, except when len(p) == 0.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, _ := p.connect()
			done := make(chan struct{})
			go func() {
				n, err := s.Read(nil)
				assert.Zero(t, n)
				assert.NoError(t, err)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(wantTimeout):
				t.Fatal("Read with a zero-length buffer never returned")
			}
		},
	},
	{
		name: "Read after Stream.Close fails",
		req:  "Close closes the connection. Any blocked Read or Write operations will be unblocked and return errors.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, id := p.connect()
			p.writeData(id, false, []byte("buffered"))
			require.Eventually(t, func() bool {
				s.mu.Lock()
				defer s.mu.Unlock()
				return len(s.chunks) > 0
			}, wantTimeout, 5*time.Millisecond)
			require.NoError(t, s.Close())
			buf := make([]byte, 16)
			n, err := s.Read(buf)
			require.ErrorIs(t, err, errStreamClosed, "Read after Close returned %d bytes: %q", n, buf[:n])
		},
	},
	{
		name: "Read after Conn.Close fails",
		req:  "Close closes the connection. Any blocked Read or Write operations will be unblocked and return errors.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, id := p.connect()
			p.writeData(id, false, []byte("buffered"))
			require.Eventually(t, func() bool {
				s.mu.Lock()
				defer s.mu.Unlock()
				return len(s.chunks) > 0
			}, wantTimeout, 5*time.Millisecond)
			require.NoError(t, p.c.Close())
			buf := make([]byte, 16)
			n, err := s.Read(buf)
			require.ErrorIs(t, err, net.ErrClosed, "Read after Conn.Close returned %d bytes: %q", n, buf[:n])
		},
	},
	{
		name: "a stream the peer ended drains to EOF through Close",
		req:  "When Read encounters an error or end-of-file condition after successfully reading n > 0 bytes, it returns the number of bytes read.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, id := p.connect()
			p.writeData(id, true, []byte("buffered"))
			require.Eventually(t, func() bool {
				s.mu.Lock()
				defer s.mu.Unlock()
				return len(s.chunks) > 0 && s.readErr != nil
			}, wantTimeout, 5*time.Millisecond)
			require.NoError(t, s.Close())
			p.wantRead(s, []byte("buffered"))
			p.wantReadError(s, io.EOF)
		},
	},
	{
		name: "a write deadline ends a Write behind a stuck writer",
		req:  "Write can be made to time out and return an error after a fixed time limit; see SetDeadline and SetWriteDeadline.",
		run: func(t *testing.T) {
			_, streams := stuckPeer(t, 2)
			s := streams[1]
			require.NoError(t, s.SetWriteDeadline(time.Now().Add(200*time.Millisecond)))
			start := time.Now()
			_, err := s.Write([]byte("late"))
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			assert.Less(t, time.Since(start), time.Second, "Write outlived its deadline behind the stuck writer")
		},
	},
	{
		name: "a write deadline set while a Write is blocked ends it",
		req:  "SetWriteDeadline sets the deadline for future Write calls and any currently-blocked Write call.",
		run: func(t *testing.T) {
			_, streams := stuckPeer(t, 2)
			s := streams[1]
			wrote := make(chan error, 1)
			go func() {
				_, err := s.Write(make([]byte, 8<<20))
				wrote <- err
			}()
			time.Sleep(300 * time.Millisecond)
			require.NoError(t, s.SetWriteDeadline(time.Now().Add(200*time.Millisecond)))
			select {
			case err := <-wrote:
				require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			case <-time.After(wantTimeout):
				t.Fatal("a deadline set while the write was blocked did not end it")
			}
		},
	},
	{
		name: "a Write past its deadline sends nothing and keeps the windows",
		req:  "If the deadline is exceeded a call to Read or Write or to other I/O methods will return an error that wraps os.ErrDeadlineExceeded. ... After a deadline has been exceeded, the connection can be refreshed by setting a deadline in the future.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, id := p.connect()
			var conn, stream int64
			p.c.onLoop(func() { conn, stream = p.c.sendWindow, s.sendWindow })
			require.NoError(t, s.SetWriteDeadline(time.Now().Add(-time.Second)))
			for range 100 {
				_, err := s.Write(make([]byte, 1000))
				require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			}
			require.NoError(t, s.SetWriteDeadline(time.Time{}))
			_, err := s.Write([]byte("drain"))
			require.NoError(t, err)
			require.Equal(t, "drain", string(p.wantData(id).Data()))
			var connNow, streamNow int64
			p.c.onLoop(func() { connNow, streamNow = p.c.sendWindow, s.sendWindow })
			assert.Equal(t, conn-5, connNow, "the skipped writes took from the connection send window")
			assert.Equal(t, stream-5, streamNow, "the skipped writes took from the stream send window")
		},
	},
	{
		name: "a Write the deadline cuts mid-way ends the stream",
		req:  "Even if write times out, it may return n > 0, indicating that some of the data was successfully written. A byte stream that lost track of what left cannot go on.",
		run: func(t *testing.T) {
			_, streams := silentPeer(t, 1, false)
			s := streams[0]
			require.NoError(t, s.SetWriteDeadline(time.Now().Add(300*time.Millisecond)))
			_, err := s.Write(make([]byte, 8<<20))
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			require.NoError(t, s.SetWriteDeadline(time.Time{}))
			_, err = s.Write([]byte("more"))
			require.Error(t, err)
			require.NotErrorIs(t, err, os.ErrDeadlineExceeded, "the stream went on after a frame it lost track of")
		},
	},
	{
		name: "a Write cut by Stream.Close reports what left",
		req:  "Even if write times out, it may return n > 0, indicating that some of the data was successfully written.",
		run: func(t *testing.T) {
			_, streams := silentPeer(t, 1, false)
			wantCutWriteReported(t, streams[0], streams[0].Close)
		},
	},
	{
		name: "a Write cut by Conn.Close reports what left",
		req:  "Even if write times out, it may return n > 0, indicating that some of the data was successfully written.",
		run: func(t *testing.T) {
			c, streams := silentPeer(t, 1, false)
			wantCutWriteReported(t, streams[0], c.Close)
		},
	},
	{
		name: "a bufio.Reader across read deadlines loses and repeats nothing",
		req:  "An idle timeout can be implemented by repeatedly extending the deadline after successful Read or Write calls. The read path of a tunnel resets the deadline at every idle period over a bufio.Reader.",
		run: func(t *testing.T) {
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
		},
	},
}

// wantCutWriteReported starts a write the peer never drains, cuts it with close and wants
// the count of what left.
func wantCutWriteReported(t *testing.T, s *Stream, close func() error) {
	t.Helper()
	wrote := make(chan writeResult, 1)
	go func() {
		n, err := s.Write(make([]byte, 8<<20))
		wrote <- writeResult{n: n, err: err}
	}()
	time.Sleep(500 * time.Millisecond)
	require.NoError(t, close())
	select {
	case r := <-wrote:
		require.Error(t, r.err)
		assert.Greater(t, r.n, 0, "Write reported 0 bytes though its frames left the socket")
	case <-time.After(wantTimeout):
		t.Fatal("the write outlived the close")
	}
}

func TestConn_SettingsWhileOpening(t *testing.T) {
	// The race detector checks this test.
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

func TestStream_ConcurrentAPI(t *testing.T) {
	// The race detector checks this test.
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
}

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

func TestConn_CreditExactUnderReadsRacingCloses(t *testing.T) {
	cli, srv := tcpPair(t)
	answered := make(chan uint32, 16)
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	peer := creditPeer(t, srv, answered, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
	require.Eventually(t, func() bool { return peer.window() == connWindow }, 5*time.Second, 5*time.Millisecond)

	for round := range 24 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s, _, oerr := c.Open(ctx, Request{Authority: "origin.test:443"})
		cancel()
		require.NoError(t, oerr)
		id := <-answered
		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 1+round*997)
			for {
				if _, rerr := s.Read(buf); rerr != nil {
					return
				}
			}
		}()
		for sent := 0; sent < 512<<10; sent += 8192 {
			if werr := peer.writeData(id, make([]byte, 8192)); werr != nil {
				break
			}
		}
		time.Sleep(time.Duration(round%7) * time.Millisecond)
		require.NoError(t, s.Close())
		<-done
		require.NoError(t, c.Err())
		require.LessOrEqual(t, peer.window(), int64(connWindow),
			"round %d: the client granted back more connection window than it ever took", round)
	}
	assert.Eventually(t, func() bool { return peer.window() == connWindow }, 5*time.Second, 10*time.Millisecond,
		"the connection window never came back, short by %d", connWindow-peer.window())
}

func TestConn_NoGoroutineLeftBehind(t *testing.T) {
	srv := echoServer(t, nil)
	before := runtime.NumGoroutine()
	for range 8 {
		c := dial(t, srv)
		s, _ := open(t, c, nil)
		_, _ = s.Write([]byte("x"))
		_ = c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+8 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	assert.LessOrEqual(t, runtime.NumGoroutine(), before+8,
		"goroutines left behind: %d before, %d after", before, runtime.NumGoroutine())
}

func TestConn_RetireRacingEverything(t *testing.T) {
	srv := echoServer(t, nil)
	for range 4 {
		c := dial(t, srv)
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 12 {
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					s, _, err := c.Open(ctx, Request{Authority: "origin.test:443"})
					cancel()
					if err != nil {
						continue
					}
					var inner sync.WaitGroup
					inner.Add(5)
					go func() { defer inner.Done(); _, _ = s.Write(make([]byte, 12<<10)) }()
					go func() { defer inner.Done(); _, _ = io.Copy(io.Discard, s) }()
					go func() { defer inner.Done(); _ = s.SetReadDeadline(time.Now().Add(10 * time.Millisecond)) }()
					go func() { defer inner.Done(); _ = s.SetWriteDeadline(time.Now().Add(10 * time.Millisecond)) }()
					go func() { defer inner.Done(); _ = s.CloseWrite() }()
					_ = s.Close()
					inner.Wait()
				}
			}()
		}
		time.Sleep(120 * time.Millisecond)
		c.Retire()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatalf("a caller was left blocked after Retire, conn err %v", c.Err())
		}
		require.NoError(t, c.Close())
	}
}

func TestConn_OpenCancelledLeavesTheRequestToTheCaller(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	for i := range 3000 {
		require.NoError(t, c.Err())
		h := http.Header{"X-A": {"1"}}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(i%120)*time.Microsecond)
		s, _, err := c.Open(ctx, Request{Authority: "origin.test:443", Header: h})
		cancel()
		h["X-B"] = []string{"2"}
		if err == nil {
			_ = s.Close()
		}
	}
}

func TestConn_OpenCancelledAsTheAnswerArrives(t *testing.T) {
	for range 40 {
		p := newPeer(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		var s *Stream
		go func() {
			s, _, _ = p.c.Open(ctx, Request{Authority: "origin.test:443"})
			close(done)
		}()
		id := p.wantHeaders().StreamID
		go cancel()
		p.answer(id)
		select {
		case <-done:
		case <-time.After(wantTimeout):
			t.Fatal("Open did not return")
		}
		if s != nil {
			// The answer won the race, so the stream is the caller's to close.
			require.NoError(t, s.Close())
		}
		var open int
		p.c.onLoop(func() { open = len(p.c.streams) })
		require.Zero(t, open, "a stream was left behind")
		_ = p.c.Close()
	}
}

// A conformance case is one requirement of an RFC checked against the client, as the peer
// sees it. The table is the catalogue: h2spec's cases first, under its own keys, then the
// scenarios of Go's HTTP/2 transport tests that apply to a client of CONNECT streams. A case
// that cannot apply states the reason instead of a scenario, so every requirement of the
// sources is accounted for in one place.
type conformanceCase struct {
	// id is the key in the source, "http2/6.5.2/1" in h2spec.
	id string
	// name states what the peer sends.
	name string
	// req is the requirement in the words of the RFC.
	req string
	// skip gives the reason the case does not apply, or where the client departs from it.
	skip string
	run  func(t *testing.T, p *peer)
}

func TestConformance(t *testing.T) {
	for _, tc := range conformance {
		t.Run(tc.id+" "+tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}
			t.Parallel()
			tc.run(t, newPeer(t))
		})
	}
}

// str is an HPACK string literal, huff the same Huffman-coded, RFC 7541 section 5.2.
func str(v string) []byte { return append([]byte{byte(len(v))}, v...) }

func huff(v string) []byte {
	b := hpack.AppendHuffmanString(nil, v)
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// bigBlock is a header block past one frame, Huffman coding included.
func bigBlock(p *peer) []byte {
	return p.block(status("200"), hpack.HeaderField{Name: "x-pad", Value: strings.Repeat("a", 30000)})
}

var conformance = []conformanceCase{
	// h2spec generic: what an endpoint accepts.
	{
		id: "generic/1/1", name: "the client sends the connection preface",
		req: "The client connection preface starts with a sequence of 24 octets, followed by a SETTINGS frame.",
		run: func(t *testing.T, p *peer) { p.wantAlive() },
	},
	{
		id: "generic/2/1", name: "PRIORITY on an idle stream",
		req: "The endpoint MUST accept PRIORITY frame.",
		run: func(t *testing.T, p *peer) {
			p.writePriority(101, http2.PriorityParam{Weight: 15})
			p.wantAlive()
		},
	},
	{
		id: "generic/2/2", name: "WINDOW_UPDATE on a stream the peer ended",
		req: "The endpoint MUST accept WINDOW_UPDATE frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writeWindowUpdate(id, 10)
			p.wantAlive()
		},
	},
	{
		id: "generic/2/3", name: "PRIORITY on a stream the peer ended",
		req: "The endpoint MUST accept PRIORITY frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writePriority(id, http2.PriorityParam{Weight: 15})
			p.wantAlive()
		},
	},
	{
		id: "generic/2/4", name: "RST_STREAM on a stream the peer ended",
		req: "The endpoint MUST accept RST_STREAM frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writeRST(id, http2.ErrCodeCancel)
			p.wantAlive()
			_, err := s.Write([]byte("late"))
			require.Error(t, err)
		},
	},
	{
		id: "generic/2/5", name: "PRIORITY on a closed stream",
		req: "The endpoint MUST accept PRIORITY frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, s.Close())
			p.wantRST(id, http2.ErrCodeCancel)
			p.writePriority(id, http2.PriorityParam{Weight: 15})
			p.wantAlive()
		},
	},
	{
		id: "generic/3.10/1", name: "the answer in HEADERS and one CONTINUATION",
		req: "The endpoint MUST accept CONTINUATION frame.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"), hpack.HeaderField{Name: "x-a", Value: "1"})
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			require.NoError(t, p.fr.WriteContinuation(id, true, block[1:]))
			_, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, "1", resp.Header.Get("x-a"))
		},
	},
	{
		id: "generic/3.10/2", name: "the answer in HEADERS and several CONTINUATIONs",
		req: "The endpoint MUST accept multiple CONTINUATION frames.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"), hpack.HeaderField{Name: "x-a", Value: "1"})
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			require.NoError(t, p.fr.WriteContinuation(id, false, block[1:2]))
			require.NoError(t, p.fr.WriteContinuation(id, true, block[2:]))
			_, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, "1", resp.Header.Get("x-a"))
		},
	},
	{
		id: "generic/3.1/1", name: "one DATA frame",
		req: "The endpoint MUST accept DATA frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, false, []byte("hello"))
			p.wantRead(s, []byte("hello"))
		},
	},
	{
		id: "generic/3.1/2", name: "several DATA frames",
		req: "The endpoint MUST accept multiple DATA frames.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, false, []byte("hel"))
			p.writeData(id, false, []byte("lo"))
			require.Equal(t, "hello", string(p.wantReadAll(s, 5)))
		},
	},
	{
		id: "generic/3.1/3", name: "a padded DATA frame",
		req: "The endpoint MUST accept DATA frame with padding.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, p.fr.WriteDataPadded(id, false, []byte("hello"), make([]byte, 7)))
			p.wantRead(s, []byte("hello"))
		},
	},
	{
		id: "generic/3.2/1", name: "the answer in one HEADERS frame",
		req: "The endpoint MUST accept HEADERS frame.",
		run: func(t *testing.T, p *peer) { p.connect() },
	},
	{
		id: "generic/3.2/2", name: "the answer in a padded HEADERS frame",
		req: "The endpoint MUST accept HEADERS frame with padding.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: id, BlockFragment: p.block(status("200")), EndHeaders: true, PadLength: 9,
			}))
			_, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		},
	},
	{
		id: "generic/3.2/3", name: "the answer in a HEADERS frame with priority",
		req: "The endpoint MUST accept HEADERS frame with priority.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: id, BlockFragment: p.block(status("200")), EndHeaders: true,
				Priority: http2.PriorityParam{StreamDep: 0, Weight: 15},
			}))
			_, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		},
	},
	{
		id: "generic/3.3/1", name: "PRIORITY with weight 1",
		req: "The endpoint MUST accept PRIORITY frame with priority 1.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writePriority(id, http2.PriorityParam{Weight: 0})
			p.wantAlive()
		},
	},
	{
		id: "generic/3.3/2", name: "PRIORITY with weight 256",
		req: "The endpoint MUST accept PRIORITY frame with priority 256.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writePriority(id, http2.PriorityParam{Weight: 255})
			p.wantAlive()
		},
	},
	{
		id: "generic/3.3/3", name: "PRIORITY with a stream dependency",
		req: "The endpoint MUST accept PRIORITY frame with stream dependency.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			_, id2 := p.connect()
			p.writePriority(id2, http2.PriorityParam{StreamDep: id, Weight: 15})
			p.wantAlive()
		},
	},
	{
		id: "generic/3.3/4", name: "PRIORITY with an exclusive dependency",
		req: "The endpoint MUST accept PRIORITY frame with exclusive.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			_, id2 := p.connect()
			p.writePriority(id2, http2.PriorityParam{StreamDep: id, Weight: 15, Exclusive: true})
			p.wantAlive()
		},
	},
	{
		id: "generic/3.3/5", name: "PRIORITY for an idle stream, then HEADERS on a lower one",
		req:  "The endpoint MUST respond the HEADER frame.",
		skip: "a server opens no stream toward a client, which disables push",
	},
	{
		id: "generic/3.4/1", name: "RST_STREAM",
		req: "The endpoint MUST accept RST_STREAM frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeRST(id, http2.ErrCodeCancel)
			p.wantReadCode(s, http2.ErrCodeCancel)
			p.wantAlive()
		},
	},
	{
		id: "generic/3.5/1", name: "SETTINGS",
		req: "The endpoint MUST accept SETTINGS frame.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100})
			p.wantSettingsAck()
		},
	},
	{
		id: "generic/3.7/1", name: "PING",
		req: "The endpoint MUST accept PING frame.",
		run: func(t *testing.T, p *peer) { p.wantAlive() },
	},
	{
		id: "generic/3.8/1", name: "GOAWAY",
		req: "The endpoint MUST accept GOAWAY frame.",
		run: func(t *testing.T, p *peer) {
			p.writeGoAway(0, http2.ErrCodeNo)
			p.wantGoAway(http2.ErrCodeNo)
			p.wantClosed()
			require.ErrorIs(t, p.c.Err(), ErrGoAway)
		},
	},
	{
		id: "generic/3.9/1", name: "WINDOW_UPDATE on the connection",
		req: "The endpoint MUST accept WINDOW_UPDATE frame.",
		run: func(t *testing.T, p *peer) {
			p.writeWindowUpdate(0, 1<<20)
			p.wantAlive()
		},
	},
	{
		id: "generic/3.9/2", name: "WINDOW_UPDATE on a stream",
		req: "The endpoint MUST accept WINDOW_UPDATE frame.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeWindowUpdate(id, 1<<20)
			p.wantAlive()
		},
	},
	{
		id: "generic/4/1", name: "a CONNECT answered, with DATA both ways",
		req: "The endpoint MUST respond to the request.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			_, err := s.Write([]byte("ping"))
			require.NoError(t, err)
			require.Equal(t, "ping", string(p.wantData(id).Data()))
			p.writeData(id, false, []byte("pong"))
			p.wantRead(s, []byte("pong"))
		},
	},
	{id: "generic/4/2", name: "a HEAD request", req: "The endpoint MUST respond to the request.", skip: "a client of CONNECT streams sends no other method"},
	{id: "generic/4/3", name: "a POST request", req: "The endpoint MUST respond to the request.", skip: "a client of CONNECT streams sends no other method"},
	{id: "generic/4/4", name: "a POST request with trailers", req: "The endpoint MUST respond to the request.", skip: "a client of CONNECT streams sends no other method"},
	{
		id: "generic/5/1", name: "an indexed field", req: "The endpoint MUST accept indexed header field representation",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, []byte{0x88}) },
	},
	{
		id: "generic/5/2", name: "a literal with incremental indexing, indexed name", req: "The endpoint MUST accept literal header field with incremental indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x48}, str("200"))) },
	},
	{
		id: "generic/5/3", name: "a literal with incremental indexing, indexed name, Huffman", req: "The endpoint MUST accept literal header field with incremental indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x48}, huff("200"))) },
	},
	{
		id: "generic/5/4", name: "a literal with incremental indexing, new name", req: "The endpoint MUST accept literal header field with incremental indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x40}, str(":status"), str("200"))) },
	},
	{
		id: "generic/5/5", name: "a literal with incremental indexing, new name, Huffman", req: "The endpoint MUST accept literal header field with incremental indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x40}, huff(":status"), huff("200"))) },
	},
	{
		id: "generic/5/6", name: "a literal without indexing, indexed name", req: "The endpoint MUST accept literal header field without indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x08}, str("200"))) },
	},
	{
		id: "generic/5/7", name: "a literal without indexing, indexed name, Huffman", req: "The endpoint MUST accept literal header field without indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x08}, huff("200"))) },
	},
	{
		id: "generic/5/8", name: "a literal without indexing, new name", req: "The endpoint MUST accept literal header field without indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x00}, str(":status"), str("200"))) },
	},
	{
		id: "generic/5/9", name: "a literal without indexing, new name, Huffman", req: "The endpoint MUST accept literal header field without indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x00}, huff(":status"), huff("200"))) },
	},
	{
		id: "generic/5/10", name: "a literal never indexed, indexed name", req: "The endpoint MUST accept literal header field never indexed",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x18}, str("200"))) },
	},
	{
		id: "generic/5/11", name: "a literal never indexed, indexed name, Huffman", req: "The endpoint MUST accept literal header field never indexed",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x18}, huff("200"))) },
	},
	{
		id: "generic/5/12", name: "a literal never indexed, new name", req: "The endpoint MUST accept literal header field never indexed",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x10}, str(":status"), str("200"))) },
	},
	{
		id: "generic/5/13", name: "a literal never indexed, new name, Huffman", req: "The endpoint MUST accept literal header field never indexed",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x10}, huff(":status"), huff("200"))) },
	},
	{
		id: "generic/5/14", name: "a dynamic table size update", req: "The endpoint MUST accept dynamic table size update",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, []byte{0x20, 0x88}) },
	},
	{
		id: "generic/5/15", name: "several dynamic table size updates", req: "The endpoint MUST accept multiple dynamic table size update",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, []byte{0x20, 0x3f, 0xe1, 0x1f, 0x88}) },
	},

	// RFC 9113 section 3, starting HTTP/2.
	{
		id: "http2/3.5/1", name: "the peer's first frame is not SETTINGS",
		req: "The server connection preface consists of a potentially empty SETTINGS frame that MUST be the first frame the server sends in the HTTP/2 connection. Clients and servers MUST treat an invalid connection preface as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p = dialPeer(t)
			p.writePing(false, [8]byte{})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/3.5/2", name: "the peer is not HTTP/2",
		req: "The endpoint MUST terminate the TCP connection.",
		run: func(t *testing.T, p *peer) {
			p = dialPeer(t)
			o := p.open(Request{Authority: "origin.test:443"})
			_, err := p.nc.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
			require.NoError(t, err)
			p.wantClosed()
			_, _, err = o.wait(t)
			require.Error(t, err)
			require.NotErrorIs(t, err, context.DeadlineExceeded, "Open waited out its context on a peer that is not HTTP/2")
		},
	},

	// RFC 9113 section 4, frames.
	{
		id: "http2/4.1/1", name: "a frame of an unknown type",
		req: "Implementations MUST ignore and discard frames of unknown types.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(0xee, 0, 0, []byte{1, 2, 3})
			p.wantAlive()
		},
	},
	{
		id: "http2/4.1/2", name: "a frame with undefined flags",
		req: "Flags that have no defined semantics for a particular frame type MUST be ignored and MUST be left unset (0x00) when sending.",
		run: func(t *testing.T, p *peer) {
			data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
			p.writeRaw(http2.FramePing, 0xfe, 0, data[:])
			p.wantPingAck(data)
		},
	},
	{
		id: "http2/4.1/3", name: "a frame with the reserved bit set",
		req: "The semantics of this bit are undefined, and the bit MUST remain unset (0x00) when sending and MUST be ignored when receiving.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameSettings, 0, 1<<31, nil)
			p.wantSettingsAck()
		},
	},
	{
		id: "http2/4.2/1", name: "a DATA frame of 2^14 octets",
		req: "All implementations MUST be capable of receiving and minimally processing frames up to 2^14 octets in length.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, false, bytes.Repeat([]byte{7}, 1<<14))
			require.Equal(t, bytes.Repeat([]byte{7}, 1<<14), p.wantReadAll(s, 1<<14))
		},
	},
	{
		id: "http2/4.2/2", name: "a DATA frame past SETTINGS_MAX_FRAME_SIZE",
		req: "An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame exceeds the size defined in SETTINGS_MAX_FRAME_SIZE.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeData(id, false, make([]byte, 1<<14+1))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},
	{
		id: "http2/4.2/3", name: "a HEADERS frame past SETTINGS_MAX_FRAME_SIZE",
		req: "A frame size error in a frame that could alter the state of the entire connection MUST be treated as a connection error; this includes any frame carrying a field block.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeBlock(id, false, bigBlock(p))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},
	{
		id: "http2/4.3/1", name: "an invalid header block",
		req: "A decoding error in a field block MUST be treated as a connection error of type COMPRESSION_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeBlock(id, false, []byte{0xff, 0xff, 0xff, 0xff, 0xff})
			p.wantConnectionError(http2.ErrCodeCompression)
		},
	},
	{
		id: "http2/4.3/2", name: "PRIORITY in the middle of a header block",
		req: "Each field block is processed as a discrete unit. Field blocks MUST be transmitted as a contiguous sequence of frames, with no interleaved frames of any other type or from any other stream.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			p.writePriority(id, http2.PriorityParam{Weight: 15})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/4.3/3", name: "HEADERS on another stream in the middle of a header block",
		req: "Field blocks MUST be transmitted as a contiguous sequence of frames, with no interleaved frames of any other type or from any other stream.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.open(Request{Authority: "origin.test:443"})
			id2 := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			p.writeBlock(id2, false, block)
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},

	// RFC 9113 section 5, streams.
	{
		id: "http2/5.1.1/1", name: "HEADERS on an even stream id",
		req: "Streams initiated by a client MUST use odd-numbered stream identifiers. An endpoint that receives an unexpected stream identifier MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.connect()
			p.writeHeaders(2, false, status("200"))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/5.1.1/2", name: "a stream id below the previous one",
		req:  "The endpoint MUST respond with a connection error of type PROTOCOL_ERROR.",
		skip: "the order of new stream ids is a rule on the endpoint that opens streams, and a server opens none toward a client that disables push",
	},
	{
		id: "http2/5.1.2/1", name: "the client at the peer's concurrent stream limit",
		req: "Endpoints MUST NOT exceed the limit set by their peer.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1})
			p.wantSettingsAck()
			s, _ := p.connect()
			require.Eventually(t, func() bool { return !p.c.CanOpen() }, wantTimeout, time.Millisecond)
			_, _, err := p.open(Request{Authority: "origin.test:443"}).wait(t)
			require.ErrorIs(t, err, ErrStreamLimit)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS past the stream limit")
			require.NoError(t, s.Close())
			p.connect()
		},
	},
	{
		id: "http2/5.1/1", name: "DATA on an idle stream",
		req: "Receiving any frame other than HEADERS or PRIORITY on a stream in this state MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeData(101, false, []byte("x"))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/5.1/2", name: "RST_STREAM on an idle stream",
		req: "Receiving any frame other than HEADERS or PRIORITY on a stream in this state MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRST(101, http2.ErrCodeCancel)
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/5.1/3", name: "WINDOW_UPDATE on an idle stream",
		req: "Receiving any frame other than HEADERS or PRIORITY on a stream in this state MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeWindowUpdate(101, 1)
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/5.1/4", name: "CONTINUATION on an idle stream",
		req: "Receiving any frame other than HEADERS or PRIORITY on a stream in this state MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			require.NoError(t, p.fr.WriteContinuation(101, true, p.block(status("200"))))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/5.1/5", name: "DATA after the peer's END_STREAM",
		req: "If an endpoint receives additional frames, except for WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a stream that is in this state, it MUST respond with a stream error of type STREAM_CLOSED.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writeData(id, false, []byte("late"))
			p.wantStreamError(id, http2.ErrCodeStreamClosed)
		},
	},
	{
		id: "http2/5.1/6", name: "HEADERS after the peer's END_STREAM",
		req: "If an endpoint receives additional frames, except for WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a stream that is in this state, it MUST respond with a stream error of type STREAM_CLOSED.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writeHeaders(id, true, hpack.HeaderField{Name: "x-late", Value: "1"})
			p.wantStreamError(id, http2.ErrCodeStreamClosed)
		},
	},
	{
		id: "http2/5.1/7", name: "HEADERS and CONTINUATION after the peer's END_STREAM",
		req: "If an endpoint receives additional frames, except for WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a stream that is in this state, it MUST respond with a stream error of type STREAM_CLOSED.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			block := p.block(hpack.HeaderField{Name: "x-late", Value: "1"})
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1], EndStream: true}))
			require.NoError(t, p.fr.WriteContinuation(id, true, block[1:]))
			p.wantStreamError(id, http2.ErrCodeStreamClosed)
		},
	},
	{
		id: "http2/5.1/8", name: "DATA after the client's RST_STREAM",
		req: "An endpoint MUST ignore frames that it receives on closed streams after it has sent a RST_STREAM frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, s.Close())
			p.wantRST(id, http2.ErrCodeCancel)
			p.writeData(id, false, []byte("late"))
			p.wantAlive()
		},
	},
	{
		id: "http2/5.1/9", name: "HEADERS after the client's RST_STREAM",
		req: "An endpoint MUST ignore frames that it receives on closed streams after it has sent a RST_STREAM frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, s.Close())
			p.wantRST(id, http2.ErrCodeCancel)
			p.writeHeaders(id, true, hpack.HeaderField{Name: "x-late", Value: "1"})
			p.wantAlive()
		},
	},
	{
		id: "http2/5.1/10", name: "HEADERS and CONTINUATION after the client's RST_STREAM",
		req: "An endpoint MUST ignore frames that it receives on closed streams after it has sent a RST_STREAM frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, s.Close())
			p.wantRST(id, http2.ErrCodeCancel)
			block := p.block(hpack.HeaderField{Name: "x-late", Value: "1"})
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1], EndStream: true}))
			require.NoError(t, p.fr.WriteContinuation(id, true, block[1:]))
			p.wantAlive()
		},
	},
	{
		id: "http2/5.1/11", name: "DATA on a stream that ended in both directions",
		req: "An endpoint MAY treat receipt of any other type of frame on a closed stream as a connection error of type STREAM_CLOSED. The client ignores the frame and credits its DATA back, as Go's transport does.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			ended(t, p, s, id)
			p.writeData(id, false, []byte("late"))
			var credited uint32
			for credited < 4 {
				credited += p.wantWindowUpdate(0)
			}
			p.wantAlive()
		},
	},
	{
		id: "http2/5.1/12", name: "HEADERS on a stream that ended in both directions",
		req: "An endpoint MAY treat receipt of any other type of frame on a closed stream as a connection error of type STREAM_CLOSED. The client ignores the frame, as Go's transport does.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			ended(t, p, s, id)
			p.writeHeaders(id, true, hpack.HeaderField{Name: "x-late", Value: "1"})
			p.wantAlive()
		},
	},
	{
		id: "http2/5.1/13", name: "CONTINUATION on a stream that ended in both directions",
		req: "An endpoint MAY treat receipt of any other type of frame on a closed stream as a connection error of type STREAM_CLOSED. The client ignores the frame, as Go's transport does.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			ended(t, p, s, id)
			block := p.block(hpack.HeaderField{Name: "x-late", Value: "1"})
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1], EndStream: true}))
			require.NoError(t, p.fr.WriteContinuation(id, true, block[1:]))
			p.wantAlive()
		},
	},
	{
		id: "http2/5.3.1/1", name: "HEADERS depending on its own stream",
		req: "A stream cannot depend on itself. An endpoint MUST treat this as a stream error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: id, BlockFragment: p.block(status("200")), EndHeaders: true,
				Priority: http2.PriorityParam{StreamDep: id, Weight: 15},
			}))
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/5.3.1/2", name: "PRIORITY depending on its own stream",
		req: "A stream cannot depend on itself. An endpoint MUST treat this as a stream error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writePriority(id, http2.PriorityParam{StreamDep: id, Weight: 15})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/5.4.1/1", name: "a PING of the wrong length",
		req: "An endpoint that encounters a connection error SHOULD first send a GOAWAY frame with the stream identifier of the last stream that it successfully received from its peer. After sending the GOAWAY frame for an error condition, the endpoint MUST close the TCP connection.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FramePing, 0, 0, make([]byte, 7))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},
	{
		id: "http2/5.4.1/2", name: "the GOAWAY of a connection error names the last stream",
		req: "An endpoint that encounters a connection error SHOULD first send a GOAWAY frame with the stream identifier of the last stream that it successfully received from its peer.",
		run: func(t *testing.T, p *peer) {
			p.connect()
			p.writeRaw(http2.FramePing, 0, 0, make([]byte, 7))
			f := p.wantGoAway(http2.ErrCodeFrameSize)
			require.Equal(t, uint32(0), f.LastStreamID, "a client received no stream from its peer")
			p.wantClosed()
		},
	},
	{
		id: "http2/5.5/1", name: "an extension frame on a stream",
		req: "Implementations MUST ignore unknown or unsupported values in all extensible protocol elements.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeRaw(0xee, 0, id, []byte{1, 2, 3})
			p.wantAlive()
		},
	},
	{
		id: "http2/5.5/2", name: "an extension frame in the middle of a header block",
		req: "Extension frames that appear in the middle of a field block are not permitted; these MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			p.writeRaw(0xee, 0, id, []byte{1, 2, 3})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},

	// RFC 9113 section 6, frame definitions.
	{
		id: "http2/6.10/1", name: "HEADERS and several CONTINUATIONs",
		req: "Any number of CONTINUATION frames can be sent, as long as the preceding frame is on the same stream and is a HEADERS, PUSH_PROMISE, or CONTINUATION frame without the END_HEADERS flag set.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: nil}))
			require.NoError(t, p.fr.WriteContinuation(id, false, block[:1]))
			require.NoError(t, p.fr.WriteContinuation(id, false, nil))
			require.NoError(t, p.fr.WriteContinuation(id, true, block[1:]))
			_, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		},
	},
	{
		id: "http2/6.10/2", name: "another frame before END_HEADERS",
		req: "A receiver MUST treat the receipt of any other type of frame or a frame on a different stream as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			require.NoError(t, p.fr.WriteContinuation(id, false, nil))
			p.writeData(id, false, []byte("x"))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.10/3", name: "CONTINUATION on stream 0",
		req: "If a CONTINUATION frame is received with a Stream Identifier field of 0x00, the recipient MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			p.writeRaw(http2.FrameContinuation, http2.FlagContinuationEndHeaders, 0, block[1:])
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.10/4", name: "CONTINUATION after HEADERS with END_HEADERS",
		req: "A CONTINUATION frame MUST be preceded by a HEADERS, PUSH_PROMISE or CONTINUATION frame without the END_HEADERS flag set. A recipient that observes violation of this rule MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.answer(id)
			require.NoError(t, p.fr.WriteContinuation(id, true, p.block(hpack.HeaderField{Name: "x-a", Value: "1"})))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.10/5", name: "CONTINUATION after CONTINUATION with END_HEADERS",
		req: "A CONTINUATION frame MUST be preceded by a HEADERS, PUSH_PROMISE or CONTINUATION frame without the END_HEADERS flag set. A recipient that observes violation of this rule MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			require.NoError(t, p.fr.WriteContinuation(id, true, block[1:]))
			require.NoError(t, p.fr.WriteContinuation(id, true, p.block(hpack.HeaderField{Name: "x-a", Value: "1"})))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.10/6", name: "CONTINUATION after DATA",
		req: "A CONTINUATION frame MUST be preceded by a HEADERS, PUSH_PROMISE or CONTINUATION frame without the END_HEADERS flag set. A recipient that observes violation of this rule MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, false, []byte("x"))
			p.wantRead(s, []byte("x"))
			require.NoError(t, p.fr.WriteContinuation(id, true, p.block(hpack.HeaderField{Name: "x-a", Value: "1"})))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.1/1", name: "DATA on stream 0",
		req: "If a DATA frame is received whose Stream Identifier field is 0x00, the recipient MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameData, 0, 0, []byte("x"))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.1/2", name: "DATA on a stream the peer ended",
		req: "If a DATA frame is received whose stream is not in the \"open\" or \"half-closed (local)\" state, the recipient MUST respond with a stream error of type STREAM_CLOSED.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writeData(id, false, []byte("late"))
			p.wantStreamError(id, http2.ErrCodeStreamClosed)
		},
	},
	{
		id: "http2/6.1/3", name: "DATA with a pad length past its payload",
		req: "If the length of the padding is the length of the frame payload or greater, the recipient MUST treat this as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeRaw(http2.FrameData, http2.FlagDataPadded, id, []byte{10, 'a', 'b'})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.2/1", name: "HEADERS without END_HEADERS, then PRIORITY",
		req: "A HEADERS frame without the END_HEADERS flag set MUST be followed by a CONTINUATION frame for the same stream. A receiver MUST treat the receipt of any other type of frame or a frame on a different stream as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: p.block(status("200"))[:1]}))
			p.writePriority(id, http2.PriorityParam{Weight: 15})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.2/2", name: "HEADERS on another stream before END_HEADERS",
		req: "A HEADERS frame without the END_HEADERS flag set MUST be followed by a CONTINUATION frame for the same stream. A receiver MUST treat the receipt of any other type of frame or a frame on a different stream as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.open(Request{Authority: "origin.test:443"})
			id2 := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			p.writeBlock(id2, false, block)
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.2/3", name: "HEADERS on stream 0",
		req: "If a HEADERS frame is received whose Stream Identifier field is 0x00, the recipient MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameHeaders, http2.FlagHeadersEndHeaders, 0, p.block(status("200")))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.2/4", name: "HEADERS with a pad length past its payload",
		req:  "Padding that exceeds the size remaining for the field block fragment MUST be treated as a PROTOCOL_ERROR.",
		skip: "the framer of x/net makes it a stream error on the stream, as Go's own server and transport do, before the client sees the frame",
	},
	{
		id: "http2/6.3/1", name: "PRIORITY on stream 0",
		req: "If a PRIORITY frame is received with a stream identifier of 0x00, the recipient MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FramePriority, 0, 0, make([]byte, 5))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.3/2", name: "PRIORITY of a length other than 5",
		req:  "A PRIORITY frame with a length other than 5 octets MUST be treated as a stream error of type FRAME_SIZE_ERROR.",
		skip: "the framer of x/net makes it a connection error of type FRAME_SIZE_ERROR, as Go's own server and transport do, before the client sees the frame",
	},
	{
		id: "http2/6.4/1", name: "RST_STREAM on stream 0",
		req: "If a RST_STREAM frame is received with a stream identifier of 0x0, the recipient MUST treat this as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameRSTStream, 0, 0, make([]byte, 4))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.4/2", name: "RST_STREAM on an idle stream",
		req: "RST_STREAM frames MUST NOT be sent for a stream in the \"idle\" state. If a RST_STREAM frame identifying an idle stream is received, the recipient MUST treat this as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.connect()
			p.writeRST(p.nextID, http2.ErrCodeCancel)
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.4/3", name: "RST_STREAM of a length other than 4",
		req: "A RST_STREAM frame with a length other than 4 octets MUST be treated as a connection error of type FRAME_SIZE_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeRaw(http2.FrameRSTStream, 0, id, make([]byte, 3))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},
	{
		id: "http2/6.5.2/1", name: "SETTINGS_ENABLE_PUSH of 2",
		req: "Any value other than 0 or 1 MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingEnablePush, Val: 2})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.5.2/2", name: "SETTINGS_INITIAL_WINDOW_SIZE past 2^31-1",
		req: "Values above the maximum flow-control window size of 2^31-1 MUST be treated as a connection error of type FLOW_CONTROL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 31})
			p.wantConnectionError(http2.ErrCodeFlowControl)
		},
	},
	{
		id: "http2/6.5.2/3", name: "SETTINGS_MAX_FRAME_SIZE below 2^14",
		req: "The initial value is 2^14 (16,384) octets. The value advertised by an endpoint MUST be between this initial value and the maximum allowed frame size (2^24-1 or 16,777,215 octets), inclusive. Values outside this range MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16383})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.5.2/4", name: "SETTINGS_MAX_FRAME_SIZE past 2^24-1",
		req: "Values outside this range MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 1 << 24})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.5.2/5", name: "a SETTINGS parameter of an unknown identifier",
		req: "An endpoint that receives a SETTINGS frame with any unknown or unsupported identifier MUST ignore that setting.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: 0xff, Val: 1})
			p.wantSettingsAck()
			p.wantAlive()
		},
	},
	{
		id: "http2/6.5.3/1", name: "SETTINGS_INITIAL_WINDOW_SIZE twice in one frame",
		req: "The values in the SETTINGS frame MUST be processed in the order they appear, with no other frame processing between values.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 100})
			p.wantSettingsAck()
			s, id := p.connect()
			go func() { _, _ = s.Write(make([]byte, 150)) }()
			require.Len(t, p.wantData(id).Data(), 100)
			wantNothing[*http2.DataFrame](p, "DATA past the send window")
		},
	},
	{
		id: "http2/6.5.3/2", name: "SETTINGS is acknowledged",
		req: "Once all values have been processed, the recipient MUST immediately emit a SETTINGS frame with the ACK flag set.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100})
			p.wantSettingsAck()
		},
	},
	{
		id: "http2/6.5/1", name: "a SETTINGS ack with a payload",
		req: "Receipt of a SETTINGS frame with the ACK flag set and a length field value other than 0 MUST be treated as a connection error of type FRAME_SIZE_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameSettings, http2.FlagSettingsAck, 0, make([]byte, 6))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},
	{
		id: "http2/6.5/2", name: "SETTINGS on a stream",
		req: "If an endpoint receives a SETTINGS frame whose Stream Identifier field is anything other than 0x00, the endpoint MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameSettings, 0, 1, nil)
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.5/3", name: "SETTINGS of a length not a multiple of 6",
		req: "A SETTINGS frame with a length other than a multiple of 6 octets MUST be treated as a connection error of type FRAME_SIZE_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameSettings, 0, 0, make([]byte, 5))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},
	{
		id: "http2/6.7/1", name: "PING",
		req: "Receivers of a PING frame that does not include an ACK flag MUST send a PING frame with the ACK flag set in response, with an identical frame payload.",
		run: func(t *testing.T, p *peer) { p.wantAlive() },
	},
	{
		id: "http2/6.7/2", name: "a PING ack",
		req: "An endpoint MUST NOT respond to PING frames containing this flag.",
		run: func(t *testing.T, p *peer) {
			p.writePing(true, [8]byte{1})
			wantNothing[*http2.PingFrame](p, "an answer to a PING ack")
		},
	},
	{
		id: "http2/6.7/3", name: "PING on a stream",
		req: "If a PING frame is received with a Stream Identifier field value other than 0x00, the recipient MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeRaw(http2.FramePing, 0, id, make([]byte, 8))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.7/4", name: "PING of a length other than 8",
		req: "Receipt of a PING frame with a length field value other than 8 MUST be treated as a connection error of type FRAME_SIZE_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FramePing, 0, 0, make([]byte, 9))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},
	{
		id: "http2/6.8/1", name: "GOAWAY on a stream",
		req: "An endpoint MUST treat a GOAWAY frame with a stream identifier other than 0x00 as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeRaw(http2.FrameGoAway, 0, id, make([]byte, 8))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.9.1/1", name: "a send window of 1",
		req: "The sender MUST NOT send a flow-controlled frame with a length that exceeds the space available in either of the flow-control windows advertised by the receiver.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1})
			p.wantSettingsAck()
			s, id := p.connect()
			wrote := make(chan error, 1)
			go func() { _, err := s.Write(make([]byte, 10)); wrote <- err }()
			require.Len(t, p.wantData(id).Data(), 1)
			wantNothing[*http2.DataFrame](p, "DATA past the send window")
			p.writeWindowUpdate(id, 9)
			for got := 1; got < 10; {
				got += len(p.wantData(id).Data())
			}
			require.NoError(t, <-wrote)
		},
	},
	{
		id: "http2/6.9.1/2", name: "WINDOW_UPDATE past 2^31-1 on the connection",
		req: "If a sender receives a WINDOW_UPDATE that causes a flow-control window to exceed this maximum, it MUST terminate either the stream or the connection, as appropriate. For streams, the sender sends a RST_STREAM with an error code of FLOW_CONTROL_ERROR; for the connection, a GOAWAY frame with an error code of FLOW_CONTROL_ERROR is sent.",
		run: func(t *testing.T, p *peer) {
			p.writeWindowUpdate(0, 1<<31-1)
			p.wantConnectionError(http2.ErrCodeFlowControl)
		},
	},
	{
		id: "http2/6.9.1/3", name: "WINDOW_UPDATE past 2^31-1 on a stream",
		req: "For streams, the sender sends a RST_STREAM with an error code of FLOW_CONTROL_ERROR.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeWindowUpdate(id, 1<<31-1)
			p.wantStreamError(id, http2.ErrCodeFlowControl)
			p.wantReadCode(s, http2.ErrCodeFlowControl)
		},
	},
	{
		id: "http2/6.9.2/1", name: "SETTINGS_INITIAL_WINDOW_SIZE changed under an open stream",
		req: "When the value of SETTINGS_INITIAL_WINDOW_SIZE changes, a receiver MUST adjust the size of all stream flow-control windows that it maintains by the difference between the new value and the old value.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0})
			p.wantSettingsAck()
			s, id := p.connect()
			go func() { _, _ = s.Write(make([]byte, 5)) }()
			wantNothing[*http2.DataFrame](p, "DATA on a window of 0")
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 5})
			p.wantSettingsAck()
			require.Len(t, p.wantData(id).Data(), 5)
		},
	},
	{
		id: "http2/6.9.2/2", name: "SETTINGS_INITIAL_WINDOW_SIZE driving a send window negative",
		req: "A change to SETTINGS_INITIAL_WINDOW_SIZE can cause the available space in a flow-control window to become negative. A sender MUST track the negative flow-control window and MUST NOT send new flow-controlled frames until it receives WINDOW_UPDATE frames that cause the flow-control window to become positive.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 10})
			p.wantSettingsAck()
			s, id := p.connect()
			_, err := s.Write(make([]byte, 10))
			require.NoError(t, err)
			require.Len(t, p.wantData(id).Data(), 10)
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 5})
			p.wantSettingsAck()
			go func() { _, _ = s.Write(make([]byte, 3)) }()
			p.writeWindowUpdate(id, 5)
			wantNothing[*http2.DataFrame](p, "DATA on a window of 0")
			p.writeWindowUpdate(id, 3)
			require.Len(t, p.wantData(id).Data(), 3)
		},
	},
	{
		id: "http2/6.9.2/3", name: "SETTINGS_INITIAL_WINDOW_SIZE past 2^31-1",
		req: "An endpoint MUST treat a change to SETTINGS_INITIAL_WINDOW_SIZE that causes any flow-control window to exceed the maximum size as a connection error of type FLOW_CONTROL_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeWindowUpdate(id, 1<<30)
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 30})
			p.wantConnectionError(http2.ErrCodeFlowControl)
		},
	},
	{
		id: "http2/6.9/1", name: "WINDOW_UPDATE of 0 on the connection",
		req: "A receiver MUST treat the receipt of a WINDOW_UPDATE frame with a flow-control window increment of 0 as a stream error of type PROTOCOL_ERROR; errors on the connection flow-control window MUST be treated as a connection error.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameWindowUpdate, 0, 0, make([]byte, 4))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.9/2", name: "WINDOW_UPDATE of 0 on a stream",
		req: "A receiver MUST treat the receipt of a WINDOW_UPDATE frame with a flow-control window increment of 0 as a stream error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeRaw(http2.FrameWindowUpdate, 0, id, make([]byte, 4))
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.9/3", name: "WINDOW_UPDATE of a length other than 4",
		req: "A WINDOW_UPDATE frame with a length other than 4 octets MUST be treated as a connection error of type FRAME_SIZE_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameWindowUpdate, 0, 0, make([]byte, 5))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},

	// RFC 9113 section 7, error codes.
	{
		id: "http2/7/1", name: "GOAWAY with an unknown error code",
		req: "Unknown or unsupported error codes MUST NOT trigger any special behavior. These MAY be treated by an implementation as being equivalent to INTERNAL_ERROR.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeGoAway(id, 0xff)
			p.wantClosed()
			_, err := p.read(s)
			require.Error(t, err)
			require.False(t, errors.Is(err, os.ErrDeadlineExceeded))
		},
	},
	{
		id: "http2/7/2", name: "RST_STREAM with an unknown error code",
		req: "Unknown or unsupported error codes MUST NOT trigger any special behavior.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeRST(id, 0xff)
			p.wantReadCode(s, 0xff)
			p.wantAlive()
		},
	},

	// RFC 9113 section 8, HTTP semantics.
	{
		id: "http2/8.1.2.1/1", name: "an unknown pseudo-header in the answer",
		req: "Endpoints MUST NOT generate pseudo-header fields other than those defined in this document. Endpoints MUST treat a request or response that contains undefined or invalid pseudo-header fields as malformed.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("200"), hpack.HeaderField{Name: ":foo", Value: "1"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.1.2.1/2", name: "a request pseudo-header in the answer",
		req: "Pseudo-header fields defined for requests MUST NOT appear in responses; pseudo-header fields defined for responses MUST NOT appear in requests.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("200"), hpack.HeaderField{Name: ":method", Value: "GET"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.1.2.1/3", name: "a pseudo-header in trailers",
		req: "Pseudo-header fields MUST NOT appear in a trailer section.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("404"))
			s, _, err := o.wait(t)
			require.NoError(t, err)
			p.writeHeaders(id, true, status("200"))
			p.wantStreamError(id, http2.ErrCodeProtocol)
			p.wantReadCode(s, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.1.2.1/4", name: "a pseudo-header after a regular field",
		req: "All pseudo-header fields MUST appear in a field block before all regular field lines. Any request or response that contains a pseudo-header field that appears in a field block after a regular field line MUST be treated as malformed.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, hpack.HeaderField{Name: "x-a", Value: "1"}, status("200"))
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.1.2.2/1", name: "a connection-specific field in the answer",
		req: "An endpoint MUST NOT generate an HTTP/2 message containing connection-specific header fields. Any message containing connection-specific header fields MUST be treated as malformed.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("200"), hpack.HeaderField{Name: "connection", Value: "close"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.1.2.2/2", name: "a TE other than trailers in the answer",
		req: "The only exception to this is the TE header field, which MAY be present in an HTTP/2 request; when it is, it MUST NOT contain any value other than \"trailers\".",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("200"), hpack.HeaderField{Name: "te", Value: "gzip"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.1.2.3/1", name: "an extended CONNECT with an empty :path",
		req: "This pseudo-header field MUST NOT be empty for \"http\" or \"https\" URIs.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
			p.wantSettingsAck()
			_, _, err := p.open(Request{Authority: "proxy.test", Protocol: "connect-udp", Scheme: "https"}).wait(t)
			require.ErrorIs(t, err, errNoTarget)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS of a refused request")
		},
	},
	{id: "http2/8.1.2.3/2", name: "a request without :method", req: "All HTTP/2 requests MUST include exactly one valid value for the :method, :scheme, and :path pseudo-header fields, unless they are CONNECT requests.", skip: "a rule on the requests a server receives, the client's own request is checked under rfc9113/8.5"},
	{id: "http2/8.1.2.3/3", name: "a request without :scheme", req: "All HTTP/2 requests MUST include exactly one valid value for the :method, :scheme, and :path pseudo-header fields, unless they are CONNECT requests.", skip: "a rule on the requests a server receives, the client's own request is checked under rfc9113/8.5"},
	{id: "http2/8.1.2.3/4", name: "a request without :path", req: "All HTTP/2 requests MUST include exactly one valid value for the :method, :scheme, and :path pseudo-header fields, unless they are CONNECT requests.", skip: "a rule on the requests a server receives, the client's own request is checked under rfc9113/8.5"},
	{id: "http2/8.1.2.3/5", name: "a request with two :method", req: "All HTTP/2 requests MUST include exactly one valid value for the :method, :scheme, and :path pseudo-header fields, unless they are CONNECT requests.", skip: "a rule on the requests a server receives, the client's own request is checked under rfc9113/8.5"},
	{id: "http2/8.1.2.3/6", name: "a request with two :scheme", req: "All HTTP/2 requests MUST include exactly one valid value for the :method, :scheme, and :path pseudo-header fields, unless they are CONNECT requests.", skip: "a rule on the requests a server receives, the client's own request is checked under rfc9113/8.5"},
	{id: "http2/8.1.2.3/7", name: "a request with two :path", req: "All HTTP/2 requests MUST include exactly one valid value for the :method, :scheme, and :path pseudo-header fields, unless they are CONNECT requests.", skip: "a rule on the requests a server receives, the client's own request is checked under rfc9113/8.5"},
	{id: "http2/8.1.2.6/1", name: "content-length against one DATA frame", req: "A request or response that is defined as having content is malformed if the value of a content-length header field does not equal the sum of the DATA frame payload lengths.", skip: "a CONNECT tunnel has no content, and a client MUST ignore a content-length in a 2xx answer to CONNECT, RFC 9110 section 9.3.6"},
	{id: "http2/8.1.2.6/2", name: "content-length against several DATA frames", req: "A request or response that is defined as having content is malformed if the value of a content-length header field does not equal the sum of the DATA frame payload lengths.", skip: "a CONNECT tunnel has no content, and a client MUST ignore a content-length in a 2xx answer to CONNECT, RFC 9110 section 9.3.6"},
	{
		id: "http2/8.1.2/1", name: "an uppercase field name in the answer",
		req: "A field name MUST NOT contain characters in the ranges 0x00-0x20, 0x41-0x5a, or 0x7f-0xff. A request or response containing uppercase characters in field names MUST be treated as malformed.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("200"), hpack.HeaderField{Name: "X-A", Value: "1"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.1/1", name: "a second HEADERS without END_STREAM",
		req: "A HEADERS frame with the END_STREAM flag set that carries an informational status code is malformed. Trailers ... consist of a HEADERS frame with the END_STREAM flag set. An endpoint that receives a HEADERS frame without the END_STREAM flag set after receiving the HEADERS frame that opens a request or after receiving a final (non-informational) status code MUST treat the corresponding request or response as malformed.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("404"))
			_, _, err := o.wait(t)
			require.NoError(t, err)
			p.writeHeaders(id, false, hpack.HeaderField{Name: "x-a", Value: "1"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.2/1", name: "PUSH_PROMISE",
		req: "PUSH_PROMISE MUST NOT be sent if the SETTINGS_ENABLE_PUSH setting of the peer endpoint is set to 0. An endpoint that has set this setting and has received acknowledgment MUST treat the receipt of a PUSH_PROMISE frame as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeRaw(http2.FramePushPromise, http2.FlagPushPromiseEndHeaders, id, cat([]byte{0, 0, 0, 2}, p.block(hpack.HeaderField{Name: ":method", Value: "GET"})))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},

	// h2spec hpack, RFC 7541: decoding errors end the connection with COMPRESSION_ERROR,
	// RFC 9113 section 4.3.
	{
		id: "hpack/2.3.3/1", name: "an indexed field past the tables",
		req: "Indices ... MUST be treated as a decoding error.",
		run: func(t *testing.T, p *peer) { wantCompressionError(t, p, []byte{0xff, 0x01}) },
	},
	{
		id: "hpack/2.3.3/2", name: "a literal whose name index is past the tables",
		req: "Indices ... MUST be treated as a decoding error.",
		run: func(t *testing.T, p *peer) { wantCompressionError(t, p, cat([]byte{0x7f, 0x01}, str("200"))) },
	},
	{
		id: "hpack/4.2/1", name: "a dynamic table size update at the end of the block",
		req: "This dynamic table size update MUST occur at the beginning of the first header block following the change to the dynamic table size.",
		run: func(t *testing.T, p *peer) {
			wantAnswerBlock(t, p, cat([]byte{0x88, 0x40}, str("x-a"), str("1")))
			wantCompressionError(t, p, []byte{0x88, 0x20})
		},
	},
	{
		id: "hpack/5.2/1", name: "a Huffman string padded by more than 7 bits",
		req: "A padding strictly longer than 7 bits MUST be treated as a decoding error.",
		run: func(t *testing.T, p *peer) {
			b := hpack.AppendHuffmanString(nil, "200")
			wantCompressionError(t, p, cat([]byte{0x08, 0x80 | byte(len(b)+1)}, b, []byte{0xff}))
		},
	},
	{
		id: "hpack/5.2/2", name: "a Huffman string padded with zeros",
		req: "A padding not corresponding to the most significant bits of the code for the EOS symbol MUST be treated as a decoding error.",
		run: func(t *testing.T, p *peer) { wantCompressionError(t, p, []byte{0x08, 0x81, 0x10}) },
	},
	{
		id: "hpack/5.2/3", name: "a Huffman string holding the EOS symbol",
		req: "A Huffman-encoded string literal containing the EOS symbol MUST be treated as a decoding error.",
		run: func(t *testing.T, p *peer) { wantCompressionError(t, p, []byte{0x08, 0x84, 0xff, 0xff, 0xff, 0xff}) },
	},
	{
		id: "hpack/6.1/1", name: "an indexed field of index 0",
		req: "The index value of 0 is not used. It MUST be treated as a decoding error if found in an indexed header field representation.",
		run: func(t *testing.T, p *peer) { wantCompressionError(t, p, []byte{0x80}) },
	},
	{
		id: "hpack/6.3/1", name: "a dynamic table size update past SETTINGS_HEADER_TABLE_SIZE",
		req: "The new maximum size MUST be lower than or equal to the limit determined by the protocol using HPACK. A value that exceeds this limit MUST be treated as a decoding error.",
		run: func(t *testing.T, p *peer) { wantCompressionError(t, p, []byte{0x3f, 0xe1, 0x3f, 0x88}) },
	},

	// RFC 8441, extended CONNECT.
	{
		id: "rfc8441/3/1", name: "SETTINGS_ENABLE_CONNECT_PROTOCOL of 2",
		req: "Upon receipt of SETTINGS_ENABLE_CONNECT_PROTOCOL with a value of 1, a client MAY use the Extended CONNECT ... Any value other than 0 or 1 MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 2})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc8441/3/2", name: "SETTINGS_ENABLE_CONNECT_PROTOCOL from 1 back to 0",
		req: "A sender MUST NOT send a SETTINGS_ENABLE_CONNECT_PROTOCOL parameter with the value of 0 after previously sending a value of 1.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
			p.wantSettingsAck()
			p.writeSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 0})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc8441/4/1", name: "an extended CONNECT before the setting",
		req: "A client MUST NOT send the extended CONNECT method to a server that has not advertised support.",
		run: func(t *testing.T, p *peer) {
			_, _, err := p.open(Request{Authority: "proxy.test", Protocol: "connect-udp", Scheme: "https", Path: "/.well-known/masque/udp/h/1/"}).wait(t)
			require.ErrorIs(t, err, ErrExtendedConnect)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS of an extended CONNECT the peer did not enable")
		},
	},
	{
		id: "rfc8441/4/2", name: "the pseudo-headers of an extended CONNECT",
		req: "A new pseudo-header field :protocol MAY be included on request HEADERS indicating the desired protocol of the tunnel created by CONNECT. On requests that contain the :protocol pseudo-header field, the :scheme and :path pseudo-header fields of the target URI MUST also be included. The :authority pseudo-header field contains the host and port to connect to.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
			p.wantSettingsAck()
			p.open(Request{Authority: "proxy.test", Protocol: "connect-udp", Scheme: "https", Path: "/.well-known/masque/udp/h/1/"})
			f := p.wantHeaders()
			require.Equal(t, "CONNECT", f.PseudoValue("method"))
			require.Equal(t, "connect-udp", f.PseudoValue("protocol"))
			require.Equal(t, "https", f.PseudoValue("scheme"))
			require.Equal(t, "/.well-known/masque/udp/h/1/", f.PseudoValue("path"))
			require.Equal(t, "proxy.test", f.PseudoValue("authority"))
		},
	},
	{
		id: "rfc8441/4/3", name: "an extended CONNECT without :scheme and :path",
		req: "On requests that contain the :protocol pseudo-header field, the :scheme and :path pseudo-header fields of the target URI MUST also be included.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
			p.wantSettingsAck()
			_, _, err := p.open(Request{Authority: "proxy.test", Protocol: "connect-udp"}).wait(t)
			require.ErrorIs(t, err, errNoTarget)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS of a refused request")
		},
	},

	// RFC 9113, what h2spec has no case for.
	{
		id: "rfc9113/6.5.2/1", name: "SETTINGS_ENABLE_PUSH of 1 from a server",
		req: "A server MUST NOT explicitly set this value to 1. A client MUST treat receipt of a SETTINGS frame with SETTINGS_ENABLE_PUSH set to 1 as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingEnablePush, Val: 1})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/8.5/1", name: "the pseudo-headers of a CONNECT",
		req: "The :method pseudo-header field is set to CONNECT. The :scheme and :path pseudo-header fields MUST be omitted. The :authority pseudo-header field contains the host and port to connect to.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			f := p.wantHeaders()
			require.Equal(t, "CONNECT", f.PseudoValue("method"))
			require.Equal(t, "origin.test:443", f.PseudoValue("authority"))
			require.Empty(t, f.PseudoValue("scheme"))
			require.Empty(t, f.PseudoValue("path"))
			require.Empty(t, f.PseudoValue("protocol"))
		},
	},
	{
		id: "rfc9113/8.5/2", name: "a CONNECT without an authority",
		req: "The :authority pseudo-header field contains the host and port to connect to. A CONNECT request that does not conform to these restrictions is malformed.",
		run: func(t *testing.T, p *peer) {
			_, _, err := p.open(Request{}).wait(t)
			require.ErrorIs(t, err, errNoAuthority)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS of a refused request")
		},
	},
	{
		id: "rfc9113/8.5/3", name: "trailers on a connected stream",
		req: "A CONNECT request that ... the proxy sends a 2xx (Successful) response ... After the initial HEADERS frame sent by each peer, all subsequent HEADERS frames MUST NOT be sent: DATA frames alone are sent on the stream from there on.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeHeaders(id, true, hpack.HeaderField{Name: "x-trailer", Value: "1"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
			p.wantReadCode(s, http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/8.1/1", name: "trailers after a refusal",
		req: "Trailers ... consist of a HEADERS frame with the END_STREAM flag set ... A response consists of ... a final HEADERS frame ... and optionally a trailer section.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("404"))
			s, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
			p.writeData(id, false, []byte("denied"))
			p.writeHeaders(id, true, hpack.HeaderField{Name: "x-trailer", Value: "1"})
			p.wantRead(s, []byte("denied"))
			p.wantReadError(s, io.EOF)
			p.wantAlive()
		},
	},
	{
		id: "rfc9113/8.1/2", name: "an informational answer before the final one",
		req: "A response is a series of zero or more informational (1xx) responses, each of which consists of a HEADERS frame, followed by the final response, which consists of a HEADERS frame.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("103"))
			p.answer(id)
			_, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		},
	},
	{
		id: "rfc9113/8.1/3", name: "an informational answer with END_STREAM",
		req: "A HEADERS frame with the END_STREAM flag set that carries an informational status code is malformed.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, true, status("103"))
			p.wantStreamError(id, http2.ErrCodeProtocol)
			_, _, err := o.wait(t)
			require.Error(t, err, "Open waits for an answer that cannot come")
		},
	},
	{
		id: "rfc9113/8.1/4", name: "DATA before the answer",
		req: "A response consists of ... the final response, which consists of a HEADERS frame, followed by zero or more DATA frames.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeData(id, true, []byte("early"))
			p.wantStreamError(id, http2.ErrCodeProtocol)
			_, _, err := o.wait(t)
			require.Error(t, err, "Open waits for an answer that cannot come")
		},
	},
	{
		id: "rfc9113/8.3.2/1", name: "a :status that is not three digits",
		req: "A single :status pseudo-header field is defined that carries the HTTP status code field. This pseudo-header field MUST be included in all responses, including interim responses.",
		run: func(t *testing.T, p *peer) {
			for _, bad := range []string{"0200", "+200", "20", "2O0", "099"} {
				o := p.open(Request{Authority: "origin.test:443"})
				id := p.wantHeaders().StreamID
				p.writeHeaders(id, false, status(bad))
				p.wantStreamError(id, http2.ErrCodeProtocol)
				_, _, err := o.wait(t)
				require.Error(t, err, "a :status of %q was taken as the answer", bad)
			}
		},
	},
	{
		id: "rfc9113/8.3.2/2", name: "an answer without :status",
		req: "This pseudo-header field MUST be included in all responses, including interim responses.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, hpack.HeaderField{Name: "x-a", Value: "1"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/8.2.1/1", name: "a field value with CR or LF from the caller",
		req: "A field value MUST NOT contain the zero value (ASCII NUL, 0x00), line feed (ASCII LF, 0x0a), or carriage return (ASCII CR, 0x0d) at any position.",
		run: func(t *testing.T, p *peer) {
			_, _, err := p.open(Request{Authority: "origin.test:443", Header: http.Header{"X-A": {"1\r\nx-b: 2"}}}).wait(t)
			require.ErrorIs(t, err, errInvalidHeader)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS of a refused request")
		},
	},
	{
		id: "rfc9113/8.2.1/2", name: "a field value with surrounding whitespace from the caller",
		req: "A field value MUST NOT start or end with an ASCII whitespace character (ASCII SP or HTAB, 0x20 or 0x09).",
		run: func(t *testing.T, p *peer) {
			_, _, err := p.open(Request{Authority: "origin.test:443", Header: http.Header{"X-A": {" 1"}}}).wait(t)
			require.ErrorIs(t, err, errInvalidHeader)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS of a refused request")
		},
	},
	{
		id: "rfc9113/8.2.2/1", name: "a connection-specific field from the caller",
		req: "An endpoint MUST NOT generate an HTTP/2 message containing connection-specific header fields.",
		run: func(t *testing.T, p *peer) {
			_, _, err := p.open(Request{Authority: "origin.test:443", Header: http.Header{"Connection": {"close"}}}).wait(t)
			require.ErrorIs(t, err, errInvalidHeader)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS of a refused request")
		},
	},
	{
		id: "rfc9113/6.8/1", name: "GOAWAY with open streams",
		req: "Once the GOAWAY is sent, the sender will ignore frames sent on streams initiated by the receiver if the stream has an identifier higher than the included last stream identifier. Receivers of a GOAWAY frame MUST NOT open additional streams on the connection.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeGoAway(id, http2.ErrCodeNo)
			require.Eventually(t, func() bool { return !p.c.CanOpen() }, wantTimeout, time.Millisecond)
			_, _, err := p.open(Request{Authority: "origin.test:443"}).wait(t)
			require.ErrorIs(t, err, ErrGoAway)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS after GOAWAY")
			p.writeData(id, false, []byte("still"))
			p.wantRead(s, []byte("still"))
			require.NoError(t, s.Close())
			p.wantGoAway(http2.ErrCodeNo)
			p.wantClosed()
		},
	},
	{
		id: "rfc9113/6.8/2", name: "GOAWAY ending the streams above its last stream id",
		req: "The last stream identifier in the GOAWAY frame contains the highest-numbered stream identifier for which the sender of the GOAWAY frame might have taken some action on or might yet take action on. All streams up to and including the identified stream might have been processed in some way. Activity on streams numbered higher than the last stream identifier cannot have been processed.",
		run: func(t *testing.T, p *peer) {
			s1, id1 := p.connect()
			s2, id2 := p.connect()
			p.writeGoAway(id1, http2.ErrCodeNo)
			p.wantReadError(s2, ErrGoAway)
			wantNothing[*http2.RSTStreamFrame](p, "RST_STREAM on a stream the peer will not process")
			p.writeData(id1, false, []byte("still"))
			p.wantRead(s1, []byte("still"))
			_ = id2
		},
	},
	{
		id: "rfc9113/6.8/3", name: "a second GOAWAY lowering the last stream id",
		req: "An endpoint MAY send multiple GOAWAY frames if circumstances change. ... Endpoints MUST NOT increase the value they send in the last stream identifier, since the peers might already have retried unprocessed requests on another connection.",
		run: func(t *testing.T, p *peer) {
			s1, id1 := p.connect()
			s2, id2 := p.connect()
			p.writeGoAway(id2, http2.ErrCodeNo)
			require.Eventually(t, func() bool { return !p.c.CanOpen() }, wantTimeout, time.Millisecond)
			p.writeGoAway(id1, http2.ErrCodeNo)
			p.wantReadError(s2, ErrGoAway)
			p.writeData(id1, false, []byte("still"))
			p.wantRead(s1, []byte("still"))
		},
	},
	{
		id: "rfc9113/6.9.1/1", name: "padding is credited back",
		req: "The entire DATA frame payload is included in flow control, including the Pad Length and Padding fields if present.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, p.fr.WriteDataPadded(id, false, []byte("hello"), make([]byte, 255)))
			p.wantRead(s, []byte("hello"))
			require.NoError(t, s.Close())
			p.wantRST(id, http2.ErrCodeCancel)
			var credited uint32
			for credited < 261 {
				credited += p.wantWindowUpdate(0)
			}
			require.Equal(t, uint32(261), credited)
		},
	},
	{
		id: "rfc9113/5.1/1", name: "RST_STREAM on a stream that ended in both directions",
		req: "An endpoint MUST NOT send a RST_STREAM in response to a RST_STREAM frame, to avoid looping. ... An endpoint MUST minimally process and then discard any frames it receives in this state.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, s.CloseWrite())
			f := p.wantData(id)
			require.True(t, f.StreamEnded())
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writeRST(id, http2.ErrCodeCancel)
			wantNothing[*http2.RSTStreamFrame](p, "RST_STREAM in answer to RST_STREAM")
			p.wantAlive()
		},
	},
	{
		id: "rfc9113/5.4.2/1", name: "a stream error ends that stream alone",
		req: "A stream error is an error related to a specific stream that does not affect processing of other streams. An endpoint that detects a stream error sends a RST_STREAM frame that contains the stream identifier of the stream where the error occurred.",
		run: func(t *testing.T, p *peer) {
			s1, id1 := p.connect()
			s2, id2 := p.connect()
			p.writeHeaders(id2, false, status("bad"))
			p.wantStreamError(id2, http2.ErrCodeProtocol)
			p.wantReadCode(s2, http2.ErrCodeProtocol)
			p.writeData(id1, false, []byte("on"))
			p.wantRead(s1, []byte("on"))
		},
	},

	{
		id: "rfc9113/5.1/2", name: "DATA on an even stream id",
		req: "Receiving any frame other than HEADERS or PRIORITY on a stream in this state MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.connect()
			p.writeData(2, false, []byte("x"))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/5.1/3", name: "a WINDOW_UPDATE the framer refuses on an idle stream",
		req: "Receiving any frame other than HEADERS or PRIORITY on a stream in this state MUST be treated as a connection error of type PROTOCOL_ERROR. ... RST_STREAM frames MUST NOT be sent for a stream in the \"idle\" state.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameWindowUpdate, 0, 101, []byte{0, 0, 0, 0})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/5.1/4", name: "HEADERS the framer refuses on a stream the server would open",
		req: "If this stream is initiated by the server, as described in Section 5.1.1, then receiving a HEADERS frame MUST also be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			// A regular field ahead of a pseudo-header, which the framer refuses on its own.
			p.writeHeaders(2, false, hpack.HeaderField{Name: "x-first", Value: "1"}, status("200"))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/5.1/5", name: "a write on a stream the peer ended at once",
		req: "A stream that is \"half-closed (remote)\" can be used by the endpoint to send frames of any type.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, true, status("200"))
			s, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, 200, resp.StatusCode)
			n, err := s.Write([]byte("still open"))
			require.NoError(t, err)
			require.Equal(t, 10, n)
			require.Equal(t, "still open", string(p.wantData(id).Data()))
		},
	},
	{
		id: "rfc9113/5.1/6", name: "a WINDOW_UPDATE after the client's END_STREAM",
		req: "An endpoint can receive any type of frame in this state.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, s.CloseWrite())
			require.True(t, p.wantData(id).StreamEnded())
			p.writeWindowUpdate(id, 1024)
			p.wantAlive()
		},
	},
	{
		id: "rfc9113/4.2/2", name: "DATA split at the peer's frame size",
		req: "The size of a frame payload is limited by the maximum size that a receiver advertises in the SETTINGS_MAX_FRAME_SIZE setting.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(
				http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384},
				http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
			p.wantSettingsAck()
			s, id := p.connect()
			p.writeWindowUpdate(0, 1<<20)
			const total = 200 << 10
			go func() { _, _ = s.Write(make([]byte, total)) }()
			for sent := 0; sent < total; {
				f := p.wantData(id)
				require.LessOrEqual(t, int(f.Length), 16384)
				sent += int(f.Length)
			}
		},
	},
	{
		id: "rfc9113/4.2/1", name: "a request past the peer's frame size continues",
		req: "An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame exceeds the size defined in SETTINGS_MAX_FRAME_SIZE. ... Field blocks MUST be transmitted as a contiguous sequence of frames.",
		run: func(t *testing.T, p *peer) {
			p.fr.ReadMetaHeaders = nil
			o := p.open(Request{Authority: "origin.test:443", Header: http.Header{"X-Big": {strings.Repeat("{", 40<<10)}}})
			f := next[*http2.HeadersFrame](p, "HEADERS")
			require.False(t, f.HeadersEnded())
			require.LessOrEqual(t, len(f.HeaderBlockFragment()), 16384)
			block := bytes.Clone(f.HeaderBlockFragment())
			for {
				cf := next[*http2.ContinuationFrame](p, "CONTINUATION")
				require.LessOrEqual(t, len(cf.HeaderBlockFragment()), 16384)
				block = append(block, cf.HeaderBlockFragment()...)
				if cf.HeadersEnded() {
					break
				}
			}
			fields, err := hpack.NewDecoder(hpackTableSize, nil).DecodeFull(block)
			require.NoError(t, err)
			require.Equal(t, "CONNECT", fields[0].Value)
			p.answer(f.StreamID)
			_, _, err = o.wait(t)
			require.NoError(t, err)
		},
	},
	{
		id: "rfc9113/6.9.1/2", name: "DATA past the connection window",
		req: "A receiver MAY respond with a stream error or connection error of type FLOW_CONTROL_ERROR if it receives more data than it advertised. The client ends the connection.",
		run: func(t *testing.T, p *peer) {
			// Every stream window is exact, only their sum passes the connection window.
			for range connWindow/window + 1 {
				o := p.open(Request{Authority: "origin.test:443"})
				id := p.wantHeaders().StreamID
				p.answer(id)
				if _, _, err := o.wait(t); err != nil {
					break
				}
				for sent := 0; sent < window; sent += 16384 {
					if err := p.fr.WriteData(id, false, make([]byte, 16384)); err != nil {
						break
					}
				}
			}
			select {
			case <-p.c.Done():
			case <-time.After(wantTimeout):
				t.Fatal("the client took more stream windows than the connection window has")
			}
			var ce http2.ConnectionError
			require.ErrorAs(t, p.c.Err(), &ce)
			require.Equal(t, http2.ErrCodeFlowControl, http2.ErrCode(ce))
		},
	},
	{
		id: "rfc9113/6.8/5", name: "a retired connection leaves with GOAWAY",
		req: "An endpoint that wishes to shut down ... A GOAWAY frame might not immediately precede closing of the connection; a receiver of a GOAWAY that has no more use for the connection SHOULD still send a GOAWAY frame before terminating the connection. The error code NO_ERROR is used for a graceful shutdown.",
		run: func(t *testing.T, p *peer) {
			s, _ := p.connect()
			p.c.Retire()
			require.Eventually(t, func() bool { return !p.c.CanOpen() }, wantTimeout, time.Millisecond)
			_, _, err := p.open(Request{Authority: "origin.test:443"}).wait(t)
			require.ErrorIs(t, err, ErrGoAway)
			require.NoError(t, s.Close())
			p.wantGoAway(http2.ErrCodeNo)
			p.wantClosed()
			require.ErrorIs(t, p.c.Err(), ErrGoAway)
		},
	},
	{
		id: "rfc9113/6.8/6", name: "what a Write reported leaves ahead of a graceful GOAWAY",
		req: "GOAWAY allows an endpoint to gracefully stop accepting new streams while still finishing processing of previously established streams. A Write that returned reached the socket unless the connection failed.",
		run: func(t *testing.T, p *peer) {
			cli, srv := tcpPair(t)
			p = dialPeerOn(t, &slowConn{Conn: cli, delay: 400 * time.Millisecond}, srv)
			p.writeSettings()
			p.wantSettingsAck()
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.c.Retire()
			// The first write is in the write goroutine's hands, the second in the
			// buffer serve still owns when the CloseWrite drains the connection.
			_, err := s.Write([]byte("first"))
			require.NoError(t, err)
			_, err = s.Write([]byte("second"))
			require.NoError(t, err)
			require.NoError(t, s.CloseWrite())
			var got []byte
			for f := p.wantData(id); ; f = p.wantData(id) {
				got = append(got, f.Data()...)
				if f.StreamEnded() {
					break
				}
			}
			require.Equal(t, "firstsecond", string(got))
			p.wantGoAway(http2.ErrCodeNo)
			p.wantClosed()
		},
	},
	{
		id: "rfc9113/6.8/7", name: "the last END_STREAM leaves ahead of the answer to the peer's GOAWAY",
		req: "GOAWAY allows an endpoint to gracefully stop accepting new streams while still finishing processing of previously established streams.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writeGoAway(id, http2.ErrCodeNo)
			require.Eventually(t, func() bool { return !p.c.CanOpen() }, wantTimeout, time.Millisecond)
			require.NoError(t, s.CloseWrite())
			require.True(t, p.wantData(id).StreamEnded())
			p.wantGoAway(http2.ErrCodeNo)
			p.wantClosed()
		},
	},
	{
		id: "rfc9113/8.2.2/2", name: "a connection-specific field in trailers",
		req: "Any message containing connection-specific header fields MUST be treated as malformed. Clients MUST NOT accept a malformed response.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("403"))
			s, _, err := o.wait(t)
			require.NoError(t, err)
			p.writeHeaders(id, true, hpack.HeaderField{Name: "connection", Value: "keep-alive"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
			p.wantReadCode(s, http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/8.2.2/3", name: "a connection-specific field in an informational answer",
		req: "Any message containing connection-specific header fields MUST be treated as malformed. Clients MUST NOT accept a malformed response.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("103"), hpack.HeaderField{Name: "connection", Value: "keep-alive"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
			_, _, err := o.wait(t)
			require.Error(t, err)
		},
	},
	// Scenarios of Go's HTTP/2 transport tests that apply to a client of CONNECT streams
	// and that no case above covers.
	{
		id: "rfc9113/6.9/4", name: "the client credits what it reads",
		req: "Flow control is specific to a connection. ... A receiver ... sends WINDOW_UPDATE frames as it consumes data and frees up space in flow-control windows.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			const total = 3 * window
			done := make(chan []byte, 1)
			go func() { done <- p.wantReadAll(s, total) }()
			var sent, avail int
			avail = window
			for sent < total {
				n := min(avail, 16384, total-sent)
				if n == 0 {
					avail += int(p.wantWindowUpdate(id))
					continue
				}
				p.writeData(id, false, bytes.Repeat([]byte{byte(sent)}, n))
				sent += n
				avail -= n
			}
			select {
			case got := <-done:
				require.Len(t, got, total)
			case <-time.After(wantTimeout):
				t.Fatal("the reads did not complete")
			}
		},
	},
	{
		id: "rfc9113/6.5.2/2", name: "the request bounded by the peer's SETTINGS_MAX_HEADER_LIST_SIZE",
		req: "SETTINGS_MAX_HEADER_LIST_SIZE: This advisory setting informs a peer of the maximum field section size that the sender is prepared to accept, in octets.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 300})
			p.wantSettingsAck()
			_, _, err := p.open(Request{Authority: "origin.test:443", Header: http.Header{"X-A": {strings.Repeat("a", 1000)}}}).wait(t)
			require.ErrorIs(t, err, errHeadersTooLarge)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS past the peer's bound")
			p.connect()
		},
	},
	{
		id: "rfc9113/6.5.2/3", name: "an answer past the client's SETTINGS_MAX_HEADER_LIST_SIZE",
		req: "SETTINGS_MAX_HEADER_LIST_SIZE: This advisory setting informs a peer of the maximum field section size that the sender is prepared to accept, in octets.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			// Fields that fit a frame each, past the bound together, a decoder that stops
			// emitting rather than one refusing a string, RFC 9113 section 10.5.1.
			fields := []hpack.HeaderField{status("200")}
			for i := range 64 {
				fields = append(fields, hpack.HeaderField{Name: fmt.Sprintf("x-%02d", i), Value: strings.Repeat("{", 1000)})
			}
			block := p.block(fields...)
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:16384]}))
			for block = block[16384:]; len(block) > 16384; block = block[16384:] {
				require.NoError(t, p.fr.WriteContinuation(id, false, block[:16384]))
			}
			require.NoError(t, p.fr.WriteContinuation(id, true, block))
			p.wantStreamError(id, http2.ErrCodeEnhanceYourCalm)
			_, _, err := o.wait(t)
			require.Error(t, err)
		},
	},
	{
		id: "rfc7541/4.2/1", name: "the encoder signals the peer's table size",
		req: "This dynamic table size update MUST occur at the beginning of the first header block following the change to the dynamic table size.",
		run: func(t *testing.T, p *peer) {
			p.connect()
			p.writeSettings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 0})
			p.wantSettingsAck()
			p.fr.ReadMetaHeaders = nil
			p.open(Request{Authority: "origin.test:443"})
			f := next[*http2.HeadersFrame](p, "HEADERS")
			require.Equal(t, byte(0x20), f.HeaderBlockFragment()[0], "a dynamic table size update to 0 opens the block")
		},
	},
	{
		id: "rfc9113/6.8/4", name: "GOAWAY with an error code",
		req: "The error code ... contains the reason for closing the connection.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeGoAway(id, http2.ErrCodeInternal)
			p.wantClosed()
			var ce http2.ConnectionError
			require.ErrorAs(t, p.c.Err(), &ce)
			require.Equal(t, http2.ErrCodeInternal, http2.ErrCode(ce))
			_, err := p.read(s)
			require.ErrorAs(t, err, &ce)
		},
	},
	{
		id: "rfc9113/5.4.2/2", name: "RST_STREAM before the answer",
		req: "RST_STREAM ... allows for immediate termination of a stream. ... The RST_STREAM frame contains a single unsigned, 32-bit integer identifying the error code. The error code indicates why the stream is being terminated.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeRST(id, http2.ErrCodeRefusedStream)
			_, _, err := o.wait(t)
			var se http2.StreamError
			require.ErrorAs(t, err, &se)
			require.Equal(t, http2.ErrCodeRefusedStream, se.Code)
			p.wantAlive()
		},
	},
	{
		id: "rfc9113/8.1/5", name: "many informational answers of unknown codes",
		req: "A response is a series of zero or more informational (1xx) responses, each of which consists of a HEADERS frame, followed by the final response.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			for range 100 {
				p.writeHeaders(id, false, status("199"), hpack.HeaderField{Name: "x-hint", Value: strings.Repeat("h", 1000)})
			}
			p.answer(id)
			_, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		},
	},
	{
		id: "rfc9113/8.2.1/3", name: "a field value with CR or LF in the answer",
		req: "A field value MUST NOT contain the zero value (ASCII NUL, 0x00), line feed (ASCII LF, 0x0a), or carriage return (ASCII CR, 0x0d) at any position. ... A request or response that contains a field that violates any of these conditions MUST be treated as malformed.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("200"), hpack.HeaderField{Name: "x-a", Value: "1\r\nx-b: 2"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/8.2.1/4", name: "an empty field name in the answer",
		req: "A field name MUST NOT contain characters in the ranges 0x00-0x20, 0x41-0x5a, or 0x7f-0xff. ... A request or response that contains a field that violates any of these conditions MUST be treated as malformed.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("200"), hpack.HeaderField{Name: "", Value: "1"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
}

// ended closes s in both directions, the client's END_STREAM first.
func ended(t *testing.T, p *peer, s *Stream, id uint32) {
	t.Helper()
	require.NoError(t, s.CloseWrite())
	require.True(t, p.wantData(id).StreamEnded())
	p.writeData(id, true, nil)
	p.wantReadError(s, io.EOF)
}

// wantCompressionError sends block as the answer and wants the decoding error to end the
// connection, RFC 9113 section 4.3.
func wantCompressionError(t *testing.T, p *peer, block []byte) {
	t.Helper()
	p.open(Request{Authority: "origin.test:443"})
	id := p.wantHeaders().StreamID
	p.writeBlock(id, false, block)
	p.wantConnectionError(http2.ErrCodeCompression)
}

// wantAnswerBlock sends block as the answer and wants it decoded as a 200.
func wantAnswerBlock(t *testing.T, p *peer, block []byte) {
	t.Helper()
	o := p.open(Request{Authority: "origin.test:443"})
	id := p.wantHeaders().StreamID
	p.writeBlock(id, false, block)
	_, resp, err := o.wait(t)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// echoH2C serves CONNECT over unencrypted HTTP/2 by echoing the stream, so the peer's TLS
// stays out of the measurement.
func echoH2C(b *testing.B) net.Addr {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "not a CONNECT", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		buf := make([]byte, 64<<10)
		for {
			n, rerr := r.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				_ = rc.Flush()
			}
			if rerr != nil {
				return
			}
		}
	})}
	srv.Protocols = new(http.Protocols)
	srv.Protocols.SetUnencryptedHTTP2(true)
	go func() { _ = srv.Serve(ln) }()
	b.Cleanup(func() { _ = srv.Close() })
	return ln.Addr()
}

func benchConn(b *testing.B, addr net.Addr) *Conn {
	b.Helper()
	nc, err := net.Dial("tcp", addr.String())
	if err != nil {
		b.Fatal(err)
	}
	c, err := Client(nc, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = c.Close() })
	return c
}

func benchStream(b *testing.B, c *Conn) *Stream {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, resp, err := c.Open(ctx, Request{Authority: "origin.test:443"})
	if err != nil {
		b.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		b.Fatalf("status %d", resp.StatusCode)
	}
	return s
}

func BenchmarkStreamThroughput(b *testing.B) {
	addr := echoH2C(b)
	c := benchConn(b, addr)
	s := benchStream(b, c)
	const chunk = 64 << 10
	payload := make([]byte, chunk)
	drained := make(chan struct{})
	go func() {
		_, _ = io.CopyN(io.Discard, s, int64(chunk)*int64(b.N))
		close(drained)
	}()
	b.SetBytes(chunk)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := s.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	<-drained
}

func BenchmarkDatagramRoundTrip(b *testing.B) {
	addr := echoH2C(b)
	c := benchConn(b, addr)
	s := benchStream(b, c)
	const size = 1200
	payload := make([]byte, size)
	buf := make([]byte, size)
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := s.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(s, buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParallelStreams(b *testing.B) {
	addr := echoH2C(b)
	c := benchConn(b, addr)
	const size = 1200
	b.SetBytes(size)
	b.ReportAllocs()
	b.SetParallelism(4)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		s := benchStream(b, c)
		payload := make([]byte, size)
		buf := make([]byte, size)
		for pb.Next() {
			if _, err := s.Write(payload); err != nil {
				b.Error(err)
				return
			}
			if _, err := io.ReadFull(s, buf); err != nil {
				b.Error(err)
				return
			}
		}
		_ = s.Close()
	})
}

func BenchmarkOpenClose(b *testing.B) {
	addr := echoH2C(b)
	c := benchConn(b, addr)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		s := benchStream(b, c)
		_ = s.Close()
	}
}

// echoTLS is echoH2C over TLS, the transport the proxy's own HTTP/2 is used with.
func echoTLS(b *testing.B) (net.Addr, *tls.Config) {
	b.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		buf := make([]byte, 64<<10)
		for {
			n, rerr := r.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				_ = rc.Flush()
			}
			if rerr != nil {
				return
			}
		}
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	b.Cleanup(srv.Close)
	cfg := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	cfg.NextProtos = []string{"h2"}
	return srv.Listener.Addr(), cfg
}

func benchTLSConn(b *testing.B) *Conn {
	b.Helper()
	addr, cfg := echoTLS(b)
	tc, err := tls.Dial("tcp", addr.String(), cfg)
	if err != nil {
		b.Fatal(err)
	}
	c, err := Client(tc, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = c.Close() })
	return c
}

func BenchmarkStreamThroughputTLS(b *testing.B) {
	c := benchTLSConn(b)
	s := benchStream(b, c)
	const chunk = 64 << 10
	payload := make([]byte, chunk)
	drained := make(chan struct{})
	go func() {
		_, _ = io.CopyN(io.Discard, s, int64(chunk)*int64(b.N))
		close(drained)
	}()
	b.SetBytes(chunk)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := s.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	<-drained
}

func BenchmarkDatagramRoundTripTLS(b *testing.B) {
	c := benchTLSConn(b)
	s := benchStream(b, c)
	const size = 1200
	payload := make([]byte, size)
	buf := make([]byte, size)
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := s.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(s, buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParallelStreamsTLS(b *testing.B) {
	c := benchTLSConn(b)
	const size = 1200
	b.SetBytes(size)
	b.ReportAllocs()
	b.SetParallelism(4)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		s := benchStream(b, c)
		payload := make([]byte, size)
		buf := make([]byte, size)
		for pb.Next() {
			if _, err := s.Write(payload); err != nil {
				b.Error(err)
				return
			}
			if _, err := io.ReadFull(s, buf); err != nil {
				b.Error(err)
				return
			}
		}
		_ = s.Close()
	})
}

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

// fakePeer is the server end of a TCP connection, reading the client preface, sending the
// settings given and answering every HEADERS with 200. What it does past that
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

func (c *memConn) LocalAddr() net.Addr { return emptyAddr{} }

func (c *memConn) RemoteAddr() net.Addr { return emptyAddr{} }

func (c *memConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

type emptyAddr struct{}

func (emptyAddr) Network() string { return "mem" }

func (emptyAddr) String() string { return "mem" }

// stuckPeer answers n streams, then stops reading its socket, and returns the streams
// once the client's writer is stuck on it, the first of them filling the socket.
func stuckPeer(t *testing.T, n int) (*Conn, []*Stream) {
	return silentPeer(t, n, true)
}

// gateConn is a socket whose writes wait at a gate the test closes and opens, so a stuck
// writer is stuck by construction and not by what a kernel buffer takes. A write deadline
// ends the wait as it would on a socket.
type gateConn struct {
	net.Conn
	mu       sync.Mutex
	cond     sync.Cond
	held     bool
	deadline time.Time
}

func newGateConn(nc net.Conn) *gateConn {
	g := &gateConn{Conn: nc}
	g.cond.L = &g.mu
	return g
}

func (g *gateConn) hold() {
	g.mu.Lock()
	g.held = true
	g.mu.Unlock()
}

func (g *gateConn) release() {
	g.mu.Lock()
	g.held = false
	g.cond.Broadcast()
	g.mu.Unlock()
}

func (g *gateConn) Write(p []byte) (int, error) {
	g.mu.Lock()
	for g.held {
		if !g.deadline.IsZero() {
			if !time.Now().Before(g.deadline) {
				g.mu.Unlock()
				return 0, os.ErrDeadlineExceeded
			}
			time.AfterFunc(time.Until(g.deadline), g.cond.Broadcast)
		}
		g.cond.Wait()
	}
	g.mu.Unlock()
	return g.Conn.Write(p)
}

func (g *gateConn) SetWriteDeadline(t time.Time) error {
	g.mu.Lock()
	g.deadline = t
	g.cond.Broadcast()
	g.mu.Unlock()
	return g.Conn.SetWriteDeadline(t)
}

func (g *gateConn) SetDeadline(t time.Time) error {
	_ = g.SetWriteDeadline(t)
	return g.Conn.SetReadDeadline(t)
}

// waitStuck returns once the write goroutine is held on a buffer and serve's own is full,
// the state in which nothing serve encodes leaves.
func waitStuck(t *testing.T, c *Conn) {
	t.Helper()
	require.Eventually(t, func() bool {
		var stuck bool
		c.onLoop(func() { stuck = c.writing && c.out.Len() >= outBound })
		return stuck
	}, wantTimeout, time.Millisecond, "the writer never got stuck")
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
	gate := newGateConn(cli)
	conn, err := Client(gate, 0)
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
		gate.hold()
		go func() { _, _ = streams[0].Write(make([]byte, 64<<20)) }()
		waitStuck(t, conn)
	}
	return conn, streams
}

// onLoop runs fn on the serve goroutine and returns once it ran, or at once when the
// connection ended.
func (c *Conn) onLoop(fn func()) {
	done := make(chan struct{})
	if c.send(msg{kind: msgFunc, fn: func() { fn(); close(done) }}) {
		select {
		case <-done:
		case <-c.done:
		}
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

func (g *stuckConn) LocalAddr() net.Addr { return emptyAddr{} }

func (g *stuckConn) RemoteAddr() net.Addr { return emptyAddr{} }

func (g *stuckConn) SetDeadline(time.Time) error { return nil }

func (g *stuckConn) SetReadDeadline(time.Time) error { return nil }

// peerWriter feeds frames to the client's read side.
type peerWriter struct{ g *stuckConn }

func (w *peerWriter) Write(p []byte) (int, error) { w.g.feed(p); return len(p), nil }

func newBufioReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }

// creditPeer answers every HEADERS, tracks what the client lets it send on the connection
// and adds back every connection WINDOW_UPDATE.
func creditPeer(t *testing.T, srv net.Conn, answered chan<- uint32, settings ...http2.Setting) *fakePeer {
	t.Helper()
	ready := make(chan *fakePeer, 1)
	go func() {
		peer, err := startFakePeer(srv, settings...)
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
	p := <-ready
	require.NotNil(t, p)
	return p
}

// peer is the far end of a connection, driven in a linear sequence: write what the peer
// sends, want what the client must send back, with every wait bounded.
type peer struct {
	t      *testing.T
	c      *Conn
	nc     net.Conn
	fr     *http2.Framer
	enc    *hpack.Encoder
	encBuf bytes.Buffer
	// nextID is the stream id the client's next HEADERS is expected on.
	nextID uint32
}

const wantTimeout = 3 * time.Second

// newPeer connects a client and reads its preface, sends the peer's SETTINGS and takes the
// ack, so a case starts on a settled connection.
func newPeer(t *testing.T, settings ...http2.Setting) *peer {
	t.Helper()
	p := dialPeer(t)
	p.writeSettings(settings...)
	p.wantSettingsAck()
	return p
}

// dialPeer is newPeer before the peer sent anything.
func dialPeer(t *testing.T) *peer {
	t.Helper()
	cli, srv := tcpPair(t)
	return dialPeerOn(t, cli, srv)
}

// dialPeerOn is dialPeer on a socket of the case's choosing.
func dialPeerOn(t *testing.T, cli, srv net.Conn) *peer {
	t.Helper()
	c, err := Client(cli, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	p := &peer{t: t, c: c, nc: srv, fr: http2.NewFramer(srv, srv), nextID: 1}
	p.fr.ReadMetaHeaders = hpack.NewDecoder(hpackTableSize, nil)
	p.fr.SetMaxReadFrameSize(1 << 24)
	p.enc = hpack.NewEncoder(&p.encBuf)
	preface := make([]byte, len(http2.ClientPreface))
	_ = srv.SetReadDeadline(time.Now().Add(wantTimeout))
	_, err = io.ReadFull(srv, preface)
	require.NoError(t, err)
	require.Equal(t, http2.ClientPreface, string(preface), "the client preface, RFC 9113 section 3.4")
	sf := p.wantSettings()
	require.False(t, sf.IsAck(), "the client's first frame is its SETTINGS, RFC 9113 section 3.4")
	return p
}

// readFrame returns the client's next frame, within wantTimeout.
func (p *peer) readFrame() (http2.Frame, error) {
	_ = p.nc.SetReadDeadline(time.Now().Add(wantTimeout))
	return p.fr.ReadFrame()
}

// next returns the client's next frame of type T, passing over the others.
func next[T http2.Frame](p *peer, what string) T {
	p.t.Helper()
	for {
		f, err := p.readFrame()
		require.NoError(p.t, err, "waiting for %s", what)
		if f, ok := f.(T); ok {
			return f
		}
	}
}

func (p *peer) wantSettings() *http2.SettingsFrame {
	p.t.Helper()
	return next[*http2.SettingsFrame](p, "SETTINGS")
}

func (p *peer) wantSettingsAck() {
	p.t.Helper()
	for {
		f := next[*http2.SettingsFrame](p, "SETTINGS ack")
		if f.IsAck() {
			return
		}
	}
}

// wantHeaders returns the client's next HEADERS, on the stream id expected next.
func (p *peer) wantHeaders() *http2.MetaHeadersFrame {
	p.t.Helper()
	f := next[*http2.MetaHeadersFrame](p, "HEADERS")
	require.Equal(p.t, p.nextID, f.StreamID, "stream ids go up by two, RFC 9113 section 5.1.1")
	p.nextID += 2
	return f
}

func (p *peer) wantData(id uint32) *http2.DataFrame {
	p.t.Helper()
	for {
		f := next[*http2.DataFrame](p, "DATA")
		if f.StreamID == id {
			return f
		}
	}
}

func (p *peer) wantRST(id uint32, code http2.ErrCode) {
	p.t.Helper()
	f := next[*http2.RSTStreamFrame](p, "RST_STREAM")
	require.Equal(p.t, id, f.StreamID)
	require.Equal(p.t, code, f.ErrCode)
}

func (p *peer) wantGoAway(code http2.ErrCode) *http2.GoAwayFrame {
	p.t.Helper()
	f := next[*http2.GoAwayFrame](p, "GOAWAY")
	require.Equal(p.t, code, f.ErrCode)
	return f
}

func (p *peer) wantWindowUpdate(id uint32) uint32 {
	p.t.Helper()
	for {
		f := next[*http2.WindowUpdateFrame](p, "WINDOW_UPDATE")
		if f.StreamID == id {
			return f.Increment
		}
	}
}

func (p *peer) wantPingAck(data [8]byte) {
	p.t.Helper()
	for {
		f := next[*http2.PingFrame](p, "PING ack")
		if f.IsAck() {
			require.Equal(p.t, data, f.Data)
			return
		}
	}
}

// wantClosed reads to the end of the socket, which the client closes within closeTimeout
// of a connection error.
func (p *peer) wantClosed() {
	p.t.Helper()
	for {
		if _, err := p.readFrame(); err != nil {
			require.False(p.t, errors.Is(err, os.ErrDeadlineExceeded), "the client kept the socket open")
			return
		}
	}
}

// wantConnectionError is what a connection error looks like from the peer, RFC 9113
// section 5.4.1: a GOAWAY with the code, then the socket closed, and the connection ended.
func (p *peer) wantConnectionError(code http2.ErrCode) {
	p.t.Helper()
	p.wantGoAway(code)
	p.wantClosed()
	select {
	case <-p.c.Done():
	case <-time.After(wantTimeout):
		p.t.Fatal("the connection did not end")
	}
	require.Error(p.t, p.c.Err())
}

// wantStreamError is what a stream error looks like from the peer, RFC 9113 section 5.4.2:
// a RST_STREAM with the code, the connection going on.
func (p *peer) wantStreamError(id uint32, code http2.ErrCode) {
	p.t.Helper()
	p.wantRST(id, code)
	p.wantAlive()
}

// wantAlive proves the connection goes on with a PING the client answers.
func (p *peer) wantAlive() {
	p.t.Helper()
	data := [8]byte{'a', 'l', 'i', 'v', 'e'}
	p.writePing(false, data)
	p.wantPingAck(data)
	require.NoError(p.t, p.c.Err())
}

// wantNothing reads for a while and fails on any frame of type T.
func wantNothing[T http2.Frame](p *peer, what string) {
	p.t.Helper()
	_ = p.nc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			require.True(p.t, errors.Is(err, os.ErrDeadlineExceeded), "the socket ended waiting for no %s: %v", what, err)
			return
		}
		if _, ok := f.(T); ok {
			p.t.Fatalf("the client sent %s: %v", what, f)
		}
	}
}

func (p *peer) writeSettings(settings ...http2.Setting) {
	require.NoError(p.t, p.fr.WriteSettings(settings...))
}

func (p *peer) writeSettingsAck() {
	require.NoError(p.t, p.fr.WriteSettingsAck())
}

// writeHeaders sends a header block, END_HEADERS set, on id.
func (p *peer) writeHeaders(id uint32, end bool, fields ...hpack.HeaderField) {
	p.t.Helper()
	require.NoError(p.t, p.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: p.block(fields...), EndHeaders: true, EndStream: end,
	}))
}

// writeBlock sends a header block as given, END_HEADERS set, on id.
func (p *peer) writeBlock(id uint32, end bool, block []byte) {
	p.t.Helper()
	require.NoError(p.t, p.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: block, EndHeaders: true, EndStream: end,
	}))
}

// block encodes fields with the peer's encoder.
func (p *peer) block(fields ...hpack.HeaderField) []byte {
	p.encBuf.Reset()
	for _, f := range fields {
		_ = p.enc.WriteField(f)
	}
	return bytes.Clone(p.encBuf.Bytes())
}

func status(code string) hpack.HeaderField {
	return hpack.HeaderField{Name: ":status", Value: code}
}

// answer sends 200 on id.
func (p *peer) answer(id uint32) {
	p.t.Helper()
	p.writeHeaders(id, false, status("200"))
}

func (p *peer) writeData(id uint32, end bool, b []byte) {
	require.NoError(p.t, p.fr.WriteData(id, end, b))
}

func (p *peer) writeRST(id uint32, code http2.ErrCode) {
	require.NoError(p.t, p.fr.WriteRSTStream(id, code))
}

func (p *peer) writePing(ack bool, data [8]byte) {
	require.NoError(p.t, p.fr.WritePing(ack, data))
}

func (p *peer) writeGoAway(last uint32, code http2.ErrCode) {
	require.NoError(p.t, p.fr.WriteGoAway(last, code, nil))
}

func (p *peer) writeWindowUpdate(id, inc uint32) {
	require.NoError(p.t, p.fr.WriteWindowUpdate(id, inc))
}

func (p *peer) writePriority(id uint32, prio http2.PriorityParam) {
	require.NoError(p.t, p.fr.WritePriority(id, prio))
}

// writeRaw sends one frame byte by byte, for what the framer would not write.
func (p *peer) writeRaw(typ http2.FrameType, flags http2.Flags, id uint32, payload []byte) {
	p.t.Helper()
	hdr := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), byte(typ), byte(flags)}
	hdr = binary.BigEndian.AppendUint32(hdr, id)
	_, err := p.nc.Write(append(hdr, payload...))
	require.NoError(p.t, err)
}

// open starts a CONNECT on a goroutine and returns what it ends with through wait.
func (p *peer) open(req Request) *opening {
	o := &opening{done: make(chan struct{})}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), wantTimeout)
		defer cancel()
		o.s, o.resp, o.err = p.c.Open(ctx, req)
		close(o.done)
	}()
	return o
}

type opening struct {
	s    *Stream
	resp *Response
	err  error
	done chan struct{}
}

func (o *opening) wait(t *testing.T) (*Stream, *Response, error) {
	t.Helper()
	select {
	case <-o.done:
	case <-time.After(wantTimeout):
		t.Fatal("Open did not return")
	}
	return o.s, o.resp, o.err
}

// connect opens a CONNECT the peer answers with 200, and returns the stream and its id.
func (p *peer) connect() (*Stream, uint32) {
	p.t.Helper()
	o := p.open(Request{Authority: "origin.test:443"})
	id := p.wantHeaders().StreamID
	p.answer(id)
	s, resp, err := o.wait(p.t)
	require.NoError(p.t, err)
	require.Equal(p.t, http.StatusOK, resp.StatusCode)
	return s, id
}

// read returns what the stream reads next, within wantTimeout.
func (p *peer) read(s *Stream) ([]byte, error) {
	p.t.Helper()
	_ = s.SetReadDeadline(time.Now().Add(wantTimeout))
	buf := make([]byte, 1<<16)
	n, err := s.Read(buf)
	return buf[:n], err
}

// wantReadAll wants the stream to read n bytes, in as many reads as it takes.
func (p *peer) wantReadAll(s *Stream, n int) []byte {
	p.t.Helper()
	_ = s.SetReadDeadline(time.Now().Add(wantTimeout))
	buf := make([]byte, n)
	_, err := io.ReadFull(s, buf)
	require.NoError(p.t, err)
	return buf
}

// wantRead wants the stream to read exactly b next.
func (p *peer) wantRead(s *Stream, b []byte) {
	p.t.Helper()
	got, err := p.read(s)
	require.NoError(p.t, err)
	require.Equal(p.t, b, got)
}

// wantReadError wants the stream's reads to end with err.
func (p *peer) wantReadError(s *Stream, err error) {
	p.t.Helper()
	_, got := p.read(s)
	require.ErrorIs(p.t, got, err)
}

// wantReadCode wants the stream's reads to end with a stream error of code.
func (p *peer) wantReadCode(s *Stream, code http2.ErrCode) {
	p.t.Helper()
	_, err := p.read(s)
	var se http2.StreamError
	require.ErrorAs(p.t, err, &se, "read ended with %v", err)
	require.Equal(p.t, code, se.Code)
}

// slowConn delays every socket write, so serve encodes ahead of the write goroutine.
type slowConn struct {
	net.Conn
	delay time.Duration
}

func (c *slowConn) Write(b []byte) (int, error) {
	time.Sleep(c.delay)
	return c.Conn.Write(b)
}
