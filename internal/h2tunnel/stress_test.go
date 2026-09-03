// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package h2tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// Races and lifecycle under the race detector: everything at once, closes under
// live streams, cancels at every moment, and nothing left behind.

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

// The credit is exact under readers flushing while serve closes their streams.
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

// A connection leaves no goroutine behind once it ended.
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

// Retire, Open, Close and the whole net.Conn API at once wedge neither serve nor a caller.
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

// An Open the context cancels returns once serve let go of the request, so the caller's
// header map is its own again.
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

// Open cancelled at the moment the peer answers leaves no stream behind and no
// caller blocked.
func TestConn_OpenCancelledAsTheAnswerArrives(t *testing.T) {
	for range 40 {
		p := newPeer(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			_, _, _ = p.c.Open(ctx, Request{Authority: "origin.test:443"})
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
		var open int
		p.c.onLoop(func() { open = len(p.c.streams) })
		require.Zero(t, open, "a stream was left behind")
		_ = p.c.Close()
	}
}
