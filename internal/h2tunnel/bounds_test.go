// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package h2tunnel

import (
	"context"
	"io"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// Bounds under a peer that stops reading or answering: stuck writers, deadlines kept
// behind them, keepalive, floods, and the close bound.

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

// A read with bytes in hand returns them, and one without returns at its deadline, while the
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

// A peer sending one byte per DATA frame costs the window and little more, the tiny
// payloads joining one chunk.
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

// A peer flooding one-byte DATA on a live stream behind a stuck writer leaves serve free
// and the control queue bounded.
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

// The resets of the caller's own streams count against no bound, only the acks a peer
// provokes do.
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

// A peer that provokes more control frames than the socket takes receives a GOAWAY
// with ENHANCE_YOUR_CALM once it reads again.
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

// Probe for the chunk joining: a peer sending tiny frames to a reader that falls behind
// must lose and repeat nothing across the backlog, the owned tail and partial reads.
func TestStream_TinyFramesKeepTheirOrder(t *testing.T) {
	p := newPeer(t)
	s, id := p.connect()
	const total = 200 << 10
	want := make([]byte, total)
	rnd := rand.New(rand.NewSource(7)) //nolint:gosec // a test stream
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
