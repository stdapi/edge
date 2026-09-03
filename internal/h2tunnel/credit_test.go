// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package h2tunnel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// Flow control accounting the client keeps exact: what a stream took goes back to the
// connection, whatever ended it, and no stream starves another.

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
