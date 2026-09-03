// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package h2tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Streams echo what they carry, the reads overlapping the next opens, and bytes past the
// frame size and both windows come back intact.
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
