// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tcpPair returns the two ends of one loopback TCP connection.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	dialed, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	accepted, err := ln.Accept()
	require.NoError(t, err)

	a, b := dialed.(*net.TCPConn), accepted.(*net.TCPConn)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestRelay_CountersAndHalfClose(t *testing.T) {
	clientA, a := tcpPair(t)
	clientB, b := tcpPair(t)

	var aToB, bToA int64
	var rerr error
	done := make(chan struct{})
	go func() {
		aToB, bToA, rerr = Relay(a, b)
		close(done)
	}()

	deadline := time.Now().Add(3 * time.Second)
	require.NoError(t, clientA.SetDeadline(deadline))
	require.NoError(t, clientB.SetDeadline(deadline))

	_, err := clientA.Write([]byte("up"))
	require.NoError(t, err)
	buf := make([]byte, 16)
	n, err := io.ReadFull(clientB, buf[:2])
	require.NoError(t, err)
	require.Equal(t, "up", string(buf[:n]))

	_, err = clientB.Write([]byte("down"))
	require.NoError(t, err)
	n, err = io.ReadFull(clientA, buf[:4])
	require.NoError(t, err)
	require.Equal(t, "down", string(buf[:n]))

	// One side done sending: the far side reads EOF while the other direction stays open.
	require.NoError(t, clientA.CloseWrite())
	_, err = clientB.Read(buf)
	require.ErrorIs(t, err, io.EOF)
	require.NoError(t, clientB.CloseWrite())

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the relay did not end after both directions closed")
	}
	assert.NoError(t, rerr)
	assert.Equal(t, int64(2), aToB)
	assert.Equal(t, int64(4), bToA)
}

func TestRelay_ResetCrossesAsReset(t *testing.T) {
	clientA, a := tcpPair(t)
	clientB, b := tcpPair(t)

	go func() { _, _, _ = Relay(a, b) }()

	require.NoError(t, clientB.SetDeadline(time.Now().Add(3*time.Second)))
	_, err := clientA.Write([]byte("up"))
	require.NoError(t, err)
	buf := make([]byte, 16)
	_, err = io.ReadFull(clientB, buf[:2])
	require.NoError(t, err)

	require.NoError(t, clientA.SetLinger(0))
	require.NoError(t, clientA.Close())
	_, err = clientB.Read(buf)
	require.Error(t, err)
	assert.NotErrorIs(t, err, io.EOF, "the reset reached the far side as a FIN")
}

func TestRelayer_IdleTimeoutEndsASilentRelay(t *testing.T) {
	_, a := tcpPair(t)
	_, b := tcpPair(t)

	done := make(chan error, 1)
	go func() {
		_, _, err := (&Relayer{IdleTimeout: 100 * time.Millisecond}).Relay(a, b)
		done <- err
	}()

	select {
	case err := <-done:
		assert.NoError(t, err, "an idle close is the normal end of a relay, not a fault")
	case <-time.After(3 * time.Second):
		t.Fatal("the idle timeout did not end the relay")
	}
}

func TestThrottled_PacesWrites(t *testing.T) {
	a, b := tcpPair(t)

	got := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(b)
		got <- data
	}()

	w := Throttled(a, 200)
	start := time.Now()
	_, err := w.Write(make([]byte, 60))
	require.NoError(t, err)
	elapsed := time.Since(start)
	require.NoError(t, a.Close())

	assert.GreaterOrEqual(t, elapsed, 250*time.Millisecond, "60 bytes at 200 B/s is 300ms")
	assert.Len(t, <-got, 60, "shaping delays the bytes, it does not lose them")
}

func TestDelayed_HoldsEachWrite(t *testing.T) {
	a, b := tcpPair(t)

	got := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(b)
		got <- data
	}()

	w := Delayed(a, 100*time.Millisecond)
	start := time.Now()
	_, err := w.Write([]byte("one"))
	require.NoError(t, err)
	_, err = w.Write([]byte("two"))
	require.NoError(t, err)
	elapsed := time.Since(start)
	require.NoError(t, a.Close())

	assert.GreaterOrEqual(t, elapsed, 180*time.Millisecond)
	assert.Equal(t, "onetwo", string(<-got))
}

func TestShaped_KeepsHalfClose(t *testing.T) {
	a, b := tcpPair(t)
	deadline := time.Now().Add(3 * time.Second)
	require.NoError(t, a.SetDeadline(deadline))
	require.NoError(t, b.SetDeadline(deadline))

	w := Throttled(a, 0)
	cw, ok := w.(interface{ CloseWrite() error })
	require.True(t, ok, "a shaped connection must forward the half-close")
	require.NoError(t, cw.CloseWrite())

	buf := make([]byte, 8)
	_, err := b.Read(buf)
	require.ErrorIs(t, err, io.EOF, "the peer reads EOF after the half-close")

	_, err = b.Write([]byte("back"))
	require.NoError(t, err)
	n, err := io.ReadFull(w, buf[:4])
	require.NoError(t, err, "the read direction outlives the half-close")
	assert.Equal(t, "back", string(buf[:n]))
}
