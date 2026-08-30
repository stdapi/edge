// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readErrWithin(t *testing.T, c net.Conn, d time.Duration) error {
	t.Helper()
	require.NoError(t, c.SetReadDeadline(time.Now().Add(d)))
	_, err := c.Read(make([]byte, 1))
	return err
}

func TestIdleTracker_ArmClosesTheTunnel(t *testing.T) {
	client, upstream := net.Pipe()
	defer func() { _ = upstream.Close() }()

	tracker := newIdleTracker(0, client, upstream)
	defer tracker.stop()

	// Nothing runs until a half-close arms it.
	require.ErrorIs(t, readErrWithin(t, client, 100*time.Millisecond), os.ErrDeadlineExceeded)

	tracker.arm(20 * time.Millisecond)
	assert.ErrorIs(t, readErrWithin(t, client, 2*time.Second), io.ErrClosedPipe)
}

func TestIdleTracker_ArmedTimerIsPushedBackByTraffic(t *testing.T) {
	client, upstream := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()

	tracker := newIdleTracker(0, client, upstream)
	defer tracker.stop()

	tracker.arm(100 * time.Millisecond)
	for range 5 {
		time.Sleep(30 * time.Millisecond)
		tracker.touch()
	}

	err := readErrWithin(t, client, 10*time.Millisecond)
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded, "traffic must keep the tunnel open")
}

func TestIdleTracker_ArmDoesNotOverrideAConfiguredTimeout(t *testing.T) {
	client, upstream := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()

	tracker := newIdleTracker(30*time.Millisecond, client, upstream)
	defer tracker.stop()

	tracker.arm(time.Hour)
	assert.ErrorIs(t, readErrWithin(t, client, 2*time.Second), io.ErrClosedPipe)
}

func TestIdleTracker_ArmAfterStopDoesNothing(t *testing.T) {
	client, upstream := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()

	tracker := newIdleTracker(0, client, upstream)
	tracker.stop()
	tracker.arm(20 * time.Millisecond)

	assert.ErrorIs(t, readErrWithin(t, client, 60*time.Millisecond), os.ErrDeadlineExceeded)
}
