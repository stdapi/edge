// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
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

func TestH2Stream_CloseWriteOnHTTP3KeepsReceiving(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	type result struct {
		late, again error
		got         string
	}
	done := make(chan result, 1)
	up := startH3Upstream(t, ca, nil, false, func(w http.ResponseWriter, r *http.Request) {
		s := newH2Stream(w, r, nil, nil)
		defer func() { _ = s.Close() }()
		w.WriteHeader(http.StatusOK)
		var res result
		if _, err := s.Write([]byte("pong")); err == nil {
			_ = s.CloseWrite()
			_, res.late = s.Write([]byte("late"))
			res.again = s.CloseWrite()
			got, _ := io.ReadAll(s)
			res.got = string(got)
		}
		done <- res
	})

	tr := &http3.Transport{}
	t.Cleanup(func() { _ = tr.Close() })
	cc := tr.NewClientConn(dialQUICFront(t, netip.MustParseAddrPort(up.addr), ca))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	str, err := cc.OpenRequestStream(ctx)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodConnect, "https://origin.test:80", nil)
	require.NoError(t, err)
	require.NoError(t, str.SendRequestHeader(req))
	resp, err := str.ReadResponse()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.NoError(t, str.SetReadDeadline(time.Now().Add(3*time.Second)))
	got, err := io.ReadAll(str)
	require.NoError(t, err, "the stream to the client was not closed after %q", got)
	assert.Equal(t, "pong", string(got))
	_, err = str.Write([]byte("more"))
	require.NoError(t, err)
	require.NoError(t, str.Close())

	select {
	case res := <-done:
		assert.True(t, errors.Is(res.late, net.ErrClosed), "%v", res.late)
		assert.NoError(t, res.again)
		assert.Equal(t, "more", res.got)
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never read the end of the stream")
	}
}
