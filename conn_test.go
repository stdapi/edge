// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
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

func TestH2Stream_ReadDeadlineReachesABlockedRead(t *testing.T) {
	deadlines := []struct {
		name string
		at   func() time.Time
	}{
		{"past", time.Now},
		{"future", func() time.Time { return time.Now().Add(100 * time.Millisecond) }},
	}
	for _, tc := range deadlines {
		t.Run(tc.name, func(t *testing.T) {
			pr, pw := io.Pipe()
			defer func() { _ = pw.Close() }()
			s := newH2Stream(httptest.NewRecorder(), httptest.NewRequest(http.MethodConnect, "/", pr), nil, nil)
			done := make(chan error, 1)
			go func() {
				_, err := s.Read(make([]byte, 1))
				done <- err
			}()
			time.Sleep(50 * time.Millisecond)
			require.NoError(t, s.SetReadDeadline(tc.at()))
			select {
			case err := <-done:
				assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
			case <-time.After(2 * time.Second):
				t.Fatal("the read blocked past its deadline")
			}
		})
	}
}

func TestH2Stream_ReadDeadlineSetTwiceUnderABlockedRead(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	s := newH2Stream(httptest.NewRecorder(), httptest.NewRequest(http.MethodConnect, "/", pr), nil, nil)
	done := make(chan error, 1)
	go func() {
		_, err := s.Read(make([]byte, 1))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	require.NotPanics(t, func() {
		_ = s.SetReadDeadline(time.Now().Add(time.Hour))
		_ = s.SetReadDeadline(time.Now())
	})
	select {
	case err := <-done:
		assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	case <-time.After(2 * time.Second):
		t.Fatal("the read blocked past its deadline")
	}
}

// finishedWriter fails the test on any use once the handler serving it has returned.
type finishedWriter struct {
	http.ResponseWriter
	t        *testing.T
	returned atomic.Bool
}

func (w *finishedWriter) check() {
	if w.returned.Load() {
		w.t.Error("the response writer was used after its handler returned")
	}
}

func (w *finishedWriter) Write(b []byte) (int, error) { w.check(); return w.ResponseWriter.Write(b) }
func (w *finishedWriter) WriteHeader(code int)        { w.check(); w.ResponseWriter.WriteHeader(code) }
func (w *finishedWriter) Flush()                      { w.check() }
func (w *finishedWriter) SetWriteDeadline(time.Time) error {
	w.check()
	return nil
}

func TestH2Stream_NothingReachesTheWriterAfterFinish(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	w := &finishedWriter{ResponseWriter: httptest.NewRecorder(), t: t}
	s := newH2Stream(w, httptest.NewRequest(http.MethodConnect, "/", pr), nil, nil)
	s.finish()
	w.returned.Store(true)

	_, err := s.Write([]byte("late"))
	assert.ErrorIs(t, err, net.ErrClosed)
	s.writeHeader(http.StatusOK)
	assert.ErrorIs(t, s.SetWriteDeadline(time.Now()), net.ErrClosed)
	assert.NoError(t, s.Close())
	s.Abort()
}

func TestH2Stream_ConcurrentReads(t *testing.T) {
	ends := []struct {
		end  func(s *h2Stream, pw *io.PipeWriter)
		name string
	}{
		{func(_ *h2Stream, pw *io.PipeWriter) {
			_, _ = pw.Write([]byte("a"))
			_, _ = pw.Write([]byte("b"))
		}, "bytes for each"},
		{func(s *h2Stream, _ *io.PipeWriter) { _ = s.Close() }, "Close"},
	}
	for _, tc := range ends {
		t.Run(tc.name, func(t *testing.T) {
			pr, pw := io.Pipe()
			defer func() { _ = pw.Close() }()
			s := newH2Stream(httptest.NewRecorder(), httptest.NewRequest(http.MethodConnect, "/", pr), nil, nil)
			done := make(chan struct{}, 2)
			for range 2 {
				go func() {
					_, _ = s.Read(make([]byte, 1))
					done <- struct{}{}
				}()
			}
			time.Sleep(50 * time.Millisecond)
			go tc.end(s, pw)
			for range 2 {
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("a read stayed blocked")
				}
			}
		})
	}
}

// blockedWriter blocks a write until a deadline in the past resets the stream, as net/http does.
type blockedWriter struct {
	http.ResponseWriter
	reset    chan struct{}
	writing  chan struct{}
	once     sync.Once
	returned atomic.Bool
}

func (w *blockedWriter) Write([]byte) (int, error) {
	close(w.writing)
	<-w.reset
	w.returned.Store(true)
	return 0, os.ErrDeadlineExceeded
}

func (w *blockedWriter) SetWriteDeadline(time.Time) error {
	w.once.Do(func() { close(w.reset) })
	return nil
}

func TestH2Stream_FinishWaitsForTheWriteInFlight(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	w := &blockedWriter{ResponseWriter: httptest.NewRecorder(), reset: make(chan struct{}), writing: make(chan struct{})}
	s := newH2Stream(w, httptest.NewRequest(http.MethodConnect, "/", pr), nil, nil)
	go func() { _, _ = s.Write([]byte("x")) }()
	<-w.writing
	s.Abort()
	s.finish()
	assert.True(t, w.returned.Load(), "finish returned with a write in flight")
}
