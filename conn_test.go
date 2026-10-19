// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/stdapi/edge/internal/netutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func readErrWithin(t *testing.T, c net.Conn, d time.Duration) error {
	t.Helper()
	require.NoError(t, c.SetReadDeadline(time.Now().Add(d)))
	_, err := c.Read(make([]byte, 1))
	return err
}

func TestIdleTracker_TimerIsPushedBackByTraffic(t *testing.T) {
	client, upstream := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()

	tracker := newIdleTracker(100*time.Millisecond, client, upstream)
	defer tracker.stop()

	for range 5 {
		time.Sleep(30 * time.Millisecond)
		tracker.touch()
	}

	err := readErrWithin(t, client, 10*time.Millisecond)
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded, "traffic must keep the tunnel open")
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

func tlsPipe(t *testing.T) (server, client *tlsConn) {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	leaf, err := ca.Leaf("pipe.test")
	require.NoError(t, err)
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	server = tlsServer(a, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	client = tlsClient(b, &tls.Config{ServerName: "pipe.test", RootCAs: ca.CertPool()})
	handshake := make(chan error, 1)
	go func() { handshake <- client.Handshake() }()
	require.NoError(t, server.Handshake())
	require.NoError(t, <-handshake)
	return server, client
}

func TestTLSConn_CloseNotifyIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		close func(server, client *tlsConn) error
	}{
		{"server close", func(server, _ *tlsConn) error { return server.Close() }},
		{"server close write", func(server, _ *tlsConn) error { return server.CloseWrite() }},
		{"client close", func(_, client *tlsConn) error { return client.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := tlsPipe(t)
			start := time.Now()
			err := tc.close(server, client)
			elapsed := time.Since(start)
			assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
			assert.GreaterOrEqual(t, elapsed, alertWriteTimeout/2, "the close_notify was not attempted")
			assert.Less(t, elapsed, 2*alertWriteTimeout)
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

// deadlineWriter counts the write deadlines that reach the response writer, each of which
// net/http turns into a reset of the stream once it expires.
type deadlineWriter struct {
	http.ResponseWriter
	set atomic.Int32
}

func (w *deadlineWriter) SetWriteDeadline(time.Time) error {
	w.set.Add(1)
	return nil
}

func TestH2Stream_AnExpiredWriteDeadlineLeavesAnIdleStream(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	w := &deadlineWriter{ResponseWriter: httptest.NewRecorder()}
	s := newH2Stream(w, httptest.NewRequest(http.MethodConnect, "/", pr), nil, nil)

	require.NoError(t, s.SetWriteDeadline(time.Now()))
	_, err := s.Write([]byte("late"))
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.NoError(t, s.SetWriteDeadline(time.Time{}))
	_, err = s.Write([]byte("on time"))
	assert.NoError(t, err)

	require.NoError(t, s.SetWriteDeadline(time.Now().Add(20*time.Millisecond)))
	time.Sleep(60 * time.Millisecond)
	_, err = s.Write([]byte("late"))
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
	assert.Zero(t, w.set.Load(), "a deadline reached the writer with no write in flight")
}

func TestH2Stream_FinishStopsTheWriteDeadline(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	s := newH2Stream(&deadlineWriter{ResponseWriter: httptest.NewRecorder()}, httptest.NewRequest(http.MethodConnect, "/", pr), nil, nil)
	require.NoError(t, s.SetWriteDeadline(time.Now().Add(time.Hour)))
	s.finish()
	assert.False(t, s.wtimer.Stop(), "the timer outlives the stream")
}

func TestH2Stream_SmallWriteCutByItsDeadlineFails(t *testing.T) {
	type result struct {
		err  error
		took time.Duration
	}
	written := make(chan result, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var protos http.Protocols
	protos.SetUnencryptedHTTP2(true)
	srv := &http.Server{Protocols: &protos, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := newH2Stream(w, r, nil, nil)
		defer s.finish()
		s.writeHeader(http.StatusOK)
		start := time.Now()
		_ = s.SetWriteDeadline(start.Add(100 * time.Millisecond))
		_, werr := s.Write([]byte("small"))
		written <- result{werr, time.Since(start)}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// A client that grants no window, so the write waits for credit that never comes.
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	_, err = raw.Write([]byte(http2.ClientPreface))
	require.NoError(t, err)
	fr := http2.NewFramer(raw, raw)
	require.NoError(t, fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}))
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	require.NoError(t, enc.WriteField(hpack.HeaderField{Name: ":method", Value: http.MethodConnect}))
	require.NoError(t, enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "example.test:443"}))
	require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: buf.Bytes(), EndHeaders: true}))
	go func() {
		for {
			if _, rerr := fr.ReadFrame(); rerr != nil {
				return
			}
		}
	}()

	select {
	case r := <-written:
		assert.Error(t, r.err, "a write the reset discarded reports success")
		assert.GreaterOrEqual(t, r.took, 100*time.Millisecond)
	case <-time.After(3 * time.Second):
		t.Fatal("the write stayed blocked past its deadline")
	}
}

func TestH2Stream_WriteBlockedPastItsDeadlineReturns(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
	w := &blockedWriter{ResponseWriter: httptest.NewRecorder(), reset: make(chan struct{}), writing: make(chan struct{})}
	s := newH2Stream(w, httptest.NewRequest(http.MethodConnect, "/", pr), nil, nil)

	const d = 50 * time.Millisecond
	start := time.Now()
	require.NoError(t, s.SetWriteDeadline(start.Add(d)))
	written := make(chan error, 1)
	go func() {
		_, err := s.Write([]byte("x"))
		written <- err
	}()
	select {
	case err := <-written:
		assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
		assert.GreaterOrEqual(t, time.Since(start), d, "the write was cut before its deadline")
	case <-time.After(2 * time.Second):
		t.Fatal("the write stayed blocked past its deadline")
	}
}

func TestTLSConn_NoCloseNotifyAfterAFailedWrite(t *testing.T) {
	server, client := tlsPipe(t)
	require.NoError(t, server.SetWriteDeadline(time.Now().Add(50*time.Millisecond)))
	_, err := server.Write([]byte("lost"))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	raw := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(client.socket.Conn)
		raw <- b
	}()
	start := time.Now()
	_ = server.Close()
	assert.Less(t, time.Since(start), alertWriteTimeout/2)
	assert.Empty(t, <-raw, "a close_notify followed a failed write")
}

type writeEntered struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *writeEntered) Write(b []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(b)
}

func TestTLSConn_CloseBoundsAnAlertOfTheReader(t *testing.T) {
	server, client := tlsPipe(t)
	alert := &writeEntered{Conn: server.socket.Conn, entered: make(chan struct{})}
	server.socket.Conn = alert
	read := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 1))
		read <- err
	}()
	// A record that does not decrypt, answered with bad_record_mac to a client that does not read.
	_, err := client.socket.Conn.Write(append([]byte{0x17, 0x03, 0x03, 0x00, 0x20}, make([]byte, 32)...))
	require.NoError(t, err)
	<-alert.entered

	closed := make(chan struct{})
	start := time.Now()
	go func() {
		_ = server.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(5 * alertWriteTimeout):
		t.Fatal("Close blocked behind the alert of the reader")
	}
	assert.Less(t, time.Since(start), 2*alertWriteTimeout)
	assert.Error(t, <-read)
}

func TestTLSConn_SetDeadlineKeepsTheBound(t *testing.T) {
	server, _ := tlsPipe(t)
	closed := make(chan time.Duration, 1)
	start := time.Now()
	go func() {
		_ = server.Close()
		closed <- time.Since(start)
	}()
	time.Sleep(200 * time.Millisecond)
	_ = server.SetDeadline(time.Now().Add(4 * alertWriteTimeout))
	assert.Less(t, <-closed, 2*alertWriteTimeout)
}

func TestTLSConn_LaterCloseKeepsTheBound(t *testing.T) {
	server, _ := tlsPipe(t)
	closed := make(chan time.Duration, 1)
	start := time.Now()
	go func() {
		_ = server.Close()
		closed <- time.Since(start)
	}()
	for range 2 {
		time.Sleep(400 * time.Millisecond)
		assert.ErrorIs(t, server.Close(), net.ErrClosed)
	}
	assert.Less(t, <-closed, alertWriteTimeout*3/2)
}

func TestTLSConn_LaterCloseReturnsAfterTheFirst(t *testing.T) {
	server, client := tlsPipe(t)
	go func() { _ = server.Close() }()
	// The first byte of the close_notify arrives, the rest waits for the peer to read.
	_, err := client.NetConn().Read(make([]byte, 1))
	require.NoError(t, err)
	start := time.Now()
	assert.ErrorIs(t, server.Close(), net.ErrClosed)
	assert.Greater(t, time.Since(start), alertWriteTimeout/2)
}

func TestTLSConn_CloseAfterARecordCutShortResetsTheSocket(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	leaf, err := ca.Leaf("pipe.test")
	require.NoError(t, err)
	a, b := tcpPair(t)
	server := tlsServer(a, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	client := tls.Client(b, &tls.Config{ServerName: "pipe.test", RootCAs: ca.CertPool()})
	handshake := make(chan error, 1)
	go func() { handshake <- client.Handshake() }()
	require.NoError(t, server.Handshake())
	require.NoError(t, <-handshake)

	// The client reads nothing, so the socket fills inside a record.
	require.NoError(t, server.SetWriteDeadline(time.Now().Add(200*time.Millisecond)))
	_, err = server.Write(make([]byte, 16<<20))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.True(t, server.socket.cut.Load(), "the record was cut short")
	_ = server.Close()
	assert.Equal(t, "RST", peerEnd(b, 3*time.Second))
}

// handshakenTLS returns a TLS server of the proxy and a client over a TCP pair, past a
// handshake of version at most, and the socket of the client.
func handshakenTLS(t *testing.T, version uint16) (*tlsConn, *tls.Conn, *net.TCPConn) {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	leaf, err := ca.Leaf("pipe.test")
	require.NoError(t, err)
	a, b := tcpPair(t)
	server := tlsServer(a, &tls.Config{Certificates: []tls.Certificate{*leaf}, SessionTicketsDisabled: true})
	client := tls.Client(b, &tls.Config{ServerName: "pipe.test", RootCAs: ca.CertPool(), MaxVersion: version})
	handshake := make(chan error, 1)
	go func() { handshake <- client.Handshake() }()
	require.NoError(t, server.Handshake())
	require.NoError(t, <-handshake)
	return server, client, b
}

func TestTLSConn_CloseWriteHalfClosesOnTLS13Alone(t *testing.T) {
	t.Run("TLS 1.3", func(t *testing.T) {
		server, client, socket := handshakenTLS(t, tls.VersionTLS13)
		require.NoError(t, server.CloseWrite())
		require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, err := client.Read(make([]byte, 1))
		require.ErrorIs(t, err, io.EOF, "no close_notify")
		_, err = socket.Read(make([]byte, 1))
		require.ErrorIs(t, err, io.EOF, "no FIN after the close_notify")

		_, err = client.Write([]byte("up"))
		require.NoError(t, err)
		got := make([]byte, 2)
		require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, err = io.ReadFull(server, got)
		require.NoError(t, err)
		assert.Equal(t, "up", string(got), "the half-close ended the other direction")
	})
	t.Run("TLS 1.2", func(t *testing.T) {
		server, client, _ := handshakenTLS(t, tls.VersionTLS12)
		require.NoError(t, server.CloseWrite())
		require.NoError(t, client.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
		_, err := client.Read(make([]byte, 1))
		require.ErrorIs(t, err, os.ErrDeadlineExceeded, "a close_notify ends a TLS 1.2 connection")
	})
}

func TestEndCopy_RelaysAFINWithoutCloseNotifyAsSuch(t *testing.T) {
	for _, notify := range []bool{true, false} {
		t.Run(map[bool]string{true: "close_notify", false: "FIN alone"}[notify], func(t *testing.T) {
			src, srcClient, srcSocket := handshakenTLS(t, tls.VersionTLS13)
			dst, _, dstSocket := handshakenTLS(t, tls.VersionTLS13)
			if notify {
				require.NoError(t, srcClient.CloseWrite())
			} else {
				require.NoError(t, srcSocket.CloseWrite())
			}
			require.NoError(t, src.SetReadDeadline(time.Now().Add(5*time.Second)))
			_, err := io.ReadAll(src)
			require.NoError(t, err)

			endCopy(src, dst, nil)
			_ = dst.Close()
			require.NoError(t, dstSocket.SetReadDeadline(time.Now().Add(5*time.Second)))
			rest, err := io.ReadAll(dstSocket)
			require.NoError(t, err)
			assert.Equal(t, notify, len(rest) > 0, "%d bytes before the FIN", len(rest))
		})
	}
}

func TestBoundedTLSConn_CloseIsBounded(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "write blocked", true: "write failed"}[failed], func(t *testing.T) {
			ca, err := GenerateCA()
			require.NoError(t, err)
			leaf, err := ca.Leaf("pipe.test")
			require.NoError(t, err)
			a, b := tcpPair(t)
			server := &boundedTLSConn{Conn: tls.Server(a, &tls.Config{Certificates: []tls.Certificate{*leaf}}), done: make(chan struct{})}
			client := tls.Client(b, &tls.Config{ServerName: "pipe.test", RootCAs: ca.CertPool()})
			handshake := make(chan error, 1)
			go func() { handshake <- client.Handshake() }()
			require.NoError(t, server.Handshake())
			require.NoError(t, <-handshake)
			if failed {
				require.NoError(t, server.SetWriteDeadline(time.Unix(1, 0)))
				_, err = server.Write([]byte("lost"))
				require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			} else {
				go func() { _, _ = server.Write(make([]byte, 64<<20)) }()
				time.Sleep(200 * time.Millisecond)
			}
			start := time.Now()
			require.NoError(t, server.Close())
			assert.Less(t, time.Since(start), 3*alertWriteTimeout/2)
			if failed {
				assert.Equal(t, "RST", peerEnd(b, 3*time.Second))
			}
		})
	}
}

func TestConn_AbortAfterFlushWaitsThroughTheFrontWrappers(t *testing.T) {
	for name, wrap := range map[string]func(net.Conn) net.Conn{
		"raw":                  func(c net.Conn) net.Conn { return c },
		"peek(cancel)":         func(c net.Conn) net.Conn { return newPeekConn(&cancelConn{Conn: c}, nil, 16) },
		"peek(scheme(cancel))": func(c net.Conn) net.Conn { return newPeekConn(newSchemeConn(&cancelConn{Conn: c}, 1024), nil, 16) },
	} {
		t.Run(name, func(t *testing.T) {
			b, peer := tcpPair(t)
			// A fixed receive buffer stops the stack from growing the window that drains the queue.
			require.NoError(t, peer.SetReadBuffer(4<<10))
			writeUntilFull(b)
			start := time.Now()
			abortAfterFlush(wrap(b))
			assert.GreaterOrEqual(t, time.Since(start), alertWriteTimeout*9/10)
		})
	}
}

func TestConn_NormalEndAfterATLSRecordCutShortResetsTheSocket(t *testing.T) {
	server, _, socket := handshakenTLS(t, tls.VersionTLS13)
	// The client reads nothing, so the socket fills inside a record.
	require.NoError(t, server.SetWriteDeadline(time.Now().Add(200*time.Millisecond)))
	_, err := server.Write(make([]byte, 16<<20))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.True(t, server.socket.cut.Load(), "the record was cut short")
	closeNormally(server)
	assert.Equal(t, "RST", peerEnd(socket, 3*time.Second))
}

func TestConn_SocketOfReachesThroughEveryWrapper(t *testing.T) {
	a, _ := tcpPair(t)
	for name, wrap := range map[string]func(net.Conn) net.Conn{
		"peek":        func(c net.Conn) net.Conn { return newPeekConn(c, nil, 16) },
		"held":        func(c net.Conn) net.Conn { return &heldConn{Conn: c} },
		"buffered":    func(c net.Conn) net.Conn { return bufferedConn{Conn: c} },
		"served":      func(c net.Conn) net.Conn { return &servedConn{Conn: c} },
		"tlsServed":   func(c net.Conn) net.Conn { return &tlsServedConn{servedConn: &servedConn{Conn: c}} },
		"cancel":      func(c net.Conn) net.Conn { return &cancelConn{Conn: c} },
		"transparent": func(c net.Conn) net.Conn { return transparentConn{Conn: c} },
		"throttled":   func(c net.Conn) net.Conn { return Throttled(c, 0) },
		"own":         func(c net.Conn) net.Conn { return &ownConn{Conn: c} },
		"gated":       func(c net.Conn) net.Conn { return &gatedConn{Conn: c} },
		"normalEnd":   func(c net.Conn) net.Conn { return normalEnd{Conn: c} },
		"scheme":      func(c net.Conn) net.Conn { return &schemeConn{Conn: c} },
		"pipe":        func(c net.Conn) net.Conn { return pipeConn{raw: c} },
		"tls":         func(c net.Conn) net.Conn { return &tlsConn{socket: tlsSocket{Conn: c}} },
		"nested":      func(c net.Conn) net.Conn { return &heldConn{Conn: transparentConn{Conn: Throttled(c, 0)}} },
	} {
		t.Run(name, func(t *testing.T) {
			assert.Same(t, a, socketOf(wrap(a)))
		})
	}
}

func TestConn_AbortAfterFlushWaitsForTheQueueThroughAWrapper(t *testing.T) {
	for name, wrap := range map[string]func(net.Conn) net.Conn{
		"plain":       func(c net.Conn) net.Conn { return c },
		"transparent": func(c net.Conn) net.Conn { return transparentConn{Conn: c} },
		"throttled":   func(c net.Conn) net.Conn { return Throttled(c, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			b, peer := tcpPair(t)
			if _, err := netutil.UnsentBytes(b); errors.Is(err, errors.ErrUnsupported) {
				t.Skip("the platform reports no send queue")
			}
			// A fixed receive buffer stops the stack from growing the window that drains the queue.
			require.NoError(t, peer.SetReadBuffer(4<<10))
			writeUntilFull(b)
			start := time.Now()
			abortAfterFlush(wrap(b))
			assert.GreaterOrEqual(t, time.Since(start), alertWriteTimeout*9/10, "the queue was dropped while it held bytes")
		})
	}
}

func TestTLSConn_FailedWriteWithNothingWrittenEndsWithAFIN(t *testing.T) {
	a, aPeer := tcpPair(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	leaf, err := ca.Leaf("svc.test")
	require.NoError(t, err)
	srv := tlsServer(a, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	cli := tls.Client(aPeer, &tls.Config{InsecureSkipVerify: true, ServerName: "svc.test"})
	errc := make(chan error, 1)
	go func() { errc <- cli.Handshake() }()
	require.NoError(t, srv.Handshake())
	require.NoError(t, <-errc)

	_ = srv.SetWriteDeadline(time.Unix(1, 0))
	n, werr := srv.Write([]byte("x"))
	require.Error(t, werr)
	require.Zero(t, n)
	go closeNormally(srv)
	_ = aPeer.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, rerr := io.Copy(io.Discard, aPeer)
	assert.NoError(t, rerr, "the peer reads a FIN")
}

func TestPeekConn_LateClientHelloAfterATimedOutRead(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithSniffTimeout(200*time.Millisecond))
	require.NoError(t, err)
	read := make(chan error, 2)
	p.MustAdd[TCP]("svc.test:443", func(c *TCPCtx) error {
		_ = c.Client().SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		_, rerr := c.Client().Read(make([]byte, 1))
		read <- rerr
		_ = c.Client().SetReadDeadline(time.Time{})
		b := make([]byte, 9)
		_, rerr = io.ReadFull(c.Client(), b)
		if rerr == nil && b[0] == 0x16 {
			rerr = errors.New("the handler read a ClientHello in the clear")
		}
		read <- rerr
		return rerr
	})
	conn := connectRaw(t, startProxy(t, p), "svc.test:443")
	time.Sleep(400 * time.Millisecond)
	_, err = conn.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00})
	require.NoError(t, err)
	first, second := <-read, <-read
	t.Logf("first read %v, second read %v", first, second)
	if !errors.Is(second, errLateClientHello) {
		t.Errorf("the late ClientHello reached the handler: %v", second)
	}
}

func TestPeekConn_LateHelloShortRecordThenFIN(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithSniffTimeout(100*time.Millisecond))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	type result struct {
		zeroReads int
		err       error
	}
	res := make(chan result, 1)
	p.MustAdd[TCP]("svc.test:25", func(c *TCPCtx) error {
		buf := make([]byte, 64)
		zero := 0
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			n, rerr := c.Client().Read(buf)
			if rerr != nil {
				res <- result{zero, rerr}
				return nil
			}
			if n == 0 {
				zero++
			}
		}
		res <- result{zero, errors.New("no end within 2s")}
		return nil
	})
	conn := connectRaw(t, startProxy(t, p), "svc.test:25")
	time.Sleep(300 * time.Millisecond)
	_, err = conn.Write([]byte{0x16, 0x03})
	require.NoError(t, err)
	require.NoError(t, conn.(*net.TCPConn).CloseWrite())
	r := <-res
	t.Logf("reads of 0 bytes with no error: %d, end: %v", r.zeroReads, r.err)
	assert.Zero(t, r.zeroReads)
	assert.NotEqual(t, "no end within 2s", r.err.Error())
}

func TestPeekConn_LateHelloShortRecordThenFINUnderRelay(t *testing.T) {
	origin, upstream := oneConnOrigin(t)
	ca, err := GenerateCA()
	require.NoError(t, err)
	p, err := New(WithCA(ca), WithSniffTimeout(100*time.Millisecond))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	p.MustAdd[TCP](origin, func(c *TCPCtx) error { return c.Relay() })
	conn := connectRaw(t, startProxy(t, p), origin)
	up := <-upstream
	time.Sleep(300 * time.Millisecond)
	var before, after syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &before)
	_, err = conn.Write([]byte{0x16, 0x03})
	require.NoError(t, err)
	require.NoError(t, conn.(*net.TCPConn).CloseWrite())
	_ = up.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, rerr := io.ReadAll(up)
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &after)
	cpu := time.Duration(after.Utime.Nano() + after.Stime.Nano() - before.Utime.Nano() - before.Stime.Nano())
	t.Logf("origin read %x, end %v, process CPU over the wait %v", got, rerr, cpu)
	assert.NoError(t, rerr, "the client's half-close never reached the origin")
}

// tlsFrontPair returns the client of a TLS front connection and that connection, the client
// having read the session tickets.
func tlsFrontPair(t *testing.T) (*tls.Conn, *tlsConn) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	tl := tlsListener{Listener: cancelListener{ln}, cfg: &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS13}}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := tl.Accept()
		_ = c.(*tlsConn).Handshake()
		accepted <- c
	}()
	client, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: poolOf(ca), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
	require.NoError(t, err)
	server := (<-accepted).(*tlsConn)
	t.Cleanup(func() { _ = server.Close() })
	_, err = server.Write([]byte("hello"))
	require.NoError(t, err)
	_, err = io.ReadFull(client, make([]byte, 5))
	require.NoError(t, err)
	return client, server
}

func TestTLSConn_CloseNotifyReadFirstKeepsTheNormalEndOfItsSocket(t *testing.T) {
	client, server := tlsFrontPair(t)
	require.NoError(t, client.Close())
	_, err := server.Read(make([]byte, 16))
	require.ErrorIs(t, err, io.EOF)
	// The client socket is gone, so the late write or the close_notify of the close draws its RST.
	_, _ = server.Write([]byte("late"))
	time.Sleep(50 * time.Millisecond)
	_ = server.Close()
	require.Equal(t, peerClean, peerEndOf(server))
	require.Equal(t, causePeer, cancelConnOf(server).causeOfEnd())
}

func TestTLSConn_RefusedWriteBeforeTheCloseNotifyReadFailsItsSocket(t *testing.T) {
	client, server := tlsFrontPair(t)
	_, err := server.Write([]byte("unread"))
	require.NoError(t, err)
	time.Sleep(20 * time.Millisecond)
	// Closed with bytes unread, the client socket resets the connection.
	require.NoError(t, client.Close())
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err = server.Write([]byte("x")); err != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	require.Error(t, err)
	_, _ = server.Read(make([]byte, 16))
	require.Equal(t, peerFailed, peerEndOf(server))
	require.Equal(t, causePeerFailed, cancelConnOf(server).causeOfEnd())
}

func TestTLSConn_FINInsideARecordFailsItsSocket(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	tl := tlsListener{Listener: cancelListener{ln}, cfg: &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS13}}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := tl.Accept()
		_ = c.(*tlsConn).Handshake()
		accepted <- c
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer raw.Close()
	client := tls.Client(raw, &tls.Config{RootCAs: poolOf(ca), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
	require.NoError(t, client.Handshake())
	server := <-accepted
	defer server.Close()

	// A record header announcing 32 bytes, 3 of them sent, then the FIN.
	_, err = raw.Write([]byte{0x17, 0x03, 0x03, 0x00, 0x20, 1, 2, 3})
	require.NoError(t, err)
	require.NoError(t, raw.(*net.TCPConn).CloseWrite())
	_, err = server.Read(make([]byte, 64))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, peerFailed, peerEndOf(server))
	require.Equal(t, causePeerFailed, cancelConnOf(server).causeOfEnd())
}

func TestBoundedTLSConn_WriteAfterItsOwnHalfCloseIsNoEndOfItsPeer(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS13})
	require.NoError(t, err)
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := cancelListener{ln}.Accept()
		_ = c.(*boundedTLSConn).Handshake()
		accepted <- c
	}()
	client, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: poolOf(ca), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
	require.NoError(t, err)
	defer client.Close()
	server := (<-accepted).(*boundedTLSConn)
	defer server.Close()
	go func() { _, _ = io.Copy(io.Discard, client) }()

	require.NoError(t, server.CloseWrite())
	_, err = server.Write([]byte("x"))
	require.Error(t, err)
	require.Equal(t, causeReturned, server.causeOfEnd())
}

func TestSessionCancel_KernelTimeoutIsTheFailedEndOfThePeer(t *testing.T) {
	for _, op := range []string{"read", "write"} {
		t.Run(op, func(t *testing.T) {
			err := &net.OpError{Op: op, Net: "tcp", Err: os.NewSyscallError(op, syscall.ETIMEDOUT)}
			var s sessionCancel
			if op == "read" {
				s.noteRead(err)
			} else {
				s.noteWrite(err)
			}
			require.Equal(t, causePeerFailed, s.causeOfEnd())
		})
	}
}

func TestCancelConn_FailedWriteIsTheFailedEndOfItsPeerBeforeItsHalfCloseAlone(t *testing.T) {
	for _, halfClosed := range []bool{false, true} {
		t.Run("half-closed "+strconv.FormatBool(halfClosed), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()
			accepted := make(chan net.Conn, 1)
			go func() {
				c, _ := cancelListener{ln}.Accept()
				accepted <- c
			}()
			client, err := net.Dial("tcp", ln.Addr().String())
			require.NoError(t, err)
			server := (<-accepted).(*cancelConn)
			defer server.Close()
			if halfClosed {
				require.NoError(t, server.CloseWrite())
			}
			lingerZero(client)
			require.NoError(t, client.Close())

			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if _, err = server.Write([]byte("x")); err != nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
			require.Error(t, err)
			want := causePeerFailed
			if halfClosed {
				want = causeReturned
			}
			require.Equal(t, want, server.causeOfEnd(), "%v", err)
		})
	}
}

func TestTLSConn_TerminatedOverAFrontSocketSharesItsRecord(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)
	cert, err := ca.Leaf("127.0.0.1")
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	cfg := &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS13}
	accepted := make(chan *tlsConn, 1)
	sockets := make(chan *cancelConn, 1)
	go func() {
		c, _ := cancelListener{ln}.Accept()
		sockets <- c.(*cancelConn)
		tc := tlsServer(newPeekConn(c, nil, 1), cfg)
		_ = tc.Handshake()
		accepted <- tc
	}()
	client, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: poolOf(ca), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13})
	require.NoError(t, err)
	server, socket := <-accepted, <-sockets
	defer server.Close()
	_, err = server.Write([]byte("hello"))
	require.NoError(t, err)
	_, err = io.ReadFull(client, make([]byte, 5))
	require.NoError(t, err)

	_, err = server.Write([]byte("unread"))
	require.NoError(t, err)
	time.Sleep(20 * time.Millisecond)
	// Closed with bytes unread, the client socket resets the connection.
	require.NoError(t, client.Close())
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err = server.Write([]byte("x")); err != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	require.Error(t, err)
	_, _ = server.Read(make([]byte, 16))
	require.Equal(t, peerFailed, peerEndOf(server))
	require.Equal(t, causePeerFailed, socket.causeOfEnd())
}

// onceErrConn returns its errors one per read, then io.EOF, as a socket reports a pending error
// once.
type onceErrConn struct {
	net.Conn
	errs []error
}

func (c *onceErrConn) Read([]byte) (int, error) {
	if len(c.errs) == 0 {
		return 0, io.EOF
	}
	err := c.errs[0]
	c.errs = c.errs[1:]
	return 0, err
}

func TestPeekConn_ReadReturnsTheErrorOfAPeek(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ECONNRESET, syscall.ETIMEDOUT} {
		for _, lateHello := range []bool{false, true} {
			t.Run(errno.Error()+" late hello "+strconv.FormatBool(lateHello), func(t *testing.T) {
				failure := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", errno)}
				c := newPeekConn(&onceErrConn{errs: []error{failure}}, nil, 6)
				c.lateHello = lateHello
				if !lateHello {
					_, err := c.Peek(1)
					require.ErrorIs(t, err, errno)
				}
				_, err := c.Read(make([]byte, 16))
				require.ErrorIs(t, err, errno)
				_, err = c.Read(make([]byte, 16))
				require.ErrorIs(t, err, io.EOF)
			})
		}
	}
}
