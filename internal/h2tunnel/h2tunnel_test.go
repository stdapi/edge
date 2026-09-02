// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package h2tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	c, err := Client(tc)
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

// Streams echo what they carry, several at once, and bytes past the frame size and both
// windows come back intact.
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

// A read deadline is a timeout, not the end of the stream.
func TestStream_ReadDeadline(t *testing.T) {
	srv := echoServer(t, nil)
	c := dial(t, srv)
	s, _ := open(t, c, nil)
	require.NoError(t, s.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, err := s.Read(make([]byte, 1))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.NoError(t, s.SetReadDeadline(time.Time{}))
	_, err = s.Write([]byte("after"))
	require.NoError(t, err)
	buf := make([]byte, 8)
	n, err := s.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "after", string(buf[:n]))
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
	require.ErrorIs(t, err, errClosed)
	_, err = s.Write([]byte("x"))
	require.ErrorIs(t, err, errClosed)
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

// A peer that is not HTTP/2 at all ends the connection with an error rather than a hang.
func TestConn_NotHTTP2(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		_ = conn.Close()
	}()
	nc, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	c, err := Client(nc)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err = c.Open(ctx, Request{Authority: "origin.test:443"})
	require.Error(t, err)
	require.False(t, errors.Is(err, context.DeadlineExceeded))
}
