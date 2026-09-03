// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package h2tunnel

import (
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A contract case is one sentence of the net.Conn or io.Reader documentation checked on a
// Stream, the contract the datagram flow of a tunnel relies on through capsulePipe.
type contractCase struct {
	name string
	// req is the requirement in the words of the standard library.
	req string
	run func(t *testing.T)
}

func TestNetConn(t *testing.T) {
	for _, tc := range contract {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t)
		})
	}
}

var contract = []contractCase{
	{
		name: "a read deadline is a timeout, not the end",
		req:  "Read can be made to time out and return an error after a fixed time limit; see SetDeadline and SetReadDeadline. A zero value for t means Read will not time out.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, id := p.connect()
			require.NoError(t, s.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
			_, err := s.Read(make([]byte, 1))
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			require.NoError(t, s.SetReadDeadline(time.Time{}))
			p.writeData(id, false, []byte("after"))
			p.wantRead(s, []byte("after"))
		},
	},
	{
		name: "a Read past its deadline fails with bytes buffered",
		req:  "A deadline is an absolute time after which I/O operations fail instead of blocking.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, id := p.connect()
			p.writeData(id, false, []byte("buffered"))
			require.Eventually(t, func() bool {
				s.mu.Lock()
				defer s.mu.Unlock()
				return len(s.chunks) > 0
			}, wantTimeout, 5*time.Millisecond)
			require.NoError(t, s.SetReadDeadline(time.Now().Add(-time.Second)))
			_, err := s.Read(make([]byte, 16))
			require.ErrorIs(t, err, os.ErrDeadlineExceeded, "a Read past its deadline returned data")
		},
	},
	{
		name: "a read deadline set while a Read is blocked ends it at that time",
		req:  "SetReadDeadline sets the deadline for future Read calls and any currently-blocked Read call.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, _ := p.connect()
			read := make(chan error, 1)
			go func() {
				_, err := s.Read(make([]byte, 16))
				read <- err
			}()
			time.Sleep(200 * time.Millisecond)
			require.NoError(t, s.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
			select {
			case err := <-read:
				require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			case <-time.After(wantTimeout):
				t.Fatal("a deadline set while the read was blocked did not end it")
			}
		},
	},
	{
		name: "a read deadline wakes every pending Read",
		req:  "The deadline applies to all future and pending I/O, not just the immediately following call to Read or Write.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, _ := p.connect()
			var wg sync.WaitGroup
			for range 2 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, _ = s.Read(make([]byte, 1))
				}()
			}
			time.Sleep(300 * time.Millisecond)
			require.NoError(t, s.SetReadDeadline(time.Now().Add(-time.Second)))
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(wantTimeout):
				t.Fatal("a pending Read outlived a deadline already past")
			}
		},
	},
	{
		name: "the peer's end wakes every pending Read with EOF",
		req:  "When Read encounters an error or end-of-file condition after successfully reading n > 0 bytes, it returns the number of bytes read. ... Callers should always process the n > 0 bytes returned before considering the error err.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, id := p.connect()
			errs := make(chan error, 2)
			for range 2 {
				go func() {
					_, err := s.Read(make([]byte, 1))
					errs <- err
				}()
			}
			time.Sleep(300 * time.Millisecond)
			p.writeData(id, true, nil)
			for range 2 {
				select {
				case err := <-errs:
					require.ErrorIs(t, err, io.EOF)
				case <-time.After(wantTimeout):
					t.Fatal("a pending Read outlived the peer's END_STREAM")
				}
			}
		},
	},
	{
		name: "Read with an empty buffer returns at once",
		req:  "Implementations of Read are discouraged from returning a zero byte count with a nil error, except when len(p) == 0.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, _ := p.connect()
			done := make(chan struct{})
			go func() {
				n, err := s.Read(nil)
				assert.Zero(t, n)
				assert.NoError(t, err)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(wantTimeout):
				t.Fatal("Read with a zero-length buffer never returned")
			}
		},
	},
	{
		name: "Read after Stream.Close fails",
		req:  "Close closes the connection. Any blocked Read or Write operations will be unblocked and return errors.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, id := p.connect()
			p.writeData(id, false, []byte("buffered"))
			require.Eventually(t, func() bool {
				s.mu.Lock()
				defer s.mu.Unlock()
				return len(s.chunks) > 0
			}, wantTimeout, 5*time.Millisecond)
			require.NoError(t, s.Close())
			buf := make([]byte, 16)
			n, err := s.Read(buf)
			require.ErrorIs(t, err, errStreamClosed, "Read after Close returned %d bytes: %q", n, buf[:n])
		},
	},
	{
		name: "Read after Conn.Close fails",
		req:  "Close closes the connection. Any blocked Read or Write operations will be unblocked and return errors.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, id := p.connect()
			p.writeData(id, false, []byte("buffered"))
			require.Eventually(t, func() bool {
				s.mu.Lock()
				defer s.mu.Unlock()
				return len(s.chunks) > 0
			}, wantTimeout, 5*time.Millisecond)
			require.NoError(t, p.c.Close())
			buf := make([]byte, 16)
			n, err := s.Read(buf)
			require.ErrorIs(t, err, net.ErrClosed, "Read after Conn.Close returned %d bytes: %q", n, buf[:n])
		},
	},
	{
		name: "a stream the peer ended drains to EOF through Close",
		req:  "When Read encounters an error or end-of-file condition after successfully reading n > 0 bytes, it returns the number of bytes read.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, id := p.connect()
			p.writeData(id, true, []byte("buffered"))
			require.Eventually(t, func() bool {
				s.mu.Lock()
				defer s.mu.Unlock()
				return len(s.chunks) > 0 && s.readErr != nil
			}, wantTimeout, 5*time.Millisecond)
			require.NoError(t, s.Close())
			p.wantRead(s, []byte("buffered"))
			p.wantReadError(s, io.EOF)
		},
	},
	{
		name: "a write deadline ends a Write behind a stuck writer",
		req:  "Write can be made to time out and return an error after a fixed time limit; see SetDeadline and SetWriteDeadline.",
		run: func(t *testing.T) {
			_, streams := stuckPeer(t, 2)
			s := streams[1]
			require.NoError(t, s.SetWriteDeadline(time.Now().Add(200*time.Millisecond)))
			start := time.Now()
			_, err := s.Write([]byte("late"))
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			assert.Less(t, time.Since(start), time.Second, "Write outlived its deadline behind the stuck writer")
		},
	},
	{
		name: "a write deadline set while a Write is blocked ends it",
		req:  "SetWriteDeadline sets the deadline for future Write calls and any currently-blocked Write call.",
		run: func(t *testing.T) {
			_, streams := stuckPeer(t, 2)
			s := streams[1]
			wrote := make(chan error, 1)
			go func() {
				_, err := s.Write(make([]byte, 8<<20))
				wrote <- err
			}()
			time.Sleep(300 * time.Millisecond)
			require.NoError(t, s.SetWriteDeadline(time.Now().Add(200*time.Millisecond)))
			select {
			case err := <-wrote:
				require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			case <-time.After(wantTimeout):
				t.Fatal("a deadline set while the write was blocked did not end it")
			}
		},
	},
	{
		name: "a Write past its deadline sends nothing and keeps the windows",
		req:  "If the deadline is exceeded a call to Read or Write or to other I/O methods will return an error that wraps os.ErrDeadlineExceeded. ... After a deadline has been exceeded, the connection can be refreshed by setting a deadline in the future.",
		run: func(t *testing.T) {
			p := newPeer(t)
			s, id := p.connect()
			var conn, stream int64
			p.c.onLoop(func() { conn, stream = p.c.sendWindow, s.sendWindow })
			require.NoError(t, s.SetWriteDeadline(time.Now().Add(-time.Second)))
			for range 100 {
				_, err := s.Write(make([]byte, 1000))
				require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			}
			require.NoError(t, s.SetWriteDeadline(time.Time{}))
			_, err := s.Write([]byte("drain"))
			require.NoError(t, err)
			require.Equal(t, "drain", string(p.wantData(id).Data()))
			var connNow, streamNow int64
			p.c.onLoop(func() { connNow, streamNow = p.c.sendWindow, s.sendWindow })
			assert.Equal(t, conn-5, connNow, "the connection send window lost what the skipped frames took")
			assert.Equal(t, stream-5, streamNow, "the stream send window lost what the skipped frames took")
		},
	},
	{
		name: "a Write the deadline cuts mid-way ends the stream",
		req:  "Even if write times out, it may return n > 0, indicating that some of the data was successfully written. A byte stream that lost track of what left cannot go on.",
		run: func(t *testing.T) {
			_, streams := silentPeer(t, 1, false)
			s := streams[0]
			require.NoError(t, s.SetWriteDeadline(time.Now().Add(300*time.Millisecond)))
			_, err := s.Write(make([]byte, 8<<20))
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			require.NoError(t, s.SetWriteDeadline(time.Time{}))
			_, err = s.Write([]byte("more"))
			require.Error(t, err)
			require.NotErrorIs(t, err, os.ErrDeadlineExceeded, "the stream went on after a frame it lost track of")
		},
	},
	{
		name: "a Write cut by Stream.Close reports what left",
		req:  "Even if write times out, it may return n > 0, indicating that some of the data was successfully written.",
		run: func(t *testing.T) {
			_, streams := silentPeer(t, 1, false)
			wantCutWriteReported(t, streams[0], streams[0].Close)
		},
	},
	{
		name: "a Write cut by Conn.Close reports what left",
		req:  "Even if write times out, it may return n > 0, indicating that some of the data was successfully written.",
		run: func(t *testing.T) {
			c, streams := silentPeer(t, 1, false)
			wantCutWriteReported(t, streams[0], c.Close)
		},
	},
	{
		name: "a bufio.Reader across read deadlines loses and repeats nothing",
		req:  "An idle timeout can be implemented by repeatedly extending the deadline after successful Read or Write calls. The read path of a tunnel resets the deadline at every idle period over a bufio.Reader.",
		run: func(t *testing.T) {
			srv := echoServer(t, nil)
			c := dial(t, srv)
			s, _ := open(t, c, nil)
			t.Cleanup(func() { _ = s.Close() })
			const records = 400
			go func() {
				for i := range records {
					// One record: a two byte length, then that many bytes of the record's index.
					body := make([]byte, 1+i%97)
					for j := range body {
						body[j] = byte(i)
					}
					hdr := []byte{byte(len(body) >> 8), byte(len(body))}
					if _, err := s.Write(append(hdr, body...)); err != nil {
						return
					}
					time.Sleep(time.Millisecond)
				}
			}()
			br := newBufioReader(s)
			deadline := time.Now().Add(30 * time.Second)
			for i := range records {
				var hdr [2]byte
				for {
					_ = s.SetReadDeadline(time.Now().Add(3 * time.Millisecond))
					n, err := io.ReadFull(br, hdr[:])
					if err == nil {
						break
					}
					require.ErrorIs(t, err, os.ErrDeadlineExceeded, "record %d header after %d bytes", i, n)
					require.True(t, time.Now().Before(deadline), "the reader never got past record %d", i)
					// io.ReadFull loses what it read on a short read, so only a clean cut may resume.
					require.Zero(t, n, "a read deadline cut a header in half at record %d", i)
				}
				want := int(hdr[0])<<8 | int(hdr[1])
				body := make([]byte, want)
				for got := 0; got < want; {
					_ = s.SetReadDeadline(time.Now().Add(3 * time.Millisecond))
					n, err := io.ReadFull(br, body[got:])
					got += n
					if err != nil {
						require.ErrorIs(t, err, os.ErrDeadlineExceeded, "record %d body", i)
						require.True(t, time.Now().Before(deadline), "the reader never finished record %d", i)
					}
				}
				for j := range body {
					require.Equal(t, byte(i), body[j], "record %d is not what was written", i)
				}
			}
		},
	},
}

// wantCutWriteReported starts a write the peer never drains, cuts it with close and wants
// the count of what left.
func wantCutWriteReported(t *testing.T, s *Stream, close func() error) {
	t.Helper()
	wrote := make(chan writeResult, 1)
	go func() {
		n, err := s.Write(make([]byte, 8<<20))
		wrote <- writeResult{n: n, err: err}
	}()
	time.Sleep(500 * time.Millisecond)
	require.NoError(t, close())
	select {
	case r := <-wrote:
		require.Error(t, r.err)
		assert.Greater(t, r.n, 0, "Write reported 0 bytes though its frames left the socket")
	case <-time.After(wantTimeout):
		t.Fatal("the write outlived the close")
	}
}
