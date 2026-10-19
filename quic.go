// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICCtx is one terminated QUIC connection, handed to a [QUIC] handler. It is not safe for
// concurrent use. A connection that negotiated h3 is served as HTTP and never reaches a QUIC
// handler.
type QUICCtx struct {
	ctx       context.Context
	dialErr   error
	acceptErr error
	endErr    error

	p      *Proxy
	sess   *Session
	entry  *entry
	conn   *quic.Conn
	dialed *quic.Conn

	acceptCh     chan *QUICStream
	acceptCancel context.CancelFunc
	target       Target

	identity string
	params   []Param
	extra    []*quic.Conn

	// streams counts the streams being relayed, the messages in flight a peer end looks at. A
	// stream a handler serves itself has an end the proxy does not see, and is not counted.
	streams atomic.Int64

	dialOnce   sync.Once
	acceptOnce sync.Once
	endOnce    sync.Once
	// mu guards the origin legs against the closer, which ends them from another goroutine and
	// sets closed.
	mu     sync.Mutex
	closed bool
}

// Context returns a context canceled when the connection ends.
func (c *QUICCtx) Context() context.Context { return c.ctx }

// Session returns the session of this connection.
func (c *QUICCtx) Session() *Session { return c.sess }

// Target returns the authority the client was headed to.
func (c *QUICCtx) Target() Target { return c.target }

// Identity returns what the configured authenticator reported for this connection, or an
// empty string when none did.
func (c *QUICCtx) Identity() string { return c.identity }

// ALPN returns the application protocol negotiated with the client.
func (c *QUICCtx) ALPN() string { return c.conn.ConnectionState().TLS.NegotiatedProtocol }

// Conn returns the terminated client connection, for a handler that accepts and opens
// streams itself.
func (c *QUICCtx) Conn() *quic.Conn { return c.conn }

// Pattern returns the pattern of the matched entry.
func (c *QUICCtx) Pattern() string {
	if c.entry == nil {
		return ""
	}
	return c.entry.pattern.str
}

// Entry returns the matched entry.
func (c *QUICCtx) Entry() Entry[QUIC] { return Entry[QUIC]{e: c.entry} }

// Params returns an iterator over the parameters matched in the pattern.
func (c *QUICCtx) Params() iter.Seq[Param] { return slices.Values(c.params) }

// Param returns the value matched for the named parameter, or an empty string.
func (c *QUICCtx) Param(name string) string {
	for _, p := range c.params {
		if p.Key == name {
			return p.Value
		}
	}
	return ""
}

// Proxy returns the [Proxy] serving this connection.
func (c *QUICCtx) Proxy() *Proxy { return c.p }

// Dial opens the upstream connection and returns it. It dials once, and every later call
// returns the same connection. The upstream handshake uses the same server name and the same
// application protocol the proxy negotiated with the client, and an origin that rejects that
// protocol fails the dial. The connection is closed when the handler returns.
func (c *QUICCtx) Dial() (*quic.Conn, error) {
	c.dialOnce.Do(func() {
		conn, err := c.dialQUIC(c.ctx, c.upstreamAddr(), c.target.Host)
		if err == nil {
			err = c.keep(conn, &c.dialed)
		}
		c.dialErr = err
	})
	return c.dialed, c.dialErr
}

// DialTo opens a connection to addr, given as host:port, with the TLS parameters of
// [QUICCtx.Dial], the server name taken from addr. Set a dial timeout through ctx. Every call
// opens a new connection, closed when the handler returns.
func (c *QUICCtx) DialTo(ctx context.Context, addr string) (*quic.Conn, error) {
	if c.ctx.Err() != nil {
		// A dial after the end of the session opens nothing, I1.
		return nil, net.ErrClosed
	}
	// The closer of the session cancels a dial in progress, whatever ctx, I1.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("edge: dial %q: %w", addr, err)
	}
	conn, err := c.dialQUIC(ctx, addr, host)
	if err != nil {
		if c.ctx.Err() != nil {
			// The dial the closer canceled fails as any dial after it.
			return nil, net.ErrClosed
		}
		return nil, err
	}
	if err := c.keep(conn, nil); err != nil {
		return nil, err
	}
	return conn, nil
}

// keep records an origin leg, in *slot or among the extra legs when slot is nil, and ends it with
// an error once the closer has run.
func (c *QUICCtx) keep(conn *quic.Conn, slot **quic.Conn) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		// Off the lock, a close through a chained exit may wait.
		go func() { _ = closeFailed(conn) }()
		return net.ErrClosed
	}
	if slot != nil {
		*slot = conn
	} else {
		c.extra = append(c.extra, conn)
	}
	return nil
}

func (c *QUICCtx) upstreamAddr() string {
	if addr := c.sess.dialAddr(); addr != "" {
		return addr
	}
	return c.target.Authority()
}

func (c *QUICCtx) dialQUIC(ctx context.Context, addr, serverName string) (*quic.Conn, error) {
	cfg := c.p.cfg.transport.upstreamTLSConfig()
	cfg.MinVersion = tls.VersionTLS13
	cfg.ServerName = serverName
	if alpn := c.ALPN(); alpn != "" {
		cfg.NextProtos = []string{alpn}
	}
	conn, err := c.p.srv.fwd.up.dialQUIC(ctx, addr, cfg, &quic.Config{
		MaxIdleTimeout:  c.p.cfg.server.idleTimeout,
		EnableDatagrams: false,
	})
	if err != nil {
		return nil, fmt.Errorf("dial quic %s: %w", addr, err)
	}
	return conn, nil
}

// close releases the connections the handler opened, once the handler has returned.
func (c *QUICCtx) close() {
	if c.acceptCancel != nil {
		c.acceptCancel()
	}
	c.endLegs(false, time.Now().Add(alertWriteTimeout))
}

// endLegs ends every origin leg by deadline, with its failed end when failed, and refuses the
// later ones.
func (c *QUICCtx) endLegs(failed bool, deadline time.Time) {
	c.mu.Lock()
	c.closed = true
	legs := c.extra
	if c.dialed != nil {
		legs = append([]*quic.Conn{c.dialed}, legs...)
	}
	c.mu.Unlock()
	var wg sync.WaitGroup
	for _, conn := range legs {
		code := noErrorCode(conn)
		if failed {
			code = failedCode(conn)
		}
		wg.Go(func() { _ = closeQUIC(conn, code, deadline) })
	}
	wg.Wait()
}

// Accept returns the next stream opened by either peer, in either direction, and blocks until
// one is opened. The first call dials the upstream connection. It returns an error once the
// connection has ended.
//
//	var wg sync.WaitGroup
//	defer wg.Wait()
//	for {
//		st, err := q.Accept()
//		if err != nil {
//			return nil
//		}
//		wg.Go(func() { _ = st.Relay() })
//	}
func (c *QUICCtx) Accept() (*QUICStream, error) {
	c.acceptOnce.Do(c.startAccept)
	if c.acceptErr != nil {
		return nil, c.acceptErr
	}
	st, ok := <-c.acceptCh
	if !ok {
		if c.endErr != nil {
			return nil, c.endErr
		}
		return nil, net.ErrClosed
	}
	return st, nil
}

func (c *QUICCtx) startAccept() {
	upstream, err := c.Dial()
	if err != nil {
		c.acceptErr = err
		return
	}

	ctx, cancel := context.WithCancel(c.ctx)
	c.acceptCancel = cancel
	c.acceptCh = make(chan *QUICStream)

	var wg sync.WaitGroup
	// Each peer may open bidirectional and unidirectional streams, so four acceptors run.
	wg.Go(func() { c.acceptBidi(ctx, cancel, c.conn, upstream, false) })
	wg.Go(func() { c.acceptBidi(ctx, cancel, upstream, c.conn, true) })
	wg.Go(func() { c.acceptUni(ctx, cancel, c.conn, upstream, false) })
	wg.Go(func() { c.acceptUni(ctx, cancel, upstream, c.conn, true) })
	go func() {
		wg.Wait()
		close(c.acceptCh)
	}()
}

// recordEnd keeps the first error that ended the connection, for [QUICCtx.Accept] to return
// once the channel is closed.
func (c *QUICCtx) recordEnd(err error) {
	c.endOnce.Do(func() { c.endErr = err })
}

// acceptBidi accepts the bidirectional streams opened on from, to be opened on to.
func (c *QUICCtx) acceptBidi(ctx context.Context, cancel context.CancelFunc, from, to *quic.Conn, inbound bool) {
	for {
		src, err := from.AcceptStream(ctx)
		if err != nil {
			if cause := context.Cause(from.Context()); cause != nil {
				// The end of the connection, which the accept may have missed for the context.
				err = cause
			}
			// Accept fails once the connection has ended, and the peer connection is closed
			// with the same error. A context the proxy canceled leaves both ends to the proxy.
			ended := ctx.Err() != nil && c.ctx.Err() == nil
			c.recordEnd(err)
			cancel()
			if !ended {
				closePeer(to, err, &c.streams, inbound)
			}
			return
		}
		st := &QUICStream{streams: &c.streams,
			ctx: ctx, id: src.StreamID(), bidi: true, inbound: inbound, fail: quic.StreamErrorCode(failedCode(from)),
			src: src, srcW: src, open: func() (io.WriteCloser, io.Reader, error) {
				dst, derr := to.OpenStreamSync(ctx)
				if derr != nil {
					return nil, nil, derr
				}
				return dst, dst, nil
			},
		}
		select {
		case c.acceptCh <- st:
		case <-ctx.Done():
			return
		}
	}
}

// acceptUni accepts the unidirectional streams opened on from. The far side is opened for
// writing only.
func (c *QUICCtx) acceptUni(ctx context.Context, cancel context.CancelFunc, from, to *quic.Conn, inbound bool) {
	for {
		src, err := from.AcceptUniStream(ctx)
		if err != nil {
			if cause := context.Cause(from.Context()); cause != nil {
				// The end of the connection, which the accept may have missed for the context.
				err = cause
			}
			ended := ctx.Err() != nil && c.ctx.Err() == nil
			c.recordEnd(err)
			cancel()
			if !ended {
				closePeer(to, err, &c.streams, inbound)
			}
			return
		}
		st := &QUICStream{streams: &c.streams,
			ctx: ctx, id: src.StreamID(), bidi: false, inbound: inbound, fail: quic.StreamErrorCode(failedCode(from)),
			src: src, open: func() (io.WriteCloser, io.Reader, error) {
				dst, derr := to.OpenUniStreamSync(ctx)
				if derr != nil {
					return nil, nil, derr
				}
				return dst, nil, nil
			},
		}
		select {
		case c.acceptCh <- st:
		case <-ctx.Done():
			return
		}
	}
}

// Relay accepts every stream of the connection and relays each one until the connection
// ends.
func (c *QUICCtx) Relay() error {
	if _, err := c.Dial(); err != nil {
		return err
	}
	var wg sync.WaitGroup
	for {
		st, err := c.Accept()
		if err != nil {
			break
		}
		wg.Go(func() { _ = st.Relay() })
	}
	wg.Wait()
	return nil
}

// QUICStream is one stream of a terminated connection. Its content is not decoded. A stream
// the handler does not relay is never opened on the far side.
type QUICStream struct {
	ctx  context.Context
	src  io.Reader
	srcW io.WriteCloser

	dstW    io.WriteCloser
	dstR    io.Reader
	openErr error
	open    func() (io.WriteCloser, io.Reader, error)
	// streams is the count of its connection, which includes Relay while it runs.
	streams *atomic.Int64

	id quic.StreamID
	// fail is the code of the failed end of the stream, the one of its connection.
	fail quic.StreamErrorCode

	openOnce sync.Once
	bidi     bool
	inbound  bool
}

// ID returns the stream ID.
func (s *QUICStream) ID() quic.StreamID { return s.id }

// Bidirectional reports whether the stream is bidirectional.
func (s *QUICStream) Bidirectional() bool { return s.bidi }

// Inbound reports whether the origin opened the stream.
func (s *QUICStream) Inbound() bool { return s.inbound }

// Reader returns the receive side of the stream. A read consumes the bytes, which are then
// not relayed.
func (s *QUICStream) Reader() io.Reader { return s.src }

// Writer returns the send side toward the peer that opened the stream, or nil on a
// unidirectional stream.
func (s *QUICStream) Writer() io.WriteCloser { return s.srcW }

// Open opens the stream on the far side and returns its send side and its receive side, the
// receive side being nil on a unidirectional stream. It opens once, and every later call
// returns the same sides. [QUICStream.Relay] uses the sides Open returned, so bytes read off
// the stream can be written to the far side before the rest is relayed.
func (s *QUICStream) Open() (io.WriteCloser, io.Reader, error) {
	s.openOnce.Do(func() { s.dstW, s.dstR, s.openErr = s.open() })
	return s.dstW, s.dstR, s.openErr
}

// Relay opens the stream on the far side and relays it in both directions until it ends. When
// the far side cannot be opened, the stream is reset toward the peer that opened it.
//
// The connection ends once the handler returned and the relays running at that point ended. A
// Relay a goroutine has yet to call by then is not waited for, so a handler that relays on
// goroutines waits for them before it returns, as the example of [QUICCtx.Accept] does.
func (s *QUICStream) Relay() error {
	if s.streams != nil {
		s.streams.Add(1)
		defer s.streams.Add(-1)
	}
	dstW, dstR, err := s.Open()
	if err != nil {
		// The stream is a message in flight, which gets its failed end, I2.
		if w, ok := s.srcW.(interface{ CancelWrite(quic.StreamErrorCode) }); ok {
			w.CancelWrite(s.fail)
		}
		if r, ok := s.src.(interface{ CancelRead(quic.StreamErrorCode) }); ok {
			r.CancelRead(s.fail)
		}
		return err
	}

	if !s.bidi {
		_, err = copyStream(dstW, s.src, nil)
		endStreamCopy(s.src, dstW, err, s.fail)
		return filterCopyErr(err)
	}

	var wg sync.WaitGroup
	var upErr, downErr error
	wg.Go(func() {
		_, upErr = copyStream(dstW, s.src, nil)
		endStreamCopy(s.src, dstW, upErr, s.fail)
	})
	wg.Go(func() {
		_, downErr = copyStream(s.srcW, dstR, nil)
		endStreamCopy(dstR, s.srcW, downErr, s.fail)
	})
	wg.Wait()
	return errors.Join(filterCopyErr(upErr), filterCopyErr(downErr))
}

// endStreamCopy passes the end of a copy between two QUIC streams on. A reset or a
// STOP_SENDING crosses with its code, the end of src with a FIN, and any other failure, the end
// of a connection included, resets dst and stops src with fail.
func endStreamCopy(src io.Reader, dst io.WriteCloser, err error, fail quic.StreamErrorCode) {
	if err == nil || errors.Is(err, io.EOF) {
		_ = dst.Close()
		return
	}
	r, canRead := src.(interface{ CancelRead(quic.StreamErrorCode) })
	w, canWrite := dst.(interface{ CancelWrite(quic.StreamErrorCode) })
	if se, reset := errors.AsType[*quic.StreamError](err); reset {
		switch {
		case errors.As(err, new(writeError)) && canRead:
			r.CancelRead(se.ErrorCode)
		case canWrite:
			w.CancelWrite(se.ErrorCode)
		default:
			_ = dst.Close()
		}
		return
	}
	if canWrite {
		w.CancelWrite(fail)
	} else {
		_ = dst.Close()
	}
	if canRead {
		r.CancelRead(fail)
	}
}

// closePeer closes to with the application error that ended the peer connection, and with its
// failed end after a transport error, or after an idle timeout with a stream in flight. It
// closes once the relays of streams ended, within T, the bytes they already read written to
// to first, I2. A normal end of to, a connection the proxy accepted, waits for its peer as
// closeAcceptedBy does.
func closePeer(to *quic.Conn, err error, streams *atomic.Int64, accepted bool) {
	deadline := time.Now().Add(alertWriteTimeout)
	inFlight := streams.Load() > 0
	for streams.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if appErr, ok := errors.AsType[*quic.ApplicationError](err); ok {
		if accepted && appErr.ErrorCode == noErrorCode(to) {
			waitPeerClose(to, deadline)
		}
		_ = closeQUIC(to, appErr.ErrorCode, deadline)
		return
	}
	if _, idle := errors.AsType[*quic.IdleTimeoutError](err); idle && !inFlight {
		if accepted {
			waitPeerClose(to, deadline)
		}
		_ = closeQUIC(to, noErrorCode(to), deadline)
		return
	}
	_ = closeQUIC(to, failedCode(to), deadline)
}
