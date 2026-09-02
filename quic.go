// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

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

	"github.com/quic-go/quic-go"
)

// QUICCtx is one terminated QUIC connection, handed to a [QUIC] handler. It is not safe for
// concurrent use. A connection that negotiated h3 is served as HTTP and never reaches a QUIC
// handler.
type QUICCtx struct {
	ctx       context.Context
	dialErr   error
	sock      net.PacketConn
	acceptErr error
	endErr    error

	p      *Proxy
	sess   *Session
	entry  *entry
	conn   *quic.Conn
	dialed *quic.Conn
	tr     *quic.Transport

	acceptCh     chan *QUICStream
	acceptCancel context.CancelFunc
	target       Target

	identity string
	params   []Param
	extra    []quicDialed

	dialOnce   sync.Once
	acceptOnce sync.Once
	endOnce    sync.Once
}

// quicDialed is one connection a handler opened with [QUICCtx.DialTo], with the transport and
// socket it lives on.
type quicDialed struct {
	conn *quic.Conn
	tr   *quic.Transport
	sock net.PacketConn
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
		var d quicDialed
		d, c.dialErr = c.dialQUIC(c.ctx, c.upstreamAddr(), c.target.Host)
		c.dialed, c.tr, c.sock = d.conn, d.tr, d.sock
	})
	return c.dialed, c.dialErr
}

// DialTo opens a connection to addr, given as host:port, with the TLS parameters of
// [QUICCtx.Dial], the server name taken from addr. Set a dial timeout through ctx. Every call
// opens a new connection, closed when the handler returns.
func (c *QUICCtx) DialTo(ctx context.Context, addr string) (*quic.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("edge: dial %q: %w", addr, err)
	}
	d, err := c.dialQUIC(ctx, addr, host)
	if err != nil {
		return nil, err
	}
	c.extra = append(c.extra, d)
	return d.conn, nil
}

func (c *QUICCtx) upstreamAddr() string {
	if addr := c.sess.dialAddr(); addr != "" {
		return addr
	}
	return c.target.Authority()
}

func (c *QUICCtx) dialQUIC(ctx context.Context, addr, serverName string) (quicDialed, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return quicDialed{}, err
	}

	cfg := c.p.cfg.transport.upstreamTLSConfig()
	cfg.MinVersion = tls.VersionTLS13
	cfg.ServerName = serverName
	if alpn := c.ALPN(); alpn != "" {
		cfg.NextProtos = []string{alpn}
	}

	sock, err := net.ListenUDP("udp", nil)
	if err != nil {
		return quicDialed{}, err
	}
	tr := &quic.Transport{Conn: sock}
	conn, err := tr.Dial(ctx, udpAddr, cfg, &quic.Config{
		MaxIdleTimeout:  c.p.cfg.server.idleTimeout,
		EnableDatagrams: false,
	})
	if err != nil {
		_ = tr.Close()
		_ = sock.Close()
		return quicDialed{}, fmt.Errorf("dial quic %s: %w", addr, err)
	}
	return quicDialed{conn: conn, tr: tr, sock: sock}, nil
}

// close releases the connections the handler opened, once the handler has returned.
func (c *QUICCtx) close() {
	if c.acceptCancel != nil {
		c.acceptCancel()
	}
	if c.dialed != nil {
		_ = closeNoError(c.dialed)
	}
	if c.tr != nil {
		_ = c.tr.Close()
	}
	if c.sock != nil {
		_ = c.sock.Close()
	}
	for _, d := range c.extra {
		_ = closeNoError(d.conn)
		_ = d.tr.Close()
		_ = d.sock.Close()
	}
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
			// Accept fails once the connection has ended, and the peer connection is closed
			// with the same error.
			c.recordEnd(err)
			cancel()
			closePeer(to, err)
			return
		}
		st := &QUICStream{
			ctx: ctx, id: src.StreamID(), bidi: true, inbound: inbound,
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
			c.recordEnd(err)
			cancel()
			return
		}
		st := &QUICStream{
			ctx: ctx, id: src.StreamID(), bidi: false, inbound: inbound,
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
	open    func() (io.WriteCloser, io.Reader, error)
	openErr error
	id      quic.StreamID
	bidi    bool
	inbound bool

	openOnce sync.Once
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
// the far side cannot be opened, the stream is closed toward the peer that opened it.
func (s *QUICStream) Relay() error {
	dstW, dstR, err := s.Open()
	if err != nil {
		if s.srcW != nil {
			_ = s.srcW.Close()
		}
		return err
	}

	if !s.bidi {
		_, err = copyStream(dstW, s.src, nil)
		_ = dstW.Close()
		return filterCopyErr(err)
	}

	var wg sync.WaitGroup
	var upErr, downErr error
	wg.Go(func() {
		_, upErr = copyStream(dstW, s.src, nil)
		_ = dstW.Close()
	})
	wg.Go(func() {
		_, downErr = copyStream(s.srcW, dstR, nil)
		_ = s.srcW.Close()
	})
	wg.Wait()
	return errors.Join(filterCopyErr(upErr), filterCopyErr(downErr))
}

// closePeer closes to with the application error that ended the peer connection, when there
// was one.
func closePeer(to *quic.Conn, err error) {
	if appErr, ok := errors.AsType[*quic.ApplicationError](err); ok {
		_ = to.CloseWithError(appErr.ErrorCode, appErr.ErrorMessage)
		return
	}
	_ = closeNoError(to)
}
