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
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"

	"github.com/quic-go/quic-go"
)

// QUICOption shapes what relaying a QUIC connection does.
type QUICOption interface{ applyQUIC(*quicRelayConfig) }

type quicOptionFunc func(*quicRelayConfig)

func (f quicOptionFunc) applyQUIC(c *quicRelayConfig) { f(c) }

type quicRelayConfig struct {
	onStream func(*QUICStream) error
	relay    []RelayOption
}

// OnStream runs fn for every stream of a relayed connection, in both directions. fn decides
// what happens to the stream: [QUICStream.Forward] carries it to the far side, and returning
// without forwarding leaves it unopened there.
//
// fn runs on its own goroutine per stream, so a connection carrying several at once calls it
// several times at once.
func OnStream(fn func(*QUICStream) error) QUICOption {
	return quicOptionFunc(func(c *quicRelayConfig) { c.onStream = fn })
}

// ShapeStreams applies relay options to every stream of a relayed connection.
func ShapeStreams(opts ...RelayOption) QUICOption {
	return quicOptionFunc(func(c *quicRelayConfig) { c.relay = append(c.relay, opts...) })
}

// QUICCtx is one terminated QUIC connection, handed to a [QUIC] handler.
//
// The unit here is the stream, and its content is whatever the peers put in it. A connection
// negotiating h3 is not served by this kind at all, it is HTTP traffic and its requests are
// routed one by one, so a QUIC handler never has to read HTTP/3 frames it cannot decode.
type QUICCtx struct {
	ctx      context.Context
	dialErr  error
	sock     net.PacketConn
	p        *Proxy
	sess     *Session
	entry    *entry
	conn     *quic.Conn
	dialed   *quic.Conn
	tr       *quic.Transport
	target   Target
	upstream netip.AddrPort

	identity string
	params   []Param

	dialOnce sync.Once
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

// Conn returns the terminated client connection, so a handler can accept and open streams
// itself instead of relaying.
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

// Dial opens the upstream connection and returns it, opening it once however many times it is
// called. The handshake carries the same server name and the same protocol the proxy negotiated
// with the client, which commits both sides to one protocol before the origin has been asked.
// See [TCPCtx.Dial] for what that costs.
//
// The caller does not own the returned connection: it is closed when the handler returns.
func (c *QUICCtx) Dial() (*quic.Conn, error) {
	c.dialOnce.Do(func() { c.dialed, c.dialErr = c.dial() })
	return c.dialed, c.dialErr
}

func (c *QUICCtx) dial() (*quic.Conn, error) {
	addr := c.target.Authority()
	if c.upstream.IsValid() {
		addr = c.upstream.String()
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	cfg := c.p.cfg.transport.upstreamTLSConfig()
	cfg.MinVersion = tls.VersionTLS13
	cfg.ServerName = c.target.Host
	if alpn := c.ALPN(); alpn != "" {
		cfg.NextProtos = []string{alpn}
	}

	sock, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: sock}
	conn, err := tr.Dial(c.ctx, udpAddr, cfg, &quic.Config{
		MaxIdleTimeout:  c.p.cfg.server.idleTimeout,
		EnableDatagrams: false,
	})
	if err != nil {
		_ = tr.Close()
		_ = sock.Close()
		return nil, fmt.Errorf("dial quic %s: %w", addr, err)
	}
	c.sock, c.tr = sock, tr
	return conn, nil
}

// close releases the upstream connection the handler opened, if any. The server owning the
// context calls it once the handler returns.
func (c *QUICCtx) close() {
	if c.dialed != nil {
		_ = closeNoError(c.dialed)
	}
	if c.tr != nil {
		_ = c.tr.Close()
	}
	if c.sock != nil {
		_ = c.sock.Close()
	}
}

// Relay carries the connection to the origin, stream by stream, until either side ends it.
//
//	return q.Relay(edge.OnStream(func(st *edge.QUICStream) error {
//		audit(q, "stream", st.ID())
//		return st.Forward()
//	}))
func (c *QUICCtx) Relay(opts ...QUICOption) error {
	upstream, err := c.Dial()
	if err != nil {
		return err
	}

	cfg := &quicRelayConfig{}
	for _, o := range opts {
		o.applyQUIC(cfg)
	}

	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()

	var wg sync.WaitGroup
	// Four acceptors: each peer may open a bidirectional or a unidirectional stream at any
	// time, and a stream opened by the origin is as much part of the connection as one the
	// client opened.
	wg.Go(func() { c.acceptBidi(ctx, cancel, cfg, &wg, c.conn, upstream, false) })
	wg.Go(func() { c.acceptBidi(ctx, cancel, cfg, &wg, upstream, c.conn, true) })
	wg.Go(func() { c.acceptUni(ctx, cancel, cfg, &wg, c.conn, upstream, false) })
	wg.Go(func() { c.acceptUni(ctx, cancel, cfg, &wg, upstream, c.conn, true) })
	wg.Wait()

	return nil
}

// acceptBidi carries the bidirectional streams from opens the way of to, opening the far side
// as each one arrives.
func (c *QUICCtx) acceptBidi(ctx context.Context, cancel context.CancelFunc, cfg *quicRelayConfig,
	wg *sync.WaitGroup, from, to *quic.Conn, inbound bool,
) {
	for {
		src, err := from.AcceptStream(ctx)
		if err != nil {
			// One side stopped accepting, which only happens when its connection ended.
			// Ending the other side is what makes the close visible end to end.
			cancel()
			closePeer(to, err)
			return
		}
		wg.Go(func() {
			st := &QUICStream{
				ctx: ctx, id: src.StreamID(), bidi: true, inbound: inbound,
				src: src, srcW: src, open: func() (io.WriteCloser, io.Reader, error) {
					dst, derr := to.OpenStreamSync(ctx)
					if derr != nil {
						return nil, nil, derr
					}
					return dst, dst, nil
				},
				relay: cfg.relay,
			}
			c.runStream(st, cfg)
		})
	}
}

// acceptUni carries the unidirectional streams the same way. There is nothing to read back on
// one, so the far side is opened for writing alone.
func (c *QUICCtx) acceptUni(ctx context.Context, cancel context.CancelFunc, cfg *quicRelayConfig,
	wg *sync.WaitGroup, from, to *quic.Conn, inbound bool,
) {
	for {
		src, err := from.AcceptUniStream(ctx)
		if err != nil {
			cancel()
			return
		}
		wg.Go(func() {
			st := &QUICStream{
				ctx: ctx, id: src.StreamID(), bidi: false, inbound: inbound,
				src: src, open: func() (io.WriteCloser, io.Reader, error) {
					dst, derr := to.OpenUniStreamSync(ctx)
					if derr != nil {
						return nil, nil, derr
					}
					return dst, nil, nil
				},
				relay: cfg.relay,
			}
			c.runStream(st, cfg)
		})
	}
}

func (c *QUICCtx) runStream(st *QUICStream, cfg *quicRelayConfig) {
	defer st.closeAll()
	if cfg.onStream == nil {
		_ = st.Forward()
		return
	}
	if err := cfg.onStream(st); err != nil {
		c.p.cfg.logger.Debug("edge: quic stream handler",
			slog.String("target", c.target.String()), slog.String("error", err.Error()))
	}
}

// closePeer ends to with the error that ended the connection this side was accepting on, so a
// close on one side reaches the other with the code it carried.
func closePeer(to *quic.Conn, err error) {
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		_ = to.CloseWithError(appErr.ErrorCode, appErr.ErrorMessage)
		return
	}
	_ = closeNoError(to)
}

// QUICStream is one stream of a relayed connection. Its content is opaque: what the peers put
// in a stream is theirs, and nothing here decodes it.
type QUICStream struct {
	ctx  context.Context
	src  io.Reader
	srcW io.WriteCloser

	dstW    io.WriteCloser
	dstR    io.Reader
	open    func() (io.WriteCloser, io.Reader, error)
	relay   []RelayOption
	id      quic.StreamID
	bidi    bool
	inbound bool
}

// ID returns the stream identifier the peer that opened it chose.
func (s *QUICStream) ID() quic.StreamID { return s.id }

// Bidirectional reports whether the stream carries data both ways.
func (s *QUICStream) Bidirectional() bool { return s.bidi }

// Inbound reports whether the origin opened the stream rather than the client.
func (s *QUICStream) Inbound() bool { return s.inbound }

// Reader returns the side the stream arrived on, so a handler can read what is on it before
// deciding. Reading consumes the bytes, which are then not forwarded.
func (s *QUICStream) Reader() io.Reader { return s.src }

// Forward opens the stream on the far side and carries it there until it ends.
func (s *QUICStream) Forward(opts ...RelayOption) error {
	dstW, dstR, err := s.open()
	if err != nil {
		return err
	}
	s.dstW, s.dstR = dstW, dstR

	cfg := newRelayConfig(append(slices.Clone(s.relay), opts...))
	out := relayWriter{w: dstW, ctx: s.ctx, rate: cfg.rate, delay: cfg.delay}

	if !s.bidi {
		_, err = copyStream(out, s.src, nil)
		_ = dstW.Close()
		return filterCopyErr(err)
	}

	var wg sync.WaitGroup
	var upErr, downErr error
	back := relayWriter{w: s.srcW, ctx: s.ctx, rate: cfg.rate, delay: cfg.delay}
	wg.Go(func() {
		_, upErr = copyStream(out, s.src, nil)
		_ = dstW.Close()
	})
	wg.Go(func() {
		_, downErr = copyStream(back, dstR, nil)
		_ = s.srcW.Close()
	})
	wg.Wait()
	return errors.Join(filterCopyErr(upErr), filterCopyErr(downErr))
}

func (s *QUICStream) closeAll() {
	if s.srcW != nil {
		_ = s.srcW.Close()
	}
	if s.dstW != nil {
		_ = s.dstW.Close()
	}
}
