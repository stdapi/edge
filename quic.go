// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fox-toolkit/edge/internal/quicsniff"
	"github.com/fox-toolkit/edge/internal/stringsutil"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	// maxDatagramSize is larger than any QUIC datagram a peer may send, which is bounded by
	// the path MTU.
	maxDatagramSize = 1500
	// maxPendingDatagrams bounds what one client may make the proxy buffer while its
	// ClientHello is still arriving. A ClientHello with post-quantum key shares spans a
	// handful of packets; well past that the peer is not trying to connect.
	maxPendingDatagrams = 32
	// quicPeerIdle is how long a peer with no traffic is kept before its state is dropped.
	quicPeerIdle = 2 * time.Minute
)

// ListenAndServeQUIC listens for UDP on addr and serves the QUIC connections routed to it. It
// is how HTTP/3 is intercepted.
//
// A proxy setting sends an HTTP/3 client back to TCP, since CONNECT tunnels a stream and
// HTTP/3 needs datagrams. No general purpose client implements MASQUE, which standardizes
// tunneling them, so a client reaches this listener by being routed to it.
func (p *Proxy) ListenAndServeQUIC(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	// A socket the platform cannot set up still serves every client that sends a server
	// name, which is every HTTP/3 client in practice.
	if transparent, terr := TransparentPacketConn(pc); terr == nil {
		pc = transparent
	} else {
		p.cfg.logger.Debug("edge: no original destination for datagrams", slog.String("error", terr.Error()))
	}
	return p.ServeQUIC(pc)
}

// ServeQUIC serves the QUIC connections arriving on pc. Wrap pc in [TransparentPacketConn]
// to place a client by the address it was headed to rather than by its server name alone.
//
// Each client is placed by reading the server name out of its first packets, which are
// protected with keys derived from a connection ID sent in clear. A tunneled client has its
// datagrams relayed untouched, so its handshake stays end to end; an intercepted one is
// handed to a QUIC server that answers with a minted certificate.
func (p *Proxy) ServeQUIC(pc net.PacketConn) error {
	if p.srv.closing.Load() {
		return ErrProxyClosed
	}

	d, err := newQUICDemux(p, pc)
	if err != nil {
		return err
	}
	defer d.close()

	p.srv.track(d, true)
	defer p.srv.track(d, false)

	return d.run()
}

// quicDemux owns one UDP socket and decides, per client, whether its datagrams are relayed
// to the origin or handed to the QUIC server the proxy terminates.
type quicDemux struct {
	pc net.PacketConn
	// origins is pc when it reports where its datagrams were headed, nil otherwise.
	origins PacketOriginalDestination

	p *Proxy

	// intercepted feeds the terminating QUIC server. Every intercepted client shares it, so
	// one server and one connection ID space serve them all.
	intercepted *demuxPacketConn
	h3          *http3.Server
	listener    *quic.EarlyListener
	transport   *quic.Transport

	peers    map[string]*quicPeer
	sessions map[string]*Session

	done chan struct{}
	wg   sync.WaitGroup

	closeOnce sync.Once

	mu sync.Mutex
}

type peerState uint8

const (
	peerSniffing peerState = iota
	peerTunneling
	peerIntercepted
	peerRejected
)

type quicPeer struct {
	lastSeen time.Time
	upstream net.Conn
	sniffer  *quicsniff.Reassembler
	target   Target
	pending  [][]byte
	state    peerState
}

func newQUICDemux(p *Proxy, pc net.PacketConn) (*quicDemux, error) {
	d := &quicDemux{
		p:        p,
		pc:       pc,
		peers:    make(map[string]*quicPeer),
		sessions: make(map[string]*Session),
		done:     make(chan struct{}),
	}
	d.origins, _ = pc.(PacketOriginalDestination)
	d.intercepted = newDemuxPacketConn(pc)
	return d, nil
}

// startInterception brings up the terminating QUIC server on first use, so a proxy that only
// ever tunnels never needs a certificate authority.
//
// The server fields are written under the lock because a shutdown may read them from another
// goroutine at any point after the first intercepted connection.
func (d *quicDemux) startInterception() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.listener != nil {
		return nil
	}
	if d.p.cfg.ca == nil {
		return fmt.Errorf("%w: %w", ErrNoCertificateAuthority, errNoCA)
	}

	transport := &quic.Transport{Conn: d.intercepted}
	ln, err := transport.ListenEarly(d.quicTLSConfig(), d.quicConfig())
	if err != nil {
		return fmt.Errorf("listen QUIC: %w", err)
	}
	d.transport = transport
	d.listener = ln

	d.h3 = &http3.Server{
		Handler:        http.HandlerFunc(d.p.serveInterceptedRequest),
		MaxHeaderBytes: d.p.cfg.server.maxHeaderBytes,
		IdleTimeout:    d.p.cfg.server.idleTimeout,
		Logger:         d.p.cfg.logger,
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			if sess := d.sessionFor(c.RemoteAddr()); sess != nil {
				// The session is created before the handshake, so this is the first point
				// where the TLS state exists. It runs before any request is read off the
				// connection, which is what lets it be written without synchronization.
				state := c.ConnectionState().TLS
				sess.tlsState = &state
				return context.WithValue(ctx, sessionKey{}, sess)
			}
			return ctx
		},
	}

	srv := d.h3
	d.wg.Go(func() {
		if err := srv.ServeListener(ln); err != nil && !errors.Is(err, quic.ErrServerClosed) {
			d.p.cfg.logger.Debug("edge: HTTP/3 server stopped", slog.String("error", err.Error()))
		}
	})
	return nil
}

func (d *quicDemux) quicTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := chi.ServerName
			if name == "" {
				// QUIC clients send a server name in practice; falling back to the peer
				// address keeps a handshake from failing outright when one does not.
				name, _ = splitHostPort(chi.Conn.RemoteAddr().String())
			}
			return d.p.cfg.ca.Leaf(name)
		},
	}
}

func (d *quicDemux) quicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:  d.p.cfg.server.idleTimeout,
		Allow0RTT:       false,
		EnableDatagrams: false,
	}
}

func (d *quicDemux) run() error {
	sweep := time.NewTicker(30 * time.Second)
	defer sweep.Stop()
	d.wg.Go(func() {
		for {
			select {
			case <-sweep.C:
				d.sweepIdle()
			case <-d.done:
				return
			}
		}
	})

	buf := make([]byte, maxDatagramSize)
	for {
		n, addr, err := d.pc.ReadFrom(buf)
		if err != nil {
			if d.p.srv.closing.Load() {
				return ErrProxyClosed
			}
			if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
				continue
			}
			return err
		}
		if n == 0 {
			continue
		}

		// The buffer is reused on the next read, so anything kept must be copied.
		d.dispatch(addr, buf[:n])
	}
}

func (d *quicDemux) dispatch(addr net.Addr, datagram []byte) {
	key := addr.String()

	d.mu.Lock()
	peer, ok := d.peers[key]
	if !ok {
		peer = &quicPeer{sniffer: quicsniff.New()}
		d.peers[key] = peer
	}
	peer.lastSeen = time.Now()
	state := peer.state
	upstream := peer.upstream
	d.mu.Unlock()

	switch state {
	case peerRejected:
		return
	case peerIntercepted:
		d.intercepted.deliver(addr, datagram)
		return
	case peerTunneling:
		if upstream != nil {
			_, _ = upstream.Write(datagram)
		}
		return
	}

	d.sniff(addr, key, peer, datagram)
}

// sniff feeds a datagram to the reassembler and, once the ClientHello is complete, decides
// what happens to the connection.
func (d *quicDemux) sniff(addr net.Addr, key string, peer *quicPeer, datagram []byte) {
	kept := make([]byte, len(datagram))
	copy(kept, datagram)

	hello, err := peer.sniffer.Feed(kept)
	switch {
	case errors.Is(err, quicsniff.ErrNotInitial):
		// A datagram from a connection whose Initial was never seen, typically a client
		// resuming across a proxy restart. There is nothing to place it by.
		d.reject(key, addr, "no Initial packet")
		return
	case err != nil:
		d.p.cfg.logger.Debug("edge: cannot read the QUIC ClientHello",
			slog.String("client", key), slog.String("error", err.Error()))
		d.reject(key, addr, err.Error())
		return
	}

	d.mu.Lock()
	if len(peer.pending) >= maxPendingDatagrams {
		d.mu.Unlock()
		d.reject(key, addr, "ClientHello spans too many datagrams")
		return
	}
	peer.pending = append(peer.pending, kept)
	pending := peer.pending
	d.mu.Unlock()

	if hello == nil {
		return // still arriving
	}

	target := d.targetFor(hello, addr)
	if target.Host == "" {
		d.reject(key, addr, "no server name in the ClientHello")
		return
	}

	switch d.p.Decide(target) {
	case Reject:
		d.reject(key, addr, "no interceptor or tunnel names this authority")
	case Intercept:
		d.beginIntercept(key, addr, target, pending)
	default:
		d.beginTunnel(key, addr, target, pending)
	}
}

// targetFor works out where a QUIC connection was headed, from the server name it offered
// and, when available, the address the datagram was redirected from.
func (d *quicDemux) targetFor(hello []byte, addr net.Addr) Target {
	target := Target{Scheme: "https", Port: "443"}

	if name := serverNameFromHello(hello); name != "" {
		target.Host = stringsutil.ToLowerASCIIString(name)
	}

	if origin := d.originalDst(addr); origin.IsValid() {
		target.Port = fmt.Sprint(origin.Port())
		if target.Host == "" {
			target.Host = origin.Addr().String()
		}
	}
	return target
}

// originalDst resolves where a datagram from client was headed before the redirect, or the
// zero value when there was none.
func (d *quicDemux) originalDst(client net.Addr) netip.AddrPort {
	if d.origins == nil {
		return netip.AddrPort{}
	}
	origin, err := d.origins.OriginalDestination(client)
	if err != nil {
		return netip.AddrPort{}
	}
	return redirectedTo(origin, d.pc.LocalAddr())
}

func (d *quicDemux) beginIntercept(key string, addr net.Addr, target Target, pending [][]byte) {
	if err := d.startInterception(); err != nil {
		d.p.cfg.logger.Error("edge: cannot intercept QUIC", slog.String("error", err.Error()))
		d.reject(key, addr, err.Error())
		return
	}

	sess := newSession(context.Background(), nil, target, Intercept, HTTP3)
	sess.remoteAddr = addr
	sess.localAddr = d.pc.LocalAddr()
	sess.transparent = true
	// Forwarding goes back to the address the client was headed to, not to a fresh
	// resolution of the authority, which behind a redirect may not resolve at all.
	sess.upstream = d.originalDst(addr)

	d.mu.Lock()
	peer := d.peers[key]
	if peer == nil {
		d.mu.Unlock()
		return
	}
	peer.state = peerIntercepted
	peer.target = target
	peer.pending = nil
	d.sessions[key] = sess
	d.mu.Unlock()

	for _, dg := range pending {
		d.intercepted.deliver(addr, dg)
	}
}

func (d *quicDemux) beginTunnel(key string, addr net.Addr, target Target, pending [][]byte) {
	upstream, err := d.dialUpstreamUDP(target, addr)
	if err != nil {
		d.p.cfg.logger.Debug("edge: cannot reach the QUIC origin",
			slog.String("target", target.String()), slog.String("error", err.Error()))
		d.reject(key, addr, err.Error())
		return
	}

	d.mu.Lock()
	peer := d.peers[key]
	if peer == nil {
		d.mu.Unlock()
		_ = upstream.Close()
		return
	}
	peer.state = peerTunneling
	peer.upstream = upstream
	peer.target = target
	peer.pending = nil
	d.mu.Unlock()

	for _, dg := range pending {
		if _, err := upstream.Write(dg); err != nil {
			break
		}
	}

	// Relay what the origin sends back to the client it belongs to.
	d.wg.Go(func() {
		defer func() { _ = upstream.Close() }()
		buf := make([]byte, maxDatagramSize)
		for {
			_ = upstream.SetReadDeadline(time.Now().Add(quicPeerIdle))
			n, err := upstream.Read(buf)
			if n > 0 {
				if _, werr := d.pc.WriteTo(buf[:n], addr); werr != nil {
					return
				}
			}
			if err != nil {
				d.drop(key)
				return
			}
			select {
			case <-d.done:
				return
			default:
			}
		}
	})
}

func (d *quicDemux) dialUpstreamUDP(target Target, client net.Addr) (net.Conn, error) {
	addr := target.Authority()
	if origin := d.originalDst(client); origin.IsValid() {
		addr = origin.String()
	}
	return net.DialTimeout("udp", addr, 10*time.Second)
}

func (d *quicDemux) reject(key string, addr net.Addr, reason string) {
	d.mu.Lock()
	if peer, ok := d.peers[key]; ok {
		peer.state = peerRejected
		peer.pending = nil
		peer.sniffer = nil
	}
	d.mu.Unlock()
	d.p.cfg.logger.Debug("edge: QUIC connection dropped",
		slog.String("client", addr.String()), slog.String("reason", reason))
}

func (d *quicDemux) drop(key string) {
	d.mu.Lock()
	if peer, ok := d.peers[key]; ok && peer.upstream != nil {
		_ = peer.upstream.Close()
	}
	delete(d.peers, key)
	delete(d.sessions, key)
	d.mu.Unlock()
}

func (d *quicDemux) sessionFor(addr net.Addr) *Session {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sessions[addr.String()]
}

func (d *quicDemux) sweepIdle() {
	cutoff := time.Now().Add(-quicPeerIdle)
	d.mu.Lock()
	defer d.mu.Unlock()
	for key, peer := range d.peers {
		if peer.lastSeen.After(cutoff) {
			continue
		}
		if peer.upstream != nil {
			_ = peer.upstream.Close()
		}
		delete(d.peers, key)
		delete(d.sessions, key)
	}
}

func (d *quicDemux) Close() error { d.close(); return nil }

func (d *quicDemux) close() {
	d.closeOnce.Do(func() {
		close(d.done)

		d.mu.Lock()
		h3, listener, transport := d.h3, d.listener, d.transport
		for _, peer := range d.peers {
			if peer.upstream != nil {
				_ = peer.upstream.Close()
			}
		}
		clear(d.peers)
		clear(d.sessions)
		d.mu.Unlock()

		if h3 != nil {
			_ = h3.Close()
		}
		if listener != nil {
			_ = listener.Close()
		}
		// The packet conn goes before the transport: the transport's listen goroutine is
		// parked in ReadFrom, and Transport.Close waits for it to return.
		d.intercepted.Close()
		if transport != nil {
			_ = transport.Close()
		}

		_ = d.pc.Close()
		d.wg.Wait()
	})
}

// serverNameFromHello reads the server name out of a raw ClientHello handshake message.
// QUIC carries handshake messages without a record layer, so one is put back for the sake of
// the parser.
func serverNameFromHello(hello []byte) string {
	if len(hello) == 0 || len(hello) > math.MaxUint16 {
		return ""
	}

	record := make([]byte, 0, 5+len(hello))
	record = append(record, 0x16, 0x03, 0x01)
	// Guarded above: the message is shorter than 65536 bytes.
	record = binary.BigEndian.AppendUint16(record, uint16(len(hello))) //nolint:gosec // bounded by the check above
	record = append(record, hello...)

	var name string
	_ = tls.Server(&replayConn{r: record}, &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			name = chi.ServerName
			return nil, errStopHandshake
		},
	}).Handshake()
	return name
}

// demuxPacketConn is the socket the terminating QUIC server reads from. Datagrams are pushed
// into it by the demultiplexer rather than read from the network, while writes go straight
// out of the real socket so the client sees answers from the address it wrote to.
type demuxPacketConn struct {
	real net.PacketConn
	in   chan datagram

	closed chan struct{}

	readDeadline atomic.Pointer[time.Time]

	closeOnce sync.Once
}

type datagram struct {
	addr net.Addr
	b    []byte
}

func newDemuxPacketConn(real net.PacketConn) *demuxPacketConn {
	return &demuxPacketConn{
		real:   real,
		in:     make(chan datagram, 256),
		closed: make(chan struct{}),
	}
}

// deliver hands a datagram to the QUIC server. It drops rather than blocks: QUIC is built on
// an unreliable datagram service, and stalling the demultiplexer would hold up every other
// client on the socket.
func (c *demuxPacketConn) deliver(addr net.Addr, b []byte) {
	kept := make([]byte, len(b))
	copy(kept, b)
	select {
	case c.in <- datagram{b: kept, addr: addr}:
	case <-c.closed:
	default:
	}
}

func (c *demuxPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	var timeout <-chan time.Time
	if dl := c.readDeadline.Load(); dl != nil && !dl.IsZero() {
		timer := time.NewTimer(time.Until(*dl))
		defer timer.Stop()
		timeout = timer.C
	}

	select {
	case dg := <-c.in:
		return copy(b, dg.b), dg.addr, nil
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *demuxPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	return c.real.WriteTo(b, addr)
}

func (c *demuxPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *demuxPacketConn) LocalAddr() net.Addr { return c.real.LocalAddr() }

func (c *demuxPacketConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *demuxPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(&t)
	return nil
}

func (c *demuxPacketConn) SetWriteDeadline(time.Time) error { return nil }

// SetReadBuffer and SetWriteBuffer are delegated to the real socket, which is the one that
// actually touches the network. QUIC needs a large receive buffer to avoid dropping packets
// under load, and looks for these methods to size it.
//
// SyscallConn is deliberately not exposed: it would let the QUIC stack read from the real
// socket directly, behind the demultiplexer that decides where each datagram belongs.
func (c *demuxPacketConn) SetReadBuffer(n int) error {
	if s, ok := c.real.(interface{ SetReadBuffer(int) error }); ok {
		return s.SetReadBuffer(n)
	}
	return errors.ErrUnsupported
}

func (c *demuxPacketConn) SetWriteBuffer(n int) error {
	if s, ok := c.real.(interface{ SetWriteBuffer(int) error }); ok {
		return s.SetWriteBuffer(n)
	}
	return errors.ErrUnsupported
}

var _ net.PacketConn = (*demuxPacketConn)(nil)
