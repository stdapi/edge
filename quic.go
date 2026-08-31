// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
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
	"github.com/quic-go/quic-go/qlogwriter"
)

const (
	// maxUDPPayload accepts any datagram UDP can deliver. A shorter buffer truncates rather
	// than drops, and a truncated QUIC packet fails its AEAD at the receiver.
	maxUDPPayload = 65535
	// maxPendingDatagrams and maxPendingBytes bound what one connection may make the proxy
	// buffer while its ClientHello is still arriving.
	maxPendingDatagrams = 32
	maxPendingBytes     = 64 * 1024
	// quicRelayIdle reaps a relay with no return traffic, the only liveness a tunnel shows
	// since a live QUIC connection always acknowledges.
	quicRelayIdle = 2 * time.Minute
	// quicSniffTTL reaps a connection whose ClientHello never completes, quicRejectTTL a
	// rejected one kept so Initial retransmits are not decrypted again, and quicAdoptTTL an
	// intercepted one the QUIC server never adopted.
	quicSniffTTL  = 10 * time.Second
	quicRejectTTL = 30 * time.Second
	quicAdoptTTL  = time.Minute
	// The state caps. Everything below is allocated for an unauthenticated peer on a
	// spoofable transport, so the worst case is the product of these bounds.
	maxQUICFlows       = 4096
	maxConnsPerFlow    = 64
	maxSniffingConns   = 512
	maxLearnedPerRelay = 32
	// Relays were bounded through the connections that create them until raw admission,
	// which has no connection, so the bound sits on the relays themselves.
	maxRelaysPerFlow = 16
	maxRelays        = 1024
	// maxIntercepts bounds the terminating stacks, one per origin under TPROXY, each
	// queueing up to interceptQueue datagrams of maxUDPPayload (the shared stack of the
	// other paths four times as many). quicInterceptTTL reaps a stack no connection has
	// fed for a while.
	maxIntercepts    = 64
	interceptQueue   = 64
	quicInterceptTTL = time.Minute
	// quicResetSize is the size of the stateless resets the demux sends itself. Only a
	// datagram strictly larger gets one, which keeps two proxies from bouncing resets at
	// each other.
	quicResetSize = 42
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
	defer func() { _ = pc.Close() }()
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
// Each connection is placed by the server name in its Initial packets. A tunneled connection
// is relayed untouched and its handshake stays end to end. An intercepted one is terminated
// with a minted certificate and served over HTTP/3. One client socket may multiplex several
// connections.
//
// Under Encrypted Client Hello the decision sees the outer server name only, unless
// [WithRejectECH] refuses such connections. QUIC versions
// other than v1 and v2 are rejected. A tunneled client that changes address in flight has
// to re-handshake. Behind a Linux redirect a client may tunnel several origins from one
// socket. Behind a Linux TPROXY rule every datagram reports its exact destination and
// replies are sent from the address the client targeted. At most 64 origins are terminated
// at once there. Beyond that the origin longest without an intercepted connection is
// reclaimed, and with every origin holding one a connection to a new origin is refused. On
// macOS, and when pc is not wrapped in [TransparentPacketConn], a client socket supports
// one tunneled origin, and connections to further origins drop shortly after their
// handshake.
//
// A datagram that is not QUIC is placed by the address it was headed to, when the platform
// reports one. A tunnel registered for that authority relays the traffic in both
// directions, and without one the datagram is dropped.
func (p *Proxy) ServeQUIC(pc net.PacketConn) error {
	if p.srv.closing.Load() {
		return ErrProxyClosed
	}

	d, err := newQUICDemux(p, pc)
	if err != nil {
		return err
	}
	defer d.close()

	// A refused registration means a shutdown started; the socket is only closed through
	// the demux, so serving would leave run reading forever.
	if !p.srv.tryTrackDemux(d) {
		return ErrProxyClosed
	}
	defer p.srv.untrackDemux(d)

	return d.run()
}

// quicDemux owns one UDP socket and decides, per connection, whether its datagrams are
// relayed to the origin or terminated by the proxy.
type quicDemux struct {
	pc net.PacketConn
	// origins is pc when it reports where its datagrams were headed, nil otherwise.
	origins PacketOriginalDestination

	// replier is set when replies must leave from the address each client targeted, the
	// TPROXY contract. replySockets holds one sending socket per origin.
	replier transparentReplier

	// ctx ends when the demux closes, bounding the resolver lookups the sniff path waits on.
	ctx context.Context

	p *Proxy

	// h3 serves every terminating stack, so one shutdown sends every GOAWAY.
	h3 *http3.Server

	// tag recognizes the connection IDs the terminating stacks emit, with no per
	// connection state. It and resetKey are set once, when interception starts.
	tag    atomic.Pointer[quicCIDTag]
	cancel context.CancelFunc

	done         chan struct{}
	flows        map[netip.AddrPort]*quicFlow
	replySockets map[netip.AddrPort]net.PacketConn
	// intercepts holds the terminating stacks, one per origin under TPROXY so replies
	// leave from the address the client targeted, and one under the zero key anywhere else.
	intercepts map[netip.AddrPort]*quicIntercept

	wg sync.WaitGroup

	// sniffing counts the connections buffering a ClientHello across every flow, the memory
	// an unauthenticated peer controls, and relays counts the sockets one holds open.
	sniffing int
	relays   int

	closeOnce sync.Once

	mu sync.Mutex
	// draining refuses new placements while the connections already placed finish. It is
	// written and, on the paths that publish state, read under mu, so a publication is
	// either refused or visible to the first snapshot the shutdown takes.
	draining atomic.Bool

	resetKey quic.StatelessResetKey

	// exactOrigins is set when pc reads each datagram's destination from the datagram
	// itself, exact enough to attribute it by.
	exactOrigins bool
}

// quicFlow is the state of one client socket, pinned to its source address. Re-pointing the
// return path on a cleartext signal would let anyone on the client's path redirect it.
type quicFlow struct {
	lastSeen time.Time
	client   net.Addr
	// conns is keyed by the DCID of each connection's first Initial.
	conns  map[string]*quicConn
	relays map[netip.AddrPort]*quicRelay
	// learned maps the connection IDs read off the origins' long headers back to their
	// relay, and lens records which lengths are present, since a short header does not say
	// where its connection ID ends.
	learned map[string]*quicRelay
	lens    uint32
}

type quicConnState uint8

const (
	connSniffing quicConnState = iota
	connTunneling
	connIntercepted
	connRejected
)

// quicConn is one QUIC connection. Its decision is taken once, on its Initial packets, and
// nothing after the handshake feeds back into it.
type quicConn struct {
	lastSeen time.Time
	sniffer  *quicsniff.Reassembler
	sess     *Session
	// qc is the terminated connection of an intercepted client, nil until the HTTP/3
	// server adopts it.
	qc     *quic.Conn
	cancel context.CancelFunc
	relay  *quicRelay
	// stack terminates an intercepted connection, nil in every other state.
	stack *quicIntercept

	odcid string
	// origin is where the client was headed, resolved from the opening datagram since no
	// later one can answer it.
	origin       netip.AddrPort
	pending      [][]byte
	pendingBytes int
	state        quicConnState
	// doomed marks an intercepted connection closed before the HTTP/3 server adopted it.
	doomed bool
}

// end ends the context of the connection's session. Whoever removes a connection, or marks
// it rejected, has to call it.
func (c *quicConn) end() {
	if c.cancel != nil {
		c.cancel()
	}
}

// quicRelay is one connected socket to one origin, shared by every connection of its flow
// headed there. The origin tells them apart by their connection IDs (RFC 9000 section 5.2).
type quicRelay struct {
	upstream net.Conn
	// sess and cancel belong to a raw relay, which has no connection to hang them on.
	sess   *Session
	cancel context.CancelFunc
	// reply, under TPROXY, is the shared per origin socket the return traffic leaves from.
	// The relay never owns it: the sweep closes it once no user is left.
	reply   net.PacketConn
	key     netip.AddrPort
	conns   []*quicConn
	learned int
	closed  bool
	// raw marks a relay whose client sent datagrams no protocol was read into. It learns no
	// connection IDs off its return traffic, arbitrary bytes being able to spell one.
	raw bool
}

// quicIntercept terminates the QUIC connections of one origin. Under TPROXY its replies
// leave from that origin's address, and the zero origin is the stack shared by every path
// replying from the proxy's own socket.
type quicIntercept struct {
	lastSeen  time.Time
	transport *quic.Transport
	listener  *quic.EarlyListener
	conn      *demuxPacketConn
	origin    netip.AddrPort
	// conns counts the live connections, and a stack holding any is neither swept nor
	// evicted.
	conns int
}

// deliver hands a datagram to the stack's QUIC transport.
func (it *quicIntercept) deliver(addr net.Addr, datagram []byte) {
	it.conn.deliver(addr, datagram)
}

// closeIntercept tears one stack down. The listener goes first, so the serve loop returns
// the error it filters, then the packet conn, unblocking the read Transport.Close waits on.
func (d *quicDemux) closeIntercept(it *quicIntercept) {
	_ = it.listener.Close()
	it.conn.Close()
	_ = it.transport.Close()
}

// h3NoError is HTTP/3's H3_NO_ERROR, what a peer sends when it closes a connection with
// nothing to report.
const h3NoError quic.ApplicationErrorCode = 0x100

var (
	errNoReplyDestination = errors.New("no destination to source the replies from")
	errInterceptsBusy     = errors.New("every terminating stack has live connections")
)

// quicConnCloser ends one QUIC connection. A tunneled one cannot be cut alone, its packets
// being indistinguishable from its siblings' once the client rotates its connection IDs, so
// closing it closes its relay and the siblings re-handshake.
type quicConnCloser struct {
	d     *quicDemux
	odcid string
	flow  netip.AddrPort
}

func (c *quicConnCloser) Close() error {
	c.d.mu.Lock()
	flow := c.d.flows[c.flow]
	if flow == nil {
		c.d.mu.Unlock()
		return nil
	}
	conn := flow.conns[c.odcid]
	if conn == nil {
		c.d.mu.Unlock()
		return nil
	}
	if conn.state == connTunneling {
		relay := conn.relay
		c.d.mu.Unlock()
		c.d.closeRelay(c.flow, relay)
		return nil
	}
	if conn.state == connIntercepted && conn.qc == nil {
		// The tag delivers this connection's packets with no state to drop, so removing it
		// would let the handshake finish unobserved. attach ends a doomed connection when
		// the server adopts it, the adopt TTL when it never does.
		conn.doomed = true
		conn.sess = nil
		conn.end()
		c.d.mu.Unlock()
		return nil
	}
	qc := conn.qc
	c.d.removeConnLocked(flow, conn)
	c.d.mu.Unlock()

	if qc == nil {
		return nil
	}
	// Outside the lock, quic-go writes a CONNECTION_CLOSE from here.
	return qc.CloseWithError(h3NoError, "")
}

// rawRelayCloser ends one raw relay. The relay is the whole of what its session covers, so
// closing the session closes exactly that.
type rawRelayCloser struct {
	d     *quicDemux
	relay *quicRelay
	flow  netip.AddrPort
}

func (c *rawRelayCloser) Close() error {
	c.d.closeRelay(c.flow, c.relay)
	return nil
}

// appendSessions adds the sessions of the connections this demux serves to out.
func (d *quicDemux) appendSessions(out []*Session) []*Session {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, flow := range d.flows {
		for _, conn := range flow.conns {
			if conn.sess != nil {
				out = append(out, conn.sess)
			}
		}
		for _, relay := range flow.relays {
			if relay.sess != nil {
				out = append(out, relay.sess)
			}
		}
	}
	return out
}

func newQUICDemux(p *Proxy, pc net.PacketConn) (*quicDemux, error) {
	d := &quicDemux{
		p:     p,
		pc:    pc,
		flows: make(map[netip.AddrPort]*quicFlow),
		done:  make(chan struct{}),
	}
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.origins, _ = pc.(PacketOriginalDestination)
	if e, ok := pc.(interface{ exactOriginalDestination() bool }); ok && d.origins != nil {
		d.exactOrigins = e.exactOriginalDestination()
	}
	d.intercepts = make(map[netip.AddrPort]*quicIntercept)
	if r, ok := pc.(transparentReplier); ok && r.transparentReplies() {
		d.replier = r
		d.replySockets = make(map[netip.AddrPort]net.PacketConn)
	}
	return d, nil
}

// quicCarrier links a connection the QUIC server accepts back to the state it was sniffed
// under, through the connection context. Transport.ConnContext stores an empty one, the
// Tracer fills it, and the HTTP/3 server reads it back.
type quicCarrier struct {
	client net.Addr
	odcid  string
}

type quicCarrierKey struct{}

// startInterception derives the keys and brings up the shared HTTP/3 server on first use, so
// a proxy that only ever tunnels never needs a certificate authority.
//
// The fields are written under the lock because a shutdown may read them from another
// goroutine at any point after the first intercepted connection.
func (d *quicDemux) startInterception() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Checked before the server field, since a shutdown already told the HTTP/3 server to
	// send GOAWAY and one brought up now would be missed.
	if d.draining.Load() {
		return ErrProxyClosed
	}
	if d.h3 != nil {
		return nil
	}
	if d.p.cfg.ca == nil {
		return fmt.Errorf("%w: %w", ErrNoCertificateAuthority, errNoCA)
	}

	tag, resetKey, err := quicInterceptKeys(d.p.cfg.ca)
	if err != nil {
		return err
	}

	d.h3 = &http3.Server{
		Handler:        http.HandlerFunc(d.p.serveInterceptedRequest),
		MaxHeaderBytes: d.p.cfg.server.maxHeaderBytes,
		IdleTimeout:    d.p.cfg.server.idleTimeout,
		Logger:         d.p.cfg.logger,
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			carrier, _ := c.Context().Value(quicCarrierKey{}).(*quicCarrier)
			if carrier == nil {
				return ctx
			}
			sess := d.attach(carrier, c)
			if sess == nil {
				return ctx
			}
			// The session is registered before the handshake, so this is the first point
			// where its TLS state exists and where HTTP/3 is established rather than
			// pending, the server offering h3 alone.
			state := c.ConnectionState().TLS
			sess.tlsState.Store(&state)
			sess.setProtocol(HTTP3)
			return context.WithValue(ctx, sessionKey{}, sess)
		},
	}
	d.resetKey = resetKey
	// Stored last, so a loaded tag guarantees the reset key beside it is readable.
	d.tag.Store(tag)
	return nil
}

// interceptForLocked returns the stack terminating connections to origin, created on first
// use. Creation shares the draining critical section with shutdown, so no stack appears
// once draining began, and the caller closes any evicted stack once off the lock. The serve
// goroutine can still lose its race with a shutdown and leave the stack unserved, which the
// adopt TTL and the close that ends every drain both bound.
func (d *quicDemux) interceptForLocked(origin netip.AddrPort) (*quicIntercept, *quicIntercept, error) {
	key := netip.AddrPort{}
	if d.replier != nil {
		if !origin.IsValid() {
			return nil, nil, errNoReplyDestination
		}
		key = origin
	}
	if it := d.intercepts[key]; it != nil {
		it.lastSeen = time.Now()
		return it, nil, nil
	}

	// Selected now so a full cap refuses before anything is built, removed only once the
	// stack is up, so a failed creation costs no live stack.
	var victim *quicIntercept
	if len(d.intercepts) >= maxIntercepts {
		if victim = d.evictableLocked(); victim == nil {
			return nil, nil, errInterceptsBusy
		}
	}

	queue := interceptQueue
	if !key.IsValid() {
		queue = 4 * interceptQueue
	}
	dpc := newDemuxPacketConn(d.pc, queue)
	if d.replier != nil {
		reply, rerr := d.replySocketLocked(key)
		if rerr != nil {
			return nil, nil, rerr
		}
		from := key.String()
		dpc.reply = func(b []byte, addr net.Addr) (int, error) {
			// Errors are absorbed. A datagram is droppable, and an error returned here
			// ends the whole connection inside quic-go.
			if _, err := reply.WriteTo(b, addr); err != nil {
				d.p.cfg.logger.Debug("edge: intercepted reply dropped",
					slog.String("origin", from), slog.String("error", err.Error()))
			}
			return len(b), nil
		}
	}

	transport := &quic.Transport{
		Conn:                  dpc,
		ConnectionIDGenerator: d.tag.Load(),
		StatelessResetKey:     &d.resetKey,
		ConnContext: func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
			return context.WithValue(ctx, quicCarrierKey{}, &quicCarrier{client: info.RemoteAddr}), nil
		},
	}
	cfg := d.quicConfig()
	cfg.Tracer = func(ctx context.Context, _ bool, odcid quic.ConnectionID) qlogwriter.Trace {
		// Returns no trace. This callback is the one place quic-go reveals the original
		// destination connection ID, pre-Retry even when a Retry happened.
		if carrier, ok := ctx.Value(quicCarrierKey{}).(*quicCarrier); ok {
			carrier.odcid = string(odcid.Bytes())
			d.adopt(ctx, carrier.client, carrier.odcid)
		}
		return nil
	}
	ln, err := transport.ListenEarly(d.quicTLSConfig(), cfg)
	if err != nil {
		dpc.Close()
		_ = transport.Close()
		return nil, nil, fmt.Errorf("listen QUIC: %w", err)
	}

	if victim != nil {
		delete(d.intercepts, victim.origin)
	}
	it := &quicIntercept{origin: key, transport: transport, listener: ln, conn: dpc, lastSeen: time.Now()}
	d.intercepts[key] = it
	srv := d.h3
	d.wg.Go(func() {
		// ServeListener answers a shutdown with http.ErrServerClosed, and a listener closed
		// under it with an error unwrapping to net.ErrClosed. Neither is worth a line.
		err := srv.ServeListener(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			d.p.cfg.logger.Debug("edge: HTTP/3 server stopped", slog.String("error", err.Error()))
		}
	})
	return it, victim, nil
}

// evictableLocked returns the stack unused the longest, or nil when every one has live
// connections. The caller removes it from the map.
func (d *quicDemux) evictableLocked() *quicIntercept {
	var victim *quicIntercept
	for _, it := range d.intercepts {
		if it.conns > 0 {
			continue
		}
		if victim == nil || it.lastSeen.Before(victim.lastSeen) {
			victim = it
		}
	}
	return victim
}

// adopt ties the removal of an intercepted connection to its context, which ends with the
// connection however that happens, a failed handshake included.
func (d *quicDemux) adopt(ctx context.Context, client net.Addr, odcid string) {
	from := addrPort(client)
	d.mu.Lock()
	defer d.mu.Unlock()
	flow := d.flows[from]
	if flow == nil {
		return
	}
	if conn := flow.conns[odcid]; conn != nil && conn.state == connIntercepted {
		context.AfterFunc(ctx, func() { d.endIntercepted(from, odcid) })
	}
}

func (d *quicDemux) endIntercepted(from netip.AddrPort, odcid string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	flow := d.flows[from]
	if flow == nil {
		return
	}
	if conn := flow.conns[odcid]; conn != nil && conn.state == connIntercepted {
		d.removeConnLocked(flow, conn)
	}
}

// attach hands the HTTP/3 server the session of the connection it accepted, recording the
// connection for Session.Close to end. One doomed or dropped meanwhile is closed here
// instead, the tag having no state left to stop delivering it.
func (d *quicDemux) attach(carrier *quicCarrier, c *quic.Conn) *Session {
	from := addrPort(carrier.client)
	d.mu.Lock()
	var conn *quicConn
	if flow := d.flows[from]; flow != nil {
		conn = flow.conns[carrier.odcid]
		if conn != nil && conn.doomed {
			d.removeConnLocked(flow, conn)
		}
	}
	if conn == nil || conn.doomed || conn.state != connIntercepted {
		d.mu.Unlock()
		_ = c.CloseWithError(h3NoError, "")
		return nil
	}
	conn.qc = c
	sess := conn.sess
	d.mu.Unlock()
	return sess
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
	sweep := time.NewTicker(5 * time.Second)
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

	buf := make([]byte, maxUDPPayload)
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
	from := addrPort(addr)
	if !from.IsValid() {
		return
	}
	if datagram[0]&0x80 != 0 {
		d.dispatchLong(addr, from, datagram)
		return
	}
	d.dispatchShort(addr, from, datagram)
}

func (d *quicDemux) dispatchLong(addr net.Addr, from netip.AddrPort, datagram []byte) {
	version, dcid, _, ok := quicsniff.ParseLongHeader(datagram)
	if !ok {
		// A raw protocol is free to set the high bit, so failing the parse places the
		// datagram by its destination rather than dropping it.
		d.dispatchRaw(addr, from, datagram)
		return
	}

	now := time.Now()
	d.mu.Lock()
	flow := d.flows[from]
	if flow != nil {
		flow.lastSeen = now
		if conn := flow.conns[string(dcid)]; conn != nil {
			switch conn.state {
			case connTunneling:
				up := conn.relay.upstream
				d.mu.Unlock()
				_, _ = up.Write(datagram)
			case connIntercepted:
				conn.lastSeen = now
				stack := conn.stack
				d.mu.Unlock()
				stack.deliver(addr, datagram)
			case connRejected:
				conn.lastSeen = now
				d.mu.Unlock()
			default:
				conn.lastSeen = now
				d.mu.Unlock()
				d.sniff(from, conn, datagram)
			}
			return
		}
		if relay := flow.learned[string(dcid)]; relay != nil {
			up := relay.upstream
			d.mu.Unlock()
			_, _ = up.Write(datagram)
			return
		}
	}
	if tag := d.tag.Load(); tag != nil && tag.matches(dcid) {
		// Initials are not exempt, since after a Retry the client's next Initial addresses
		// the server's chosen ID and is only routable this way. With the stack gone the
		// datagram is dropped, only a short header gets a reset.
		it, _, _ := d.lookupInterceptLocked(addr)
		d.mu.Unlock()
		if it != nil {
			it.deliver(addr, datagram)
		}
		return
	}
	if quicsniff.IsInitial(datagram[0], version) &&
		len(datagram) >= quicsniff.MinClientInitialDatagram && len(dcid) >= 8 {
		conn := d.admitConnLocked(from, addr, string(dcid), now)
		d.mu.Unlock()
		if conn != nil {
			d.sniff(from, conn, datagram)
		}
		return
	}
	up := d.fallbackLocked(flow, addr)
	d.mu.Unlock()
	if up != nil {
		_, _ = up.Write(datagram)
		return
	}
	d.rawAdmit(addr, from, datagram)
}

// dispatchShort places a short header datagram, whose connection ID length is not on the
// wire, so the learned IDs are probed at each length the origins use.
func (d *quicDemux) dispatchShort(addr net.Addr, from netip.AddrPort, datagram []byte) {
	now := time.Now()
	d.mu.Lock()
	flow := d.flows[from]
	if flow != nil {
		flow.lastSeen = now
		for l := 1; l <= 20; l++ {
			if flow.lens&(1<<l) == 0 || len(datagram) < 1+l {
				continue
			}
			if relay := flow.learned[string(datagram[1:1+l])]; relay != nil {
				up := relay.upstream
				d.mu.Unlock()
				_, _ = up.Write(datagram)
				return
			}
		}
	}
	if tag := d.tag.Load(); tag != nil && len(datagram) >= 1+8 && tag.matches(datagram[1:9]) {
		// No flow needed. The tag survives a client whose address changed in flight, and
		// quic-go validates the new path itself.
		it, origin, ok := d.lookupInterceptLocked(addr)
		d.mu.Unlock()
		if it != nil {
			it.deliver(addr, datagram)
		} else if ok {
			d.statelessReset(addr, origin, datagram)
		}
		return
	}
	up := d.fallbackLocked(flow, addr)
	d.mu.Unlock()
	if up != nil {
		_, _ = up.Write(datagram)
		return
	}
	d.rawAdmit(addr, from, datagram)
}

// dispatchRaw places a datagram whose bytes rule out QUIC. An existing relay of its flow
// takes it, or raw admission decides it.
func (d *quicDemux) dispatchRaw(addr net.Addr, from netip.AddrPort, datagram []byte) {
	d.mu.Lock()
	flow := d.flows[from]
	if flow != nil {
		flow.lastSeen = time.Now()
	}
	up := d.fallbackLocked(flow, addr)
	d.mu.Unlock()
	if up != nil {
		_, _ = up.Write(datagram)
		return
	}
	d.rawAdmit(addr, from, datagram)
}

// fallbackLocked places a datagram no connection ID could attribute, the steady state of
// every tunnel once the client rotates to IDs it received encrypted (RFC 9000 section 5.1).
// The destination picks the relay when the platform reports it exactly, and a flow with a
// single relay leaves one place to send.
func (d *quicDemux) fallbackLocked(flow *quicFlow, client net.Addr) net.Conn {
	if flow == nil || len(flow.relays) == 0 {
		return nil
	}
	if d.exactOrigins {
		if origin := d.originalDst(client); origin.IsValid() {
			if relay := flow.relays[origin]; relay != nil {
				return relay.upstream
			}
			// The destination is known and no relay goes there. Anywhere else would be
			// the wrong origin.
			return nil
		}
	}
	if len(flow.relays) == 1 {
		for _, relay := range flow.relays {
			return relay.upstream
		}
	}
	return nil
}

// replySocketLocked returns the sending socket of one origin, opened on first use. The bind
// is a local pair of syscalls, cheap enough to hold the lock through.
func (d *quicDemux) replySocketLocked(origin netip.AddrPort) (net.PacketConn, error) {
	if sock := d.replySockets[origin]; sock != nil {
		return sock, nil
	}
	sock, err := d.replier.replySocket(origin)
	if err != nil {
		return nil, err
	}
	d.replySockets[origin] = sock
	return sock, nil
}

// lookupInterceptLocked resolves the stack a tagged datagram feeds, by its original
// destination under TPROXY and the zero key anywhere else. A nil stack with ok set may be
// answered with a stateless reset. Not ok means the destination is unknown and the datagram
// undeliverable.
func (d *quicDemux) lookupInterceptLocked(client net.Addr) (it *quicIntercept, origin netip.AddrPort, ok bool) {
	key := netip.AddrPort{}
	if d.replier != nil {
		key = d.originalDst(client)
		if !key.IsValid() {
			return nil, netip.AddrPort{}, false
		}
	}
	it = d.intercepts[key]
	if it != nil {
		it.lastSeen = time.Now()
	}
	return it, key, true
}

// statelessReset answers a tagged short header packet with no stack left behind it, so the
// client learns its connection is dead instead of waiting out its idle timeout. The token
// matches the one the stack advertised, both derived from the same key (RFC 9000 section
// 10.3). Under TPROXY the reset leaves from a reply socket the demux already holds, since
// opening one for an unauthenticated datagram would hand an attacker file descriptors.
func (d *quicDemux) statelessReset(client net.Addr, origin netip.AddrPort, datagram []byte) {
	if len(datagram) <= quicResetSize {
		return
	}
	pkt := make([]byte, quicResetSize)
	if _, err := rand.Read(pkt[:quicResetSize-16]); err != nil {
		return
	}
	pkt[0] = pkt[0]&0x3f | 0x40
	mac := hmac.New(sha256.New, d.resetKey[:])
	mac.Write(datagram[1:9])
	copy(pkt[quicResetSize-16:], mac.Sum(nil)[:16])

	if origin.IsValid() {
		d.mu.Lock()
		sock := d.replySockets[origin]
		d.mu.Unlock()
		if sock != nil {
			_, _ = sock.WriteTo(pkt, client)
		}
		return
	}
	_, _ = d.pc.WriteTo(pkt, client)
}

// rawAdmit is the terminal step of dispatch, for a datagram nothing QUIC could attribute.
// With no server name to decide on, the authority tree answers for the destination the
// client wrote, and a Tunnel entry there opens a relay carrying the bytes untouched.
func (d *quicDemux) rawAdmit(client net.Addr, from netip.AddrPort, datagram []byte) {
	origin := d.originalDst(client)
	if !origin.IsValid() {
		return
	}

	d.mu.Lock()
	if flow := d.flows[from]; flow != nil {
		// The platform answered with an origin the fallback could not see, natlook on a
		// flow with several relays typically.
		if relay := flow.relays[origin]; relay != nil {
			up := relay.upstream
			d.mu.Unlock()
			_, _ = up.Write(datagram)
			return
		}
	}
	d.mu.Unlock()

	target := Target{Host: origin.Addr().String(), Port: fmt.Sprint(origin.Port())}
	action := d.p.ActionFor(target)
	if action != Tunnel {
		reason := "no tunnel matches this destination"
		if action == Intercept {
			reason = "an intercepted authority cannot carry raw datagrams"
		}
		d.p.cfg.logger.Debug("edge: raw datagram dropped",
			slog.String("client", from.String()),
			slog.String("origin", origin.String()),
			slog.String("reason", reason))
		return
	}

	upstream, err := d.dialUpstreamUDP(target, origin)
	if err != nil {
		d.p.cfg.logger.Debug("edge: cannot reach the origin",
			slog.String("origin", origin.String()), slog.String("error", err.Error()))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	sess := newSession(ctx, nil, target, Tunnel, UDP)
	sess.remoteAddr = client
	sess.localAddr = d.pc.LocalAddr()
	sess.transparent = true
	sess.upstream = origin
	relay := &quicRelay{upstream: upstream, key: origin, raw: true, sess: sess, cancel: cancel}
	sess.closer = &rawRelayCloser{d: d, flow: from, relay: relay}

	d.mu.Lock()
	ok := d.publishRawLocked(from, client, relay)
	d.mu.Unlock()
	if !ok {
		cancel()
		_ = upstream.Close()
		d.p.cfg.logger.Debug("edge: raw datagram dropped",
			slog.String("client", from.String()),
			slog.String("origin", origin.String()),
			slog.String("reason", "the proxy is at capacity or shutting down"))
		return
	}

	// See beginTunnel. Published, so a sweep started after the tree changed either found
	// the session or ran before this read, which then observes the change.
	if d.p.ActionFor(target) == Reject {
		d.closeRelay(from, relay)
		return
	}

	_, _ = relay.upstream.Write(datagram)
}

// publishRawLocked places a raw relay in its flow, created when the datagram is the first
// of its socket. It shares the draining critical section with shutdown, so the relay is
// either refused or in the snapshot a shutdown sweeps.
func (d *quicDemux) publishRawLocked(from netip.AddrPort, client net.Addr, relay *quicRelay) bool {
	if d.draining.Load() || d.relays >= maxRelays {
		return false
	}
	flow := d.flowLocked(from, client, time.Now())
	if flow == nil || len(flow.relays) >= maxRelaysPerFlow || flow.relays[relay.key] != nil {
		return false
	}
	if d.replier != nil {
		reply, err := d.replySocketLocked(relay.key)
		if err != nil {
			return false
		}
		relay.reply = reply
	}
	flow.relays[relay.key] = relay
	d.relays++
	d.wg.Go(func() { d.runRelay(from, client, relay) })
	return true
}

// flowLocked returns the flow of one client socket, created on first sight, or nil at the
// flow cap.
func (d *quicDemux) flowLocked(from netip.AddrPort, client net.Addr, now time.Time) *quicFlow {
	flow := d.flows[from]
	if flow == nil {
		if len(d.flows) >= maxQUICFlows {
			return nil
		}
		flow = &quicFlow{
			lastSeen: now,
			client:   client,
			conns:    make(map[string]*quicConn),
			relays:   make(map[netip.AddrPort]*quicRelay),
			learned:  make(map[string]*quicRelay),
		}
		d.flows[from] = flow
	}
	return flow
}

func (d *quicDemux) admitConnLocked(from netip.AddrPort, client net.Addr, odcid string, now time.Time) *quicConn {
	if d.draining.Load() || d.sniffing >= maxSniffingConns {
		return nil
	}
	flow := d.flowLocked(from, client, now)
	if flow == nil {
		return nil
	}
	if len(flow.conns) >= maxConnsPerFlow {
		return nil
	}
	conn := &quicConn{
		lastSeen: now,
		odcid:    odcid,
		sniffer:  quicsniff.New(),
		origin:   d.originalDst(client),
		state:    connSniffing,
	}
	flow.conns[odcid] = conn
	d.sniffing++
	return conn
}

// setStateLocked keeps the sniffing count and the stack references in step with the state
// changes.
func (d *quicDemux) setStateLocked(conn *quicConn, s quicConnState) {
	if conn.state == connSniffing && s != connSniffing {
		d.sniffing--
	}
	if conn.state == connIntercepted && s != connIntercepted {
		d.releaseInterceptLocked(conn)
	}
	conn.state = s
}

func (d *quicDemux) removeConnLocked(flow *quicFlow, conn *quicConn) {
	if conn.state == connSniffing {
		d.sniffing--
	}
	if conn.state == connIntercepted {
		d.releaseInterceptLocked(conn)
	}
	delete(flow.conns, conn.odcid)
	conn.end()
}

func (d *quicDemux) releaseInterceptLocked(conn *quicConn) {
	if conn.stack != nil {
		conn.stack.conns--
		conn.stack.lastSeen = time.Now()
		conn.stack = nil
	}
}

// sniff feeds a datagram to the reassembler and decides the connection once its ClientHello
// is complete. A first flight datagram with no Initial in it, 0-RTT typically, still joins
// the pending ones, so the winning side receives the flight whole.
func (d *quicDemux) sniff(from netip.AddrPort, conn *quicConn, datagram []byte) {
	kept := bytes.Clone(datagram)

	hello, err := conn.sniffer.Feed(kept)
	if err != nil && !errors.Is(err, quicsniff.ErrNotInitial) {
		d.p.cfg.logger.Debug("edge: cannot read the QUIC ClientHello",
			slog.String("client", from.String()), slog.String("error", err.Error()))
		d.rejectConn(from, conn, err.Error())
		return
	}

	d.mu.Lock()
	flow := d.flows[from]
	if flow == nil || flow.conns[conn.odcid] != conn || conn.state != connSniffing {
		d.mu.Unlock()
		return
	}
	if len(conn.pending) >= maxPendingDatagrams || conn.pendingBytes+len(kept) > maxPendingBytes {
		d.mu.Unlock()
		d.rejectConn(from, conn, "ClientHello spans too many datagrams")
		return
	}
	conn.pending = append(conn.pending, kept)
	conn.pendingBytes += len(kept)
	client := flow.client
	pending := conn.pending
	d.mu.Unlock()

	if hello == nil {
		return // still arriving
	}

	if d.p.cfg.rejectECH {
		offered, ok := offersECH(hello)
		if !ok {
			d.rejectConn(from, conn, "ClientHello cannot be checked for Encrypted Client Hello")
			return
		}
		if offered {
			d.rejectConn(from, conn, "ClientHello offers Encrypted Client Hello")
			return
		}
	}

	ch := clientHelloFromQUIC(hello)
	target := d.targetFor(ch, conn.origin)
	if target.Host == "" {
		d.rejectConn(from, conn, "no server name in the ClientHello")
		return
	}

	named := ch != nil && ch.ServerName != ""
	action, target, verdict := d.p.actionForTransparent(d.ctx, target, conn.origin, named)
	switch verdict {
	case nameMismatch:
		d.rejectConn(from, conn, "the server name does not resolve to the destination")
		return
	case nameUnresolved:
		d.rejectConn(from, conn, "the server name cannot be resolved")
		return
	}

	switch action {
	case Reject:
		d.rejectConn(from, conn, "no interceptor or tunnel matches this authority")
	case Intercept:
		d.beginIntercept(from, client, conn, target, ch, pending)
	default:
		d.beginTunnel(from, client, conn, target, ch, pending)
	}
}

// targetFor works out where a QUIC connection was headed, from the server name it offered
// and, when known, the address its first datagram was redirected from.
func (d *quicDemux) targetFor(hello *ClientHello, origin netip.AddrPort) Target {
	target := Target{Scheme: "https", Port: "443"}

	if hello != nil && hello.ServerName != "" {
		target.Host = stringsutil.ToLowerASCIIString(hello.ServerName)
	}

	if origin.IsValid() {
		target.Port = fmt.Sprint(origin.Port())
		if target.Host == "" {
			target.Host = origin.Addr().String()
		}
	}
	return target
}

// originalDst resolves where the datagram last read from client was headed before the
// redirect, or the zero value when there was none.
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

// newQUICSession builds the session of one QUIC connection. The upstream is the address the
// client was headed to, not a fresh resolution of the authority, which behind a redirect
// may not resolve at all.
func (d *quicDemux) newQUICSession(from netip.AddrPort, client net.Addr, conn *quicConn, target Target, hello *ClientHello, action Action) (*Session, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sess := newSession(ctx, nil, target, action, QUIC)
	sess.remoteAddr = client
	sess.localAddr = d.pc.LocalAddr()
	sess.transparent = true
	sess.upstream = conn.origin
	sess.clientHello = hello
	sess.closer = &quicConnCloser{d: d, flow: from, odcid: conn.odcid}
	return sess, cancel
}

func (d *quicDemux) beginIntercept(from netip.AddrPort, client net.Addr, conn *quicConn, target Target, hello *ClientHello, pending [][]byte) {
	if err := d.startInterception(); err != nil {
		if !errors.Is(err, ErrProxyClosed) {
			d.p.cfg.logger.Error("edge: cannot intercept QUIC", slog.String("error", err.Error()))
		}
		d.rejectConn(from, conn, err.Error())
		return
	}

	sess, cancel := d.newQUICSession(from, client, conn, target, hello, Intercept)

	d.mu.Lock()
	flow := d.flows[from]
	if flow == nil || flow.conns[conn.odcid] != conn || conn.state != connSniffing {
		d.mu.Unlock()
		cancel()
		return
	}
	// Inside the publish critical section, so a shutdown either refuses this connection or
	// finds it in the snapshot it takes under the same lock. startInterception alone cannot
	// guarantee that once the server is already up.
	if d.draining.Load() {
		d.mu.Unlock()
		cancel()
		d.rejectConn(from, conn, "the proxy is shutting down")
		return
	}
	it, evicted, err := d.interceptForLocked(conn.origin)
	if err != nil {
		d.mu.Unlock()
		cancel()
		d.rejectConn(from, conn, err.Error())
		return
	}
	d.setStateLocked(conn, connIntercepted)
	conn.pending = nil
	conn.pendingBytes = 0
	conn.sess = sess
	conn.cancel = cancel
	conn.stack = it
	it.conns++
	d.mu.Unlock()
	if evicted != nil {
		d.closeIntercept(evicted)
	}

	// The session is published, so a sweep started after the tree changed either found it or
	// ran before this read, which then observes the change. Nothing has been handed to the
	// QUIC server yet, so a connection refused here never completes a handshake.
	if d.p.ActionFor(target) == Reject {
		d.rejectConn(from, conn, "the authority was withdrawn while the connection was starting")
		return
	}

	for _, dg := range pending {
		it.deliver(client, dg)
	}
}

func (d *quicDemux) beginTunnel(from netip.AddrPort, client net.Addr, conn *quicConn, target Target, hello *ClientHello, pending [][]byte) {
	sess, cancel := d.newQUICSession(from, client, conn, target, hello, Tunnel)

	d.mu.Lock()
	relay, ok := d.placeTunnelLocked(from, conn, conn.origin, nil, sess, cancel)
	d.mu.Unlock()
	if !ok {
		cancel()
		return
	}
	if relay == nil {
		upstream, err := d.dialUpstreamUDP(target, conn.origin)
		if err != nil {
			cancel()
			d.p.cfg.logger.Debug("edge: cannot reach the QUIC origin",
				slog.String("target", target.String()), slog.String("error", err.Error()))
			d.rejectConn(from, conn, err.Error())
			return
		}
		d.mu.Lock()
		relay, ok = d.placeTunnelLocked(from, conn, addrPort(upstream.RemoteAddr()), upstream, sess, cancel)
		d.mu.Unlock()
		if !ok {
			_ = upstream.Close()
			cancel()
			return
		}
		if relay.upstream != upstream {
			// Another decision resolved the same origin first and this socket is redundant.
			_ = upstream.Close()
		}
	}

	// See beginIntercept. Enforcement is per relay, the packets of siblings being
	// indistinguishable, so a tree that no longer accepts the authority costs the relay.
	if d.p.ActionFor(target) == Reject {
		d.closeRelay(from, relay)
		d.p.cfg.logger.Debug("edge: QUIC connection dropped",
			slog.String("client", from.String()),
			slog.String("reason", "the authority was withdrawn while the connection was starting"))
		return
	}

	for _, dg := range pending {
		if _, err := relay.upstream.Write(dg); err != nil {
			break
		}
	}
}

// placeTunnelLocked publishes a tunneled connection onto the relay for key, dialing left to
// the caller when it returns no relay with ok true. The draining check, the relay start and
// the placement share one critical section, so a shutdown refuses all of it or sweeps all
// of it.
func (d *quicDemux) placeTunnelLocked(from netip.AddrPort, conn *quicConn, key netip.AddrPort, upstream net.Conn, sess *Session, cancel context.CancelFunc) (*quicRelay, bool) {
	flow := d.flows[from]
	if flow == nil || flow.conns[conn.odcid] != conn || conn.state != connSniffing {
		return nil, false
	}
	if d.draining.Load() {
		return nil, false
	}

	var relay *quicRelay
	if key.IsValid() {
		relay = flow.relays[key]
	}
	if relay == nil {
		if len(flow.relays) >= maxRelaysPerFlow || d.relays >= maxRelays {
			return nil, false
		}
		if upstream == nil {
			return nil, true
		}
		relay = &quicRelay{upstream: upstream, key: key}
		if d.replier != nil {
			reply, err := d.replySocketLocked(key)
			if err != nil {
				return nil, false
			}
			relay.reply = reply
		}
		flow.relays[key] = relay
		d.relays++
		// The relay's Add shares the critical section with the close that waits on the
		// group, so it either precedes the wait or does not happen.
		client := flow.client
		d.wg.Go(func() { d.runRelay(from, client, relay) })
	}
	// A raw relay reached first can end up carrying a QUIC connection, reordered 0-RTT
	// ahead of its Initial typically. Learning has to resume, a Retry is unroutable
	// without the origin's IDs.
	relay.raw = false

	d.setStateLocked(conn, connTunneling)
	conn.pending = nil
	conn.pendingBytes = 0
	conn.sess = sess
	conn.cancel = cancel
	conn.relay = relay
	relay.conns = append(relay.conns, conn)
	return relay, true
}

// runRelay relays what the origin sends back to its client, learning the origin's
// connection IDs on the way. Learning happens before the write to the client, so by
// causality a client can never use an ID before the demux knows it, a Retry included.
func (d *quicDemux) runRelay(from netip.AddrPort, client net.Addr, relay *quicRelay) {
	defer func() { _ = relay.upstream.Close() }()
	buf := make([]byte, maxUDPPayload)
	for {
		_ = relay.upstream.SetReadDeadline(time.Now().Add(quicRelayIdle))
		n, err := relay.upstream.Read(buf)
		if n > 0 {
			d.learnOrigin(from, relay, buf[:n])
			// Verbatim, parseable or not. A stateless reset is a short header packet the
			// client depends on receiving.
			var werr error
			if relay.reply != nil {
				_, werr = relay.reply.WriteTo(buf[:n], client)
			} else {
				_, werr = d.pc.WriteTo(buf[:n], client)
			}
			if werr != nil {
				d.closeRelay(from, relay)
				return
			}
		}
		if err != nil {
			d.closeRelay(from, relay)
			return
		}
		select {
		case <-d.done:
			return
		default:
		}
	}
}

// learnOrigin records the source connection ID of an origin's long header packet, the only
// place the origin's IDs are ever readable on this path.
func (d *quicDemux) learnOrigin(from netip.AddrPort, relay *quicRelay, datagram []byte) {
	if len(datagram) == 0 || datagram[0]&0x80 == 0 {
		return
	}
	version, _, scid, ok := quicsniff.ParseLongHeader(datagram)
	// Version Negotiation echoes the client's own IDs and teaches nothing, and a zero
	// length ID would put an empty key in the table, matching every probe.
	if !ok || version == 0 || len(scid) == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	flow := d.flows[from]
	if flow == nil || relay.closed || relay.raw || relay.learned >= maxLearnedPerRelay {
		return
	}
	if _, seen := flow.learned[string(scid)]; seen {
		return
	}
	relay.learned++
	flow.learned[string(scid)] = relay
	flow.lens |= 1 << len(scid)
}

// closeRelay tears down the relay, its learned IDs and every connection on it, whose
// sessions end here.
func (d *quicDemux) closeRelay(from netip.AddrPort, relay *quicRelay) {
	d.mu.Lock()
	flow := d.flows[from]
	if flow == nil || relay.closed {
		d.mu.Unlock()
		return
	}
	relay.closed = true
	delete(flow.relays, relay.key)
	d.relays--
	if relay.cancel != nil {
		relay.cancel()
	}
	for cid, r := range flow.learned {
		if r == relay {
			delete(flow.learned, cid)
		}
	}
	flow.lens = 0
	for cid := range flow.learned {
		flow.lens |= 1 << len(cid)
	}
	for _, conn := range relay.conns {
		d.removeConnLocked(flow, conn)
	}
	d.mu.Unlock()
	_ = relay.upstream.Close()
}

func (d *quicDemux) dialUpstreamUDP(target Target, origin netip.AddrPort) (net.Conn, error) {
	addr := target.Authority()
	if origin.IsValid() {
		addr = origin.String()
	}
	return net.DialTimeout("udp", addr, 10*time.Second)
}

// rejectConn marks a connection refused. The state stays as a tombstone until its TTL, so
// the client's Initial retransmits are dropped without being decrypted again, and a fresh
// Initial with a new connection ID from the same socket is evaluated from scratch.
func (d *quicDemux) rejectConn(from netip.AddrPort, conn *quicConn, reason string) {
	d.mu.Lock()
	if flow := d.flows[from]; flow != nil && flow.conns[conn.odcid] == conn {
		d.setStateLocked(conn, connRejected)
		conn.lastSeen = time.Now()
		conn.sniffer = nil
		conn.pending = nil
		conn.pendingBytes = 0
		conn.sess = nil
		conn.end()
	}
	d.mu.Unlock()
	d.p.cfg.logger.Debug("edge: QUIC connection dropped",
		slog.String("client", from.String()), slog.String("reason", reason))
}

func (d *quicDemux) sweepIdle() {
	now := time.Now()
	d.mu.Lock()
	for from, flow := range d.flows {
		for _, conn := range flow.conns {
			switch conn.state {
			case connSniffing:
				if now.Sub(conn.lastSeen) > quicSniffTTL {
					d.removeConnLocked(flow, conn)
				}
			case connRejected:
				if now.Sub(conn.lastSeen) > quicRejectTTL {
					d.removeConnLocked(flow, conn)
				}
			case connIntercepted:
				// Removed when its connection context ends, unless the handshake never
				// reached the server and no AfterFunc was registered.
				if conn.qc == nil && now.Sub(conn.lastSeen) > quicAdoptTTL {
					d.removeConnLocked(flow, conn)
				}
			case connTunneling:
				// Lives and dies with its relay. The connection's own end is encrypted, so
				// the relay's return traffic is the only liveness signal.
			}
		}
		if len(flow.conns) == 0 && len(flow.relays) == 0 && now.Sub(flow.lastSeen) > quicSniffTTL {
			delete(d.flows, from)
		}
	}
	idle := d.sweepInterceptsLocked(now)
	d.sweepRepliesLocked()
	d.mu.Unlock()
	for _, it := range idle {
		d.closeIntercept(it)
	}
}

// sweepInterceptsLocked removes the stacks no connection has fed for a while. The caller
// closes them off the lock, Transport.Close waiting on goroutines of its own.
func (d *quicDemux) sweepInterceptsLocked(now time.Time) []*quicIntercept {
	var idle []*quicIntercept
	for key, it := range d.intercepts {
		if it.conns == 0 && now.Sub(it.lastSeen) > quicInterceptTTL {
			delete(d.intercepts, key)
			idle = append(idle, it)
		}
	}
	return idle
}

// sweepRepliesLocked closes the reply sockets nothing uses any more, after the stack sweep
// so a stack removed this pass frees its socket immediately.
func (d *quicDemux) sweepRepliesLocked() {
	if d.replier == nil {
		return
	}
	used := make(map[netip.AddrPort]bool, len(d.replySockets))
	for _, flow := range d.flows {
		for key, relay := range flow.relays {
			if relay.reply != nil {
				used[key] = true
			}
		}
	}
	for origin := range d.intercepts {
		used[origin] = true
	}
	for origin, sock := range d.replySockets {
		if !used[origin] {
			delete(d.replySockets, origin)
			_ = sock.Close()
		}
	}
}

// shutdown drains the demux. Nothing new is placed, the terminating server tells its clients
// with a GOAWAY and waits for their requests, and the tunnels are relayed until they go
// quiet or ctx is done. The read loop keeps running through all of it, because the
// connections being drained only finish if their datagrams still arrive.
func (d *quicDemux) shutdown(ctx context.Context) error {
	d.mu.Lock()
	d.draining.Store(true)
	h3 := d.h3
	d.mu.Unlock()

	var err error
	if h3 != nil {
		err = h3.Shutdown(ctx)
	}

	// A tunnel ends invisibly, the far side stops answering and the relay ages out through
	// its read deadline. Polling for that is all there is to wait on. The done case covers
	// a teardown that started elsewhere, and joining the close waits for it.
	tick := time.Tick(500 * time.Millisecond)
poll:
	for d.tunneling() {
		select {
		case <-tick:
		case <-ctx.Done():
			break poll
		case <-d.done:
			break poll
		}
	}

	d.close()
	return err
}

// tunneling reports whether any relay is still up.
func (d *quicDemux) tunneling() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, flow := range d.flows {
		if len(flow.relays) > 0 {
			return true
		}
	}
	return false
}

func (d *quicDemux) Close() error { d.close(); return nil }

func (d *quicDemux) close() {
	d.closeOnce.Do(func() {
		close(d.done)
		d.cancel()

		d.mu.Lock()
		// The read loop publishes with no lock held across its dials, so close must refuse
		// a late publication the way a shutdown does.
		d.draining.Store(true)
		h3 := d.h3
		var sockets []net.Conn
		for _, flow := range d.flows {
			for _, relay := range flow.relays {
				relay.closed = true
				if relay.cancel != nil {
					relay.cancel()
				}
				sockets = append(sockets, relay.upstream)
			}
			for _, conn := range flow.conns {
				conn.end()
			}
		}
		replies := make([]net.PacketConn, 0, len(d.replySockets))
		for _, sock := range d.replySockets {
			replies = append(replies, sock)
		}
		intercepts := make([]*quicIntercept, 0, len(d.intercepts))
		for _, it := range d.intercepts {
			intercepts = append(intercepts, it)
		}
		clear(d.replySockets)
		clear(d.intercepts)
		clear(d.flows)
		d.sniffing = 0
		d.relays = 0
		d.mu.Unlock()

		for _, s := range sockets {
			_ = s.Close()
		}
		if h3 != nil {
			_ = h3.Close()
		}
		for _, it := range intercepts {
			d.closeIntercept(it)
		}
		for _, s := range replies {
			_ = s.Close()
		}

		_ = d.pc.Close()
		d.wg.Wait()
	})
}

// quicCIDTag mints and recognizes the connection IDs the terminating stacks emit, 4
// random bytes and 4 of a keyed MAC over them, so a packet of an intercepted connection is
// recognizable with no per connection state, NAT rebinding and restarts included. A random
// Initial DCID passes with probability 2^-32, the one way past the policy decision.
type quicCIDTag struct {
	block cipher.Block
}

func newQUICCIDTag(key [16]byte) (*quicCIDTag, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return &quicCIDTag{block: block}, nil
}

// GenerateConnectionID implements quic.ConnectionIDGenerator. quic-go parses short headers
// at the generator's length, so an ID of any other length is silently unroutable.
func (t *quicCIDTag) GenerateConnectionID() (quic.ConnectionID, error) {
	var cid [8]byte
	if _, err := rand.Read(cid[:4]); err != nil {
		return quic.ConnectionID{}, err
	}
	mac := t.mac(cid[:4])
	copy(cid[4:], mac[:])
	return quic.ConnectionIDFromBytes(cid[:]), nil
}

func (t *quicCIDTag) ConnectionIDLen() int { return 8 }

func (t *quicCIDTag) matches(cid []byte) bool {
	if len(cid) != 8 {
		return false
	}
	mac := t.mac(cid[:4])
	return subtle.ConstantTimeCompare(cid[4:], mac[:]) == 1
}

// mac is one AES block over the random half, a MAC nothing short of the key can forge at
// the cost of one block on the dispatch path.
func (t *quicCIDTag) mac(r []byte) [4]byte {
	var in, out [16]byte
	copy(in[:], r)
	t.block.Encrypt(out[:], in[:])
	return [4]byte(out[:4])
}

// quicInterceptKeys derives the tag and stateless reset keys from the CA key so both survive
// a restart, which lets a connection minted by a previous process be recognized and reset
// instead of expiring on its idle timeout. A key that cannot be serialized, hardware backed
// for instance, falls back to per process random keys.
func quicInterceptKeys(ca *CA) (*quicCIDTag, quic.StatelessResetKey, error) {
	var tagKey [16]byte
	var reset quic.StatelessResetKey

	if der, err := x509.MarshalPKCS8PrivateKey(ca.key); err == nil {
		t, terr := hkdf.Key(sha256.New, der, nil, "edge quic cid tag", len(tagKey))
		r, rerr := hkdf.Key(sha256.New, der, nil, "edge quic stateless reset", len(reset))
		if terr == nil && rerr == nil {
			copy(tagKey[:], t)
			copy(reset[:], r)
			tag, err := newQUICCIDTag(tagKey)
			return tag, reset, err
		}
	}

	if _, err := rand.Read(tagKey[:]); err != nil {
		return nil, reset, err
	}
	if _, err := rand.Read(reset[:]); err != nil {
		return nil, reset, err
	}
	tag, err := newQUICCIDTag(tagKey)
	return tag, reset, err
}

// clientHelloFromQUIC reads the ClientHello out of a raw handshake message. QUIC carries
// handshake messages without a record layer, so one is put back for the sake of the parser.
func clientHelloFromQUIC(hello []byte) *ClientHello {
	if len(hello) == 0 || len(hello) > math.MaxUint16 {
		return nil
	}

	record := make([]byte, 0, 5+len(hello))
	record = append(record, 0x16, 0x03, 0x01)
	// Guarded above: the message is shorter than 65536 bytes.
	record = binary.BigEndian.AppendUint16(record, uint16(len(hello))) //nolint:gosec // bounded by the check above
	record = append(record, hello...)
	return clientHelloFromRecords(record)
}

// demuxPacketConn is the socket a terminating stack's transport reads from. Datagrams are pushed
// into it by the demultiplexer rather than read from the network, while writes go straight
// out of the real socket so the client sees answers from the address it wrote to.
type demuxPacketConn struct {
	real net.PacketConn
	// reply, set before the server ever writes, replaces the real socket for writes whose
	// source must be the address the client targeted.
	reply func(b []byte, addr net.Addr) (int, error)
	in    chan datagram

	closed chan struct{}

	readDeadline atomic.Pointer[time.Time]

	closeOnce sync.Once
}

type datagram struct {
	addr net.Addr
	b    []byte
}

func newDemuxPacketConn(real net.PacketConn, queue int) *demuxPacketConn {
	return &demuxPacketConn{
		real:   real,
		in:     make(chan datagram, queue),
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
	if c.reply != nil {
		return c.reply(b, addr)
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
// under load, and looks for these methods to size it. Every stack sizes the same socket,
// which is idempotent.
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
