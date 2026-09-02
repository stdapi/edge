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
	"slices"
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
	// quicSniffTTL reaps a connection whose ClientHello never completes, quicRejectTTL a
	// rejected one kept so Initial retransmits are not decrypted again, and quicAdoptTTL one
	// the QUIC server never accepted.
	quicSniffTTL  = 10 * time.Second
	quicRejectTTL = 30 * time.Second
	quicAdoptTTL  = time.Minute
	// udpFlowIdle reaps a datagram flow neither side has used for a while. A flow has no
	// handshake to end, so idleness is the only signal it is over.
	udpFlowIdle = 2 * time.Minute
	// The state caps. Everything below is allocated for an unauthenticated peer on a
	// spoofable transport, so the worst case is the product of these bounds.
	maxQUICFlows     = 4096
	maxConnsPerFlow  = 64
	maxSniffingConns = 512
	// Datagram flows are bounded on themselves: they are opened by a datagram, not by a
	// connection, so nothing else bounds them.
	maxUDPPerFlow = 16
	maxUDPFlows   = 1024
	// maxIntercepts bounds the terminating stacks, one per origin under TPROXY, each queueing
	// up to interceptQueue datagrams of maxUDPPayload (the shared stack of the other paths
	// four times as many). quicInterceptTTL reaps a stack no connection has fed for a while.
	// maxTunnels bounds them behind CONNECT-UDP, where every tunnel has one.
	maxIntercepts    = 64
	maxTunnels       = 1024
	interceptQueue   = 64
	quicInterceptTTL = time.Minute
	// quicResetSize is the size of the stateless resets the demux sends itself. Only a
	// datagram strictly larger gets one, which keeps two proxies from bouncing resets at each
	// other.
	quicResetSize = 42
)

// ListenAndServeTransparentUDP listens for UDP on addr and serves the datagrams redirected to
// it: QUIC connections, HTTP/3 among them, and raw datagram flows. A client configured with a
// proxy setting reaches [Proxy.ListenAndServeQUIC] instead and tunnels its UDP with
// CONNECT-UDP.
func (p *Proxy) ListenAndServeTransparentUDP(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = pc.Close() }()
	// A socket the platform cannot set up still serves every client that sends a server name,
	// which is every HTTP/3 client in practice.
	if transparent, terr := TransparentPacketConn(pc); terr == nil {
		pc = transparent
	} else {
		p.cfg.logger.Debug("edge: no original destination for datagrams", slog.String("error", terr.Error()))
	}
	return p.ServeTransparentUDP(pc)
}

// ServeTransparentUDP serves the redirected datagrams arriving on pc. Wrap pc in
// [TransparentPacketConn] to place a client by the address it was headed to. Without it a
// client is placed by its server name alone.
//
// Every QUIC connection is terminated. Its ClientHello names where it was headed and which
// protocol it asked for: a connection offering h3 is HTTP traffic and its requests are routed
// one by one, and one offering anything else is served by the [QUIC] entry admitting its
// authority, stream by stream. QUIC requires ALPN, so a connection offering none is refused
// rather than guessed at.
//
// A datagram that is not QUIC is placed by the address it was headed to, when the platform
// reports one, and served by the [UDP] entry admitting it, one datagram at a time. Encrypted
// datagrams belonging to a QUIC connection are never served that way: a connection the proxy
// cannot read is one it refuses rather than one it passes on.
//
// A [UDP] handler runs on the goroutine reading the socket, so one that blocks holds up every
// other client on it. So does the name resolution [WithNameVerification] asks for, on the
// connection being placed. Neither is true of the connection-level kinds, which run on a
// goroutine of their own.
//
// Under Encrypted Client Hello the decision sees the outer server name only, unless
// [WithRejectECH] refuses such connections. QUIC versions other than v1 and v2 are rejected.
// Behind a Linux TPROXY rule every datagram reports its exact destination and replies are sent
// from the address the client targeted. At most 64 origins are terminated at once there.
// Beyond that the origin longest without a live connection is reclaimed, and with every origin
// holding one a connection to a new origin is refused.
func (p *Proxy) ServeTransparentUDP(pc net.PacketConn) error {
	if p.srv.closing.Load() {
		return ErrProxyClosed
	}

	d, err := newQUICDemux(p, pc)
	if err != nil {
		return err
	}
	defer d.close()

	// A refused registration means a shutdown started; the socket is only closed through the
	// demux, so serving would leave run reading forever.
	if !p.srv.tryTrackDemux(d) {
		return ErrProxyClosed
	}
	defer p.srv.untrackDemux(d)

	return d.run()
}

// quicDemux owns one UDP socket and places every datagram arriving on it: into the QUIC
// connection it belongs to, into the terminating stack of its origin, or into the datagram
// flow serving its destination.
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

	// tag recognizes the connection IDs the terminating stacks emit, with no per connection
	// state. It and resetKey are set once, when the first connection is terminated.
	tag    atomic.Pointer[quicCIDTag]
	cancel context.CancelFunc

	done         chan struct{}
	flows        map[flowKey]*quicFlow
	replySockets map[netip.AddrPort]net.PacketConn
	// intercepts holds the terminating stacks, one per origin under TPROXY so replies leave
	// from the address the client targeted, one per CONNECT-UDP tunnel so a connection stays
	// with the identity that opened it, and one under the zero key anywhere else.
	intercepts map[interceptKey]*quicIntercept
	// raw holds the QUIC connections served by a [QUIC] handler. The HTTP/3 server owns the
	// ones it serves and drains them itself; these have to be closed by hand.
	raw map[*quic.Conn]struct{}

	wg sync.WaitGroup

	// maxStacks caps intercepts, maxIntercepts on a socket and maxTunnels behind tunnels.
	maxStacks int

	// sniffing counts the connections buffering a ClientHello across every flow, the memory
	// an unauthenticated peer controls, and udps counts the datagram flows.
	sniffing int
	udps     int

	closeOnce sync.Once

	mu sync.Mutex
	// draining refuses new placements while what is already placed finishes. It is written
	// and, on the paths that publish state, read under mu, so a publication is either refused
	// or visible to the first snapshot the shutdown takes.
	draining atomic.Bool

	resetKey quic.StatelessResetKey

	// exactOrigins is set when pc reads each datagram's destination from the datagram itself,
	// exact enough to attribute it by.
	exactOrigins bool
}

// flowKey identifies one client socket by its address, and by the CONNECT-UDP tunnel when the
// datagrams arrive through one.
type flowKey struct {
	tunnel *connectUDPTunnel
	addr   netip.AddrPort
}

func flowKeyOf(addr net.Addr) flowKey {
	if ta, ok := addr.(*tunnelAddr); ok {
		return flowKey{addr: ta.client, tunnel: ta.tunnel}
	}
	return flowKey{addr: addrPort(addr)}
}

func (k flowKey) String() string {
	if k.tunnel != nil {
		return k.tunnel.addr.String()
	}
	return k.addr.String()
}

// interceptKey identifies one terminating stack: the origin it replies from under TPROXY, the
// tunnel it serves behind CONNECT-UDP, and the zero value for the stack every other path
// shares.
type interceptKey struct {
	tunnel *connectUDPTunnel
	origin netip.AddrPort
}

// quicFlow is the state of one client socket, pinned to its source address. Re-pointing the
// return path on a cleartext signal would let anyone on the client's path redirect it.
type quicFlow struct {
	lastSeen time.Time
	client   net.Addr
	// conns is keyed by the DCID of each connection's first Initial.
	conns map[string]*quicConn
	// udp holds the datagram flows of this socket, one per destination.
	udp map[netip.AddrPort]*udpFlow
}

type quicConnState uint8

const (
	connSniffing quicConnState = iota
	connTerminated
	connRejected
)

// quicConn is one QUIC connection being placed. The kind it belongs to is read off its
// ClientHello, and the entry serving each of its units is looked up as the units arrive.
type quicConn struct {
	lastSeen time.Time
	sniffer  *quicsniff.Reassembler
	sess     *Session
	// qc is the terminated connection, nil until the QUIC server accepts it.
	qc     *quic.Conn
	cancel context.CancelFunc
	// stack terminates the connection, nil in every other state.
	stack *quicIntercept

	odcid string
	// origin is where the client was headed, resolved from the opening datagram since no
	// later one can answer it. declared is the target a CONNECT-UDP named, possibly a
	// hostname, and stays empty off a socket.
	origin       netip.AddrPort
	declared     Target
	pending      [][]byte
	pendingBytes int
	// kind is the kind the ClientHello named, KindHTTP for a connection offering h3 and
	// KindQUIC for anything else.
	kind  Kind
	state quicConnState
	// doomed marks a connection closed before the QUIC server accepted it.
	doomed bool
}

// end ends the context of the connection's session. Whoever removes a connection, or marks it
// rejected, has to call it.
func (c *quicConn) end() {
	if c.cancel != nil {
		c.cancel()
	}
}

// udpFlow is one datagram flow, a client socket talking to one destination. It holds the
// upstream socket and the decision cache the per-datagram lookup rides on.
type udpFlow struct {
	upstream net.Conn
	// reply, under TPROXY, is the shared per origin socket the return traffic leaves from.
	// The flow never owns it: the sweep closes it once no user is left.
	reply  net.PacketConn
	client net.Addr
	sink   *udpSink
	sess   *Session
	cancel context.CancelFunc
	target Target
	key    netip.AddrPort
	// out and in are the per direction contexts. A single goroutine serves each direction,
	// so at most one datagram is ever in flight on a context.
	out DatagramCtx
	in  DatagramCtx
	// lastSeenNano is when a datagram last travelled, either way. Both directions write it,
	// from their own goroutine, so it is read and written atomically.
	lastSeenNano atomic.Int64
	outSeq       atomic.Uint64
	inSeq        atomic.Uint64
	closed       bool
	started      bool
}

// quicIntercept terminates the QUIC connections of one origin. Under TPROXY its replies leave
// from that origin's address, and the zero origin is the stack shared by every path replying
// from the proxy's own socket.
type quicIntercept struct {
	lastSeen  time.Time
	transport *quic.Transport
	listener  *quic.Listener
	conn      *demuxPacketConn
	key       interceptKey
	// conns counts the live connections, and a stack holding any is neither swept nor
	// evicted.
	conns int
}

// deliver hands a datagram to the stack's QUIC transport.
func (it *quicIntercept) deliver(addr net.Addr, datagram []byte) {
	it.conn.deliver(addr, datagram)
}

// closeIntercept tears one stack down. The listener goes first, so the accept loop returns the
// error it filters, then the packet conn, unblocking the read Transport.Close waits on.
func (d *quicDemux) closeIntercept(it *quicIntercept) {
	_ = it.listener.Close()
	it.conn.Close()
	_ = it.transport.Close()
}

// h3NoError is HTTP/3's H3_NO_ERROR, what a peer sends when it closes a connection with
// nothing to report.
const h3NoError quic.ApplicationErrorCode = 0x100

// closeNoError closes qc with the no-error code of the protocol it negotiated, since the
// application error space belongs to that protocol. An h3 connection served stream by stream
// still gets H3_NO_ERROR.
func closeNoError(qc *quic.Conn) error {
	var code quic.ApplicationErrorCode
	if qc.ConnectionState().TLS.NegotiatedProtocol == "h3" {
		code = h3NoError
	}
	return qc.CloseWithError(code, "")
}

var (
	errNoReplyDestination = errors.New("no destination to source the replies from")
	errInterceptsBusy     = errors.New("every terminating stack has live connections")
)

// quicConnCloser ends one QUIC connection. Every connection here is terminated by the proxy
// and owns its own state, so closing one closes exactly it.
type quicConnCloser struct {
	flow  flowKey
	d     *quicDemux
	odcid string
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
	if conn.state == connTerminated && conn.qc == nil {
		// The tag delivers this connection's packets with no state to drop, so removing it
		// would let the handshake finish unobserved. accept ends a doomed connection when the
		// server takes it, the adopt TTL when it never does.
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
	return closeNoError(qc)
}

// udpFlowCloser ends one datagram flow. The flow is the whole of what its session covers, so
// closing the session closes exactly that.
//
// It does not bar the destination afterwards. Every datagram is routed on the tree as it
// stands, so what a client may reach is the tree's answer and not a memory of this close: a
// client that keeps sending opens a new flow exactly when an entry still admits it.
type udpFlowCloser struct {
	d    *quicDemux
	flow flowKey
	key  netip.AddrPort
}

func (c *udpFlowCloser) Close() error {
	c.d.mu.Lock()
	var sock net.Conn
	if flow := c.d.flows[c.flow]; flow != nil {
		if u := flow.udp[c.key]; u != nil && !u.closed {
			u.closed = true
			sock = u.upstream
			if u.cancel != nil {
				u.cancel()
			}
			delete(flow.udp, c.key)
			c.d.udps--
		}
	}
	c.d.mu.Unlock()
	if sock != nil {
		return sock.Close()
	}
	return nil
}

// appendSessions adds the sessions of what this demux serves to out.
func (d *quicDemux) appendSessions(out []*Session) []*Session {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, flow := range d.flows {
		for _, conn := range flow.conns {
			if conn.sess != nil {
				out = append(out, conn.sess)
			}
		}
		for _, u := range flow.udp {
			if u.sess != nil {
				out = append(out, u.sess)
			}
		}
	}
	return out
}

func newQUICDemux(p *Proxy, pc net.PacketConn) (*quicDemux, error) {
	d := &quicDemux{
		p:         p,
		pc:        pc,
		flows:     make(map[flowKey]*quicFlow),
		raw:       make(map[*quic.Conn]struct{}),
		done:      make(chan struct{}),
		maxStacks: maxIntercepts,
	}
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.origins, _ = pc.(PacketOriginalDestination)
	if e, ok := pc.(interface{ exactOriginalDestination() bool }); ok && d.origins != nil {
		d.exactOrigins = e.exactOriginalDestination()
	}
	if _, ok := pc.(*tunnelPacketConn); ok {
		d.maxStacks = maxTunnels
	}
	d.intercepts = make(map[interceptKey]*quicIntercept)
	if r, ok := pc.(transparentReplier); ok && r.transparentReplies() {
		d.replier = r
		d.replySockets = make(map[netip.AddrPort]net.PacketConn)
	}
	// Started before the demux is visible to anyone, so this Add cannot race the Wait in close.
	d.wg.Go(func() {
		sweep := time.NewTicker(5 * time.Second)
		defer sweep.Stop()
		for {
			select {
			case <-sweep.C:
				d.sweepIdle()
			case <-d.done:
				return
			}
		}
	})
	return d, nil
}

// quicCarrier links a connection the QUIC server accepts back to the state it was sniffed
// under, through the connection context. Transport.ConnContext stores an empty one, the Tracer
// fills in the connection ID, and the accept loop puts the session in it.
type quicCarrier struct {
	client net.Addr
	sess   *Session
	odcid  string
}

type quicCarrierKey struct{}

// startTermination derives the keys and brings up the shared HTTP/3 server on first use.
//
// The fields are written under the lock because a shutdown may read them from another
// goroutine at any point after the first terminated connection.
func (d *quicDemux) startTermination() error {
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
		Handler:        http.HandlerFunc(d.p.serveTerminatedRequest),
		MaxHeaderBytes: d.p.cfg.server.maxHeaderBytes,
		IdleTimeout:    d.p.cfg.server.idleTimeout,
		Logger:         d.p.cfg.logger,
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			carrier, _ := c.Context().Value(quicCarrierKey{}).(*quicCarrier)
			if carrier == nil || carrier.sess == nil {
				return ctx
			}
			return context.WithValue(ctx, sessionKey{}, carrier.sess)
		},
	}
	d.resetKey = resetKey
	// Stored last, so a loaded tag guarantees the reset key beside it is readable.
	d.tag.Store(tag)
	return nil
}

// interceptForLocked returns the stack terminating the connections of client to origin,
// created on first use. Creation shares the draining critical section with shutdown, so no
// stack appears once draining began, and the caller closes any evicted stack once off the
// lock.
func (d *quicDemux) interceptForLocked(client net.Addr, origin netip.AddrPort) (*quicIntercept, *quicIntercept, error) {
	key := interceptKey{}
	if ta, ok := client.(*tunnelAddr); ok {
		key.tunnel = ta.tunnel
	} else if d.replier != nil {
		if !origin.IsValid() {
			return nil, nil, errNoReplyDestination
		}
		key.origin = origin
	}
	if it := d.intercepts[key]; it != nil {
		it.lastSeen = time.Now()
		return it, nil, nil
	}

	// Selected now so a full cap refuses before anything is built, removed only once the
	// stack is up, so a failed creation costs no live stack.
	var victim *quicIntercept
	if len(d.intercepts) >= d.maxStacks {
		if victim = d.evictableLocked(); victim == nil {
			return nil, nil, errInterceptsBusy
		}
	}

	queue := interceptQueue
	if key == (interceptKey{}) {
		queue = 4 * interceptQueue
	}
	dpc := newDemuxPacketConn(d.pc, queue)
	cfg := d.quicConfig()
	switch {
	case key.tunnel != nil:
		tun := key.tunnel
		dpc.reply = func(b []byte, _ net.Addr) (int, error) {
			tun.send(b)
			return len(b), nil
		}
		// The front connection carries about 1200 bytes of payload at its initial MTU, which
		// quic-go's default initial packet size exceeds. A probe above it would only be
		// dropped on the way out.
		cfg.InitialPacketSize = quicsniff.MinClientInitialDatagram
		cfg.DisablePathMTUDiscovery = true
	case d.replier != nil:
		reply, rerr := d.replySocketLocked(key.origin)
		if rerr != nil {
			return nil, nil, rerr
		}
		from := key.origin.String()
		dpc.reply = func(b []byte, addr net.Addr) (int, error) {
			// Errors are absorbed. A datagram is droppable, and an error returned here ends
			// the whole connection inside quic-go.
			if _, err := reply.WriteTo(b, addr); err != nil {
				d.p.cfg.logger.Debug("edge: reply dropped",
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
	cfg.Tracer = func(ctx context.Context, _ bool, odcid quic.ConnectionID) qlogwriter.Trace {
		// Returns no trace. This callback is the one place quic-go reveals the original
		// destination connection ID, pre-Retry even when a Retry happened.
		if carrier, ok := ctx.Value(quicCarrierKey{}).(*quicCarrier); ok {
			carrier.odcid = string(odcid.Bytes())
			d.adopt(ctx, carrier.client, carrier.odcid)
		}
		return nil
	}
	ln, err := transport.Listen(d.quicTLSConfig(), cfg)
	if err != nil {
		dpc.Close()
		_ = transport.Close()
		return nil, nil, fmt.Errorf("listen QUIC: %w", err)
	}

	if victim != nil {
		delete(d.intercepts, victim.key)
	}
	it := &quicIntercept{key: key, transport: transport, listener: ln, conn: dpc, lastSeen: time.Now()}
	d.intercepts[key] = it
	d.wg.Go(func() { d.acceptLoop(it) })
	return it, victim, nil
}

// acceptLoop takes the connections one stack terminates and serves each in the kind its
// ClientHello named. The negotiated protocol is the same answer read off the finished
// handshake, so nothing here can disagree with what was decided before the datagrams were
// handed over.
func (d *quicDemux) acceptLoop(it *quicIntercept) {
	for {
		qc, err := it.listener.Accept(d.ctx)
		if err != nil {
			return
		}
		d.wg.Go(func() { d.serveQUICConn(qc) })
	}
}

func (d *quicDemux) serveQUICConn(qc *quic.Conn) {
	sess := d.accept(qc)
	if sess == nil {
		return
	}

	if sess.kind == KindHTTP {
		sess.setProtocol(HTTP3)
		if err := d.h3.ServeQUICConn(qc); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.p.cfg.logger.Debug("edge: HTTP/3 connection closed", slog.String("error", err.Error()))
		}
		return
	}

	d.serveRawQUIC(qc, sess)
}

// serveRawQUIC runs the [QUIC] handler admitting this authority.
func (d *quicDemux) serveRawQUIC(qc *quic.Conn, sess *Session) {
	d.mu.Lock()
	draining := d.draining.Load()
	if !draining {
		d.raw[qc] = struct{}{}
	}
	d.mu.Unlock()
	if draining {
		_ = closeNoError(qc)
		return
	}
	defer func() {
		d.mu.Lock()
		delete(d.raw, qc)
		d.mu.Unlock()
		_ = closeNoError(qc)
	}()

	e, params := d.p.admitWith(sess.target, KindQUIC)
	if e == nil {
		// The entry went away between the decision and the handshake completing.
		return
	}

	handler, _ := e.serve.(QUIC)
	if handler == nil {
		return
	}

	c := &QUICCtx{
		ctx:      qc.Context(),
		p:        d.p,
		sess:     sess,
		entry:    e,
		conn:     qc,
		params:   params,
		target:   sess.target,
		identity: sess.identity,
	}
	defer c.close()

	if err := runKindHandler(d.p, sess, func() error { return handler(c) }); err != nil {
		d.p.cfg.logger.Debug("edge: quic handler",
			slog.String("target", sess.target.String()), slog.String("error", err.Error()))
	}
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

// adopt ties the removal of a terminated connection to its context, which ends with the
// connection however that happens, a failed handshake included.
func (d *quicDemux) adopt(ctx context.Context, client net.Addr, odcid string) {
	from := flowKeyOf(client)
	d.mu.Lock()
	defer d.mu.Unlock()
	flow := d.flows[from]
	if flow == nil {
		return
	}
	if conn := flow.conns[odcid]; conn != nil && conn.state == connTerminated {
		context.AfterFunc(ctx, func() { d.endTerminated(from, odcid) })
	}
}

func (d *quicDemux) endTerminated(from flowKey, odcid string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	flow := d.flows[from]
	if flow == nil {
		return
	}
	if conn := flow.conns[odcid]; conn != nil && conn.state == connTerminated {
		d.removeConnLocked(flow, conn)
	}
}

// accept hands the accepted connection the session it was sniffed under, recording the
// connection for Session.Close to end. One doomed or dropped meanwhile is closed here instead,
// the tag having no state left to stop delivering it.
func (d *quicDemux) accept(c *quic.Conn) *Session {
	carrier, _ := c.Context().Value(quicCarrierKey{}).(*quicCarrier)
	if carrier == nil {
		_ = closeNoError(c)
		return nil
	}

	from := flowKeyOf(carrier.client)
	d.mu.Lock()
	var conn *quicConn
	if flow := d.flows[from]; flow != nil {
		conn = flow.conns[carrier.odcid]
		if conn != nil && conn.doomed {
			d.removeConnLocked(flow, conn)
		}
	}
	if conn == nil || conn.doomed || conn.state != connTerminated {
		d.mu.Unlock()
		_ = closeNoError(c)
		return nil
	}
	conn.qc = c
	sess := conn.sess
	d.mu.Unlock()

	if sess != nil {
		// The session is registered before the handshake, so this is the first point where
		// its TLS state exists.
		state := c.ConnectionState().TLS
		sess.tlsState.Store(&state)
		carrier.sess = sess
	}
	return sess
}

// quicTLSConfig builds the configuration the proxy presents to a terminated client. The
// protocol offered back mirrors what the client asked for, h3 when it offered h3 and its own
// first choice otherwise, so what the connection is stays what its ClientHello said.
func (d *quicDemux) quicTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			name := chi.ServerName
			if name == "" {
				name = d.routedHost(chi.Context())
			}
			leaf, err := d.p.cfg.ca.Leaf(name)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion:   tls.VersionTLS13,
				NextProtos:   negotiateALPN(chi.SupportedProtos, KindQUIC),
				Certificates: []tls.Certificate{*leaf},
			}, nil
		},
	}
}

// quic-go derives the handshake context from ConnContext, and the connection is recorded
// before its datagrams reach the stack.
func (d *quicDemux) routedHost(ctx context.Context) string {
	carrier, _ := ctx.Value(quicCarrierKey{}).(*quicCarrier)
	if carrier == nil {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if flow := d.flows[flowKeyOf(carrier.client)]; flow != nil {
		if conn := flow.conns[carrier.odcid]; conn != nil && conn.sess != nil {
			return conn.sess.target.Host
		}
	}
	return ""
}

func (d *quicDemux) quicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:  d.p.cfg.server.idleTimeout,
		Allow0RTT:       false,
		EnableDatagrams: false,
	}
}

func (d *quicDemux) run() error {
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

// dispatch places one datagram from addr. The tunnels call it from their own goroutines, and a
// datagram of one flow is only ever handled by the goroutine feeding that flow.
func (d *quicDemux) dispatch(addr net.Addr, datagram []byte) {
	from := flowKeyOf(addr)
	if !from.addr.IsValid() || len(datagram) == 0 {
		return
	}
	if from.tunnel != nil && from.tunnel.closed.Load() {
		return
	}
	if datagram[0]&0x80 != 0 {
		d.dispatchLong(addr, from, datagram)
		return
	}
	d.dispatchShort(addr, from, datagram)
}

func (d *quicDemux) dispatchLong(addr net.Addr, from flowKey, datagram []byte) {
	version, dcid, _, ok := quicsniff.ParseLongHeader(datagram)
	if !ok {
		// Arbitrary bytes are free to set the high bit, so failing the parse places the
		// datagram by its destination rather than dropping it.
		d.dispatchDatagram(addr, from, datagram)
		return
	}

	now := time.Now()
	d.mu.Lock()
	flow := d.flows[from]
	if flow != nil {
		flow.lastSeen = now
		if conn := flow.conns[string(dcid)]; conn != nil {
			switch conn.state {
			case connTerminated:
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
	d.mu.Unlock()
	d.dispatchDatagram(addr, from, datagram)
}

// dispatchShort places a short header datagram. Only the connection IDs the proxy minted are
// recognizable here, the ones a peer chose being unreadable without its state.
func (d *quicDemux) dispatchShort(addr net.Addr, from flowKey, datagram []byte) {
	d.mu.Lock()
	if flow := d.flows[from]; flow != nil {
		flow.lastSeen = time.Now()
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
	d.mu.Unlock()
	d.dispatchDatagram(addr, from, datagram)
}

// replySocketLocked returns the sending socket of one origin, opened on first use. The bind is
// a local pair of syscalls, cheap enough to hold the lock through.
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

// lookupInterceptLocked resolves the stack a tagged datagram feeds, by its tunnel behind
// CONNECT-UDP, by its original destination under TPROXY and the zero key anywhere else. A nil
// stack with ok set may be answered with a stateless reset. Not ok means the destination is
// unknown and the datagram undeliverable.
func (d *quicDemux) lookupInterceptLocked(client net.Addr) (it *quicIntercept, origin netip.AddrPort, ok bool) {
	key := interceptKey{}
	if ta, isTunnel := client.(*tunnelAddr); isTunnel {
		key.tunnel = ta.tunnel
	} else if d.replier != nil {
		key.origin = d.originalDst(client)
		if !key.origin.IsValid() {
			return nil, netip.AddrPort{}, false
		}
	}
	it = d.intercepts[key]
	if it != nil {
		it.lastSeen = time.Now()
	}
	return it, key.origin, true
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

// dispatchDatagram is the terminal step, for a datagram no QUIC connection could claim. It is
// its own unit: the flow it belongs to is looked up, the entry serving it is resolved on the
// tree as it stands, and the handler decides what happens to it.
func (d *quicDemux) dispatchDatagram(client net.Addr, from flowKey, datagram []byte) {
	origin := d.originalDst(client)
	if !origin.IsValid() {
		return
	}

	d.mu.Lock()
	flow := d.flows[from]
	var u *udpFlow
	if flow != nil {
		u = flow.udp[origin]
	}
	d.mu.Unlock()

	if u != nil {
		d.serveDatagram(u, datagram, false)
		return
	}
	d.openUDPFlow(client, from, origin, datagram)
}

// openUDPFlow admits the first datagram of a flow and opens the socket carrying it.
func (d *quicDemux) openUDPFlow(client net.Addr, from flowKey, origin netip.AddrPort, datagram []byte) {
	target := d.declaredTarget(client, origin)

	// Admitted before the socket is opened, so a destination nothing names costs no dial. The
	// datagram is routed again once the flow exists, like every other one.
	if !d.p.Admits(target, KindUDP) {
		d.p.cfg.logger.Debug("edge: datagram dropped",
			slog.String("client", from.String()),
			slog.String("origin", origin.String()),
			slog.String("reason", "no entry admits this destination"))
		return
	}

	upstream, err := d.dialUDP(origin)
	if err != nil {
		d.p.cfg.logger.Debug("edge: cannot reach the origin",
			slog.String("origin", origin.String()), slog.String("error", err.Error()))
		return
	}

	ctx, cancel := context.WithCancel(d.ctx)
	sess := newSession(ctx, nil, target, KindUDP, 0)
	d.fillSession(sess, client)
	sess.setUpstream(origin)
	u := &udpFlow{
		upstream: upstream,
		sess:     sess,
		cancel:   cancel,
		client:   client,
		key:      origin,
		target:   target,
	}
	sess.closer = &udpFlowCloser{d: d, flow: from, key: origin}
	u.sink = &udpSink{d: d, u: u}
	u.out = DatagramCtx{
		ctx:    sess.Context(),
		sink:   u.sink,
		p:      d.p,
		sess:   sess,
		target: target,
		client: addrPort(sess.remoteAddr),
	}
	u.in = u.out
	u.in.inbound = true
	u.touch(time.Now())

	d.mu.Lock()
	ok := d.publishUDPLocked(from, client, u)
	d.mu.Unlock()
	if !ok {
		cancel()
		_ = upstream.Close()
		d.p.cfg.logger.Debug("edge: datagram dropped",
			slog.String("client", from.String()),
			slog.String("origin", origin.String()),
			slog.String("reason", "the proxy is at capacity or shutting down"))
		return
	}

	d.serveDatagram(u, datagram, false)
}

// dialUDP opens the socket a datagram flow sends through, with the transport's dialer.
func (d *quicDemux) dialUDP(origin netip.AddrPort) (net.Conn, error) {
	dial := d.p.cfg.transport.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()
	return dial(ctx, "udp", origin.String())
}

// declaredTarget is the authority a datagram flow is routed on, the target a CONNECT-UDP named
// or the address the datagram was headed to.
func (d *quicDemux) declaredTarget(client net.Addr, origin netip.AddrPort) Target {
	if ta, ok := client.(*tunnelAddr); ok {
		return ta.tunnel.target
	}
	return Target{
		Scheme: schemeForPort(fmt.Sprint(origin.Port())),
		Host:   origin.Addr().Unmap().String(),
		Port:   fmt.Sprint(origin.Port()),
	}
}

// fillSession sets the addresses and the identity of a session from the socket, or from the
// tunnel its datagrams arrive through.
func (d *quicDemux) fillSession(sess *Session, client net.Addr) {
	if ta, ok := client.(*tunnelAddr); ok {
		via := ta.tunnel.sess
		sess.remoteAddr, sess.localAddr = via.remoteAddr, via.localAddr
		sess.identity = via.identity
		sess.via = via
		return
	}
	sess.remoteAddr = client
	sess.localAddr = d.pc.LocalAddr()
	sess.transparent = true
}

// publishUDPLocked places a datagram flow in its client's flow. It shares the draining
// critical section with shutdown, so the flow is either refused or in the snapshot a shutdown
// sweeps.
func (d *quicDemux) publishUDPLocked(from flowKey, client net.Addr, u *udpFlow) bool {
	if d.draining.Load() || d.udps >= maxUDPFlows {
		return false
	}
	flow := d.flowLocked(from, client, time.Now())
	if flow == nil || len(flow.udp) >= maxUDPPerFlow || flow.udp[u.key] != nil {
		return false
	}
	if d.replier != nil {
		reply, err := d.replySocketLocked(u.key)
		if err != nil {
			return false
		}
		u.reply = reply
	}
	flow.udp[u.key] = u
	d.udps++
	u.started = true
	d.wg.Go(func() { d.runUDPFlow(from, u) })
	return true
}

// serveDatagram routes one datagram and runs the handler that serves it. The entry is resolved
// on the tree as it stands, so an entry removed while the flow is open stops it here rather
// than at the next flow.
func (d *quicDemux) serveDatagram(u *udpFlow, payload []byte, inbound bool) {
	d.mu.Lock()
	closed := u.closed
	d.mu.Unlock()
	if closed {
		return
	}
	u.touch(time.Now())

	c, seq := &u.out, &u.outSeq
	if inbound {
		c, seq = &u.in, &u.inSeq
	}

	// Routed on the tree as it stands, per datagram. Nothing is remembered between two of
	// them: a datagram is its own unit, and what serves it is whatever the tree says now.
	e, params := d.p.admitInto(u.target, KindUDP, c.params)
	if e == nil {
		return
	}
	handler, _ := e.serve.(UDP)
	if handler == nil {
		return
	}

	c.entry = e
	c.payload = payload
	c.params = params
	c.identity = u.sess.identity
	c.seq = seq.Add(1) - 1

	if err := runKindHandler(d.p, u.sess, func() error { return handler(c) }); err != nil {
		d.p.cfg.logger.Debug("edge: datagram handler",
			slog.String("target", u.target.String()), slog.String("error", err.Error()))
	}
}

// udpSink is how a datagram handler writes, either on to the origin or back to the client.
type udpSink struct {
	d *quicDemux
	u *udpFlow
}

func (s *udpSink) toOrigin(b []byte) error {
	_, err := s.u.upstream.Write(b)
	return err
}

func (s *udpSink) toClient(b []byte) error {
	if s.u.reply != nil {
		_, err := s.u.reply.WriteTo(b, s.u.client)
		return err
	}
	_, err := s.d.pc.WriteTo(b, s.u.client)
	return err
}

// runUDPFlow reads what the origin sends back and routes each datagram the same way the
// outbound ones are routed.
func (d *quicDemux) runUDPFlow(from flowKey, u *udpFlow) {
	buf := make([]byte, maxUDPPayload)
	for {
		// The deadline is what the flow has left before it falls idle, counted from the last
		// datagram in either direction. A client that only ever sends, telemetry or logs,
		// keeps its flow alive without the origin saying anything back.
		_ = u.upstream.SetReadDeadline(u.idleDeadline())
		n, err := u.upstream.Read(buf)
		if n > 0 {
			d.serveDatagram(u, buf[:n], true)
		}
		if err != nil {
			if isTimeout(err) && time.Since(u.lastUse()) < udpFlowIdle {
				// The outbound side kept the flow alive while this read was waiting.
				continue
			}
			d.closeUDPFlow(from, u)
			return
		}
	}
}

// idleDeadline is when the flow falls idle if nothing else happens on it.
func (u *udpFlow) idleDeadline() time.Time { return u.lastUse().Add(udpFlowIdle) }

// lastUse is when a datagram last travelled in either direction.
func (u *udpFlow) lastUse() time.Time { return time.Unix(0, u.lastSeenNano.Load()) }

// touch records that a datagram travelled. Both directions call it, from their own goroutine.
func (u *udpFlow) touch(now time.Time) { u.lastSeenNano.Store(now.UnixNano()) }

func (d *quicDemux) closeUDPFlow(from flowKey, u *udpFlow) {
	d.mu.Lock()
	if u.closed {
		d.mu.Unlock()
		return
	}
	u.closed = true
	if flow := d.flows[from]; flow != nil && flow.udp[u.key] == u {
		delete(flow.udp, u.key)
		d.udps--
	}
	if u.cancel != nil {
		u.cancel()
	}
	d.mu.Unlock()
	_ = u.upstream.Close()
}

// flowLocked returns the flow of one client socket, created on first sight, or nil at the flow
// cap.
func (d *quicDemux) flowLocked(from flowKey, client net.Addr, now time.Time) *quicFlow {
	flow := d.flows[from]
	if flow == nil {
		if len(d.flows) >= maxQUICFlows {
			return nil
		}
		// closed is written under this lock. A datagram that passed the check in dispatch
		// before the close finds it set here.
		if from.tunnel != nil && from.tunnel.closed.Load() {
			return nil
		}
		flow = &quicFlow{
			lastSeen: now,
			client:   client,
			conns:    make(map[string]*quicConn),
			udp:      make(map[netip.AddrPort]*udpFlow),
		}
		d.flows[from] = flow
	}
	return flow
}

func (d *quicDemux) admitConnLocked(from flowKey, client net.Addr, odcid string, now time.Time) *quicConn {
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
	if from.tunnel != nil {
		conn.declared = from.tunnel.target
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
	if conn.state == connTerminated && s != connTerminated {
		d.releaseInterceptLocked(conn)
	}
	conn.state = s
}

func (d *quicDemux) removeConnLocked(flow *quicFlow, conn *quicConn) {
	if conn.state == connSniffing {
		d.sniffing--
	}
	if conn.state == connTerminated {
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

// sniff feeds a datagram to the reassembler and decides the connection once its ClientHello is
// complete. A first flight datagram with no Initial in it, 0-RTT typically, still joins the
// pending ones, so the terminating stack receives the flight whole.
func (d *quicDemux) sniff(from flowKey, conn *quicConn, datagram []byte) {
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
	target := d.targetFor(ch, conn)
	if target.Host == "" {
		d.rejectConn(from, conn, "no server name in the ClientHello")
		return
	}

	// RFC 9001 section 8.1 makes ALPN mandatory on QUIC, so an offer with nothing in it says
	// nothing about what the connection carries and is refused rather than guessed at.
	if ch == nil || len(ch.ALPN) == 0 {
		d.rejectConn(from, conn, "the ClientHello offers no application protocol")
		return
	}
	// What the connection is comes from its own offer; which granularity serves it comes
	// from the tree, most refined first. An h3 connection with only a QUIC entry on its
	// authority is served stream by stream, and both see it decrypted.
	candidates := []Kind{KindQUIC}
	if slices.Contains(ch.ALPN, "h3") {
		candidates = []Kind{KindHTTP, KindQUIC}
	}

	named := ch.ServerName != ""
	target, _, verdict := d.p.targetForTransparent(d.ctx, target, conn.origin, named, candidates...)
	switch verdict {
	case nameMismatch:
		d.rejectConn(from, conn, "the server name does not resolve to the destination")
		return
	case nameUnresolved:
		d.rejectConn(from, conn, "the server name cannot be resolved")
		return
	}

	kind := d.p.firstAdmitted(target, candidates...)
	if kind == 0 {
		d.rejectConn(from, conn, "no entry admits this authority")
		return
	}

	d.beginTermination(from, client, conn, target, ch, kind, candidates, pending)
}

// targetFor is the authority a QUIC connection is routed on, its server name when it offered
// one, otherwise the declared target of its tunnel or the address its first datagram was
// redirected from.
func (d *quicDemux) targetFor(hello *ClientHello, conn *quicConn) Target {
	target := Target{Scheme: "https", Port: "443"}

	switch {
	case conn.declared.Host != "":
		target.Host, target.Port = conn.declared.Host, conn.declared.Port
	case conn.origin.IsValid():
		target.Host, target.Port = conn.origin.Addr().String(), fmt.Sprint(conn.origin.Port())
	}
	if hello != nil && hello.ServerName != "" {
		target.Host = stringsutil.ToLowerASCIIString(hello.ServerName)
	}
	return target
}

// originalDst is the address the datagram last read from client was headed to, the one its
// tunnel resolved or the destination before the redirect, or the zero value when there was
// none.
func (d *quicDemux) originalDst(client net.Addr) netip.AddrPort {
	if ta, ok := client.(*tunnelAddr); ok {
		return ta.tunnel.upstream
	}
	if d.origins == nil {
		return netip.AddrPort{}
	}
	origin, err := d.origins.OriginalDestination(client)
	if err != nil {
		return netip.AddrPort{}
	}
	return redirectedTo(origin, d.pc.LocalAddr())
}

func (d *quicDemux) beginTermination(from flowKey, client net.Addr, conn *quicConn,
	target Target, hello *ClientHello, kind Kind, candidates []Kind, pending [][]byte,
) {
	if err := d.startTermination(); err != nil {
		if !errors.Is(err, ErrProxyClosed) {
			d.p.cfg.logger.Error("edge: cannot terminate QUIC", slog.String("error", err.Error()))
		}
		d.rejectConn(from, conn, err.Error())
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	sess := newSession(ctx, nil, target, kind, 0)
	d.fillSession(sess, client)
	sess.setUpstream(conn.origin)
	sess.clientHello = hello
	sess.servableAs = candidates
	sess.closer = &quicConnCloser{d: d, flow: from, odcid: conn.odcid}

	d.mu.Lock()
	flow := d.flows[from]
	if flow == nil || flow.conns[conn.odcid] != conn || conn.state != connSniffing {
		d.mu.Unlock()
		cancel()
		return
	}
	// Inside the publish critical section, so a shutdown either refuses this connection or
	// finds it in the snapshot it takes under the same lock. startTermination alone cannot
	// guarantee that once the server is already up.
	if d.draining.Load() {
		d.mu.Unlock()
		cancel()
		d.rejectConn(from, conn, "the proxy is shutting down")
		return
	}
	it, evicted, err := d.interceptForLocked(client, conn.origin)
	if err != nil {
		d.mu.Unlock()
		cancel()
		d.rejectConn(from, conn, err.Error())
		return
	}
	d.setStateLocked(conn, connTerminated)
	conn.pending = nil
	conn.pendingBytes = 0
	conn.sess = sess
	conn.cancel = cancel
	conn.kind = kind
	conn.stack = it
	it.conns++
	d.mu.Unlock()
	if evicted != nil {
		d.closeIntercept(evicted)
	}

	// The session is published, so a sweep started after the tree changed either found it or
	// ran before this read, which then observes the change. Nothing has been handed to the
	// QUIC server yet, so a connection refused here never completes a handshake.
	if !d.p.Admits(target, kind) {
		d.rejectConn(from, conn, "the authority was withdrawn while the connection was starting")
		return
	}

	for _, dg := range pending {
		it.deliver(client, dg)
	}
}

// rejectConn marks a connection refused. The state stays as a tombstone until its TTL, so the
// client's Initial retransmits are dropped without being decrypted again, and a fresh Initial
// with a new connection ID from the same socket is evaluated from scratch.
func (d *quicDemux) rejectConn(from flowKey, conn *quicConn, reason string) {
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
	var stale []*udpFlow
	var tunnels []*connectUDPTunnel
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
			case connTerminated:
				// Removed when its connection context ends, unless the handshake never
				// reached the server and no AfterFunc was registered.
				if conn.qc == nil && now.Sub(conn.lastSeen) > quicAdoptTTL {
					d.removeConnLocked(flow, conn)
				}
			}
		}
		for key, u := range flow.udp {
			if now.Sub(u.lastUse()) > udpFlowIdle {
				u.closed = true
				delete(flow.udp, key)
				d.udps--
				if u.cancel != nil {
					u.cancel()
				}
				stale = append(stale, u)
			}
		}
		if len(flow.conns) == 0 && len(flow.udp) == 0 {
			// A socket's state is bookkeeping and goes quickly. A tunnel is closed once
			// nothing has lived in it for udpFlowIdle, the floor RFC 9298 sets for closing
			// on inactivity.
			idle := quicSniffTTL
			if from.tunnel != nil {
				idle = udpFlowIdle
			}
			if now.Sub(flow.lastSeen) > idle {
				delete(d.flows, from)
				if from.tunnel != nil {
					tunnels = append(tunnels, from.tunnel)
				}
			}
		}
	}
	idle := d.sweepInterceptsLocked(now)
	d.sweepRepliesLocked()
	d.mu.Unlock()
	for _, u := range stale {
		_ = u.upstream.Close()
	}
	for _, it := range idle {
		d.closeIntercept(it)
	}
	for _, t := range tunnels {
		t.close()
	}
}

// sweepInterceptsLocked removes the stacks no connection has fed for a while. The caller closes
// them off the lock, Transport.Close waiting on goroutines of its own.
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

// sweepRepliesLocked closes the reply sockets nothing uses any more, after the stack sweep so a
// stack removed this pass frees its socket immediately.
func (d *quicDemux) sweepRepliesLocked() {
	if d.replier == nil {
		return
	}
	used := make(map[netip.AddrPort]bool, len(d.replySockets))
	for _, flow := range d.flows {
		for key, u := range flow.udp {
			if u.reply != nil {
				used[key] = true
			}
		}
	}
	for key := range d.intercepts {
		if key.origin.IsValid() {
			used[key.origin] = true
		}
	}
	for origin, sock := range d.replySockets {
		if !used[origin] {
			delete(d.replySockets, origin)
			_ = sock.Close()
		}
	}
}

// shutdown drains the demux. Nothing new is placed, the HTTP/3 server tells its clients with a
// GOAWAY and waits for their requests, and the connections a handler owns are waited on until
// ctx is done. The read loop keeps running through all of it, because what is being drained
// only finishes if its datagrams still arrive.
func (d *quicDemux) shutdown(ctx context.Context) error {
	d.mu.Lock()
	d.draining.Store(true)
	h3 := d.h3
	d.mu.Unlock()

	var err error
	if h3 != nil {
		err = h3.Shutdown(ctx)
	}

	// A handler serving a raw QUIC connection or a datagram flow ends when its peers do.
	// Polling for that is all there is to wait on. The done case covers a teardown that
	// started elsewhere, and joining the close waits for it.
	tick := time.Tick(500 * time.Millisecond)
poll:
	for d.serving() {
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

// serving reports whether any handler still owns something.
func (d *quicDemux) serving() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.raw) > 0 {
		return true
	}
	for _, flow := range d.flows {
		if len(flow.udp) > 0 {
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
		// The read loop publishes with no lock held across its dials, so close must refuse a
		// late publication the way a shutdown does.
		d.draining.Store(true)
		h3 := d.h3
		var sockets []net.Conn
		var tunnels []*connectUDPTunnel
		for key, flow := range d.flows {
			if key.tunnel != nil {
				tunnels = append(tunnels, key.tunnel)
			}
			for _, u := range flow.udp {
				u.closed = true
				if u.cancel != nil {
					u.cancel()
				}
				sockets = append(sockets, u.upstream)
			}
			for _, conn := range flow.conns {
				conn.end()
			}
		}
		raw := make([]*quic.Conn, 0, len(d.raw))
		for qc := range d.raw {
			raw = append(raw, qc)
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
		clear(d.raw)
		d.sniffing = 0
		d.udps = 0
		d.mu.Unlock()

		for _, s := range sockets {
			_ = s.Close()
		}
		// http3.Server.Close leaves the connections handed to ServeQUICConn alone, and a raw
		// one is not its at all, so both kinds are ended here.
		for _, qc := range raw {
			_ = closeNoError(qc)
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
		for _, t := range tunnels {
			t.close()
		}

		_ = d.pc.Close()
		d.wg.Wait()
	})
}

// quicCIDTag mints and recognizes the connection IDs the terminating stacks emit, 4 random
// bytes and 4 of a keyed MAC over them, so a packet of a terminated connection is recognizable
// with no per connection state, NAT rebinding and restarts included. A random Initial DCID
// passes with probability 2^-32, the one way past the policy decision.
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

// GenerateConnectionID implements quic.ConnectionIDGenerator. quic-go parses short headers at
// the generator's length, so an ID of any other length is silently unroutable.
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

// mac is one AES block over the random half, a MAC nothing short of the key can forge at the
// cost of one block on the dispatch path.
func (t *quicCIDTag) mac(r []byte) [4]byte {
	var in, out [16]byte
	copy(in[:], r)
	t.block.Encrypt(out[:], in[:])
	return [4]byte(out[:4])
}

// quicInterceptKeys derives the tag and stateless reset keys from the CA key so both survive a
// restart, which lets a connection minted by a previous process be recognized and reset instead
// of expiring on its idle timeout. A key that cannot be serialized, hardware backed for
// instance, falls back to per process random keys.
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

// demuxPacketConn is the socket a terminating stack's transport reads from. Datagrams are
// pushed into it by the demultiplexer rather than read from the network, while writes go
// straight out of the real socket so the client sees answers from the address it wrote to.
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

// deliver hands a datagram to the QUIC server. It drops rather than blocks: QUIC is built on an
// unreliable datagram service, and stalling the demultiplexer would hold up every other client
// on the socket.
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
// under load, and looks for these methods to size it. Every stack sizes the same socket, which
// is idempotent.
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
