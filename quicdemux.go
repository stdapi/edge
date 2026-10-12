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

	"github.com/fox-toolkit/edge/internal/netutil"
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
	// maxUDPAlternates bounds the origins one datagram flow may reach through SendTo.
	maxUDPAlternates = 8
	// udpBufSize is the pooled buffer a queued datagram fits in. A larger one is allocated
	// for itself.
	udpBufSize = 2048
	// The state caps. Everything below is allocated for an unauthenticated peer on a
	// spoofable transport, so the worst case is the product of these bounds.
	maxQUICFlows     = 4096
	maxConnsPerFlow  = 64
	maxSniffingConns = 512
	// Datagram flows are bounded on themselves: they are opened by a datagram, not by a
	// connection, so nothing else bounds them.
	maxUDPPerFlow = 16
	maxUDPFlows   = 1024
	// udpQueue and udpQueueBytes bound the outbound datagrams one flow queues behind its
	// handler, in datagrams and in bytes.
	udpQueue      = 64
	udpQueueBytes = 256 << 10
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
	// quicMinResetSize is the smallest stateless reset, RFC 9000 section 10.3.
	quicMinResetSize = 21
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
// ServeTransparentUDP always returns a non-nil error and closes pc. After [Proxy.Shutdown]
// or [Proxy.Close], the returned error is [ErrProxyClosed].
//
// Every QUIC connection is terminated. Its ClientHello names where it was headed and which
// protocol it asked for: a connection offering h3 is HTTP traffic and its requests are routed
// one by one, and one offering anything else is served by the [QUIC] entry admitting its
// authority, stream by stream. QUIC requires ALPN, so a connection offering none is refused
// rather than guessed at.
//
// A connection refused before its handshake is closed with the error code of the TLS alert a
// TLS client gets for the same refusal, or with CONNECTION_REFUSED.
//
// A datagram that is not QUIC is placed by the address it was headed to, when the platform
// reports one, and served by the [UDP] entry admitting it, one datagram at a time. Encrypted
// datagrams belonging to a QUIC connection are never served that way: a connection the proxy
// cannot read is one it refuses rather than one it passes on.
//
// A [UDP] handler serves the datagrams of a flow one at a time, in the order they arrived.
// While it blocks, up to 64 datagrams or 256 KiB of that flow wait and the rest are dropped.
//
// Under Encrypted Client Hello the decision sees the outer server name only, unless
// [WithRejectECH] refuses such connections. A QUIC version other than v1 and v2 is served by the
// [UDP] entry admitting its destination.
// Behind a Linux TPROXY rule every datagram reports its exact destination and replies are sent
// from the address the client targeted. At most 64 origins are terminated at once there.
// Beyond that the origin longest without a live connection is reclaimed, and with every origin
// holding one a connection to a new origin is refused.
func (p *Proxy) ServeTransparentUDP(pc net.PacketConn) error {
	if p.srv.closing.Load() {
		_ = pc.Close()
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

	resetSecret *quicResetSecret

	// h3 serves every terminating stack, so one shutdown sends every GOAWAY.
	h3 *http3.Server

	// tag recognizes the connection IDs the terminating stacks emit with nothing kept per
	// connection. It, resetSecret and socketResetKey are set once, when the first connection is
	// terminated.
	tag    atomic.Pointer[quicCIDTag]
	cancel context.CancelFunc

	done         chan struct{}
	flows        map[flowKey]*quicFlow
	replySockets map[netip.AddrPort]net.PacketConn
	// intercepts holds the terminating stacks, one per origin under TPROXY so replies leave
	// from the address the client targeted, one per CONNECT-UDP tunnel so a connection stays
	// with the identity that opened it, and one under the zero key anywhere else.
	intercepts map[interceptKey]*quicIntercept
	// raw holds the QUIC connections a [QUIC] handler is serving, what a shutdown waits on.
	// accepted holds every connection taken off a listener until it is done with, what a
	// cut closes.
	raw      map[*quic.Conn]struct{}
	accepted map[*quic.Conn]struct{}

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

	socketResetKey quic.StatelessResetKey

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
// tunnel and the origin it serves behind a tunnel, and the zero value for the stack every
// other path shares.
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
	udp map[udpKey]*udpFlow
}

// udpKey identifies a datagram flow inside one client socket, its origin and, behind a tunnel
// addressing every datagram, the hostname of its destination. Two hostnames resolving to one
// address are two flows, each decided on its own.
type udpKey struct {
	name   string
	origin netip.AddrPort
}

type quicConnState uint8

const (
	connSniffing quicConnState = iota
	connPlacing
	connTerminated
	connRejected
)

// sniffing reports whether a connection in state s still counts against maxSniffingConns.
func (s quicConnState) sniffing() bool { return s == connSniffing || s == connPlacing }

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
	// version and scid are those of the first Initial, to address a refusal.
	version uint32
	scid    [20]byte
	scidLen uint8
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
	// alts are the origins reached through SendTo, keyed on the address as the handler wrote
	// it. Guarded by the demux mutex.
	alts map[string]*udpAlt
	// outQ is the outbound datagrams waiting for the handler.
	outQ   chan udpDatagram
	target Target
	key    netip.AddrPort
	id     udpKey
	// out and in are the per direction contexts. A single goroutine serves each direction,
	// so at most one datagram is ever in flight on a context.
	out DatagramCtx
	in  DatagramCtx
	// lastSeenNano is when a datagram last travelled, either way. Both directions write it,
	// from their own goroutine, so it is read and written atomically.
	lastSeenNano atomic.Int64
	outSeq       atomic.Uint64
	inSeq        atomic.Uint64
	// queued counts the bytes waiting in outQ.
	queued atomic.Int64
	closed bool
	// overflowed records that the queue dropped a datagram, so the first drop is logged.
	overflowed bool
}

// udpDatagram is a queued outbound datagram. buf is the pooled buffer b was copied into, nil
// when b came owned.
type udpDatagram struct {
	buf *[udpBufSize]byte
	b   []byte
}

var udpBufPool = sync.Pool{New: func() any { return new([udpBufSize]byte) }}

func (dg udpDatagram) release() {
	if dg.buf != nil {
		udpBufPool.Put(dg.buf)
	}
}

// enqueue copies datagram unless owned and queues it for the handler, dropping it when the
// flow's queue is full.
func (u *udpFlow) enqueue(datagram []byte, owned bool) {
	u.touch(time.Now())
	n := int64(len(datagram))
	if u.queued.Add(n) > udpQueueBytes {
		u.queued.Add(-n)
		u.overflow()
		return
	}
	dg := udpDatagram{b: datagram}
	if !owned {
		if len(datagram) <= udpBufSize {
			dg.buf = udpBufPool.Get().(*[udpBufSize]byte)
			dg.b = dg.buf[:copy(dg.buf[:], datagram)]
		} else {
			dg.b = bytes.Clone(datagram)
		}
	}
	select {
	case u.outQ <- dg:
	default:
		u.queued.Add(-n)
		dg.release()
		u.overflow()
	}
}

// overflow logs the first datagram the queue drops. Only the goroutine feeding the flow calls
// it, so overflowed needs no lock.
func (u *udpFlow) overflow() {
	if u.overflowed {
		return
	}
	u.overflowed = true
	u.sink.d.p.cfg.logger.Debug("edge: datagram dropped",
		slog.String("client", u.client.String()),
		slog.String("origin", u.key.String()),
		slog.String("reason", "the handler is behind and the flow's queue is full"))
}

// udpAlt is one origin a datagram flow reaches through SendTo. Its reader serves the replies
// on a context of its own.
type udpAlt struct {
	conn net.Conn
	in   DatagramCtx
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
	conns    int
	resetKey quic.StatelessResetKey
}

// deliver hands a datagram to the stack's QUIC transport.
func (it *quicIntercept) deliver(addr net.Addr, datagram []byte, owned bool) {
	it.conn.deliver(addr, datagram, owned)
}

// closeIntercept tears one stack down. The listener goes first, so the accept loop returns the
// error it filters, then the packet conn, unblocking the read Transport.Close waits on.
func (d *quicDemux) closeIntercept(it *quicIntercept) {
	closeListener(it.listener)
	it.conn.Close()
	_ = it.transport.Close()
}

// closeListener closes ln, then the connections that finished their handshake on it without
// being accepted, which Accept keeps returning before the close error.
func closeListener(ln *quic.Listener) {
	_ = ln.Close()
	for {
		c, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		_ = closeNoError(c)
	}
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

// alertNoApplicationProtocol is the alert crypto/tls ends a TLS handshake with when no
// protocol is in common, RFC 7301 section 3.2.
const alertNoApplicationProtocol = 120

// The QUIC codes of the TLS alerts a refusal sends, 0x100 plus the alert, RFC 9001 section 4.8.
const (
	quicHandshakeFailure      = quic.TransportErrorCode(0x100 + alertHandshakeFailure)
	quicDecodeError           = quic.TransportErrorCode(0x100 + alertDecodeError)
	quicInternalError         = quic.TransportErrorCode(0x100 + alertInternalError)
	quicMissingExtension      = quic.TransportErrorCode(0x100 + alertMissingExtension)
	quicUnrecognizedName      = quic.TransportErrorCode(0x100 + alertUnrecognizedName)
	quicNoApplicationProtocol = quic.TransportErrorCode(0x100 + alertNoApplicationProtocol)
)

var (
	errNoReplyDestination = errors.New("no destination to source the replies from")
	errInterceptsBusy     = errors.New("every terminating stack has live connections")
)

// quicConnCloser ends one QUIC connection. Every connection here is terminated by the proxy
// and owns its own state, so closing one closes exactly it.
type quicConnCloser struct {
	flow  flowKey
	d     *quicDemux
	conn  *quicConn
	odcid string
}

func (c *quicConnCloser) Close() error {
	c.d.mu.Lock()
	flow := c.d.flows[c.flow]
	if flow == nil {
		c.d.mu.Unlock()
		return nil
	}
	// Compared by identity, the key may be held by a later connection of the same client.
	conn := flow.conns[c.odcid]
	if conn != c.conn {
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
	u    *udpFlow
	flow flowKey
	key  udpKey
}

func (c *udpFlowCloser) Close() error {
	c.d.mu.Lock()
	var conns []net.Conn
	if flow := c.d.flows[c.flow]; flow != nil {
		// Compared by identity, the key may be held by a later flow of the same client.
		if u := flow.udp[c.key]; u == c.u && !u.closed {
			delete(flow.udp, c.key)
			c.d.udps--
			conns = u.endLocked()
		}
	}
	c.d.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
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
		accepted:  make(map[*quic.Conn]struct{}),
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

	tag, resetSecret, err := quicInterceptKeys(d.p.cfg.ca)
	if err != nil {
		return err
	}
	socketResetKey := resetSecret.addrKey(addrPort(d.pc.LocalAddr()))

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
	d.resetSecret = resetSecret
	d.socketResetKey = socketResetKey
	// Stored last, so a loaded tag guarantees the reset keys beside it are readable.
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
	}
	if key.tunnel != nil || d.replier != nil {
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

	resetKey, kerr := d.stackResetKey(key)
	if kerr != nil {
		return nil, nil, kerr
	}
	queue := interceptQueue
	if key == (interceptKey{}) {
		queue = 4 * interceptQueue
	}
	dpc := newDemuxPacketConn(d.pc, queue)
	cfg := d.quicConfig()
	switch {
	case key.tunnel != nil:
		tun, origin := key.tunnel, key.origin
		dpc.reply = func(b []byte, _ net.Addr) (int, error) {
			tun.send(origin, b)
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

	it := &quicIntercept{key: key, conn: dpc, resetKey: resetKey}
	transport := &quic.Transport{
		Conn:                  dpc,
		ConnectionIDGenerator: d.tag.Load(),
		StatelessResetKey:     &it.resetKey,
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
	it.transport, it.listener, it.lastSeen = transport, ln, time.Now()
	d.intercepts[key] = it
	d.wg.Go(func() { d.acceptLoop(it) })
	return it, victim, nil
}

// stackResetKey derives the stateless reset key of the stack key identifies, from the address it
// replies from. A stack behind a tunnel has no such address and gets a random identity, so the
// connections it terminated are no longer reset once it is gone.
func (d *quicDemux) stackResetKey(key interceptKey) (quic.StatelessResetKey, error) {
	switch {
	case key.tunnel != nil:
		var id [32]byte
		if _, err := rand.Read(id[:]); err != nil {
			return quic.StatelessResetKey{}, err
		}
		return d.resetSecret.key(id[:]), nil
	case key.origin.IsValid():
		return d.resetSecret.addrKey(key.origin), nil
	default:
		return d.socketResetKey, nil
	}
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
		// Recorded on this goroutine, so a cut reaches the connection before anything else
		// has run for it.
		d.mu.Lock()
		draining := d.draining.Load()
		if !draining {
			d.accepted[qc] = struct{}{}
		}
		d.mu.Unlock()
		if draining {
			_ = closeNoError(qc)
			continue
		}
		// Off the WaitGroup, a handler that ignores its cut would otherwise keep the socket.
		go d.serveQUICConn(qc)
	}
}

func (d *quicDemux) serveQUICConn(qc *quic.Conn) {
	defer func() {
		d.mu.Lock()
		delete(d.accepted, qc)
		d.mu.Unlock()
	}()
	sess := d.accept(qc)
	if sess == nil {
		return
	}

	if sess.kind == KindHTTP {
		sess.setProtocol(HTTP3)
		err := d.h3.ServeQUICConn(qc)
		// Refused or failed before it was established, the connection is still open.
		_ = closeNoError(qc)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	sess.entry.Store(e)
	// Replayed once stored, so a commit in between is seen here and by every later sweep.
	if sess.Stale() {
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
			sess := d.placedSession(chi.Context())
			if sess == nil {
				return nil, errNotPlaced
			}
			// The connection was placed on the ClientHello the demultiplexer read, and quic-go
			// parses its own copy. Two copies that differ would terminate a name nothing admits.
			if hello := sess.ClientHello(); hello == nil || hello.ServerName != chi.ServerName ||
				!slices.Equal(hello.ALPN, chi.SupportedProtos) {
				return nil, errHelloChanged
			}
			name := chi.ServerName
			if name == "" {
				name = sess.target.Host
			}
			leaf, err := d.p.cfg.ca.Leaf(name)
			if err != nil {
				return nil, err
			}
			sess.leaf.Store(leaf.Leaf)
			return &tls.Config{
				MinVersion:   tls.VersionTLS13,
				NextProtos:   negotiateALPN(chi.SupportedProtos, KindQUIC),
				Certificates: []tls.Certificate{*leaf},
			}, nil
		},
	}
}

var (
	errNotPlaced    = errors.New("edge: QUIC handshake of a connection the proxy did not place")
	errHelloChanged = errors.New("edge: QUIC ClientHello differs from the one the connection was placed on")
)

// placedSession returns the session of the connection being handshaken. The connection is
// recorded before its datagrams reach the stack.
func (d *quicDemux) placedSession(ctx context.Context) *Session {
	carrier, _ := ctx.Value(quicCarrierKey{}).(*quicCarrier)
	if carrier == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if flow := d.flows[flowKeyOf(carrier.client)]; flow != nil {
		if conn := flow.conns[carrier.odcid]; conn != nil {
			return conn.sess
		}
	}
	return nil
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
		// The buffer is reused on the next read, so anything kept must be copied.
		d.dispatch(addr, buf[:n], false)
	}
}

// dispatch places one datagram from addr. The tunnels call it from their own goroutines, and a
// datagram of one flow is only ever handled by the goroutine feeding that flow.
func (d *quicDemux) dispatch(addr net.Addr, datagram []byte, owned bool) {
	from := flowKeyOf(addr)
	if !from.addr.IsValid() {
		return
	}
	if from.tunnel != nil && from.tunnel.closed.Load() {
		return
	}
	if len(datagram) == 0 {
		// An empty UDP payload is no QUIC packet.
		d.dispatchDatagram(addr, from, datagram, owned)
		return
	}
	if datagram[0]&0x80 != 0 {
		d.dispatchLong(addr, from, datagram, owned)
		return
	}
	d.dispatchShort(addr, from, datagram, owned)
}

func (d *quicDemux) dispatchLong(addr net.Addr, from flowKey, datagram []byte, owned bool) {
	version, dcid, scid, ok := quicsniff.ParseInvariantHeader(datagram)
	if ok && (len(dcid) > 20 || len(scid) > 20) {
		// Only a version the demux cannot read may have such IDs, and no flow or tag uses them.
		if !quicsniff.KnownVersion(version) {
			d.dispatchUnknownVersion(addr, from, datagram, owned, version, dcid, scid)
			return
		}
		ok = false
	}
	if !ok {
		// Arbitrary bytes are free to set the high bit, so failing the parse places the
		// datagram by its destination rather than dropping it.
		d.dispatchDatagram(addr, from, datagram, owned)
		return
	}
	initial := quicsniff.IsInitial(datagram[0], version)
	if initial && len(datagram) < quicsniff.MinClientInitialDatagram {
		// RFC 9000 section 14.1 applies to every Initial, and quic-go only checks the first.
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
				stack.deliver(addr, datagram, owned)
			case connPlacing:
				conn.lastSeen = now
				d.pendLocked(conn, datagram, owned)
				d.mu.Unlock()
			case connRejected:
				conn.lastSeen = now
				d.mu.Unlock()
			default:
				conn.lastSeen = now
				d.mu.Unlock()
				d.sniff(from, conn, datagram, owned)
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
			it.deliver(addr, datagram, owned)
		}
		return
	}
	if initial && len(dcid) >= 8 {
		if flow == nil && d.ownSource(from) {
			d.mu.Unlock()
			d.refuseOwn(addr, from, version, dcid, scid)
			return
		}
		conn := d.admitConnLocked(from, addr, string(dcid), now)
		if conn != nil {
			conn.version = version
			conn.scidLen = uint8(copy(conn.scid[:], scid)) //nolint:gosec // dispatchLong refuses an ID past 20 bytes
		}
		d.mu.Unlock()
		if conn != nil {
			d.sniff(from, conn, datagram, owned)
		}
		return
	}
	d.mu.Unlock()
	if quicsniff.KnownVersion(version) {
		// A version the demux reads is QUIC and never reaches a datagram handler, where another
		// version may be another protocol.
		return
	}
	d.dispatchUnknownVersion(addr, from, datagram, owned, version, dcid, scid)
}

// dispatchUnknownVersion places a long header of a version the demux cannot read by its
// destination, and answers it with Version Negotiation when nothing admits it.
func (d *quicDemux) dispatchUnknownVersion(addr net.Addr, from flowKey, datagram []byte, owned bool,
	version uint32, dcid, scid []byte,
) {
	if d.dispatchDatagram(addr, from, datagram, owned) {
		return
	}
	// Version 0 is a Version Negotiation packet, which RFC 9000 section 6.1 bars answering, and
	// RFC 9000 section 5.2.2 answers only a datagram large enough to open a connection.
	if version != 0 && len(datagram) >= quicsniff.MinClientInitialDatagram {
		d.answer(addr, d.originalDst(addr), versionNegotiation(dcid, scid), false)
	}
}

// versionNegotiation is the Version Negotiation packet answering a long header of dcid and
// scid, RFC 9000 section 17.2.1, listing the versions the terminating stacks accept.
func versionNegotiation(dcid, scid []byte) []byte {
	b := make([]byte, 0, 7+len(scid)+len(dcid)+8)
	var unused [1]byte
	_, _ = rand.Read(unused[:])
	// The 0x40 bit stays set for the protocols sharing the port, RFC 9000 section 17.2.1.
	b = append(b, 0xc0|unused[0]&0x3f)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = append(b, byte(len(scid))) //nolint:gosec // a length byte of the header it answers
	b = append(b, scid...)
	b = append(b, byte(len(dcid))) //nolint:gosec // a length byte of the header it answers
	b = append(b, dcid...)
	b = binary.BigEndian.AppendUint32(b, quicsniff.Version1)
	return binary.BigEndian.AppendUint32(b, quicsniff.Version2)
}

// dispatchShort places a short header datagram. Only the connection IDs the proxy minted are
// recognizable here, the ones a peer chose being unreadable without its state.
func (d *quicDemux) dispatchShort(addr net.Addr, from flowKey, datagram []byte, owned bool) {
	d.mu.Lock()
	flow := d.flows[from]
	if flow != nil {
		flow.lastSeen = time.Now()
	}
	if tag := d.tag.Load(); tag != nil && len(datagram) >= 1+8 && tag.matches(datagram[1:9]) {
		// No flow needed. The tag survives a client whose address changed in flight, and
		// quic-go validates the new path itself.
		it, origin, ok := d.lookupInterceptLocked(addr)
		d.mu.Unlock()
		if it != nil {
			it.deliver(addr, datagram, owned)
		} else if ok {
			d.statelessReset(addr, origin, datagram)
		}
		return
	}
	if maybeStatelessReset(datagram) && flow != nil && len(flow.conns) > 0 {
		// A stateless reset from the client has no connection ID the proxy minted, and only the
		// stack with its tokens can recognize it, RFC 9000 section 10.3.1.
		if stack := d.terminatedStackLocked(flow, addr); stack != nil {
			d.mu.Unlock()
			stack.deliver(addr, datagram, owned)
			return
		}
	}
	d.mu.Unlock()
	d.dispatchDatagram(addr, from, datagram, owned)
}

// maybeStatelessReset reports whether a short header datagram has the form of a stateless reset,
// RFC 9000 section 10.3. The terminating stacks never advertise grease_quic_bit, RFC 9287, so
// the QUIC bit of a client's reset is set.
func maybeStatelessReset(b []byte) bool {
	return len(b) >= quicMinResetSize && b[0]&0x40 != 0
}

// terminatedStackLocked returns the stack terminating a connection of flow to the destination
// of the datagram just read from client, or nil when there is none.
func (d *quicDemux) terminatedStackLocked(flow *quicFlow, client net.Addr) *quicIntercept {
	origin := d.originalDst(client)
	for _, conn := range flow.conns {
		if conn.state == connTerminated && conn.stack != nil && conn.origin == origin {
			return conn.stack
		}
	}
	return nil
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
	}
	if key.tunnel != nil || d.replier != nil {
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
// matches the one the stack advertised, both derived from the key of the address the stack
// replied from (RFC 9000 section 10.3). A tunnel's stack leaves no key behind, so nothing
// answers there.
func (d *quicDemux) statelessReset(client net.Addr, origin netip.AddrPort, datagram []byte) {
	if len(datagram) <= quicResetSize {
		return
	}
	if _, ok := client.(*tunnelAddr); ok {
		return
	}
	key := d.socketResetKey
	if origin.IsValid() {
		key = d.resetSecret.addrKey(origin)
	}
	pkt := make([]byte, quicResetSize)
	if _, err := rand.Read(pkt[:quicResetSize-16]); err != nil {
		return
	}
	pkt[0] = pkt[0]&0x3f | 0x40
	mac := hmac.New(sha256.New, key[:])
	mac.Write(datagram[1:9])
	copy(pkt[quicResetSize-16:], mac.Sum(nil)[:16])
	d.answer(client, origin, pkt, false)
}

// answer sends a packet of the demux to client from the address the client wrote to, under
// TPROXY the reply socket of origin. With open, an origin with no reply socket gets one for this
// packet only, closed at once so an unauthenticated datagram never keeps a file descriptor.
func (d *quicDemux) answer(client net.Addr, origin netip.AddrPort, pkt []byte, open bool) {
	if ta, ok := client.(*tunnelAddr); ok {
		ta.tunnel.send(origin, pkt)
		return
	}
	if d.replier == nil {
		_, _ = d.pc.WriteTo(pkt, client)
		return
	}
	if !origin.IsValid() {
		return
	}
	d.mu.Lock()
	sock := d.replySockets[origin]
	d.mu.Unlock()
	if sock != nil {
		_, _ = sock.WriteTo(pkt, client)
		return
	}
	if !open {
		return
	}
	sock, err := d.replier.replySocket(origin)
	if err != nil {
		return
	}
	_, _ = sock.WriteTo(pkt, client)
	_ = sock.Close()
}

// dispatchDatagram is the terminal step, for a datagram no QUIC connection could claim. It is
// its own unit: the flow it belongs to is looked up, the entry serving it is resolved on the
// tree as it stands, and the handler decides what happens to it. It reports false when nothing
// admits the datagram, which is then left untouched.
func (d *quicDemux) dispatchDatagram(client net.Addr, from flowKey, datagram []byte, owned bool) bool {
	origin := d.originalDst(client)
	if !origin.IsValid() {
		return false
	}

	id := udpKey{origin: origin, name: d.declaredName(client)}
	d.mu.Lock()
	flow := d.flows[from]
	var u *udpFlow
	if flow != nil {
		u = flow.udp[id]
	}
	d.mu.Unlock()

	if u != nil {
		u.enqueue(datagram, owned)
		return true
	}
	if flow == nil && d.ownSource(from) {
		d.p.cfg.logger.Debug("edge: datagram dropped",
			slog.String("client", from.String()),
			slog.String("origin", origin.String()),
			slog.String("reason", "the proxy sent it upstream, a request loop"))
		return true
	}
	return d.openUDPFlow(client, from, origin, datagram, owned)
}

// ownSource reports whether from is a socket the proxy opened upstream. It is called for a
// source without a flow only, and never for a tunnel, which a front checked when it opened.
func (d *quicDemux) ownSource(from flowKey) bool {
	return from.tunnel == nil && d.p.srv.fwd.up.own.datagram(from.addr)
}

// refuseOwn replies to the Initial of a QUIC connection the proxy opened upstream with a
// CONNECTION_CLOSE, so that its dial fails at once instead of waiting out its handshake timeout.
func (d *quicDemux) refuseOwn(addr net.Addr, from flowKey, version uint32, dcid, scid []byte) {
	d.logRefused(from, "the proxy opened it upstream, a request loop")
	pkt, err := quicsniff.CloseInitial(version, dcid, scid, dcid, uint64(quic.ConnectionRefused))
	if err != nil {
		return
	}
	d.answer(addr, d.originalDst(addr), pkt, true)
}

// openUDPFlow admits the first datagram of a flow and publishes the flow, whose goroutine
// dials the origin. It reports false when no entry admits the destination.
func (d *quicDemux) openUDPFlow(client net.Addr, from flowKey, origin netip.AddrPort, datagram []byte, owned bool) bool {
	target := d.declaredTarget(client, origin)

	// Admitted before the socket is opened, so a destination nothing names costs no dial. The
	// datagram is routed again once the flow exists, like every other one.
	if !d.p.Admits(target, KindUDP) {
		d.p.cfg.logger.Debug("edge: datagram dropped",
			slog.String("client", from.String()),
			slog.String("origin", origin.String()),
			slog.String("reason", "no entry admits this destination"))
		return false
	}

	ctx, cancel := context.WithCancel(d.ctx)
	sess := newSession(d.p, ctx, nil, target, KindUDP, 0)
	d.fillSession(sess, client)
	sess.setUpstream(origin)
	u := &udpFlow{
		sess:   sess,
		cancel: cancel,
		client: client,
		key:    origin,
		id:     udpKey{origin: origin, name: d.declaredName(client)},
		target: target,
		outQ:   make(chan udpDatagram, udpQueue),
	}
	sess.closer = &udpFlowCloser{d: d, u: u, flow: from, key: u.id}
	u.sink = &udpSink{d: d, u: u}
	u.out = u.newCtx(false, origin)
	u.in = u.newCtx(true, origin)
	u.touch(time.Now())

	d.mu.Lock()
	evicted, ok := d.publishUDPLocked(from, client, u)
	d.mu.Unlock()
	for _, c := range evicted {
		_ = c.Close()
	}
	if !ok {
		cancel()
		d.p.cfg.logger.Debug("edge: datagram dropped",
			slog.String("client", from.String()),
			slog.String("origin", origin.String()),
			slog.String("reason", "the proxy is at capacity or shutting down"))
		return true
	}

	u.enqueue(datagram, owned)
	return true
}

// newCtx builds the context of one direction of the flow, for datagrams exchanged with origin.
func (u *udpFlow) newCtx(inbound bool, origin netip.AddrPort) DatagramCtx {
	return DatagramCtx{
		ctx:     u.sess.Context(),
		sink:    u.sink,
		p:       u.sink.d.p,
		sess:    u.sess,
		target:  u.target,
		client:  addrPort(u.sess.remoteAddr),
		origin:  origin,
		inbound: inbound,
	}
}

// dialUDP opens the socket u sends through toward addr, with the transport's dialer. Behind a
// CONNECT-UDP tunnel the socket sets the Don't Fragment bit where the platform allows it, RFC
// 9298 section 3.1, and elsewhere a datagram is fragmented as it would be without the proxy.
func (d *quicDemux) dialUDP(u *udpFlow, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(u.sess.Context(), 10*time.Second)
	defer cancel()
	sock, err := d.p.srv.fwd.up.dial(ctx, "udp", addr, "https")
	if err != nil {
		return nil, err
	}
	if ta, isTunnel := u.client.(*tunnelAddr); isTunnel {
		if _, isConnectUDP := ta.tunnel.framing.(*contextFraming); isConnectUDP {
			_ = netutil.SetDontFragment(sock)
		}
	}
	return noICMPConn{sock}, nil
}

// declaredTarget is the authority a datagram flow is routed on, the target a CONNECT-UDP named
// or the address the datagram was headed to.
func (d *quicDemux) declaredTarget(client net.Addr, origin netip.AddrPort) Target {
	if ta, ok := client.(*tunnelAddr); ok {
		return ta.tunnel.framing.declared()
	}
	return Target{
		Scheme: schemeForPort(fmt.Sprint(origin.Port())),
		Host:   origin.Addr().Unmap().String(),
		Port:   fmt.Sprint(origin.Port()),
	}
}

// declaredName is the name the datagram being dispatched was addressed to behind a tunnel,
// empty for an address and off a socket.
func (d *quicDemux) declaredName(client net.Addr) string {
	if ta, ok := client.(*tunnelAddr); ok {
		return ta.tunnel.framing.declaredName()
	}
	return ""
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

// publishUDPLocked places a datagram flow in its client's flow, and returns the sockets of
// the flow it evicted to make room, the least recently used, for the caller to close off the
// lock. It shares the draining critical section with shutdown, so the flow is either refused
// or in the snapshot a shutdown sweeps.
func (d *quicDemux) publishUDPLocked(from flowKey, client net.Addr, u *udpFlow) ([]net.Conn, bool) {
	if d.draining.Load() || d.udps >= maxUDPFlows {
		return nil, false
	}
	flow := d.flowLocked(from, client, time.Now())
	if flow == nil || flow.udp[u.id] != nil {
		return nil, false
	}
	if d.replier != nil {
		reply, err := d.replySocketLocked(u.key)
		if err != nil {
			return nil, false
		}
		u.reply = reply
	}
	var evicted []net.Conn
	if len(flow.udp) >= maxUDPPerFlow {
		var victim *udpFlow
		for _, other := range flow.udp {
			if victim == nil || other.lastUse().Before(victim.lastUse()) {
				victim = other
			}
		}
		delete(flow.udp, victim.id)
		d.udps--
		evicted = victim.endLocked()
	}
	flow.udp[u.id] = u
	d.udps++
	// Off the WaitGroup, a handler that ignores its cut would otherwise keep the socket.
	go d.runOutbound(from, u)
	return evicted, true
}

// runOutbound dials the origin, then serves the queued outbound datagrams of the flow in the
// order they arrived.
func (d *quicDemux) runOutbound(from flowKey, u *udpFlow) {
	defer func() {
		for len(u.outQ) > 0 {
			(<-u.outQ).release()
		}
	}()
	upstream, err := d.dialUDP(u, u.key.String())
	if err != nil {
		d.p.cfg.logger.Debug("edge: cannot reach the origin",
			slog.String("origin", u.key.String()), slog.String("error", err.Error()))
		d.closeUDPFlow(from, u)
		return
	}
	d.mu.Lock()
	if u.closed {
		d.mu.Unlock()
		_ = upstream.Close()
		return
	}
	u.upstream = upstream
	d.mu.Unlock()
	go d.runUDPFlow(from, u)

	done := u.sess.Context().Done()
	for {
		select {
		case dg := <-u.outQ:
			u.queued.Add(-int64(len(dg.b)))
			d.serveDatagram(u, dg.b, false)
			dg.release()
		case <-done:
			return
		}
	}
}

// serveDatagram routes one datagram and runs the handler that serves it. The entry is resolved
// on the tree as it stands, so an entry removed while the flow is open stops it here rather
// than at the next flow.
func (d *quicDemux) serveDatagram(u *udpFlow, payload []byte, inbound bool) {
	if inbound {
		d.serveDatagramOn(u, &u.in, payload)
		return
	}
	d.serveDatagramOn(u, &u.out, payload)
}

// serveDatagramOn routes one datagram of the flow through c, the context of the direction and
// the origin it arrived on.
func (d *quicDemux) serveDatagramOn(u *udpFlow, c *DatagramCtx, payload []byte) {
	d.mu.Lock()
	closed := u.closed
	d.mu.Unlock()
	if closed {
		return
	}
	if c.inbound {
		u.touch(time.Now())
	}

	seq := &u.outSeq
	if c.inbound {
		seq = &u.inSeq
	}

	// Routed on the tree as it stands, per datagram. Nothing is remembered between two of
	// them, and what serves one is whatever the tree says now.
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
	if ta, ok := s.u.client.(*tunnelAddr); ok {
		ta.tunnel.send(s.u.key, b)
		return nil
	}
	if s.u.reply != nil {
		_, err := s.u.reply.WriteTo(b, s.u.client)
		return err
	}
	_, err := s.d.pc.WriteTo(b, s.u.client)
	return err
}

func (s *udpSink) toAddr(addr string, b []byte) error {
	alt, err := s.d.alternate(s.u, addr)
	if err != nil {
		return err
	}
	_, err = alt.conn.Write(b)
	return err
}

// alternate returns the socket of the flow toward addr, opening it and starting its reader on
// first use.
func (d *quicDemux) alternate(u *udpFlow, addr string) (*udpAlt, error) {
	d.mu.Lock()
	alt, err := u.alternateLocked(addr)
	d.mu.Unlock()
	if alt != nil || err != nil {
		return alt, err
	}

	conn, err := d.dialUDP(u, addr)
	if err != nil {
		return nil, err
	}
	alt = &udpAlt{conn: conn, in: u.newCtx(true, addrPort(conn.RemoteAddr()))}

	d.mu.Lock()
	existing, err := u.alternateLocked(addr)
	if existing == nil && err == nil {
		if u.alts == nil {
			u.alts = make(map[string]*udpAlt)
		}
		u.alts[addr] = alt
	}
	d.mu.Unlock()
	if existing != nil || err != nil {
		_ = conn.Close()
		return existing, err
	}

	go d.runUDPAlternate(u, addr, alt)
	return alt, nil
}

// alternateLocked returns the flow's socket toward addr when it exists, or the reason one
// cannot be opened.
func (u *udpFlow) alternateLocked(addr string) (*udpAlt, error) {
	if u.closed {
		return nil, net.ErrClosed
	}
	if alt := u.alts[addr]; alt != nil {
		return alt, nil
	}
	if len(u.alts) >= maxUDPAlternates {
		return nil, ErrTooManyOrigins
	}
	return nil, nil
}

// runUDPAlternate reads what one alternate origin sends back and routes each datagram on the
// flow. The flow's own reader decides when the flow falls idle, so a silent alternate never
// keeps it alive and never ends it.
func (d *quicDemux) runUDPAlternate(u *udpFlow, addr string, alt *udpAlt) {
	buf := make([]byte, maxUDPPayload)
	for {
		_ = alt.conn.SetReadDeadline(u.idleDeadline())
		n, err := alt.conn.Read(buf)
		if n > 0 || err == nil {
			d.serveDatagramOn(u, &alt.in, buf[:n])
		}
		if err == nil || isTimeout(err) {
			continue
		}
		d.mu.Lock()
		if u.alts[addr] == alt {
			delete(u.alts, addr)
		}
		d.mu.Unlock()
		_ = alt.conn.Close()
		return
	}
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
		if n > 0 || err == nil {
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

// endLocked marks the flow closed and returns its sockets, the upstream one and the
// alternates, for the caller to close outside the lock. d.mu must be held.
func (u *udpFlow) endLocked() []net.Conn {
	u.closed = true
	if u.cancel != nil {
		u.cancel()
	}
	conns := make([]net.Conn, 0, 1+len(u.alts))
	if u.upstream != nil {
		conns = append(conns, u.upstream)
	}
	for _, alt := range u.alts {
		conns = append(conns, alt.conn)
	}
	u.alts = nil
	return conns
}

func (d *quicDemux) closeUDPFlow(from flowKey, u *udpFlow) {
	d.mu.Lock()
	if u.closed {
		d.mu.Unlock()
		return
	}
	if flow := d.flows[from]; flow != nil && flow.udp[u.id] == u {
		delete(flow.udp, u.id)
		d.udps--
	}
	conns := u.endLocked()
	d.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
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
			udp:      make(map[udpKey]*udpFlow),
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
		conn.declared = from.tunnel.framing.declared()
	}
	flow.conns[odcid] = conn
	d.sniffing++
	return conn
}

// setStateLocked keeps the sniffing count and the stack references in step with the state
// changes.
func (d *quicDemux) setStateLocked(conn *quicConn, s quicConnState) {
	if conn.state.sniffing() && !s.sniffing() {
		d.sniffing--
	}
	if conn.state == connTerminated && s != connTerminated {
		d.releaseInterceptLocked(conn)
	}
	conn.state = s
}

func (d *quicDemux) removeConnLocked(flow *quicFlow, conn *quicConn) {
	if conn.state.sniffing() {
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

// sniff feeds a datagram to the reassembler and starts placing the connection once its
// ClientHello is complete. A first flight datagram with no Initial in it, 0-RTT typically,
// still joins the pending ones, so the terminating stack receives the flight whole.
func (d *quicDemux) sniff(from flowKey, conn *quicConn, datagram []byte, owned bool) {
	kept := datagram
	if !owned {
		kept = bytes.Clone(datagram)
	}

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
	if hello == nil {
		d.mu.Unlock()
		return // still arriving
	}
	// Spawned under the lock close sets draining under, so this Add cannot race the Wait in
	// close.
	if d.draining.Load() {
		d.mu.Unlock()
		d.refuseConn(from, conn, quic.ConnectionRefused, "the proxy is shutting down")
		return
	}
	client := flow.client
	d.setStateLocked(conn, connPlacing)
	conn.sniffer = nil
	d.wg.Go(func() { d.place(from, client, conn, hello) })
	d.mu.Unlock()
}

// pendLocked keeps a datagram of a connection being placed for its stack, within the pending
// bounds. d.mu must be held.
func (d *quicDemux) pendLocked(conn *quicConn, datagram []byte, owned bool) {
	if len(conn.pending) >= maxPendingDatagrams || conn.pendingBytes+len(datagram) > maxPendingBytes {
		return
	}
	if !owned {
		datagram = bytes.Clone(datagram)
	}
	conn.pending = append(conn.pending, datagram)
	conn.pendingBytes += len(datagram)
}

// place decides a connection whose ClientHello is complete and hands it to a stack or rejects
// it. It runs off the goroutine reading the datagrams, which keeps appending to pending.
func (d *quicDemux) place(from flowKey, client net.Addr, conn *quicConn, hello []byte) {
	if d.p.cfg.rejectECH {
		offered, ok := offersECH(hello)
		if !ok {
			d.refuseConn(from, conn, quicDecodeError, "ClientHello cannot be checked for Encrypted Client Hello")
			return
		}
		if offered {
			d.refuseConn(from, conn, quicHandshakeFailure, "ClientHello offers Encrypted Client Hello")
			return
		}
	}

	ch, alert := clientHelloFromQUIC(hello)
	if ch == nil {
		code := quicDecodeError
		if alert != 0 {
			code = quic.TransportErrorCode(0x100 + uint64(alert))
		}
		d.refuseConn(from, conn, code, "the ClientHello cannot be parsed")
		return
	}
	target := d.targetFor(ch, conn)
	if target.Host == "" {
		d.refuseConn(from, conn, quicMissingExtension, "no server name in the ClientHello")
		return
	}

	// RFC 9001 section 8.1 makes ALPN mandatory on QUIC, so an offer with nothing in it says
	// nothing about what the connection carries and is refused rather than guessed at.
	if len(ch.ALPN) == 0 {
		d.refuseConn(from, conn, quicNoApplicationProtocol, "the ClientHello offers no application protocol")
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
	if d.ctx.Err() != nil {
		return
	}
	switch verdict {
	case nameMismatch:
		d.refuseConn(from, conn, quicUnrecognizedName, "the server name does not resolve to the destination")
		return
	case nameUnresolved:
		d.refuseConn(from, conn, quicUnrecognizedName, "the server name cannot be resolved")
		return
	}

	kind := d.p.firstAdmitted(target, candidates...)
	if kind == 0 {
		// An authority admitted for HTTP only has no protocol in common with an offer without
		// h3, RFC 9001 section 8.1.
		if !slices.Contains(candidates, KindHTTP) && d.p.firstAdmitted(target, KindHTTP) != 0 {
			d.refuseConn(from, conn, quicNoApplicationProtocol, "the ClientHello offers no protocol the authority admits")
			return
		}
		// Without a server name the refusal reports the missing extension, as a TLS front does.
		code := quicUnrecognizedName
		if !named {
			code = quicMissingExtension
		}
		d.refuseConn(from, conn, code, "no entry admits this authority")
		return
	}

	d.beginTermination(from, client, conn, target, ch, kind, candidates)
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
	target Target, hello *ClientHello, kind Kind, candidates []Kind,
) {
	if err := d.startTermination(); err != nil {
		if !errors.Is(err, ErrProxyClosed) {
			d.p.cfg.logger.Error("edge: cannot terminate QUIC", slog.String("error", err.Error()))
		}
		code := quic.ConnectionRefused
		if errors.Is(err, ErrNoCertificateAuthority) {
			code = quicInternalError
		}
		d.refuseConn(from, conn, code, err.Error())
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	sess := newSession(d.p, ctx, nil, target, kind, 0)
	d.fillSession(sess, client)
	sess.setUpstream(conn.origin)
	sess.clientHello.Store(hello)
	d.p.seedVerified(sess, hello.ServerName, target)
	sess.servableAs = candidates
	sess.closer = &quicConnCloser{d: d, conn: conn, flow: from, odcid: conn.odcid}

	d.mu.Lock()
	flow := d.flows[from]
	if flow == nil || flow.conns[conn.odcid] != conn || conn.state != connPlacing {
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
		d.refuseConn(from, conn, quic.ConnectionRefused, "the proxy is shutting down")
		return
	}
	it, evicted, err := d.interceptForLocked(client, conn.origin)
	if err != nil {
		d.mu.Unlock()
		cancel()
		d.refuseConn(from, conn, quic.ConnectionRefused, err.Error())
		return
	}
	d.setStateLocked(conn, connTerminated)
	pending := conn.pending
	conn.pending = nil
	conn.pendingBytes = 0
	conn.sess = sess
	conn.cancel = cancel
	conn.kind = kind
	conn.stack = it
	it.conns++
	// The session is published, so a sweep started after the tree changed either found it or
	// ran before this check, which then observes the change. Refused under the same lock, so
	// nothing reaches the stack and no handshake completes.
	withdrawn := !d.p.Admits(target, kind)
	if withdrawn {
		d.rejectConnLocked(conn)
	} else {
		// Delivered under the lock, so a datagram read once the state is terminated follows
		// the first flight into the stack.
		for _, dg := range pending {
			it.deliver(client, dg, true)
		}
	}
	d.mu.Unlock()
	if evicted != nil {
		d.closeIntercept(evicted)
	}
	if withdrawn {
		d.logRefused(from, "the authority was withdrawn while the connection was starting")
		d.sendRefusal(client, conn, quic.ConnectionRefused)
	}
}

// rejectConn marks a connection refused. The state stays as a tombstone until its TTL, so the
// client's Initial retransmits are dropped without being decrypted again, and a fresh Initial
// with a new connection ID from the same socket is evaluated from scratch.
func (d *quicDemux) rejectConn(from flowKey, conn *quicConn, reason string) {
	d.mu.Lock()
	if flow := d.flows[from]; flow != nil && flow.conns[conn.odcid] == conn {
		d.rejectConnLocked(conn)
	}
	d.mu.Unlock()
	d.logRejected(from, reason)
}

// refuseConn is rejectConn for a connection whose ClientHello was read, answered once with an
// Initial with a CONNECTION_CLOSE of code, RFC 9000 section 5.2.2. The tombstone keeps a
// retransmit from being answered again.
func (d *quicDemux) refuseConn(from flowKey, conn *quicConn, code quic.TransportErrorCode, reason string) {
	var client net.Addr
	d.mu.Lock()
	if flow := d.flows[from]; flow != nil && flow.conns[conn.odcid] == conn && conn.state != connRejected {
		client = flow.client
		d.rejectConnLocked(conn)
	}
	d.mu.Unlock()
	d.logRefused(from, reason)
	if client != nil {
		d.sendRefusal(client, conn, code)
	}
}

// sendRefusal writes the Initial refusing conn to client, from the address the client wrote to.
// The fields it reads are set before the connection is published.
func (d *quicDemux) sendRefusal(client net.Addr, conn *quicConn, code quic.TransportErrorCode) {
	odcid := []byte(conn.odcid)
	pkt, err := quicsniff.CloseInitial(conn.version, odcid, conn.scid[:conn.scidLen], odcid, uint64(code))
	if err != nil {
		return
	}
	d.answer(client, conn.origin, pkt, true)
}

func (d *quicDemux) rejectConnLocked(conn *quicConn) {
	d.setStateLocked(conn, connRejected)
	conn.lastSeen = time.Now()
	conn.sniffer = nil
	conn.pending = nil
	conn.pendingBytes = 0
	conn.sess = nil
	conn.end()
}

func (d *quicDemux) logRejected(from flowKey, reason string) {
	d.p.cfg.logger.Debug("edge: QUIC connection dropped",
		slog.String("client", from.String()), slog.String("reason", reason))
}

func (d *quicDemux) logRefused(from flowKey, reason string) {
	d.p.cfg.logger.Debug("edge: QUIC connection refused",
		slog.String("client", from.String()), slog.String("reason", reason))
}

func (d *quicDemux) sweepIdle() {
	now := time.Now()
	d.mu.Lock()
	var stale []net.Conn
	var tunnels []*connectUDPTunnel
	for from, flow := range d.flows {
		for _, conn := range flow.conns {
			switch conn.state {
			case connSniffing, connPlacing:
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
				delete(flow.udp, key)
				d.udps--
				stale = append(stale, u.endLocked()...)
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
	for _, c := range stale {
		_ = c.Close()
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
				used[key.origin] = true
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
		var sockets []net.Conn
		var tunnels []*connectUDPTunnel
		for key, flow := range d.flows {
			if key.tunnel != nil {
				tunnels = append(tunnels, key.tunnel)
			}
			for _, u := range flow.udp {
				sockets = append(sockets, u.endLocked()...)
			}
			for _, conn := range flow.conns {
				conn.end()
			}
		}
		conns := make([]*quic.Conn, 0, len(d.accepted))
		for qc := range d.accepted {
			conns = append(conns, qc)
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
		clear(d.accepted)
		d.sniffing = 0
		d.udps = 0
		d.mu.Unlock()

		for _, s := range sockets {
			_ = s.Close()
		}
		// http3.Server.Close would wait for every handler, so every accepted connection is
		// closed here.
		for _, qc := range conns {
			_ = closeNoError(qc)
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

// quicInterceptKeys derives the tag and the stateless reset secret from the CA key, so a proxy
// restarted with the same CA on the same address resets the connections of the previous process.
// A key that cannot be serialized, hardware backed for instance, gets per process random keys.
func quicInterceptKeys(ca *CA) (*quicCIDTag, *quicResetSecret, error) {
	var tagKey [16]byte
	reset := new(quicResetSecret)

	if der, err := x509.MarshalPKCS8PrivateKey(ca.key); err == nil {
		t, terr := hkdf.Key(sha256.New, der, nil, "edge quic cid tag", len(tagKey))
		r, rerr := hkdf.Extract(sha256.New, der, nil)
		if terr == nil && rerr == nil {
			copy(tagKey[:], t)
			copy(reset[:], r)
			tag, err := newQUICCIDTag(tagKey)
			return tag, reset, err
		}
	}

	if _, err := rand.Read(tagKey[:]); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(reset[:]); err != nil {
		return nil, nil, err
	}
	tag, err := newQUICCIDTag(tagKey)
	return tag, reset, err
}

// quicResetSecret is what the stateless reset key of every terminating stack derives from.
type quicResetSecret [32]byte

const (
	quicResetLabel = "edge quic stateless reset "
	// quicResetIDSize is the largest stack identity, the random one of a stack behind a tunnel.
	quicResetIDSize = 32
)

// key derives the stateless reset key of the stack id identifies, HKDF-Expand of RFC 5869 over
// the label and id. RFC 9000 section 21.11 bars a reset for a connection ID that may be live on
// any endpoint sharing the key, so every stack has a key of its own.
func (s *quicResetSecret) key(id []byte) quic.StatelessResetKey {
	// One HMAC-SHA256 block, written out on arrays so an orphan datagram costs no allocation.
	var ipad, opad [sha256.BlockSize]byte
	for i := range ipad {
		ipad[i], opad[i] = 0x36, 0x5c
	}
	for i, b := range s {
		ipad[i] ^= b
		opad[i] ^= b
	}
	if len(id) > quicResetIDSize {
		panic("edge: stateless reset identity longer than quicResetIDSize")
	}
	var msg [sha256.BlockSize + len(quicResetLabel) + quicResetIDSize + 1]byte
	n := copy(msg[:], ipad[:])
	n += copy(msg[n:], quicResetLabel)
	n += copy(msg[n:], id)
	msg[n] = 0x01
	inner := sha256.Sum256(msg[:n+1])

	var outer [sha256.BlockSize + sha256.Size]byte
	copy(outer[:], opad[:])
	copy(outer[sha256.BlockSize:], inner[:])
	return quic.StatelessResetKey(sha256.Sum256(outer[:]))
}

// addrKey derives the stateless reset key of the stack replying from addr, the same for every
// process serving that address.
func (s *quicResetSecret) addrKey(addr netip.AddrPort) quic.StatelessResetKey {
	var id [18]byte
	ip := addr.Addr().As16()
	copy(id[:], ip[:])
	binary.BigEndian.PutUint16(id[16:], addr.Port())
	return s.key(id[:])
}

// clientHelloFromQUIC reads the ClientHello out of a raw handshake message. QUIC carries
// handshake messages without a record layer, so one is put back for the sake of the parser.
// It returns what clientHelloFromRecords returns.
func clientHelloFromQUIC(hello []byte) (*ClientHello, byte) {
	if len(hello) == 0 || len(hello) > math.MaxUint16 {
		return nil, 0
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
func (c *demuxPacketConn) deliver(addr net.Addr, b []byte, owned bool) {
	if !owned {
		b = bytes.Clone(b)
	}
	select {
	case c.in <- datagram{b: b, addr: addr}:
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
