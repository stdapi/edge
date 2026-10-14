// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stdapi/edge/internal/stringsutil"
)

const (
	// connectUDPPath is the well-known template of RFC 9298 section 3, without its variables.
	connectUDPPath = "/.well-known/masque/udp/"
	// tunnelSendQueue bounds the datagrams waiting to be sent into one tunnel. SendDatagram
	// blocks once 32 datagrams wait on the front connection, and a full queue drops so one
	// stalled client does not stall the stack serving every other tunnel.
	tunnelSendQueue = 64
	// tunnelBufSize exceeds the largest packet the terminating stack writes, 1452 bytes in
	// quic-go, plus the context ID and the capsule header.
	tunnelBufSize = 2048
	// tunnelDrainTimeout bounds the writes that end a tunnel to a client that stopped reading.
	tunnelDrainTimeout = time.Second
	// connectUDPUpgrade is the Upgrade token and the :protocol of RFC 9298.
	connectUDPUpgrade = "connect-udp"
)

var (
	tunnelSeq     atomic.Uint64
	tunnelBufPool = sync.Pool{New: func() any { return new([tunnelBufSize]byte) }}
)

// serveConnectUDP handles a CONNECT-UDP request, RFC 9298, an extended CONNECT over HTTP/2
// and HTTP/3 and a GET with an Upgrade over HTTP/1.1. The tunnel's datagrams are placed by
// the demultiplexer like a redirected socket's, and the tunnel is a session of its own.
func (p *Proxy) serveConnectUDP(w http.ResponseWriter, r *http.Request, identity string) {
	target, err := targetFromConnectUDP(r)
	if err != nil {
		p.writeStatus(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if hasContentFields(r.Header, r.TransferEncoding) {
		// net/http drains the body of a request it keeps the connection of before answering,
		// and the body of a GET may never end.
		w.Header().Set("Connection", "close")
		p.writeStatus(w, r, http.StatusBadRequest, "CONNECT-UDP request with content fields")
		return
	}

	// The tunnel is recorded under the most specific kind admitted. Admission comes before
	// resolution, and a refused target is not resolved.
	candidates := []Kind{KindHTTP, KindQUIC, KindUDP}
	kind := p.firstAdmitted(target, candidates...)
	if kind == 0 {
		p.writeStatus(w, r, http.StatusForbidden, "no entry admits this authority")
		return
	}
	// RFC 9298 section 3.1 has the proxy resolve the target before answering, and answer
	// 502 when it cannot.
	upstream, err := p.resolveTarget(r.Context(), target)
	if err != nil {
		p.writeStatus(w, r, http.StatusBadGateway, "cannot resolve the target: "+err.Error())
		return
	}

	d, err := p.srv.tunnelDemux()
	if err != nil {
		p.writeStatus(w, r, http.StatusServiceUnavailable, "the proxy is shutting down")
		return
	}

	ctx, cancel := p.tunnelContext(r)
	defer cancel()
	sess := newSession(p, ctx, nil, target, kind, protoOfRequest(r))
	sess.cancel = cancel
	sess.servableAs = candidates
	sess.setUpstream(upstream)
	sess.identity = identity
	sess.tunnel = true
	front := sessionFromRequest(r)
	sess.remoteAddr, sess.localAddr = front.remoteAddr, front.localAddr
	if state := front.tlsState.Load(); state != nil {
		sess.tlsState.Store(state)
	} else {
		sess.pendingTLS = front.pendingTLS
	}

	tun := newConnectUDPTunnel(d, sess, &contextFraming{target: target, upstream: upstream}, cancel)
	sess.closer = tun
	if !d.publishTunnel(tun) {
		p.writeStatus(w, r, http.StatusServiceUnavailable, "the proxy is at capacity or shutting down")
		return
	}
	defer tun.close()

	// A refused registration means the proxy is stopping. Returning would let the server
	// answer 200 for a tunnel that is already gone, so the stream is reset instead.
	if !p.srv.tryTrack(tun) {
		panic(http.ErrAbortHandler)
	}
	defer p.srv.untrack(tun)

	if !p.srv.admitSession(sess) {
		p.writeStatus(w, r, http.StatusForbidden, "the entries changed while the tunnel was admitted")
		return
	}
	defer p.srv.untrackSession(sess)

	pipe := p.openTunnel(ctx, w, r, tun)
	if pipe == nil {
		return
	}
	tun.serve(ctx, pipe)
	if cp, isCapsules := pipe.(*capsulePipe); isCapsules {
		if stream, isStream := cp.conn.(*h2Stream); isStream {
			stream.finish()
			if stream.aborted.Load() {
				// A return ends the stream cleanly.
				panic(http.ErrAbortHandler)
			}
		}
	}
}

// hasContentFields reports whether a message of the Capsule Protocol has a field RFC 9297
// section 3.2 forbids on it.
func hasContentFields(h http.Header, transferEncoding []string) bool {
	return len(transferEncoding) > 0 || h["Content-Length"] != nil || h["Content-Type"] != nil ||
		h["Transfer-Encoding"] != nil
}

// tunnelContext returns the context a tunnel lives under. A stream ends with its request. A
// hijacked HTTP/1.1 connection outlives the request that opened it, the way a CONNECT does.
func (p *Proxy) tunnelContext(r *http.Request) (context.Context, context.CancelFunc) {
	if r.ProtoMajor >= 2 {
		return context.WithCancel(r.Context())
	}
	return p.hijackedContext(r)
}

// openTunnel answers the request and returns the pipe of the tunnel, nil once the client was
// answered with an error. Over HTTP/3 the datagrams are QUIC datagrams, over HTTP/2 capsules
// on the CONNECT stream, over HTTP/1.1 capsules on the connection the 101 leaves behind. The
// tunnel lives under ctx.
func (p *Proxy) openTunnel(ctx context.Context, w http.ResponseWriter, r *http.Request, tun *connectUDPTunnel) tunnelPipe {
	switch r.ProtoMajor {
	case 3:
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			p.writeStatus(w, r, http.StatusInternalServerError, "the stream has no datagram support")
			return nil
		}
		// A tunnel closed while the SETTINGS are awaited is answered, and serve ends it.
		capsules := peerWithoutDatagrams(ctx, w)
		if r.Context().Err() != nil {
			return nil
		}
		w.Header().Set(http3.CapsuleProtocolHeader, "?1")
		w.WriteHeader(http.StatusOK)
		pipe := newDatagramPipe(streamer.HTTPStream(), quic.StreamErrorCode(http3.ErrCodeRequestCanceled), capsules)
		pipe.run(tun.close)
		return pipe
	case 2:
		w.Header().Set(http3.CapsuleProtocolHeader, "?1")
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		stream := newH2Stream(w, r, tun.sess.localAddr, tun.sess.remoteAddr)
		return newCapsulePipe(stream, bufio.NewReader(stream))
	default:
		client, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			p.writeStatus(w, r, http.StatusInternalServerError, "cannot hijack the connection for CONNECT-UDP")
			return nil
		}
		if err := writeConnectUDPUpgrade(brw); err != nil {
			_ = client.Close()
			return nil
		}
		// Anything the reader buffered past the request is already capsule data.
		return newCapsulePipe(client, brw.Reader)
	}
}

// peerWithoutDatagrams waits for the SETTINGS of the client until ctx ends, and reports
// whether it did not send SETTINGS_H3_DATAGRAM, true when they did not arrive.
func peerWithoutDatagrams(ctx context.Context, w http.ResponseWriter) bool {
	s, isSettingser := w.(http3.Settingser)
	if !isSettingser {
		return false
	}
	select {
	case <-s.ReceivedSettings():
		return !s.Settings().EnableDatagrams
	case <-ctx.Done():
		return true
	}
}

func writeConnectUDPUpgrade(brw *bufio.ReadWriter) error {
	if _, err := brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " +
		connectUDPUpgrade + "\r\n" + http3.CapsuleProtocolHeader + ": ?1\r\n\r\n"); err != nil {
		return err
	}
	return brw.Flush()
}

func isConnectUDPUpgrade(r *http.Request) bool {
	return r.Method == http.MethodGet && r.ProtoMajor == 1 &&
		strings.EqualFold(upgradeType(r.Header), connectUDPUpgrade)
}

// targetFromConnectUDP reads the target out of the request path. The host and the port arrive
// percent-encoded, an IPv6 literal without brackets, and the host is returned unbracketed like
// every Target.
func targetFromConnectUDP(r *http.Request) (Target, error) {
	if r.URL == nil {
		return Target{}, errors.New("CONNECT-UDP carries no target")
	}
	raw := r.URL.EscapedPath()
	rest, ok := strings.CutPrefix(raw, connectUDPPath)
	if !ok {
		return Target{}, errors.New("CONNECT-UDP target must be under " + connectUDPPath)
	}
	segments := strings.Split(rest, "/")
	if len(segments) != 3 || segments[2] != "" || segments[0] == "" || segments[1] == "" {
		return Target{}, errors.New("CONNECT-UDP target must be host/port/")
	}
	host, err := url.PathUnescape(segments[0])
	if err != nil {
		return Target{}, fmt.Errorf("CONNECT-UDP target host: %w", err)
	}
	port, err := url.PathUnescape(segments[1])
	if err != nil {
		return Target{}, fmt.Errorf("CONNECT-UDP target port: %w", err)
	}
	return targetFromWire(host, port)
}

// targetFromWire builds a target from a host and a port read off the wire, the host a
// hostname or an address, an IPv6 one unbracketed. The pair must survive a rejoin, or the
// authority written back would not be the one routed on.
func targetFromWire(host, port string) (Target, error) {
	host = canonicalHost(stringsutil.ToLowerASCIIString(host))
	port, ok := canonicalPort(port)
	if !ok {
		return Target{}, errors.New("target port is not a port")
	}
	if h, _, ok := splitAuthority(joinHostPort(host, port)); !ok || h == "" || h != host {
		return Target{}, errors.New("target host is not a hostname or an address")
	}
	return Target{Scheme: schemeForPort(port), Host: host, Port: port}, nil
}

// resolveTarget resolves the address a tunnel sends to, once for its life.
func (p *Proxy) resolveTarget(ctx context.Context, t Target) (netip.AddrPort, error) {
	port, err := strconv.ParseUint(t.Port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if addr, aerr := netip.ParseAddr(t.Host); aerr == nil {
		return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
	}
	rctx, cancel := context.WithTimeout(ctx, nameVerifyTimeout)
	defer cancel()
	addrs, err := p.cfg.resolver.LookupNetIP(rctx, "ip", t.Host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, errors.New("no address")
	}
	return netip.AddrPortFrom(addrs[0].Unmap(), uint16(port)), nil
}

// tunnelFraming is how the datagrams of a tunnel are framed on its pipe, and where each is
// headed.
type tunnelFraming interface {
	// unwrap returns the payload of a datagram read off the pipe and where it is headed, ok
	// false for one dropped.
	unwrap(b []byte) (payload []byte, upstream netip.AddrPort, ok bool)
	// declared returns the target of the datagram unwrap last returned, and declaredName its
	// host when that is a name, allocating nothing.
	declared() Target
	declaredName() string
	// wrap returns b framed as a datagram from origin, in a buffer from tunnelBuf with
	// capsuleHeadroom ahead of the frame.
	wrap(origin netip.AddrPort, b []byte) []byte
}

type contextFraming struct {
	target   Target
	upstream netip.AddrPort
}

func (f *contextFraming) unwrap(b []byte) ([]byte, netip.AddrPort, bool) {
	// Context ID 0 is a UDP payload, RFC 9298 section 5. Anything else is dropped.
	id, n, err := quicvarint.Parse(b)
	if err != nil || id != 0 {
		return nil, netip.AddrPort{}, false
	}
	return b[n:], f.upstream, true
}

func (f *contextFraming) declared() Target { return f.target }

// One destination per tunnel, so the key of its flows needs no name to be distinct.
func (*contextFraming) declaredName() string { return "" }

func (*contextFraming) wrap(_ netip.AddrPort, b []byte) []byte {
	// The stack reuses its buffer once the write returns, and the context ID goes first.
	out := tunnelBuf(capsuleHeadroom + 1 + len(b))
	out[capsuleHeadroom] = 0
	copy(out[capsuleHeadroom+1:], b)
	return out
}

// connectUDPTunnel is one CONNECT-UDP tunnel or SOCKS5 association. To the demultiplexer it
// is a client socket keyed on the tunnel itself. upstream is the destination of the datagram
// being dispatched, written by the goroutine feeding the tunnel and read on the dispatch
// path alone.
type connectUDPTunnel struct {
	key       flowKey
	d         *quicDemux
	sess      *Session
	framing   tunnelFraming
	pipe      atomic.Pointer[tunnelPipe]
	addr      *tunnelAddr
	cancel    context.CancelFunc
	sendCh    chan []byte
	done      chan struct{}
	sent      chan struct{}
	upstream  netip.AddrPort
	closeOnce sync.Once
	// closed refuses datagrams that reach the demultiplexer after the tunnel ended, so a
	// datagram in flight cannot recreate the flow the close removed.
	closed atomic.Bool
}

func newConnectUDPTunnel(d *quicDemux, sess *Session, framing tunnelFraming, cancel context.CancelFunc) *connectUDPTunnel {
	t := &connectUDPTunnel{
		d:       d,
		sess:    sess,
		framing: framing,
		cancel:  cancel,
		sendCh:  make(chan []byte, tunnelSendQueue),
		done:    make(chan struct{}),
		sent:    make(chan struct{}),
	}
	client := addrPort(sess.remoteAddr)
	t.addr = &tunnelAddr{
		tunnel: t,
		client: client,
		name:   fmt.Sprintf("%s/connect-udp/%d", client, tunnelSeq.Add(1)),
	}
	t.key = flowKey{addr: client, tunnel: t}
	return t
}

// tunnelAddr is the address a tunnel's datagrams arrive with. quic-go compares an address of
// a type it does not know by its string form, so that form stays unique and stable for the
// tunnel's life.
type tunnelAddr struct {
	tunnel *connectUDPTunnel
	client netip.AddrPort
	name   string
}

func (a *tunnelAddr) Network() string { return "connect-udp" }
func (a *tunnelAddr) String() string  { return a.name }

// serve reads the datagrams off the pipe and places each, until the tunnel ends.
func (t *connectUDPTunnel) serve(ctx context.Context, pipe tunnelPipe) {
	t.pipe.Store(&pipe)
	// A reset or the loss of the front connection cancels the context. A FIN alone does
	// not, which the pipe reports as the end of its reads.
	stop := context.AfterFunc(ctx, t.close)
	defer stop()
	go t.sender(pipe)

	for {
		b, err := pipe.recv(ctx)
		if err != nil {
			break
		}
		payload, upstream, ok := t.framing.unwrap(b)
		if !ok {
			continue
		}
		t.upstream = upstream
		t.d.dispatch(t.addr, payload, true)
	}
	t.close()
	// The deadline close armed bounds the drain of every pipe but QUIC datagrams while the client
	// reads its connection. A QUIC datagram waits for room in the connection's queue, so that
	// stream is ended here after tunnelDrainTimeout, and a send still waiting returns once the
	// queue has room or the connection ends.
	if dp, isDatagrams := pipe.(*datagramPipe); !isDatagrams || dp.capsules {
		<-t.sent
		return
	}
	drained := time.NewTimer(tunnelDrainTimeout)
	defer drained.Stop()
	select {
	case <-t.sent:
	case <-drained.C:
		_ = pipe.close()
	}
}

// send queues b, from origin, for the client and drops it when the queue is full.
func (t *connectUDPTunnel) send(origin netip.AddrPort, b []byte) {
	out := t.framing.wrap(origin, b)
	select {
	case t.sendCh <- out:
	default:
		putTunnelBuf(out)
	}
}

func tunnelBuf(n int) []byte {
	if n <= tunnelBufSize {
		return tunnelBufPool.Get().(*[tunnelBufSize]byte)[:n]
	}
	return make([]byte, n)
}

func putTunnelBuf(b []byte) {
	if cap(b) == tunnelBufSize {
		tunnelBufPool.Put((*[tunnelBufSize]byte)(b[:tunnelBufSize]))
	}
}

// sender is the one goroutine writing the pipe. Once the tunnel is done it drains the queue,
// the CONNECTION_CLOSE of every inner connection among it, then ends the pipe, unless serve
// ended it first.
func (t *connectUDPTunnel) sender(pipe tunnelPipe) {
	defer close(t.sent)
	for {
		select {
		case b := <-t.sendCh:
			t.sendDatagram(pipe, b)
			continue
		case <-t.done:
		}
		break
	}
	for {
		select {
		case b := <-t.sendCh:
			t.sendDatagram(pipe, b)
			continue
		default:
		}
		break
	}
	_ = pipe.close()
}

func (t *connectUDPTunnel) sendDatagram(pipe tunnelPipe, b []byte) {
	err := pipe.send(b)
	putTunnelBuf(b)
	if err != nil {
		if tooLarge, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
			t.d.p.cfg.logger.Debug("edge: datagram larger than the tunnel carries",
				slog.String("tunnel", t.addr.String()),
				slog.Int("size", len(b)-capsuleHeadroom),
				slog.Int64("max", tooLarge.MaxDatagramPayloadSize))
		}
	}
}

func (t *connectUDPTunnel) Close() error {
	t.close()
	return nil
}

// close ends the tunnel. Every inner connection is closed with a CONNECTION_CLOSE sent
// through the tunnel, every datagram flow is closed, the stack is torn down, and the stream
// is ended once those closes are sent.
func (t *connectUDPTunnel) close() {
	t.closeOnce.Do(func() {
		d := t.d
		d.mu.Lock()
		t.closed.Store(true)
		var qcs []*quic.Conn
		var sockets []net.Conn
		if flow := d.flows[t.key]; flow != nil {
			for _, conn := range flow.conns {
				if conn.qc != nil {
					qcs = append(qcs, conn.qc)
				}
				d.removeConnLocked(flow, conn)
			}
			for key, u := range flow.udp {
				sockets = append(sockets, u.endLocked()...)
				delete(flow.udp, key)
				d.udps--
			}
			delete(d.flows, t.key)
		}
		var stacks []*quicIntercept
		for key, it := range d.intercepts {
			if key.tunnel == t {
				stacks = append(stacks, it)
				delete(d.intercepts, key)
			}
		}
		d.mu.Unlock()

		// CloseWithError returns once the close has been written, so the packet is queued
		// before the stack goes and before the stream is ended behind it.
		for _, qc := range qcs {
			_ = closeNoError(qc)
		}
		for _, s := range sockets {
			_ = s.Close()
		}
		for _, it := range stacks {
			d.closeIntercept(it)
		}
		if pipe := t.pipe.Load(); pipe != nil {
			_ = (*pipe).setWriteDeadline(time.Now().Add(tunnelDrainTimeout))
		}
		close(t.done)
		if t.cancel != nil {
			t.cancel()
		}
	})
}

// publishTunnel places the tunnel's flow in the demultiplexer, inside the draining critical
// section, so a shutdown either refuses it or finds it.
func (d *quicDemux) publishTunnel(t *connectUDPTunnel) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.draining.Load() {
		return false
	}
	return d.flowLocked(t.key, t.addr, time.Now()) != nil
}

// tunnelPacketConn stands in for the socket of a demultiplexer fed by tunnels. Nothing is
// read from it, the tunnels dispatch their datagrams themselves, and nothing is written to
// it, a reply into a tunnel needs the origin it comes from and goes through the tunnel.
type tunnelPacketConn struct {
	closed chan struct{}
	once   sync.Once
}

func newTunnelPacketConn() *tunnelPacketConn {
	return &tunnelPacketConn{closed: make(chan struct{})}
}

func (c *tunnelPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}

func (c *tunnelPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("edge: write to a tunnel without its origin")
}

func (c *tunnelPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *tunnelPacketConn) LocalAddr() net.Addr { return emptyAddr{} }

// SetReadBuffer and SetWriteBuffer report success so quic-go does not warn, there being no
// socket to size.
func (c *tunnelPacketConn) SetReadBuffer(int) error          { return nil }
func (c *tunnelPacketConn) SetWriteBuffer(int) error         { return nil }
func (c *tunnelPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *tunnelPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *tunnelPacketConn) SetWriteDeadline(time.Time) error { return nil }

var _ net.PacketConn = (*tunnelPacketConn)(nil)
