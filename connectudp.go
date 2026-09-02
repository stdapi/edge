// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
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

	"github.com/fox-toolkit/edge/internal/stringsutil"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	// connectUDPPath is the well-known template of RFC 9298 section 3, without its variables.
	connectUDPPath = "/.well-known/masque/udp/"
	// tunnelSendQueue bounds the datagrams waiting to be sent into one tunnel. SendDatagram
	// blocks once 32 datagrams wait on the front connection, and a full queue drops so one
	// stalled client does not stall the stack serving every other tunnel.
	tunnelSendQueue = 64
	// tunnelBufSize exceeds the largest packet the terminating stack writes, 1452 bytes in
	// quic-go, plus the context ID.
	tunnelBufSize = 2048
)

var (
	tunnelSeq     atomic.Uint64
	tunnelBufPool = sync.Pool{New: func() any { return new([tunnelBufSize]byte) }}
)

// serveConnectUDP handles a CONNECT-UDP request, RFC 9298. The tunnel's datagrams are placed
// by the demultiplexer like a redirected socket's, and the tunnel is a session of its own.
func (p *Proxy) serveConnectUDP(w http.ResponseWriter, r *http.Request, identity string) {
	if r.ProtoMajor < 3 {
		// Over HTTP/2 the datagrams travel as capsules on the stream, which is not
		// implemented.
		http.Error(w, "edge: CONNECT-UDP is served over HTTP/3", http.StatusNotImplemented)
		return
	}
	target, err := targetFromConnectUDP(r)
	if err != nil {
		http.Error(w, "edge: "+err.Error(), http.StatusBadRequest)
		return
	}

	// The tunnel is recorded under the most specific kind admitted. Admission comes before
	// resolution, and a refused target is not resolved.
	candidates := []Kind{KindHTTP, KindQUIC, KindUDP}
	kind := p.firstAdmitted(target, candidates...)
	if kind == 0 {
		http.Error(w, "edge: connection rejected, no entry admits this authority", http.StatusForbidden)
		return
	}
	// RFC 9298 section 3.1 has the proxy resolve the target before answering, and answer
	// 502 when it cannot.
	upstream, err := p.resolveTarget(r.Context(), target)
	if err != nil {
		http.Error(w, "edge: cannot resolve the target: "+err.Error(), http.StatusBadGateway)
		return
	}

	d, err := p.srv.tunnelDemux()
	if err != nil {
		http.Error(w, "edge: the proxy is shutting down", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	sess := newSession(ctx, nil, target, kind, HTTP3)
	sess.servableAs = candidates
	sess.setUpstream(upstream)
	sess.identity = identity
	sess.tunnel = true
	if front := sessionFromRequest(r); front != nil {
		sess.remoteAddr, sess.localAddr = front.remoteAddr, front.localAddr
		if state := front.tlsState.Load(); state != nil {
			sess.tlsState.Store(state)
		}
	}

	tun := newConnectUDPTunnel(d, sess, target, upstream, cancel)
	sess.closer = tun
	if !d.publishTunnel(tun) {
		http.Error(w, "edge: the proxy is at capacity or shutting down", http.StatusServiceUnavailable)
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
		http.Error(w, "edge: connection rejected, no entry admits this authority any more", http.StatusForbidden)
		return
	}
	defer p.srv.trackSession(sess, false)

	streamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		http.Error(w, "edge: the stream cannot carry datagrams", http.StatusInternalServerError)
		return
	}
	w.Header().Set(http3.CapsuleProtocolHeader, "?1")
	w.WriteHeader(http.StatusOK)
	tun.serve(ctx, streamer.HTTPStream())
}

// targetFromConnectUDP reads the target out of the request path. The host arrives
// percent-encoded, an IPv6 literal without brackets, and is returned unbracketed like every
// Target.
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
	host = stringsutil.ToLowerASCIIString(host)
	if strings.ContainsAny(host, "/[] ") {
		return Target{}, errors.New("CONNECT-UDP target host is not a hostname or an address")
	}
	if strings.Contains(host, ":") {
		if _, perr := netip.ParseAddr(host); perr != nil {
			return Target{}, errors.New("CONNECT-UDP target host is not an IPv6 address")
		}
	}
	port, ok := canonicalPort(segments[1])
	if !ok {
		return Target{}, errors.New("CONNECT-UDP target port is not a port")
	}
	// The pair must survive a rejoin, or the authority written back would not be the one
	// routed on.
	if h, p := splitHostPort(joinHostPort(host, port)); h != host || p != port {
		return Target{}, errors.New("CONNECT-UDP target host is not a hostname or an address")
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

// connectUDPTunnel is one CONNECT-UDP tunnel. To the demultiplexer it is a client socket with
// one destination, keyed on the tunnel itself.
type connectUDPTunnel struct {
	key       flowKey
	d         *quicDemux
	sess      *Session
	str       *http3.Stream
	addr      *tunnelAddr
	cancel    context.CancelFunc
	sendCh    chan []byte
	done      chan struct{}
	sent      chan struct{}
	target    Target
	upstream  netip.AddrPort
	closeOnce sync.Once
	// closed refuses datagrams that reach the demultiplexer after the tunnel ended, so a
	// datagram in flight cannot recreate the flow the close removed.
	closed atomic.Bool
}

func newConnectUDPTunnel(d *quicDemux, sess *Session, target Target, upstream netip.AddrPort, cancel context.CancelFunc) *connectUDPTunnel {
	t := &connectUDPTunnel{
		d:        d,
		sess:     sess,
		target:   target,
		upstream: upstream,
		cancel:   cancel,
		sendCh:   make(chan []byte, tunnelSendQueue),
		done:     make(chan struct{}),
		sent:     make(chan struct{}),
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

// serve reads the datagrams off the tunnel and places each, until the tunnel ends.
func (t *connectUDPTunnel) serve(ctx context.Context, str *http3.Stream) {
	t.str = str
	// A reset or the loss of the front connection cancels the request context. A FIN alone
	// does not, which the capsule reader catches.
	stop := context.AfterFunc(ctx, t.close)
	defer stop()
	go t.sender()
	go t.drainCapsules()

	for {
		b, err := str.ReceiveDatagram(ctx)
		if err != nil {
			break
		}
		// Context ID 0 is a UDP payload, RFC 9298 section 5. Anything else is dropped.
		id, n, perr := quicvarint.Parse(b)
		if perr != nil || id != 0 || n >= len(b) {
			continue
		}
		t.d.dispatch(t.addr, b[n:], true)
	}
	t.close()
	<-t.sent
}

// drainCapsules drops every capsule the client sends, RFC 9297 section 3.2, and ends the
// tunnel on the client's FIN.
func (t *connectUDPTunnel) drainCapsules() {
	parser := http3.NewCapsuleParser(t.str)
	for {
		_, r, err := parser.Next()
		if err != nil {
			t.close()
			return
		}
		if err := r.Discard(); err != nil {
			t.close()
			return
		}
	}
}

// send queues b for the client and drops it when the queue is full.
func (t *connectUDPTunnel) send(b []byte) {
	// The stack reuses its buffer once the write returns, and the context ID goes first.
	var out []byte
	if 1+len(b) <= tunnelBufSize {
		out = tunnelBufPool.Get().(*[tunnelBufSize]byte)[:1+len(b)]
	} else {
		out = make([]byte, 1+len(b))
	}
	out[0] = 0
	copy(out[1:], b)
	select {
	case t.sendCh <- out:
	default:
		putTunnelBuf(out)
	}
}

func putTunnelBuf(b []byte) {
	if cap(b) == tunnelBufSize {
		tunnelBufPool.Put((*[tunnelBufSize]byte)(b[:tunnelBufSize]))
	}
}

// sender is the one goroutine writing the stream. Once the tunnel is done it drains the queue,
// the CONNECTION_CLOSE of every inner connection among it, then ends the stream with a FIN on
// the response and a STOP_SENDING on the request.
func (t *connectUDPTunnel) sender() {
	defer close(t.sent)
	for {
		select {
		case b := <-t.sendCh:
			t.sendDatagram(b)
			continue
		case <-t.done:
		}
		break
	}
	for {
		select {
		case b := <-t.sendCh:
			t.sendDatagram(b)
			continue
		default:
		}
		break
	}
	_ = t.str.Close()
	t.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
}

func (t *connectUDPTunnel) sendDatagram(b []byte) {
	err := t.str.SendDatagram(b)
	putTunnelBuf(b)
	if err != nil {
		if tooLarge, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
			t.d.p.cfg.logger.Debug("edge: datagram larger than the tunnel carries",
				slog.String("target", t.target.String()),
				slog.Int("size", len(b)),
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
				u.closed = true
				if u.cancel != nil {
					u.cancel()
				}
				sockets = append(sockets, u.upstream)
				delete(flow.udp, key)
				d.udps--
			}
			delete(d.flows, t.key)
		}
		stack := d.intercepts[interceptKey{tunnel: t}]
		if stack != nil {
			delete(d.intercepts, interceptKey{tunnel: t})
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
		if stack != nil {
			d.closeIntercept(stack)
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
// read from it, the tunnels dispatch their datagrams themselves, and a write goes back into
// the tunnel its address names.
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

func (c *tunnelPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ta, ok := addr.(*tunnelAddr)
	if !ok {
		return 0, errors.New("edge: write to an address no tunnel carries")
	}
	ta.tunnel.send(b)
	return len(b), nil
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
