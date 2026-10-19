// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
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
func (p *Proxy) serveConnectUDP(w http.ResponseWriter, r *http.Request, identity string, rq *request) {
	if r.ProtoMajor >= 2 {
		// The server ends the stream as this handler returns, so the cut waits for the return
		// before it ends the connection under the stream, I3.
		p.srv.serving.add()
		defer p.srv.serving.done()
	}
	target, err := targetFromConnectUDP(r)
	if err != nil {
		p.writeStatus(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if hasContentFields(r.Header, r.TransferEncoding) {
		// net/http drains the body of a request it keeps the connection of before answering,
		// and the body of a GET may never end.
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
	if r.ProtoMajor >= 2 {
		sess.carrier = front
	} else {
		// The socket rides what the connection that sent the upgrade rides, Handover.
		sess.carrier = front.carrier
	}
	sess.remoteAddr, sess.localAddr = front.remoteAddr, front.localAddr
	if state := front.tlsState.Load(); state != nil {
		sess.tlsState.Store(state)
	} else {
		sess.pendingTLS = front.pendingTLS
	}

	tun := newConnectUDPTunnel(d, sess, &contextFraming{target: target, upstream: upstream}, cancel)
	defer tun.noSender()
	sess.closer = tun
	if r.ProtoMajor >= 2 {
		// A tunnel on a stream ends through its closer, which the end of its connection runs,
		// I1, armed once the fields its end reads are set.
		defer sess.endWith(parentOf(r, front))()
	}
	if !d.publishTunnel(tun) {
		p.writeStatus(w, r, http.StatusServiceUnavailable, "the proxy is at capacity or shutting down")
		return
	}
	defer tun.close()

	// A refused registration means the proxy is stopping. Returning would let the server
	// answer 200 for a tunnel that is already gone, so the stream is reset instead.
	if !p.srv.trackRegistered(tun) {
		panic(http.ErrAbortHandler)
	}
	defer p.srv.untrack(tun)

	if err := p.srv.admitSession(sess, nil); err != nil {
		if errors.Is(err, errSessionEnded) {
			panic(http.ErrAbortHandler)
		}
		p.writeStatus(w, r, http.StatusForbidden, "the entries changed while the tunnel was admitted")
		return
	}
	defer p.srv.untrackSession(sess)
	p.srv.requests.release(rq)

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
		return context.WithCancel(context.WithoutCancel(r.Context()))
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
		// The close of the tunnel and the client leaving its request end the wait for the
		// SETTINGS.
		capsules := peerWithoutDatagrams(ctx, r.Context(), w)
		if c := tun.sess.end.first(); r.Context().Err() != nil && c != causeClosed && c != causeCut {
			// The client left, a failed end through the closer, I1. A tunnel that Session.Close
			// or the cut ended is accepted first, docs/lifecycle.md End forms.
			tun.noSender()
			_ = tun.sess.endBy(causePeerFailed, time.Now().Add(alertWriteTimeout))
			abortWith(w, r, http3.ErrCodeRequestCanceled, false)
			return nil
		}
		// A tunnel closed meanwhile is accepted all the same, and serve ends it with its normal
		// end.
		// HTTPStream writes the header, so the pipe exists only once the tunnel is accepted.
		w.Header().Set(http3.CapsuleProtocolHeader, "?1")
		w.WriteHeader(http.StatusOK)
		pipe := newDatagramPipe(streamer.HTTPStream(), capsules)
		tun.accept(pipe)
		pipe.run(func(failed bool) {
			if failed {
				tun.peerEnded(errTunnelEnded)
			} else {
				tun.peerEnded(io.EOF)
			}
		})
		return pipe
	case 2:
		stream := newH2Stream(w, r, tun.sess.localAddr, tun.sess.remoteAddr)
		pipe := newCapsulePipe(stream, bufio.NewReader(stream))
		tun.accept(pipe)
		w.Header().Set(http3.CapsuleProtocolHeader, "?1")
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		return pipe
	default:
		client, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			tun.noSender()
			_ = tun.sess.endAfter(causeRefused, time.Now().Add(alertWriteTimeout), func() {
				p.writeStatus(w, r, http.StatusInternalServerError, "cannot hijack the connection for CONNECT-UDP")
			})
			return nil
		}
		sessionFromRequest(r).handOver()
		// Anything the reader buffered past the request is already capsule data.
		pipe := newSocketCapsulePipe(client, brw.Reader)
		tun.accept(pipe)
		if err := writeConnectUDPUpgrade(brw); err != nil {
			// The client did not get its acceptance, a failed end of its socket, I1.
			tun.noSender()
			_ = tun.sess.endBy(causePeerFailed, time.Now().Add(alertWriteTimeout))
			pipe.fail()
			return nil
		}
		return pipe
	}
}

// peerWithoutDatagrams waits for the SETTINGS of the client until ctx or req ends, and reports
// whether it did not send SETTINGS_H3_DATAGRAM, true when they did not arrive.
func peerWithoutDatagrams(ctx, req context.Context, w http.ResponseWriter) bool {
	s, isSettingser := w.(http3.Settingser)
	if !isSettingser {
		return false
	}
	select {
	case <-s.ReceivedSettings():
		return !s.Settings().EnableDatagrams
	case <-ctx.Done():
		return true
	case <-req.Done():
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
	framing tunnelFraming
	d       *quicDemux
	sess    *Session
	pipe    atomic.Pointer[tunnelPipe]
	addr    *tunnelAddr
	cancel  context.CancelFunc
	sendCh  chan []byte
	done    chan struct{}
	sent    chan struct{}
	// answered is closed once the handler stored the pipe or gave up.
	answered chan struct{}
	// readEnd is closed once serve read its stream to an error, readErr.
	readEnd  chan struct{}
	readErr  error
	key      flowKey
	upstream netip.AddrPort
	// deadline is the deadline of the closer in nanoseconds since the epoch, zero before it ran,
	// and ending is set once the sender began the end of the pipe.
	deadline   atomic.Int64
	closeOnce  sync.Once
	sentOnce   sync.Once
	answerOnce sync.Once
	ending     atomic.Bool
	// closed refuses datagrams that reach the demultiplexer after the tunnel ended, so a
	// datagram in flight cannot recreate the flow the close removed.
	closed atomic.Bool
	// refusing refuses a new inner unit once the end of the tunnel began, I3, while the inner
	// units already placed still receive their packets until they ended.
	refusing atomic.Bool
	// failed is set when the tunnel ends with its failed end, which the sender gives its stream.
	failed atomic.Bool
}

func newConnectUDPTunnel(d *quicDemux, sess *Session, framing tunnelFraming, cancel context.CancelFunc) *connectUDPTunnel {
	t := &connectUDPTunnel{
		d:        d,
		sess:     sess,
		framing:  framing,
		cancel:   cancel,
		sendCh:   make(chan []byte, tunnelSendQueue),
		done:     make(chan struct{}),
		sent:     make(chan struct{}),
		answered: make(chan struct{}),
		readEnd:  make(chan struct{}),
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

// accept stores pipe once the tunnel is answered, so a closer that runs meanwhile waits for the
// end of the stream.
func (t *connectUDPTunnel) accept(pipe tunnelPipe) {
	t.pipe.Store(&pipe)
	t.answer()
}

// streamFailed reports whether the peer reset the stream of the tunnel or broke its framing, on
// HTTP/2 and HTTP/3, waiting until deadline for the read of the stream the end of its connection
// ends. A read still running at deadline gives the failed end, I4.
func (t *connectUDPTunnel) streamFailed(deadline time.Time) bool {
	// The end of the tunnel began, so the read drains the stream without opening an inner unit,
	// I3.
	t.refusing.Store(true)
	pipe := t.pipe.Load()
	if pipe == nil {
		return false
	}
	switch p := (*pipe).(type) {
	case *datagramPipe:
		return p.streamFailed(deadline)
	case *capsulePipe:
		if _, ok := p.conn.(*h2Stream); !ok {
			return false
		}
		// net/http hands the bytes buffered before a reset out ahead of it, so the reader of the
		// stream reads to its error first.
		if !waitUntil(t.readEnd, deadline) {
			return true
		}
		err := t.readErr
		return err != nil && !errors.Is(err, io.EOF) && !isTimeout(err) && !endedWithConn(err)
	}
	return false
}

// peerEnded runs the closer of the tunnel once err ended the read of its stream.
func (t *connectUDPTunnel) peerEnded(err error) {
	c := causePeer
	if !cleanEnd(err) {
		c = causePeerFailed
		if endedWithConn(err) {
			if carried, ok := t.sess.carrierEnd(); ok {
				// The stream ended with its connection, which gives its cause, I3.
				c = carried
			}
		}
	}
	_ = t.sess.endBy(c, time.Now().Add(alertWriteTimeout))
}

// noSender stands for the sender of a tunnel once the handler returns, which no closer then
// waits for.
func (t *connectUDPTunnel) noSender() {
	t.sentOnce.Do(func() { close(t.sent) })
	t.answer()
}

func (t *connectUDPTunnel) answer() { t.answerOnce.Do(func() { close(t.answered) }) }

// serve reads the datagrams off the pipe and places each, until the tunnel ends.
func (t *connectUDPTunnel) serve(ctx context.Context, pipe tunnelPipe) {
	t.pipe.Store(&pipe)
	go t.sender(pipe)

	for {
		b, err := pipe.recv(ctx)
		if err != nil {
			t.readErr = err
			close(t.readEnd)
			// A tunnel runs no handler, so a peer end of its stream runs its closer, I1.
			t.peerEnded(err)
			break
		}
		payload, upstream, ok := t.framing.unwrap(b)
		if !ok {
			continue
		}
		t.upstream = upstream
		t.d.dispatch(t.addr, payload, true)
	}
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
	defer t.sentOnce.Do(func() { close(t.sent) })
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
	// The end shares the deadline of a closer, so the closer does not reset a stream after
	// its normal end has begun.
	deadline := time.Now().Add(alertWriteTimeout)
	if n := t.deadline.Load(); n != 0 {
		deadline = time.Unix(0, n)
	}
	t.ending.Store(true)
	if t.failed.Load() {
		pipe.fail()
		return
	}
	_ = pipe.closeBy(deadline)
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

func (t *connectUDPTunnel) Close() error { return t.closeBy(time.Now().Add(alertWriteTimeout)) }

func (t *connectUDPTunnel) closeBy(deadline time.Time) error { return t.endBy(causeClosed, deadline) }

// endBy ends the tunnel with the forms c gives, returning once the stream ended. A stream still
// ending at deadline gets its failed end, I4.
func (t *connectUDPTunnel) endBy(c cause, deadline time.Time) error {
	t.deadline.CompareAndSwap(0, deadline.UnixNano())
	t.closeInner(c, deadline)
	t.closeWith(formOf(framed, c, false) == formFailed)
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	pipe := t.pipe.Load()
	if pipe == nil {
		// The handler is past the admission and stores its pipe or gives up at once.
		select {
		case <-t.answered:
		case <-timer.C:
		}
		if pipe = t.pipe.Load(); pipe == nil {
			return nil
		}
	}
	_ = (*pipe).setWriteDeadline(deadline)
	select {
	case <-t.sent:
	case <-timer.C:
		if t.ending.Load() {
			// The normal end has begun under the same deadline, which ends it now.
			<-t.sent
			return nil
		}
		(*pipe).fail()
	}
	return nil
}

// closeInner runs the closer of every session the tunnel carries, as the closer of any carrier
// does, I3.
func (t *connectUDPTunnel) closeInner(c cause, deadline time.Time) {
	d := t.d
	d.mu.Lock()
	// Refused from here on, no inner unit joins the ones closed below.
	t.refusing.Store(true)
	var sessions []*Session
	if flow := d.flows[t.key]; flow != nil {
		for _, conn := range flow.conns {
			if conn.sess != nil {
				sessions = append(sessions, conn.sess)
			}
		}
		for _, u := range flow.udp {
			if u.sess != nil {
				sessions = append(sessions, u.sess)
			}
		}
	}
	d.mu.Unlock()
	var wg sync.WaitGroup
	for _, sess := range sessions {
		wg.Go(func() { _ = sess.endBy(carriedCause(c), deadline) })
	}
	wg.Wait()
}

// close ends the tunnel. Every inner connection is closed with a CONNECTION_CLOSE sent
// through the tunnel, every datagram flow is closed, the stack is torn down, and the stream
// is ended once those closes are sent.
func (t *connectUDPTunnel) close() { t.closeWith(false) }

// closeWith is close. An inner connection with a request or a stream in flight gets its failed
// end, and so does every other one when failed reports a failed end of the tunnel's client leg.
func (t *connectUDPTunnel) closeWith(failed bool) {
	t.closeOnce.Do(func() {
		d := t.d
		d.mu.Lock()
		t.failed.Store(failed)
		t.refusing.Store(true)
		t.closed.Store(true)
		var inner []innerConn
		var sockets []net.Conn
		var pending []expiredConn
		if flow := d.flows[t.key]; flow != nil {
			for _, conn := range flow.conns {
				if conn.state.sniffing() {
					// A connection still being placed has no quic-go connection to refuse it.
					pending = append(pending, expiredConn{client: flow.client, conn: conn})
					conn.end()
				}
				ic := innerConn{qc: conn.qc, sess: conn.sess}
				if conn.sess != nil {
					if cl, ok := conn.sess.closer.(*quicConnCloser); ok {
						cl.ran.Store(true)
						ic.legs = cl.legs.Load()
					}
				}
				if ic.qc != nil || ic.legs != nil {
					inner = append(inner, ic)
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
		// before the stack goes and before the stream is ended behind it. The origin legs of
		// the connections the tunnel carries end with them.
		for _, ic := range inner {
			end := closeNoError
			if failed || ic.inFlight(d.p.srv.requests) {
				end = closeFailed
			}
			// The origin legs first, so a handler woken by the end of the client leg cannot
			// fail them.
			if ic.legs != nil {
				ic.legs.endLegs(failed || ic.inFlight(d.p.srv.requests), time.Now().Add(alertWriteTimeout))
			}
			if ic.qc != nil {
				_ = end(ic.qc)
			}
		}
		for _, r := range pending {
			// Pending, CONNECTION_REFUSED, docs/lifecycle.md End forms, queued before the end of
			// the stream as the CONNECTION_CLOSE of the others.
			d.sendRefusal(r.client, r.conn, quic.ConnectionRefused)
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

// innerConn is a QUIC connection a tunnel carries, as its tunnel ends it.
type innerConn struct {
	qc   *quic.Conn
	legs *QUICCtx
	sess *Session
}

func (ic innerConn) inFlight(requests *requestList) bool {
	return (ic.legs != nil && ic.legs.streams.Load() > 0) || (ic.sess != nil && requests.hasOf(ic.sess))
}

// publishTunnel places the tunnel's flow in the demultiplexer, inside the draining critical
// section, so a shutdown either refuses it or finds it.
func (d *quicDemux) publishTunnel(t *connectUDPTunnel) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	// A tunnel reaches here only when it arrived before the start of a drain.
	if d.closing.Load() {
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
