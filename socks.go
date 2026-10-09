// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fox-toolkit/edge/internal/simplelru"
	"github.com/fox-toolkit/edge/internal/socks5"
)

const (
	socks5NameCache     = 64
	socks5NameResolving = 8
	socks5NameRetry     = 5 * time.Second
	// socks5RefuseLinger stays well under the ten seconds RFC 1928 section 6 allows between a
	// failure reply and the close.
	socks5RefuseLinger = 2 * time.Second
)

// ListenAndServeSOCKS5 listens on addr and serves as a SOCKS5 proxy, RFC 1928. Clients point
// at it with their SOCKS setting. A CONNECT opens a connection to its target, terminated and
// routed as one opened by an HTTP CONNECT is. A client sending the hostname of the target has
// the connection routed on that hostname and dialed as it. A client sending an address it
// resolved itself has the connection routed on the server name or the Host header inside,
// which [WithNameVerification] checks against that address.
//
// A UDP ASSOCIATE opens a relay the client sends its datagrams to, each addressed to its own
// destination, a hostname or an address. Every datagram is routed on that destination as a
// redirected one is on the destination before the redirect, and the association is a
// [Session] of its own, ended with the connection that opened it. A fragmented datagram is
// dropped.
//
// The authenticator [WithProxyAuth] sets serves this front through the username/password
// method of RFC 1929, and must be a [PasswordAuthenticator]. Without one, no authentication
// is required. GSSAPI is not offered. BIND is answered "command not supported".
//
// ListenAndServeSOCKS5 always returns a non-nil error. After [Proxy.Shutdown] or [Proxy.Close]
// it returns [ErrProxyClosed].
func (p *Proxy) ListenAndServeSOCKS5(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	return p.ServeSOCKS5(ln)
}

// ServeSOCKS5 accepts connections on ln and serves them as a SOCKS5 proxy, see
// [Proxy.ListenAndServeSOCKS5]. It returns [ErrInvalidConfig] at once when the authenticator
// [WithProxyAuth] sets is not a [PasswordAuthenticator].
func (p *Proxy) ServeSOCKS5(ln net.Listener) error {
	if p.cfg.proxyAuth != nil {
		if _, ok := p.cfg.proxyAuth.(PasswordAuthenticator); !ok {
			return fmt.Errorf("%w: the proxy authenticator authenticates HTTP requests only, a SOCKS5 client presents a username and a password", ErrInvalidConfig)
		}
	}
	return p.acceptEach(ln, p.serveSOCKS5, "SOCKS5 connection closed")
}

// The codec reads exactly the bytes of each message, so nothing the client sends after the
// reply is consumed before the connection is handed on.
func (p *Proxy) serveSOCKS5(conn net.Conn) error {
	if !p.srv.tryTrack(conn) {
		_ = conn.Close()
		return ErrProxyClosed
	}
	defer func() {
		_ = conn.Close()
		p.srv.untrack(conn)
	}()

	ctx, cancel := context.WithCancel(p.srv.ctx)
	defer cancel()

	if d := p.cfg.server.readHeaderTimeout; d > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(d))
	}
	identity, err := p.negotiateSOCKS5(conn)
	if err != nil {
		return err
	}
	bound := socks5Bound(conn.LocalAddr())
	cmd, addr, err := socks5.ReadRequest(conn)
	if err != nil {
		switch {
		case errors.Is(err, socks5.ErrAddressType):
			refuseSOCKS5(conn, socks5.AddressTypeNotSupported, bound)
		case errors.Is(err, socks5.ErrNameLength):
			refuseSOCKS5(conn, socks5.GeneralFailure, bound)
		}
		return err
	}
	_ = conn.SetReadDeadline(time.Time{})

	switch cmd {
	case socks5.CmdConnect:
	case socks5.CmdAssociate:
		return p.serveSOCKS5Associate(ctx, conn, addr, identity)
	default:
		_ = socks5.WriteReply(conn, socks5.CommandNotSupported, bound)
		return fmt.Errorf("SOCKS5 command %d is not served", cmd)
	}
	target, err := targetFromSOCKS5(addr)
	if err != nil {
		_ = socks5.WriteReply(conn, socks5.GeneralFailure, bound)
		return err
	}
	if !p.admitsAny(target, KindHTTP, KindTCP) {
		_ = socks5.WriteReply(conn, socks5.NotAllowed, bound)
		return errors.New("no entry admits this authority")
	}

	sess := newSession(p, ctx, conn, target, 0, 0)
	sess.identity = identity
	sess.setDestination(target)

	// The client sends its ClientHello only once it has the reply, so the reply comes before
	// termination, as the 200 of a CONNECT does.
	if err := socks5.WriteReply(conn, socks5.Succeeded, bound); err != nil {
		return err
	}
	if err := p.terminate(ctx, newPeekConn(conn, nil, clientHelloPeekSize), sess); err != nil {
		p.logf(ctx, slog.LevelDebug, "connection closed", sess, err)
	}
	return nil
}

// refuseSOCKS5 answers a request it could not read to its end. A close with unread data
// sends a reset, which can destroy the reply before the client reads it.
func refuseSOCKS5(conn net.Conn, rep socks5.Reply, bound socks5.Addr) {
	if socks5.WriteReply(conn, rep, bound) != nil {
		return
	}
	_ = closeWrite(conn)
	_ = conn.SetReadDeadline(time.Now().Add(socks5RefuseLinger))
	_, _ = io.Copy(io.Discard, conn)
}

// One method is offered, username/password when an authenticator is configured and none
// otherwise.
func (p *Proxy) negotiateSOCKS5(rw io.ReadWriter) (string, error) {
	methods, err := socks5.ReadMethods(rw)
	if err != nil {
		return "", err
	}
	auth, _ := p.cfg.proxyAuth.(PasswordAuthenticator)
	want := byte(socks5.MethodNoAuth)
	if p.cfg.proxyAuth != nil {
		want = socks5.MethodPassword
	}
	if !slices.Contains(methods, want) || (want == socks5.MethodPassword && auth == nil) {
		_ = socks5.WriteMethod(rw, socks5.MethodNoAcceptable)
		return "", errors.New("the client offers no acceptable authentication method")
	}
	if werr := socks5.WriteMethod(rw, want); werr != nil {
		return "", werr
	}
	if auth == nil {
		return "", nil
	}

	username, password, err := socks5.ReadCredentials(rw)
	if err != nil {
		return "", err
	}
	identity, ok := auth.AuthenticatePassword(username, password)
	if err := socks5.WriteCredentialsStatus(rw, ok); err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("proxy authentication failed")
	}
	return identity, nil
}

// The proxy binds nothing on the client's behalf before it answers, so the BND address is
// the unspecified one of the family the client reached the proxy on.
func socks5Bound(local net.Addr) socks5.Addr {
	if ap := addrPort(local); ap.IsValid() && ap.Addr().Is6() {
		return socks5.Addr{IP: netip.IPv6Unspecified()}
	}
	return socks5.Addr{IP: netip.IPv4Unspecified()}
}

func targetFromSOCKS5(addr socks5.Addr) (Target, error) {
	host := addr.Name
	if host == "" {
		host = addr.IP.Unmap().String()
	}
	return targetFromWire(host, strconv.Itoa(int(addr.Port)))
}

// serveSOCKS5Associate feeds the relay of one association to the demultiplexer as a tunnel
// that declares no destination.
func (p *Proxy) serveSOCKS5Associate(ctx context.Context, conn net.Conn, from socks5.Addr, identity string) error {
	bound := socks5Bound(conn.LocalAddr())
	d, err := p.srv.tunnelDemux()
	if err != nil {
		_ = socks5.WriteReply(conn, socks5.GeneralFailure, bound)
		return err
	}
	local := addrPort(conn.LocalAddr())
	relay, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local.Addr(), 0)))
	if err != nil {
		_ = socks5.WriteReply(conn, socks5.GeneralFailure, bound)
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sess := newSession(p, ctx, conn, Target{}, 0, 0)
	sess.identity = identity
	sess.tunnel = true

	assoc := newSOCKSAssociation(ctx, p, relay, from, addrPort(conn.RemoteAddr()).Addr())
	tun := newConnectUDPTunnel(d, sess, assoc, cancel)
	sess.closer = tun
	if !d.publishTunnel(tun) {
		_ = relay.Close()
		_ = socks5.WriteReply(conn, socks5.GeneralFailure, bound)
		return errors.New("the proxy is at capacity or shutting down")
	}
	defer tun.close()
	if !p.srv.tryTrack(tun) {
		_ = relay.Close()
		return ErrProxyClosed
	}
	defer p.srv.untrack(tun)
	if !p.srv.admitSession(sess) {
		_ = relay.Close()
		return errors.New("the entries changed while the association was admitted")
	}
	defer p.srv.trackSession(sess, false)

	relayAddr := addrPort(relay.LocalAddr())
	if err := socks5.WriteReply(conn, socks5.Succeeded, socks5.Addr{IP: relayAddr.Addr(), Port: relayAddr.Port()}); err != nil {
		_ = relay.Close()
		return err
	}
	// RFC 1928 section 7 ends the association with the connection, so it is read until
	// the client closes it.
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		cancel()
	}()
	tun.serve(ctx, assoc)
	assoc.wg.Wait()
	return nil
}

type socksName struct {
	retry time.Time
	addr  netip.Addr
	host  string
}

// socksResolution is one name being resolved and the datagrams waiting on it.
type socksResolution struct {
	name    string
	host    string
	entry   socksName
	pending [][]byte
	bytes   int
}

func (r *socksResolution) hold(b []byte) {
	if len(r.pending) >= maxPendingDatagrams || r.bytes+len(b) > maxPendingBytes {
		return
	}
	r.pending = append(r.pending, b)
	r.bytes += len(b)
}

// socksAssociation is one UDP association, the relay socket as the pipe of a tunnel and the
// framing of RFC 1928 section 7, a destination ahead of every payload. A name is resolved off
// the goroutine feeding the tunnel, and the resolver wakes recv with a read deadline in the
// past, so the relay's read deadline is its alone.
type socksAssociation struct {
	ip        netip.Addr
	ctx       context.Context
	conn      *net.UDPConn
	p         *Proxy
	names     *simplelru.LRU[string, socksName]
	resolving map[string]*socksResolution
	bound     atomic.Pointer[netip.AddrPort]
	expect    netip.AddrPort
	host      string
	queued    [][]byte
	ready     []*socksResolution
	wg        sync.WaitGroup
	mu        sync.Mutex
	port      uint16
}

// The datagrams must come from the address of the control connection, whatever the client
// declared, on the port it declared when it declared one.
func newSOCKSAssociation(ctx context.Context, p *Proxy, conn *net.UDPConn, from socks5.Addr, client netip.Addr) *socksAssociation {
	a := &socksAssociation{
		conn:      conn,
		ctx:       ctx,
		p:         p,
		resolving: make(map[string]*socksResolution),
		expect:    netip.AddrPortFrom(client, from.Port),
	}
	a.names, _ = simplelru.NewLRU[string, socksName](socks5NameCache, nil)
	return a
}

func (a *socksAssociation) unwrap(b []byte) ([]byte, netip.AddrPort, bool) {
	dg, err := socks5.ParseDatagram(b)
	if err != nil || dg.Port == 0 {
		return nil, netip.AddrPort{}, false
	}
	a.port = dg.Port
	if dg.Name == nil {
		a.host, a.ip = "", dg.IP.Unmap()
		return dg.Payload, netip.AddrPortFrom(a.ip, dg.Port), true
	}
	if r := a.resolving[string(dg.Name)]; r != nil {
		r.hold(b)
		return nil, netip.AddrPort{}, false
	}
	name := string(dg.Name)
	entry, ok := a.names.Get(name)
	if !ok || (!entry.addr.IsValid() && time.Now().After(entry.retry)) {
		if entry, ok = a.resolve(name, b); !ok {
			return nil, netip.AddrPort{}, false
		}
	}
	if !entry.addr.IsValid() {
		return nil, netip.AddrPort{}, false
	}
	a.host, a.ip = entry.host, netip.Addr{}
	return dg.Payload, netip.AddrPortFrom(entry.addr, dg.Port), true
}

// resolve returns the entry of a name decided without a lookup. Otherwise it queues b, starts
// the lookup off the feeding goroutine and returns false.
func (a *socksAssociation) resolve(name string, b []byte) (socksName, bool) {
	entry := socksName{host: name, retry: time.Now().Add(socks5NameRetry)}
	target, err := targetFromWire(name, "1")
	if err != nil {
		a.names.Add(name, entry)
		return entry, true
	}
	entry.host = target.Host
	if ip, perr := netip.ParseAddr(target.Host); perr == nil {
		entry.addr = ip.Unmap()
		a.names.Add(name, entry)
		return entry, true
	}
	if len(a.resolving) >= socks5NameResolving {
		return socksName{}, false
	}
	r := &socksResolution{name: name, host: target.Host}
	r.hold(b)
	a.resolving[name] = r
	a.wg.Go(func() {
		r.entry = socksName{host: r.host, addr: a.lookup(r.host), retry: time.Now().Add(socks5NameRetry)}
		a.mu.Lock()
		a.ready = append(a.ready, r)
		a.mu.Unlock()
		_ = a.conn.SetReadDeadline(time.Now())
	})
	return socksName{}, false
}

func (a *socksAssociation) lookup(host string) netip.Addr {
	rctx, cancel := context.WithTimeout(a.ctx, nameVerifyTimeout)
	defer cancel()
	addrs, err := a.p.cfg.resolver.LookupNetIP(rctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return netip.Addr{}
	}
	return addrs[0].Unmap()
}

func (a *socksAssociation) drainReady() {
	a.mu.Lock()
	ready := a.ready
	a.ready = nil
	a.mu.Unlock()
	for _, r := range ready {
		delete(a.resolving, r.name)
		a.names.Add(r.name, r.entry)
		if r.entry.addr.IsValid() {
			a.queued = append(a.queued, r.pending...)
		}
	}
}

func (a *socksAssociation) declaredName() string { return a.host }

func (a *socksAssociation) declared() Target {
	port := strconv.Itoa(int(a.port))
	host := a.host
	if host == "" {
		host = a.ip.String()
	}
	return Target{Scheme: schemeForPort(port), Host: host, Port: port}
}

func (*socksAssociation) wrap(origin netip.AddrPort, b []byte) []byte {
	from := socks5.Addr{IP: origin.Addr(), Port: origin.Port()}
	n := socks5.DatagramHeaderLen(from)
	out := tunnelBuf(capsuleHeadroom + n + len(b))
	socks5.AppendDatagramHeader(out[capsuleHeadroom:capsuleHeadroom], from)
	copy(out[capsuleHeadroom+n:], b)
	return out
}

// accepts binds the association to the first source it accepts, and replies go there.
func (a *socksAssociation) accepts(from netip.AddrPort) bool {
	if bound := a.bound.Load(); bound != nil {
		return from == *bound
	}
	if from.Addr() != a.expect.Addr() || (a.expect.Port() != 0 && from.Port() != a.expect.Port()) {
		return false
	}
	a.bound.Store(&from)
	return true
}

// A resolver queues its result before it sets the deadline, and recv clears the deadline
// before it drains the queue, so a wake is never lost.
func (a *socksAssociation) recv(context.Context) ([]byte, error) {
	buf := socks5ReadPool.Get().(*[maxUDPPayload]byte)
	defer socks5ReadPool.Put(buf)
	for {
		if len(a.queued) == 0 {
			a.drainReady()
		}
		if len(a.queued) > 0 {
			b := a.queued[0]
			a.queued[0] = nil
			a.queued = a.queued[1:]
			return b, nil
		}
		n, from, err := a.conn.ReadFromUDPAddrPort(buf[:])
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				_ = a.conn.SetReadDeadline(time.Time{})
				continue
			}
			return nil, err
		}
		if !a.accepts(netip.AddrPortFrom(from.Addr().Unmap(), from.Port())) {
			continue
		}
		return slices.Clone(buf[:n]), nil
	}
}

func (a *socksAssociation) send(b []byte) error {
	bound := a.bound.Load()
	if bound == nil {
		return errors.New("no datagram received yet")
	}
	_, err := a.conn.WriteToUDPAddrPort(b[capsuleHeadroom:], *bound)
	return err
}

func (a *socksAssociation) setReadDeadline(t time.Time) error  { return a.conn.SetReadDeadline(t) }
func (a *socksAssociation) setWriteDeadline(t time.Time) error { return a.conn.SetWriteDeadline(t) }
func (a *socksAssociation) close() error                       { return a.conn.Close() }
