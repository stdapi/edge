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
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/fox-toolkit/edge/internal/simplelru"
	"github.com/fox-toolkit/edge/internal/socks5"
)

const (
	socks5NameCache = 64
	socks5NameRetry = 5 * time.Second
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
	cmd, addr, err := socks5.ReadRequest(conn)
	if err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Time{})

	bound := socks5Bound(conn.LocalAddr())
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

	framing := &socksFraming{p: p, ctx: ctx}
	framing.names, _ = simplelru.NewLRU[string, socksName](socks5NameCache, nil)
	tun := newConnectUDPTunnel(d, sess, framing, cancel)
	sess.closer = tun
	pipe := newSOCKS5Pipe(relay, from, addrPort(conn.RemoteAddr()).Addr())
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
	tun.serve(ctx, pipe)
	return nil
}

type socksName struct {
	retry time.Time
	addr  netip.Addr
	host  string
}

// socksFraming is the framing of RFC 1928 section 7, a destination ahead of every payload. A
// name is resolved once per association, on the goroutine feeding it.
type socksFraming struct {
	ip    netip.Addr
	ctx   context.Context
	p     *Proxy
	names *simplelru.LRU[string, socksName]
	host  string
	port  uint16
}

func (f *socksFraming) unwrap(b []byte) ([]byte, netip.AddrPort, bool) {
	dg, err := socks5.ParseDatagram(b)
	if err != nil || dg.Port == 0 {
		return nil, netip.AddrPort{}, false
	}
	f.port = dg.Port
	if dg.Name == nil {
		f.host, f.ip = "", dg.IP.Unmap()
		return dg.Payload, netip.AddrPortFrom(f.ip, dg.Port), true
	}
	name := string(dg.Name)
	entry, ok := f.names.Get(name)
	if !ok || (!entry.addr.IsValid() && time.Now().After(entry.retry)) {
		entry = f.resolve(name)
		f.names.Add(name, entry)
	}
	if !entry.addr.IsValid() {
		return nil, netip.AddrPort{}, false
	}
	f.host, f.ip = entry.host, netip.Addr{}
	return dg.Payload, netip.AddrPortFrom(entry.addr, dg.Port), true
}

func (f *socksFraming) resolve(name string) socksName {
	entry := socksName{host: name, retry: time.Now().Add(socks5NameRetry)}
	target, err := targetFromWire(name, "1")
	if err != nil {
		return entry
	}
	entry.host = target.Host
	if ip, perr := netip.ParseAddr(target.Host); perr == nil {
		entry.addr = ip.Unmap()
		return entry
	}
	rctx, cancel := context.WithTimeout(f.ctx, nameVerifyTimeout)
	defer cancel()
	addrs, err := f.p.cfg.resolver.LookupNetIP(rctx, "ip", target.Host)
	if err != nil || len(addrs) == 0 {
		return entry
	}
	entry.addr = addrs[0].Unmap()
	return entry
}

func (f *socksFraming) declaredName() string { return f.host }

func (f *socksFraming) declared() Target {
	port := strconv.Itoa(int(f.port))
	host := f.host
	if host == "" {
		host = f.ip.String()
	}
	return Target{Scheme: schemeForPort(port), Host: host, Port: port}
}

func (*socksFraming) wrap(origin netip.AddrPort, b []byte) []byte {
	from := socks5.Addr{IP: origin.Addr(), Port: origin.Port()}
	n := socks5.DatagramHeaderLen(from)
	out := tunnelBuf(capsuleHeadroom + n + len(b))
	socks5.AppendDatagramHeader(out[capsuleHeadroom:capsuleHeadroom], from)
	copy(out[capsuleHeadroom+n:], b)
	return out
}

// socks5Pipe binds to the first source it accepts, and replies go there.
type socks5Pipe struct {
	conn   *net.UDPConn
	bound  atomic.Pointer[netip.AddrPort]
	expect netip.AddrPort
}

// The datagrams must come from the address of the control connection, whatever the client
// declared, on the port it declared when it declared one.
func newSOCKS5Pipe(conn *net.UDPConn, from socks5.Addr, client netip.Addr) *socks5Pipe {
	return &socks5Pipe{conn: conn, expect: netip.AddrPortFrom(client, from.Port)}
}

func (p *socks5Pipe) accepts(from netip.AddrPort) bool {
	if bound := p.bound.Load(); bound != nil {
		return from == *bound
	}
	if from.Addr() != p.expect.Addr() || (p.expect.Port() != 0 && from.Port() != p.expect.Port()) {
		return false
	}
	p.bound.Store(&from)
	return true
}

func (p *socks5Pipe) recv(context.Context) ([]byte, error) {
	buf := socks5ReadPool.Get().(*[maxUDPPayload]byte)
	defer socks5ReadPool.Put(buf)
	for {
		n, from, err := p.conn.ReadFromUDPAddrPort(buf[:])
		if err != nil {
			return nil, err
		}
		if !p.accepts(netip.AddrPortFrom(from.Addr().Unmap(), from.Port())) {
			continue
		}
		return slices.Clone(buf[:n]), nil
	}
}

func (p *socks5Pipe) send(b []byte) error {
	bound := p.bound.Load()
	if bound == nil {
		return errors.New("no datagram received yet")
	}
	_, err := p.conn.WriteToUDPAddrPort(b[capsuleHeadroom:], *bound)
	return err
}

func (p *socks5Pipe) setReadDeadline(t time.Time) error  { return p.conn.SetReadDeadline(t) }
func (p *socks5Pipe) setWriteDeadline(t time.Time) error { return p.conn.SetWriteDeadline(t) }
func (p *socks5Pipe) close() error                       { return p.conn.Close() }
