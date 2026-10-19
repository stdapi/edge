// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/stdapi/edge/internal/socks5"
)

func isSOCKS5(proxy *url.URL) bool {
	return proxy.Scheme == "socks5" || proxy.Scheme == "socks5h"
}

func socks5Addr(addr string) (socks5.Addr, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return socks5.Addr{}, err
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return socks5.Addr{}, fmt.Errorf("port %q is not a port", port)
	}
	a := socks5.Addr{Port: uint16(n)}
	if ip, perr := netip.ParseAddr(host); perr == nil {
		a.IP = ip.Unmap()
	} else {
		a.Name = host
	}
	return a, nil
}

func (u *upstreamDialer) socks5Open(ctx context.Context, proxy *url.URL, cmd byte, target socks5.Addr) (net.Conn, socks5.Addr, error) {
	conn, err := u.dialRaw(ctx, "tcp", proxyAddr(proxy))
	if err != nil {
		return nil, socks5.Addr{}, fmt.Errorf("%w %s: %w", errDialProxy, proxy.Redacted(), err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	bound, err := socks5Handshake(conn, proxy, cmd, target)
	if !stop() || err != nil {
		_ = conn.Close()
		if err == nil {
			err = ctx.Err()
		}
		return nil, socks5.Addr{}, err
	}
	return conn, bound, nil
}

func socks5Handshake(conn net.Conn, proxy *url.URL, cmd byte, target socks5.Addr) (socks5.Addr, error) {
	_ = conn.SetDeadline(time.Now().Add(proxyConnectTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	methods := []byte{socks5.MethodNoAuth}
	if proxy.User != nil {
		methods = append(methods, socks5.MethodPassword)
	}
	if err := socks5.WriteMethods(conn, methods...); err != nil {
		return socks5.Addr{}, err
	}
	method, err := socks5.ReadMethod(conn)
	if err != nil {
		return socks5.Addr{}, err
	}
	switch method {
	case socks5.MethodNoAuth:
	case socks5.MethodPassword:
		if proxy.User == nil {
			return socks5.Addr{}, errors.New("the proxy requires a username and a password")
		}
		pass, _ := proxy.User.Password()
		if err = socks5.WriteCredentials(conn, proxy.User.Username(), pass); err != nil {
			return socks5.Addr{}, err
		}
		if err = socks5.ReadCredentialsStatus(conn); err != nil {
			return socks5.Addr{}, err
		}
	default:
		return socks5.Addr{}, errors.New("the proxy accepts none of the authentication methods offered")
	}

	if err = socks5.WriteRequest(conn, cmd, target); err != nil {
		return socks5.Addr{}, err
	}
	_, bound, err := socks5.ReadReply(conn)
	return bound, err
}

func (u *upstreamDialer) connectSOCKS5(ctx context.Context, proxy *url.URL, addr string) (net.Conn, error) {
	target, err := socks5Addr(addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s through %s: %w", addr, proxy.Redacted(), err)
	}
	conn, _, err := u.socks5Open(ctx, proxy, socks5.CmdConnect, target)
	if err != nil {
		return nil, fmt.Errorf("dial %s through %s: %w", addr, proxy.Redacted(), err)
	}
	return conn, nil
}

func (u *upstreamDialer) associateSOCKS5(ctx context.Context, proxy *url.URL, addr string) (net.Conn, error) {
	conn, err := u.associate(ctx, proxy, addr)
	if err != nil {
		return nil, fmt.Errorf("dial udp %s through %s: %w", addr, proxy.Redacted(), err)
	}
	return conn, nil
}

func (u *upstreamDialer) associate(ctx context.Context, proxy *url.URL, addr string) (net.Conn, error) {
	dest, err := socks5Addr(addr)
	if err != nil {
		return nil, err
	}
	// The source is not known before the relay is, so none is declared.
	ctrl, bound, err := u.socks5Open(ctx, proxy, socks5.CmdAssociate, socks5.Addr{IP: netip.IPv4Unspecified()})
	if err != nil {
		return nil, err
	}
	// A relay bound on every address is reached at the address of the proxy.
	if bound.Name == "" && bound.IP.IsUnspecified() {
		bound.IP = addrPort(ctrl.RemoteAddr()).Addr()
	}
	sock, err := u.dialRaw(ctx, "udp", bound.String())
	if err != nil {
		_ = ctrl.Close()
		return nil, fmt.Errorf("dial the relay %s: %w", bound, err)
	}
	c := &socks5UDPConn{
		sock:   sock,
		ctrl:   ctrl,
		dest:   dest,
		hdr:    socks5.AppendDatagramHeader(nil, dest),
		remote: tunnelTarget(addr),
	}
	// RFC 1928 section 7 ends the association with the control connection.
	go func() {
		_, _ = io.Copy(io.Discard, ctrl)
		_ = c.Close()
	}()
	return c, nil
}

type socks5UDPConn struct {
	sock      net.Conn
	ctrl      net.Conn
	remote    tunnelTarget
	hdr       []byte
	dest      socks5.Addr
	closeOnce sync.Once
}

var socks5ReadPool = sync.Pool{New: func() any { return new([maxUDPPayload]byte) }}

func (c *socks5UDPConn) Read(b []byte) (int, error) {
	buf := socks5ReadPool.Get().(*[maxUDPPayload]byte)
	defer socks5ReadPool.Put(buf)
	for {
		n, err := c.sock.Read(buf[:])
		if err != nil {
			return 0, err
		}
		dg, perr := socks5.ParseDatagram(buf[:n])
		if perr != nil {
			continue
		}
		// A relay may forward from any origin. Only a datagram from the address dialed is
		// delivered, which a name leaves unverifiable.
		if c.dest.Name == "" && (dg.Name != nil || dg.IP.Unmap() != c.dest.IP || dg.Port != c.dest.Port) {
			continue
		}
		return copy(b, dg.Payload), nil
	}
}

func (c *socks5UDPConn) Write(b []byte) (int, error) {
	out := tunnelBuf(len(c.hdr) + len(b))
	copy(out, c.hdr)
	copy(out[len(c.hdr):], b)
	_, err := c.sock.Write(out)
	putTunnelBuf(out)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close returns at once, as the Close of a socket does. A closer ends the association with
// closeBy or Abort.
func (c *socks5UDPConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.sock.Close()
		_ = c.ctrl.Close()
	})
	return nil
}

// closeBy ends the association by deadline, its control connection with the normal end of TCP,
// docs/lifecycle.md End forms, Datagram flow.
func (c *socks5UDPConn) closeBy(deadline time.Time) error {
	c.closeOnce.Do(func() {
		_ = c.sock.Close()
		closeNormallyBy(c.ctrl, deadline)
	})
	return nil
}

// Abort ends the association at once, its control connection with the failed end of TCP.
func (c *socks5UDPConn) Abort() {
	c.closeOnce.Do(func() {
		_ = c.sock.Close()
		abort(c.ctrl)
	})
}

func (c *socks5UDPConn) LocalAddr() net.Addr                { return c.sock.LocalAddr() }
func (c *socks5UDPConn) RemoteAddr() net.Addr               { return c.remote }
func (c *socks5UDPConn) SetDeadline(t time.Time) error      { return c.sock.SetDeadline(t) }
func (c *socks5UDPConn) SetReadDeadline(t time.Time) error  { return c.sock.SetReadDeadline(t) }
func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error { return c.sock.SetWriteDeadline(t) }
