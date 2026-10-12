// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stdapi/edge/internal/h2tunnel"
	"golang.org/x/net/http/httpguts"
)

const (
	// proxyConnectTimeout bounds the CONNECT and CONNECT-UDP exchange with a proxy.
	proxyConnectTimeout = time.Minute
	// proxyResponseBytes bounds the response head a proxy may answer a CONNECT with.
	proxyResponseBytes = http.DefaultMaxHeaderBytes
	// proxyKeepAlive keeps the connection to a proxy open while its tunnels are silent.
	proxyKeepAlive = 10 * time.Second
	// maxInformational bounds the 1xx answers a proxy may send ahead of its final answer.
	maxInformational = 5
	// proxyRetry is how long the dialer remembers a fact of a proxy, a failed dial or a
	// version that does not serve a CONNECT.
	proxyRetry = 5 * time.Minute
)

var (
	errTunnelEnded = errors.New("edge: tunnel ended")
	errOpenStream  = errors.New("open stream")
	errDialProxy   = errors.New("dial proxy")
	// errDialWaited is returned by overTCP after waiting for a dial of the proxy in flight.
	// The caller should retry.
	errDialWaited = errors.New("dial in flight")
	// errMalformedAnswer is a CONNECT-UDP answer RFC 9297 section 3.2 treats as malformed, a
	// 204, 205 or 206 or a success with a content field.
	errMalformedAnswer = errors.New("malformed answer")
	// errFromItself ends a connection the proxy opened upstream to one of its own fronts.
	errFromItself = errors.New("edge: connection opened by the proxy itself")
)

// refusal is the status a proxy answered a CONNECT or a CONNECT-UDP with.
type refusal struct {
	status string
	code   int
}

func newRefusal(code int) *refusal {
	return &refusal{code: code, status: strconv.Itoa(code) + " " + http.StatusText(code)}
}

func (r *refusal) Error() string { return "refused with " + r.status }

func isRefusal(err error) bool {
	_, ok := errors.AsType[*refusal](err)
	return ok
}

// notServed reports whether the proxy answered that it does not serve the method, which
// another version of the proxy may.
func notServed(err error) bool {
	r, ok := errors.AsType[*refusal](err)
	return ok && (r.code == http.StatusMethodNotAllowed || r.code == http.StatusNotImplemented)
}

// proxyFact is what the dialer remembers of a proxy for proxyRetry.
type proxyFact string

const (
	noH3Dial     proxyFact = "no dial over HTTP/3"
	noTCPDial    proxyFact = "no dial over TCP"
	noH2         proxyFact = "no h2 in ALPN"
	noH2Extended proxyFact = "no extended CONNECT over HTTP/2"
	noH2Connect  proxyFact = "no CONNECT over HTTP/2"
	noH3Connect  proxyFact = "no CONNECT over HTTP/3"
)

// upstreamDialer opens every connection the proxy makes upstream, through the proxy
// [Transport.Proxy] selects when it selects one.
type upstreamDialer struct {
	t       *Transport
	h3      *http3.Transport
	conns   map[string]*h3ProxyConn
	h2conns map[string]*h2tunnel.Conn
	// remembered is when each proxyFact of a proxy expires.
	remembered map[string]time.Time
	h3Dialing  map[string]*dialCall
	tcpDialing map[string]chan struct{}
	own        *ownSockets
	// draining holds the HTTP/2 connections replaced after a GOAWAY while their last tunnels
	// end, so that close reaches them.
	draining []*h2tunnel.Conn
	mu       sync.Mutex
	// closed refuses a proxy connection opened after close, so none outlives the forwarder.
	closed bool
}

func newUpstreamDialer(t *Transport) *upstreamDialer {
	return &upstreamDialer{
		t:          t,
		h3:         &http3.Transport{EnableDatagrams: true, DisableCompression: true},
		conns:      make(map[string]*h3ProxyConn),
		h2conns:    make(map[string]*h2tunnel.Conn),
		remembered: make(map[string]time.Time),
		h3Dialing:  make(map[string]*dialCall),
		tcpDialing: make(map[string]chan struct{}),
		own:        newOwnSockets(),
	}
}

// dialRaw dials with [Transport.DialContext] and records the socket it returns until it is
// closed. Every connection the proxy opens upstream starts here.
func (u *upstreamDialer) dialRaw(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := u.t.dialer()(ctx, network, addr)
	if err != nil || c == nil {
		return c, err
	}
	return u.own.track(network, c), nil
}

func (u *upstreamDialer) close() {
	u.mu.Lock()
	u.closed = true
	conns, h2conns, draining := u.conns, u.h2conns, u.draining
	u.conns, u.h2conns, u.draining = nil, nil, nil
	u.mu.Unlock()
	for _, cc := range conns {
		_ = cc.CloseWithError(0, "")
	}
	for _, cc := range h2conns {
		_ = cc.Close()
	}
	for _, cc := range draining {
		_ = cc.Close()
	}
	_ = u.h3.Close()
}

// selectProxy returns the proxy [Transport.Proxy] selects for req, nil for a direct
// connection.
func (u *upstreamDialer) selectProxy(req *http.Request) (*url.URL, error) {
	if u.t.Proxy == nil {
		return nil, nil
	}
	proxy, err := u.t.Proxy(req)
	if err != nil {
		return nil, fmt.Errorf("edge: select a proxy for %s: %w", req.URL.Host, err)
	}
	if proxy != nil {
		switch proxy.Scheme {
		case "http", "https":
			if err := checkBasicCredentials(proxy.User); err != nil {
				return nil, fmt.Errorf("edge: dial %s through %s: %w", req.URL.Host, proxy.Redacted(), err)
			}
		case "socks5", "socks5h":
		default:
			return nil, fmt.Errorf("edge: dial %s through %s: proxy scheme %q is not supported", req.URL.Host, proxy.Redacted(), proxy.Scheme)
		}
	}
	return proxy, nil
}

// checkBasicCredentials reports why user cannot be sent as Basic credentials, RFC 7617 section 2.
func checkBasicCredentials(user *url.Userinfo) error {
	if user == nil {
		return nil
	}
	name := user.Username()
	pass, _ := user.Password()
	if strings.IndexByte(name, ':') >= 0 {
		return errors.New("a user-id with a colon cannot be sent in Basic credentials")
	}
	for _, s := range [...]string{name, pass} {
		for i := range len(s) {
			if isASCIIControl(s[i]) {
				return errors.New("a user-id or password with a control character cannot be sent in Basic credentials")
			}
		}
	}
	return nil
}

// proxyFor is selectProxy with a request for the destination alone. scheme is https for TLS
// and QUIC and http for plaintext.
func (u *upstreamDialer) proxyFor(addr, scheme string) (*url.URL, error) {
	if u.t.Proxy == nil {
		return nil, nil
	}
	return u.selectProxy(&http.Request{URL: &url.URL{Scheme: scheme, Host: addr}, Host: addr, Header: make(http.Header)})
}

// dial opens a connection to addr on network, through the proxy selected for it when there
// is one.
func (u *upstreamDialer) dial(ctx context.Context, network, addr, scheme string) (net.Conn, error) {
	proxy, err := u.proxyFor(addr, scheme)
	if err != nil {
		return nil, err
	}
	return u.dialThrough(ctx, network, addr, proxy)
}

// dialThrough opens a connection to addr on network, through proxy when it is not nil.
func (u *upstreamDialer) dialThrough(ctx context.Context, network, addr string, proxy *url.URL) (net.Conn, error) {
	if proxy == nil {
		return u.dialRaw(ctx, network, addr)
	}
	socks := isSOCKS5(proxy)
	switch {
	case network == "tcp" && socks:
		return u.connectSOCKS5(ctx, proxy, addr)
	case network == "tcp":
		return u.connect(ctx, proxy, addr)
	case network == "udp" && socks:
		return u.associateSOCKS5(ctx, proxy, addr)
	case network == "udp":
		return u.connectUDP(ctx, proxy, addr)
	}
	return nil, fmt.Errorf("edge: dial %s %s through %s: network not supported", network, addr, proxy.Redacted())
}

// dialQUIC opens a QUIC connection to addr on a socket dial returns. The socket is closed when
// the connection ends.
func (u *upstreamDialer) dialQUIC(ctx context.Context, addr string, tlsCfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
	sock, err := u.dial(ctx, "udp", addr, "https")
	if err != nil {
		return nil, err
	}
	return quicOn(ctx, sock, addr, tlsCfg, qcfg)
}

// quicOn opens a QUIC connection on a connected socket and ties the socket to it.
func quicOn(ctx context.Context, sock net.Conn, addr string, tlsCfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
	if sock.RemoteAddr() == nil {
		_ = sock.Close()
		return nil, fmt.Errorf("edge: dial %s: the dialer returned a socket with no peer", addr)
	}
	switch sock.(type) {
	case *connectUDPConn, *socks5UDPConn:
		// Each packet goes inside one QUIC datagram of the proxy connection, or behind a
		// SOCKS5 header, so the packets stay at the size every path accepts.
		qcfg = qcfg.Clone()
		qcfg.InitialPacketSize = 1200
		qcfg.DisablePathMTUDiscovery = true
	}
	tr := &quic.Transport{Conn: packetConnOf(sock)}
	// The socket goes first, so the read loop the transport waits on ends whatever the socket
	// does with a read deadline.
	release := func() {
		_ = sock.Close()
		_ = tr.Close()
	}
	conn, err := tr.Dial(ctx, sock.RemoteAddr(), tlsCfg, qcfg)
	if err != nil {
		release()
		return nil, err
	}
	context.AfterFunc(conn.Context(), release)
	return conn, nil
}

// proxyAddr returns the host:port a proxy URL is reached at.
func proxyAddr(proxy *url.URL) string {
	if proxy.Port() != "" {
		return proxy.Host
	}
	if isSOCKS5(proxy) {
		return joinHostPort(proxy.Hostname(), "1080")
	}
	return joinHostPort(proxy.Hostname(), defaultPort(proxy.Scheme))
}

// proxyAuthorization returns the Proxy-Authorization value the credentials of a proxy URL
// make, or an empty string without credentials.
func proxyAuthorization(proxy *url.URL) string {
	if proxy.User == nil {
		return ""
	}
	pass, _ := proxy.User.Password()
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(proxy.User.Username()+":"+pass))
}

// connect opens a TCP connection to addr with a CONNECT to the proxy. The CONNECT goes on
// the connection the dialer has to the proxy, HTTP/3 or HTTP/2, and over TCP otherwise, where
// TLS negotiates HTTP/2 or HTTP/1.1, and a proxy whose dial over TCP timed out is dialed over
// HTTP/3 first for proxyRetry. A CONNECT answered with 405 or 501 goes over the next version,
// any other refusal is final.
func (u *upstreamDialer) connect(ctx context.Context, proxy *url.URL, addr string) (net.Conn, error) {
	var waited, own bool
	for round := 1; ; round++ {
		conn, again, err := u.connectOnce(ctx, proxy, addr, tcpDial{wait: !waited, own: own})
		waited = waited || errors.Is(err, errDialWaited)
		own = own || errors.Is(err, h2tunnel.ErrStreamLimit)
		if again && round < connectRounds && ctx.Err() == nil {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("dial %s through %s: %w", addr, proxy.Redacted(), err)
		}
		return conn, nil
	}
}

// connectRounds bounds the rounds of one connect, one to wait for a dial in flight and one
// per connection or version a tunnel may move to after a failure.
const connectRounds = 5

// tcpDial is how a proxy is dialed over TCP. h2 offers h2 in ALPN, wait lets the dial wait
// for one in flight, and own keeps an HTTP/2 connection for this tunnel alone.
type tcpDial struct {
	h2, wait, own bool
}

// connectOnce reports whether the tunnel may go on another connection or version after a
// failure.
func (u *upstreamDialer) connectOnce(ctx context.Context, proxy *url.URL, addr string, d tcpDial) (net.Conn, bool, error) {
	https := proxy.Scheme == "https"
	if https {
		if cc := u.h3Conn(proxy); cc != nil && !u.remembers(noH3Connect, proxy) {
			conn, err := connectOnH3(ctx, cc, proxy, addr)
			if err != nil {
				return nil, u.h3Failed(proxy, cc, err), err
			}
			return conn, false, nil
		}
		if cc := u.h2Conn(proxy); cc != nil && !d.own && !u.remembers(noH2Connect, proxy) {
			conn, err := connectOnH2(ctx, cc, proxy, addr)
			if err != nil {
				return nil, u.h2Failed(proxy, cc, err, true), err
			}
			return conn, false, nil
		}
	}
	var h3err error
	if https && u.remembers(noTCPDial, proxy) && u.h3ForConnect(proxy) {
		conn, dialed, again, err := u.connectH3(ctx, proxy, addr)
		if dialed || ctx.Err() != nil {
			return conn, again, err
		}
		h3err = err
	}
	var cc *h2tunnel.Conn
	d.h2 = !u.remembers(noH2Connect, proxy)
	conn, shared, err := overTCP(ctx, u, proxy, d,
		func(conn net.Conn) (net.Conn, error) { return connectOn(conn, proxy, addr) },
		func(c *h2tunnel.Conn) (net.Conn, error) {
			cc = c
			return connectOnH2(ctx, c, proxy, addr)
		})
	switch {
	case err == nil:
		return conn, false, nil
	case errors.Is(err, errDialWaited):
		return nil, true, err
	case errors.Is(err, errDialProxy):
		if https && h3err == nil && ctx.Err() == nil && u.h3ForConnect(proxy) {
			// A refusal costs the next dial nothing, a dropped SYN costs it the dial timeout.
			if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
				u.remember(noTCPDial, proxy)
			}
			conn, dialed, again, oerr := u.connectH3(ctx, proxy, addr)
			if dialed {
				return conn, again, oerr
			}
			return nil, false, errors.Join(err, oerr)
		}
		if h3err != nil {
			err = errors.Join(h3err, err)
		}
		return nil, false, err
	case cc != nil:
		return nil, u.h2Failed(proxy, cc, err, shared), err
	}
	return nil, false, err
}

// h3ForConnect reports whether a CONNECT is worth a dial over HTTP/3.
func (u *upstreamDialer) h3ForConnect(proxy *url.URL) bool {
	return !u.remembers(noH3Dial, proxy) && !u.remembers(noH3Connect, proxy)
}

// connectH3 opens the tunnel over HTTP/3 and reports whether the dial to the proxy succeeded,
// and whether the tunnel may go elsewhere after a failure.
func (u *upstreamDialer) connectH3(ctx context.Context, proxy *url.URL, addr string) (conn net.Conn, dialed, again bool, err error) {
	cc, err := u.proxyConn(ctx, proxy)
	if err != nil {
		if ctx.Err() == nil {
			u.remember(noH3Dial, proxy)
		}
		return nil, false, false, fmt.Errorf("over HTTP/3: %w", err)
	}
	conn, err = connectOnH3(ctx, cc, proxy, addr)
	if err != nil {
		return nil, true, u.h3Failed(proxy, cc, err), err
	}
	return conn, true, false, nil
}

// h3Failed records what a failed CONNECT over HTTP/3 showed of the proxy and reports whether
// the tunnel may go on another connection or version.
func (u *upstreamDialer) h3Failed(proxy *url.URL, cc *h3ProxyConn, err error) bool {
	switch {
	case notServed(err):
		u.remember(noH3Connect, proxy)
	case errors.Is(err, errOpenStream) && !isContextErr(err), requestRejected(err):
		// The connection is going away or gone. A connection going away closes itself once
		// its streams end.
		u.dropH3Conn(proxy, cc)
	case cc.Context().Err() != nil:
		u.dropH3Conn(proxy, cc)
		return !closedOnError(cc)
	default:
		return false
	}
	return true
}

// closedOnError reports whether this end closed the connection on an error, which quic-go does
// when the proxy breaks the protocol, and the proxy may have processed the request by then.
func closedOnError(cc *h3ProxyConn) bool {
	cause := context.Cause(cc.Context())
	if ae, ok := errors.AsType[*quic.ApplicationError](cause); ok {
		// H3_NO_ERROR is the close of a connection drained after a GOAWAY.
		return !ae.Remote && ae.ErrorCode != quic.ApplicationErrorCode(http3.ErrCodeNoError)
	}
	te, ok := errors.AsType[*quic.TransportError](cause)
	return ok && !te.Remote
}

// requestRejected reports whether the proxy reset the stream with H3_REQUEST_REJECTED, a
// request it did not process, RFC 9114 section 4.1.1.
func requestRejected(err error) bool {
	if se, ok := errors.AsType[*quic.StreamError](err); ok {
		return se.Remote && se.ErrorCode == quic.StreamErrorCode(http3.ErrCodeRequestRejected)
	}
	he, ok := errors.AsType[*http3.Error](err)
	return ok && he.Remote && he.ErrorCode == http3.ErrCodeRequestRejected
}

// h2Failed is h3Failed for HTTP/2. shared reports that the tunnel went on a connection another
// one opened, which the next round leaves alone once it can open no stream.
func (u *upstreamDialer) h2Failed(proxy *url.URL, cc *h2tunnel.Conn, err error, shared bool) bool {
	switch {
	case notServed(err):
		u.remember(noH2Connect, proxy)
	case errors.Is(err, h2tunnel.ErrStreamLimit):
		// The next round opens a connection of its own.
	default:
		return shared && !cc.CanOpen()
	}
	return true
}

func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// overTCP dials the proxy over TCP and opens a tunnel on the connection, with onH2 when TLS
// negotiates h2 and with h1 otherwise. It reports whether the tunnel went on an HTTP/2
// connection another tunnel recorded first.
func overTCP[T any](ctx context.Context, u *upstreamDialer, proxy *url.URL, d tcpDial, h1 func(net.Conn) (T, error), onH2 func(*h2tunnel.Conn) (T, error)) (T, bool, error) {
	var zero T
	https := proxy.Scheme == "https"
	var release func()
	if d.h2 && https && !d.own {
		var cerr error
		if release, cerr = u.claimDial(ctx, proxy, d.wait); cerr != nil {
			return zero, false, cerr
		}
	}
	// Released once TLS decided the version, and on any earlier exit.
	known := func() {
		if release != nil {
			release()
			release = nil
		}
	}
	defer known()

	nc, err := u.dialRaw(ctx, "tcp", proxyAddr(proxy))
	if err != nil {
		return zero, false, fmt.Errorf("%w %s: %w", errDialProxy, proxy.Redacted(), err)
	}
	_ = nc.SetDeadline(time.Now().Add(proxyConnectTimeout))
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	conn := nc
	if https {
		cfg := u.t.upstreamTLSConfig()
		cfg.ServerName = proxy.Hostname()
		cfg.NextProtos = []string{"http/1.1"}
		if d.h2 {
			cfg.NextProtos = []string{"h2", "http/1.1"}
		}
		tc := tls.Client(nc, cfg)
		hctx := ctx
		if u.t.TLSHandshakeTimeout > 0 {
			var cancel context.CancelFunc
			hctx, cancel = context.WithTimeout(ctx, u.t.TLSHandshakeTimeout)
			defer cancel()
		}
		if herr := tc.HandshakeContext(hctx); herr != nil {
			stop()
			_ = nc.Close()
			return zero, false, fmt.Errorf("tls handshake: %w", herr)
		}
		if tc.ConnectionState().NegotiatedProtocol == "h2" {
			// The connection outlives this tunnel, so the dial's cancellation and deadline
			// come off it here, and a tunnel refused on it leaves it shared.
			if !stop() {
				_ = nc.Close()
				return zero, false, ctx.Err()
			}
			_ = nc.SetDeadline(time.Time{})
			if d.own {
				cc, cerr := h2tunnel.Client(tc, proxyKeepAlive)
				if cerr != nil {
					return zero, false, fmt.Errorf("dial proxy %s: %w", proxy.Redacted(), cerr)
				}
				v, oerr := onH2(cc)
				u.retire(cc)
				return v, false, oerr
			}
			cc, shared, serr := u.shareH2Conn(proxy, tc)
			known()
			if serr != nil {
				return zero, false, serr
			}
			v, oerr := onH2(cc)
			return v, shared, oerr
		}
		if d.h2 {
			u.remember(noH2, proxy)
		}
		known()
		conn = tc
	}
	v, err := h1(conn)
	if !stop() {
		_ = conn.Close()
		return zero, false, ctx.Err()
	}
	if err != nil {
		_ = conn.Close()
		return zero, false, err
	}
	_ = nc.SetDeadline(time.Time{})
	return v, false, nil
}

// connectOn sends a CONNECT to the proxy on conn and returns the connection once the proxy
// answered 2xx, with the bytes the proxy sent behind its answer.
func connectOn(conn net.Conn, proxy *url.URL, addr string) (net.Conn, error) {
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr, Header: proxyRequestHeader()}
	if auth := proxyAuthorization(proxy); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}
	br := bufio.NewReader(io.LimitReader(conn, proxyResponseBytes))
	code, _, err := readAnswer(br)
	if err != nil {
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	if err := connectAnswer(code, nil); err != nil {
		// The body is left unread, the caller closes the connection.
		return nil, fmt.Errorf("CONNECT %w", err)
	}
	if br.Buffered() == 0 {
		return conn, nil
	}
	// A peer that sends first, an SMTP banner for instance, may already be behind the
	// response.
	early, _ := br.Peek(br.Buffered())
	return bufferedConn{Conn: conn, r: io.MultiReader(bytes.NewReader(slices.Clone(early)), conn)}, nil
}

// proxyRequestHeader returns the header of a request to a proxy. Request.Write and quic-go
// write a User-Agent of their own unless the field is present, and an empty one is omitted.
func proxyRequestHeader() http.Header {
	return http.Header{"User-Agent": {""}}
}

// readAnswer reads the answer of a proxy over HTTP/1.1 up to the end of its header section,
// past any 1xx other than 101. The framing fields are left unparsed, since a client ignores
// them in a 2xx to CONNECT, RFC 9110 section 9.3.6.
func readAnswer(br *bufio.Reader) (int, http.Header, error) {
	tp := textproto.NewReader(br)
	for n := 0; ; n++ {
		line, err := tp.ReadLine()
		if err != nil {
			return 0, nil, err
		}
		proto, rest, _ := strings.Cut(line, " ")
		status, _, _ := strings.Cut(rest, " ")
		code, ok := statusCode(status)
		if _, _, vok := http.ParseHTTPVersion(proto); !vok || !ok {
			return 0, nil, fmt.Errorf("malformed status line %q", line)
		}
		header, err := tp.ReadMIMEHeader()
		if err != nil {
			return 0, nil, err
		}
		if finalStatus(code) {
			return code, http.Header(header), nil
		}
		if n == maxInformational {
			return 0, nil, errors.New("too many 1xx answers")
		}
	}
}

// finalStatus reports whether code ends the answers to a request. A 101 ends them, as in
// quic-go's client.
func finalStatus(code int) bool {
	return code >= 200 || code == http.StatusSwitchingProtocols
}

func statusCode(s string) (int, bool) {
	if len(s) != 3 {
		return 0, false
	}
	code := 0
	for i := range 3 {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		code = code*10 + int(s[i]-'0')
	}
	return code, code >= 100
}

// connectOnH2 opens the tunnel as a CONNECT stream on the HTTP/2 connection to the proxy.
func connectOnH2(ctx context.Context, cc *h2tunnel.Conn, proxy *url.URL, addr string) (net.Conn, error) {
	ctx, done := context.WithTimeout(ctx, proxyConnectTimeout)
	defer done()
	var header http.Header
	if auth := proxyAuthorization(proxy); auth != "" {
		header = http.Header{"Proxy-Authorization": {auth}}
	}
	str, resp, err := cc.Open(ctx, h2tunnel.Request{Authority: addr, Header: header})
	if err != nil {
		return nil, fmt.Errorf("CONNECT: %w", err)
	}
	if err := connectAnswer(resp.StatusCode, resp.Header); err != nil {
		_ = str.Close()
		return nil, fmt.Errorf("CONNECT %w", err)
	}
	return str, nil
}

// connectOnH3 opens the tunnel as a CONNECT stream on the HTTP/3 connection to the proxy.
func connectOnH3(ctx context.Context, cc *h3ProxyConn, proxy *url.URL, addr string) (net.Conn, error) {
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: addr}, Host: addr, Header: proxyRequestHeader()}
	if auth := proxyAuthorization(proxy); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	str, err := requestOn(ctx, cc.ClientConn, req, "CONNECT", connectAnswer)
	if err != nil {
		return nil, err
	}
	return newH3StreamConn(str, cc.local, cc.remote), nil
}

// connectUDP opens a UDP tunnel to addr with a CONNECT-UDP to the proxy, RFC 9298. HTTP/3
// comes first, and a proxy whose dial over HTTP/3 failed is dialed over TCP for proxyRetry.
// A refusal the proxy answers is final.
func (u *upstreamDialer) connectUDP(ctx context.Context, proxy *url.URL, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("edge: dial udp %q: %w", addr, err)
	}
	var h3err error
	if proxy.Scheme == "https" && !u.remembers(noH3Dial, proxy) {
		cc, cerr := u.proxyConn(ctx, proxy)
		switch {
		case cerr == nil:
			if s := cc.Settings(); s.EnableDatagrams && s.EnableExtendedConnect {
				pipe, oerr := openTunnelOn(ctx, cc.ClientConn, proxy, host, port)
				if oerr != nil {
					return nil, fmt.Errorf("dial udp %s through %s: %w", addr, proxy.Redacted(), oerr)
				}
				return &connectUDPConn{pipe: pipe, remote: tunnelTarget(addr)}, nil
			}
			// The connection stays for the CONNECT tunnels.
			h3err = errors.New("over HTTP/3: the proxy does not support CONNECT-UDP")
		case ctx.Err() != nil:
			return nil, fmt.Errorf("dial proxy %s: %w", proxy.Redacted(), cerr)
		default:
			u.remember(noH3Dial, proxy)
			h3err = fmt.Errorf("over HTTP/3: %w", cerr)
		}
	}
	pipe, err := u.connectUDPStream(ctx, proxy, host, port)
	if err != nil {
		if h3err != nil {
			err = errors.Join(h3err, err)
		}
		return nil, fmt.Errorf("dial udp %s through %s: %w", addr, proxy.Redacted(), err)
	}
	return &connectUDPConn{pipe: pipe, remote: tunnelTarget(addr)}, nil
}

func (u *upstreamDialer) remembers(fact proxyFact, proxy *url.URL) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.remembersLocked(fact, proxyAddr(proxy))
}

// remembersLocked is remembers with u.mu held.
func (u *upstreamDialer) remembersLocked(fact proxyFact, key string) bool {
	until, ok := u.remembered[key+" "+string(fact)]
	return ok && time.Now().Before(until)
}

// claimDial claims the dial of a proxy whose version is unknown and returns what releases it,
// nil when the version is known. A caller that finds the dial in flight waits for it and gets
// errDialWaited when wait is set, and dials alongside it otherwise.
func (u *upstreamDialer) claimDial(ctx context.Context, proxy *url.URL, wait bool) (func(), error) {
	key := proxyAddr(proxy)
	u.mu.Lock()
	if u.closed || u.h2Locked(key) != nil || u.remembersLocked(noH2, key) {
		u.mu.Unlock()
		return nil, nil
	}
	if done := u.tcpDialing[key]; done != nil {
		u.mu.Unlock()
		if !wait {
			return nil, nil
		}
		select {
		case <-done:
		case <-ctx.Done():
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, errDialWaited
	}
	done := make(chan struct{})
	u.tcpDialing[key] = done
	u.mu.Unlock()
	return func() {
		u.mu.Lock()
		if u.tcpDialing[key] == done {
			delete(u.tcpDialing, key)
		}
		u.mu.Unlock()
		close(done)
	}, nil
}

func (u *upstreamDialer) remember(fact proxyFact, proxy *url.URL) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.remembered[proxyAddr(proxy)+" "+string(fact)] = time.Now().Add(proxyRetry)
}

// connectUDPTargetPath expands the default template of RFC 9298 section 3, the colons of an
// IPv6 literal percent-encoded.
func connectUDPTargetPath(host, port string) string {
	return connectUDPPath + strings.ReplaceAll(url.PathEscape(host), ":", "%3A") + "/" + port + "/"
}

// connectAnswer returns the error of a CONNECT answer other than a 2xx, RFC 9110 section 9.3.6.
func connectAnswer(code int, _ http.Header) error {
	if code < 200 || code > 299 {
		return newRefusal(code)
	}
	return nil
}

// connectUDPAnswer returns why a CONNECT-UDP answer over HTTP/2 or HTTP/3 fails, nil for a
// 2xx other than the 204, 205 and 206 RFC 9297 section 3.2 forbids.
func connectUDPAnswer(code int, header http.Header) error {
	switch {
	case code < 200 || code > 299:
		return newRefusal(code)
	case code == http.StatusNoContent || code == http.StatusResetContent || code == http.StatusPartialContent:
		return fmt.Errorf("%w with status %d", errMalformedAnswer, code)
	case hasContentFields(header, nil):
		return fmt.Errorf("%w with content fields", errMalformedAnswer)
	}
	return nil
}

func openTunnelOn(ctx context.Context, cc *http3.ClientConn, proxy *url.URL, host, port string) (tunnelPipe, error) {
	target, err := url.Parse("https://" + proxyAddr(proxy) + connectUDPTargetPath(host, port))
	if err != nil {
		return nil, err
	}
	req := &http.Request{Method: http.MethodConnect, Proto: connectUDPUpgrade, URL: target, Host: target.Host, Header: proxyRequestHeader()}
	req.Header.Set(http3.CapsuleProtocolHeader, "?1")
	if auth := proxyAuthorization(proxy); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	str, err := requestOn(ctx, cc, req, "CONNECT-UDP", connectUDPAnswer)
	if err != nil {
		return nil, err
	}
	pipe := newDatagramPipe(str, quic.StreamErrorCode(http3.ErrCodeNoError), false)
	pipe.run(func() { _ = pipe.close() })
	return pipe, nil
}

// requestOn sends req on a new stream of the HTTP/3 connection to a proxy and returns the
// stream once check accepts the answer. Its errors start with verb, and a malformed answer
// resets the stream with H3_MESSAGE_ERROR, RFC 9114 section 4.1.2.
func requestOn(ctx context.Context, cc *http3.ClientConn, req *http.Request, verb string,
	check func(code int, header http.Header) error,
) (*http3.RequestStream, error) {
	ctx, done := context.WithTimeout(ctx, proxyConnectTimeout)
	defer done()
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errOpenStream, err)
	}
	reset := func(code http3.ErrCode) {
		str.CancelRead(quic.StreamErrorCode(code))
		str.CancelWrite(quic.StreamErrorCode(code))
	}
	cancel := func() { reset(http3.ErrCodeRequestCanceled) }
	stop := context.AfterFunc(ctx, cancel)
	if werr := str.SendRequestHeader(req); werr != nil {
		stop()
		cancel()
		return nil, fmt.Errorf("write %s: %w", verb, werr)
	}
	resp, err := str.ReadResponse()
	// Each call reads one header section, and quic-go's own client calls again past a 1xx.
	for n := 0; err == nil && !finalStatus(resp.StatusCode); n++ {
		if n == maxInformational {
			err = errors.New("too many 1xx answers")
			break
		}
		resp, err = str.ReadResponse()
	}
	if !stop() {
		return nil, ctx.Err()
	}
	if err != nil {
		cancel()
		return nil, fmt.Errorf("read %s response: %w", verb, err)
	}
	if err := check(resp.StatusCode, resp.Header); err != nil {
		if errors.Is(err, errMalformedAnswer) {
			reset(http3.ErrCodeMessageError)
		} else {
			cancel()
		}
		return nil, fmt.Errorf("%s %w", verb, err)
	}
	return str, nil
}

// connectUDPStream opens a tunnel over TCP, an extended CONNECT on the HTTP/2 connection to
// the proxy when TLS negotiates h2, a GET with an Upgrade over HTTP/1.1 otherwise, RFC 9298
// section 3.2, and always over HTTP/1.1 on a plain http proxy.
func (u *upstreamDialer) connectUDPStream(ctx context.Context, proxy *url.URL, host, port string) (tunnelPipe, error) {
	var retried, waited, own bool
	for {
		d := tcpDial{h2: proxy.Scheme == "https" && !u.remembers(noH2Extended, proxy), wait: !waited, own: own}
		var pipe tunnelPipe
		var err error
		pooled := false
		if cc := u.h2Conn(proxy); d.h2 && !d.own && cc != nil {
			pooled = true
			pipe, err = openTunnelOnH2(ctx, cc, proxy, host, port)
		} else {
			pipe, pooled, err = u.dialTunnel(ctx, proxy, host, port, d)
		}
		switch {
		case errors.Is(err, errDialWaited):
			waited = true
			continue
		case errors.Is(err, h2tunnel.ErrStreamLimit):
			own = true
			continue
		case errors.Is(err, h2tunnel.ErrExtendedConnect):
			// An HTTP/2 proxy without extended CONNECT may still upgrade an HTTP/1.1
			// connection, so the next one offers nothing else. The connection stays for the
			// CONNECT tunnels.
			u.remember(noH2Extended, proxy)
			continue
		case err != nil && pooled && !retried && ctx.Err() == nil && !isRefusal(err) && !errors.Is(err, errMalformedAnswer):
			// The pooled connection was gone, going away or full as the tunnel was opened
			// on it, and the proxy saw nothing of the tunnel. The next round finds the
			// connection unusable and opens another.
			retried = true
			continue
		}
		return pipe, err
	}
}

func (u *upstreamDialer) dialTunnel(ctx context.Context, proxy *url.URL, host, port string, d tcpDial) (tunnelPipe, bool, error) {
	return overTCP(ctx, u, proxy, d,
		func(conn net.Conn) (tunnelPipe, error) { return upgradeOn(conn, proxy, host, port) },
		func(cc *h2tunnel.Conn) (tunnelPipe, error) { return openTunnelOnH2(ctx, cc, proxy, host, port) })
}

func (u *upstreamDialer) h2Conn(proxy *url.URL) *h2tunnel.Conn {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.h2Locked(proxyAddr(proxy))
}

// h2Locked is h2Conn with u.mu held.
func (u *upstreamDialer) h2Locked(key string) *h2tunnel.Conn {
	if cc := u.h2conns[key]; cc != nil && cc.CanOpen() {
		return cc
	}
	return nil
}

// shareH2Conn records the HTTP/2 connection on tc for the next tunnels. When another tunnel
// recorded one first, that one is returned and tc closed.
func (u *upstreamDialer) shareH2Conn(proxy *url.URL, tc net.Conn) (*h2tunnel.Conn, bool, error) {
	cc, err := h2tunnel.Client(tc, proxyKeepAlive)
	if err != nil {
		return nil, false, fmt.Errorf("dial proxy %s: %w", proxy.Redacted(), err)
	}
	key := proxyAddr(proxy)
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		_ = cc.Close()
		return nil, false, net.ErrClosed
	}
	if other := u.h2conns[key]; other != nil {
		if other.CanOpen() {
			_ = cc.Close()
			return other, true, nil
		}
		u.retireLocked(other)
	}
	u.h2conns[key] = cc
	return cc, false, nil
}

// retire ends an HTTP/2 connection once its tunnels end, and with the dialer.
func (u *upstreamDialer) retire(cc *h2tunnel.Conn) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		_ = cc.Close()
		return
	}
	u.retireLocked(cc)
}

func (u *upstreamDialer) retireLocked(cc *h2tunnel.Conn) {
	cc.Retire()
	u.draining = slices.DeleteFunc(u.draining, func(d *h2tunnel.Conn) bool { return d.Err() != nil })
	u.draining = append(u.draining, cc)
}

func openTunnelOnH2(ctx context.Context, cc *h2tunnel.Conn, proxy *url.URL, host, port string) (tunnelPipe, error) {
	ctx, done := context.WithTimeout(ctx, proxyConnectTimeout)
	defer done()
	header := http.Header{http3.CapsuleProtocolHeader: {"?1"}}
	if auth := proxyAuthorization(proxy); auth != "" {
		header.Set("Proxy-Authorization", auth)
	}
	str, resp, err := cc.Open(ctx, h2tunnel.Request{
		Protocol:  connectUDPUpgrade,
		Scheme:    "https",
		Authority: proxyAddr(proxy),
		Path:      connectUDPTargetPath(host, port),
		Header:    header,
	})
	if err != nil {
		return nil, fmt.Errorf("CONNECT-UDP: %w", err)
	}
	if err := connectUDPAnswer(resp.StatusCode, resp.Header); err != nil {
		if errors.Is(err, errMalformedAnswer) {
			str.Abort()
		} else {
			_ = str.Close()
		}
		return nil, fmt.Errorf("CONNECT-UDP %w", err)
	}
	return newCapsulePipe(str, bufio.NewReader(str)), nil
}

func upgradeOn(conn net.Conn, proxy *url.URL, host, port string) (tunnelPipe, error) {
	target, err := url.Parse(proxy.Scheme + "://" + proxyAddr(proxy) + connectUDPTargetPath(host, port))
	if err != nil {
		return nil, err
	}
	req := &http.Request{Method: http.MethodGet, URL: target, Host: target.Host, Header: proxyRequestHeader()}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", connectUDPUpgrade)
	req.Header.Set(http3.CapsuleProtocolHeader, "?1")
	if auth := proxyAuthorization(proxy); auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}
	if werr := req.WriteProxy(conn); werr != nil {
		return nil, fmt.Errorf("write CONNECT-UDP: %w", werr)
	}
	br := bufio.NewReader(io.LimitReader(conn, proxyResponseBytes))
	code, header, err := readAnswer(br)
	if err != nil {
		return nil, fmt.Errorf("read CONNECT-UDP response: %w", err)
	}
	if code != http.StatusSwitchingProtocols {
		// The body is left unread, the caller closes the connection.
		return nil, fmt.Errorf("CONNECT-UDP %w", newRefusal(code))
	}
	// RFC 9298 section 3.3 requires one Upgrade value and the upgrade option in Connection.
	if upgrade := header.Values("Upgrade"); len(upgrade) != 1 || !strings.EqualFold(upgrade[0], connectUDPUpgrade) {
		return nil, errors.New("CONNECT-UDP upgraded to " + strings.Join(upgrade, ", "))
	}
	if !httpguts.HeaderValuesContainsToken(header["Connection"], "upgrade") {
		return nil, errors.New("CONNECT-UDP upgraded without the upgrade option in Connection")
	}
	if hasContentFields(header, nil) {
		return nil, fmt.Errorf("CONNECT-UDP %w with content fields", errMalformedAnswer)
	}
	// Capsules the proxy sent right behind the 101 may already be in the buffer.
	early, _ := br.Peek(br.Buffered())
	return newCapsulePipe(conn, bufio.NewReader(io.MultiReader(bytes.NewReader(slices.Clone(early)), conn))), nil
}

// h3ProxyConn is the HTTP/3 connection to a proxy. The tunnels on it report the addresses of
// its QUIC connection.
type h3ProxyConn struct {
	*http3.ClientConn
	local, remote net.Addr
}

type dialCall struct {
	done chan struct{}
	cc   *h3ProxyConn
	err  error
}

// proxyConn returns the HTTP/3 connection to a proxy, opened on the first tunnel and shared
// by every later one until it ends. A caller that finds the dial in flight waits for it, and
// dials itself when that dial ended with the context of the caller that started it.
func (u *upstreamDialer) proxyConn(ctx context.Context, proxy *url.URL) (*h3ProxyConn, error) {
	key := proxyAddr(proxy)
	for {
		u.mu.Lock()
		if u.closed {
			u.mu.Unlock()
			return nil, net.ErrClosed
		}
		if cc := u.h3Locked(key); cc != nil {
			u.mu.Unlock()
			return cc, nil
		}
		call := u.h3Dialing[key]
		if call == nil {
			call = &dialCall{done: make(chan struct{})}
			u.h3Dialing[key] = call
			u.mu.Unlock()
			return u.runDial(ctx, proxy, key, call)
		}
		u.mu.Unlock()
		select {
		case <-call.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if call.err == nil || !isContextErr(call.err) {
			return call.cc, call.err
		}
	}
}

func (u *upstreamDialer) runDial(ctx context.Context, proxy *url.URL, key string, call *dialCall) (*h3ProxyConn, error) {
	defer close(call.done)
	call.cc, call.err = u.openProxyConn(ctx, proxy, key)
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.h3Dialing, key)
	if call.err == nil && u.closed {
		_ = call.cc.CloseWithError(0, "")
		call.cc, call.err = nil, net.ErrClosed
	}
	if call.err == nil {
		u.conns[key] = call.cc
	}
	return call.cc, call.err
}

func (u *upstreamDialer) h3Conn(proxy *url.URL) *h3ProxyConn {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.h3Locked(proxyAddr(proxy))
}

// h3Locked is h3Conn with u.mu held.
func (u *upstreamDialer) h3Locked(key string) *h3ProxyConn {
	if cc := u.conns[key]; cc != nil && cc.Context().Err() == nil {
		return cc
	}
	return nil
}

func (u *upstreamDialer) dropH3Conn(proxy *url.URL, cc *h3ProxyConn) {
	key := proxyAddr(proxy)
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conns[key] == cc {
		delete(u.conns, key)
	}
}

func (u *upstreamDialer) openProxyConn(ctx context.Context, proxy *url.URL, addr string) (*h3ProxyConn, error) {
	// The proxy itself is dialed directly, it cannot be reached through itself.
	sock, err := u.dialRaw(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	cfg := u.t.upstreamTLSConfig()
	cfg.MinVersion = tls.VersionTLS13
	cfg.ServerName = proxy.Hostname()
	cfg.NextProtos = []string{http3.NextProtoH3}
	qc, err := quicOn(ctx, sock, addr, cfg, &quic.Config{
		EnableDatagrams:      true,
		HandshakeIdleTimeout: u.t.TLSHandshakeTimeout,
		MaxIdleTimeout:       u.t.IdleConnTimeout,
		KeepAlivePeriod:      proxyKeepAlive,
		// The 1200 byte Initial of an inner QUIC connection goes inside one datagram, which
		// the default initial packet size does not leave room for.
		InitialPacketSize: 1350,
	})
	if err != nil {
		return nil, err
	}
	cc := u.h3.NewClientConn(qc)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		_ = cc.CloseWithError(0, "")
		return nil, ctx.Err()
	case <-cc.Context().Done():
		return nil, context.Cause(cc.Context())
	}
	return &h3ProxyConn{ClientConn: cc, local: qc.LocalAddr(), remote: qc.RemoteAddr()}, nil
}

// h3StreamConn is a CONNECT tunnel on an HTTP/3 stream as a net.Conn. The stream frames its
// bytes in DATA frames and a deadline that cuts a frame short loses the parser's place, so a
// read waits on a deadlineReader and a write the deadline cut resets the stream.
type h3StreamConn struct {
	str    *http3.RequestStream
	r      *deadlineReader
	local  net.Addr
	remote net.Addr
	wmu    sync.Mutex
	closed atomic.Bool
}

func newH3StreamConn(str *http3.RequestStream, local, remote net.Addr) *h3StreamConn {
	return &h3StreamConn{str: str, r: newDeadlineReader(tunnelReader{str}), local: local, remote: remote}
}

// tunnelReader reads the stream of a tunnel. The error of a stream or a connection is sticky,
// and some report themselves as a timeout, which a reader would retry.
type tunnelReader struct{ str *http3.RequestStream }

func (r tunnelReader) Read(b []byte) (int, error) {
	n, err := r.str.Read(b)
	if err != nil && !errors.Is(err, io.EOF) && isTimeout(err) {
		err = fmt.Errorf("%w: %v", errTunnelEnded, err)
	}
	return n, err
}

func (c *h3StreamConn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.r.Read(b)
}

func (c *h3StreamConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.str.Write(b)
	if err != nil && isTimeout(err) {
		// The deadline may have cut a frame short, and the proxy cannot parse the stream past
		// it.
		c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	}
	return n, err
}

func (c *h3StreamConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.str.Close()
}

func (c *h3StreamConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	if c.wmu.TryLock() {
		_ = c.str.Close()
		c.wmu.Unlock()
	} else {
		// A write blocked on flow control only returns on a reset.
		c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	}
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	return nil
}

// Abort resets both directions with H3_CONNECT_ERROR, RFC 9114 section 4.4.
func (c *h3StreamConn) Abort() {
	if c.closed.Swap(true) {
		return
	}
	c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeConnectError))
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeConnectError))
}

func (c *h3StreamConn) LocalAddr() net.Addr  { return c.local }
func (c *h3StreamConn) RemoteAddr() net.Addr { return c.remote }

func (c *h3StreamConn) SetDeadline(t time.Time) error {
	c.r.setDeadline(t)
	return c.str.SetWriteDeadline(t)
}

func (c *h3StreamConn) SetReadDeadline(t time.Time) error {
	c.r.setDeadline(t)
	return nil
}

func (c *h3StreamConn) SetWriteDeadline(t time.Time) error { return c.str.SetWriteDeadline(t) }

// connectUDPConn is a CONNECT-UDP tunnel as a connected socket, one datagram per Read and per
// Write. A datagram too large for the tunnel is dropped, and one past the 65527 bytes of
// RFC 9298 section 5 is refused.
type connectUDPConn struct {
	pipe      tunnelPipe
	remote    tunnelTarget
	closeOnce sync.Once
}

// tunnelTarget is the address a tunnel is opened to, as the proxy resolves it.
type tunnelTarget string

func (tunnelTarget) Network() string  { return "udp" }
func (t tunnelTarget) String() string { return string(t) }

func (c *connectUDPConn) Read(b []byte) (int, error) {
	for {
		data, err := c.pipe.recv(context.Background())
		if err != nil {
			return 0, err
		}
		// Context ID 0 is a UDP payload, RFC 9298 section 5. Anything else is dropped.
		id, n, perr := quicvarint.Parse(data)
		if perr != nil || id != 0 {
			continue
		}
		return copy(b, data[n:]), nil
	}
}

func (c *connectUDPConn) Write(b []byte) (int, error) {
	if len(b) > maxCapsuleDatagram {
		return 0, fmt.Errorf("edge: a UDP payload of %d bytes exceeds the %d bytes of a tunnel", len(b), maxCapsuleDatagram)
	}
	out := tunnelBuf(capsuleHeadroom + 1 + len(b))
	out[capsuleHeadroom] = 0
	copy(out[capsuleHeadroom+1:], b)
	err := c.pipe.send(out)
	putTunnelBuf(out)
	if err != nil {
		if _, tooLarge := errors.AsType[*quic.DatagramTooLargeError](err); tooLarge {
			return len(b), nil
		}
		return 0, err
	}
	return len(b), nil
}

func (c *connectUDPConn) Close() error {
	c.closeOnce.Do(func() { _ = c.pipe.close() })
	return nil
}

func (c *connectUDPConn) LocalAddr() net.Addr                { return emptyAddr{} }
func (c *connectUDPConn) RemoteAddr() net.Addr               { return c.remote }
func (c *connectUDPConn) SetDeadline(t time.Time) error      { return c.SetReadDeadline(t) }
func (c *connectUDPConn) SetReadDeadline(t time.Time) error  { return c.pipe.setReadDeadline(t) }
func (c *connectUDPConn) SetWriteDeadline(t time.Time) error { return c.pipe.setWriteDeadline(t) }

// ownSockets records the sockets the proxy has open upstream, so that a front refuses a
// connection one of them opened to the proxy itself. Linux gives one local port to
// several connections toward distinct peers, so a stream socket is matched on both its addresses
// and a datagram socket on its local address alone.
type ownSockets struct {
	shards [ownShards]ownShard
}

// ownShards is a power of two, and the low bits of the local port of a record select its shard.
const ownShards = 16

type ownShard struct {
	m  map[ownKey]int32
	mu sync.Mutex
	_  [cacheLine - 16]byte
}

const cacheLine = 64

// ownKey is the two addresses of a stream socket, or the local address of a datagram socket
// and a zero remote.
type ownKey struct {
	local, remote netip.AddrPort
}

func newOwnSockets() *ownSockets {
	o := new(ownSockets)
	for i := range o.shards {
		o.shards[i].m = make(map[ownKey]int32)
	}
	return o
}

func (o *ownSockets) shard(key ownKey) *ownShard {
	return &o.shards[key.local.Port()&(ownShards-1)]
}

// ownAddr returns the address and port of a, unmapped and without a zone, so that both ends of
// a socket report it alike.
func ownAddr(a net.Addr) netip.AddrPort {
	ap := addrPort(a)
	return netip.AddrPortFrom(ap.Addr().WithZone(""), ap.Port())
}

// track records c and returns it wrapped so that closing it releases the record. A socket
// whose addresses are not IP addresses is returned as it is.
func (o *ownSockets) track(network string, c net.Conn) net.Conn {
	key := ownKey{local: ownAddr(c.LocalAddr())}
	if !key.local.IsValid() {
		return c
	}
	if !strings.HasPrefix(network, "udp") {
		if key.remote = ownAddr(c.RemoteAddr()); !key.remote.IsValid() {
			return c
		}
	}
	sh := o.shard(key)
	sh.mu.Lock()
	sh.m[key]++
	sh.mu.Unlock()
	switch c := c.(type) {
	case *net.TCPConn:
		return &ownTCPConn{TCPConn: c, own: ownRecord{o: o, key: key}}
	case *net.UDPConn:
		return &ownUDPConn{UDPConn: c, own: ownRecord{o: o, key: key}}
	}
	return &ownConn{Conn: c, own: ownRecord{o: o, key: key}}
}

func (o *ownSockets) has(key ownKey) bool {
	sh := o.shard(key)
	sh.mu.Lock()
	n := sh.m[key]
	sh.mu.Unlock()
	return n > 0
}

// stream reports whether a connection from remote to local, or to dst it was redirected
// from, is one the proxy opened.
func (o *ownSockets) stream(remote, local net.Addr, dst netip.AddrPort) bool {
	key := ownKey{local: ownAddr(remote), remote: ownAddr(local)}
	if !key.local.IsValid() {
		return false
	}
	if key.remote.IsValid() && o.has(key) {
		return true
	}
	if dst.IsValid() {
		key.remote = netip.AddrPortFrom(dst.Addr().Unmap().WithZone(""), dst.Port())
		return o.has(key)
	}
	return false
}

// fromItself reports whether the stream connection from remote to local, or to dst it was
// redirected from, is one the proxy opened upstream, and logs it. A front calls it once the
// first bytes have arrived, which the proxy writes only after recording the socket.
func (p *Proxy) fromItself(remote, local net.Addr, dst netip.AddrPort) bool {
	if !p.srv.fwd.up.own.stream(remote, local, dst) {
		return false
	}
	p.cfg.logger.Debug("edge: connection refused", slog.String("client", remote.String()),
		slog.String("reason", "the proxy opened it upstream, a request loop"))
	return true
}

// datagram reports whether a datagram from addr was sent by a socket the proxy opened.
func (o *ownSockets) datagram(addr netip.AddrPort) bool {
	addr = netip.AddrPortFrom(addr.Addr().Unmap().WithZone(""), addr.Port())
	return addr.IsValid() && o.has(ownKey{local: addr})
}

// ownRecord releases one record of ownSockets, once. A socket releases it before it closes,
// so a peer that saw the close finds the record gone.
type ownRecord struct {
	o        *ownSockets
	key      ownKey
	released atomic.Bool
}

func (r *ownRecord) release() {
	if !r.released.CompareAndSwap(false, true) {
		return
	}
	sh := r.o.shard(r.key)
	sh.mu.Lock()
	if sh.m[r.key]--; sh.m[r.key] <= 0 {
		delete(sh.m, r.key)
	}
	sh.mu.Unlock()
}

// ownTCPConn keeps the methods of *net.TCPConn, the half-close and the splice net/http and the
// relays reach for.
type ownTCPConn struct {
	*net.TCPConn
	own ownRecord
}

func (c *ownTCPConn) Close() error {
	c.own.release()
	return c.TCPConn.Close()
}

func (c *ownTCPConn) Abort() {
	_ = c.SetLinger(0)
	_ = c.Close()
}

// ownUDPConn keeps the methods of *net.UDPConn, the batched reads quic-go reaches for through
// packetConnOf and the socket options.
type ownUDPConn struct {
	*net.UDPConn
	own ownRecord
}

func (c *ownUDPConn) Close() error {
	c.own.release()
	return c.UDPConn.Close()
}

type ownConn struct {
	net.Conn
	own ownRecord
}

func (c *ownConn) Close() error {
	c.own.release()
	return c.Conn.Close()
}

func (c *ownConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

func (c *ownConn) Abort() {
	c.own.release()
	abort(c.Conn)
}
