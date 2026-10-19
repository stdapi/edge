package edge

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2/hpack"
)

// h2HeaderTableSize is the HPACK table size the front's HTTP/2 server advertises, which is
// the table a schemeConn mirrors.
const h2HeaderTableSize = 4096

// h2MaxReadFrameSize is the largest frame the front's HTTP/2 server reads.
const h2MaxReadFrameSize = 1 << 20

// schemeName is the name of the field a schemeConn adds to an HTTP/2 request for its
// :scheme. It is random per process, so that no client can send it.
var schemeName = "edge-scheme-" + strings.ToLower(rand.Text())

var schemeHeader = http.CanonicalHeaderKey(schemeName)

// The field as a never-indexed literal, which leaves the HPACK table of both ends as the
// client left it. Its value is one byte, so a frame grows by one length whatever its
// :scheme.
var (
	schemeFieldHTTP  = schemeField('h')
	schemeFieldHTTPS = schemeField('s')
	schemeFieldNone  = schemeField('-')
)

func schemeField(code byte) string {
	return string(slices.Concat([]byte{0x10, byte(len(schemeName))}, []byte(schemeName), []byte{1, code})) //nolint:gosec // schemeName is 38 bytes
}

// schemeOutKeep is the capacity of the output buffer a schemeConn keeps once drained. A
// frame held in full may grow it to h2MaxReadFrameSize.
const schemeOutKeep = 64 << 10

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

const (
	h2FrameHeaders      = 0x1
	h2FrameContinuation = 0x9
	h2FlagEndHeaders    = 0x4
	h2FlagPadded        = 0x8
	h2FlagPriority      = 0x20
)

const (
	schemeUndecided uint8 = iota
	schemeFrames
	schemeRaw
	// schemeRefused ends every read of a connection the proxy opened itself. net/http reads
	// again after an error and would find the buffered request.
	schemeRefused
)

// schemeConn adds the :scheme of each HTTP/2 request as schemeHeader, at the end of its
// header block. net/http exposes :scheme nowhere, and schemeConn goes once net/http puts it
// on the Request (golang/go#68365).
type schemeConn struct {
	net.Conn
	br  *bufio.Reader
	dec *hpack.Decoder
	// p refuses a connection the proxy opened itself, nil where nothing is refused.
	p      *Proxy
	scheme string
	out    []byte
	// headerBy is the bound of the first request header in nanoseconds since the epoch, zero
	// once it is read. asked is the read deadline last asked for, applied once the bound goes.
	headerBy atomic.Int64
	asked    atomic.Int64
	outPos   int
	maxStr   int

	// The frame being read.
	left      int
	pos       int
	fragStart int
	fragEnd   int

	// The header block being read.
	stream  uint32
	last    uint32
	state   uint8
	end     bool
	inBlock bool
	request bool
	skip    bool
	desync  bool
	// held marks the frame ending a request block, kept in out until it is read in full since
	// the field is added only to a block that decodes.
	held bool
}

// tlsSchemeConn is a schemeConn over TLS. Its ConnectionState and HandshakeContext have
// net/http negotiate h2 on it as on a *tls.Conn.
type tlsSchemeConn struct {
	*schemeConn
}

type connectionStater interface {
	ConnectionState() tls.ConnectionState
}

func (c tlsSchemeConn) ConnectionState() tls.ConnectionState {
	return c.Conn.(connectionStater).ConnectionState()
}

func (c tlsSchemeConn) HandshakeContext(ctx context.Context) error {
	if h, ok := c.Conn.(interface{ HandshakeContext(context.Context) error }); ok {
		return h.HandshakeContext(ctx)
	}
	return nil
}

func newSchemeConn(c net.Conn, maxHeaderBytes int) net.Conn {
	sc := &schemeConn{Conn: c, maxStr: maxHeaderBytes}
	if _, ok := c.(connectionStater); ok {
		return tlsSchemeConn{sc}
	}
	return sc
}

// schemeConnOf returns the schemeConn c is, if it is one.
func schemeConnOf(c net.Conn) *schemeConn {
	switch c := c.(type) {
	case *schemeConn:
		return c
	case tlsSchemeConn:
		return c.schemeConn
	}
	return nil
}

func (c *schemeConn) NetConn() net.Conn { return c.Conn }

// SetReadDeadline is the read deadline of the connection, capped by the bound of its first
// request header, which counts from the accept.
func (c *schemeConn) SetReadDeadline(t time.Time) error {
	var asked int64
	if !t.IsZero() {
		asked = t.UnixNano()
	}
	c.asked.Store(asked)
	if by := c.headerBy.Load(); by != 0 && (t.IsZero() || t.UnixNano() > by) {
		t = time.Unix(0, by)
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *schemeConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// boundHeader caps the read deadlines at t until the first request header is read. A zero t
// lifts the cap and gives the connection the read deadline last asked for.
func (c *schemeConn) boundHeader(t time.Time) {
	if !t.IsZero() {
		c.headerBy.Store(t.UnixNano())
		return
	}
	if c.headerBy.Swap(0) == 0 {
		return
	}
	var asked time.Time
	if n := c.asked.Load(); n != 0 {
		asked = time.Unix(0, n)
	}
	_ = c.Conn.SetReadDeadline(asked)
}

func (c *schemeConn) CloseWrite() error { return closeWrite(c.Conn) }

func (c *schemeConn) Abort() { abort(c.Conn) }

func (c *schemeConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if c.held {
			if err := c.fill(); err != nil {
				return 0, err
			}
			continue
		}
		if c.outPos < len(c.out) {
			n := copy(p, c.out[c.outPos:])
			c.outPos += n
			if c.outPos == len(c.out) {
				c.out, c.outPos = c.out[:0], 0
				if cap(c.out) > schemeOutKeep {
					c.out = nil
				}
			}
			return n, nil
		}
		switch c.state {
		case schemeUndecided:
			if err := c.decide(); err != nil {
				return 0, err
			}
			continue
		case schemeRefused:
			return 0, errFromItself
		case schemeRaw:
			if c.br != nil {
				if c.br.Buffered() > 0 {
					return c.br.Read(p)
				}
				c.br, c.dec, c.out = nil, nil, nil
			}
			return c.Conn.Read(p)
		}
		if c.left > 0 {
			return c.readPayload(p)
		}
		if err := c.nextFrame(); err != nil {
			return 0, err
		}
	}
}

// http2 decides, as the first read would, whether the connection uses HTTP/2, from the ALPN of
// a TLS connection or the preface of a plaintext one. What it reads is read again by the server.
func (c *schemeConn) http2() (bool, error) {
	if c.state == schemeUndecided {
		if err := c.decide(); err != nil {
			return false, err
		}
	}
	return c.state == schemeFrames, nil
}

// decide reads the frames of an HTTP/2 connection and passes any other through. In plaintext
// it decides on the first byte that leaves the preface, so a short HTTP/1.1 request is never
// delayed.
func (c *schemeConn) decide() error {
	cs, isTLS := c.Conn.(connectionStater)
	if !isTLS {
		if c.br == nil {
			c.br = bufio.NewReader(c.Conn)
		}
		if _, err := c.br.Peek(1); err != nil {
			return err
		}
	}
	// net/http has run the handshake of a TLS connection before its first read.
	if c.p != nil && c.p.fromItself(c.RemoteAddr(), c.LocalAddr(), netip.AddrPort{}) {
		abort(c.Conn)
		c.state = schemeRefused
		c.br = nil
		return errFromItself
	}
	if isTLS && cs.ConnectionState().NegotiatedProtocol != "h2" {
		// The first byte of a request, awaited under the deadline of the front as on plaintext.
		if c.br == nil {
			c.br = bufio.NewReader(c.Conn)
		}
		if _, err := c.br.Peek(1); err != nil {
			return err
		}
		c.state = schemeRaw
		return nil
	}
	if c.br == nil {
		c.br = bufio.NewReader(c.Conn)
	}
	n := max(c.br.Buffered(), 1)
	for {
		b, err := c.br.Peek(min(n, len(h2Preface)))
		if string(b) != h2Preface[:len(b)] {
			c.state = schemeRaw
			return nil
		}
		if len(b) == len(h2Preface) {
			c.out = append(c.out, b...)
			_, _ = c.br.Discard(len(b))
			c.dec = hpack.NewDecoder(h2HeaderTableSize, c.emit)
			c.dec.SetMaxStringLength(c.maxStr)
			c.state = schemeFrames
			return nil
		}
		if err != nil {
			return err
		}
		n = max(n+1, c.br.Buffered())
	}
}

func (c *schemeConn) emit(f hpack.HeaderField) {
	if !f.IsPseudo() {
		c.dec.SetEmitEnabled(false)
		return
	}
	if f.Name == ":scheme" {
		c.scheme = f.Value
	}
}

// A frame on which net/http ends the connection stops the parsing, and the rest of the
// connection passes through unread.
func (c *schemeConn) nextFrame() error {
	h, err := c.br.Peek(9)
	if err != nil {
		return err
	}
	length := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
	typ, flags := h[3], h[4]
	stream := binary.BigEndian.Uint32(h[5:9]) & 0x7fffffff
	if length > h2MaxReadFrameSize {
		c.state = schemeRaw
		return nil
	}

	if typ != h2FrameHeaders && typ != h2FrameContinuation {
		if c.inBlock {
			c.state = schemeRaw
			return nil
		}
		c.out = append(c.out, h...)
		_, _ = c.br.Discard(9)
		c.left, c.fragStart, c.fragEnd = length, 0, 0
		return nil
	}

	fragStart, fragEnd := 0, length
	if typ == h2FrameHeaders {
		if c.inBlock {
			c.state = schemeRaw
			return nil
		}
		if flags&h2FlagPadded != 0 {
			if length == 0 {
				c.state = schemeRaw
				return nil
			}
			p, err := c.br.Peek(10)
			if err != nil {
				return err
			}
			fragStart, fragEnd = 1, length-int(p[9])
		}
		if flags&h2FlagPriority != 0 {
			fragStart += 5
		}
		if fragStart > length {
			c.state = schemeRaw
			return nil
		}
		c.inBlock, c.stream = true, stream
		// net/http resets the stream of a HEADERS frame padded past its fragment and keeps the
		// connection, with its HPACK table and its highest stream as they were.
		c.skip = fragStart > fragEnd
		c.request = !c.skip && stream > c.last
		if c.request {
			c.last, c.scheme = stream, ""
		}
		c.dec.SetEmitEnabled(c.request)
	} else if !c.inBlock || stream != c.stream {
		c.state = schemeRaw
		return nil
	}
	if c.skip {
		fragStart, fragEnd = 0, 0
	}

	c.out = append(c.out, h...)
	_, _ = c.br.Discard(9)
	c.end = flags&h2FlagEndHeaders != 0
	c.left, c.pos, c.fragStart, c.fragEnd = length, 0, fragStart, fragEnd
	c.held = c.end && c.request
	if !c.held {
		c.advance()
	}
	return nil
}

func (c *schemeConn) fill() error {
	for c.left > 0 {
		// Grown with what arrives, so a length the client does not send costs nothing.
		c.out = slices.Grow(c.out, min(c.left, 16<<10))
		n, err := c.br.Read(c.out[len(c.out):min(cap(c.out), len(c.out)+c.left)])
		c.out = c.out[:len(c.out)+n]
		c.pos += n
		c.left -= n
		// An error returned with the last octets of the frame comes back on the next read.
		if err != nil && c.left > 0 {
			return err
		}
	}
	c.held = false
	c.seal()
	return nil
}

// seal decodes the fragment of the held frame and adds the field if the block decodes. A
// block that does not decode passes unchanged, so the server fails the connection on it,
// where a field completing a truncated value would make it a stream error.
func (c *schemeConn) seal() {
	frame := c.out[len(c.out)-9-c.pos:]
	if !c.desync {
		if _, err := c.dec.Write(frame[9+c.fragStart : 9+c.fragEnd]); err != nil {
			c.desync = true
		}
	}
	c.inBlock = false
	c.closeBlock()
	if c.desync {
		return
	}
	field := c.field()
	// net/http ends the connection on a CONTINUATION after an invalid or a truncated field
	// list, where the same list in one frame is a stream error.
	if grown := c.pos + len(field); grown <= h2MaxReadFrameSize {
		frame[0], frame[1], frame[2] = byte(grown>>16), byte(grown>>8), byte(grown) //nolint:gosec // at most h2MaxReadFrameSize
		at := len(c.out) - (c.pos - c.fragEnd)
		c.out = append(c.out, field...)
		copy(c.out[at+len(field):], c.out[at:len(c.out)-len(field)])
		copy(c.out[at:], field)
		return
	}
	frame[4] &^= h2FlagEndHeaders
	c.out = append(c.out, 0, 0, byte(len(field)), h2FrameContinuation, h2FlagEndHeaders) //nolint:gosec // a field is 42 bytes
	c.out = binary.BigEndian.AppendUint32(c.out, c.stream)
	c.out = append(c.out, field...)
}

func (c *schemeConn) readPayload(p []byte) (int, error) {
	n, err := c.br.Read(p[:min(len(p), c.left)])
	if c.inBlock && !c.desync {
		lo, hi := max(c.pos, c.fragStart), min(c.pos+n, c.fragEnd)
		if lo < hi {
			if _, werr := c.dec.Write(p[lo-c.pos : hi-c.pos]); werr != nil {
				c.desync = true
			}
		}
	}
	c.pos += n
	c.left -= n
	c.advance()
	return n, err
}

// The frame ending a request block never reaches advance, seal ends that block.
func (c *schemeConn) advance() {
	if c.left > 0 || !c.inBlock || !c.end {
		return
	}
	c.inBlock = false
	if c.skip {
		c.skip = false
		return
	}
	c.closeBlock()
}

func (c *schemeConn) closeBlock() {
	if !c.desync && c.dec.Close() != nil {
		c.desync = true
	}
}

func (c *schemeConn) field() string {
	switch c.scheme {
	case "http":
		return schemeFieldHTTP
	case "https":
		return schemeFieldHTTPS
	}
	return schemeFieldNone
}

// schemeListener wraps each connection a front accepts in a schemeConn.
type schemeListener struct {
	net.Listener
	p              *Proxy
	maxHeaderBytes int
}

func (l schemeListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	sc := newSchemeConn(c, l.maxHeaderBytes)
	schemeConnOf(sc).p = l.p
	return sc, nil
}

// takeScheme returns the scheme of an HTTP/2 or HTTP/3 request and removes schemeHeader from
// it. It returns "" for an HTTP/1.1 request, whose absolute target has the scheme.
//
// An HTTP/2 request on a stream below the last one, which net/http accepts and the schemeConn
// takes for trailers, has no schemeHeader and gets "".
func takeScheme(r *http.Request) string {
	if r.ProtoMajor < 2 {
		return ""
	}
	if sessionFromRequest(r).hasSchemeField {
		vs := r.Header[schemeHeader]
		delete(r.Header, schemeHeader)
		if len(vs) != 1 {
			return ""
		}
		switch vs[0] {
		case "h":
			return "http"
		case "s":
			return "https"
		}
		return ""
	}
	// quic-go does not expose :scheme either, so the scheme is the connection's. A client
	// sending "http" over TLS is forwarded as "https".
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
