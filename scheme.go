package edge

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"

	"golang.org/x/net/http2/hpack"
)

// h2HeaderTableSize is the HPACK table size the front's HTTP/2 server advertises, which is
// the table a schemeConn mirrors.
const h2HeaderTableSize = 4096

// h2MaxReadFrameSize is the largest frame the front's HTTP/2 server reads.
const h2MaxReadFrameSize = 1 << 20

// schemeHeader is the field a schemeConn adds to an HTTP/2 request for its :scheme.
const schemeHeader = "Edge-Scheme"

// The field as a never-indexed literal, which leaves the HPACK table of both ends as the
// client left it. Its value is one byte, so the length of a frame is decided before its
// :scheme is decoded.
const (
	schemeFieldHTTP  = "\x10\x0bedge-scheme\x01h"
	schemeFieldHTTPS = "\x10\x0bedge-scheme\x01s"
	schemeFieldNone  = "\x10\x0bedge-scheme\x01-"
)

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
)

// schemeConn adds the :scheme of each HTTP/2 request as schemeHeader, at the end of its
// header block. net/http exposes :scheme nowhere, and schemeConn goes once net/http puts it
// on the Request (golang/go#68365).
type schemeConn struct {
	net.Conn
	br     *bufio.Reader
	dec    *hpack.Decoder
	scheme string
	out    []byte
	outPos int
	maxStr int

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
	desync  bool
	// inline adds the field at the end of the fragment of the frame, trail in a CONTINUATION
	// after it, when the frame would grow past h2MaxReadFrameSize.
	inline bool
	trail  bool
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

func (c *schemeConn) CloseWrite() error { return closeWrite(c.Conn) }

func (c *schemeConn) Abort() { abort(c.Conn) }

func (c *schemeConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if c.outPos < len(c.out) {
			n := copy(p, c.out[c.outPos:])
			c.outPos += n
			if c.outPos == len(c.out) {
				c.out, c.outPos = c.out[:0], 0
			}
			return n, nil
		}
		switch c.state {
		case schemeUndecided:
			if err := c.decide(); err != nil {
				return 0, err
			}
			continue
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

// decide reads the frames of an HTTP/2 connection and passes any other through. In plaintext
// it decides on the first byte that leaves the preface, so a short HTTP/1.1 request is never
// delayed.
func (c *schemeConn) decide() error {
	if cs, ok := c.Conn.(connectionStater); ok && cs.ConnectionState().NegotiatedProtocol != "h2" {
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

// A frame net/http refuses as malformed stops the parsing, and the rest of the connection
// passes through unread.
func (c *schemeConn) nextFrame() error {
	h, err := c.br.Peek(9)
	if err != nil {
		return err
	}
	length := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
	typ, flags := h[3], h[4]
	stream := binary.BigEndian.Uint32(h[5:9]) & 0x7fffffff

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
		if fragStart > fragEnd {
			c.state = schemeRaw
			return nil
		}
		c.inBlock, c.stream = true, stream
		c.request = stream > c.last
		if c.request {
			c.last, c.scheme = stream, ""
		}
		c.dec.SetEmitEnabled(c.request)
	} else if !c.inBlock || stream != c.stream {
		c.state = schemeRaw
		return nil
	}

	c.out = append(c.out, h...)
	_, _ = c.br.Discard(9)
	c.end = flags&h2FlagEndHeaders != 0
	// net/http ends the connection on a CONTINUATION after an invalid or a truncated field
	// list, where the same list in one frame is a stream error.
	if c.end && c.request {
		if grown := length + len(schemeFieldNone); grown <= h2MaxReadFrameSize {
			hdr := c.out[len(c.out)-9:]
			hdr[0], hdr[1], hdr[2] = byte(grown>>16), byte(grown>>8), byte(grown) //nolint:gosec // at most h2MaxReadFrameSize
			c.inline = true
		} else {
			c.out[len(c.out)-5] &^= h2FlagEndHeaders
			c.trail = true
		}
	}
	c.left, c.pos, c.fragStart, c.fragEnd = length, 0, fragStart, fragEnd
	c.advance()
	return nil
}

func (c *schemeConn) readPayload(p []byte) (int, error) {
	want := min(len(p), c.left)
	if c.inline {
		want = min(want, c.fragEnd-c.pos)
	}
	n, err := c.br.Read(p[:want])
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

// advance adds the field once the fragment of the frame ending a request block is read, and
// ends the block with the frame.
func (c *schemeConn) advance() {
	if c.inline && c.pos == c.fragEnd {
		c.inline = false
		c.closeBlock()
		c.out = append(c.out, c.field()...)
	}
	if c.left > 0 || !c.inBlock || !c.end {
		return
	}
	c.inBlock = false
	if !c.request {
		c.closeBlock()
		return
	}
	if c.trail {
		c.trail = false
		c.closeBlock()
		field := c.field()
		c.out = append(c.out, 0, 0, byte(len(field)), h2FrameContinuation, h2FlagEndHeaders) //nolint:gosec // a field is 15 bytes
		c.out = binary.BigEndian.AppendUint32(c.out, c.stream)
		c.out = append(c.out, field...)
	}
}

func (c *schemeConn) closeBlock() {
	if !c.desync && c.dec.Close() != nil {
		c.desync = true
	}
}

// field returns the field for the request block just decoded. After a decoding error the
// table can no longer be mirrored, so every later request gets schemeFieldNone.
func (c *schemeConn) field() string {
	if !c.desync {
		switch c.scheme {
		case "http":
			return schemeFieldHTTP
		case "https":
			return schemeFieldHTTPS
		}
	}
	return schemeFieldNone
}

// schemeListener wraps each connection a front accepts in a schemeConn.
type schemeListener struct {
	net.Listener
	maxHeaderBytes int
}

func (l schemeListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newSchemeConn(c, l.maxHeaderBytes), nil
}

// takeScheme returns the scheme of an HTTP/2 or HTTP/3 request and removes schemeHeader from
// it. It returns "" for an HTTP/1.1 request, whose absolute target has the scheme.
//
// The last schemeHeader is the one the schemeConn added, unless the request opened a stream
// below the last one, which net/http accepts and the schemeConn takes for trailers.
func takeScheme(r *http.Request) string {
	if r.ProtoMajor < 2 {
		return ""
	}
	if sess := sessionFromRequest(r); sess != nil && sess.hasSchemeField {
		vs := r.Header[schemeHeader]
		if len(vs) == 0 {
			return ""
		}
		code := vs[len(vs)-1]
		if len(vs) == 1 {
			delete(r.Header, schemeHeader)
		} else {
			r.Header[schemeHeader] = vs[:len(vs)-1]
		}
		switch code {
		case "h":
			return "http"
		case "s":
			return "https"
		}
		return ""
	}
	// quic-go does not expose :scheme either, nor does the server edge is mounted on, so the
	// scheme is the connection's. A client sending "http" over TLS is forwarded as "https".
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
