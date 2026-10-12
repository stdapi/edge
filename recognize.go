// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bytes"
	"errors"
	"net"
	"os"
	"slices"
	"time"
)

// negotiateALPN returns the protocols to offer a client, in the order the proxy prefers them.
// An HTTP protocol wins when the client offers one, and otherwise the client's own first
// choice is echoed back, which is what an origin supporting everything would do.
//
// An offer with nothing in it leaves ALPN unset, which falls back to HTTP/1.1 rather than
// failing the handshake with no_application_protocol.
func negotiateALPN(offered []string, over Kind) []string {
	if len(offered) == 0 {
		return nil
	}
	supported := httpOver(over)
	for _, proto := range offered {
		if slices.Contains(supported, proto) {
			// The client offered HTTP. Everything it offered that the proxy speaks is
			// echoed, in the client's own preference order.
			out := make([]string, 0, len(offered))
			for _, p := range offered {
				if slices.Contains(supported, p) {
					out = append(out, p)
				}
			}
			return out
		}
	}
	// No HTTP in the offer. The connection is a byte stream whatever the label says, and
	// echoing the client's first choice keeps the label the one it asked for.
	return offered[:1]
}

// httpOver lists the HTTP protocols a transport can carry. h3 does not run on TCP and h2 does
// not run on QUIC, so a peer naming one on the wrong transport has not named HTTP.
func httpOver(over Kind) []string {
	if over == KindQUIC {
		return []string{"h3"}
	}
	return []string{"h2", "http/1.1"}
}

// candidatesForALPN reports the kinds that may serve a connection speaking this protocol,
// most refined first. An empty protocol means the client offered none, which says nothing, so
// the caller sniffs instead.
//
// The traffic says what a connection is; the tree says at which granularity it is served. An
// HTTP connection can be served request by request or as the byte stream it runs on, and both
// see it in the clear, so both are candidates and the entries registered decide. A granularity
// where the handler would see ciphertext the proxy holds the keys for is never a candidate:
// that is a relay nothing observes, which is the one thing this proxy does not do.
func candidatesForALPN(alpn string, over Kind) []Kind {
	if alpn == "" {
		return nil
	}
	if slices.Contains(httpOver(over), alpn) {
		return []Kind{KindHTTP, over}
	}
	return []Kind{over}
}

// sniffStreamCandidates reports the kinds that may serve a stream, read off its first bytes.
// It consumes nothing: the peek leaves the bytes for whatever ends up serving the connection.
//
// HTTP is what it recognizes, and everything else is a byte stream and nothing more. The
// recognizer reads the traffic and nothing else, never the tree, so what a connection is can
// never depend on what happened to be registered when it arrived.
func sniffStreamCandidates(conn *peekConn, wait time.Duration) []Kind {
	if wait > 0 {
		// A protocol whose server speaks first sends nothing here. The wait is what tells it
		// apart from a client that is merely slow, and it is only ever paid once.
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	}

	if looksLikeHTTPRequestLine(conn) {
		return []Kind{KindHTTP, KindTCP}
	}
	return []Kind{KindTCP}
}

// requestLinePeek bounds how much of a first line the sniff reads. A request target longer
// than this is not what tells HTTP from anything else.
const requestLinePeek = 512

// looksLikeHTTPRequestLine reports whether what is waiting on conn starts with an HTTP/1.x
// request line, "method SP target SP HTTP/1.d". The HTTP/2 connection preface is one too, its
// method being PRI and its version 2.0, so both are recognized by the same scan.
//
// What is already buffered is scanned first, and the scan waits for one more byte at a time.
// A short first write that is not HTTP is decided on the spot.
func looksLikeHTTPRequestLine(conn *peekConn) bool {
	n := max(conn.Buffered(), 1)
	for {
		b, err := conn.Peek(n)
		if len(b) > 0 {
			switch verdict := scanRequestLine(b); verdict {
			case sniffYes:
				return true
			case sniffNo:
				return false
			}
		}
		if err != nil {
			// Short of a full line, and nothing more is coming: a timeout means the peer is
			// waiting to be spoken to, which HTTP never does.
			return false
		}
		if n >= requestLinePeek {
			return false
		}
		n = min(max(n+1, conn.Buffered()), requestLinePeek)
	}
}

type sniffVerdict uint8

const (
	sniffMore sniffVerdict = iota
	sniffYes
	sniffNo
)

// scanRequestLine reads a token method and a space, then reports sniffYes at the first later
// space followed by an HTTP version. A target containing a space is still HTTP, so that the server
// replies 400 to the invalid request line, RFC 9112 section 3.2.
func scanRequestLine(b []byte) sniffVerdict {
	// method
	i := 0
	for i < len(b) && b[i] != ' ' {
		if !isTokenByte(b[i]) {
			return sniffNo
		}
		i++
	}
	if i == len(b) {
		return sniffMore
	}
	if i == 0 {
		return sniffNo
	}

	// target and version, up to the end of the line
	for i++; i < len(b); i++ {
		switch c := b[i]; {
		case c == ' ':
			switch scanVersion(b[i+1:]) {
			case sniffYes:
				return sniffYes
			case sniffMore:
				return sniffMore
			}
		case c < ' ' && c != '\t', c == 0x7f:
			// A control byte, the end of a line without a version among them.
			return sniffNo
		}
	}
	return sniffMore
}

// scanVersion reports whether b starts with "HTTP/", a digit, "." and a digit.
func scanVersion(b []byte) sniffVerdict {
	const version = "HTTP/"
	if len(b) >= len(version)+3 {
		if string(b[:len(version)]) == version && isDigit(b[5]) && b[6] == '.' && isDigit(b[7]) {
			return sniffYes
		}
		return sniffNo
	}
	for i, c := range b {
		if i < len(version) && c != version[i] || i == len(version) && !isDigit(c) || i == len(version)+1 && c != '.' {
			return sniffNo
		}
	}
	return sniffMore
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// isTokenByte reports whether b may appear in an HTTP token (RFC 9110 section 5.6.2).
func isTokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// peekAuthority returns the authority of the request opening conn, found within limit bytes
// and consuming nothing, and the read error that cut the scan short. The HTTP/2 preface has no
// authority, and the client may send no request before it receives the server's SETTINGS, RFC
// 9113 section 3.4, which nothing sends while its bytes are peeked.
func peekAuthority(conn *peekConn, limit int) (string, error) {
	s := lineScanner{conn: conn, limit: min(limit, conn.max)}
	s.b, _ = conn.Peek(min(conn.Buffered(), s.limit))

	line, ok := s.next()
	if !ok {
		return "", s.err
	}
	method, target, ok := splitRequestLine(line)
	if !ok {
		return "", nil
	}
	if string(method) == "CONNECT" && target[0] != '/' {
		return string(target), nil
	}
	if authority, absolute := absoluteFormAuthority(target); absolute && len(authority) > 0 {
		return string(authority), nil
	}
	for {
		if line, ok = s.next(); !ok {
			return "", s.err
		}
		if len(line) == 0 {
			return "", nil
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Obsolete line folding, the tail of the line before.
			continue
		}
		name, value, ok := splitHeader(line)
		if !ok {
			return "", nil
		}
		if bytes.EqualFold(name, []byte("host")) {
			return string(value), nil
		}
	}
}

// lineScanner returns the lines of a header block as they arrive, never scanning a byte twice.
type lineScanner struct {
	conn  *peekConn
	err   error
	b     []byte
	off   int
	limit int
}

func (s *lineScanner) next() ([]byte, bool) {
	from := s.off
	for {
		if i := bytes.IndexByte(s.b[from:], '\n'); i >= 0 {
			line := s.b[s.off : from+i]
			s.off = from + i + 1
			if n := len(line); n > 0 && line[n-1] == '\r' {
				line = line[:n-1]
			}
			return line, true
		}
		from = len(s.b)
		if s.err != nil || from >= s.limit {
			return nil, false
		}
		b, err := s.conn.Peek(min(max(from+1, s.conn.Buffered()), s.limit))
		// What arrived before an error is all of the buffer, past the limit included.
		s.b, s.err = b[:min(len(b), s.limit)], err
	}
}

func splitRequestLine(line []byte) (method, target []byte, ok bool) {
	i := bytes.IndexByte(line, ' ')
	if i <= 0 {
		return nil, nil, false
	}
	rest := line[i+1:]
	j := bytes.IndexByte(rest, ' ')
	if j <= 0 {
		return nil, nil, false
	}
	return line[:i], rest[:j], true
}

// absoluteFormAuthority returns the authority of an absolute-form target, RFC 9112 section
// 3.2.2, userinfo dropped.
func absoluteFormAuthority(target []byte) ([]byte, bool) {
	i := bytes.IndexByte(target, ':')
	if i <= 0 || len(target) < i+3 || target[i+1] != '/' || target[i+2] != '/' || !isAlpha(target[0]) {
		return nil, false
	}
	for _, c := range target[1:i] {
		if !isAlpha(c) && !isDigit(c) && c != '+' && c != '-' && c != '.' {
			return nil, false
		}
	}
	authority := target[i+3:]
	if j := bytes.IndexAny(authority, "/?#"); j >= 0 {
		authority = authority[:j]
	}
	if j := bytes.LastIndexByte(authority, '@'); j >= 0 {
		authority = authority[j+1:]
	}
	return authority, true
}

// splitHeader returns the name and the value of a header line, false for one the server would
// refuse.
func splitHeader(line []byte) (name, value []byte, ok bool) {
	i := bytes.IndexByte(line, ':')
	if i <= 0 {
		return nil, nil, false
	}
	name = line[:i]
	for _, c := range name {
		if !isTokenByte(c) {
			return nil, nil, false
		}
	}
	return name, bytes.Trim(line[i+1:], " \t"), true
}

func isAlpha(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }

// isTimeout reports whether err is a deadline rather than a failure.
func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	ne, ok := errors.AsType[net.Error](err)
	return ok && ne.Timeout()
}
