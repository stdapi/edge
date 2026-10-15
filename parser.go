// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"fmt"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"

	"github.com/stdapi/edge/internal/stringsutil"
)

// pattern is a parsed pattern: an authority, and for an interceptor a path after it. key is
// what the radix tree is indexed on, the pattern minus its port, with an address host in
// its encoded form.
//
// The port is deliberately not a tree dimension: folded into the hostname it would turn "any
// port" into a host no request could ever match. It is kept beside the key and compared once
// the walk has reached a leaf, which is what lets two entries share a key and differ only by
// the port they name.
//
// The scheme is not in a pattern at all. Folding it into the key would put it ahead of the
// path in the priority order, so a scheme qualified parameter would outrank a static segment.
// It is expressed with [WithScheme], which attaches a matcher.
type pattern struct {
	str  string
	key  string
	host string
	// port is the port the pattern restricts to, empty when it matches every port. It is
	// never part of key.
	port string
	path string
	// prefix is set when the host is an address, an exact one being full length. It routes
	// the pattern to the address root, where key holds the encoded form, not the host text.
	prefix netip.Prefix
	tokens []token
	// pathStart is the index in tokens where the path begins, len(tokens) for an authority
	// pattern. The host tokens end on the node carrying the admission.
	pathStart        int
	optionalCatchAll bool
	catchAll         bool
}

// parsePattern parses the pattern of one kind. A kind that routes each message of a
// connection is written host[:port]/path, one that routes whole connections or datagrams is
// written host[:port] alone, so a pattern always says which of the two key spaces it lands in.
//
// The hostname is required either way. An entry admits the authority it matches, so one
// without a hostname would admit nothing and leave a handler no traffic can reach. Matching
// every hostname is spelled with a wildcard, and every address with a zero-length range, so
// both say so.
func (p *Proxy) parsePattern(raw string, kind Kind) (pattern, int, error) {
	if !kind.requiresPath() {
		return p.parseAuthorityPattern(raw)
	}

	if len(raw) == 0 {
		return pattern{}, 0, fmt.Errorf("%w: empty pattern", ErrInvalidEntry)
	}

	endHost := hostPathSplit(raw)
	if endHost > 0 && raw[endHost-1] == ':' && strings.HasPrefix(raw[endHost:], "//") {
		return pattern{}, 0, &PatternError{
			Pattern: raw,
			Type:    "hostname",
			Reason:  "syntax",
			Hint:    "a pattern is a hostname and a path, it carries no scheme",
			Start:   0,
			End:     endHost + 2,
		}
	}

	if endHost == -1 {
		return pattern{}, 0, &PatternError{
			Pattern: raw,
			Type:    "hostname",
			Reason:  "syntax",
			Hint:    "missing trailing '/' after hostname",
			Start:   len(raw),
			End:     len(raw),
		}
	}

	path := raw[endHost:]
	host := raw[:endHost]

	if host == "" {
		return pattern{}, 0, &PatternError{
			Pattern: raw,
			Type:    "hostname",
			Reason:  "syntax",
			Hint:    "a pattern starts with the authority it admits, write +{any} to match every hostname",
			Start:   0,
			End:     1,
		}
	}

	ah, pe := p.parseAuthorityHost(host)
	if pe != nil {
		pe.Pattern = raw
		pe.Type = "hostname"
		return pattern{}, 0, pe
	}

	// "10.0.0.0/8" reads as an address and a path here, and as a range everywhere else.
	// Only a spelling whose range reading is valid is refused: unbracketed, masked, and
	// shorter than a full address. Brackets or a non-zero bit past the length say path.
	if ah.prefix.IsValid() && raw[0] != '[' {
		addr := ah.prefix.Addr()
		if segEnd, n, ok := looksLikePrefixLen(path, addr.BitLen()); ok &&
			n < addr.BitLen() && netip.PrefixFrom(addr, n).Masked().Addr() == addr {
			return pattern{}, 0, &PatternError{
				Pattern: raw,
				Type:    "hostname",
				Reason:  "syntax",
				Hint:    "ambiguous with an address range, which is written in brackets: [" + ah.host + path[:segEnd] + "]" + path[segEnd:],
				Start:   0,
				End:     endHost + segEnd,
			}
		}
	}

	pathTokens, optCatchAll, paramCount, pe := p.parsePath(path, ah.params)
	if pe != nil {
		pe.Pattern = raw
		pe.Type = "path"
		pe.Start += endHost
		pe.End += endHost
		return pattern{}, 0, pe
	}

	tokens := make([]token, 0, len(ah.tokens)+len(pathTokens))
	tokens = append(tokens, ah.tokens...)
	tokens = append(tokens, pathTokens...)

	// The key drops the port and the brackets of an address literal, and an address host is
	// keyed on its encoded form, so a pattern naming a port and one naming none land on the
	// same node and are told apart by their port alone.
	return pattern{
		str:              raw,
		key:              ah.key + path,
		host:             ah.host,
		port:             ah.port,
		path:             path,
		prefix:           ah.prefix,
		tokens:           tokens,
		pathStart:        len(ah.tokens),
		optionalCatchAll: optCatchAll,
		catchAll:         pathTokens[len(pathTokens)-1].typ == nodeWildcard,
	}, paramCount, nil
}

// hostPathSplit returns the index of the '/' separating the host from the path, or -1. The
// scan is bracket aware, so the '/' inside a bracketed address range never counts as the
// split.
func hostPathSplit(raw string) int {
	start := 0
	if len(raw) > 0 && raw[0] == '[' {
		if end := strings.IndexByte(raw, ']'); end >= 0 {
			start = end
		}
	}
	i := strings.IndexByte(raw[start:], '/')
	if i < 0 {
		return -1
	}
	return start + i
}

// looksLikePrefixLen reports whether the first segment of path spells a prefix length up to
// bitLen, the way the length of an unbracketed range would parse. It also returns the index
// just past that segment, so a hint brackets the right part, and the length itself, so the
// caller decides what that length means.
func looksLikePrefixLen(path string, bitLen int) (segEnd, n int, ok bool) {
	if len(path) < 2 || path[0] != '/' {
		return 0, 0, false
	}
	seg := path[1:]
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg = seg[:i]
	}
	if len(seg) == 0 || len(seg) > 3 {
		return 0, 0, false
	}
	for i := range len(seg) {
		c := seg[i]
		if c < '0' || c > '9' {
			return 0, 0, false
		}
		n = n*10 + int(c-'0')
	}
	return 1 + len(seg), n, n <= bitLen
}

// parseAuthorityHost parses the authority portion of a pattern: a hostname, an address
// literal or a bracketed address range, optionally followed by a port. An interceptor
// pattern and an authority pattern name an authority the same way, so they share this and
// differ only in what may follow.
//
// An address literal is written the way an authority carries it, which for IPv6 means
// bracketed. The brackets tell the colons of the address from the one before a port, and a
// host that could be spelled two ways would reach the tree under one key from two patterns.
// A range is bracketed for its '/', which would otherwise read as the start of a path.
func (p *Proxy) parseAuthorityHost(raw string) (authorityHost, *PatternError) {
	host, port, pe := splitHostPortPattern(raw)
	if pe != nil {
		return authorityHost{}, pe
	}
	if host == "" {
		return authorityHost{}, newPatternError("syntax", 0, len(raw), "missing host")
	}

	if strings.IndexByte(host, '/') >= 0 {
		// An address range, which splitHostPortPattern only lets through bracketed.
		prefix, rpe := canonicalRange(host, len(raw))
		if rpe != nil {
			return authorityHost{}, rpe
		}
		return addressHost(host, port, prefix), nil
	}

	if addr, ok := hostAddr(host); ok {
		// An address is not a domain name: it has no labels to validate, no case to fold and
		// no parameter to capture. It must be written the way a request will present it,
		// since two spellings of one address would reach the tree from two patterns.
		if canonical := addr.String(); canonical != host {
			return authorityHost{}, newPatternError("syntax", 0, len(raw),
				"non-canonical address literal, write "+bracketed(canonical))
		}
		return addressHost(host, port, netip.PrefixFrom(addr, addr.BitLen())), nil
	}

	tokens, params, pe := p.parseHostname(host)
	if pe != nil {
		return authorityHost{}, pe
	}
	return authorityHost{host: host, key: host, port: port, tokens: tokens, params: params}, nil
}

// authorityHost is the parsed authority of a pattern: the host as written, brackets and
// port dropped, and the tree key it is indexed under, which is the encoded prefix when the
// host is an address and the host itself otherwise.
type authorityHost struct {
	host   string
	key    string
	port   string
	prefix netip.Prefix
	tokens []token
	params int
}

func addressHost(host, port string, prefix netip.Prefix) authorityHost {
	key := prefixKey(prefix)
	return authorityHost{
		host:   host,
		key:    key,
		port:   port,
		prefix: prefix,
		tokens: []token{{typ: nodeStatic, value: key, hsplit: true}},
	}
}

// canonicalRange parses host as an address range and refuses every spelling but the
// canonical one: masked, shorter than a full address, and written the way the prefix prints
// itself. rawLen sizes the error spans.
func canonicalRange(host string, rawLen int) (netip.Prefix, *PatternError) {
	prefix, err := netip.ParsePrefix(host)
	if err != nil {
		return netip.Prefix{}, newPatternError("syntax", 0, rawLen, "invalid address range")
	}
	if prefix.Addr().Is4In6() {
		// A mapped range names IPv4 addresses, which have a spelling of their own.
		if bits := prefix.Bits() - 96; bits >= 0 {
			unmapped := netip.PrefixFrom(prefix.Addr().Unmap(), bits).Masked()
			if bits == unmapped.Addr().BitLen() {
				return netip.Prefix{}, newPatternError("syntax", 0, rawLen,
					"a full-length prefix is an address, write "+bracketed(unmapped.Addr().String()))
			}
			return netip.Prefix{}, newPatternError("syntax", 0, rawLen,
				"non-canonical address range, write ["+unmapped.String()+"]")
		}
		return netip.Prefix{}, newPatternError("syntax", 0, rawLen,
			"a mapped address range has no canonical form, write the IPv4 range or a wider IPv6 prefix")
	}
	if masked := prefix.Masked(); masked != prefix {
		return netip.Prefix{}, newPatternError("syntax", 0, rawLen,
			"non-canonical address range, the bits past the prefix must be zero, write ["+masked.String()+"]")
	}
	if prefix.Bits() == prefix.Addr().BitLen() {
		return netip.Prefix{}, newPatternError("syntax", 0, rawLen,
			"a full-length prefix is an address, write "+bracketed(prefix.Addr().String()))
	}
	if canonical := prefix.String(); canonical != host {
		return netip.Prefix{}, newPatternError("syntax", 0, rawLen,
			"non-canonical address range, write ["+canonical+"]")
	}
	return prefix, nil
}

// bracketed renders an address literal the way a pattern must spell it.
func bracketed(addr string) string {
	if strings.IndexByte(addr, ':') >= 0 {
		return "[" + addr + "]"
	}
	return addr
}

// parseAuthorityPattern parses an authority pattern: a host with an optional port and no
// path. The tokens stop at the host, so the key holds no '/' while an interceptor key
// always does, in the address root as in the name root. That is what lets both kinds share
// a root without ever colliding: the walk that answers a CONNECT cannot reach an
// interceptor, and the walk that answers a request cannot reach an authority.
func (p *Proxy) parseAuthorityPattern(raw string) (pattern, int, error) {
	if len(raw) == 0 {
		return pattern{}, 0, fmt.Errorf("%w: empty authority", ErrInvalidAuthority)
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		// The decision to intercept is taken before the connection is established, when
		// nothing has revealed whether it carries TLS. A scheme here would be a promise
		// the authority entry cannot keep.
		return pattern{}, 0, &PatternError{
			Pattern: raw,
			Type:    "authority",
			Reason:  "syntax",
			Hint:    "an authority pattern is evaluated before the connection exists, when no scheme is known",
			Start:   0,
			End:     i + 3,
		}
	}
	if i := hostPathSplit(raw); i >= 0 {
		hint := "an authority pattern must not carry a path"
		if addr, ok := hostAddr(raw[:i]); ok {
			// The hint only names a spelling the parser accepts: a valid, shorter-than-full
			// prefix length over a masked base, and nothing after it.
			if segEnd, n, isBits := looksLikePrefixLen(raw[i:], addr.BitLen()); isBits && i+segEnd == len(raw) {
				switch {
				case n == addr.BitLen():
					hint = "a full-length prefix is an address, write " + bracketed(addr.String())
				case netip.PrefixFrom(addr, n).Masked().Addr() == addr:
					hint = "an address range is written in brackets: [" + raw + "]"
				}
			}
		}
		return pattern{}, 0, &PatternError{
			Pattern: raw,
			Type:    "authority",
			Reason:  "syntax",
			Hint:    hint,
			Start:   i,
			End:     len(raw),
		}
	}

	ah, pe := p.parseAuthorityHost(raw)
	if pe != nil {
		pe.Pattern = raw
		pe.Type = "authority"
		return pattern{}, 0, pe
	}

	return pattern{
		str:       raw,
		key:       ah.key,
		host:      ah.host,
		port:      ah.port,
		prefix:    ah.prefix,
		tokens:    ah.tokens,
		pathStart: len(ah.tokens),
	}, ah.params, nil
}

// splitHostPortPattern splits an authority pattern into its host and port. The host of an
// IPv6 literal or of a range is returned without its brackets.
func splitHostPortPattern(authority string) (host, port string, pe *PatternError) {
	if authority == "" {
		return "", "", nil
	}

	if authority[0] == '[' {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return "", "", newPatternError("syntax", 0, len(authority), "unbalanced brackets in IPv6 literal")
		}
		host = authority[1:end]
		switch rest := authority[end+1:]; {
		case rest == "":
		case rest[0] == ':':
			port, pe = parsePort(rest[1:], end+2)
			if pe != nil {
				return "", "", pe
			}
		default:
			return "", "", newPatternError("syntax", end+1, len(authority), "illegal character after IPv6 literal")
		}
		if strings.IndexByte(host, '/') >= 0 {
			// An address range. Validity and canonical form are parseAuthorityHost's job,
			// only the bracket grammar is decided here.
			return host, port, nil
		}
		// The inner text is returned as written. Refusing a non-canonical literal is
		// parseAuthorityHost's job, and rewriting one here would let two spellings of the
		// same address reach the tree under one key.
		addr, ok := hostAddr(host)
		if !ok {
			return "", "", newPatternError("syntax", 1, end, "invalid IPv6 literal")
		}
		if canonical := addr.String(); strings.IndexByte(canonical, ':') < 0 {
			// An IPv4-mapped literal unmaps to an address the brackets do not belong to.
			return "", "", newPatternError("syntax", 0, end+1,
				"non-canonical address literal, write "+canonical)
		}
		return host, port, nil
	}

	// A regexp constraint holds its own colons, so the port separator is looked for past the
	// last brace. An address literal never carries a brace, which is what keeps the check
	// below sound: reaching it means the authority is unparameterized.
	start := afterLastBrace(authority)
	k := strings.LastIndexByte(authority[start:], ':')
	if k < 0 {
		return authority, "", nil
	}
	i := start + k
	if start == 0 && strings.IndexByte(authority[:i], ':') >= 0 {
		return "", "", newPatternError("syntax", 0, len(authority), "IPv6 literal must be bracketed")
	}
	port, pe = parsePort(authority[i+1:], i+1)
	if pe != nil {
		return "", "", pe
	}
	return authority[:i], port, nil
}

// patternKey returns the tree key of a raw pattern and whether it belongs to the address
// root: the pattern minus its port, minus the brackets of an address literal, and with an
// address host in its encoded form. A lookup by pattern has to walk on this rather than on
// what the caller wrote, since two patterns differing only by their port share one key.
//
// A malformed pattern is returned unchanged. It indexes nothing, so the walk finds nothing,
// which is the answer a lookup by an unregistrable pattern deserves.
func patternKey(raw string) (string, bool) {
	host, path := raw, ""
	if i := hostPathSplit(raw); i >= 0 {
		host, path = raw[:i], raw[i:]
	}
	h, port, pe := splitHostPortPattern(host)
	if pe != nil {
		return raw, false
	}
	if prefix, ok := hostPrefix(h); ok {
		return prefixKey(prefix) + path, true
	}
	if port == "" && h == host {
		return raw, false
	}
	return h + path, false
}

// afterLastBrace returns the index just past the last closing brace of s, or zero when it
// carries none. A parameter's regexp constraint may hold a colon, so any scan looking for a
// port separator has to start here rather than at the beginning.
func afterLastBrace(s string) int {
	if i := strings.LastIndexByte(s, '}'); i >= 0 {
		return i + 1
	}
	return 0
}

func parsePort(s string, offset int) (string, *PatternError) {
	if s == "" {
		return "", newPatternError("syntax", offset, offset, "missing port after ':'")
	}
	// Characters come before length and range, so a port that is not a number at all is
	// reported as such. "{port}" is a plausible mistake, and answering "port out of range"
	// to it sends the reader looking in the wrong place.
	for i := range len(s) {
		if c := s[i]; c < '0' || c > '9' {
			return "", newPatternError("syntax", offset+i, offset+i+1, "illegal character in port")
		}
	}
	// Leading zeros would never match the canonical form seen on the wire.
	if s[0] == '0' {
		return "", newPatternError("syntax", offset, offset+len(s), "leading zero in port")
	}
	if len(s) > 5 {
		return "", newPatternError("constraint", offset, offset+len(s), "port out of range")
	}

	n := 0
	for i := range len(s) {
		n = n*10 + int(s[i]-'0')
	}
	if n > 65535 || n == 0 {
		return "", newPatternError("constraint", offset, offset+len(s), "port out of range")
	}
	return s, nil
}
func (p *Proxy) parseHostname(hostname string) ([]token, int, *PatternError) {
	var sb strings.Builder
	sb.Grow(len(hostname))
	tokens := make([]token, 0, 5)
	var (
		paramCount      int
		prevWild        bool
		sawWild         bool
		staticSinceWild int
		partLen         int
		totalLen        int
		labelStart      int
		last            = dotDelim
		nonNumeric      bool
	)

	i := 0
	for i < len(hostname) {
		c := hostname[i]

		switch c {
		case '{', '+':
			if sb.Len() > 0 {
				tokens = append(tokens, token{typ: nodeStatic, value: sb.String(), hsplit: true})
				sb.Reset()
			}
			isWild := c == '+'
			paramStart := i
			if isWild {
				i++
				if i >= len(hostname) || hostname[i] != '{' {
					return nil, 0, newPatternError("syntax", i-1, i, "missing parameter after delimiter")
				}
				if prevWild && staticSinceWild <= 1 {
					paramEnd := len(hostname)
					if idx := braceIndex(hostname[i+1:], 1); idx >= 0 {
						paramEnd = i + 1 + idx + 1
					}
					return nil, 0, newPatternError("syntax", i-1, paramEnd, "consecutive wildcard")
				}
			}
			name, re, n, pe := p.parseBrace(hostname[i:], dotDelim, false)
			if pe != nil {
				pe.Start += i
				pe.End += i
				return nil, 0, pe
			}
			paramCount++
			if paramCount > p.cfg.maxParams {
				return nil, 0, newPatternError("constraint", paramStart, i+n, "too many parameters")
			}

			kind := nodeParam
			if isWild {
				kind = nodeWildcard
				prevWild = true
				staticSinceWild = 0
			} else {
				prevWild = false
			}
			tokens = append(tokens, token{typ: kind, value: name, regexp: re, nested: isWild && sawWild})
			sawWild = sawWild || isWild
			i += n
			last = 0
			nonNumeric = true
			if i < len(hostname) && hostname[i] != '.' {
				return nil, 0, newPatternError("syntax", i, i+1, "illegal character after parameter")
			}

		case '*':
			if i+1 < len(hostname) && hostname[i+1] == '{' {
				paramEnd := len(hostname)
				if idx := braceIndex(hostname[i+2:], 1); idx >= 0 {
					paramEnd = i + 2 + idx + 1
				}
				return nil, 0, newPatternError("syntax", i, paramEnd, "optional wildcard allowed only as suffix")
			}
			return nil, 0, newPatternError("syntax", i, i+1, "illegal character in label")

		default:
			switch {
			case 'a' <= c && c <= 'z' || c == '_':
				nonNumeric = true
				partLen++
			case '0' <= c && c <= '9':
				partLen++
			case c == '-':
				if last == '.' {
					if i == 0 {
						return nil, 0, newPatternError("syntax", i, i+1, "label starts with '-'")
					}
					return nil, 0, newPatternError("syntax", i, i+1, "illegal character after '.'")
				}
				partLen++
				nonNumeric = true
			case c == '.':
				if last == '.' {
					if i == 0 {
						return nil, 0, newPatternError("syntax", i, i+1, "label starts with '.'")
					}
					return nil, 0, newPatternError("syntax", i-1, i+1, "illegal consecutive '.'")
				}
				if last == '-' {
					return nil, 0, newPatternError("syntax", i-1, i, "label ends with '-'")
				}
				if partLen > 63 {
					return nil, 0, newPatternError("constraint", labelStart, i, "label exceeds 63 characters")
				}
				totalLen += partLen + 1 // +1 counts the current dot.
				partLen = 0
				labelStart = i + 1
			case 'A' <= c && c <= 'Z':
				return nil, 0, newPatternError("syntax", i, i+1, "uppercase character in label")
			default:
				return nil, 0, newPatternError("syntax", i, i+1, "illegal character in label")
			}
			last = c
			sb.WriteByte(c)
			staticSinceWild++
			i++
		}
	}

	totalLen += partLen
	if last == '-' {
		return nil, 0, newPatternError("syntax", len(hostname)-1, len(hostname), "illegal trailing '-'")
	}
	if last == '.' {
		return nil, 0, newPatternError("syntax", len(hostname)-1, len(hostname), "illegal trailing '.'")
	}
	if !nonNumeric {
		return nil, 0, newPatternError("syntax", 0, len(hostname), "all numeric")
	}
	if partLen > 63 {
		return nil, 0, newPatternError("constraint", labelStart, len(hostname), "label exceeds 63 characters")
	}
	if totalLen > 253 {
		return nil, 0, newPatternError("constraint", 0, len(hostname), "exceeds 253 characters")
	}

	if sb.Len() > 0 {
		tokens = append(tokens, token{typ: nodeStatic, value: sb.String(), hsplit: true})
	}
	return tokens, paramCount, nil
}

func (p *Proxy) parsePath(path string, paramCount int) ([]token, bool, int, *PatternError) {
	var sb strings.Builder
	sb.Grow(len(path))
	tokens := make([]token, 0, 5)
	var (
		prevWild        bool
		sawWild         bool
		staticSinceWild int
		optCatchAll     bool
	)

	i := 0
	for i < len(path) {
		c := path[i]

		switch c {
		case '{', '+', '*':
			isOpt := c == '*'
			isWild := c == '+' || isOpt
			// The wildcard syntax requires an immediate '{'. A bare '+' or '*'
			// is a literal character (both may appear unescaped in a request path).
			if isWild && (i+1 >= len(path) || path[i+1] != '{') {
				sb.WriteByte(c)
				staticSinceWild++
				i++
				continue
			}
			if sb.Len() > 0 {
				tokens = append(tokens, token{typ: nodeStatic, value: sb.String()})
				sb.Reset()
			}
			paramStart := i
			if isWild {
				i++
				if prevWild && staticSinceWild <= 1 {
					paramEnd := len(path)
					if idx := braceIndex(path[i+1:], 1); idx >= 0 {
						paramEnd = i + 1 + idx + 1
					}
					return nil, false, 0, newPatternError("syntax", i-1, paramEnd, "consecutive wildcard")
				}
			}
			name, re, n, pe := p.parseBrace(path[i:], slashDelim, isOpt)
			if pe != nil {
				pe.Start += i
				pe.End += i
				if isOpt && pe.Reason == "regexp" {
					pe.Start = paramStart
				}
				return nil, false, 0, pe
			}
			paramCount++
			if paramCount > p.cfg.maxParams {
				return nil, false, 0, newPatternError("constraint", paramStart, i+n, "too many parameters")
			}

			kind := nodeParam
			if isWild {
				kind = nodeWildcard
				prevWild = true
				staticSinceWild = 0
			} else {
				prevWild = false
			}
			tokens = append(tokens, token{typ: kind, value: name, regexp: re, nested: isWild && sawWild})
			sawWild = sawWild || isWild
			i += n
			if isOpt {
				if i < len(path) {
					return nil, false, 0, newPatternError("syntax", paramStart, i, "optional wildcard allowed only as suffix")
				}
				optCatchAll = true
			}
			if i < len(path) && path[i] != '/' {
				return nil, false, 0, newPatternError("syntax", i, i+1, "illegal character after parameter")
			}

		case '%':
			// Escape sequences must use the canonical routing form. Any other encoding could never match a request
			// routing path (see stringsutil.NormalizeRawPath).
			if i+2 >= len(path) {
				return nil, false, 0, newPatternError("syntax", i, len(path), "invalid percent-encoding")
			}
			b, ok := stringsutil.DecodeHexPair(path[i+1], path[i+2])
			if !ok {
				return nil, false, 0, newPatternError("syntax", i, i+3, "invalid percent-encoding")
			}
			if stringsutil.IsUnreserved(b) {
				return nil, false, 0, newPatternError("syntax", i, i+3, "non-canonical percent-encoding, encodes an unreserved character")
			}
			if path[i+1] != stringsutil.UpperHex(path[i+1]) || path[i+2] != stringsutil.UpperHex(path[i+2]) {
				return nil, false, 0, newPatternError("syntax", i, i+3, "non-canonical percent-encoding, hex must be uppercase")
			}
			sb.WriteString(path[i : i+3])
			staticSinceWild += 3
			i += 3

		default:
			if isASCIIControl(c) {
				return nil, false, 0, newPatternError("syntax", i, i+1, "illegal control character")
			}
			// Literals may only use bytes that can appear unescaped in a request routing path.
			// Anything else could never match (see stringsutil.IsRoutableRaw).
			if !stringsutil.IsRoutableRaw(c) {
				switch c {
				case '}':
					return nil, false, 0, newPatternError("syntax", i, i+1, "unbalanced braces")
				case '?':
					return nil, false, 0, newPatternError("syntax", i, i+1, "illegal query delimiter in patterns")
				case '#':
					return nil, false, 0, newPatternError("syntax", i, i+1, "illegal fragment delimiter in patterns")
				}
				_, size := utf8.DecodeRuneInString(path[i:])
				return nil, false, 0, newPatternError("syntax", i, i+size, "character requires percent-encoding")
			}
			if c == '.' && i > 0 && path[i-1] == '/' {
				next := i + 1
				if next >= len(path) || path[next] == '/' {
					// "/." at end or "/./"
					end := next
					if next < len(path) {
						end = next + 1
					}
					return nil, false, 0, newPatternError("syntax", i-1, end, "unsafe dot segment")
				}
				if path[next] == '.' {
					afterDots := next + 1
					if afterDots >= len(path) || path[afterDots] == '/' {
						// "/.." at end or "/../"
						end := afterDots
						if afterDots < len(path) {
							end = afterDots + 1
						}
						return nil, false, 0, newPatternError("syntax", i-1, end, "unsafe dot segment")
					}
				}
			}
			sb.WriteByte(c)
			staticSinceWild++
			i++
		}
	}

	if sb.Len() > 0 {
		tokens = append(tokens, token{typ: nodeStatic, value: sb.String()})
	}
	return tokens, optCatchAll, paramCount, nil
}

func (p *Proxy) parseBrace(s string, delim byte, isOptional bool) (string, *regexp.Regexp, int, *PatternError) {
	// Skip s[0] (the opening '{') and start at nesting level 1 to account for it.
	idx := braceIndex(s[1:], 1)
	if idx == -1 {
		return "", nil, 0, newPatternError("syntax", 0, len(s), "unbalanced braces")
	}

	content := s[1 : 1+idx] // Everything between { and }.
	consumed := 1 + idx + 1 // { + content + }

	name := content
	var rawRegex string
	hasRegex := false
	colonIdx := -1
	if ci := strings.IndexByte(content, ':'); ci >= 0 {
		colonIdx = ci
		name = content[:colonIdx]
		rawRegex = content[colonIdx+1:]
		hasRegex = true
	}

	if len(name) > p.cfg.maxParamKeyBytes {
		return "", nil, 0, newPatternError("constraint", 1, 1+len(name), "key too large")
	}

	if len(name) == 0 {
		return "", nil, 0, newPatternError("parameter", 0, consumed, "missing name")
	}

	for j := 0; j < len(name); j++ {
		c := name[j]
		if isASCIIControl(c) {
			return "", nil, 0, newPatternError("parameter", 1+j, 1+j+1, "illegal control character in name")
		}
		switch c {
		case delim, '/', '*', '+', '{':
			return "", nil, 0, newPatternError("parameter", 1+j, 1+j+1, "illegal character in name")
		}
	}

	if !hasRegex {
		return name, nil, consumed, nil
	}

	if isOptional {
		return "", nil, 0, newPatternError("regexp", 0, consumed, "not allowed in optional wildcard")
	}

	for j := 0; j < len(rawRegex); j++ {
		if isASCIIControl(rawRegex[j]) {
			off := 1 + colonIdx + 1
			return "", nil, 0, newPatternError("regexp", off+j, off+j+1, "illegal control character")
		}
	}

	re, pe := p.compileParamRegexp(rawRegex, delim == dotDelim)
	if pe != nil {
		regexOffset := 1 + colonIdx + 1
		pe.Start += regexOffset
		pe.End += regexOffset
		return "", nil, 0, pe
	}
	return name, re, consumed, nil
}

// compileParamRegexp validates and compiles a regular expression constraint for a parameter.
// Hostnames are compiled with the ignoreCase flag since hostname matching is case-insensitive.
// Positions in the returned PatternError are relative to rawRegex.
func (p *Proxy) compileParamRegexp(rawRegex string, ignoreCase bool) (*regexp.Regexp, *PatternError) {
	if !p.cfg.allowRegexp {
		return nil, newPatternError("regexp", 0, len(rawRegex), "feature not enabled")
	}
	if rawRegex == "" {
		return nil, newPatternError("regexp", 0, 0, "missing expression")
	}

	// A source that is invalid on its own can still balance inside the wrapper
	// (e.g. "a)|(?:") and defeat the anchoring, so it must compile standalone.
	if _, err := syntax.Parse(rawRegex, syntax.Perl); err != nil {
		return nil, &PatternError{
			Reason: "regexp",
			Start:  0,
			End:    len(rawRegex),
			Hint:   err.Error(),
			err:    err,
		}
	}

	expr := "^(?:" + rawRegex + ")$"
	if ignoreCase {
		expr = "(?i)" + expr
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, &PatternError{
			Reason: "regexp",
			Start:  0,
			End:    len(rawRegex),
			Hint:   err.Error(),
			err:    err,
		}
	}
	if re.NumSubexp() > 0 {
		return nil, newPatternError("regexp", 0, len(rawRegex), "capture group, use (?:...) instead")
	}

	return re, nil
}

// isASCIIControl reports whether c is an ASCII control character: a C0 byte
// (0x00 to 0x1F) or DEL (0x7F).
func isASCIIControl(c byte) bool {
	return c < 0x20 || c == 0x7f
}

// braceIndex returns the index of the closing brace that balances an opening
// brace. It starts at startLevel opened brace.
func braceIndex(s string, startLevel int) int {
	level := startLevel

	for i := range len(s) {
		switch s[i] {
		case '{':
			level++
		case '}':
			if level--; level == 0 {
				return i
			}
		}
	}
	return -1
}
