// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"

	"github.com/fox-toolkit/edge/internal/stringsutil"
)

// pattern is a parsed interceptor pattern: a hostname followed by a path. key is what the radix
// tree is indexed on, which for an interceptor is the pattern itself, byte for byte.
//
// The scheme and the port are deliberately not part of an interceptor pattern. Neither is a tree
// dimension: folding a scheme into the key would put it ahead of the path in the priority
// order, so a scheme qualified parameter would outrank a static segment, and folding a port
// into the hostname would turn "any port" into a host that no request could ever match.
// They are expressed with [WithScheme] and [WithPort], which attach a matcher evaluated once
// the walk has reached a leaf.
type pattern struct {
	str  string
	key  string
	host string
	// port is set only for an interception rule, whose pattern is an authority and may
	// carry one. An interceptor pattern never does; it uses [WithPort].
	port             string
	path             string
	tokens           []token
	optionalCatchAll bool
	catchAll         bool
	endHost          int
}

// parsePattern parses an interceptor pattern of the form host/path. The hostname is required: a
// route arms the interception of the authority it names, and one that names none would arm
// nothing, leaving a handler registered that no connection can ever reach. Matching every
// authority is spelled with a wildcard, which says so.
func (p *Proxy) parsePattern(raw string) (pattern, int, error) {
	if len(raw) == 0 {
		return pattern{}, 0, fmt.Errorf("%w: empty pattern", ErrInvalidInterceptor)
	}

	if i := strings.Index(raw, "://"); i >= 0 {
		return pattern{}, 0, &PatternError{
			Pattern: raw,
			Type:    "hostname",
			Reason:  "syntax",
			Hint:    "an interceptor pattern is a hostname and a path, it carries no scheme",
			Start:   0,
			End:     i + 3,
		}
	}

	endHost := strings.IndexByte(raw, '/')
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

	host := raw[:endHost]
	path := raw[endHost:]

	if host == "" {
		return pattern{}, 0, &PatternError{
			Pattern: raw,
			Type:    "hostname",
			Reason:  "syntax",
			Hint:    "an interceptor pattern names the authority it intercepts, write +{any} to match every one",
			Start:   0,
			End:     1,
		}
	}

	hostTokens, paramCount, pe := p.parseInterceptorHostname(host)
	if pe != nil {
		pe.Pattern = raw
		pe.Type = "hostname"
		return pattern{}, 0, pe
	}

	pathTokens, optCatchAll, paramCount, pe := p.parsePath(path, paramCount)
	if pe != nil {
		pe.Pattern = raw
		pe.Type = "path"
		pe.Start += endHost
		pe.End += endHost
		return pattern{}, 0, pe
	}

	tokens := make([]token, 0, len(hostTokens)+len(pathTokens))
	tokens = append(tokens, hostTokens...)
	tokens = append(tokens, pathTokens...)

	return pattern{
		str:              raw,
		key:              raw,
		host:             host,
		path:             path,
		tokens:           tokens,
		endHost:          endHost,
		optionalCatchAll: optCatchAll,
		catchAll:         pathTokens[len(pathTokens)-1].typ == nodeWildcard,
	}, paramCount, nil
}

// parseInterceptorHostname parses the hostname half of an interceptor pattern.
//
// A port here is a mistake worth naming: the hostname is the tree key, and a port in it would
// make the interceptor unreachable rather than narrow, so it is refused instead of folded in.
func (p *Proxy) parseInterceptorHostname(host string) ([]token, int, *PatternError) {
	if host[0] == '[' {
		// Brackets exist in an authority to tell the colons of an address from the one
		// before a port. An interceptor pattern carries no port, so they separate nothing.
		end := strings.IndexByte(host, ']')
		if end > 0 {
			if canonical, ok := canonicalIP(host[1:end]); ok {
				return nil, 0, newPatternError("syntax", 0, len(host),
					"an interceptor pattern takes an address literal without brackets, write "+canonical)
			}
		}
		return nil, 0, newPatternError("syntax", 0, len(host), "illegal character in label")
	}

	if canonical, ok := canonicalIP(host); ok {
		// An address is not a domain name: it has no labels to validate, no case to fold
		// and no parameter to capture. It must be written the way a request will present
		// it, since the pattern is what the tree is indexed on.
		if canonical != host {
			return nil, 0, newPatternError("syntax", 0, len(host),
				"non-canonical address literal, write "+canonical)
		}
		return []token{{typ: nodeStatic, value: host, hsplit: true}}, 0, nil
	}

	// Only a colon outside every brace can be a port: inside one it belongs to a regexp
	// constraint, which parseHostname hands to parseBrace.
	start := afterLastBrace(host)
	if i := strings.IndexByte(host[start:], ':'); i >= 0 {
		return nil, 0, newPatternError("syntax", start+i, len(host),
			"a port is not part of an interceptor pattern")
	}

	return p.parseHostname(host)
}

// parseAuthorityPattern parses an authority pattern: a host with an optional port and no
// path. The tokens stop at the hostname, so the key holds no '/' while an interceptor key always
// does. That is what lets both live in one tree without ever colliding: the walk that
// answers a CONNECT cannot reach an interceptor, and the walk that answers a request cannot reach
// an authority.
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
	if i := strings.IndexByte(raw, '/'); i >= 0 {
		return pattern{}, 0, &PatternError{
			Pattern: raw,
			Type:    "authority",
			Reason:  "syntax",
			Hint:    "an authority pattern must not carry a path",
			Start:   i,
			End:     len(raw),
		}
	}

	offset := 0
	host, port, pe := splitHostPortPattern(raw)
	if pe != nil {
		pe.Pattern = raw
		pe.Type = "authority"
		pe.Start += offset
		pe.End += offset
		return pattern{}, 0, pe
	}
	if host == "" {
		return pattern{}, 0, &PatternError{
			Pattern: raw,
			Type:    "authority",
			Reason:  "syntax",
			Hint:    "missing host",
			Start:   0,
			End:     len(raw),
		}
	}

	var (
		hostTokens []token
		paramCount int
	)
	if canonical, ok := canonicalIP(host); ok {
		host = canonical
		hostTokens = []token{{typ: nodeStatic, value: host, hsplit: true}}
	} else {
		hostTokens, paramCount, pe = p.parseHostname(host)
		if pe != nil {
			pe.Pattern = raw
			pe.Type = "hostname"
			pe.Start += offset
			pe.End += offset
			return pattern{}, 0, pe
		}
	}

	return pattern{
		str:     raw,
		key:     host,
		host:    host,
		port:    port,
		tokens:  hostTokens,
		endHost: len(host),
	}, paramCount, nil
}

// splitHostPortPattern splits an authority into its host and port. The host of an IPv6
// literal is returned without its brackets so it matches the form the lookup is given.
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
		canonical, ok := canonicalIP(host)
		if !ok || !strings.Contains(canonical, ":") {
			return "", "", newPatternError("syntax", 1, end, "invalid IPv6 literal")
		}
		return canonical, port, nil
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

// afterLastBrace returns the index just past the last closing brace of s, or zero when it
// carries none. A parameter's regexp constraint may hold a colon, so any scan looking for a
// port separator has to start here rather than at the beginning.
func afterLastBrace(s string) int {
	if i := strings.LastIndexByte(s, '}'); i >= 0 {
		return i + 1
	}
	return 0
}

// canonicalIP reports whether host is an IP literal and returns the form the lookup will
// compare against: 127.000.000.001 and 127.0.0.1 are the same address but only one of them
// ever appears on the wire.
func canonicalIP(host string) (string, bool) {
	if host == "" {
		return "", false
	}
	// A domain name never starts with a digit-only label followed by a dot in a way that
	// parses as an address, so the cheap first-byte test authorities out the common case.
	if c := host[0]; (c < '0' || c > '9') && c != ':' {
		return "", false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", false
	}
	if addr.Zone() != "" {
		// A zone identifier is local to the host that wrote it and never matches a target.
		return "", false
	}
	return addr.Unmap().String(), true
}

func parsePort(s string, offset int) (string, *PatternError) {
	if s == "" {
		return "", newPatternError("syntax", offset, offset, "missing port after ':'")
	}
	// Characters come before length and range, so a port that is not a number at all is
	// reported as such. "{port}" is a plausible mistake, and answering "port out of range"
	// to it sends the reader looking in the wrong place.
	for i := 0; i < len(s); i++ {
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
	for i := 0; i < len(s); i++ {
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
			tokens = append(tokens, token{typ: kind, value: name, regexp: re})
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
			tokens = append(tokens, token{typ: kind, value: name, regexp: re})
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
			if c == '/' && i > 0 && path[i-1] == '/' && p.cfg.mergeSlash {
				return nil, false, 0, newPatternError("syntax", i-1, i+1, "consecutive '/' unreachable, slashes are merged before matching")
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

	for i := 0; i < len(s); i++ {
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
