// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser_KeyIsThePatternWithoutItsPort(t *testing.T) {
	p := testProxy(t)

	// Without a port, a name pattern is the key byte for byte.
	for _, raw := range []string{
		"api.stripe.com/v1/charges",
		"+{any}/v1/charges",
		"+{sub}.stripe.com/v1/{id}",
	} {
		pat, _, err := p.parsePattern(raw, KindHTTP)
		require.NoError(t, err, raw)
		assert.Equal(t, raw, pat.key, raw)
	}

	// With one, the key drops it, so a pattern naming a port and one naming none land on the
	// same node and are told apart by the port alone. An address host is keyed on its encoded
	// form, brackets and port dropped the same way.
	loKey := prefixKey(netip.PrefixFrom(netip.MustParseAddr("127.0.0.1"), 32))
	v6Key := prefixKey(netip.PrefixFrom(netip.MustParseAddr("::1"), 128))
	for _, tc := range []struct{ raw, key, port string }{
		{"api.stripe.com:8443/v1/charges", "api.stripe.com/v1/charges", "8443"},
		{"127.0.0.1/health", loKey + "/health", ""},
		{"127.0.0.1:8080/health", loKey + "/health", "8080"},
		{"[::1]:8080/health", v6Key + "/health", "8080"},
		{"[::1]/health", v6Key + "/health", ""},
	} {
		pat, _, err := p.parsePattern(tc.raw, KindHTTP)
		require.NoError(t, err, tc.raw)
		assert.Equal(t, tc.key, pat.key, tc.raw)
		assert.Equal(t, tc.port, pat.port, tc.raw)
		assert.Equal(t, tc.raw, pat.str, tc.raw)
		key, _ := patternKey(tc.raw)
		assert.Equal(t, tc.key, key, tc.raw)
	}
}
func TestParser_SchemeIsRefusedInAnInterceptorPattern(t *testing.T) {
	p := testProxy(t, WithRegexpParam(true))

	for _, pattern := range []string{"https://api.test/v1", "http://api.test/v1"} {
		_, err := p.Add(pattern, noopHandler, WithMethods[HTTP](http.MethodGet))
		var pe *PatternError
		require.ErrorAs(t, err, &pe, pattern)
		assert.Contains(t, pe.Error(), "it carries no scheme",
			"the error for %q must name what is refused", pattern)
		assert.Equal(t, strings.Index(pattern, "//")+2, pe.End, pattern)
	}

	for _, pattern := range []string{"api.test/wayback/http://x.test", "api.test/foo/z+{args:///}/bar"} {
		_, err := p.Add(pattern, noopHandler)
		require.NoError(t, err, pattern)
	}

	// A port, on the other hand, is part of the pattern.
	for _, pattern := range []string{"api.test:8443/v1", "localhost:8080/api"} {
		_, err := p.Add(pattern, noopHandler, WithMethods[HTTP](http.MethodGet))
		require.NoError(t, err, pattern)
	}
}
func TestParser_RegexpConstraintMayHoldAColon(t *testing.T) {
	p := testProxy(t, WithRegexpParam(true))

	// A colon inside a brace belongs to the constraint, not to a port. Both scans that name
	// a port have to skip the brace, or every regexp constrained hostname is refused.
	for _, pattern := range []string{
		`{sub:[a-z]+}.example.com/health`,
		`+{any:[a-z.]+}/health`,
	} {
		_, err := p.Add(pattern, noopHandler)
		require.NoError(t, err, pattern)
	}
	// Tunnels go on authorities no interceptor claims, since an interceptor and a tunnel cannot disagree
	// on the same authority.
	for _, pattern := range []string{
		`{sub:[a-z]+}.tunnelled.test`,
		`+{any:[a-z.]+}.also-tunnelled.test`,
	} {
		_, err := p.Add[TCP](pattern, noopStream)
		require.NoError(t, err, pattern)
	}

	// Past the last brace the colon is a port again, and both patterns split on it.
	p.MustAdd[TCP](`{sub:[a-z]+}.other.com:8080`, noopStream)
	pat, _, err := p.parseAuthorityPattern(`{sub:[a-z]+}.other.com:8080`)
	require.NoError(t, err)
	assert.Equal(t, `{sub:[a-z]+}.other.com`, pat.host)
	assert.Equal(t, "8080", pat.port)

	pat, _, err = p.parsePattern(`{sub:[a-z]+}.other.com:8080/health`, KindHTTP)
	require.NoError(t, err)
	assert.Equal(t, `{sub:[a-z]+}.other.com`, pat.host)
	assert.Equal(t, "8080", pat.port)

	// The same authority carries a stream entry, which is another kind and no conflict: the
	// pattern is well formed and the two never compete for one connection.
	_, err = p.Add(`{sub:[a-z]+}.other.com:8080/health`, noopHandler)
	require.NoError(t, err)
}
func TestParser_AddressLiteralMustBeCanonical(t *testing.T) {
	p := testProxy(t)

	// An address has exactly one spelling, bracketed as an authority carries it. Anything
	// else is refused with the form to use, so no two patterns reach one key.
	pat, _, err := p.parsePattern("[::1]/health", KindHTTP)
	require.NoError(t, err)
	assert.Equal(t, "::1", pat.host)
	assert.Equal(t, prefixKey(netip.PrefixFrom(netip.MustParseAddr("::1"), 128))+"/health", pat.key)

	for _, tc := range []struct{ pattern, hint string }{
		{"::1/health", "IPv6 literal must be bracketed"},
		{"[::0]/health", "non-canonical address literal, write [::]"},
		{"[::FF]/health", "non-canonical address literal, write [::ff]"},
		{"[0:0:0:0:0:0:0:1]/health", "non-canonical address literal, write [::1]"},
		{"[::ffff:127.0.0.1]/health", "non-canonical address literal, write 127.0.0.1"},
	} {
		_, _, err := p.parsePattern(tc.pattern, KindHTTP)
		var pe *PatternError
		require.ErrorAs(t, err, &pe, tc.pattern)
		assert.Contains(t, pe.Error(), tc.hint, tc.pattern)
	}
}

func TestParser_Pattern(t *testing.T) {
	p := testProxy(t, WithRegexpParam(true))

	staticToken := func(v string, hsplit bool) token {
		return token{value: v, typ: nodeStatic, hsplit: hsplit}
	}
	constrained := func(typ nodeType, v, reg, flags string) token {
		tk := token{value: v, typ: typ}
		if reg != "" {
			tk.regexp = regexp.MustCompile(flags + "^(?:" + reg + ")$")
		}
		return tk
	}
	paramToken := func(v, reg string) token { return constrained(nodeParam, v, reg, "") }
	wildcardToken := func(v, reg string) token { return constrained(nodeWildcard, v, reg, "") }
	nestedWildcardToken := func(v, reg string) token {
		tk := wildcardToken(v, reg)
		tk.nested = true
		return tk
	}
	hostParamToken := func(v, reg string) token { return constrained(nodeParam, v, reg, "(?i)") }
	hostWildcardToken := func(v, reg string) token { return constrained(nodeWildcard, v, reg, "(?i)") }

	cases := []struct {
		name             string
		pattern          string
		params           int
		tokens           []token
		optionalCatchAll bool
		err              string
	}{
		{
			name:    "valid static pattern",
			pattern: "a.test/foo/bar",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/bar", false),
			},
		},
		{
			name:    "top level domain param",
			pattern: "{tld}/foo/bar",
			params:  1,
			tokens: []token{
				paramToken("tld", ""),
				staticToken("/foo/bar", false),
			},
		},
		{
			name:    "top level domain wildcard",
			pattern: "+{tld}/foo/bar",
			params:  1,
			tokens: []token{
				wildcardToken("tld", ""),
				staticToken("/foo/bar", false),
			},
		},
		{
			name:    "valid catch all pattern",
			pattern: "a.test/foo/bar/+{arg}",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/bar/", false),
				wildcardToken("arg", ""),
			},
		},
		{
			name:    "valid param pattern",
			pattern: "a.test/foo/bar/{baz}",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/bar/", false),
				paramToken("baz", ""),
			},
		},
		{
			name:    "valid multi params pattern",
			pattern: "a.test/foo/{bar}/{baz}",
			params:  2,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/", false),
				paramToken("bar", ""),
				staticToken("/", false),
				paramToken("baz", ""),
			},
		},
		{
			name:    "valid same params pattern",
			pattern: "a.test/foo/{bar}/{bar}",
			params:  2,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/", false),
				paramToken("bar", ""),
				staticToken("/", false),
				paramToken("bar", ""),
			},
		},
		{
			name:    "valid multi params and catch all pattern",
			pattern: "a.test/foo/{bar}/{baz}/+{arg}",
			params:  3,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/", false),
				paramToken("bar", ""),
				staticToken("/", false),
				paramToken("baz", ""),
				staticToken("/", false),
				wildcardToken("arg", ""),
			},
		},
		{
			name:    "valid inflight param",
			pattern: "a.test/foo/xyz:{bar}",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/xyz:", false),
				paramToken("bar", ""),
			},
		},
		{
			name:    "valid inflight catchall",
			pattern: "a.test/foo/xyz:+{bar}",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/xyz:", false),
				wildcardToken("bar", ""),
			},
		},
		{
			name:    "valid multi inflight param and catch all",
			pattern: "a.test/foo/xyz:{bar}/abc:{bar}/+{arg}",
			params:  3,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/xyz:", false),
				paramToken("bar", ""),
				staticToken("/abc:", false),
				paramToken("bar", ""),
				staticToken("/", false),
				wildcardToken("arg", ""),
			},
		},
		{
			name:    "catch all with arg in the middle of the pattern",
			pattern: "a.test/foo/bar/+{bar}/baz",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/bar/", false),
				wildcardToken("bar", ""),
				staticToken("/baz", false),
			},
		},
		{
			name:    "multiple catch all suffix and inflight with arg in the middle of the pattern",
			pattern: "a.test/foo/bar/+{bar}/x+{args}/y/+{z}/{b}",
			params:  4,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/bar/", false),
				wildcardToken("bar", ""),
				staticToken("/x", false),
				nestedWildcardToken("args", ""),
				staticToken("/y/", false),
				nestedWildcardToken("z", ""),
				staticToken("/", false),
				paramToken("b", ""),
			},
		},
		{
			name:    "inflight catch all with arg in the middle of the pattern",
			pattern: "a.test/foo/bar/damn+{bar}/baz",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/bar/damn", false),
				wildcardToken("bar", ""),
				staticToken("/baz", false),
			},
		},
		{
			name:    "catch all with arg in the middle of the pattern and param after",
			pattern: "a.test/foo/bar/+{bar}/{baz}",
			params:  2,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/bar/", false),
				wildcardToken("bar", ""),
				staticToken("/", false),
				paramToken("baz", ""),
			},
		},
		{
			name:    "simple domain and path",
			pattern: "foo/bar",
			tokens: []token{
				staticToken("foo", true),
				staticToken("/bar", false),
			},
		},
		{
			name:    "simple domain with trailing slash",
			pattern: "foo/",
			tokens: []token{
				staticToken("foo", true),
				staticToken("/", false),
			},
		},
		{
			name:    "period in param path allowed",
			pattern: "foo/{.bar}",
			params:  1,
			tokens: []token{
				staticToken("foo", true),
				staticToken("/", false),
				paramToken(".bar", ""),
			},
		},
		{
			name:    "missing trailing slash after hostname",
			pattern: "foo.com",
			err:     "missing trailing '/' after hostname",
		},
		{
			name:    "empty parameter",
			pattern: "a.test/foo/bar{}",
			err:     "missing name",
		},
		{
			name:    "encoded unreserved rejected",
			pattern: "a.test/a%61b",
			err:     "non-canonical percent-encoding, encodes an unreserved character",
		},
		{
			name:    "lowercase hex rejected",
			pattern: "a.test/foo%2fbar/caf%c3%a9",
			err:     "non-canonical percent-encoding, hex must be uppercase",
		},
		{
			name:    "encoded reserved with uppercase hex kept as registered",
			pattern: "a.test/foo%2Fbar/caf%C3%A9",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo%2Fbar/caf%C3%A9", false),
			},
		},
		{
			name:    "encoded structural characters stay literal",
			pattern: "a.test/a%7Bb%7D/%2A/%2B",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/a%7Bb%7D/%2A/%2B", false),
			},
		},
		{
			name:    "encoded unreserved before param rejected",
			pattern: "a.test/x%61/{id}",
			err:     "non-canonical percent-encoding, encodes an unreserved character",
		},
		{
			name:    "regex constraint not decoded",
			pattern: "a.test/foo/{bar:[%41]+}",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/", false),
				paramToken("bar", "[%41]+"),
			},
		},
		{
			name:    "escape inside brace segment not validated",
			pattern: "a.test/foo/{bar:[%61%2f]+}",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/", false),
				paramToken("bar", "[%61%2f]+"),
			},
		},
		{
			name:    "escape after brace segment rejected",
			pattern: "a.test/{id}/%2e",
			err:     "non-canonical percent-encoding, encodes an unreserved character",
		},
		{
			name:    "unbalanced brace with escape",
			pattern: "a.test/foo/{bar%2",
			err:     "unbalanced braces",
		},
		{
			name:    "encoded dot dot segment rejected",
			pattern: "a.test/foo/%2E%2E/bar",
			err:     "non-canonical percent-encoding, encodes an unreserved character",
		},
		{
			name:    "encoded single dot segment rejected",
			pattern: "a.test/foo/%2e/bar",
			err:     "non-canonical percent-encoding, encodes an unreserved character",
		},
		{
			name:    "trailing percent rejected",
			pattern: "a.test/100%",
			err:     "invalid percent-encoding",
		},
		{
			name:    "truncated escape rejected",
			pattern: "a.test/foo%2",
			err:     "invalid percent-encoding",
		},
		{
			name:    "invalid escape rejected",
			pattern: "a.test/%zz",
			err:     "invalid percent-encoding",
		},
		{
			name:    "literal star as suffix",
			pattern: "a.test/foo/bar/*",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/bar/*", false),
			},
		},
		{
			name:    "missing arguments name after param",
			pattern: "a.test/foo/bar/{",
			err:     "unbalanced braces",
		},
		{
			name:    "literal star in the middle of the pattern",
			pattern: "a.test/foo/bar/*/baz",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/bar/*/baz", false),
			},
		},
		{
			name:    "literal plus as suffix",
			pattern: "a.test/foo/bar/a+",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/bar/a+", false),
			},
		},
		{
			name:    "literal plus in the middle of the pattern",
			pattern: "a.test/emails/a+b/baz",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/emails/a+b/baz", false),
			},
		},
		{
			name:    "literal plus before wildcard brace still wildcard",
			pattern: "a.test/foo/+{bar}",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/", false),
				wildcardToken("bar", ""),
			},
		},
		{
			name:    "empty infix catch all",
			pattern: "a.test/foo/bar/+{}/baz",
			err:     "missing name",
		},
		{
			name:    "empty ending catch all",
			pattern: "a.test/foo/bar/baz/+{}",
			err:     "missing name",
		},
		{
			name:    "unbalanced brace in param",
			pattern: "a.test/foo/{{bar}",
			err:     "unbalanced braces",
		},
		{
			name:    "unexpected character in param",
			pattern: "a.test/foo/{*bar}",
			err:     "illegal character in name",
		},
		{
			name:    "unexpected character in catch-all",
			pattern: "a.test/foo/+{/bar}",
			err:     "illegal character in name",
		},
		{
			name:    "catch all not supported in hostname",
			pattern: "a.b.c*/",
			err:     "illegal character in label",
		},
		{
			name:    "illegal character in params hostname",
			pattern: "a.b.c{/",
			err:     "unbalanced braces",
		},
		{
			name:    "illegal character in hostname label",
			pattern: "a.b.c}/",
			err:     "illegal character in label",
		},
		{
			name:    "unexpected character in param hostname",
			pattern: "a.{.bar}.c/",
			err:     "illegal character in name",
		},
		{
			name:    "unexpected character in wildcard hostname",
			pattern: "a.+{.bar}.c/",
			err:     "illegal character in name",
		},
		{
			name:    "slash in param hostname",
			pattern: "a.{/bar}.c/",
			err:     "unbalanced braces",
		},
		{
			name:    "slash in wildcard hostname",
			pattern: "a.+{/bar}.c/",
			err:     "unbalanced braces",
		},
		{
			name:    "in flight catch-all after param in one pattern segment",
			pattern: "a.test/foo/{bar}+{baz}",
			err:     "illegal character after parameter",
		},
		{
			name:    "multiple param in one pattern segment",
			pattern: "a.test/foo/{bar}{baz}",
			err:     "illegal character after parameter",
		},
		{
			name:    "in flight param after catch all",
			pattern: "a.test/foo/+{args}{param}",
			err:     "illegal character after parameter",
		},
		{
			name:    "consecutive catch all with no slash",
			pattern: "a.test/foo/+{args}+{param}",
			err:     "illegal character after parameter",
		},
		{
			name:    "consecutive catch all",
			pattern: "a.test/foo/+{args}/+{param}",
			err:     "consecutive wildcard",
		},
		{
			name:    "consecutive catch all with inflight",
			pattern: "a.test/foo/ab+{args}/+{param}",
			err:     "consecutive wildcard",
		},
		{
			name:    "unexpected char after inflight catch all",
			pattern: "a.test/foo/ab+{args}a",
			err:     "illegal character after parameter",
		},
		{
			name:    "unexpected char after catch all",
			pattern: "a.test/foo/+{args}a",
			err:     "illegal character after parameter",
		},
		{
			name:    "prefix catch-all in hostname",
			pattern: "+{any}.com/foo",
			params:  1,
			tokens: []token{
				wildcardToken("any", ""),
				staticToken(".com", true),
				staticToken("/foo", false),
			},
		},
		{
			name:    "infix catch-all in hostname",
			pattern: "a.+{any}.com/foo",
			params:  1,
			tokens: []token{
				staticToken("a.", true),
				wildcardToken("any", ""),
				staticToken(".com", true),
				staticToken("/foo", false),
			},
		},
		{
			name:    "illegal catch-all in hostname",
			pattern: "a.b.+{any}/foo",
			params:  1,
			tokens: []token{
				staticToken("a.b.", true),
				wildcardToken("any", ""),
				staticToken("/foo", false),
			},
		},
		{
			name:    "static hostname with catch-all path",
			pattern: "a.b.com/+{any}",
			params:  1,
			tokens: []token{
				staticToken("a.b.com", true),
				staticToken("/", false),
				wildcardToken("any", ""),
			},
		},
		{
			name:    "illegal control character in path",
			pattern: "example.com/foo\x00",
			err:     "illegal control character",
		},
		{
			name:    "illegal control character in path regex constraint",
			pattern: "a.test/x/{a:\x01}",
			err:     "illegal control character",
		},
		{
			name:    "illegal control character in hostname regex constraint",
			pattern: "{s:a\nb}.example.com/",
			err:     "illegal control character",
		},
		{
			name:    "illegal leading hyphen in hostname",
			pattern: "-a.com/",
			err:     "label starts with '-'",
		},
		{
			name:    "illegal leading dot in hostname",
			pattern: ".a.com/",
			err:     "label starts with '.'",
		},
		{
			name:    "illegal trailing hyphen in hostname",
			pattern: "a.com-/",
			err:     "illegal trailing '-'",
		},
		{
			name:    "illegal trailing dot in hostname",
			pattern: "a.com./",
			err:     "illegal trailing '.'",
		},
		{
			name:    "illegal trailing dot in hostname after param",
			pattern: "{tld}./foo/bar",
			err:     "illegal trailing '.'",
		},
		{
			name:    "illegal single dot in hostname",
			pattern: "./",
			err:     "label starts with '.'",
		},
		{
			name:    "illegal hyphen before dot",
			pattern: "a-.com/",
			err:     "label ends with '-'",
		},
		{
			name:    "illegal hyphen after dot",
			pattern: "a.-com/",
			err:     "illegal character after '.'",
		},
		{
			name:    "illegal double dot",
			pattern: "a..com/",
			err:     "illegal consecutive '.'",
		},
		{
			name:    "illegal double dot with param state",
			pattern: "{b}..com/",
			err:     "illegal consecutive '.'",
		},
		{
			name:    "illegal double dot with inflight param state",
			pattern: "a{b}..com/",
			err:     "illegal consecutive '.'",
		},
		{
			name:    "param not finishing with delimiter in hostname",
			pattern: "{a}b{b}.com/",
			err:     "illegal character after parameter",
		},
		{
			name:    "consecutive parameter in hostname",
			pattern: "{a}{b}.com/",
			err:     "illegal character after parameter",
		},
		{
			name:    "leading hostname label exceed 63 characters",
			pattern: "uj01dowf1x5lk6lysurbr0lgbdd1wfyw8sm8q17mnt0i9igk774vcwr5rly5dguu.b.com/",
			err:     "label exceeds 63 characters",
		},
		{
			name:    "middle hostname label exceed 63 characters",
			pattern: "a.uj01dowf1x5lk6lysurbr0lgbdd1wfyw8sm8q17mnt0i9igk774vcwr5rly5dguu.com/",
			err:     "label exceeds 63 characters",
		},
		{
			name:    "trailing hostname label exceed 63 characters",
			pattern: "a.b.uj01dowf1x5lk6lysurbr0lgbdd1wfyw8sm8q17mnt0i9igk774vcwr5rly5dguu/",
			err:     "label exceeds 63 characters",
		},
		{
			name:    "illegal character in domain",
			pattern: "a.b!.com/",
			err:     "illegal character in label",
		},
		{
			name:    "all-numeric hostname",
			pattern: "123/",
			err:     "all numeric",
		},
		{
			name:    "all-numeric label with param",
			pattern: "123.{a}.456/",
			params:  1,
			tokens: []token{
				staticToken("123.", true),
				paramToken("a", ""),
				staticToken(".456", true),
				staticToken("/", false),
			},
		},
		{
			name:    "all-numeric label with wildcard",
			pattern: "123.+{a}.456/",
			params:  1,
			tokens: []token{
				staticToken("123.", true),
				wildcardToken("a", ""),
				staticToken(".456", true),
				staticToken("/", false),
			},
		},
		{
			name:    "all-numeric label with path wildcard",
			pattern: "123.456/{abc}",
			err:     "all numeric",
		},
		{
			name:    "hostname exceed 255 character",
			pattern: "a.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjx.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr/",
			err:     "exceeds 253 characters",
		},
		{
			name:    "all-numeric labels",
			pattern: "11.22.33/",
			err:     "all numeric",
		},
		{
			name:    "invalid uppercase label",
			pattern: "ABC/",
			err:     "uppercase character in label",
		},
		{
			name:    "2 regular params in domain",
			pattern: "{a}.{b}.com/",
			params:  2,
			tokens: []token{
				paramToken("a", ""),
				staticToken(".", true),
				paramToken("b", ""),
				staticToken(".com", true),
				staticToken("/", false),
			},
		},
		{
			name:    "253 character with .",
			pattern: "78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzj/",
			tokens: []token{
				staticToken("78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzj", true),
				staticToken("/", false),
			},
		},
		{
			name:    "param does not count at character",
			pattern: "{a}.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjx.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzj/",
			params:  1,
			tokens: []token{
				paramToken("a", ""),
				staticToken(".78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjx.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzj", true),
				staticToken("/", false),
			},
		},
		{
			name:    "hostname variant with multiple catch all suffix and inflight with arg in the middle of the pattern",
			pattern: "example.com/foo/bar/+{bar}/x+{args}/y/+{z}/{b}",
			params:  4,
			tokens: []token{
				staticToken("example.com", true),
				staticToken("/foo/bar/", false),
				wildcardToken("bar", ""),
				staticToken("/x", false),
				nestedWildcardToken("args", ""),
				staticToken("/y/", false),
				nestedWildcardToken("z", ""),
				staticToken("/", false),
				paramToken("b", ""),
			},
		},
		{
			name:    "hostname variant with inflight catch all with arg in the middle of the pattern",
			pattern: "example.com/foo/bar/damn+{bar}/baz",
			params:  1,
			tokens: []token{
				staticToken("example.com", true),
				staticToken("/foo/bar/damn", false),
				wildcardToken("bar", ""),
				staticToken("/baz", false),
			},
		},
		{
			name:    "hostname variant catch all with arg in the middle of the pattern and param after",
			pattern: "example.com/foo/bar/+{bar}/{baz}",
			params:  2,
			tokens: []token{
				staticToken("example.com", true),
				staticToken("/foo/bar/", false),
				wildcardToken("bar", ""),
				staticToken("/", false),
				paramToken("baz", ""),
			},
		},
		{
			name:    "complex domain and path",
			pattern: "{ab}.{c}.de{f}.com/foo/bar/+{bar}/x+{args}/y/+{z}/{b}",
			params:  7,
			tokens: []token{
				paramToken("ab", ""),
				staticToken(".", true),
				paramToken("c", ""),
				staticToken(".de", true),
				paramToken("f", ""),
				staticToken(".com", true),
				staticToken("/foo/bar/", false),
				wildcardToken("bar", ""),
				staticToken("/x", false),
				nestedWildcardToken("args", ""),
				staticToken("/y/", false),
				nestedWildcardToken("z", ""),
				staticToken("/", false),
				paramToken("b", ""),
			},
		},
		{
			name:    "path with double slash",
			pattern: "a.test/foo//bar",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo//bar", false),
			},
		},
		{
			name:    "path with > double slash",
			pattern: "a.test/foo///bar",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo///bar", false),
			},
		},
		{
			name:    "hostname with double slash path",
			pattern: "example.com//foo",
			tokens: []token{
				staticToken("example.com", true),
				staticToken("//foo", false),
			},
		},
		{
			name:    "param after empty segment",
			pattern: "a.test/foo//{bar}",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo//", false),
				paramToken("bar", ""),
			},
		},
		{
			name:    "path with slash dot slash",
			pattern: "a.test/foo/./bar",
			err:     "unsafe dot segment",
		},
		{
			name:    "path with repeated slash dot slash",
			pattern: "a.test/foo/././bar",
			err:     "unsafe dot segment",
		},
		{
			name:    "path with double dot parent reference",
			pattern: "a.test/foo/../bar",
			err:     "unsafe dot segment",
		},
		{
			name:    "path with repeated double dot parent reference",
			pattern: "a.test/foo/../../bar",
			err:     "unsafe dot segment",
		},
		{
			name:    "path ending with slash dot",
			pattern: "a.test/foo/.",
			err:     "unsafe dot segment",
		},
		{
			name:    "path ending with slash double dot",
			pattern: "a.test/foo/..",
			err:     "unsafe dot segment",
		},
		{
			name:    "root path of a single dot",
			pattern: "a.test/.",
			err:     "unsafe dot segment",
		},
		{
			name:    "root path of a double dot",
			pattern: "a.test/..",
			err:     "unsafe dot segment",
		},
		{
			name:    "last path segment starting with slash dot and text",
			pattern: "a.test/foo/.bar",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/.bar", false),
			},
		},
		{
			name:    "last path segment starting with two dots and text",
			pattern: "a.test/foo/..bar",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/..bar", false),
			},
		},
		{
			name:    "path segment starting with slash dot and text",
			pattern: "a.test/foo/.bar/baz",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/.bar/baz", false),
			},
		},
		{
			name:    "path segment starting with slash dot and param",
			pattern: "a.test/foo/.{foo}/baz",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/.", false),
				paramToken("foo", ""),
				staticToken("/baz", false),
			},
		},
		{
			name:    "path segment starting with two dots and text",
			pattern: "a.test/foo/..bar/baz",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/..bar/baz", false),
			},
		},
		{
			name:    "path segment starting with two dots and param",
			pattern: "a.test/foo/..{foo}/baz",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/..", false),
				paramToken("foo", ""),
				staticToken("/baz", false),
			},
		},
		{
			name:    "path segment ending with dot slash",
			pattern: "a.test/foo/bar./baz",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/bar./baz", false),
			},
		},
		{
			name:    "path segment ending with double dot slash",
			pattern: "a.test/foo/bar../baz",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/bar../baz", false),
			},
		},
		{
			name:    "path segment with > double dot",
			pattern: "a.test/foo/.../baz",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/.../baz", false),
			},
		},
		{
			name:    "path segment ending with slash and > double dot",
			pattern: "a.test/foo/...",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/...", false),
			},
		},
		{
			name:    "last path segment ending with dot",
			pattern: "a.test/foo/bar.",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/bar.", false),
			},
		},
		{
			name:    "last path segment ending with double dot",
			pattern: "a.test/foo/bar..",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/bar..", false),
			},
		},
		{
			name:    "path segment with dot",
			pattern: "a.test/foo/a.b.c",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/a.b.c", false),
			},
		},
		{
			name:    "path segment with double dot",
			pattern: "a.test/foo/a..b..c",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/a..b..c", false),
			},
		},
		{
			name:    "simple ending param with regexp",
			pattern: "a.test/foo/{bar:[A-z]+}",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/", false),
				paramToken("bar", "[A-z]+"),
			},
		},
		{
			name:    "simple ending wildcard with regexp",
			pattern: "a.test/foo/+{bar:[A-z]+}",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/", false),
				wildcardToken("bar", "[A-z]+"),
			},
		},
		{
			name:    "simple infix param with regexp",
			pattern: "a.test/foo/{bar:[A-z]+}/baz",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/", false),
				paramToken("bar", "[A-z]+"),
				staticToken("/baz", false),
			},
		},
		{
			name:    "multi infix and ending param with regexp",
			pattern: "a.test/foo/{bar:[A-z]+}/{baz:[0-9]+}",
			params:  2,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/", false),
				paramToken("bar", "[A-z]+"),
				staticToken("/", false),
				paramToken("baz", "[0-9]+"),
			},
		},
		{
			name:    "multi infix and ending wildcard with regexp",
			pattern: "a.test/foo/+{bar:[A-z]+}/a+{baz:[0-9]+}",
			params:  2,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/", false),
				wildcardToken("bar", "[A-z]+"),
				staticToken("/a", false),
				nestedWildcardToken("baz", "[0-9]+"),
			},
		},
		{
			name:    "consecutive infix regexp wildcard and regexp param allowed",
			pattern: "a.test/foo/+{bar:[A-z]+}/{baz:[0-9]+}",
			params:  2,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/", false),
				wildcardToken("bar", "[A-z]+"),
				staticToken("/", false),
				paramToken("baz", "[0-9]+"),
			},
		},
		{
			name:    "hostname starting with regexp",
			pattern: "{a:[A-z]+}.b.c/foo",
			params:  1,
			tokens: []token{
				hostParamToken("a", "[A-z]+"),
				staticToken(".b.c", true),
				staticToken("/foo", false),
			},
		},
		{
			name:    "hostname with middle param regexp",
			pattern: "a.{b:[A-z]+}.c/foo",
			params:  1,
			tokens: []token{
				staticToken("a.", true),
				hostParamToken("b", "[A-z]+"),
				staticToken(".c", true),
				staticToken("/foo", false),
			},
		},
		{
			name:    "hostname ending with param regexp",
			pattern: "a.b.{c:[A-z]+}/foo",
			params:  1,
			tokens: []token{
				staticToken("a.b.", true),
				hostParamToken("c", "[A-z]+"),
				staticToken("/foo", false),
			},
		},
		{
			name:    "non capturing group allowed in regexp",
			pattern: "a.test/foo/{bar:(?:foo|bar)}",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/", false),
				paramToken("bar", "(?:foo|bar)"),
			},
		},
		{
			name:    "regexp wildcard at the beginning of the path",
			pattern: "a.test/+{foo:[A-z]+}/bar",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/", false),
				wildcardToken("foo", "[A-z]+"),
				staticToken("/bar", false),
			},
		},
		{
			name:    "regexp wildcard at the beginning of the host",
			pattern: "+{a:[A-z]+}.b.c/",
			params:  1,
			tokens: []token{
				hostWildcardToken("a", "[A-z]+"),
				staticToken(".b.c", true),
				staticToken("/", false),
			},
		},
		{
			name:    "consecutive wildcard from hostname to path",
			pattern: "+{foo}/+{bar}",
			params:  2,
			tokens: []token{
				wildcardToken("foo", ""),
				staticToken("/", false),
				wildcardToken("bar", ""),
			},
		},
		{
			name:    "consecutive wildcard with empty catch all from hostname to path",
			pattern: "+{foo}/*{bar}",
			params:  2,
			tokens: []token{
				wildcardToken("foo", ""),
				staticToken("/", false),
				wildcardToken("bar", ""),
			},
			optionalCatchAll: true,
		},
		{
			name:    "param then wildcard regexp",
			pattern: "{a}.+{b:b}/",
			params:  2,
			tokens: []token{
				paramToken("a", ""),
				staticToken(".", true),
				hostWildcardToken("b", "b"),
				staticToken("/", false),
			},
		},
		{
			name:    "param regexp then wildcard regexp",
			pattern: "{a:a}.+{b:b}/",
			params:  2,
			tokens: []token{
				hostParamToken("a", "a"),
				staticToken(".", true),
				hostWildcardToken("b", "b"),
				staticToken("/", false),
			},
		},
		{
			name:    "catch all empty as suffix",
			pattern: "a.test/foo/*{any}",
			params:  1,
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/", false),
				wildcardToken("any", ""),
			},
			optionalCatchAll: true,
		},
		{
			name:    "consecutive infix wildcard at start with regexp not allowed",
			pattern: "a.test/+{foo:[A-z]+}/+{baz:[0-9]+}",
			err:     "consecutive wildcard",
		},
		{
			name:    "consecutive wildcard with catch all empty not allowed",
			pattern: "a.test/+{foo}/*{baz}",
			err:     "consecutive wildcard",
		},
		{
			name:    "consecutive infix wildcard with catch all empty at start with regexp not allowed",
			pattern: "a.test/+{foo:[A-z]+}/*{baz:[0-9]+}",
			err:     "consecutive wildcard",
		},
		{
			name:    "param followed by a wildcard in one path segment not allowed",
			pattern: "a.test/{foo:[A-z]+}.+{baz:[0-9]+}/",
			err:     "illegal character after parameter",
		},
		{
			name:    "consecutive infix wildcard at start with and without regexp not allowed",
			pattern: "a.test/+{foo:[A-z]+}/+{baz}",
			err:     "consecutive wildcard",
		},
		{
			name:    "hostname consecutive infix wildcard at start with and without regexp not allowed",
			pattern: "+{foo:[A-z]+}.+{baz}/",
			err:     "consecutive wildcard",
		},
		{
			name:    "consecutive infix wildcard after a plain wildcard not allowed",
			pattern: "a.test/+{foo}/+{baz:[0-9]+}/",
			err:     "consecutive wildcard",
		},
		{
			name:    "hostname consecutive infix wildcard at start with regexp not allowed",
			pattern: "+{foo}.+{baz:[0-9]+}/",
			err:     "consecutive wildcard",
		},
		{
			name:    "consecutive infix wildcard with regexp not allowed",
			pattern: "a.test/foo/+{bar:[A-z]+}/+{baz:[0-9]+}",
			err:     "consecutive wildcard",
		},
		{
			name:    "hostname consecutive infix wildcard with regexp not allowed",
			pattern: "foo.+{bar:[A-z]+}.+{baz:[0-9]+}/",
			err:     "consecutive wildcard",
		},
		{
			name:    "consecutive infix wildcard with first regexp not allowed",
			pattern: "a.test/foo/+{bar:[A-z]+}/+{baz}",
			err:     "consecutive wildcard",
		},
		{
			name:    "hostname consecutive infix wildcard with first regexp not allowed",
			pattern: "foo.+{bar:[A-z]+}.+{baz}/",
			err:     "consecutive wildcard",
		},
		{
			name:    "consecutive infix wildcard with second regexp not allowed",
			pattern: "a.test/foo/+{bar}/+{baz:[A-z]+}/",
			err:     "consecutive wildcard",
		},
		{
			name:    "hostname consecutive infix wildcard with second regexp not allowed",
			pattern: "foo.+{bar}.+{baz:[A-z]+}/",
			err:     "consecutive wildcard",
		},
		{
			name:    "non slash char after regexp param not allowed",
			pattern: "a.test/foo/{bar:[A-z]+}a/",
			err:     "illegal character after parameter",
		},
		{
			name:    "non slash char after regexp wildcard not allowed",
			pattern: "a.test/foo/+{bar:[A-z]+}a/",
			err:     "illegal character after parameter",
		},
		{
			name:    "nested brace in hostname wildcard",
			pattern: "+{a.{b:[A-z]+}}.c/",
			err:     "illegal character in name",
		},
		{
			name:    "unbalanced nested brace in hostname wildcard",
			pattern: "+{a.b.{c:[A-z]+}/",
			err:     "unbalanced braces",
		},
		{
			name:    "missing param name with regexp",
			pattern: "a.test/foo/{:[A-z]+}",
			err:     "missing name",
		},
		{
			name:    "missing wildcard name with regexp",
			pattern: "a.test/foo/+{:[A-z]+}",
			err:     "missing name",
		},
		{
			name:    "missing regular expression",
			pattern: "a.test/foo/{a:}",
			err:     "missing expression",
		},
		{
			name:    "missing regular expression with only ':'",
			pattern: "a.test/foo/{:}",
			err:     "missing name",
		},
		{
			name:    "unsupported regexp in optional wildcard",
			pattern: "a.test/foo/*{any:[A-z]+}",
			err:     "not allowed in optional wildcard",
		},
		{
			name:    "unbalanced braces in param regexp",
			pattern: "a.test/foo/{bar:[A-z]+",
			err:     "unbalanced braces",
		},
		{
			name:    "unbalanced braces in wildcard regexp",
			pattern: "a.test/foo/+{bar:[A-z]+",
			err:     "unbalanced braces",
		},
		{
			name:    "balanced braces in param regexp with invalid char after",
			pattern: "a.test/foo/{bar:{}}a",
			err:     "illegal character after parameter",
		},
		{
			name:    "balanced braces in wildcard regexp with invalid brace after",
			pattern: "a.test/foo/{bar:{}}}",
			err:     "illegal character after parameter",
		},
		{
			name:    "unbalanced braces in regexp complex",
			pattern: "a.test/foo/{bar:{{{{}}}}",
			err:     "unbalanced braces",
		},
		{
			name:    "invalid regular expression",
			pattern: "a.test/foo/{bar:a{5,2}}",
			err:     "error parsing regexp: invalid repeat count: `{5,2}`",
		},
		{
			name:    "invalid regular expression escape",
			pattern: "a.test/foo/{bar:\\k}",
			err:     "error parsing regexp: invalid escape sequence: `\\k`",
		},
		{
			name:    "capture group in regexp are not allowed",
			pattern: "a.test/foo/{bar:(foo|bar)}",
			err:     "capture group, use (?:...) instead",
		},
		{
			name:    "literal star without opening brace",
			pattern: "a.test/foo/*:bar",
			tokens: []token{
				staticToken("a.test", true),
				staticToken("/foo/*:bar", false),
			},
		},
		{
			name:    "no infix catch all empty",
			pattern: "a.test/foo/*{any}/bar",
			err:     "optional wildcard allowed only as suffix",
		},
		{
			name:    "no infix inflight catch all empty",
			pattern: "a.test/foo/uuid_*{any}/bar",
			err:     "optional wildcard allowed only as suffix",
		},
		{
			name:    "no suffix catch all empty in hostname",
			pattern: "a.b.*{any}/",
			err:     "optional wildcard allowed only as suffix",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pat, n, err := p.parsePattern(tc.pattern, KindHTTP)
			if tc.err != "" {
				var pe *PatternError
				require.ErrorAs(t, err, &pe)
				assert.Equal(t, tc.err, pe.Hint)
				assert.Equal(t, tc.pattern, pe.Pattern)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.pattern, pat.str)
			assert.Equal(t, tc.params, n)
			assert.Equal(t, tc.tokens, pat.tokens)
			assert.Equal(t, tc.optionalCatchAll, pat.optionalCatchAll)
		})
	}
}

func TestParser_HostnameIsRequired(t *testing.T) {
	p := testProxy(t)

	_, err := p.Add("/v1/charges", noopHandler, WithMethods[HTTP](http.MethodGet))
	var pe *PatternError
	require.ErrorAs(t, err, &pe)
	assert.Contains(t, pe.Error(), "write +{any} to match every hostname")
}

func TestParser_CanonicalEncoding(t *testing.T) {
	p := testProxy(t)

	for _, raw := range []string{
		"a.test/users/john",
		"a.test/a%7Bb",
		"a.test/a%2Fb/{id}",
		"example.com/caf%C3%A9",
	} {
		pat, _, err := p.parsePattern(raw, KindHTTP)
		require.NoError(t, err, raw)
		assert.Equal(t, raw, pat.str)
	}

	for _, tc := range []struct {
		name    string
		pattern string
		hint    string
	}{
		{"encoded unreserved", "a.test/users/j%6Fhn", "non-canonical percent-encoding, encodes an unreserved character"},
		{"lowercase hex", "a.test/a%2fb", "non-canonical percent-encoding, hex must be uppercase"},
		{"encoded tilde", "a.test/%7E", "non-canonical percent-encoding, encodes an unreserved character"},
		{"lowercase encoded unreserved", "example.com/%7e%61", "non-canonical percent-encoding, encodes an unreserved character"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := p.parsePattern(tc.pattern, KindHTTP)
			var pe *PatternError
			require.ErrorAs(t, err, &pe)
			assert.Equal(t, "syntax", pe.Reason)
			assert.Equal(t, tc.pattern, pe.Pattern)
			assert.Equal(t, tc.hint, pe.Hint)
		})
	}
}

func TestParser_MinRegexpSize(t *testing.T) {
	cases := []struct {
		expr  string
		limit int
		want  int
	}{
		{expr: `a`, limit: 1000, want: 1},
		{expr: `abc`, limit: 1000, want: 3},
		{expr: `[a-z]+`, limit: 1000, want: 1},
		{expr: `a{3}`, limit: 1000, want: 3},
		{expr: `a{2,5}`, limit: 1000, want: 5},
		{expr: `a{2,}`, limit: 1000, want: 2},
		{expr: `a{0}`, limit: 1000, want: 1},
		{expr: `a*`, limit: 1000, want: 1},
		{expr: `(?:)`, limit: 1000, want: 1},
		{expr: `(?:a|bc)`, limit: 1000, want: 3},
		{expr: `\b`, limit: 1000, want: 1},
		{expr: `(?i)k`, limit: 1000, want: 1},
		{expr: `[^\x00-\x{10FFFF}]`, limit: 1000, want: 1},
		{expr: `(?:a{0,3}){2,}`, limit: 1000, want: 6},
		{expr: `(?:(?:)*){10}`, limit: 1000, want: 10},
		{expr: `(?:a{10}){100}`, limit: 1000, want: 1000},
		{expr: `(?:a{10}){100}`, limit: 999, want: 1000},
		{expr: strings.Repeat("a{1000}", 3000), limit: 1000, want: 1001},
	}

	for _, tc := range cases {
		t.Run(tc.expr[:min(len(tc.expr), 32)], func(t *testing.T) {
			re, err := syntax.Parse(tc.expr, syntax.Perl)
			require.NoError(t, err)
			got := minRegexpSize(re, tc.limit)
			assert.Equal(t, tc.want, got)
			if got <= tc.limit {
				prog, err := syntax.Compile(re.Simplify())
				require.NoError(t, err)
				assert.LessOrEqual(t, got, len(prog.Inst))
			}
		})
	}
}

func TestParser_ParamLimits(t *testing.T) {
	t.Run("param count", func(t *testing.T) {
		p := testProxy(t, WithMaxPatternParams(3))
		for _, tc := range []struct {
			pattern string
			ok      bool
		}{
			{"a.test/{1}/{2}/{3}", true},
			{"{0}.test/{1}/{2}", true},
			{"a.test/{1}/{2}/{3}/{4}", false},
			{"a.test/ab{1}/{2}/cd/{3}/{4}/ef", false},
			{"{0}.test/{1}/{2}/{3}", false},
		} {
			_, _, err := p.parsePattern(tc.pattern, KindHTTP)
			assert.Equal(t, tc.ok, err == nil, tc.pattern)
		}
	})

	t.Run("param key length", func(t *testing.T) {
		p := testProxy(t, WithMaxPatternParamKeyBytes(3), WithRegexpParam(true))
		for _, tc := range []struct {
			pattern string
			ok      bool
		}{
			{"a.test/{abc}/{abc}/{abc}", true},
			{"a.test/{abcd}/{abc}/{abc}", false},
			{"a.test/{abc}/{abcd}/{abc}", false},
			{"a.test/{abc}/{abc}/{abcd}", false},
			{"a.test/{abc}/+{abcd}/{abc}", false},
			{"a.test/{abc}/{abc}/+{abcdef}", false},
			{"a.test/{abc:a}/{abc:a}/{abc:a}", true},
			{"a.test/{abcd:a}/{abc:a}/{abc:a}", false},
			{"a.test/{abc:a}/+{abcd:a}/{abc:a}", false},
			{"{abcd}.test/{abc}", false},
		} {
			_, _, err := p.parsePattern(tc.pattern, KindHTTP)
			assert.Equal(t, tc.ok, err == nil, tc.pattern)
		}
	})

	t.Run("regexp disabled", func(t *testing.T) {
		p := testProxy(t)
		for _, tc := range []struct {
			pattern string
			ok      bool
		}{
			{"a.test/{a}/{b}/{c}", true},
			{"a.test/{a:a}/{b}/{c}", false},
			{"a.test/{a}/{b}/{c:c}", false},
			{"a.test/+{a:a}/{b}", false},
			{"a.test/{a}/+{b:b}", false},
			{"{a:a}.{b}.{c}/", false},
			{"{a}.{b}.{c:c}/", false},
			{"+{a:a}.b.c/", false},
		} {
			_, _, err := p.parsePattern(tc.pattern, KindHTTP)
			assert.Equal(t, tc.ok, err == nil, tc.pattern)
		}
	})
}

func TestPatternError_Position(t *testing.T) {
	cases := []struct {
		name       string
		pattern    string
		options    []ProxyOption
		wantType   string
		wantReason string
		wantStart  int
		wantEnd    int
		wantMsg    string
	}{
		{
			name:       "hostname missing trailing slash",
			pattern:    "foo.com",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  7,
			wantEnd:    7,
			wantMsg:    "missing trailing '/' after hostname",
		},
		{
			name:       "hostname label starts with dash",
			pattern:    "-a.com/",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  0,
			wantEnd:    1,
			wantMsg:    "label starts with '-'",
		},
		{
			name:       "hostname label starts with dot",
			pattern:    ".a.com/",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  0,
			wantEnd:    1,
			wantMsg:    "label starts with '.'",
		},
		{
			name:       "hostname dash after dot",
			pattern:    "a.-b.com/",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  2,
			wantEnd:    3,
			wantMsg:    "illegal character after '.'",
		},
		{
			name:       "hostname consecutive dots",
			pattern:    "a..com/",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  1,
			wantEnd:    3,
			wantMsg:    "illegal consecutive '.'",
		},
		{
			name:       "hostname label ends with dash",
			pattern:    "a-.com/",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  1,
			wantEnd:    2,
			wantMsg:    "label ends with '-'",
		},
		{
			name:       "hostname label exceeds 63 chars at dot",
			pattern:    "uj01dowf1x5lk6lysurbr0lgbdd1wfyw8sm8q17mnt0i9igk774vcwr5rly5dguu.com/",
			wantType:   "hostname",
			wantReason: "constraint",
			wantStart:  0,
			wantEnd:    64,
			wantMsg:    "label exceeds 63 characters",
		},
		{
			name:       "hostname uppercase character",
			pattern:    "A.com/",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  0,
			wantEnd:    1,
			wantMsg:    "uppercase character in label",
		},
		{
			name:       "hostname illegal character in label",
			pattern:    "a!.com/",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  1,
			wantEnd:    2,
			wantMsg:    "illegal character in label",
		},
		{
			name:       "hostname trailing dash",
			pattern:    "a.com-/",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  5,
			wantEnd:    6,
			wantMsg:    "illegal trailing '-'",
		},
		{
			name:       "hostname trailing dot",
			pattern:    "a.com./",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  5,
			wantEnd:    6,
			wantMsg:    "illegal trailing '.'",
		},
		{
			name:       "hostname all numeric",
			pattern:    "123/",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  0,
			wantEnd:    3,
			wantMsg:    "all numeric",
		},
		{
			name:       "hostname trailing label exceeds 63 chars",
			pattern:    "a.b.uj01dowf1x5lk6lysurbr0lgbdd1wfyw8sm8q17mnt0i9igk774vcwr5rly5dguu/",
			wantType:   "hostname",
			wantReason: "constraint",
			wantStart:  4,
			wantEnd:    68,
			wantMsg:    "label exceeds 63 characters",
		},
		{
			name:       "hostname exceeds 253 characters",
			pattern:    "a.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjx.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr.78fayzyiqkt3hh2mquv9szfroeexx8qztscu3oudoyfarjl6jmdyxk2cefvzjxr/",
			wantType:   "hostname",
			wantReason: "constraint",
			wantStart:  0,
			wantEnd:    256,
			wantMsg:    "exceeds 253 characters",
		},
		{
			name:       "hostname missing parameter after + delimiter",
			pattern:    "+a.com/",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  0,
			wantEnd:    1,
			wantMsg:    "missing parameter after delimiter",
		},
		{
			name:       "hostname consecutive wildcard",
			pattern:    "+{a}.+{b}.com/",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  5,
			wantEnd:    9,
			wantMsg:    "consecutive wildcard",
		},
		{
			name:       "hostname too many parameters",
			pattern:    "{a}.{b}.com/",
			options:    []ProxyOption{WithMaxPatternParams(1)},
			wantType:   "hostname",
			wantReason: "constraint",
			wantStart:  4,
			wantEnd:    7,
			wantMsg:    "too many parameters",
		},
		{
			name:       "hostname illegal character after parameter",
			pattern:    "{a}b.com/",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  3,
			wantEnd:    4,
			wantMsg:    "illegal character after parameter",
		},
		{
			name:       "hostname optional wildcard not allowed",
			pattern:    "a.*{any}/",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  2,
			wantEnd:    8,
			wantMsg:    "optional wildcard allowed only as suffix",
		},
		{
			name:       "hostname lone star illegal character",
			pattern:    "a.b*/",
			wantType:   "hostname",
			wantReason: "syntax",
			wantStart:  3,
			wantEnd:    4,
			wantMsg:    "illegal character in label",
		},
		{
			name:       "path consecutive wildcard",
			pattern:    "a.test/+{a}/+{b}",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  12,
			wantEnd:    16,
			wantMsg:    "consecutive wildcard",
		},
		{
			name:       "path too many parameters",
			pattern:    "a.test/foo/{a}/{b}",
			options:    []ProxyOption{WithMaxPatternParams(1)},
			wantType:   "path",
			wantReason: "constraint",
			wantStart:  15,
			wantEnd:    18,
			wantMsg:    "too many parameters",
		},
		{
			name:       "path optional wildcard not as suffix",
			pattern:    "a.test/foo/*{any}/bar",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  11,
			wantEnd:    17,
			wantMsg:    "optional wildcard allowed only as suffix",
		},
		{
			name:       "path illegal character after parameter",
			pattern:    "a.test/foo/{a}b",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  14,
			wantEnd:    15,
			wantMsg:    "illegal character after parameter",
		},
		{
			name:       "path illegal control character",
			pattern:    "a.test/foo\x01bar",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  10,
			wantEnd:    11,
			wantMsg:    "illegal control character",
		},
		{
			name:       "path invalid percent encoding",
			pattern:    "a.test/foo/%zzbar",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  11,
			wantEnd:    14,
			wantMsg:    "invalid percent-encoding",
		},
		{
			name:       "path truncated percent encoding",
			pattern:    "a.test/foo%2",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  10,
			wantEnd:    12,
			wantMsg:    "invalid percent-encoding",
		},
		{
			name:       "path invalid percent encoding with hostname",
			pattern:    "example.com/%zz",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  12,
			wantEnd:    15,
			wantMsg:    "invalid percent-encoding",
		},
		{
			name:       "path encoded dot segment rejected as non-canonical",
			pattern:    "a.test/foo/%2E%2E/bar",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  11,
			wantEnd:    14,
			wantMsg:    "non-canonical percent-encoding, encodes an unreserved character",
		},
		{
			name:       "path lowercase hex rejected as non-canonical",
			pattern:    "a.test/a%2fb",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  8,
			wantEnd:    11,
			wantMsg:    "non-canonical percent-encoding, hex must be uppercase",
		},
		{
			name:       "path raw space requires encoding",
			pattern:    "a.test/foo bar",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  10,
			wantEnd:    11,
			wantMsg:    "character requires percent-encoding",
		},
		{
			name:       "path raw non-ascii rune spans all bytes",
			pattern:    "a.test/café",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  10,
			wantEnd:    12,
			wantMsg:    "character requires percent-encoding",
		},
		{
			name:       "path invalid utf8 byte spans one byte",
			pattern:    "a.test/a\x80b",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  8,
			wantEnd:    9,
			wantMsg:    "character requires percent-encoding",
		},
		{
			name:       "path raw pipe requires encoding",
			pattern:    "a.test/a|b",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  8,
			wantEnd:    9,
			wantMsg:    "character requires percent-encoding",
		},
		{
			name:       "path raw backslash requires encoding",
			pattern:    "a.test/a\\b",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  8,
			wantEnd:    9,
			wantMsg:    "character requires percent-encoding",
		},
		{
			name:       "path del byte is a control character",
			pattern:    "a.test/a\x7fb",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  8,
			wantEnd:    9,
			wantMsg:    "illegal control character",
		},
		{
			name:       "path query delimiter rejected",
			pattern:    "a.test/search?q=1",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  13,
			wantEnd:    14,
			wantMsg:    "illegal query delimiter in patterns",
		},
		{
			name:       "path fragment delimiter rejected",
			pattern:    "a.test/foo#frag",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  10,
			wantEnd:    11,
			wantMsg:    "illegal fragment delimiter in patterns",
		},
		{
			name:       "path stray closing brace rejected",
			pattern:    "a.test/foo}bar",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  10,
			wantEnd:    11,
			wantMsg:    "unbalanced braces",
		},
		{
			name:       "path dot segment single dot mid",
			pattern:    "a.test/foo/./bar",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  10,
			wantEnd:    13,
			wantMsg:    "unsafe dot segment",
		},
		{
			name:       "path dot segment single dot end",
			pattern:    "a.test/foo/.",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  10,
			wantEnd:    12,
			wantMsg:    "unsafe dot segment",
		},
		{
			name:       "path dot segment double dot mid",
			pattern:    "a.test/foo/../bar",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  10,
			wantEnd:    14,
			wantMsg:    "unsafe dot segment",
		},
		{
			name:       "path dot segment double dot end",
			pattern:    "a.test/foo/..",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  10,
			wantEnd:    13,
			wantMsg:    "unsafe dot segment",
		},
		{
			name:       "path root single dot",
			pattern:    "a.test/.",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  6,
			wantEnd:    8,
			wantMsg:    "unsafe dot segment",
		},
		{
			name:       "path root double dot",
			pattern:    "a.test/..",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  6,
			wantEnd:    9,
			wantMsg:    "unsafe dot segment",
		},
		{
			name:       "unbalanced braces",
			pattern:    "a.test/foo/{bar",
			wantType:   "path",
			wantReason: "syntax",
			wantStart:  11,
			wantEnd:    15,
			wantMsg:    "unbalanced braces",
		},
		{
			name:       "parameter key too large",
			pattern:    "a.test/foo/{abcd}",
			options:    []ProxyOption{WithMaxPatternParamKeyBytes(3)},
			wantType:   "path",
			wantReason: "constraint",
			wantStart:  12,
			wantEnd:    16,
			wantMsg:    "key too large",
		},
		{
			name:       "missing parameter name",
			pattern:    "a.test/foo/{}",
			wantType:   "path",
			wantReason: "parameter",
			wantStart:  11,
			wantEnd:    13,
			wantMsg:    "missing name",
		},
		{
			name:       "illegal character in parameter name",
			pattern:    "a.test/foo/{*bar}",
			wantType:   "path",
			wantReason: "parameter",
			wantStart:  12,
			wantEnd:    13,
			wantMsg:    "illegal character in name",
		},
		{
			name:       "regexp not allowed in optional wildcard",
			pattern:    "a.test/foo/*{any:[A-z]+}",
			wantType:   "path",
			wantReason: "regexp",
			wantStart:  11,
			wantEnd:    24,
			wantMsg:    "not allowed in optional wildcard",
		},
		{
			name:       "regexp feature not enabled",
			pattern:    "a.test/foo/{a:[A-z]+}",
			wantType:   "path",
			wantReason: "regexp",
			wantStart:  14,
			wantEnd:    20,
			wantMsg:    "feature not enabled",
		},
		{
			name:       "regexp missing expression",
			pattern:    "a.test/foo/{a:}",
			options:    []ProxyOption{WithRegexpParam(true)},
			wantType:   "path",
			wantReason: "regexp",
			wantStart:  14,
			wantEnd:    14,
			wantMsg:    "missing expression",
		},
		{
			name:       "regexp compile error",
			pattern:    "a.test/foo/{a:a{5,2}}",
			options:    []ProxyOption{WithRegexpParam(true)},
			wantType:   "path",
			wantReason: "regexp",
			wantStart:  14,
			wantEnd:    20,
			wantMsg:    "error parsing regexp",
		},
		{
			name:       "regexp capture group not allowed",
			pattern:    "a.test/foo/{a:(foo|bar)}",
			options:    []ProxyOption{WithRegexpParam(true)},
			wantType:   "path",
			wantReason: "regexp",
			wantStart:  14,
			wantEnd:    23,
			wantMsg:    "capture group",
		},
		{
			name:       "regexp anchor escape rejected",
			pattern:    "a.test/foo/{a:a)|(?:}",
			options:    []ProxyOption{WithRegexpParam(true)},
			wantType:   "path",
			wantReason: "regexp",
			wantStart:  14,
			wantEnd:    20,
			wantMsg:    "error parsing regexp",
		},
		{
			name:       "regexp too large",
			pattern:    "a.test/foo/{a:[a-z]{1,1000}}",
			options:    []ProxyOption{WithRegexpParam(true)},
			wantType:   "path",
			wantReason: "regexp",
			wantStart:  14,
			wantEnd:    27,
			wantMsg:    "expression too large",
		},
		{
			name:       "regexp exceeds max size",
			pattern:    "a.test/foo/{a:[0-9]+}",
			options:    []ProxyOption{WithRegexpParam(true), WithMaxRegexpSize(3)},
			wantType:   "path",
			wantReason: "regexp",
			wantStart:  14,
			wantEnd:    20,
			wantMsg:    "expression too large",
		},
		{
			name:       "hostname regexp too large",
			pattern:    "{a:[a-z]{1,1000}}.test/",
			options:    []ProxyOption{WithRegexpParam(true)},
			wantType:   "hostname",
			wantReason: "regexp",
			wantStart:  3,
			wantEnd:    16,
			wantMsg:    "expression too large",
		},
		{
			name:       "hostname label exceeds 63 chars before dot with param",
			pattern:    strings.Repeat("a", 64) + "{b}.com/",
			wantType:   "hostname",
			wantReason: "constraint",
			wantStart:  0,
			wantEnd:    67,
			wantMsg:    "label exceeds 63 characters",
		},
		{
			name:       "hostname trailing label exceeds 63 chars with param",
			pattern:    strings.Repeat("a", 64) + "{b}/",
			wantType:   "hostname",
			wantReason: "constraint",
			wantStart:  0,
			wantEnd:    67,
			wantMsg:    "label exceeds 63 characters",
		},
		{
			name:       "hostname middle label exceeds 63 chars with param",
			pattern:    "a.b." + strings.Repeat("a", 64) + "{b}.com/",
			wantType:   "hostname",
			wantReason: "constraint",
			wantStart:  4,
			wantEnd:    71,
			wantMsg:    "label exceeds 63 characters",
		},
		{
			name:       "path control character in parameter name",
			pattern:    "a.test/foo/{a\x00b}",
			wantType:   "path",
			wantReason: "parameter",
			wantStart:  13,
			wantEnd:    14,
			wantMsg:    "illegal control character in name",
		},
		{
			name:       "hostname control character in parameter name",
			pattern:    "{a\x7fb}.com/",
			wantType:   "hostname",
			wantReason: "parameter",
			wantStart:  2,
			wantEnd:    3,
			wantMsg:    "illegal control character in name",
		},
		{
			name:       "path control character in regex constraint",
			pattern:    "a.test/x/{a:a\nb}",
			options:    []ProxyOption{WithRegexpParam(true)},
			wantType:   "path",
			wantReason: "regexp",
			wantStart:  13,
			wantEnd:    14,
			wantMsg:    "illegal control character",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testProxy(t, tc.options...)
			_, _, err := p.parsePattern(tc.pattern, KindHTTP)
			var pe *PatternError
			require.ErrorAs(t, err, &pe)
			assert.Equal(t, tc.wantType, pe.Type)
			assert.Equal(t, tc.wantReason, pe.Reason)
			assert.Equal(t, tc.wantStart, pe.Start)
			assert.Equal(t, tc.wantEnd, pe.End)
			assert.Contains(t, pe.Error(), tc.wantMsg)
		})
	}
}

func TestPatternError_PointerLine(t *testing.T) {
	p := testProxy(t)

	t.Run("multi-byte rune gets a single caret", func(t *testing.T) {
		_, _, err := p.parsePattern("a.test/café", KindHTTP)
		var pe *PatternError
		require.ErrorAs(t, err, &pe)
		lines := strings.Split(pe.Error(), "\n")
		require.Len(t, lines, 3)
		assert.Equal(t, "      a.test/café", lines[1])
		assert.Equal(t, "                ^", lines[2])
	})

	t.Run("ascii span keeps one caret per character", func(t *testing.T) {
		_, _, err := p.parsePattern("a.test/a/./b", KindHTTP)
		var pe *PatternError
		require.ErrorAs(t, err, &pe)
		lines := strings.Split(pe.Error(), "\n")
		require.Len(t, lines, 3)
		assert.Equal(t, "      a.test/a/./b", lines[1])
		assert.Equal(t, "              ^^^", lines[2])
	})

	t.Run("multi-byte prefix keeps the caret aligned", func(t *testing.T) {
		pe := &PatternError{Pattern: "/héllo wörld", Reason: "syntax", Start: 7, End: 8}
		lines := strings.Split(pe.Error(), "\n")
		require.Len(t, lines, 3)
		assert.Equal(t, "      /héllo wörld", lines[1])
		assert.Equal(t, "            ^", lines[2])
	})

	t.Run("out of range offsets clamp", func(t *testing.T) {
		pe := &PatternError{Pattern: "/a", Reason: "syntax", Start: -1, End: 10}
		lines := strings.Split(pe.Error(), "\n")
		require.Len(t, lines, 3)
		assert.Equal(t, "      ^^", lines[2])
	})
}

func TestPatternError_Unwrap(t *testing.T) {
	t.Run("regexp error wraps the compile error", func(t *testing.T) {
		p := testProxy(t, WithRegexpParam(true))
		_, _, err := p.parsePattern("a.test/foo/{a:a{5,2}}", KindHTTP)
		var pe *PatternError
		require.ErrorAs(t, err, &pe)
		var syntaxErr *syntax.Error
		assert.ErrorAs(t, pe, &syntaxErr)
	})

	t.Run("regexp too large wraps ErrLarge", func(t *testing.T) {
		p := testProxy(t, WithRegexpParam(true))
		_, _, err := p.parsePattern("a.test/foo/{a:[a-z]{1,1000}}", KindHTTP)
		var syntaxErr *syntax.Error
		require.ErrorAs(t, err, &syntaxErr)
		assert.Equal(t, syntax.ErrLarge, syntaxErr.Code)
	})

	t.Run("syntax error wraps nothing", func(t *testing.T) {
		p := testProxy(t)
		_, _, err := p.parsePattern("a.test/foo/./bar", KindHTTP)
		var pe *PatternError
		require.ErrorAs(t, err, &pe)
		assert.Nil(t, pe.Unwrap())
		assert.Equal(t, "a.test/foo/./bar", pe.Pattern)
	})

	t.Run("empty pattern", func(t *testing.T) {
		p := testProxy(t)
		_, _, err := p.parsePattern("", KindHTTP)
		require.ErrorIs(t, err, ErrInvalidEntry)
		assert.False(t, errors.As(err, new(*PatternError)))
	})
}

func FuzzParsePattern(f *testing.F) {
	seeds := []string{
		"api.stripe.com/v1/charges",
		"https://api.stripe.com/v1/charges",
		"localhost:8080/api",
		"[::1]:8443/health",
		"[::1]/health",
		"+{sub}.stripe.com/v1/{id}",
		"/v1/charges",
		"127.0.0.1/health",
		"api.stripe.com/files/*{path}",
		"api.stripe.com/files/+{path}/meta",
		"://",
		"ftp://a.com/",
		"a.com:0/",
		"a.com:99999/",
		"a.com:08/",
		"",
		"/",
		"{}/",
		"a.com/%2F",
		"a.com/%zz",
		"[10.0.0.0/8]/api",
		"[fd00::/8]/v1/{id}",
		"[0.0.0.0/0]/+{rest}",
		"[::/0]/health",
		"[10.0.0.0/8]:8443/api",
		"[10.0.0.1/8]/api",
		"10.0.0.0/8",
		"10.0.0.0/8/api",
		"[10.0.0.0/8",
		"a.test/users/{id:[0-9]+}",
		"a.test/users/uuid:{id}/config",
		"a.test/bucket/+{path}/meta",
		"a.test/src/file=*{path}",
		"a.test/foo//+{bar}",
		"example.com//foo",
		"{sub}.example.com/users",
		"_srv.example.com/",
		"API.Example.COM/",
		".example.com/",
		"example.com./",
		"a.test/{",
		"a.test/+{}",
		"a.test/{id:[unclosed",
		"a.test/{id}{jd}",
		"a.test/\x00",
		"a.test/\xe9",
		"a.test/+{a}/+{b}",
		"a.test/*{path}/foo",
		"a.test/a%61b",
		"a.test/%2E%2E/",
		"a.test/100%",
		"a.test/emails/a+b",
		"a.test/a*{x}",
		"a.test/wayback/http://x.test",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	p := mustFuzzProxy(f)

	f.Fuzz(func(t *testing.T, raw string) {
		pat, _, err := p.parsePattern(raw, KindHTTP)
		if err != nil {
			return
		}

		if pat.str != raw {
			t.Fatalf("pattern.str = %q, want the input %q", pat.str, raw)
		}
		// The key is the pattern minus its port and the brackets of an address literal, with
		// an address host in its encoded form, so two patterns differing only by their port
		// share one node.
		wantKey := pat.host + pat.path
		if pat.prefix.IsValid() {
			wantKey = prefixKey(pat.prefix) + pat.path
		}
		if pat.key != wantKey {
			t.Fatalf("pattern.key = %q, want %q", pat.key, wantKey)
		}
		key, isAddr := patternKey(raw)
		if pat.key != key {
			t.Fatalf("patternKey(%q) = %q, want the parsed key %q", raw, key, pat.key)
		}
		if isAddr != pat.prefix.IsValid() {
			t.Fatalf("patternKey(%q) reports addr=%v, the parser says %v", raw, isAddr, pat.prefix.IsValid())
		}
		if pat.port != "" && strings.Index(raw, ":"+pat.port) < 0 {
			t.Fatalf("pattern.port = %q, which the input %q does not carry", pat.port, raw)
		}
	})
}

func FuzzParseAuthorityPattern(f *testing.F) {
	seeds := []string{
		"api.stripe.com",
		"localhost:8080",
		"+{sub}.stripe.com",
		"127.0.0.1",
		"[::1]:443",
		"https://api.stripe.com",
		"api.stripe.com/v1",
		"",
		":443",
		"a.com:",
		"[10.0.0.0/8]",
		"[fd00::/8]:443",
		"[0.0.0.0/0]",
		"[::/0]",
		"[10.0.0.1/8]",
		"10.0.0.0/8",
		"[fd00::1]",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	p := mustFuzzProxy(f)

	f.Fuzz(func(t *testing.T, raw string) {
		pat, _, err := p.parseAuthorityPattern(raw)
		if err != nil {
			return
		}
		// The empty path is what tells an authority entry from an interceptor once both are in
		// the same tree, and the key holding no '/' is what keeps the two lookups apart.
		if pat.path != "" {
			t.Fatalf("authority path = %q, want empty", pat.path)
		}
		wantKey := pat.host
		if pat.prefix.IsValid() {
			wantKey = prefixKey(pat.prefix)
		}
		if pat.key != wantKey {
			t.Fatalf("authority key %q is not %q", pat.key, wantKey)
		}
		if strings.Contains(pat.key, "/") {
			t.Fatalf("authority key %q must hold no path separator", pat.key)
		}
	})
}
