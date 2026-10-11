// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNode_ParseBraceSegment(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		end     int
		key     string
	}{
		{"simple param", "{name}", 5, "?"},
		{"param with regexp", "{name:regex}", 11, "regex"},
		{"single character param", "{a}", 2, "?"},
		{"param with complex regexp", "{id:[0-9]+}", 10, "[0-9]+"},
		{"param with nested braces in regexp", "{id:[0-9]{1,3}}", 14, "[0-9]{1,3}"},
		{"param followed by static", "{name}/foo", 5, "?"},
		{"simple wildcard", "+{path}", 6, "*"},
		{"wildcard with regexp", "+{path:regex}", 12, "regex"},
		{"wildcard with complex regexp", "+{file:[a-z]+\\.txt}", 18, "[a-z]+\\.txt"},
		{"wildcard followed by static", "+{path}/thumbnail", 6, "*"},
		{"empty string", "", 0, ""},
		{"empty braces", "{}", 1, "?"},
		{"empty wildcard braces", "+{}", 2, "*"},
		{"no braces", "static", 0, ""},
		{"opening brace alone", "{", 0, ""},
		{"closing brace alone", "}", 0, ""},
		{"asterisk alone", "*", 0, ""},
		{"asterisk without brace", "*path", 0, ""},
		{"unclosed param", "{name", 0, ""},
		{"unclosed wildcard", "+{path", 0, ""},
		{"unclosed with content", "{name:regex", 0, ""},
		{"colon alone in braces", "{:}", 2, ""},
		{"colon at start of param key", "{:regex}", 7, "regex"},
		{"colon then brace", ":foo{bar}", 0, ""},
		{"unbalanced nested braces", "{id:[0-9]{1,3}", 0, ""},
		{"slash alone", "/", 0, ""},
		{"path without param", "/users/list", 0, ""},
		{"closing before opening", "}name{", 0, ""},
		{"double opening brace", "{{name}", 0, ""},
		{"double closing brace", "{name}}", 5, "?"},
		{"asterisk and space before a brace", "* {path}", 0, ""},
		{"literal star before brace segment", "*0{id}", 0, ""},
		{"literal plus before brace segment", "+a{id}", 0, ""},
		{"brace in middle of static", "foo{bar}baz", 7, "?"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			end, key := parseBraceSegment(tc.pattern)
			assert.Equal(t, tc.end, end)
			assert.Equal(t, tc.key, key)
		})
	}
}

func FuzzParseBraceSegment(f *testing.F) {
	for _, s := range []string{
		"{name}", "{a}", "{id:[0-9]+}", "{id:[0-9]{1,3}}", "{name}/foo",
		"+{path}", "+{path:regex}", "+{file:[a-z]+\\.txt}", "+{path}/thumbnail",
		"*{path}", "*{filepath}", "*{any:[a-z]+}", "*{path}/thumbnail",
		"", "{}", "+{}", "*{}",
		"{", "}", "+{", "*{",
		"{name", "+{path", "*{path", "{name:regex",
		"{id:[0-9]{1,3}", "}name{", "{{name}", "{name}}",
		"static", "/", "/users/list", "foo{bar}baz",
		"{:}", "{:regex}", "+{:regex}", "*{:regex}",
		":foo{bar}", "* {path}", "*", "*path", "+", "+path",
		"{\x80}", "+{\xff}", "*{\x80}", "\x00{name}",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, pattern string) {
		end, key := parseBraceSegment(pattern)
		if end < 0 || end >= max(len(pattern), 1) {
			t.Fatalf("end %d out of %q", end, pattern)
		}
		if end == 0 && key != "" {
			t.Fatalf("key %q without a segment in %q", key, pattern)
		}
	})
}

func TestNode_String(t *testing.T) {
	p := testProxy(t)
	q, err := MatchQuery("a", "b")
	require.NoError(t, err)
	h, err := MatchHeader("b", "c")
	require.NoError(t, err)

	p.MustAdd("a.test/foo/{bar}/+{baz}", noopHandler, WithMethods[HTTP](http.MethodGet))
	p.MustAdd("a.test/foo/bar", noopHandler, WithRequestMatchers[HTTP](q, h))
	p.MustAdd("a.test/foo/bar", noopHandler, WithRequestMatchers[HTTP](q), WithMethods[HTTP](http.MethodPost, http.MethodDelete))
	p.MustAdd("a.test/foo/bar", relayFrames)
	p.MustAdd[TCP]("a.test:25", noopStream)

	want := `root:
      path: a.test (host)
            => a.test:25 [kind: TCP] [priority: 0]
            => a.test [kind: HTTP] [priority: 0]
          path: /foo/ [params: 1]
              path: bar
                    => a.test/foo/bar [kind: WebSocket] [priority: 0]
                    => a.test/foo/bar [kind: HTTP] [matchers: query:a=b, header:B=c] [priority: 2]
                    => a.test/foo/bar [kind: HTTP] [matchers: query:a=b, method=DELETE,POST] [priority: 2]
              path: ?
                  path: / [wildcards: 1]
                      path: *
                            => a.test/foo/{bar}/+{baz} [kind: HTTP] [matchers: method=GET] [priority: 1]`
	assert.Equal(t, want, strings.TrimSuffix(p.getTree().patterns.String(), "\n"))
}

func TestNode_EntryOrder(t *testing.T) {
	p := testProxy(t)
	q, err := MatchQuery("a", "b")
	require.NoError(t, err)
	h, err := MatchHeader("b", "c")
	require.NoError(t, err)

	plain := p.MustAdd("a.test/x", noopHandler)
	low := p.MustAdd("a.test/x", noopHandler, WithRequestMatchers[HTTP](q))
	high := p.MustAdd("a.test/x", noopHandler, WithRequestMatchers[HTTP](q, h))
	pinned := p.MustAdd("a.test/x", noopHandler, WithRequestMatchers[HTTP](h), WithMatchersPriority[HTTP](10))
	ws := p.MustAdd("a.test/x", relayFrames)
	port := p.MustAdd("a.test:8080/x", noopHandler)
	portWS := p.MustAdd("a.test:8080/x", relayFrames)

	n := p.getTree().patterns.searchPattern("a.test/x")
	require.NotNil(t, n)
	assert.Equal(t, []*entry{portWS.e, port.e, ws.e, pinned.e, high.e, low.e, plain.e}, n.entries)

	updated, err := p.Update("a.test/x", noopHandler, WithRequestMatchers[HTTP](h))
	require.NoError(t, err)
	n = p.getTree().patterns.searchPattern("a.test/x")
	assert.Equal(t, []*entry{portWS.e, port.e, ws.e, high.e, low.e, updated.e, plain.e}, n.entries)
}
