// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net/http"
	"strings"
	"testing"
)

// FuzzParsePattern checks that no input makes the pattern parser panic, and that a pattern
// it accepts is indexed under itself. The tree key is the pattern byte for byte, which is
// what makes a registered interceptor findable again by the string it was registered with.
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
	}
	for _, s := range seeds {
		f.Add(s)
	}

	p := mustFuzzProxy(f)

	f.Fuzz(func(t *testing.T, raw string) {
		pat, _, err := p.parsePattern(raw)
		if err != nil {
			return
		}

		if pat.str != raw {
			t.Fatalf("pattern.str = %q, want the input %q", pat.str, raw)
		}
		// The key is the pattern minus its port and the brackets of an address literal, so
		// two patterns differing only by their port share one node.
		if pat.key != pat.host+pat.path {
			t.Fatalf("pattern.key = %q, want host %q plus path %q", pat.key, pat.host, pat.path)
		}
		if pat.key != patternKey(raw) {
			t.Fatalf("patternKey(%q) = %q, want the parsed key %q", raw, patternKey(raw), pat.key)
		}
		if pat.port != "" && strings.Index(raw, ":"+pat.port) < 0 {
			t.Fatalf("pattern.port = %q, which the input %q does not carry", pat.port, raw)
		}
	})
}

// FuzzRoundTripRegistration checks that an interceptor the proxy accepts can be found again by the
// pattern it was registered with, and deleted by it.
func FuzzRoundTripRegistration(f *testing.F) {
	seeds := []string{
		"api.stripe.com/v1/charges",
		"127.0.0.1/health",
		"+{sub}.corp.internal/health",
		"/v1/charges",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		p := mustFuzzProxy(t)

		rte, err := p.AddInterceptor([]string{http.MethodGet}, raw, noopHandler)
		if err != nil {
			return
		}

		found := p.Interceptor([]string{http.MethodGet}, raw)
		if found == nil {
			t.Fatalf("route registered as %q cannot be found again", raw)
		}
		if found != rte {
			t.Fatalf("Interceptor returned a different entry for %q", raw)
		}

		deleted, err := p.DeleteInterceptor([]string{http.MethodGet}, raw)
		if err != nil {
			t.Fatalf("delete %q: %v", raw, err)
		}
		if deleted != rte {
			t.Fatalf("Delete returned a different route for %q", raw)
		}
		if p.InterceptorsLen() != 0 {
			t.Fatalf("tree still holds %d routes after deleting %q", p.InterceptorsLen(), raw)
		}
	})
}

// FuzzParseAuthorityPattern does the same for interception authorities, which carry an authority
// and no path.
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
		if pat.key != pat.host {
			t.Fatalf("authority key %q is not the host %q", pat.key, pat.host)
		}
		if strings.Contains(pat.key, "/") {
			t.Fatalf("authority key %q must hold no path separator", pat.key)
		}
	})
}

// FuzzSplitHostPort checks the authority splitter against its inverse. Everything the proxy
// routes on goes through it, including hostile authorities off the wire.
func FuzzSplitHostPort(f *testing.F) {
	seeds := []string{
		"api.stripe.com:443",
		"api.stripe.com",
		"[::1]:8080",
		"[::1]",
		"::1",
		"",
		":",
		":443",
		"a:b:c",
		"[",
		"]",
		"[]:1",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, authority string) {
		host, port := splitHostPort(authority)

		// Splitting and rejoining is idempotent. A malformed authority has no canonical
		// form to round-trip to, but once the pair has been through joinHostPort it must
		// survive every further pass: targets are split and rejoined all along the path a
		// request takes.
		joined := joinHostPort(host, port)
		host2, port2 := splitHostPort(joined)
		if host2 != host || port2 != port {
			t.Fatalf("split(%q) = (%q, %q), then split(join(...)) = (%q, %q)", authority, host, port, host2, port2)
		}
	})
}

func mustFuzzProxy(tb testing.TB) *Proxy {
	tb.Helper()
	ca, err := GenerateCA()
	if err != nil {
		tb.Fatal(err)
	}
	p, err := New(WithCA(ca), WithRegexpParam(true))
	if err != nil {
		tb.Fatal(err)
	}
	return p
}
