// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestForward_407FromTheProxyIsBadGateway(t *testing.T) {
	b := newUpstreamBench(t, nil, upstreamH1("", "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"upstream\"\r\nContent-Length: 0\r\n\r\n"))
	got := b.exchange(t, "GET", "GET http://origin.test/x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	assert.Equal(t, http.StatusBadGateway, got.resp.StatusCode)
	assert.Empty(t, fieldValues(got.head, "Proxy-Authenticate"))
}

func BenchmarkStripHopByHop(b *testing.B) {
	// The common case: an ordinary request with nothing connection-scoped to remove, where
	// the header map is left untouched and can be reused across iterations.
	b.Run("nothing to strip", func(b *testing.B) {
		h := http.Header{
			"Accept":          {"*/*"},
			"User-Agent":      {"edge-bench"},
			"Accept-Encoding": {"gzip, deflate, br"},
			"Authorization":   {"Bearer token"},
		}
		b.ReportAllocs()
		for b.Loop() {
			stripHopByHop(h)
		}
	})

	// The case that does work. The clone is inside the loop because the strip is
	// destructive, so its cost is part of what is measured.
	b.Run("with hop by hop", func(b *testing.B) {
		base := http.Header{
			"Connection":       {"Keep-Alive, X-Custom"},
			"Proxy-Connection": {"keep-alive"},
			"Keep-Alive":       {"timeout=5"},
			"X-Custom":         {"value"},
			"Accept":           {"*/*"},
			"User-Agent":       {"edge-bench"},
		}
		b.ReportAllocs()
		for b.Loop() {
			stripHopByHop(base.Clone())
		}
	})
}
