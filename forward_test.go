// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net/http"
	"testing"
)

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
