// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net/http"
	"testing"
)

// FuzzRoundTripRegistration checks that an interceptor the proxy accepts can be found again by the
// pattern it was registered with, and deleted by it.
func FuzzRoundTripRegistration(f *testing.F) {
	seeds := []string{
		"api.stripe.com/v1/charges",
		"127.0.0.1/health",
		"+{sub}.corp.internal/health",
		"/v1/charges",
		"[10.0.0.0/8]/api",
		"[fd00::/8]/v1/{id}",
		"[::1]/8/metrics",
		"10.0.0.1/32",
		"[::/0]/+{rest}",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		p := mustFuzzProxy(t)

		ic, err := p.Add(raw, noopHandler, WithMethods[HTTP](http.MethodGet))
		if err != nil {
			return
		}

		found := lookupHTTP(p, raw, mustMethods(http.MethodGet))
		if found == (Entry[HTTP]{}) {
			t.Fatalf("entry registered as %q cannot be found again", raw)
		}
		if found != ic {
			t.Fatalf("Lookup returned a different entry for %q", raw)
		}

		deleted, err := p.Delete[HTTP](raw, WithMethods[HTTP](http.MethodGet))
		if err != nil {
			t.Fatalf("delete %q: %v", raw, err)
		}
		if deleted != ic {
			t.Fatalf("Delete returned a different interceptor for %q", raw)
		}
		if p.Len() != 0 {
			t.Fatalf("tree still holds %d interceptors after deleting %q", p.Len(), raw)
		}
	})
}
