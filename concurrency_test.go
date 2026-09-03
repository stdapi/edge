// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrency_InterceptorMutationDuringTraffic changes the routing tree while requests are in
// flight. Lookups take no lock, so what this checks is that a reader never observes a
// partially applied write and that a writer never blocks one.
func TestConcurrency_InterceptorMutationDuringTraffic(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin %s", r.URL.Path)
	}))
	defer origin.Close()

	p, authority, client := interceptingProxy(t, origin)

	var served atomic.Int64
	p.MustAdd(authority+"/stable", func(c *HTTPCtx) (*http.Response, error) {
		served.Add(1)
		return Text(http.StatusOK, "stable"), nil
	}, WithMethods[HTTP](http.MethodGet))

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// A writer churning the tree: interceptors come and go for the whole run.
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}

			pattern := fmt.Sprintf("%s/churn/%d", authority, i%16)
			ic, err := p.Add(pattern, func(c *HTTPCtx) (*http.Response, error) {
				return Text(http.StatusOK, "churn"), nil
			}, WithMethods[HTTP](http.MethodGet))
			if err != nil {
				continue
			}
			// The matchers identify an entry, methods included, so a delete names the same
			// ones the add did.
			if _, err := p.Delete[HTTP](ic.Pattern(), WithMethods[HTTP](http.MethodGet)); err != nil {
				t.Errorf("delete %s: %v", pattern, err)
				return
			}
		}
	})

	// Readers hammering an interceptor the writer never touches.
	const readers = 8
	for range readers {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}

				resp, err := client.Get(origin.URL + "/stable")
				if err != nil {
					t.Errorf("get: %v", err)
					return
				}
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if string(body) != "stable" {
					t.Errorf("body = %q, want stable", body)
					return
				}
			}
		})
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	assert.Positive(t, served.Load(), "no request was served")
	assert.Equal(t, true, p.Admits(target(authority), KindHTTP), "the authority the stable interceptor implies must have survived the churn")
}

// TestConcurrency_AuthorityMutationDuringTraffic does the same for the authority entry set, which decides
// what happens to a connection before any request is parsed.
func TestConcurrency_AuthorityMutationDuringTraffic(t *testing.T) {
	p := testProxy(t)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			pattern := fmt.Sprintf("churn-%d.example.test", i%32)
			if _, err := p.Add[TCP](pattern, relayStream); err != nil {
				continue
			}
			if _, err := p.Delete[TCP](pattern); err != nil {
				t.Errorf("delete tunnel %s: %v", pattern, err)
				return
			}
		}
	})

	p.MustAdd("stable.example.test/*{any}", noopHandler)

	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if !p.Admits(target("stable.example.test:443"), KindHTTP) {
					t.Error("stable authority is not admitted")
					return
				}
				// Named by nothing, so it stays refused however the entry set churns.
				if p.Admits(target("other.example.test:443"), KindHTTP) {
					t.Error("unnamed authority is admitted")
					return
				}
			}
		})
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestConcurrency_LeafCacheIsMintedOnce checks that a burst of connections to one authority
// signs a single certificate rather than one per connection.
func TestConcurrency_LeafCacheIsMintedOnce(t *testing.T) {
	ca, err := GenerateCA()
	require.NoError(t, err)

	const goroutines = 64
	var (
		wg      sync.WaitGroup
		start   = make(chan struct{})
		mu      sync.Mutex
		serials = make(map[string]int)
	)

	for range goroutines {
		wg.Go(func() {
			<-start
			cert, err := ca.Leaf("burst.example.test")
			if err != nil {
				t.Errorf("leaf: %v", err)
				return
			}
			mu.Lock()
			serials[cert.Leaf.SerialNumber.String()]++
			mu.Unlock()
		})
	}

	close(start)
	wg.Wait()

	assert.Len(t, serials, 1, "the authority must have been signed once, got %d distinct certificates", len(serials))
}
