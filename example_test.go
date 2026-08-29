// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge_test

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/fox-toolkit/edge"
)

// Capture the traffic of an application under test: intercept one API, tunnel everything
// else end to end.
func Example() {
	ca, err := edge.GenerateCA()
	if err != nil {
		log.Fatal(err)
	}

	p, err := edge.New(edge.WithCA(ca))
	if err != nil {
		log.Fatal(err)
	}

	p.MustAddInterceptor([]string{http.MethodPost}, "api.stripe.com/v1/charges", func(c *edge.Context) (*http.Response, error) {
		if c.Request().Header.Get("Idempotency-Key") == "" {
			return edge.Text(http.StatusBadRequest, "missing idempotency key"), nil
		}
		return c.Forward()
	})

	// The application needs to trust the authority the proxy signs with.
	if err := os.WriteFile("ca.pem", ca.CertificatePEM(), 0o600); err != nil {
		log.Fatal(err)
	}

	log.Fatal(p.ListenAndServe(":8080"))
}

// Rewrite a response on the way back to the client.
func ExampleRewrite() {
	ca, _ := edge.GenerateCA()
	p, _ := edge.New(edge.WithCA(ca))

	p.MustAddInterceptor([]string{http.MethodGet}, "api.example.test/v1/status", func(c *edge.Context) (*http.Response, error) {
		resp, err := c.Forward()
		if err != nil {
			return nil, err
		}

		// DecodeBody undoes any Content-Encoding and drops the header, so the patched bytes
		// can go straight back out.
		body, err := edge.DecodeBody(resp, 1<<20)
		if err != nil {
			return nil, err
		}

		patched := bytes.ReplaceAll(body, []byte(`"healthy"`), []byte(`"degraded"`))
		return edge.Rewrite(resp, patched), nil
	})
}

// Tell apart two local services that share a host, which is what a test environment is
// usually made of. The port belongs to the pattern.
func Example_port() {
	ca, _ := edge.GenerateCA()
	p, _ := edge.New(edge.WithCA(ca))

	p.MustAddInterceptor([]string{http.MethodGet}, "localhost:8080/api/health", func(c *edge.Context) (*http.Response, error) {
		return edge.Text(http.StatusOK, "stubbed"), nil
	})

	fmt.Println(p.InterceptorsLen())
	// Output: 1
}

// Carve a tunnel out of a broader interception. Authorities are evaluated most specific
// first, so a static authority beats a wildcard. Nothing about traffic policy is decided at
// construction: authorities change while the proxy is serving. An authority named by neither is
// refused, so an application reaching somewhere the test did not plan for says so.
func ExampleProxy_AddTunnel() {
	ca, _ := edge.GenerateCA()

	p, err := edge.New(edge.WithCA(ca))
	if err != nil {
		log.Fatal(err)
	}

	// An interceptor names the authority it intercepts, so registering one arms it. Here nothing
	// is rewritten, the catch-all just forwards, which is enough to observe the traffic.
	if _, err := p.AddInterceptor(nil, "+{sub}.stripe.com/*{any}", edge.DefaultNoInterceptorHandler); err != nil {
		log.Fatal(err)
	}
	if err := p.AddTunnel("checkout.stripe.com"); err != nil {
		log.Fatal(err)
	}

	fmt.Println(p.Decide(edge.Target{Scheme: "https", Host: "api.stripe.com", Port: "443"}))
	fmt.Println(p.Decide(edge.Target{Scheme: "https", Host: "checkout.stripe.com", Port: "443"}))
	fmt.Println(p.Decide(edge.Target{Scheme: "https", Host: "example.test", Port: "443"}))
	// Output:
	// intercept
	// tunnel
	// reject
}

// Record every request that crosses the proxy, whatever it is routed to.
func ExampleWithMiddleware() {
	ca, _ := edge.GenerateCA()

	var recorded []string
	record := func(next edge.HandlerFunc) edge.HandlerFunc {
		return func(c *edge.Context) (*http.Response, error) {
			recorded = append(recorded, c.Method()+" "+c.Scheme()+"://"+c.Authority()+c.RoutingPath())
			return next(c)
		}
	}

	p, _ := edge.New(
		edge.WithCA(ca),
		edge.WithMiddleware(record),
	)
	// A catch-all that forwards untouched: it arms the authority and records its traffic
	// without changing a byte of it.
	_, _ = p.AddInterceptor(nil, "api.example.test/*{any}", edge.DefaultNoInterceptorHandler)
}

// Change routes while traffic is flowing. Lookups never block on a write.
func ExampleProxy_Updates() {
	ca, _ := edge.GenerateCA()
	p, _ := edge.New(edge.WithCA(ca))

	err := p.Updates(func(txn *edge.Txn) error {
		if _, err := txn.AddInterceptor([]string{http.MethodGet}, "api.example.test/v1/health", failOnce()); err != nil {
			return err
		}
		_, err := txn.AddInterceptor([]string{http.MethodPost}, "api.example.test/v1/orders", failOnce())
		return err
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(p.InterceptorsLen())
	// Output: 2
}

// failOnce returns a handler that fails the first request it sees and forwards the rest,
// which is the shape of most fault injection in a test.
func failOnce() edge.HandlerFunc {
	var failed bool
	return func(c *edge.Context) (*http.Response, error) {
		if !failed {
			failed = true
			return edge.Status(http.StatusServiceUnavailable), nil
		}
		return c.Forward()
	}
}
