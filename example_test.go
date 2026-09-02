// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/fox-toolkit/edge"
)

// The handler signature selects the kind of traffic served, so no type argument is needed.
func ExampleProxy_Add() {
	ca, err := edge.GenerateCA()
	if err != nil {
		log.Fatal(err)
	}
	p := edge.Must(edge.WithCA(ca))

	// One request, on a hostname and a path.
	p.MustAdd("api.stripe.com/v1/charges/{id}", func(c *edge.HTTPCtx) (*http.Response, error) {
		if c.Param("id") == "ch_denied" {
			return edge.Text(http.StatusPaymentRequired, "declined"), nil
		}
		return c.Forward()
	}, edge.WithMethods(http.MethodGet, http.MethodPost))

	// The catch-all is a route, not a hidden default: what passes through is written down.
	p.MustAdd("api.stripe.com/*{any}", func(c *edge.HTTPCtx) (*http.Response, error) {
		return c.Forward()
	})

	fmt.Println(p.Len())
	// Output: 2
}

// A kind that routes whole connections is keyed on an authority alone, with no path.
func ExampleProxy_Add_stream() {
	ca, _ := edge.GenerateCA()
	p := edge.Must(edge.WithCA(ca))

	p.MustAdd[edge.TCP]("smtp.test:465", func(c *edge.TCPCtx) error {
		// TLS is already terminated, so the bytes are in the clear and the upstream
		// handshake mirrors what the client asked for.
		log.Printf("smtp over %q", c.ALPN())
		up, err := c.Dial()
		if err != nil {
			return err
		}
		// Shaping is a wrapper on one side, so it applies to one direction alone.
		_, _, err = edge.Relay(c.Client(), edge.Throttled(up, 256<<10))
		return err
	})

	fmt.Println(p.Admits(edge.Target{Scheme: "https", Host: "smtp.test", Port: "465"}, edge.KindTCP))
	// Output: true
}

func ExampleTCPCtx_StartTLS() {
	ca, _ := edge.GenerateCA()
	p := edge.Must(edge.WithCA(ca))

	// Postgres starts in the clear: the client sends an 8-byte SSLRequest and the server
	// answers 'S' before the handshake. The handler relays that exchange, then terminates.
	p.MustAdd[edge.TCP]("db.test:5432", func(c *edge.TCPCtx) error {
		up, err := c.Dial()
		if err != nil {
			return err
		}
		var req [8]byte
		if _, err := io.ReadFull(c.Client(), req[:]); err != nil {
			return err
		}
		if _, err := up.Write(req[:]); err != nil {
			return err
		}
		var answer [1]byte
		if _, err := io.ReadFull(up, answer[:]); err != nil {
			return err
		}
		if _, err := c.Client().Write(answer[:]); err != nil {
			return err
		}
		if answer[0] == 'S' {
			if err := c.StartTLS(); err != nil {
				return err
			}
		}
		return c.Relay()
	})

	fmt.Println(p.Admits(edge.Target{Scheme: "http", Host: "db.test", Port: "5432"}, edge.KindTCP))
	// Output: true
}

// Datagrams have units to lose, which is what makes drop and delay expressible.
func ExampleProxy_Add_datagram() {
	p := edge.Must()

	p.MustAdd("[0.0.0.0/0]:53", func(d *edge.DatagramCtx) error {
		if d.Seq()%50 == 0 {
			return d.Drop()
		}
		return d.Forward(edge.Delay(20 * time.Millisecond))
	})

	fmt.Println(p.Len())
	// Output: 1
}

// A gRPC entry and an HTTP entry can name the same path. The request tells them apart.
func ExampleProxy_Add_grpc() {
	ca, _ := edge.GenerateCA()
	p := edge.Must(edge.WithCA(ca))

	var calls int
	p.MustAdd("api.test/billing.v1.Billing/Charge", func(c *edge.GRPCCtx) error {
		calls++
		if calls <= 2 {
			return c.Fail(edge.Unavailable, "upstream flaky")
		}
		return c.Forward()
	})

	fmt.Println(p.Admits(edge.Target{Scheme: "https", Host: "api.test", Port: "443"}, edge.KindHTTP))
	// Output: true
}

// Past the 101 a connection is no longer HTTP, so its unit is the frame.
func ExampleProxy_Add_webSocket() {
	ca, _ := edge.GenerateCA()
	p := edge.Must(edge.WithCA(ca))

	p.MustAdd("chat.test/ws", func(c *edge.WebSocketCtx) error {
		src := edge.MergeFrames(c.Outbound(), c.Inbound())
		for {
			f, err := src.ReadFrame()
			if err != nil {
				return nil
			}
			// The ping is swallowed rather than relayed, to see how the client's
			// keepalive reacts.
			if !f.Inbound() && f.Opcode() == edge.OpPing {
				continue
			}
			if err := f.Forward(); err != nil {
				return err
			}
		}
	})

	fmt.Println(p.Len())
	// Output: 1
}

// Entries change while traffic flows, and every unit is routed on the tree as it stands.
func ExampleProxy_Updates() {
	ca, _ := edge.GenerateCA()
	p := edge.Must(edge.WithCA(ca))
	p.MustAdd("api.test/v1", func(c *edge.HTTPCtx) (*http.Response, error) { return c.Forward() })

	err := p.Updates(func(txn *edge.Txn) error {
		if _, err := txn.Delete[edge.HTTP]("api.test/v1"); err != nil {
			return err
		}
		_, err := txn.Add("api.test/v1", func(c *edge.HTTPCtx) (*http.Response, error) {
			return edge.Text(http.StatusTeapot, "closed"), nil
		})
		return err
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(p.Len())
	// Output: 1
}

// Removing an entry governs the next request on connections that are already open. Closing is
// for ending a connection on its own terms, revoking an identity being the usual one.
func ExampleProxy_Sessions() {
	ca, _ := edge.GenerateCA()
	p := edge.Must(edge.WithCA(ca))

	revoked := "alice"
	for s := range p.Sessions() {
		if s.Identity() == revoked {
			_ = s.Close()
		}
	}
	fmt.Println("swept")
	// Output: swept
}
