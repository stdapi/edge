# Edge

Edge is an intercepting forward proxy library for [Go](https://go.dev/), designed for building debugging proxies,
fault injection tools, traffic recorders, egress gateways, or other applications that need to inspect and control the
traffic a client sends over the network. It terminates TLS with certificates issued on demand by a certificate
authority the client trusts, and supports HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket, TCP, QUIC and UDP. Edge aims to
give every kind of traffic, from an HTTP request to a UDP datagram, its own handler, as simple to write as an HTTP
handler.

Edge supports **mutation on its routing tree while proxying traffic concurrently**. Internally, it uses a Radix Tree
adapted from [Fox](https://github.com/fox-toolkit/fox) that supports **lock-free** reads while allowing a concurrent
writer. Entries support flexible patterns on the hostname, the port and the path, with named parameters, catch-all
wildcards, regexp constraints, address ranges and request matchers. Edge enforces clear priority rules and performs strict
validation to prevent misconfigurations.

> [!WARNING]
> Edge is experimental. The API is not stabilized, and breaking changes may occur at any time.

## Features
### Client to proxy

<table>
<thead>
<tr>
  <th colspan="2" rowspan="2">Traffic</th>
  <th colspan="4">Explicit<sup>1</sup></th>
  <th rowspan="2">Transparent<sup>2</sup><br><sub>routed on</sub></th>
</tr>
<tr>
  <th>HTTP/1.1</th>
  <th>HTTP/2</th>
  <th>HTTP/3</th>
  <th>SOCKS5</th>
</tr>
</thead>
<tbody>
<tr>
  <th rowspan="4">Over TCP</th>
  <th>HTTP<br><sub>HTTP/1.1, HTTP/2</sub></th>
  <td>request<br>CONNECT</td>
  <td>request<br>CONNECT</td>
  <td>request<br>CONNECT</td>
  <td>CONNECT</td>
  <td>SNI, Host<br>or destination</td>
</tr>
<tr>
  <th>gRPC</th>
  <td colspan="5">as HTTP, HTTP/3 included</td>
</tr>
<tr>
  <th>WebSocket</th>
  <td colspan="5">as HTTP/1.1</td>
</tr>
<tr>
  <th>TCP</th>
  <td colspan="4">CONNECT</td>
  <td>SNI, Host<br>or destination</td>
</tr>
<tr>
  <th rowspan="3">Over UDP</th>
  <th>HTTP<br><sub>HTTP/3</sub></th>
  <td colspan="2" rowspan="3">CONNECT-UDP<sup>3</sup><br>DATAGRAM capsules</td>
  <td>request<br>CONNECT-UDP<br>QUIC DATAGRAM frames</td>
  <td rowspan="3">UDP ASSOCIATE</td>
  <td rowspan="2">SNI<br>or destination</td>
</tr>
<tr>
  <th>QUIC</th>
  <td rowspan="2">CONNECT-UDP<br>QUIC DATAGRAM frames</td>
</tr>
<tr>
  <th>UDP</th>
  <td>destination</td>
</tr>
</tbody>
</table>

1. Proxy authentication with HTTP Basic or a custom `ProxyAuthenticator`, and with a username and a password on SOCKS5.
2. Requires Linux with REDIRECT or TPROXY, TPROXY for UDP, or macOS with pf and read access to `/dev/pf`.
3. CONNECT-UDP over HTTP/2 requires `GODEBUG=http2xconnect=1`, which enables extended CONNECT in the Go HTTP/2 server.

### Proxy to origin

<table>
<thead>
<tr>
  <th colspan="2" rowspan="2">Traffic</th>
  <th rowspan="2">Direct</th>
  <th colspan="4">Chained</th>
</tr>
<tr>
  <th><code>http</code>, <code>https</code><br><sub>HTTP/1.1</sub></th>
  <th><code>https</code><br><sub>HTTP/2</sub></th>
  <th><code>https</code><br><sub>HTTP/3</sub></th>
  <th><code>socks5</code>, <code>socks5h</code></th>
</tr>
</thead>
<tbody>
<tr>
  <th rowspan="4">Over TCP</th>
  <th>HTTP<br><sub>HTTP/1.1, HTTP/2</sub></th>
  <td rowspan="2">HTTP/1.1, HTTP/2, h2c<sup>1</sup></td>
  <td colspan="3" rowspan="4">CONNECT</td>
  <td rowspan="4">CONNECT</td>
</tr>
<tr>
  <th>gRPC</th>
</tr>
<tr>
  <th>WebSocket</th>
  <td>HTTP/1.1</td>
</tr>
<tr>
  <th>TCP</th>
  <td>TCP or TLS</td>
</tr>
<tr>
  <th rowspan="3">Over UDP</th>
  <th>HTTP<br><sub>HTTP/3</sub></th>
  <td>HTTP/3<sup>2</sup></td>
  <td colspan="2" rowspan="3">CONNECT-UDP<br>DATAGRAM capsules</td>
  <td rowspan="3">CONNECT-UDP<br>QUIC DATAGRAM frames</td>
  <td rowspan="3">UDP ASSOCIATE</td>
</tr>
<tr>
  <th>QUIC</th>
  <td>QUIC</td>
</tr>
<tr>
  <th>UDP</th>
  <td>UDP</td>
</tr>
</tbody>
</table>

1. h2c for gRPC, and for HTTP only when the client used h2c through a tunnel or a transparent listener.
2. Opt-in with `Transport.AllowHTTP3`.

---
* [Getting started](#getting-started)
  * [Install](#install)
  * [Basic example](#basic-example)
* [License](#license)
---

## Getting started
#### Install
With a [correctly configured](https://go.dev/doc/install#testing) Go toolchain:
```shell
go get -u github.com/stdapi/edge
```
This library requires Go 1.27 or above.

#### Basic example
The proxy below intercepts the outbound traffic of a checkout service under test. It refuses a Stripe charge sent
without an idempotency key, fails one method of a gRPC inventory service, and throttles the responses of a Redis cache
to 64 KiB/s.

```go
package main

import (
	"log"
	"net/http"

	"github.com/stdapi/edge"
)

func main() {
	ca, err := edge.LoadCAFile("ca.pem", "ca-key.pem")
	if err != nil {
		log.Fatal(err)
	}

	p := edge.Must(edge.WithCA(ca))

	// Refuse a charge without an idempotency key, forward the others to Stripe.
	p.MustAdd("api.stripe.com/v1/charges", func(c *edge.HTTPCtx) (*http.Response, error) {
		if c.Header("Idempotency-Key") == "" {
			return edge.Text(http.StatusBadRequest, "missing idempotency key"), nil
		}
		return c.Forward()
	}, edge.WithMethods[edge.HTTP](http.MethodPost))

	// Every other Stripe endpoint is forwarded unchanged.
	p.MustAdd("api.stripe.com/*{any}", func(c *edge.HTTPCtx) (*http.Response, error) {
		return c.Forward()
	})

	// One gRPC method fails with UNAVAILABLE, the other methods are forwarded.
	p.MustAdd("inventory.internal/inventory.v1.Inventory/Reserve", func(c *edge.GRPCCtx) error {
		return c.Fail(edge.CodeUnavailable, "inventory unavailable")
	})
	p.MustAdd("inventory.internal/*{method}", func(c *edge.GRPCCtx) error {
		return c.Forward()
	})

	// Throttle the responses of the cache to 64 KiB/s.
	p.MustAdd("cache.internal:6379", func(c *edge.TCPCtx) error {
		up, err := c.Dial()
		if err != nil {
			return err
		}
		_, _, err = edge.Relay(edge.Throttled(c.Client(), 64<<10), up)
		return err
	})

	go func() { log.Fatal(p.ListenAndServeSOCKS5(":1080")) }()
	log.Fatal(p.ListenAndServe(":8080"))
}
```

## License
Apache-2.0. The routing core is adapted from [Fox](https://github.com/fox-toolkit/fox), under the same license.
