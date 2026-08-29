# Edge

Edge is a forward HTTP proxy library for Go. It tunnels the traffic it was not asked to look at and intercepts the rest, terminating TLS with a local certificate authority so your code can inspect and rewrite requests and responses in flight.

It was built to capture the outbound traffic of an application under end-to-end test without the application being able to tell. What goes upstream is what the client sent, byte for byte, minus only the hop-by-hop headers a proxy must not relay. The HTTP version is mirrored in both directions. Bodies are never decompressed on the way through. Nothing is added: no `Via`, no `X-Forwarded-For`, no `Accept-Encoding` of the proxy's own.

Routing uses an immutable radix tree with lock-free reads and single-writer semantics, adapted from [Fox](https://github.com/fox-toolkit/fox). Routes and interception rules change while traffic flows, without blocking a lookup.

```go
ca, _ := edge.GenerateCA()

p, _ := edge.New(
    edge.WithCA(ca),
    // MITM these authorities, tunnel everything else end to end
    edge.WithIntercept("+{sub}.stripe.com", "api.internal.corp"),
)

p.MustHandle([]string{"POST"}, "api.stripe.com/v1/charges", func(c *edge.Context) (*http.Response, error) {
    // 1. inspect the request, block it or change it
    if c.Request().Header.Get("Idempotency-Key") == "" {
        return edge.Text(400, "missing idempotency key"), nil
    }
    c.Request().Header.Set("X-Test-Run", runID)

    // 2. forward to the real upstream
    resp, err := c.Forward()
    if err != nil {
        return nil, err
    }

    // 3. inspect and rewrite the response
    body, err := edge.ReadBody(resp, 0)
    if err != nil {
        return nil, err
    }
    return edge.Rewrite(resp, injectFault(body)), nil
})

log.Fatal(p.ListenAndServe(":8080"))
```

Point the application at it with `HTTPS_PROXY=http://localhost:8080` and install `ca.CertificatePEM()` in its trust store.

## What it supports

|                      | HTTP/1.1 | HTTP/2 | HTTP/3 |
| -------------------- | -------- | ------ | ------ |
| Explicit proxy       | yes      | yes    | n/a    |
| Transparent redirect | yes      | yes    | yes    |
| Tunnel end to end    | yes      | yes    | yes    |
| Intercept and route  | yes      | yes    | yes    |

HTTP/3 has no `CONNECT` a client can be pointed at: a proxy setting sends it back to TCP. It is therefore reached transparently, with the client's datagrams routed to the proxy by the network.

Protocol upgrades, including WebSocket, are spliced through in both modes. Server-sent events and other streamed bodies are relayed as they are produced, not buffered. Trailers are forwarded.

## Two axes, not one

It is worth separating two things that both get called "transparent":

**How the client reaches the proxy.** Either *explicitly*, configured with a proxy setting, sending `CONNECT` or an absolute request target; or *transparently*, not configured at all, with its packets redirected by the network, leaving the proxy to work out where they were headed.

**What the proxy does with the connection.** Either *tunnel*, relaying bytes so the client's TLS stays end to end and the proxy never sees the plaintext; or *intercept*, terminating TLS with a minted certificate so handlers can see and change what goes past.

The two combine freely. Most test setups want an explicit proxy that intercepts a handful of authorities and tunnels the rest. An application that ignores proxy environment variables needs the transparent listener instead.

## Interception rules

A connection is placed by its authority, before any request is parsed. Rules live in their own tree and are evaluated most specific first: a static authority beats a parameter, which beats a wildcard.

```go
p, _ := edge.New(
    edge.WithCA(ca),
    edge.WithIntercept("+{sub}.stripe.com"),  // every subdomain
    edge.WithTunnel("checkout.stripe.com"),   // except this one, static wins
    edge.WithReject("telemetry.vendor.test"), // refuse outright
)
```

Registering a handler implicitly marks its authority for interception, so a route always sees the traffic it was written for. Those implicit rules are reference counted and disappear with the last route that needed them. An explicit rule always wins over an implicit one.

Without a rule and without a route, the default is to tunnel: traffic the proxy was not asked about stays opaque to it. `WithDefaultAction(edge.Intercept)` flips that.

`p.Decide(target)` answers what would happen to an authority without opening a connection.

## Patterns

A pattern is a hostname and a path.

```
api.stripe.com/v1/charges           any scheme, any port
+{sub}.corp.internal/health         every subdomain
127.0.0.1/health                    address literal
::1/health                          IPv6, no brackets
/v1/charges                         every authority
```

Parameters use Fox's syntax:

- Named: `{name}`, or `{name:[a-z]+}` with `WithRegexpParam` enabled
- Wildcards: `*{param}` matches empty, suffix only; `+{param}` needs at least one character and works as a prefix, infix or suffix

Matching priority is static, then regex parameter, then parameter, then regex wildcard, then wildcard, with backtracking to the last decision point.

An address literal has one spelling, the one a request presents: `::1`, not `[::1]` or `::0001`.

### Scheme and port

They are matchers, not part of the pattern:

```go
p.MustHandle([]string{"GET"}, "localhost/api", api, edge.WithPort("8080"))
p.MustHandle([]string{"GET"}, "localhost/", ui, edge.WithPort("3000"))
p.MustHandle([]string{"POST"}, "api.test/v1", h, edge.WithScheme("https"))
```

A route with no port matches every port. The port compared against is always explicit, so `WithPort("443")` matches a plain `https://` target. Writing either in a pattern is an error naming the option to use.

Rules are authorities, so they do carry a port: `edge.WithIntercept("localhost:8080")`.

## Message framing

Intercepted traffic is parsed and re-serialized, never relayed as bytes. A message whose framing is ambiguous, a request carrying both a `Content-Length` and a `Transfer-Encoding` for example, is resolved once, by the proxy, and what reaches the origin is what the proxy read. Client and origin cannot end up disagreeing about where a message ends, and nothing reaches the origin without having been routed first.

Tunneled traffic is relayed byte for byte and is not parsed at all, which is what makes a tunnel transparent in the first place.

## Handlers

```go
type HandlerFunc func(c *edge.Context) (*http.Response, error)
```

A route is registered for a set of methods. An empty or nil set matches every method, which is the only way to say it: there is no separate constant for it and no single-method form of the call.

Returning a response from `c.Forward()` relays the upstream answer without buffering it. Returning one built locally short-circuits the upstream entirely and the request never leaves the proxy. Returning an error hands it to the configured `ErrorHandler`, which answers 502 by default.

A request that matches no route is forwarded unchanged, so interception without a matching route is observable but not disruptive. `WithNoRouteHandler` changes that.

Response helpers: `Text`, `Textf`, `HTML`, `JSON`, `Bytes`, `Stream`, `Status`, `Redirect`. Body helpers: `ReadBody` returns the bytes as they came off the wire, `DecodeBody` decompresses first and drops the `Content-Encoding`, and `Rewrite` puts a new body back with the length headers fixed up.

Middleware composes the way it does in Fox:

```go
p, _ := edge.New(
    edge.WithCA(ca),
    edge.WithMiddleware(logging, recordToHAR),
)
p.MustHandle([]string{"GET"}, "api.stripe.com/v1/charges", h, edge.WithRouteMiddleware(retry))
```

This is also where anything protocol-specific goes. A gRPC decoder is middleware that recognizes `application/grpc` and unwraps the length-prefixed frames before the handler sees them; edge itself stays an HTTP proxy.

## Sessions

A `Session` is the client connection a request arrived on, shared by every request multiplexed onto it. It carries the peer address, the negotiated protocol, the TLS state, what the client offered in its ClientHello, and a key-value store for middleware that needs to correlate requests across one connection.

```go
p.MustHandle([]string{"GET"}, "api.stripe.com/v1/charges", func(c *edge.Context) (*http.Response, error) {
    log.Printf("%s over %s, client offered ALPN %v",
        c.Authority(), c.Protocol(), c.Session().ClientHello().ALPN)
    return c.Forward()
})
```

## Certificate authority

```go
ca, _ := edge.GenerateCA(edge.WithCASubject("acme test CA", "ACME"))
os.WriteFile("ca.pem", ca.CertificatePEM(), 0o600)
```

Or bring your own with `edge.LoadCA(certPEM, keyPEM)` or `edge.LoadCAFile(certPath, keyPath)`.

Leaf certificates are minted on demand for the name the client asked for, cached, and share one key pair. Signing a new leaf costs about 60µs; reading a cached one back costs about 60ns. Concurrent connections to the same authority wait on a single signature rather than each producing their own.

## Transparent mode

```go
p, _ := edge.New(
    edge.WithCA(ca),
    edge.WithIntercept("api.stripe.com"),
    edge.WithOriginalDestination(edge.OriginalDestinationSocket),
)

go p.ListenAndServeTransparent(":8443") // TCP, redirected
go p.ListenAndServeQUIC(":8443")        // UDP, redirected
```

The destination of a connection is resolved from the original destination reported by the resolver, the server name of a TLS ClientHello, and the Host header of a plaintext request, in that order.

`OriginalDestinationSocket` reads `SO_ORIGINAL_DST` on Linux behind an iptables or nftables redirect, and asks pf on macOS, which needs read access to `/dev/pf`. Supply your own `OriginalDestination` for anything else. Without one, transparent mode still works for any client that sends a server name or a Host header.

For QUIC, the proxy reads the server name out of the Initial packets by deriving their protection keys from the connection ID they carry in clear, reassembling the ClientHello across as many packets as it spans. That is what lets a connection be tunneled without being terminated first.

## Runtime changes

Routes and rules are transactional and can change under load:

```go
p.Updates(func(txn *edge.Txn) error {
    if _, err := txn.Add([]string{"POST"}, "api.stripe.com/v1/charges", failOnce); err != nil {
        return err
    }
    _, err := txn.Delete([]string{"GET"}, "api.stripe.com/v1/health")
    return err
})
```

A write transaction takes the proxy write lock; lookups never take it and never block. The rule tree is committed before the routing tree, so a route is never visible before the rule that makes its authority intercepted.

## Performance

On an M4 Max, with zero allocations on every lookup:

```
BenchmarkLookup/static-16                 20.7 ns/op    0 B/op   0 allocs/op
BenchmarkLookup/param-16                  28.1 ns/op    0 B/op   0 allocs/op
BenchmarkLookup/wildcard_host-16          37.2 ns/op    0 B/op   0 allocs/op
BenchmarkLookupDeepTree-16                40.4 ns/op    0 B/op   0 allocs/op
BenchmarkDecide/hit_static-16             25.7 ns/op    0 B/op   0 allocs/op
BenchmarkLeafCached-16                    60.7 ns/op   48 B/op   1 allocs/op
BenchmarkLeafMint-16                     61.4 µs/op
```

## Testing

The conformance suite drives the proxy with `curl` rather than a Go client, because a Go client shares its HTTP implementation with the proxy and would agree with it on anything both get wrong. It uses `curl3`, the Homebrew build that speaks HTTP/3 and reports the negotiated version, and falls back to whatever `curl` is on `PATH`.

```bash
go test -race ./...
go test -run TestConformance -v .
go test -run TestQUIC -v .
```

## License

Apache-2.0. The routing core is adapted from [Fox](https://github.com/fox-toolkit/fox), under the same license.
