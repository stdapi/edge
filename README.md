# Edge

Edge is a forward HTTP proxy library for Go. It intercepts the authorities you name, terminating TLS with a local certificate authority so your code can inspect and rewrite requests and responses in flight, tunnels the ones you want left alone, and refuses everything else.

It was built to capture the outbound traffic of an application under end-to-end test without the application being able to tell. What goes upstream is what the client sent, byte for byte, minus only the hop-by-hop headers a proxy must not relay. The HTTP version is mirrored in both directions. Bodies are never decompressed on the way through. Nothing is added: no `Via`, no `X-Forwarded-For`, no `Accept-Encoding` of the proxy's own.

Routing uses an immutable radix tree with lock-free reads and single-writer semantics, adapted from [Fox](https://github.com/fox-toolkit/fox). Nothing is configured at construction: interceptors and tunnels are added and removed while traffic flows, without blocking a lookup.

```go
ca, _ := edge.GenerateCA()

p, _ := edge.New(edge.WithCA(ca))

// An interceptor names the authority it intercepts, so this arms api.stripe.com on its own.
p.MustAddInterceptor([]string{"POST"}, "api.stripe.com/v1/charges", func(c *edge.Context) (*http.Response, error) {
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

// Leave this one alone: its TLS stays end to end and the proxy never sees the plaintext.
p.AddTunnel("checkout.stripe.com")

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

A classic proxy setting sends an HTTP/3 client back to TCP, since `CONNECT` tunnels a stream and HTTP/3 needs datagrams. Tunneling those is what MASQUE standardizes, and no general purpose client implements it, so HTTP/3 is reached by routing the client to the proxy rather than by configuring it.

Protocol upgrades, including WebSocket, are spliced through in both modes. Server-sent events and other streamed bodies are relayed as they are produced, not buffered. Trailers are forwarded.

## Two axes, not one

It is worth separating two things that both get called "transparent":

**How the client reaches the proxy.** Either *explicitly*, configured with a proxy setting, sending `CONNECT` or an absolute request target; or *transparently*, not configured at all, with its packets redirected by the network, leaving the proxy to work out where they were headed.

**What the proxy does with the connection.** Either *tunnel*, relaying bytes so the client's TLS stays end to end and the proxy never sees the plaintext; or *intercept*, terminating TLS with a minted certificate so handlers can see and change what goes past.

The two combine freely. Most test setups want an explicit proxy that intercepts a handful of authorities and tunnels the rest. An application that ignores proxy environment variables needs the transparent listener instead.

## What happens to a connection

The decision is taken from the authority alone, before any request is parsed, and the most specific pattern wins: a static authority beats a parameter, which beats a wildcard. It is taken again for every request that names another authority, through its `Host` header or through a transparent listener carrying many, so nothing is reached on the strength of a decision taken for something else.

```go
// Watch every Stripe subdomain, forwarding untouched unless a narrower interceptor matches.
p.MustAddInterceptor(nil, "+{sub}.stripe.com/*{any}", edge.DefaultNoInterceptorHandler)

// Except this one, whose TLS must stay end to end. Static beats the wildcard.
p.AddTunnel("checkout.stripe.com")
```

There are only these two ways to admit an authority, and both name it explicitly. An interceptor arms the authority in its own pattern, so a handler always sees the traffic it was written for; the entry it implies is reference counted and disappears with the last interceptor that needed it.

**Everything else is refused.** A proxy that captures the traffic of an application under test should say what it expects that application to reach, and hear about it when the application reaches somewhere else. One line restores a permissive proxy, and it is visible in the code:

```go
p.AddTunnel("+{any}") // relay anything not named above
```

An authority cannot be both tunneled and intercepted by the same pattern. Declaring the second is an error rather than a silent no-op, in either order, because one of the two would otherwise be dead.

`p.Decide(target)` answers what would happen to an authority without opening a connection, and `p.Authorities()` iterates what is registered.

## Patterns

A pattern is an authority and a path. The authority is required: it is what the interceptor arms.

```
api.stripe.com/v1/charges           any scheme, any port
api.stripe.com:8443/v1/charges      one port
+{sub}.corp.internal/health         every subdomain
+{any}/v1/charges                   every authority
api.stripe.com/*{any}               every path on one host, which is how to just watch it
127.0.0.1/health                    address literal
[::1]:8080/health                   IPv6, bracketed
```

Parameters use Fox's syntax:

- Named: `{name}`, or `{name:[a-z]+}` with `WithRegexpParam` enabled
- Wildcards: `*{param}` matches empty, suffix only; `+{param}` needs at least one character and works as a prefix, infix or suffix

Matching priority is static, then regex parameter, then parameter, then regex wildcard, then wildcard, with backtracking to the last decision point.

An address literal has one spelling, the one an authority carries: `[::1]`, not `::1` or `[::0001]`.

### Port

The port is part of the pattern:

```go
p.MustAddInterceptor([]string{"GET"}, "localhost:8080/api", api)
p.MustAddInterceptor([]string{"GET"}, "localhost:3000/", ui)
```

Two patterns differing only by their port are two interceptors, and each arms only its own authority. An interceptor naming no port matches every port, and one naming a port is tried first, ahead of a method or a matcher. The port compared against is always explicit, so `api.test:443/v1` matches a plain `https://api.test/v1` target.

An authority pattern carries its port the same way: `p.AddTunnel("localhost:8080")`.

### Scheme

The scheme is a matcher, not part of the pattern:

```go
p.MustAddInterceptor([]string{"POST"}, "api.test/v1", h, edge.WithScheme("https"))
```

Writing one in a pattern is an error describing what is refused.

## Message framing

Intercepted traffic is parsed and re-serialized, never relayed as bytes. A message whose framing is ambiguous, a request carrying both a `Content-Length` and a `Transfer-Encoding` for example, is resolved once, by the proxy, and what reaches the origin is what the proxy read. Client and origin cannot end up disagreeing about where a message ends, and nothing reaches the origin without having been routed first.

Tunneled traffic is relayed byte for byte and is not parsed at all, which is what makes a tunnel transparent in the first place.

## Handlers

```go
type HandlerFunc func(c *edge.Context) (*http.Response, error)
```

An interceptor is registered for a set of methods. An empty or nil set matches every method, which is the only way to say it: there is no separate constant for it and no single-method form of the call.

Returning a response from `c.Forward()` relays the upstream answer without buffering it. Returning one built locally short-circuits the upstream entirely and the request never leaves the proxy. Returning an error hands it to the configured `ErrorHandler`, which answers 502 by default. A panicking handler is recovered and reaches the same `ErrorHandler` as a `PanicError` carrying the value and the stack; the default logs it and answers 500.

A request matching no interceptor is forwarded unchanged, so watching an authority without rewriting anything stays non-disruptive. `WithNoInterceptorHandler` changes that.

Response helpers: `Text`, `Textf`, `HTML`, `JSON`, `Bytes`, `Stream`, `Status`, `Redirect`. Body helpers: `ReadBody` returns the bytes as they came off the wire, `DecodeBody` decompresses first and drops the `Content-Encoding`, and `Rewrite` puts a new body back with the length headers fixed up.

Middleware composes the way it does in Fox:

```go
p, _ := edge.New(
    edge.WithCA(ca),
    edge.WithMiddleware(logging, recordToHAR),
)
p.MustAddInterceptor([]string{"GET"}, "api.stripe.com/v1/charges", h, edge.WithMiddleware(retry))
```

This is also where anything protocol-specific goes. A gRPC decoder is middleware that recognizes `application/grpc` and unwraps the length-prefixed frames before the handler sees them; edge itself stays an HTTP proxy.

## Sessions

A `Session` is the client connection a request arrived on, shared by every request multiplexed onto it. It carries the peer address, the negotiated protocol, the TLS state, what the client offered in its ClientHello, and a key-value store for middleware that needs to correlate requests across one connection.

```go
p.MustAddInterceptor([]string{"GET"}, "api.stripe.com/v1/charges", func(c *edge.Context) (*http.Response, error) {
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
p, _ := edge.New(edge.WithCA(ca))

go p.ListenAndServeTransparent(":8443") // TCP, redirected
go p.ListenAndServeQUIC(":8443")        // UDP, redirected
```

Transparent means the client is not configured, not that a particular mechanism brought its traffic here. Two get it here:

- **Resolve the authority to the proxy**, with a dedicated resolver, a hosts entry or a split-horizon zone, and listen on the port the client expects. Costs no privilege and works from another machine.
- **Redirect the packets**, with an iptables or nftables `REDIRECT` on Linux or an `rdr` rule in pf on macOS. Needs the rule and the proxy on the same host, and an exclusion for the proxy's own user so its upstream connections are not redirected back into it.

The destination of a connection is resolved from the address it was headed to before the redirect, then the server name of a TLS ClientHello, then the Host header of a plaintext request. The first is only needed to recover the port, to reach the exact address the client had resolved, or to place a client that sends no server name.

The two `ListenAndServe` calls above set that up on the sockets they open. Bring your own and you wrap them yourself:

```go
ln, _ := net.Listen("tcp", ":8443")
go p.ServeTransparent(edge.TransparentListener(ln))

pc, _ := net.ListenPacket("udp", ":8443")
conn, _ := edge.TransparentPacketConn(pc)
go p.ServeQUIC(conn)
```

The connection reports where it was headed and the proxy asks it, through the `OriginalDestination` and `PacketOriginalDestination` interfaces, so a setup neither of these covers is a connection type of your own.

For TCP the lookup reads `SO_ORIGINAL_DST` on Linux and asks the pf state table on macOS, which needs read access to `/dev/pf`. For UDP, netfilter reports the address with each datagram through `IP_RECVORIGDSTADDR`, while pf reports nothing with the datagram, so the socket asks for the address it arrived on and the destination comes from a `DIOCNATLOOK`.

For QUIC, the proxy reads the server name out of the Initial packets by deriving their protection keys from the connection ID they carry in clear, reassembling the ClientHello across as many packets as it spans. That is what lets a connection be tunneled without being terminated first.

## Runtime changes

Interceptors and tunnels are transactional and can change together under load:

```go
p.Updates(func(txn *edge.Txn) error {
    if _, err := txn.AddInterceptor([]string{"POST"}, "api.stripe.com/v1/charges", failOnce); err != nil {
        return err
    }
    _, err := txn.DeleteInterceptor([]string{"GET"}, "api.stripe.com/v1/health")
    return err
})
```

A write transaction takes the proxy write lock; lookups never take it and never block. Interceptors and authorities share one tree, so an interceptor and the authority entry it implies are published together and cannot disagree.

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
