// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

/*
Package edge is a forward proxy that terminates what it admits.

Every connection the proxy lets through is terminated: TLS is terminated when there is TLS,
and what a handler sees is the traffic in the clear. Nothing is relayed encrypted, so nothing
crosses the proxy unobserved. What cannot be terminated fails, and fails visibly: a client that
pins a certificate, an SSH host key, an authority missing from the client's trust store, an
encrypted ClientHello.

# Kinds

A registration names the kind of traffic it serves, and the handler signature is what selects
it. There is no type argument to write unless one is wanted for clarity.

	p.Add("api.test/v1/charges/{id}", func(c *edge.HTTPCtx) (*http.Response, error) { ... })
	p.Add[edge.TCP]("smtp.test:465", relay)

	[KindHTTP]       one request, keyed on a hostname and a path
	[KindGRPC]       one call, keyed on the hostname and the full method name
	[KindWebSocket]  the frames past a 101, keyed on the hostname and path that upgraded
	[KindTCP]        one byte stream, keyed on an authority
	[KindQUIC]       one terminated QUIC connection and its streams, keyed on an authority
	[KindUDP]        one datagram, keyed on an authority

gRPC and WebSocket ride on HTTP, so an entry for either admits the authority as HTTP and is
reached through it.

# What decides what

The traffic says what a connection is: the negotiated ALPN when the client offered one, and
what the first bytes are otherwise. The tree says at which granularity it is served, among the
granularities where a handler would see the traffic in the clear, most refined first. An HTTP
connection whose authority carries only a stream entry is served as a byte stream; a QUIC
connection is never served as datagrams, since those are ciphertext the proxy holds the keys
for and a handler reading them would observe nothing.

Every unit is routed on the tree as it stands when it arrives: a request, a stream, a frame, a
datagram. An entry added or removed while a connection is open governs its next unit rather
than the next connection. Routing is as fine as the protocol's units, so a request is placed on
its own and a byte stream is placed once.

# Nothing passes by default

An authority no entry names is refused, and so is a unit no entry matches. What is let through
is written down:

	p.Add("api.test/*{any}", func(c *edge.HTTPCtx) (*http.Response, error) { return c.Forward() })

# Patterns

A pattern is an authority, and a path for the kinds that route each message of a connection.
The authority is required either way, it is the one the entry admits.

	api.stripe.com/v1/charges       one host
	+{sub}.corp.internal/health     every subdomain
	+{any}/health                   every hostname
	api.stripe.com/*{any}           every path on one host
	[10.0.0.0/8]/health             every address in a range
	[::/0]/health                   every IPv6 address
	smtp.test:465                   one authority, for a kind that routes connections

Parameter syntax is Fox's: {name}, {name:regexp} with [WithRegexpParam], and the wildcards
*{param} and +{param}. The port belongs to the pattern, as "host:port/path"; an entry naming
none matches every port. The scheme and the method are matchers, see [WithScheme] and
[WithMethods].

Hostnames and addresses route through separate roots, so {a} and +{any} match names only and an
address is matched as an address. An address literal must be canonical and bracketed the way an
authority carries it, and a range is bracketed, masked and shorter than a full address.

# How a client reaches the proxy

Orthogonal to all of the above. A client reaches the proxy explicitly, configured with a proxy
setting, or transparently, its traffic redirected by the network.

	go p.ListenAndServe(":8080")                // CONNECT, CONNECT-UDP and absolute request targets, over TCP
	go p.ListenAndServeQUIC(":8443", cert)      // the same over HTTP/3
	go p.ListenAndServeTransparent(":8888")     // TCP redirected by the network
	go p.ListenAndServeTransparentUDP(":8888")  // UDP redirected by the network, QUIC and datagrams

A CONNECT names where the packets go and the server name inside says what the client expects
there. The server name selects the entry, the CONNECT target is what the proxy dials, and
[WithNameVerification] checks one against the other when the target is an address. A
CONNECT-UDP tunnel, RFC 9298, is how a configured client sends UDP, HTTP/3 to an origin
included. A client that cannot reach the proxy over UDP opens the tunnel over HTTP/2 or
HTTP/1.1 instead, its datagrams in capsules, RFC 9297. The tunnel is a
[Session] of its own, and so is every connection or datagram flow inside it, each decided on
its own, see [Session.Via].

# Invisibility

What goes upstream is what the client sent, byte for byte, minus only the hop-by-hop headers a
proxy must not relay. The HTTP version is mirrored in both directions, bodies are never
decompressed on the way through, and nothing is added: no Via, no X-Forwarded-For, no
Accept-Encoding of the proxy's own.

# Changing things while traffic flows

Entries can be added and removed at any time. Lookups are lock-free and never observe a
partially applied write, and a transaction commits everything it changed at once.

	p.Updates(func(txn *edge.Txn) error {
		if _, err := txn.Delete[edge.HTTP]("api.test/v1"); err != nil {
			return err
		}
		_, err := txn.Add("api.test/v1", handler)
		return err
	})

Closing a connection is not how a change is applied: the next unit is already routed on the new
tree. [Proxy.Sessions] is for ending connections on their own terms, revoking an identity being
the usual one.
*/
package edge
