// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

// Package edge implements a forward HTTP proxy that can tunnel traffic end to end or
// intercept it, terminating TLS with a local certificate authority so handlers can
// inspect and rewrite requests and responses in flight.
//
// The proxy routes on the full request target, scheme, authority and path, using an
// immutable radix tree with lock-free reads and single-writer semantics. Routes can be
// added and removed while traffic is flowing without blocking any lookup.
//
// # Interception
//
// A connection is either tunneled or intercepted. Tunneled connections are relayed
// byte for byte and the proxy never sees the plaintext. Intercepted connections are
// terminated by the proxy, which mints a leaf certificate for the requested authority
// and speaks the negotiated protocol on both sides.
//
// The decision is made per authority by a rule set, evaluated most specific first.
// Registering a handler implicitly adds an intercept rule for the route's authority,
// so a route always sees the traffic it was written for.
//
// # Message framing
//
// Intercepted traffic is parsed and re-serialized, never relayed as bytes. A message whose
// framing is ambiguous, a request carrying both a Content-Length and a Transfer-Encoding for
// example, is resolved once, by the proxy, and what reaches the origin is what the proxy
// read. Client and origin therefore cannot end up disagreeing about where a message ends,
// and nothing reaches the origin without having been routed first.
//
// Tunneled traffic is relayed byte for byte and is not parsed at all, which is what makes a
// tunnel transparent in the first place.
package edge
