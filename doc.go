// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

// Package edge implements a forward HTTP proxy that can tunnel traffic end to end or
// intercept it, terminating TLS with a local certificate authority so handlers can
// inspect and rewrite requests and responses in flight.
//
// The proxy routes on the full request target, authority and path, using an immutable radix
// tree with lock-free reads and single-writer semantics. Interceptors and tunnels can be
// added and removed while traffic is flowing without blocking any lookup. Nothing is
// configured at construction: the whole traffic policy is set and changed at runtime.
//
// # Interception
//
// A connection is tunneled, intercepted, or refused. A tunneled connection is relayed byte
// for byte and the proxy never sees the plaintext. An intercepted connection is terminated
// by the proxy, which mints a leaf certificate for the requested authority and speaks the
// negotiated protocol on both sides.
//
// The decision is taken per authority, most specific first, before a single byte of the
// request exists. There are two ways to declare one, and neither is a policy applied
// globally:
//
//   - [Proxy.AddInterceptor] registers a handler for an authority and a path. The authority
//     it names is the one it intercepts, so a handler always sees the traffic it was written
//     for.
//   - [Proxy.AddTunnel] names an authority to relay untouched, which is how a host that
//     pins its certificate is carved out of a broader interception.
//
// Anything else is refused. A proxy meant to capture the traffic of an application under
// test should say what it expects that application to reach, and hear about it when the
// application reaches somewhere else. [Proxy.AddTunnel] with a wildcard authority is the
// one line that restores a permissive proxy, and it says so in the code.
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
