// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import "net/http"

// The handler signatures the proxy serves. Each one names a kind of traffic, and the kind
// is what [Proxy.Add] is parameterized on.
//
// They are aliases rather than defined types so a handler literal infers its own kind:
// Add("api.test/v1", func(c *HTTPCtx) (*http.Response, error) { ... }) needs no type
// argument. Writing one, Add[edge.HTTP], selects the same kind explicitly.
type (
	// HTTP handles one request. It returns the response to send back to the client, which
	// is either the upstream response from [HTTPCtx.Forward] or one built locally.
	HTTP = func(c *HTTPCtx) (*http.Response, error)
	// GRPC handles one gRPC call on a request whose content type says so.
	GRPC = func(c *GRPCCtx) error
	// WebSocket handles the frames of one connection, past the 101 that established it.
	WebSocket = func(c *WebSocketCtx) error
	// TCP handles one byte stream, TLS already terminated when there was any.
	TCP = func(c *TCPCtx) error
	// QUIC handles one terminated QUIC connection and the streams on it.
	QUIC = func(c *QUICCtx) error
	// UDP handles one datagram.
	UDP = func(c *DatagramCtx) error
)

// Handler constrains what [Proxy.Add] accepts. Its terms are the handler signatures above,
// one per kind of traffic.
type Handler interface {
	HTTP | GRPC | WebSocket | TCP | QUIC | UDP
}

// PathKeyed is the kinds whose entry is keyed on a hostname and a path. The others are keyed
// on an authority alone and are decided before a request exists, so an option reading a
// request is declared on this constraint.
type PathKeyed interface {
	HTTP | GRPC | WebSocket
}

// Kind is the traffic a handler is registered for. It is fixed by the handler signature,
// never by the pattern.
type Kind uint8

const (
	// KindHTTP routes one request, on a hostname and a path.
	KindHTTP Kind = iota + 1
	// KindGRPC routes one gRPC call, on a hostname and the full method name as its path.
	KindGRPC
	// KindWebSocket routes the frames of one connection, on the hostname and path of the
	// request that upgraded it.
	KindWebSocket
	// KindTCP routes one byte stream, on an authority.
	KindTCP
	// KindQUIC routes one QUIC connection, on an authority.
	KindQUIC
	// KindUDP routes one datagram, on an authority.
	KindUDP
)

func (k Kind) String() string {
	switch k {
	case KindHTTP:
		return "HTTP"
	case KindGRPC:
		return "gRPC"
	case KindWebSocket:
		return "WebSocket"
	case KindTCP:
		return "TCP"
	case KindQUIC:
		return "QUIC"
	case KindUDP:
		return "UDP"
	default:
		return "unknown"
	}
}

// kindOf reports the kind H registers for. The zero value of a handler type carries the type
// itself, which is all the switch reads, so no handler is ever called here.
func kindOf[H Handler]() Kind {
	var h H
	switch any(h).(type) {
	case HTTP:
		return KindHTTP
	case GRPC:
		return KindGRPC
	case WebSocket:
		return KindWebSocket
	case TCP:
		return KindTCP
	case QUIC:
		return KindQUIC
	case UDP:
		return KindUDP
	default:
		// Unreachable: Handler has no other term.
		panic("edge: unknown handler kind")
	}
}

// admittedAs is the kind whose admission covers this one. A gRPC call and a WebSocket
// connection are both carried by HTTP, so an entry for either is admitted as HTTP and reached
// through it.
//
// What a connection is comes from the traffic, never from the tree: an ALPN, a content type, a
// sniffed request line. Which kinds exist is fixed at compile time, so what a connection may be
// cannot move under one that is already open.
func (k Kind) admittedAs() Kind {
	switch k {
	case KindGRPC, KindWebSocket:
		return KindHTTP
	default:
		return k
	}
}

// refines reports whether the kind narrows the one that admits it, which a gRPC or a
// WebSocket entry does to HTTP. A refinement carries a precondition its carrier does not, so it
// is tried first among the entries of one node naming the same port. The port is the tier
// above, so an entry naming one still outranks a refinement that names none.
func (k Kind) refines() bool { return k != k.admittedAs() }

// requiresPath reports whether this kind is keyed on a hostname and a path. The others are
// keyed on an authority alone, which is what keeps the two key spaces disjoint.
func (k Kind) requiresPath() bool {
	switch k {
	case KindHTTP, KindGRPC, KindWebSocket:
		return true
	default:
		return false
	}
}
