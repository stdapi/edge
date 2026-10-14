# Connection lifecycle

This document specifies how every unit the proxy serves ends: on `Session.Close`, on `Proxy.Close`, during the drain of `Proxy.Shutdown` and at its deadline, and when a peer or a handler ends it. It is the reference for the code, the tests and the reviews. A change to how something ends starts here.

The last section lists where main differs from this document. A fix removes its row.

## Terms

- **Unit.** What the proxy decided once at arrival: a client connection, a CONNECT, a terminated QUIC connection, a datagram flow, a CONNECT-UDP tunnel, an upgraded connection. A unit is reported as a `Session`. A plain request on a front is a unit too, with no Session.
- **Leg.** One connection a unit owns. The client leg is the connection or stream toward the client. The origin legs are every upstream connection the unit dialed or was given: `TCPCtx.Dial`, `TCPCtx.DialTo`, the backend of a 101, a QUIC upstream, the upstream request of an HTTP or gRPC handler.
- **Carrier.** The connection under a unit that does not own its socket: the front HTTP/2 connection under a CONNECT stream, the QUIC connection under an HTTP/3 request, the tunnel under an inner QUIC connection.
- **Closer.** The one function that ends a unit, `Session.closer` for a session.
- **Framed leg.** A leg with a protocol that marks the end of each message, so a truncation shows above the transport: HTTP/1.1 with a length, HTTP/2, HTTP/3, a QUIC stream, WebSocket, DATAGRAM capsules.
- **Byte stream.** A leg with no such framing: a TCP entry, the bytes of a CONNECT, the pipe left by a 101 served as TCP.
- **Cut.** `Session.Close`, `Proxy.Close`, or the deadline of `Shutdown`.

## The end of each protocol

| Leg | Normal end | Failed end |
|---|---|---|
| TCP | FIN | RST |
| TLS | close_notify, then FIN | RST, no close_notify |
| HTTP/2 stream | END_STREAM | RST_STREAM |
| HTTP/2 connection | GOAWAY, then close | close with streams open |
| HTTP/3 or QUIC stream | FIN | RESET_STREAM and STOP_SENDING |
| QUIC connection | CONNECTION_CLOSE with the no-error code of the protocol | CONNECTION_CLOSE with an error code |
| WebSocket | Close frame, then TCP close | TCP close with no Close frame, read as 1006 |
| UDP flow | none | none |

Go's TLS client reads an EOF at a record boundary as `io.EOF` with or without close_notify. On a byte stream only an RST separates a broken connection from a finished one.

## Rules

**L1. One closer per unit, and it ends every leg.** A cut ends a unit through its closer, and the closer ends the client leg and every origin leg in the same call. Nothing the unit owns is left for its handler to release later. A sibling unit to the same origin is no part of it.

**L2. A cut on a byte stream is a failed end, on both sides.** The client leg and the origin legs get an RST, with no close_notify, and a CONNECT stream gets its stream reset. A framed leg ends in the normal form of its protocol, since its framing already shows what was cut: close_notify on TLS, END_STREAM or GOAWAY on HTTP/2, CONNECTION_CLOSE with the no-error code on QUIC, the inner CONNECTION_CLOSE of every connection inside a tunnel, then the end of the tunnel. A WebSocket is cut by closing its connection, with no Close frame. A natural end is relayed as the same natural end.

**L3. The origin observes what the client side observed, in the same cut.** A cut reaches every origin leg as a failure within the bound of the cut. A FIN from the client reaches the origin as a FIN and a reset as a reset. The proxy adds no end of its own on either side.

**L4. The drain withdraws nothing from an admitted unit.**
- From the start of `Shutdown`, a new unit is refused in the terms of its protocol: GOAWAY, H3_REQUEST_REJECTED, a refused handshake, SOCKS5 reply 0x01.
- An admitted unit keeps its context until it ends. Its handshake completes and its dials succeed.
- HTTP/2 and HTTP/3 connections get one GOAWAY at the start of the drain, the inner HTTP/3 connections of a tunnel included. A connection idle after its GOAWAY is closed by the proxy.
- A unit with no graceful signal, a byte stream, a raw QUIC connection, a UDP flow, ends when its peers end it or at the deadline.
- A CONNECT-UDP tunnel ends as soon as nothing inside it is active, independently of the other tunnels.

**L5. The deadline of `Shutdown` is `Proxy.Close` applied to what remains,** the front connections and their requests included.

**L6. Every step of a cut is bounded, and the bounds do not add up per unit.**
- A close_notify or a TLS alert is written within `alertWriteTimeout` (1 s), and none is written after a failed write on the same socket.
- The last capsules of a tunnel are written within `tunnelDrainTimeout` (1 s).
- A CONNECTION_CLOSE never waits for the peer.
- Units are cut concurrently, so a cut costs the largest bound of each phase, never that bound times the number of units.

**L7. A cut ends inner layers before outer ones.** A cut runs these phases in order, each concurrent within itself and capped:
1. Refuse new units.
2. Cut the requests in flight: plain requests, gRPC calls, the requests of a terminated HTTP connection. Their upstream requests are canceled and their streams reset.
3. End every session in its innermost protocol: a CONNECT stream reset, the inner CONNECTION_CLOSE of a tunnel, the close_notify of a framed TLS leg, the RST of a byte stream.
4. Close the carriers: sockets, front connections, QUIC connections.
5. Close the transports, the listeners and the upstream pools.

Closing a carrier first destroys the signal of everything inside it. A request cut after its carrier reads as finished on both sides.

**L8. A TLS connection the proxy opens or terminates has one end.** A second `Close` returns once the first has ended, so a caller that closes the socket next cannot cut the close_notify.

**L9. Once a cut has returned, the proxy no longer uses the network for that unit,** and once `Proxy.Close` or `Shutdown` has returned, for any unit. No upstream connection is opened after it, and every upstream connection still open is closed, busy or idle. A handler still running finds its I/O failing and is not waited for.

**L10. `Session.Close` behaves as above on every session a handler can reach.** The session of a front connection decides nothing at arrival, so it has nothing to end. `Session.Close` returns nil there, and its godoc documents it.

## Per unit

E1 is `Session.Close`, E2 `Proxy.Close`, E3 the drain of `Shutdown`, E4 its deadline. E4 is E2 applied to what remains (L5) and is listed with it.

| Unit | E1 | E2 and E4 | E3 | Peer or handler ends it |
|---|---|---|---|---|
| Front connection over HTTP/1.1, HTTP/2, h2c, and its plain requests | Nothing, L10 | Requests cut, upstream requests canceled, then the connection closed. A body with a length is truncated, an HTTP/2 stream is reset | Requests complete, HTTP/2 gets GOAWAY, HTTP/1.1 closes after the response | A client end cancels the upstream request |
| Front connection over HTTP/3 | Nothing, L10 | CONNECTION_CLOSE H3_NO_ERROR, requests in flight fail | GOAWAY, H3_REQUEST_REJECTED for new streams, idle connections closed | As HTTP/2 |
| CONNECT on an HTTP/1.1 front, transparent TCP, TPROXY, SOCKS5 CONNECT, served as a byte stream | RST to the client and to every origin leg | As E1 | The relay continues with a live context and working dials until the deadline | The relay passes a FIN as a half-close and a failure as an RST |
| The same, served as HTTP over terminated TLS | Requests cut, then close_notify and FIN | As E1 | Requests complete, HTTP/2 gets GOAWAY | As a front connection |
| CONNECT on an HTTP/2 or HTTP/3 stream | RST_STREAM on HTTP/2, H3_CONNECT_ERROR on HTTP/3, RST to every origin leg, sibling streams untouched | As E1, before the front connection closes | The tunnel continues until the deadline | As above |
| A stream after `TCPCtx.StartTLS` | As a byte stream, the closer being the TLS connection StartTLS established | As E1 | As a byte stream | close_notify when the handler returns |
| Pipe left by a 101, served as TCP | RST to the client and to the backend | As E1 | Continues until the deadline | A half-close reaches the backend as a half-close, a failure as an RST |
| WebSocket session | Both connections closed, no Close frame | As E1 | Continues until the deadline | Close frames relayed |
| gRPC call | Through its carrier | Call cut before its carrier: the client stream reset, the upstream stream canceled | Messages complete, then the status | A client reset cancels the upstream call |
| CONNECT-UDP tunnel over HTTP/3, HTTP/2, HTTP/1.1, SOCKS5 UDP ASSOCIATE | Inner CONNECTION_CLOSE for every inner connection, delivered reliably, then the end of the tunnel stream or connection | As E1, before the front connection closes | GOAWAY to inner HTTP/3 connections, the tunnel ends once nothing inside it is active | The tunnel ends with its client, or after 2 minutes with nothing inside |
| Terminated QUIC connection, KindQUIC, HTTP/3 on it | CONNECTION_CLOSE with the no-error code of the protocol, the same end mirrored to the upstream | As E1 | HTTP/3 gets GOAWAY, other QUIC continues until the deadline | Each end mirrored with its code |
| UDP datagram flow | Replies stop, upstream sockets closed, nothing sent | As E1 | Continues until the deadline | Idle 2 minutes ends it |
| Upstream connection | Closed with the unit, L1 | Closed, busy or idle, and no new one opened, L9 | Untouched until the drain ends | n/a |

## Limits of the libraries

These ends differ from the rules because Go, x/net or quic-go leave no other choice. They are kept as they are.

- An HTTP/2 CONNECT stream is reset with INTERNAL_ERROR, where RFC 9113 section 8.5 specifies CONNECT_ERROR. A past write deadline is the only reset net/http lets a handler trigger. A malformed capsule on HTTP/2 gets the same code where RFC 9297 specifies PROTOCOL_ERROR.
- `Proxy.Close` drops an HTTP/2 front connection with no GOAWAY. net/http writes a GOAWAY only from `Shutdown`, asynchronously.
- A QUIC connection closed before quic-go delivers it to the proxy gets its CONNECTION_CLOSE only once it is delivered, or ends on its handshake timeout.
- The drain of an HTTP/3 server stays blocked in quic-go past the deadline on a handler that does not return. `Shutdown` itself returns on time.
- UDP has no end signal.

## Where main differs

Audited at 02d6932. The rows are grouped into lots, worked in the order of their numbers, each with its own tests and review.

1. The order of a cut.
2. The legs of a unit.
3. The drain of the units admitted before it.
4. The upstream connections.
5. The CONNECT-UDP tunnels.
6. The smaller items.

| Lot | Gap | Rule | Evidence |
|---|---|---|---|
| 1 | The deadline of `Shutdown` does not cut plain requests or gRPC calls on the HTTP/1.1, HTTP/2 and h2c fronts. The response still reaches the client after `Shutdown` has returned | L5, L7 | A request to a slow origin with a 300 ms deadline completes 1.8 s later |
| 1 | `Proxy.Close` closes an HTTP/2 front connection before the CONNECT streams inside it, and closes the front connections one after the other, up to 1 s each behind a TLS client that stopped reading | L6, L7 | The client reads `unexpected EOF`, 5 runs out of 5. Three stalled TLS clients take 2.0 s |
| 1 | Three closers race on the socket of a terminated connection, so the close_notify is lost on a cut, and a second `Close` of a TLS connection returns before the first has written it | L7, L8 | close_notify missing in 9 runs out of 30 on `Proxy.Close` |
| 2 | A cut ends the client leg only. The origin receives a FIN, as if the client had finished, and keeps its connection up to 30 s, with no bound behind a handler that ignores its I/O | L1, L3 | Origin connection open 30.0 s after `Session.Close` and after `Proxy.Close` |
| 2 | A cut on a byte stream ends with a FIN or a close_notify, a normal end | L2 | `io.EOF` on the client after `Session.Close` |
| 2 | The backend of a 101 loses the half-close and the abort, both become a full close | L2, L3 | Read in `pipeConn` |
| 2 | A TCP handler returning an error other than a dial error ends the client leg with a FIN | L2 | Read in `serveTerminatedStream` |
| 2 | After `StartTLS`, `Session.Close` closes the socket under the TLS connection | L2 | No close_notify in 10 runs out of 10 |
| 2 | The request context of a terminated connection is no child of its session, so an HTTP/1.1 upstream request can outlive `Session.Close` until net/http fails its next write | L1 | Read in the `term` server |
| 3 | `Shutdown` cancels the context of the units of the HTTP/1.1 front, transparent, SOCKS5, 101 pipes, WebSocket, HTTP/1.1 CONNECT-UDP tunnels and SOCKS5 associations at its start. Their dials fail, a CONNECT answered 200 is reset, HTTP/1.1 tunnels and SOCKS5 associations are closed | L4 | Context done at 0 s on HTTP/1.1, 2.0 s on h2c. `Dial` fails on HTTP/1.1, succeeds on h2c |
| 3 | A SOCKS5 CONNECT negotiated during the drain is answered "succeeded" then reset, and a refused association gets no reply | L4 | Read in `socks.go` |
| 4 | After `Close` or `Shutdown`, upstream pools and dialers keep working, and an HTTP/2 upstream connection busy at the cut lives until `IdleConnTimeout` | L9 | Read in the forwarder and the exits |
| 4 | TLS connections opened by `http.Transport`, the backend of a 101 among them, keep crypto/tls's 5 s close_notify | L6 | `Session.Close` of a 101 pipe takes 5.0 s behind an origin that stopped reading |
| 5 | During the drain, every CONNECT-UDP tunnel ends as soon as no tunnel has a raw QUIC connection or a UDP flow inside it | L4 | A tunnel with an inner HTTP/3 request is gone 300 ms into the drain |
| 5 | The inner CONNECTION_CLOSE a tunnel sends is dropped when its send queue is full | L2 | Read in `connectUDPTunnel.send` |
| 6 | An HTTP/3 front connection idle after its GOAWAY keeps `Shutdown` waiting until the deadline | L4 | `Shutdown` reports the deadline with nothing in flight |
| 6 | QUIC close codes are not mirrored: an upstream ends with code 0 where H3_NO_ERROR applies, a client idle timeout reaches the origin as an explicit close, an origin error reaches the client as a no-error close | L3 | Read in the QUIC relay and the h3 pools |
| 6 | A UDP handler can still reply to the client after `Session.Close` | L9 | Read in `udpSink.toClient` |
| 6 | The documentation of `Session.Close` omits the front session | L10 | Read in `Session.Close` |
