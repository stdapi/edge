# Connection lifecycle

This document defines how every unit edge serves ends. Five invariants derive the form of every end from its cause and the class of its unit. The tables classify: what each kind of unit is, which form each protocol writes, which reply each refusal gets, which kind of cause each timer is. Where the code differs, the code has a defect. Where a library forbids an end, the Limits give what happens instead.

## Terms

**Unit.** What the proxy decides once, at its arrival, and serves until it ends: a **request**, one HTTP request or gRPC call served to its response, or a **session**, which serves a connection past one request. A **front connection** is a connection to an **explicit front**, a listener a client addresses as a proxy over HTTP, HTTP/3 or SOCKS5, from its arrival to its end or its handover. It is no unit, and ends as a unit does. The Units table lists each kind. A **redirected connection** is a connection a transparent listener accepts or `ServeConn` receives. A **demultiplexer** places each QUIC connection that arrives on a UDP socket or in a tunnel before it is served.

**Arrival and placement.** A unit or a front connection **arrives** as the Units table gives. A request that becomes a session **registers** it. An entry **admits** a unit when it matches the name the unit is routed on and its kind. The **destination** of a unit is the address it dials. A **pending** session is placed once the entry that serves what it carries is decided, and becomes the placed kind the Units table gives.

**HTTP connection.** A front connection to an HTTP or HTTP/3 front, or a session served as HTTP. It **reaches its server** once its TLS handshake ended, at its accept or its placement on plaintext.

**Leg.** What a unit or a front connection owns toward a peer: its **client leg**, toward the client, each connection dialed for it alone, each stream opened for it on a chained proxy connection, and for a request its response and each upstream request its handler sends with a context derived from the request's. A pooled upstream connection and a chained proxy connection shared by units belong to the **pool**, and so does the dial net/http keeps for a canceled upstream request. The pool ends a connection with the form of a framed unit.

**Layer.** A leg is a stack of layers, each with its own end: TCP, TLS, an HTTP/1.1 response, an HTTP/2 or HTTP/3 stream or connection, a QUIC stream or connection, WebSocket. A leg ends when each of its layers has ended, from the top down.

**Carrier.** What a unit arrives on when it belongs to another unit, to a front connection or to a UDP socket, as the Units table gives. A unit has at most one carrier, fixed at its arrival or at its handover.

**Handover.** A session registered on an HTTP/1.1 connection or on a SOCKS5 front connection takes its socket. What it was registered on ends then with no end form, and the socket is a leg of the session alone. The session is on the carrier of what it was registered on, and on none when that was a front connection.

**Class.** A **byte stream** ends with the forms of its transport and has no message of its own. A **framed** unit has messages or layers of its own. A **datagram flow** has no end signal. TLS the proxy terminates leaves a byte stream a byte stream.

**Handler** and **relay.** A handler is the function of the entry that serves a unit. A relay is the copy of the reads of one leg to another for a unit. The Units table gives which kinds run a handler and what each relays.

**Message in flight.** A request and its response, a gRPC call, a WebSocket message or a QUIC stream, from its first byte until it ended in both directions. A carrier has a message in flight while a unit on it has one. A byte stream and a datagram flow have none.

**Answer.** A status, a reply or a TLS alert the proxy writes in place of the origin:
- the **acceptance** of a session the Units table gives
- a refusal of the Refusals table, and a 408 at the read header timeout
- the response of the error handler to the error or the panic of an HTTP handler, and a 502 to one that returns no response and no error
- the status of a gRPC call that the proxy refuses, as the Refusals give, or that its handler ends before the origin's trailers with `Fail`, with an error, by a return before the end of an `Inbound` it began to read, or by a return of nil with no call to `Forward` or `Open`: the status given to `Fail`, else the status the handler's error maps to, else INTERNAL.

A panic with `http.ErrAbortHandler` gets no answer.

**Cause.** Why a unit or a front connection ends. A cause is **normal** or **failed**.
- Normal: its peer ended a leg normally, its handler returned nil, `Session.Close`, a cut, a refusal of the unit, a timer the Timers table gives as normal.
- Failed: its peer ended a leg with a failure or sent what the protocol of the leg forbids, gRPC framing included, its handler returned an error or panicked, a timer the Timers table gives as failed.

A **peer end** is a leg its peer ended, normally or with a failure, or on which its peer sent what the protocol forbids. A GOAWAY is no end. A **cause of the proxy** is any cause but a peer end and the return of a handler.

**Closer.** The one function that ends a unit or a front connection.

**T.** `alertWriteTimeout`, 1 s.

### Units

| Kind | Arrives | Carrier | Class | Handler | Relay | Acceptance |
|---|---|---|---|---|---|---|
| HTTP front connection | at its accept | none | framed | none | none | none |
| HTTP/3 front connection | at its first Initial | its UDP socket | framed | none | none | none |
| SOCKS5 front connection | at its accept | none | byte stream | none | none | none |
| HTTP request | once its header is read | its HTTP connection | framed | one, none before the 101 of an upgrade on a WebSocket entry | the request body a `Forward` method sends, the response its handler returns, after the return, and the response other than a 101 to an upgrade on a WebSocket entry | none |
| gRPC call | once its header is read | its HTTP connection | framed | one | `GRPCCtx.Forward`, and what `GRPCCtx.Open` relays once its handler returned | none |
| CONNECT | registers once authenticated and admitted on its authority | its HTTP/2 or HTTP/3 connection, by its handover on HTTP/1.1 | pending | none | none | its 200 |
| CONNECT-UDP, a tunnel | as a CONNECT | as a CONNECT | framed | none | none | its 200, its 101 on HTTP/1.1 |
| redirected connection | at its accept | none | pending | none | none | none |
| SOCKS5 CONNECT | registers once its request is read | by its handover | pending | none | none | the success reply |
| SOCKS5 association, a tunnel | registers once its request is read | by its handover, its control connection a leg | framed | none | none | the success reply |
| QUIC connection at a demultiplexer | at its first Initial | its UDP socket or its tunnel | pending | none | none | none |
| datagram flow | at its first datagram | its UDP socket or its tunnel | datagram flow | once per datagram, and its return ends nothing | none | none |
| WebSocket session | registers once the origin's 101 to an upgrade on a WebSocket entry reached the proxy | by its handover | framed | one | `WebSocketCtx.Relay` | its 101 |
| pipe | registers once the origin's 101 to an upgrade on an HTTP entry reached the proxy, a `TCP` entry admitting its authority | by its handover | byte stream | the handler of that `TCP` entry | the `Relay` function and methods | its 101 |

A pending session is a byte stream, a QUIC connection framed, and runs no handler. Once placed it is one of these, with its arrival, carrier and acceptance:

| Placed kind | Placed when | Class | Handler | Relay |
|---|---|---|---|---|
| session served by a `TCP` entry | a `TCP` entry admits it, or at the sniff timeout one admits its destination | byte stream | one | the `Relay` function and methods |
| session served as HTTP | an HTTP entry admits it, or a plaintext connection has no host to be placed on, an HTTP/2 preface or a first request with no host, and its requests are routed one by one | framed | none | none |
| terminated QUIC connection served stream by stream | a `QUIC` entry admits it | framed | one | `QUICCtx.Relay`, `QUICStream.Relay` |
| terminated QUIC connection served as HTTP/3 | as a session served as HTTP | framed | none | none |

## Invariants

**I1. One end.** A unit ends once, through its closer, and the first cause decides its forms. The closer runs at the first of these: a cause of the proxy, the return of the handler once the relays it started and the relay of what it returned ended, and, for a datagram flow and for a unit or a front connection that runs no handler, the end of its relay or a peer end of one of its legs. While a handler runs, a peer end is no cause of its unit. It reaches the handler as the result of a read, and reaches another leg only through a relay. An ICMP error ends nothing. The closer cancels the context of its unit and every dial in progress for it, and ends every leg of the unit in the same call, each layer once. A handler that returns after the closer finds nothing left to release, and its return writes nothing. A dial for a unit after its closer ran returns an error, and a leg that a dial opens then gets its failed end at once.

**I2. A truthful form.** The form of each layer follows from the cause and the class of its unit.
- The proxy writes an answer to a unit or a message only before anything from the origin reached the client for it, except the gRPC status of a call, in its trailers. A cut and `Session.Close` write no answer but the acceptance of a framed session, and an answer they find partly written is a message in flight. A CONNECT and a SOCKS5 CONNECT get their acceptance before the proxy reads what they carry, and what they carry is refused by the column of its first bytes.
- A message in flight gets its failed end, unless its peer or its handler ended it normally, which the proxy relays, or the proxy answered it. A request that its peer or its handler ended normally, or that the proxy answered, ends its layers with their normal end whatever its cause. An upstream request gets its failed end unless its handler or a relay read its response to its end, or its transport read the rest of the response and reused its connection.
- A layer gets its own form once the messages in flight on it have ended: its normal end when the cause is normal, its failed end when the cause is failed.
- A byte stream ends normally only when its peer or its handler ended it normally, or after an answer other than its acceptance. Any other cause gives it its failed end.
- A relay passes the end of one leg to the other in the same form, after the bytes it already read.

**I3. Carriers end last.** The closer of a carrier runs the closers of the units on it before it ends its own layers. A unit registers only on a carrier that has not ended. When a peer ends a carrier, a unit on it with a message in flight, and a byte stream with its own layer not ended, get their failed end, and any other unit on it the form of the carrier's end, at its own layer. A unit ends no layer of its carrier, except an HTTP/1.1 connection that the End forms and the Refusals end.

**I4. One deadline.** A closer and the closers it starts share one deadline, T after it started. A closer that runs again ends by the earlier of its own deadline and the deadline of the closer that runs it. The closer of a refusal has the bound of the read after it, `alertDrainTimeout` or `socks5RefuseLinger`, in place of T. A layer still ending at its deadline gets its failed end, except a layer that already wrote its normal end. The layers under that one then write nothing more, and its socket or stream closes. No end waits for a peer, a handler or a lock past its deadline, and a timer of an end ends at that deadline.

**I5. Nothing escapes.** Everything the proxy owns is registered from its creation to its end: listeners, UDP sockets, front connections, units, legs, pooled connections, dials and name resolutions. The drain and the cut wait on that registry alone. After their start the proxy creates nothing but what the drain serves, and when they return the registry is empty but for a resolution the system resolver has not returned. A dial that ignores its cancel is waited on no longer than the bound of the cut, and what it opens then gets its failed end at once.

## The drain and the cut

**Drain.** At the start of `Shutdown` the TCP listeners close, and the UDP sockets refuse each new QUIC connection. The proxy refuses every unit that arrives after the start, except a request on an HTTP connection that has not ended that is no CONNECT, no CONNECT-UDP and has no `Upgrade` field other than h2c, and a datagram flow in a tunnel that arrived before the start. The proxy decides a unit that arrived before the start as outside a drain. A unit that a front connection reads after the start arrives after the start. An HTTP connection gets its stop signal at the start, or, when it reaches its server after the start, once it began its first request or T after it reached its server: a GOAWAY on HTTP/2 and HTTP/3, `Connection: close` on each HTTP/1.1 response that does not hand its socket over. It serves the requests it began before its stop signal and, on HTTP/1.1, the requests read during the drain. It ends with its normal end once it has no request in flight and no session on it, at once on HTTP/1.1 and no earlier than T after its GOAWAY on HTTP/2 and HTTP/3. One on HTTP/1.1 that began no request ends T after the start or after it reached its server, whichever is later, unless it begins one by then. A front connection still in its TLS handshake at the start, which no read header timeout bounds, ends with its normal end T after the start. Once only the pools and the UDP sockets remain registered, the pools end, then the UDP sockets close, and `Shutdown` returns.

**Cut.** `Proxy.Close`, and `Shutdown` once its context ends, cut. A cut closes every listener, makes every UDP socket refuse each new QUIC connection, and refuses every new unit. Then it ends the registry in three stages: the units, the front connections, the pools. The UDP sockets close after the connections on them. Each stage starts its closers once the stage before it ended, and ends once its closers ended and the handlers of its units returned, within T of its start for each stage but the pools. The pool ends a chained HTTP/2 proxy connection after the wait for a write in progress and its GOAWAY, each bounded by `closeTimeout`, 1 s, so the pool stage ends within T and two `closeTimeout`. A cut returns within 3T and two `closeTimeout`. A cut that starts during a drain waits for the ends the drain started, within their bounds.

**Returns.** The proxy **stops** once a drain or a cut ended, and stops once. `Proxy.Close` starts the cut unless one runs. `Shutdown` joins the drain or the cut that runs, and starts the drain when none runs. Each returns once the proxy stopped. `Proxy.Close` returns the errors of closing the listeners in the call that closed them, nil otherwise. `Shutdown` returns those errors, joined to its context's error when its context started the cut and to `ErrProxyClosed` when another call started it. After the proxy stopped, both return nil at once. A `Serve` method closes its listener or socket, as net/http's `Serve` does, and returns `ErrProxyClosed` once it closed, at once when called after the start of a drain or a cut. `ServeConn` returns once its connection and the session it registered ended, `ErrProxyClosed` for a cut, nil for another normal cause, and otherwise the error that ended them. Called after the start, it gives its connection its failed end and returns `ErrProxyClosed`.

**Session.Close** runs the closer of one session and returns nil once that closer ended. On a session that another cause ended, it ends nothing. A call during another returns once the other returned. On the `Session` of a front connection, it ends the connection as the cut ends front connections. It writes no GOAWAY on an HTTP/2 or HTTP/3 connection, a front connection or a session served as HTTP. On a QUIC connection in its handshake, it waits for the handshake within T, and neither the cut nor the end of the tunnel that carries it does.

## Vocabulary

### End forms

| Layer | Normal end | Failed end | Half-close |
|---|---|---|---|
| TCP | FIN, then a read and discard until the peer's FIN, and close | RST, once the peer acknowledged what was written on Linux and macOS, within T, at once elsewhere | FIN |
| TLS | close_notify, then the normal end under it. After a failed write, no close_notify, and the failed end under it when the write cut a record short | the failed end under it | TLS 1.3: close_notify, then the half-close under it. TLS 1.2: none. A close_notify received on TLS 1.2 is the peer's normal end, and a relay withholds the half-close toward a TLS 1.2 leg until the other direction ends, RFC 5246 section 7.2.1. A FIN with no close_notify is the peer's half-close with no close_notify. A relay passes it as a FIN with no close_notify, and the leg it reached ends later with no close_notify |
| HTTP/1.1 response | the body complete | no response before the status line, the body cut after it, then the normal end of its connection. To an HTTP/1.0 request, the failed end of its connection | none |
| Upstream request | the response read to its end, by its handler, a relay, or the transport that reuses its connection | HTTP/1.1: the failed end of its connection. HTTP/2 and HTTP/3: the failed end of its stream | none |
| HTTP/2 stream | END_STREAM | RST_STREAM INTERNAL_ERROR on a stream accepted. On a stream opened, CONNECT_ERROR on a CONNECT and CANCEL on any other stream | END_STREAM |
| HTTP/3 stream | FIN, with STOP_SENDING H3_NO_ERROR when the request body did not end | RESET_STREAM and STOP_SENDING. H3_MESSAGE_ERROR on a stream with a peer that sent a malformed HTTP/3 message or capsule, RFC 9114 section 4.1.2 and RFC 9297 section 3.3. On a stream accepted, H3_INTERNAL_ERROR before its response header. Otherwise H3_CONNECT_ERROR on a CONNECT and H3_REQUEST_CANCELLED on any other stream | FIN |
| HTTP/2, HTTP/3 connection | GOAWAY, then the normal end under it | the failed end under it. After a connection error on HTTP/2, a GOAWAY with its code, then the normal end under it, RFC 9113 section 5.4.1, the code being the failure signal as a TLS alert is | none |
| QUIC stream | FIN | RESET_STREAM and STOP_SENDING with the failed code of its connection | FIN |
| QUIC connection | CONNECTION_CLOSE H3_NO_ERROR with ALPN h3, code 0 otherwise. On a connection the proxy accepted and serves stream by stream, ended by the return of its handler with no stream in flight, or by its other leg, written once the peer closed the connection or at the deadline, as quic-go's HTTP/3 server waits for its clients. In its handshake, APPLICATION_ERROR, RFC 9000 section 10.2.3. Pending, CONNECTION_REFUSED | CONNECTION_CLOSE H3_INTERNAL_ERROR with ALPN h3, code 0x1 otherwise. In its handshake, APPLICATION_ERROR. Pending, CONNECTION_REFUSED | none |
| WebSocket | a Close frame, then the normal end under it | no Close frame, then the failed end under it | none |
| Datagram flow | its sockets close, each origin leg that has an end form gets its normal end, and the datagrams queued are dropped | as the normal end | none |

A framed session that a cause of the proxy other than a refusal ends before its acceptance gets its acceptance first. A Close frame the proxy writes of its own has the code of the receiving peer's own Close frame when it sent one, else 1001 on `Session.Close` and a cut, else 1000. None goes to a peer to which a message is partly written, the Close of a broken protocol included. A peer that sent what RFC 6455 forbids gets a Close frame 1002, 1007 for text that is not UTF-8, then the normal end under it, RFC 6455 section 7.1.7. A relay keeps the peer's code between two legs of one protocol. Across protocols CANCEL and H3_REQUEST_CANCELLED, CONNECT_ERROR and H3_CONNECT_ERROR map to each other, and any other code gives the failed end of the leg written.

### Refusals

The column follows the first bytes of the unit. A connection refused with first bytes of no column gets its failed end. A datagram the entries refuse is dropped, and its flow goes on.

| Cause | HTTP | SOCKS5 | TLS ClientHello | QUIC Initial |
|---|---|---|---|---|
| Malformed | 400 | 0xFF during method selection, the failure status of RFC 1929 during its subnegotiation, and to a request reply 0x07 to a command other than CONNECT and UDP ASSOCIATE, 0x08 to an unknown address type, 0x01 otherwise | decode_error | as TLS |
| Authentication fails | 407, or 403 when the authenticator offers no challenge | the failure status of RFC 1929 | not applicable | not applicable |
| No entry admits the unit | 403 | reply 0x02 | unrecognized_name, missing_extension with no server name | as TLS |
| Under `VerifyReject`, the name does not match its destination, or cannot be resolved | 403 | not applicable | unrecognized_name | as TLS |
| A request host the certificate of its connection does not cover | 421 | not applicable | not applicable | not applicable |
| Before a handler runs, a host the proxy dials cannot be resolved or reached, or ends before its response header | 502 | not applicable | not applicable | not applicable |
| An extended CONNECT with a protocol other than connect-udp | 501 | not applicable | not applicable | not applicable |
| The termination of its TLS fails | not applicable | not applicable | the alert of the handshake error | the CONNECTION_CLOSE of the handshake error |
| A request loop | the failed end of the connection once its first bytes arrived, before they are parsed | as HTTP | as HTTP | CONNECTION_REFUSED at its first Initial at a demultiplexer, CONNECTION_CLOSE H3_EXCESSIVE_LOAD after the handshake on the HTTP/3 front, the datagram dropped on a datagram flow |
| The drain refuses it | 503 | reply 0x01 | not applicable | CONNECTION_REFUSED, the first datagram dropped on a datagram flow |
| The cut refuses it | the failed end | the failed end | the failed end | CONNECTION_REFUSED |

Under `VerifyLoose` a name that does not match or cannot be resolved is dropped, and the unit is decided on its destination. Under `VerifyOff`, the default, the name is trusted as the client sent it.

A refusal that ends a connection after a TLS handshake the proxy terminated writes close_notify, RFC 8446 section 6.1, the cut and a request loop excepted. On HTTP/1.1, a 400, a refused CONNECT or upgrade, the refusal of the first request of a plaintext connection placed on that request, and the 408, have `Connection: close` and end the connection with its normal end, and the connection stays open after another refusal.

A gRPC call gets a trailers-only response with HTTP status 200 and the status of its refusal: INVALID_ARGUMENT for 400, UNAUTHENTICATED for 407, PERMISSION_DENIED for 403, UNAVAILABLE for 421 and 502. A gRPC call refused at a later message gets UNAVAILABLE in its trailers.

The SOCKS5 success reply of a CONNECT comes before any resolution and any dial. Its BND.ADDR and BND.PORT are the address of the proxy's end of the client connection, where RFC 1928 section 6 gives the address the proxy connects to the target from. The success reply of a UDP ASSOCIATE has the address of its relay socket, RFC 1928 section 7.

### Timers

| Timer | Bound | What it bounds | End |
|---|---|---|---|
| read header timeout, `WithReadHeaderTimeout` | 10 s by default | a request header, a SOCKS5 negotiation, a ClientHello, a TLS handshake the proxy terminates over TCP | failed. A 408 on a plaintext connection placed on its first request, the refusal of a malformed request on a SOCKS5 negotiation |
| QUIC handshake timeout, quic-go | 5 s with no packet, 10 s in all | a QUIC handshake | none. The connection closes with no CONNECTION_CLOSE |
| idle timeout, `WithIdleTimeout` | 90 s by default | an HTTP connection with no request in flight and no session on it | normal |
| QUIC idle timeout, `WithIdleTimeout` | 90 s by default, or the shorter one the peer gives | a QUIC connection with no packet | normal. The connection that timed out closes with no CONNECTION_CLOSE, RFC 9000 section 10.1 |
| sniff timeout, `WithSniffTimeout` | 1 s by default | the first bytes of a connection not yet placed | none. The connection is placed on its destination. A ClientHello as its first bytes after it is failed |
| `udpFlowIdle` | 2 min | a datagram flow with no datagram in either direction, a tunnel with no inner unit. A tunnel ends with its last flow when that flow ends at this timer, RFC 9298 section 3.1 | normal |
| `wsCloseTimeout` | 5 s | the wait for a WebSocket peer's Close frame after a relay passed the other peer's | normal |
| `Relayer.IdleTimeout` | set by the caller | a byte-stream relay with no byte in either direction | failed |
| `quicSniffTTL` | 10 s | a QUIC connection with an incomplete ClientHello | CONNECTION_REFUSED |
| `nameVerifyTimeout` | 5 s | the resolution of a name to verify | the refusal for a name that cannot be resolved |
| `alertDrainTimeout`, `socks5RefuseLinger` | 500 ms, 2 s | the read after a TLS alert, after a SOCKS5 refusal | normal |
| `tunnelDrainTimeout` | 1 s | the queue of an ended tunnel toward a client that no longer reads | failed |
| the dial timeout of the transport | set by the caller | the dial before a handler runs | 502 |
| the dial of a flow's upstream socket | 10 s | the dial | the end of the flow |
| `proxyConnectTimeout` | 1 min | the dial of a chained proxy | the error of the dial, to the handler |
| `proxyKeepAlive`, chained write timeout | 10 s, 30 s | a PING with no reply, a write that does not end, on a chained HTTP/2 proxy connection | failed |
| `closeTimeout` | 1 s | each closing write of a chained HTTP/2 proxy connection | failed |

The timers that bound a retry or a memory end nothing on the network.

## Limits

Go, x/net, quic-go and the kernel are fixed. These ends differ from the invariants or the RFCs.

- net/http lets a handler reset an HTTP/2 stream only with INTERNAL_ERROR, where RFC 9113 gives CONNECT_ERROR to a CONNECT and CANCEL to a canceled request. It writes END_STREAM only when the handler returns, and then RST_STREAM NO_ERROR when the request body was not read to its end. An origin half-close ends an HTTP/2 CONNECT stream and stops the client's upload.
- quic-go lets a handler reset an HTTP/3 stream only from its goroutine, and before a response header only with H3_INTERNAL_ERROR. The stream it hands over has a response header, 200 when none was written. So the closer of a request on HTTP/3 ends its stream when its handler returns, or with its connection, which then gets its failed end at its deadline, and a request the proxy refuses before processing it gets no H3_REQUEST_REJECTED.
- quic-go cancels the context of an HTTP/3 request with the send side of its stream, so a client RESET_STREAM with no STOP_SENDING after the request body was read reaches no handler.
- quic-go hands an HTTP/3 front connection over once its handshake completed, and the close of its listener ends a connection still in its handshake with CONNECTION_REFUSED. So a cut gives that connection CONNECTION_REFUSED.
- net/http writes RST_STREAM and GOAWAY from its own goroutines, and quic-go drops a RESET_STREAM still queued at CONNECTION_CLOSE, so a client may read the end of a connection before them.
- net/http reports no connection error of an HTTP/2 connection it serves, so a session served as HTTP gets a normal cause when its peer broke HTTP/2, while its connection gets the GOAWAY with the code of that error.
- net/http closes an HTTP/2 connection at a failed write, so its end is decided before what is still unread behind it, the reset of a stream or a close_notify among them, is read.
- quic-go closes an HTTP/3 connection at its idle timeout with H3_NO_ERROR and no GOAWAY. It drops a CONNECTION_REFUSED it cannot queue, so a QUIC connection refused under load gets no reply.
- quic-go drops the stream data still queued at CONNECTION_CLOSE and reports no acknowledgement, so the bytes queued toward an origin at the normal end of a connection the proxy opened can be lost.
- quic-go packs a QUIC datagram and the end of a stream in no fixed order, and its client drops a datagram that arrives once it read its stream to the end, so the CONNECTION_CLOSE and the refusals the end of a tunnel queues on HTTP/3 can be lost.
- quic-go closes an idle pooled HTTP/3 connection itself, and its close waits for the writes queued on the connection, so the eviction of a pool waits on a chained exit that stopped reading until the proxy connection under the exit or the cut ends it.
- quic-go closes an established connection only with an application error code, so a transport error on one leg of a terminated QUIC connection reaches the other leg as its failed end.
- net/http discards the streams begun after its GOAWAY, RFC 9113 section 6.8, and quic-go rejects them with H3_REQUEST_REJECTED, so a request on HTTP/2 or HTTP/3 that arrives after the stop signal gets no response. quic-go reports neither the GOAWAY of an HTTP/3 connection nor the streams it accepted, so a request stream accepted before the GOAWAY with no handler begun T after it gets the normal end of its connection.
- net/http closes an idle pooled HTTP/2 connection with no GOAWAY. quic-go closes an idle pooled HTTP/3 connection with code 0 and no GOAWAY, and reports no use count, so the eviction of an idle pool gives its HTTP/3 connections code 0.
- net/http cancels an HTTP/1.1 request when its client sends a FIN after the request. The upstream request gets its failed end, and the handler reads the cancel as the error of `Forward`.
- net/http answers a request it cannot parse with 400, 417, 431, 501 or 505, and resets a malformed HTTP/2 request with PROTOCOL_ERROR, before any handler runs. It ends a connection at the read header timeout of a request after the first through the close that ends a connection once its response was written, so that connection gets its normal end.
- crypto/tls writes no close_notify before its handshake completes, and reports no record to the caller of `Write`, so a failed write on a TLS connection a caller's listener established gives the failed end of its socket. It reports a FIN with no close_notify as a close_notify, so a relay passes such a FIN from a TLS connection a caller's listener established as a half-close with close_notify.
- A connection a caller's listener established that is not a `*net.TCPConn` ends through its own Close, the proxy reaching no socket under it, so its failed end is the end that Close gives.
- An RST, a RESET_STREAM or an RST_STREAM may discard bytes the peer has not read, and a socket closed with bytes unread draws an RST from the kernel.
- Go abandons a canceled resolution on macOS and leaves the system resolver running, so its queries may outlive the cut.
