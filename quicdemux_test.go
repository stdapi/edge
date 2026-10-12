// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/fox-toolkit/edge/internal/quicsniff"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConformanceQUIC(t *testing.T) { runConformance(t, quicConformance) }

// quicConformance lists the requirements QUIC places on the endpoint standing where a server
// would be, checked with packets written by hand in front of the demultiplexer around a
// ClientHello from crypto/tls, and with a quic-go client where a row needs a connection past
// its handshake.
var quicConformance = []conformanceCase{
	// RFC 9000 section 5.2, matching packets to connections.
	{
		id: "rfc9000/5.2/1", name: "the client continues its handshake toward the connection ID the proxy chose",
		req: "If the packet has a non-zero-length Destination Connection ID corresponding to an existing connection, QUIC processes that packet accordingly.",
		run: func(t *testing.T) {
			p, addr := quicHTTPServer(t)
			pc, err := loopbackUDP()
			require.NoError(t, err)
			conn := dialSharedQUIC(t, clientTransport(t, pc), addr, h3Authority, poolOf(p.cfg.ca))
			require.Equal(t, "ok", h3Get(t, h3Over(t, conn), h3Authority, addr.Port()))
		},
	},

	// RFC 9000 section 5.2.2, server packet handling.
	{
		id: "rfc9000/5.2.2/1", name: "a long header of an unsupported version in a datagram of 1200 bytes",
		req: "If a server receives a packet that indicates an unsupported version and if the packet is large enough to initiate a new connection for any supported version, the server SHOULD send a Version Negotiation packet as described in Section 6.1.",
		run: func(t *testing.T) {
			addr := quicServer(t, h3Authority)
			client, _ := udpClient(t)
			dcid, scid := randomBytes(t, 8), randomBytes(t, 8)
			sendDatagram(t, client, addr, unknownVersion(t, dcid, scid, 1200))
			dg, err := readDatagram(t, client, 5*time.Second)
			require.NoError(t, err, "no Version Negotiation came back")
			h, ok := parseQUICLong([]byte(dg))
			require.True(t, ok, "the answer has no long header")
			require.Zero(t, h.version, "the answer is no Version Negotiation packet")
			assert.Equal(t, scid, h.dcid)
			assert.Equal(t, dcid, h.scid)
			versions := []byte(dg)[7+len(h.dcid)+len(h.scid):]
			require.Zero(t, len(versions)%4, "the version list is cut")
			var listed []uint32
			for v := range slices.Chunk(versions, 4) {
				listed = append(listed, binary.BigEndian.Uint32(v))
			}
			assert.Contains(t, listed, quicsniff.Version1)
			assert.Contains(t, listed, quicsniff.Version2)
		},
	},
	{
		id: "rfc9000/5.2.2/2", name: "a long header of an unsupported version in a datagram of 100 bytes, to a destination a UDP entry admits",
		req:  "Servers MUST drop smaller packets that specify unsupported versions.",
		skip: "a datagram of a version the demultiplexer cannot read is indistinguishable from another protocol on a socket that serves every UDP flow, so dispatchLong in quicdemux.go hands it to the UDP entry admitting its destination",
	},
	{
		id: "rfc9000/5.2.2/3", name: "a QUIC v1 Initial of 1200 bytes with a complete ClientHello",
		req: "If the packet is an Initial packet fully conforming with the specification, the server proceeds with the handshake (Section 7). This commits the server to the version that the client selected.",
		run: func(t *testing.T) { wantHandshake(t, quicsniff.Version1) },
	},
	{
		id: "rfc9000/5.2.2/4", name: "two Initials of different connection IDs from one client socket",
		req: "If the packet is an Initial packet fully conforming with the specification, the server proceeds with the handshake (Section 7).",
		run: func(t *testing.T) {
			addr := quicServer(t, "a.example.test", "b.example.test")
			client, _ := udpClient(t)
			a := newQUICAttempt(t, quicsniff.Version1, "a.example.test")
			b := newQUICAttempt(t, quicsniff.Version1, "b.example.test")
			sendDatagram(t, client, addr, a.first(t))
			sendDatagram(t, client, addr, b.first(t))

			answered := map[string]bool{}
			deadline := time.Now().Add(5 * time.Second)
			for len(answered) < 2 {
				dg, err := readDatagram(t, client, time.Until(deadline))
				require.NoError(t, err, "answered %d of the two connections", len(answered))
				h, ok := parseQUICLong([]byte(dg))
				if ok && (h.isInitial() || h.isRetry()) {
					answered[string(h.dcid)] = true
				}
			}
			assert.True(t, answered[string(a.scid)])
			assert.True(t, answered[string(b.scid)])
		},
	},
	{
		id: "rfc9000/5.2.2/5", name: "an Initial for a server name no entry admits",
		req: "If a server refuses to accept a new connection, it SHOULD send an Initial packet containing a CONNECTION_CLOSE frame with error code CONNECTION_REFUSED.",
		run: func(t *testing.T) {
			for _, v := range quicVersions {
				t.Run(v.name, func(t *testing.T) {
					addr := quicServer(t, h3Authority)
					client, _ := udpClient(t)
					a := newQUICAttempt(t, v.version, "refused.example.test")
					sendDatagram(t, client, addr, a.first(t))
					assert.Contains(t, []uint64{0x02, 0x170}, wantCloseBack(t, client, a, 5*time.Second), "the error code is neither CONNECTION_REFUSED nor unrecognized_name")
				})
			}
		},
	},
	{
		id: "rfc9000/5.2.2/6", name: "a Handshake packet before any Initial, to a destination a UDP entry admits",
		req: "Clients are not able to send Handshake packets prior to receiving a server response, so servers SHOULD ignore any such packets.",
		run: func(t *testing.T) {
			pkt := quicPacket{version: quicsniff.Version1, typ: quicTypeHandshake, dcid: randomBytes(t, 8), scid: randomBytes(t, 8)}
			wantDropped(t, pkt.sized(t, 200))
		},
	},
	{
		id: "rfc9000/5.2.2/7", name: "a 0-RTT packet, a Retry packet and an Initial of a 7-byte connection ID, to a destination a UDP entry admits",
		req: "Servers MUST drop incoming packets under all other circumstances.",
		run: func(t *testing.T) {
			zeroRTT := quicPacket{version: quicsniff.Version1, typ: quicType0RTT, dcid: randomBytes(t, 8), scid: randomBytes(t, 8)}
			short := newQUICAttempt(t, quicsniff.Version1, h3Authority)
			short.dcid = randomBytes(t, 7)
			for _, tc := range []struct {
				name     string
				datagram []byte
			}{
				{"0-RTT", zeroRTT.sized(t, 1200)},
				{"Retry", retryPacket(t)},
				{"Initial", short.first(t)},
			} {
				t.Run(tc.name, func(t *testing.T) { wantDropped(t, tc.datagram) })
			}
		},
	},
	{
		id: "rfc9000/5.2.2/8", name: "a short header packet of a connection ID the proxy did not mint, to a destination a UDP entry admits",
		req:  "Servers MUST drop incoming packets under all other circumstances.",
		skip: "a short header has no version field and any datagram with the high bit cleared reads as one, so dispatchShort in quicdemux.go hands it to the UDP entry admitting its destination",
	},

	// RFC 9000 section 8.2.2, path validation responses.
	{
		id: "rfc9000/8.2.2/1", name: "the client probes a new path from a second socket",
		req: "A PATH_RESPONSE frame MUST be sent on the network path where the PATH_CHALLENGE frame was received.",
		run: func(t *testing.T) {
			for _, front := range quicSockets {
				t.Run(front.name, func(t *testing.T) {
					p, addr := front.start(t)
					first, err := loopbackUDP()
					require.NoError(t, err)
					second, err := loopbackUDP()
					require.NoError(t, err)
					old := &pathConn{PacketConn: first}
					conn := dialSharedQUIC(t, clientTransport(t, old), addr, h3Authority, poolOf(p.cfg.ca))
					require.Equal(t, "ok", h3Get(t, h3Over(t, conn), h3Authority, addr.Port()))

					path, err := conn.AddPath(clientTransport(t, second))
					require.NoError(t, err)
					// quic-go accepts a PATH_RESPONSE on any path, so only the probed one may
					// deliver it.
					old.blocked.Store(true)
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					require.NoError(t, path.Probe(ctx), "no PATH_RESPONSE reached the probed path")
				})
			}
		},
	},

	// RFC 9000 section 9.3, responding to connection migration.
	{
		id: "rfc9000/9.3/1", name: "a NAT moves the client to another port in the middle of the connection",
		req: "If the recipient permits the migration, it MUST send subsequent packets to the new peer address",
		run: func(t *testing.T) {
			for _, front := range quicSockets {
				t.Run(front.name, func(t *testing.T) {
					p, addr := front.start(t)
					mc := newMovingConn(t)
					conn := dialSharedQUIC(t, clientTransport(t, mc), addr, h3Authority, poolOf(p.cfg.ca))
					cc := h3Over(t, conn)
					require.Equal(t, "ok", h3Get(t, cc, h3Authority, addr.Port()))

					mc.rebind()
					require.Equal(t, "ok", h3Get(t, cc, h3Authority, addr.Port()))
					assert.Positive(t, mc.arrived.Load(), "nothing reached the new port")
				})
			}
		},
	},

	// RFC 9000 section 10.3, stateless reset.
	{
		id: "rfc9000/10.3/1", name: "an open connection the proxy closes through its session",
		req: "An endpoint that wishes to communicate a fatal connection error MUST use a CONNECTION_CLOSE frame if it is able.",
		run: func(t *testing.T) {
			p, addr := quicHTTPServer(t)
			pc, err := loopbackUDP()
			require.NoError(t, err)
			conn := dialSharedQUIC(t, clientTransport(t, pc), addr, h3Authority, poolOf(p.cfg.ca))
			require.Equal(t, "ok", h3Get(t, h3Over(t, conn), h3Authority, addr.Port()))

			require.NoError(t, waitForSessions(t, p, 1)[0].Close())
			select {
			case <-conn.Context().Done():
			case <-time.After(5 * time.Second):
				t.Fatal("the connection outlived the close")
			}
			cause := context.Cause(conn.Context())
			var appErr *quic.ApplicationError
			var transportErr *quic.TransportError
			switch {
			case errors.As(cause, &appErr):
				assert.True(t, appErr.Remote)
			case errors.As(cause, &transportErr):
				assert.True(t, transportErr.Remote)
			default:
				t.Fatalf("the connection ended without a CONNECTION_CLOSE: %v", cause)
			}
		},
	},
	{
		id: "rfc9000/10.3/2", name: "two packets of one orphaned connection ID",
		req: "The remainder of the first byte and an arbitrary number of bytes following it are set to values that SHOULD be indistinguishable from random.",
		run: func(t *testing.T) {
			o := newOrphan(t)
			cid := o.mint(t)
			o.send(t, o.trigger(t, cid, 1200))
			o.send(t, o.trigger(t, cid, 1200))
			first, second := o.read(t), o.read(t)
			require.Len(t, first, quicResetSize)
			require.Len(t, second, quicResetSize)
			assert.NotEqual(t, first[1:quicResetSize-16], second[1:quicResetSize-16])
		},
	},
	{
		id: "rfc9000/10.3/3", name: "a packet of 43 bytes on an orphaned connection ID",
		req: "An endpoint that sends a Stateless Reset in response to a packet that is 43 bytes or shorter SHOULD send a Stateless Reset that is one byte shorter than the packet it responds to.",
		run: func(t *testing.T) {
			o := newOrphan(t)
			cid := o.mint(t)
			for _, reset := range o.resets(t, o.trigger(t, cid, 43)) {
				if o.answers(reset, cid) {
					assert.Len(t, reset, 42)
				}
			}
		},
	},
	{
		id: "rfc9000/10.3/4", name: "a packet of 14 bytes on an orphaned connection ID",
		req: "An endpoint MUST NOT send a Stateless Reset that is three times or more larger than the packet it receives to avoid being used for amplification.",
		run: func(t *testing.T) {
			o := newOrphan(t)
			cid := o.mint(t)
			for _, reset := range o.resets(t, o.trigger(t, cid, 14)) {
				if o.answers(reset, cid) {
					assert.Less(t, len(reset), 3*14)
				}
			}
		},
	},
	{
		id: "rfc9000/10.3/5", name: "a short header packet of 20 bytes on an orphaned connection ID",
		req: "Endpoints MUST discard packets that are too small to be valid QUIC packets.",
		run: func(t *testing.T) {
			o := newOrphan(t)
			cid := o.mint(t)
			for _, reset := range o.resets(t, o.trigger(t, cid, 20)) {
				assert.False(t, o.answers(reset, cid), "a packet of 20 bytes was answered")
			}
		},
	},
	{
		id: "rfc9000/10.3/6", name: "a packet of 1200 bytes on an orphaned connection ID",
		req: "Endpoints MUST send Stateless Resets formatted as a packet with a short header.",
		run: func(t *testing.T) {
			o := newOrphan(t)
			o.send(t, o.trigger(t, o.mint(t), 1200))
			reset := o.read(t)
			assert.Zero(t, reset[0]&0x80, "the reset has a long header")
		},
	},

	// RFC 9000 section 10.3.1, detecting a stateless reset.
	{
		id: "rfc9000/10.3.1/1", name: "the client sends a stateless reset for the connection ID the proxy addresses",
		req: "However, the comparison MUST be performed when the first packet in an incoming datagram either cannot be associated with a connection or cannot be decrypted.",
		run: func(t *testing.T) {
			for _, front := range quicSockets {
				t.Run(front.name, func(t *testing.T) {
					p, addr := front.start(t)
					pc, err := loopbackUDP()
					require.NoError(t, err)
					rec := &cidConn{PacketConn: pc}
					key := quic.StatelessResetKey(randomBytes(t, 32))
					tr := &quic.Transport{Conn: rec, StatelessResetKey: &key, ConnectionIDLength: 8}
					t.Cleanup(func() { _ = tr.Close(); _ = pc.Close() })
					conn := dialSharedQUIC(t, tr, addr, h3Authority, poolOf(p.cfg.ca))
					require.Equal(t, "ok", h3Get(t, h3Over(t, conn), h3Authority, addr.Port()))
					sess := waitForSessions(t, p, 1)[0]

					// The client issues no token for its first connection ID, and the proxy
					// moves to another one after the handshake.
					require.Eventually(t, func() bool {
						read := rec.lastRead()
						return read != nil && !bytes.Equal(read, rec.firstSource())
					}, 5*time.Second, 10*time.Millisecond, "the proxy kept addressing the first connection ID of the client")

					reset := randomBytes(t, quicResetSize)
					reset[0] = reset[0]&0x3f | 0x40
					copy(reset[quicResetSize-16:], resetTokenOf(key[:], rec.lastRead()))
					_, err = rec.WriteTo(reset, net.UDPAddrFromAddrPort(addr))
					require.NoError(t, err)
					select {
					case <-sess.Context().Done():
					case <-time.After(2 * time.Second):
						t.Fatal("the connection outlived a stateless reset from its client")
					}
				})
			}
		},
	},

	// RFC 9000 section 10.3.3, looping.
	{
		id: "rfc9000/10.3.3/1", name: "packets of 42 and 43 bytes on orphaned connection IDs",
		req: "An endpoint MUST ensure that every Stateless Reset that it sends is smaller than the packet that triggered it, unless it maintains state sufficient to prevent looping.",
		run: func(t *testing.T) {
			o := newOrphan(t)
			small, large := o.mint(t), o.mint(t)
			for _, reset := range o.resets(t, o.trigger(t, small, 42), o.trigger(t, large, 43)) {
				if o.answers(reset, small) {
					assert.Less(t, len(reset), 42)
				}
				if o.answers(reset, large) {
					assert.Less(t, len(reset), 43)
				}
			}
		},
	},

	// RFC 9000 section 12.2, coalescing packets.
	{
		id: "rfc9000/12.2/1", name: "a 0-RTT packet coalesced ahead of the first Initial",
		req:  "For example, if decryption fails (because the keys are not available or for any other reason), the receiver MAY either discard or buffer the packet for later processing and MUST attempt to process the remaining packets.",
		skip: "the sentence binds a receiver that attributed the datagram to a connection, RFC 9000 section 12.2 lets a receiver route on the first packet of a datagram, and quic-go drops a datagram whose first packet is 0-RTT since quicConfig in quicdemux.go leaves Allow0RTT off",
	},

	// RFC 9000 section 14.1, initial datagram size.
	{
		id: "rfc9000/14.1/1", name: "a first Initial in a datagram of 1199 bytes, to a destination a UDP entry admits",
		req: "A server MUST discard an Initial packet that is carried in a UDP datagram with a payload that is smaller than the smallest allowed maximum datagram size of 1200 bytes.",
		run: func(t *testing.T) {
			for _, v := range quicVersions {
				t.Run(v.name, func(t *testing.T) {
					a := newQUICAttempt(t, v.version, h3Authority)
					wantDropped(t, a.packet(0, cryptoFrameOf(0, a.hello)).sized(t, 1199))
				})
			}
		},
	},
	{
		id: "rfc9000/14.1/2", name: "an Initial in a datagram of 600 bytes after the proxy answered the first one",
		req: "A server MUST discard an Initial packet that is carried in a UDP datagram with a payload that is smaller than the smallest allowed maximum datagram size of 1200 bytes.",
		run: func(t *testing.T) {
			addr := quicServer(t, h3Authority)
			client, _ := udpClient(t)
			a := newQUICAttempt(t, quicsniff.Version1, h3Authority)
			sendDatagram(t, client, addr, a.first(t))
			wantInitialBack(t, client, a, 5*time.Second)

			sendDatagram(t, client, addr, a.packet(1, []byte{0x01}).sized(t, 600))
			deadline := time.Now().Add(time.Second)
			for {
				dg, err := readDatagram(t, client, time.Until(deadline))
				if err != nil {
					return
				}
				frames, ok := openServerInitial(quicsniff.Version1, a.dcid, []byte(dg))
				if !ok {
					continue
				}
				c, ok := initialFrames(frames)
				require.True(t, ok, "the frames of the Initial do not parse")
				if slices.Contains(c.types, 0x1c) {
					// The server MAY close the connection with PROTOCOL_VIOLATION.
					require.Equal(t, uint64(0x0a), c.closeCode, "the error code is not PROTOCOL_VIOLATION")
					return
				}
				require.False(t, c.acks(1), "the proxy acknowledged the Initial it had to discard")
			}
		},
	},

	// RFC 9000 section 21.11, stateless reset oracle.
	{
		id: "rfc9000/21.11/1", name: "a short header with the connection ID of a live connection, sent to another destination of the proxy",
		req: "More generally, servers MUST NOT generate a stateless reset if a connection with the corresponding connection ID could be active on any endpoint using the same static key.",
		run: func(t *testing.T) {
			for _, tc := range []struct {
				start func(t *testing.T) (cid []byte, key quic.StatelessResetKey, attacker net.PacketConn, to net.Addr)
				name  string
			}{
				{oracleTwoSockets, "two sockets"},
				{oracleTwoOrigins, "two origins under TPROXY"},
				{oracleDatagramOrigin, "an origin with a datagram flow and no stack under TPROXY"},
				{oracleTwoTunnels, "two CONNECT-UDP tunnels to one target"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					cid, key, attacker, to := tc.start(t)
					require.Len(t, cid, 8)

					probe := randomBytes(t, 1200)
					probe[0] = probe[0]&0x3f | 0x40
					copy(probe[1:], cid)
					_, err := attacker.WriteTo(probe, to)
					require.NoError(t, err)

					token := resetTokenOf(key[:], cid)
					buf := make([]byte, maxUDPPayload)
					require.NoError(t, attacker.SetReadDeadline(time.Now().Add(time.Second)))
					for {
						n, _, err := attacker.ReadFrom(buf)
						if err != nil {
							return
						}
						require.False(t, bytes.HasSuffix(buf[:n], token), "a stateless reset for the connection ID of a live connection came back")
					}
				})
			}
		},
	},

	// RFC 9287 section 3.1, clearing the QUIC bit.
	{
		id: "rfc9287/3.1/1", name: "a packet of 1200 bytes on an orphaned connection ID",
		req: "An endpoint MUST NOT set the QUIC Bit to 0 without knowing whether the peer supports the extension.",
		run: func(t *testing.T) {
			o := newOrphan(t)
			o.send(t, o.trigger(t, o.mint(t), 1200))
			reset := o.read(t)
			assert.NotZero(t, reset[0]&0x40, "the reset clears the QUIC bit")
		},
	},

	// RFC 9369 section 3, differences with QUIC version 1.
	{
		id: "rfc9369/3/1", name: "a QUIC v2 Initial of 1200 bytes with a complete ClientHello",
		req: "Except for a few differences, QUIC version 2 endpoints MUST implement the QUIC version 1 specification as described in [QUIC], [QUIC-TLS], and [QUIC-RECOVERY].",
		run: func(t *testing.T) { wantHandshake(t, quicsniff.Version2) },
	},

	// RFC 9369 section 4, version negotiation considerations.
	{
		id: "rfc9369/4/1", name: "a QUIC v2 connection",
		req:  "Any QUIC endpoint that supports QUIC version 2 MUST send, process, and validate the version_information transport parameter specified in [QUIC-VN] to prevent version downgrade attacks.",
		skip: "quic-go v0.63 sends no version_information transport parameter, and the terminating stacks accept the versions quic-go supports",
	},
}

func TestQUIC_ClientTakesTheResetOfARestartedProxy(t *testing.T) {
	p := testProxy(t)
	p.MustAdd(h3Authority+"/", okHandler)
	listened, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	crashing := &muteConn{PacketConn: listened}
	gone, goneAddr := serveDemuxOn(t, p, crashing)

	pc, err := loopbackUDP()
	require.NoError(t, err)
	conn := dialSharedQUIC(t, clientTransport(t, pc), goneAddr, h3Authority, poolOf(p.cfg.ca))
	require.Equal(t, "ok", h3Get(t, h3Over(t, conn), h3Authority, goneAddr.Port()))

	crashing.muted.Store(true)
	gone.close()
	o := newOrphanAt(t, p, goneAddr.String())
	require.Equal(t, goneAddr, o.addr)

	str, err := conn.OpenStream()
	require.NoError(t, err)
	_, _ = str.Write(make([]byte, 64))
	select {
	case <-conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the client did not take the reset")
	}
	var reset *quic.StatelessResetError
	require.True(t, errors.As(context.Cause(conn.Context()), &reset))
}

func TestQUIC_SniffDropsAnInitialUnder1200Bytes(t *testing.T) {
	addr := quicServer(t, h3Authority)
	client, _ := udpClient(t)
	a := newQUICAttempt(t, quicsniff.Version1, h3Authority)
	half := len(a.hello) / 2
	sendDatagram(t, client, addr, a.packet(0, cryptoFrameOf(0, a.hello[:half])).sized(t, 1200))
	sendDatagram(t, client, addr, a.packet(1, cryptoFrameOf(half, a.hello[half:])).sized(t, 600))
	_, err := readDatagram(t, client, 500*time.Millisecond)
	require.Error(t, err, "the proxy completed the ClientHello with an Initial of 600 bytes")

	sendDatagram(t, client, addr, a.packet(2, cryptoFrameOf(half, a.hello[half:])).sized(t, 1200))
	wantInitialBack(t, client, a, 5*time.Second)
}

func TestQUIC_RefusalCodes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		host   string
		protos []string
		code   uint64
	}{
		{"no entry admits the server name", "refused.example.test", []string{"h3"}, 0x170},
		{"no server name and no destination", "", []string{"h3"}, 0x16d},
		{"an offer without a protocol", h3Authority, nil, 0x178},
		{"an offer without h3 to an authority admitted for HTTP", h3Authority, []string{"x-test"}, 0x178},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := quicServer(t, h3Authority)
			client, _ := udpClient(t)
			a := newQUICAttemptOffering(t, quicsniff.Version1, tc.host, tc.protos)
			sendDatagram(t, client, addr, a.first(t))
			assert.Equal(t, tc.code, wantCloseBack(t, client, a, 5*time.Second))
		})
	}
}

func TestQUIC_RefusalAnswersAnAttemptOnce(t *testing.T) {
	addr := quicServer(t, h3Authority)
	client, _ := udpClient(t)
	a := newQUICAttempt(t, quicsniff.Version1, "refused.example.test")
	sendDatagram(t, client, addr, a.first(t))
	wantCloseBack(t, client, a, 5*time.Second)

	sendDatagram(t, client, addr, a.first(t))
	_, err := readDatagram(t, client, 500*time.Millisecond)
	require.Error(t, err, "a retransmitted Initial was answered again")
}

func TestQUIC_TProxyRefusalLeavesFromTheOrigin(t *testing.T) {
	p := testProxy(t)
	p.MustAdd(h3Authority+"/", okHandler)
	wrapper, addr := startTProxyQUIC(t, p, netip.MustParseAddrPort("127.0.0.1:4431"))
	client, _ := udpClient(t)
	a := newQUICAttempt(t, quicsniff.Version1, "refused.example.test")
	sendDatagram(t, client, addr, a.first(t))
	assert.Equal(t, uint64(0x170), wantCloseBack(t, client, a, 5*time.Second))
	assert.Zero(t, wrapper.direct.Load(), "the refusal left from the socket of the proxy")
	select {
	case <-wrapper.replies:
	default:
		t.Fatal("no socket of the origin sent the refusal")
	}
}

func TestQUIC_DatagramThatCannotBeAResetReachesItsUDPEntry(t *testing.T) {
	sink, received := udpSinkOrigin(t)
	p := testProxy(t)
	p.MustAdd(h3Authority+"/", okHandler)
	p.MustAdd[UDP](sink.String(), forwardDatagram)
	addr := startQUICRedirected(t, p, sink)
	pc, err := loopbackUDP()
	require.NoError(t, err)
	conn := dialSharedQUIC(t, clientTransport(t, pc), addr, h3Authority, poolOf(p.cfg.ca))
	require.Equal(t, "ok", h3Get(t, h3Over(t, conn), h3Authority, addr.Port()))

	stun := append([]byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}, randomBytes(t, 52)...)
	short := append([]byte{0x40}, randomBytes(t, quicMinResetSize-2)...)
	for _, dg := range [][]byte{stun, short} {
		_, err = pc.WriteTo(dg, net.UDPAddrFromAddrPort(addr))
		require.NoError(t, err)
	}
	require.Eventually(t, func() bool {
		got := received()
		return slices.Contains(got, string(stun)) && slices.Contains(got, string(short))
	}, 5*time.Second, 5*time.Millisecond, "a datagram that cannot be a stateless reset did not reach the UDP entry")
}

func TestQUIC_UnknownVersionReachesItsUDPEntry(t *testing.T) {
	sink, received := udpSinkOrigin(t)
	p := testProxy(t)
	p.MustAdd[UDP](sink.String(), forwardDatagram)
	addr := startQUICRedirected(t, p, sink)
	client, _ := udpClient(t)
	dg := unknownVersion(t, randomBytes(t, 8), randomBytes(t, 8), 1200)
	sendDatagram(t, client, addr, dg)
	require.Eventually(t, func() bool { return slices.Contains(received(), string(dg)) }, 5*time.Second, 5*time.Millisecond)
	_, err := readDatagram(t, client, 300*time.Millisecond)
	require.Error(t, err, "a datagram a UDP entry admits was answered")
}

func TestQUIC_VersionNegotiationEchoesLongConnectionIDs(t *testing.T) {
	addr := quicServer(t, h3Authority)
	client, _ := udpClient(t)
	dcid, scid := randomBytes(t, 21), randomBytes(t, 255)
	sendDatagram(t, client, addr, unknownVersion(t, dcid, scid, 1200))
	dg, err := readDatagram(t, client, 5*time.Second)
	require.NoError(t, err, "no Version Negotiation came back")
	version, gotDCID, gotSCID, ok := quicsniff.ParseInvariantHeader([]byte(dg))
	require.True(t, ok)
	require.Zero(t, version)
	assert.Equal(t, scid, gotDCID)
	assert.Equal(t, dcid, gotSCID)
}

func TestQUIC_VersionNegotiationAnswersOnlyAnOpening(t *testing.T) {
	addr := quicServer(t, h3Authority)
	client, _ := udpClient(t)
	dcid, scid := randomBytes(t, 8), randomBytes(t, 8)
	vn := unknownVersion(t, dcid, scid, 1200)
	binary.BigEndian.PutUint32(vn[1:5], 0)
	sendDatagram(t, client, addr, unknownVersion(t, dcid, scid, 1199))
	sendDatagram(t, client, addr, vn)
	_, err := readDatagram(t, client, 500*time.Millisecond)
	require.Error(t, err, "a datagram of 1199 bytes or a Version Negotiation packet was answered")
}

var quicVersions = []struct {
	name    string
	version uint32
}{
	{"v1", quicsniff.Version1},
	{"v2", quicsniff.Version2},
}

// quicSockets are the two ways a socket serves redirected datagrams, placing a connection by
// its server name, and by an exact destination it replies from under TPROXY.
var quicSockets = []struct {
	start func(t *testing.T) (*Proxy, netip.AddrPort)
	name  string
}{
	{quicHTTPServer, "socket"},
	{func(t *testing.T) (*Proxy, netip.AddrPort) {
		p := testProxy(t)
		p.MustAdd(h3Authority+"/", okHandler)
		_, addr := startTProxyQUIC(t, p, netip.MustParseAddrPort("127.0.0.1:4431"))
		return p, addr
	}, "TPROXY"},
}

// quicServer starts a proxy terminating HTTP/3 for hosts on a socket with no original
// destination, so a datagram no connection claims has nowhere to go.
func quicServer(t *testing.T, hosts ...string) netip.AddrPort {
	t.Helper()
	p := testProxy(t)
	for _, host := range hosts {
		p.MustAdd(host+"/", okHandler)
	}
	return startQUIC(t, p)
}

func quicHTTPServer(t *testing.T) (*Proxy, netip.AddrPort) {
	t.Helper()
	p := testProxy(t)
	p.MustAdd(h3Authority+"/", okHandler)
	return p, startQUIC(t, p)
}

// clientTransport is a quic-go client transport on pc, closed with pc at the end of the test.
func clientTransport(t *testing.T, pc net.PacketConn) *quic.Transport {
	t.Helper()
	tr := &quic.Transport{Conn: pc}
	t.Cleanup(func() { _ = tr.Close(); _ = pc.Close() })
	return tr
}

func h3Over(t *testing.T, conn *quic.Conn) *http3.ClientConn {
	t.Helper()
	h3 := &http3.Transport{}
	t.Cleanup(func() { _ = h3.Close() })
	return h3.NewClientConn(conn)
}

// wantHandshake sends a conformant first Initial of version and wants the proxy's Initial back
// in the same version.
func wantHandshake(t *testing.T, version uint32) {
	t.Helper()
	addr := quicServer(t, h3Authority)
	client, _ := udpClient(t)
	a := newQUICAttempt(t, version, h3Authority)
	sendDatagram(t, client, addr, a.first(t))
	wantInitialBack(t, client, a, 5*time.Second)
}

// wantInitialBack wants the attempt answered with an Initial that has a CRYPTO frame, or with
// the Retry RFC 9000 section 8.1.2 permits.
func wantInitialBack(t *testing.T, client *net.UDPConn, a *quicAttempt, wait time.Duration) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for {
		s, err := readDatagram(t, client, time.Until(deadline))
		require.NoError(t, err, "no Initial came back")
		dg := []byte(s)
		h, ok := parseQUICLong(dg)
		if !ok {
			continue
		}
		require.Equal(t, a.version, h.version, "the answer is in another version")
		require.Equal(t, a.scid, h.dcid)
		if h.isRetry() {
			return
		}
		require.True(t, h.isInitial(), "the first answer is no Initial")
		frames, ok := openServerInitial(a.version, a.dcid, dg)
		require.True(t, ok, "the Initial does not open with the server keys")
		c, ok := initialFrames(frames)
		require.True(t, ok, "the frames of the Initial do not parse")
		require.Contains(t, c.types, uint64(0x06), "the Initial has no CRYPTO frame")
		return
	}
}

// quicAnswer sends the first datagram of a to the proxy through pc and returns the frames of
// the Initial it answers with.
func quicAnswer(t *testing.T, pc net.PacketConn, to net.Addr, a *quicAttempt) initialContent {
	t.Helper()
	_, err := pc.WriteTo(a.first(t), to)
	require.NoError(t, err)
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 2048)
	for {
		n, _, err := pc.ReadFrom(buf)
		require.NoError(t, err, "no Initial came back")
		frames, ok := openServerInitial(a.version, a.dcid, buf[:n])
		if !ok {
			continue
		}
		c, ok := initialFrames(frames)
		require.True(t, ok, "the frames of the Initial do not parse")
		return c
	}
}

// wantCloseBack wants the attempt answered with an Initial with a CONNECTION_CLOSE, and returns
// its error code.
func wantCloseBack(t *testing.T, client *net.UDPConn, a *quicAttempt, wait time.Duration) uint64 {
	t.Helper()
	deadline := time.Now().Add(wait)
	for {
		s, err := readDatagram(t, client, time.Until(deadline))
		require.NoError(t, err, "no CONNECTION_CLOSE came back")
		dg := []byte(s)
		h, ok := parseQUICLong(dg)
		if !ok {
			continue
		}
		require.Equal(t, a.version, h.version, "the answer is in another version")
		require.Equal(t, a.scid, h.dcid)
		frames, ok := openServerInitial(a.version, a.dcid, dg)
		require.True(t, ok, "the answer is no Initial protected with the server keys")
		c, ok := initialFrames(frames)
		require.True(t, ok, "the frames of the Initial do not parse")
		require.Contains(t, c.types, uint64(0x1c), "the Initial has no CONNECTION_CLOSE frame")
		return c.closeCode
	}
}

// unknownVersion is a long header of a version no QUIC implementation uses, padded to n bytes.
func unknownVersion(t *testing.T, dcid, scid []byte, n int) []byte {
	t.Helper()
	b := []byte{0xc0}
	b = binary.BigEndian.AppendUint32(b, 0x1a2a3a4a)
	b = append(b, byte(len(dcid)))
	b = append(b, dcid...)
	b = append(b, byte(len(scid)))
	b = append(b, scid...)
	return append(b, randomBytes(t, n-len(b))...)
}

// wantDropped sends datagram to a destination a UDP entry admits, then a datagram that is no
// QUIC packet, and wants the origin to receive the second alone.
func wantDropped(t *testing.T, datagram []byte) {
	t.Helper()
	sink, received := udpSinkOrigin(t)
	p := testProxy(t)
	p.MustAdd(h3Authority+"/", okHandler)
	p.MustAdd[UDP](sink.String(), forwardDatagram)
	addr := startQUICRedirected(t, p, sink)

	client, _ := udpClient(t)
	sendDatagram(t, client, addr, datagram)
	sendDatagram(t, client, addr, []byte("edge sentinel"))
	require.Eventually(t, func() bool { return slices.Contains(received(), "edge sentinel") }, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, 1, len(received()), "the QUIC packet reached the origin")
}

func sendDatagram(t *testing.T, conn *net.UDPConn, to netip.AddrPort, b []byte) {
	t.Helper()
	_, err := conn.WriteToUDPAddrPort(b, to)
	require.NoError(t, err)
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

// QUIC v1 long packet types, RFC 9000 section 17.2.
const (
	quicTypeInitial = iota
	quicType0RTT
	quicTypeHandshake
)

// quicPacket is a long header packet protected with the client Initial keys of its
// destination connection ID, RFC 9001 section 5, whatever its type.
type quicPacket struct {
	dcid    []byte
	scid    []byte
	frames  []byte
	version uint32
	pn      uint32
	typ     int
}

func (p quicPacket) header(length int) []byte {
	typ := byte(p.typ)
	if p.version == quicsniff.Version2 {
		// RFC 9369 section 3.2 rotates the type bits by one.
		typ = byte(p.typ+1) % 4
	}
	hdr := []byte{0xc0 | typ<<4 | 3}
	hdr = binary.BigEndian.AppendUint32(hdr, p.version)
	hdr = append(hdr, byte(len(p.dcid)))
	hdr = append(hdr, p.dcid...)
	hdr = append(hdr, byte(len(p.scid)))
	hdr = append(hdr, p.scid...)
	if p.typ == quicTypeInitial {
		hdr = append(hdr, 0)
	}
	hdr = quicvarint.AppendWithLen(hdr, uint64(length), 2)
	return binary.BigEndian.AppendUint32(hdr, p.pn)
}

// sized pads the frames with PADDING so the protected packet is n bytes.
func (p quicPacket) sized(t *testing.T, n int) []byte {
	t.Helper()
	pad := n - len(p.header(0)) - len(p.frames) - 16
	require.GreaterOrEqual(t, pad, 0, "the frames do not fit in %d bytes", n)
	p.frames = append(slices.Clone(p.frames), make([]byte, pad)...)
	return p.protect(t)
}

func (p quicPacket) protect(t *testing.T) []byte {
	t.Helper()
	key, iv, hp := quicInitialKeys(p.version, p.dcid, "client in")
	hdr := p.header(4 + len(p.frames) + 16)
	pnOffset := len(hdr) - 4

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := slices.Clone(iv)
	for i := range 4 {
		nonce[len(nonce)-1-i] ^= byte(p.pn >> (8 * i))
	}
	out := aead.Seal(slices.Clone(hdr), nonce, p.frames, hdr)

	block, err = aes.NewCipher(hp)
	require.NoError(t, err)
	var mask [16]byte
	block.Encrypt(mask[:], out[pnOffset+4:pnOffset+20])
	out[0] ^= mask[0] & 0x0f
	for i := range 4 {
		out[pnOffset+i] ^= mask[1+i]
	}
	return out
}

func quicInitialKeys(version uint32, dcid []byte, side string) (key, iv, hp []byte) {
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	prefix := "quic "
	if version == quicsniff.Version2 {
		salt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
		prefix = "quicv2 "
	}
	expand := func(secret []byte, label string, n int) []byte {
		full := "tls13 " + label
		info := binary.BigEndian.AppendUint16(nil, uint16(n))
		info = append(info, byte(len(full)))
		info = append(info, full...)
		info = append(info, 0)
		out, err := hkdf.Expand(sha256.New, secret, string(info), n)
		if err != nil {
			panic(err)
		}
		return out
	}
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		panic(err)
	}
	secret := expand(initial, side, 32)
	return expand(secret, prefix+"key", 16), expand(secret, prefix+"iv", 12), expand(secret, prefix+"hp", 16)
}

func cryptoFrameOf(offset int, data []byte) []byte {
	b := quicvarint.Append([]byte{0x06}, uint64(offset))
	b = quicvarint.Append(b, uint64(len(data)))
	return append(b, data...)
}

// retryPacket is a long header of type Retry, RFC 9000 section 17.2.5, which only a server
// sends.
func retryPacket(t *testing.T) []byte {
	t.Helper()
	b := []byte{0xf0}
	b = binary.BigEndian.AppendUint32(b, quicsniff.Version1)
	b = append(b, 8)
	b = append(b, randomBytes(t, 8)...)
	b = append(b, 8)
	b = append(b, randomBytes(t, 8)...)
	return append(b, randomBytes(t, 48)...)
}

// quicAttempt is the opening of one connection, its connection IDs and the ClientHello Go's
// TLS stack writes for it.
type quicAttempt struct {
	dcid    []byte
	scid    []byte
	hello   []byte
	version uint32
}

func newQUICAttempt(t *testing.T, version uint32, name string) *quicAttempt {
	t.Helper()
	return newQUICAttemptOffering(t, version, name, []string{"h3"})
}

func newQUICAttemptOffering(t *testing.T, version uint32, name string, protos []string) *quicAttempt {
	t.Helper()
	return newQUICAttemptWith(t, version, &tls.Config{
		ServerName:         name,
		InsecureSkipVerify: name == "",
		NextProtos:         protos,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519},
	})
}

// newQUICAttemptWith is an attempt whose ClientHello Go's TLS stack writes under cfg.
func newQUICAttemptWith(t *testing.T, version uint32, cfg *tls.Config) *quicAttempt {
	t.Helper()
	a := &quicAttempt{version: version, dcid: randomBytes(t, 8), scid: randomBytes(t, 8)}

	qc := tls.QUICClient(&tls.QUICConfig{TLSConfig: cfg})
	params := quicvarint.Append(nil, 0x0f)
	params = quicvarint.Append(params, uint64(len(a.scid)))
	params = append(params, a.scid...)
	qc.SetTransportParameters(params)
	require.NoError(t, qc.Start(t.Context()))
	defer func() { _ = qc.Close() }()
	for {
		ev := qc.NextEvent()
		if ev.Kind == tls.QUICNoEvent {
			break
		}
		if ev.Kind == tls.QUICWriteData && ev.Level == tls.QUICEncryptionLevelInitial {
			a.hello = append(a.hello, ev.Data...)
		}
	}
	require.NotEmpty(t, a.hello)
	return a
}

func (a *quicAttempt) packet(pn uint32, frames []byte) quicPacket {
	return quicPacket{version: a.version, typ: quicTypeInitial, dcid: a.dcid, scid: a.scid, pn: pn, frames: frames}
}

// first is the conformant first datagram of the attempt, its complete ClientHello in one Initial
// padded to 1200 bytes.
func (a *quicAttempt) first(t *testing.T) []byte {
	t.Helper()
	return a.packet(0, cryptoFrameOf(0, a.hello)).sized(t, 1200)
}

type quicLong struct {
	dcid    []byte
	scid    []byte
	version uint32
	first   byte
}

func parseQUICLong(dg []byte) (quicLong, bool) {
	version, dcid, scid, ok := quicsniff.ParseLongHeader(dg)
	if !ok {
		return quicLong{}, false
	}
	return quicLong{first: dg[0], version: version, dcid: dcid, scid: scid}, true
}

func (h quicLong) isInitial() bool { return quicsniff.IsInitial(h.first, h.version) }

// isRetry reports a Retry packet, whose type bits RFC 9369 section 3.2 rotates in QUIC v2.
func (h quicLong) isRetry() bool {
	typ := h.first >> 4 & 3
	if h.version == quicsniff.Version2 {
		return typ == 0
	}
	return typ == 3
}

// openServerInitial removes the protection of the Initial opening datagram with the server
// keys of odcid, and returns its frames.
func openServerInitial(version uint32, odcid, dg []byte) ([]byte, bool) {
	h, ok := parseQUICLong(dg)
	if !ok || !h.isInitial() || h.version != version {
		return nil, false
	}
	pos := 1 + 4 + 1 + len(h.dcid) + 1 + len(h.scid)
	token, n, err := quicvarint.Parse(dg[pos:])
	if err != nil || uint64(len(dg)-pos-n) < token {
		return nil, false
	}
	pos += n + int(token)
	length, n, err := quicvarint.Parse(dg[pos:])
	if err != nil || uint64(len(dg)-pos-n) < length || length < 20 {
		return nil, false
	}
	pos += n
	end := pos + int(length)

	key, iv, hp := quicInitialKeys(version, odcid, "server in")
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, false
	}
	var mask [16]byte
	block.Encrypt(mask[:], dg[pos+4:pos+20])
	hdr := slices.Clone(dg[:pos])
	hdr[0] ^= mask[0] & 0x0f
	pnLen := int(hdr[0]&0x03) + 1
	var pn uint64
	for i := range pnLen {
		b := dg[pos+i] ^ mask[1+i]
		hdr = append(hdr, b)
		pn = pn<<8 | uint64(b)
	}
	block, err = aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	nonce := slices.Clone(iv)
	binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(nonce[4:])^pn)
	frames, err := aead.Open(nil, nonce, dg[pos+pnLen:end], hdr)
	return frames, err == nil
}

type initialContent struct {
	types []uint64
	// acked lists the smallest and largest packet number of each ACK range.
	acked     [][2]uint64
	closeCode uint64
}

func (c initialContent) acks(pn uint64) bool {
	for _, r := range c.acked {
		if r[0] <= pn && pn <= r[1] {
			return true
		}
	}
	return false
}

// initialFrames walks the frames an Initial may contain, with ok cleared when a frame does not
// parse.
func initialFrames(frames []byte) (c initialContent, ok bool) {
	varint := func() (uint64, bool) {
		v, n, err := quicvarint.Parse(frames)
		if err != nil {
			return 0, false
		}
		frames = frames[n:]
		return v, true
	}
	skip := func(n uint64) bool {
		for range n {
			if _, ok := varint(); !ok {
				return false
			}
		}
		return true
	}
	for len(frames) > 0 {
		typ, ok := varint()
		if !ok {
			return c, false
		}
		c.types = append(c.types, typ)
		switch typ {
		case 0x00, 0x01:
		case 0x02, 0x03:
			largest, ok := varint()
			if !ok || !skip(1) {
				return c, false
			}
			ranges, ok := varint()
			if !ok {
				return c, false
			}
			first, ok := varint()
			if !ok || first > largest {
				return c, false
			}
			lo := largest - first
			c.acked = append(c.acked, [2]uint64{lo, largest})
			for range ranges {
				gap, okGap := varint()
				length, okLen := varint()
				if !okGap || !okLen || lo < gap+2 || length > lo-gap-2 {
					return c, false
				}
				hi := lo - gap - 2
				lo = hi - length
				c.acked = append(c.acked, [2]uint64{lo, hi})
			}
			if typ == 0x03 && !skip(3) {
				return c, false
			}
		case 0x06:
			if !skip(1) {
				return c, false
			}
			length, ok := varint()
			if !ok || length > uint64(len(frames)) {
				return c, false
			}
			frames = frames[length:]
		case 0x1c:
			code, ok := varint()
			c.closeCode = code
			return c, ok
		default:
			return c, false
		}
	}
	return c, true
}

// serveDemux serves a socket of p through a demultiplexer the test owns, so the test may end
// it on its own.
func serveDemux(t *testing.T, p *Proxy) (*quicDemux, netip.AddrPort) {
	t.Helper()
	return serveDemuxAt(t, p, "127.0.0.1:0")
}

func serveDemuxAt(t *testing.T, p *Proxy, addr string) (*quicDemux, netip.AddrPort) {
	t.Helper()
	pc, err := net.ListenPacket("udp", addr)
	require.NoError(t, err)
	return serveDemuxOn(t, p, pc)
}

func serveDemuxOn(t *testing.T, p *Proxy, pc net.PacketConn) (*quicDemux, netip.AddrPort) {
	t.Helper()
	d, err := newQUICDemux(p, pc)
	require.NoError(t, err)
	go func() { _ = d.run() }()
	t.Cleanup(d.close)
	return d, netip.MustParseAddrPort(pc.LocalAddr().String())
}

// orphan is a demultiplexer with the keys of a proxy's terminating stacks and no stack,
// standing in for a proxy restarted with the same certificate authority, and a raw client in
// front of it.
type orphan struct {
	d      *quicDemux
	client *net.UDPConn
	addr   netip.AddrPort
}

func newOrphan(t *testing.T) *orphan {
	t.Helper()
	return newOrphanAt(t, testProxy(t), "127.0.0.1:0")
}

func newOrphanAt(t *testing.T, p *Proxy, addr string) *orphan {
	t.Helper()
	d, bound := serveDemuxAt(t, p, addr)
	require.NoError(t, d.startTermination())
	client, _ := udpClient(t)
	return &orphan{d: d, addr: bound, client: client}
}

func (o *orphan) mint(t *testing.T) []byte {
	t.Helper()
	cid, err := o.d.tag.Load().GenerateConnectionID()
	require.NoError(t, err)
	return cid.Bytes()
}

func (o *orphan) trigger(t *testing.T, cid []byte, n int) []byte {
	t.Helper()
	b := randomBytes(t, n)
	b[0] = b[0]&0x3f | 0x40
	copy(b[1:], cid)
	return b
}

func (o *orphan) send(t *testing.T, b []byte) {
	t.Helper()
	sendDatagram(t, o.client, o.addr, b)
}

func (o *orphan) read(t *testing.T) []byte {
	t.Helper()
	dg, err := readDatagram(t, o.client, 3*time.Second)
	require.NoError(t, err, "no stateless reset came back")
	return []byte(dg)
}

// answers reports whether reset ends in the token of cid. The expected token repeats the
// computation of the demultiplexer, so it only matches each answer to its trigger.
func (o *orphan) answers(reset, cid []byte) bool {
	return len(reset) >= 17 && bytes.HasSuffix(reset, resetTokenOf(o.d.socketResetKey[:], cid))
}

// resetTokenOf is the stateless reset token of cid under key, the HMAC of RFC 9000 section
// 10.3.2 as quic-go and the demultiplexer compute it.
func resetTokenOf(key, cid []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(cid)
	return mac.Sum(nil)[:16]
}

// resets sends triggers, then a packet of 1200 bytes on a fresh connection ID, and returns
// every datagram that came back before the answer to that last one.
func (o *orphan) resets(t *testing.T, triggers ...[]byte) [][]byte {
	t.Helper()
	for _, b := range triggers {
		o.send(t, b)
	}
	last := o.mint(t)
	o.send(t, o.trigger(t, last, 1200))
	var out [][]byte
	for {
		dg := o.read(t)
		if o.answers(dg, last) {
			return out
		}
		out = append(out, dg)
	}
}

// oracleTwoSockets serves two sockets with one proxy, the victim reaching the first and the
// attacker the other.
func oracleTwoSockets(t *testing.T) ([]byte, quic.StatelessResetKey, net.PacketConn, net.Addr) {
	p, victim := quicHTTPServer(t)
	other := startQUIC(t, p)
	cid := oracleVictim(t, p, victim)
	warmQUIC(t, p, other, nil)
	attacker, _ := udpClient(t)
	key := stackResetKey(t, p, func(d *quicDemux, _ interceptKey) bool { return addrPort(d.pc.LocalAddr()) == victim })
	return cid, key, attacker, net.UDPAddrFromAddrPort(other)
}

// oracleTwoOrigins serves one TPROXY socket, the victim reaching a first origin and the
// attacker a second one.
func oracleTwoOrigins(t *testing.T) ([]byte, quic.StatelessResetKey, net.PacketConn, net.Addr) {
	p := testProxy(t)
	p.MustAdd(h3Authority+"/", okHandler)
	first, second := netip.MustParseAddrPort("127.0.0.1:4431"), netip.MustParseAddrPort("127.0.0.1:4432")
	wrapper, addr := startTProxyQUIC(t, p, first)
	cid := oracleVictim(t, p, addr)
	attacker, _ := udpClient(t)
	wrapper.perClient.Store(attacker.LocalAddr().String(), second)
	warmQUIC(t, p, addr, func(warm net.Addr) { wrapper.perClient.Store(warm.String(), second) })
	key := stackResetKey(t, p, func(_ *quicDemux, key interceptKey) bool { return key.origin == first })
	return cid, key, attacker, net.UDPAddrFromAddrPort(addr)
}

// oracleDatagramOrigin serves one TPROXY socket, the victim reaching a first origin and the
// attacker relaying a datagram to a UDP origin, so that origin has a reply socket and no stack.
func oracleDatagramOrigin(t *testing.T) ([]byte, quic.StatelessResetKey, net.PacketConn, net.Addr) {
	echo := udpEchoOrigin(t)
	p := testProxy(t)
	p.MustAdd(h3Authority+"/", okHandler)
	p.MustAdd[UDP](echo.String(), forwardDatagram)
	first := netip.MustParseAddrPort("127.0.0.1:4431")
	wrapper, addr := startTProxyQUIC(t, p, first)
	cid := oracleVictim(t, p, addr)
	attacker, _ := udpClient(t)
	wrapper.perClient.Store(attacker.LocalAddr().String(), echo)
	sendDatagram(t, attacker, addr, []byte("warm-up"))
	_, err := readDatagram(t, attacker, 3*time.Second)
	require.NoError(t, err, "the datagram flow did not open")
	key := stackResetKey(t, p, func(_ *quicDemux, key interceptKey) bool { return key.origin == first })
	return cid, key, attacker, net.UDPAddrFromAddrPort(addr)
}

// oracleTwoTunnels opens two CONNECT-UDP tunnels to one target on an HTTP/3 front, the victim
// reaching the target through the first and the attacker writing into the second.
func oracleTwoTunnels(t *testing.T) ([]byte, quic.StatelessResetKey, net.PacketConn, net.Addr) {
	p, proxyCA, front, origin := masqueProxy(t)
	cc := masqueClient(t, front, proxyCA)
	target := net.JoinHostPort(h3Authority, strconv.Itoa(int(origin.Port())))
	victim, _, err := openTunnel(t, cc, front, target, nil)
	require.NoError(t, err)
	rec := &cidConn{PacketConn: victim}
	inner, _ := innerH3(t, rec, origin, h3Authority, proxyCA)
	body, err := getThrough(inner, "https://"+target+"/echo")
	require.NoError(t, err)
	require.Contains(t, body, "path=/echo")
	attacker, _, err := openTunnel(t, cc, front, target, nil)
	require.NoError(t, err)
	key := stackResetKey(t, p, func(_ *quicDemux, key interceptKey) bool { return key.tunnel != nil })
	return rec.lastWritten(), key, attacker, nil
}

// stackResetKey is the stateless reset key of the one terminating stack of p that match
// selects.
func stackResetKey(t *testing.T, p *Proxy, match func(d *quicDemux, key interceptKey) bool) quic.StatelessResetKey {
	t.Helper()
	p.srv.mu.Lock()
	demuxes := slices.Collect(maps.Keys(p.srv.quics))
	p.srv.mu.Unlock()
	var keys []quic.StatelessResetKey
	for _, d := range demuxes {
		d.mu.Lock()
		for key, it := range d.intercepts {
			if match(d, key) {
				keys = append(keys, it.resetKey)
			}
		}
		d.mu.Unlock()
	}
	require.Len(t, keys, 1, "no single stack terminates the victim")
	return keys[0]
}

// oracleVictim opens a connection to addr and returns the destination connection ID of the
// last short header packet it wrote.
func oracleVictim(t *testing.T, p *Proxy, addr netip.AddrPort) []byte {
	t.Helper()
	pc, err := loopbackUDP()
	require.NoError(t, err)
	rec := &cidConn{PacketConn: pc}
	conn := dialSharedQUIC(t, clientTransport(t, rec), addr, h3Authority, poolOf(p.cfg.ca))
	require.Equal(t, "ok", h3Get(t, h3Over(t, conn), h3Authority, addr.Port()))
	return rec.lastWritten()
}

// warmQUIC opens a connection to addr from a fresh socket, after placed has seen its address.
func warmQUIC(t *testing.T, p *Proxy, addr netip.AddrPort, placed func(net.Addr)) {
	t.Helper()
	pc, err := loopbackUDP()
	require.NoError(t, err)
	if placed != nil {
		placed(pc.LocalAddr())
	}
	conn := dialSharedQUIC(t, clientTransport(t, pc), addr, h3Authority, poolOf(p.cfg.ca))
	h3Get(t, h3Over(t, conn), h3Authority, addr.Port())
}

// cidConn records the connection IDs a quic-go client uses on pc, the source connection ID of
// its first long header and the destination connection ID of the last short header it wrote
// and of the last it read, both 8 bytes.
type cidConn struct {
	net.PacketConn
	first   atomic.Pointer[[]byte]
	written atomic.Pointer[[]byte]
	read    atomic.Pointer[[]byte]
}

func (c *cidConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil && n > 9 && b[0]&0x80 == 0 {
		cid := bytes.Clone(b[1:9])
		c.read.Store(&cid)
	}
	return n, addr, err
}

func (c *cidConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(b) > 9 && b[0]&0x80 == 0 {
		cid := bytes.Clone(b[1:9])
		c.written.Store(&cid)
	} else if _, _, scid, ok := quicsniff.ParseLongHeader(b); ok && c.first.Load() == nil {
		scid = bytes.Clone(scid)
		c.first.Store(&scid)
	}
	return c.PacketConn.WriteTo(b, addr)
}

func (c *cidConn) firstSource() []byte { return loadBytes(&c.first) }

func (c *cidConn) lastWritten() []byte { return loadBytes(&c.written) }

func (c *cidConn) lastRead() []byte { return loadBytes(&c.read) }

func loadBytes(p *atomic.Pointer[[]byte]) []byte {
	if b := p.Load(); b != nil {
		return *b
	}
	return nil
}

// muteConn is a socket that drops what it sends once muted, as a process that crashed does.
type muteConn struct {
	net.PacketConn
	muted atomic.Bool
}

func (c *muteConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.muted.Load() {
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, addr)
}

// pathConn is a client socket that drops what it receives while blocked.
type pathConn struct {
	net.PacketConn
	blocked atomic.Bool
}

func (c *pathConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil || !c.blocked.Load() {
			return n, addr, err
		}
	}
}

// movingConn is the socket of a quic-go client whose path the test moves. rebind sends from a
// second port and drops what still arrives on the first, as a NAT allocating a new mapping
// does.
type movingConn struct {
	socks    [2]*net.UDPConn
	in       chan movingPacket
	kick     chan struct{}
	done     chan struct{}
	deadline atomic.Pointer[time.Time]
	arrived  atomic.Int64
	once     sync.Once
	rebound  atomic.Bool
}

type movingPacket struct {
	addr net.Addr
	b    []byte
}

func newMovingConn(t *testing.T) *movingConn {
	t.Helper()
	c := &movingConn{in: make(chan movingPacket, 64), kick: make(chan struct{}, 1), done: make(chan struct{})}
	for i := range c.socks {
		s, err := loopbackUDP()
		require.NoError(t, err)
		c.socks[i] = s
	}
	t.Cleanup(func() { _ = c.Close() })
	for i, s := range c.socks {
		go c.readFrom(i, s)
	}
	return c
}

func (c *movingConn) readFrom(i int, s *net.UDPConn) {
	buf := make([]byte, maxUDPPayload)
	for {
		n, addr, err := s.ReadFrom(buf)
		if err != nil {
			return
		}
		if i == 0 && c.rebound.Load() {
			continue
		}
		if i == 1 {
			c.arrived.Add(1)
		}
		select {
		case c.in <- movingPacket{addr: addr, b: bytes.Clone(buf[:n])}:
		case <-c.done:
			return
		}
	}
}

func (c *movingConn) rebind() { c.rebound.Store(true) }

func (c *movingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err, again := c.readOnce(b)
		if !again {
			return n, addr, err
		}
	}
}

// readOnce waits for a packet until the deadline, and reports again when the deadline moved
// meanwhile.
func (c *movingConn) readOnce(b []byte) (n int, addr net.Addr, err error, again bool) {
	var timeout <-chan time.Time
	if dl := c.deadline.Load(); dl != nil && !dl.IsZero() {
		timer := time.NewTimer(time.Until(*dl))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case pkt := <-c.in:
		return copy(b, pkt.b), pkt.addr, nil, false
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded, false
	case <-c.kick:
		return 0, nil, nil, true
	case <-c.done:
		return 0, nil, net.ErrClosed, false
	}
}

func (c *movingConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	s := c.socks[0]
	if c.rebound.Load() {
		s = c.socks[1]
	}
	return s.WriteTo(b, addr)
}

func (c *movingConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		for _, s := range c.socks {
			_ = s.Close()
		}
	})
	return nil
}

func (c *movingConn) LocalAddr() net.Addr { return c.socks[0].LocalAddr() }

func (c *movingConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *movingConn) SetReadDeadline(t time.Time) error {
	c.deadline.Store(&t)
	select {
	case c.kick <- struct{}{}:
	default:
	}
	return nil
}

func (c *movingConn) SetWriteDeadline(time.Time) error { return nil }

func TestQUICResetSecret_KeyIsHKDFExpand(t *testing.T) {
	secret := quicResetSecret(randomBytes(t, 32))
	for _, id := range [][]byte{randomBytes(t, 18), randomBytes(t, quicResetIDSize)} {
		want, err := hkdf.Expand(sha256.New, secret[:], quicResetLabel+string(id), 32)
		require.NoError(t, err)
		key := secret.key(id)
		assert.Equal(t, want, key[:])
	}
	origin := netip.MustParseAddrPort("192.0.2.1:443")
	assert.Zero(t, testing.AllocsPerRun(100, func() { _ = secret.addrKey(origin) }))
}

func BenchmarkStatelessResetKey(b *testing.B) {
	ca, err := GenerateCA()
	if err != nil {
		b.Fatal(err)
	}
	_, secret, err := quicInterceptKeys(ca)
	if err != nil {
		b.Fatal(err)
	}
	origin := netip.MustParseAddrPort("192.0.2.1:443")
	b.ReportAllocs()
	for b.Loop() {
		_ = secret.addrKey(origin)
	}
}

func TestQUICDemux_DatagramFromItsOwnSocketIsDropped(t *testing.T) {
	logger, dropped := recordLogger("the proxy sent it upstream")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	self := pc.LocalAddr().String()
	var dials, handled atomic.Int32
	tr := DefaultTransport()
	// A redirect that also catches the datagrams of the proxy and reports every one headed to dst.
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if dials.Add(1) > 8 {
			return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, self)
	}
	dst := netip.MustParseAddrPort("192.0.2.1:53")
	p := testProxy(t, WithTransport(tr), WithLogger(logger))
	p.MustAdd[UDP](dst.String(), func(c *DatagramCtx) error {
		handled.Add(1)
		return c.Forward()
	})
	go func() { _ = p.ServeTransparentUDP(fixedOriginPacketConn{PacketConn: pc, origin: dst}) }()
	t.Cleanup(func() { _ = p.Close() })

	client, err := loopbackUDP()
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	_, err = client.WriteTo([]byte("ping"), pc.LocalAddr())
	require.NoError(t, err)
	select {
	case <-dropped:
	case <-time.After(10 * time.Second):
		t.Fatal("the proxy did not drop the datagram it sent itself")
	}
	assert.Equal(t, int32(1), handled.Load(), "the datagram came back to the proxy")
	assert.Equal(t, int32(1), dials.Load())
}

func TestQUICDemux_InitialFromItsOwnSocketIsRefused(t *testing.T) {
	logger, refused := recordLogger("the proxy opened it upstream")
	p := testProxy(t, WithLogger(logger))
	p.MustAdd("origin.test/*{any}", okHandler)
	addr := startQUICRedirected(t, p, netip.MustParseAddrPort("192.0.2.1:443"))

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	_, err := p.srv.fwd.up.dialQUIC(ctx, addr.String(),
		&tls.Config{ServerName: "origin.test", NextProtos: []string{http3.NextProtoH3}, MinVersion: tls.VersionTLS13}, &quic.Config{})
	te, ok := errors.AsType[*quic.TransportError](err)
	require.True(t, ok, "the dial ended on %v", err)
	assert.Equal(t, quic.ConnectionRefused, te.ErrorCode)
	assert.True(t, te.Remote)
	select {
	case <-refused:
	default:
		t.Fatal("the refusal was not logged")
	}
}
