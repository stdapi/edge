// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package quicsniff_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fox-toolkit/edge/internal/quicsniff"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureInitials starts a QUIC dial that will never be answered and returns the datagrams
// the client sent, which is where its ClientHello lives.
func captureInitials(t testing.TB, serverName string, tlsCfg *tls.Config) [][]byte {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()

	cfg := tlsCfg.Clone()
	cfg.ServerName = serverName
	cfg.InsecureSkipVerify = true

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	go func() {
		conn, err := quic.DialAddr(ctx, pc.LocalAddr().String(), cfg, &quic.Config{HandshakeIdleTimeout: time.Second})
		if err == nil {
			_ = conn.CloseWithError(0, "")
		}
	}()

	var out [][]byte
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		require.NoError(t, pc.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
		buf := make([]byte, 2048)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
				break
			}
			break
		}
		out = append(out, buf[:n])
		if len(out) >= 8 {
			break
		}
	}
	require.NotEmpty(t, out, "the client sent no datagram")
	return out
}

// serverNameFrom parses the SNI out of a raw ClientHello handshake message, so the test
// checks the reassembled bytes rather than trusting the reassembler's own view of them.
func serverNameFrom(t *testing.T, hello []byte) string {
	t.Helper()

	// Wrap the handshake message in a TLS record so a TLS server will parse it.
	record := make([]byte, 0, 5+len(hello))
	record = append(record, 0x16, 0x03, 0x01)
	record = binary.BigEndian.AppendUint16(record, uint16(len(hello)))
	record = append(record, hello...)

	var name string
	stop := errors.New("captured")
	_ = tls.Server(&replayOnce{b: record}, &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			name = chi.ServerName
			return nil, stop
		},
	}).Handshake()
	return name
}

type replayOnce struct {
	b   []byte
	off int
}

func (c *replayOnce) Read(b []byte) (int, error) {
	if c.off >= len(c.b) {
		return 0, net.ErrClosed
	}
	n := copy(b, c.b[c.off:])
	c.off += n
	return n, nil
}

func (c *replayOnce) Write(b []byte) (int, error)      { return len(b), nil }
func (c *replayOnce) Close() error                     { return nil }
func (c *replayOnce) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *replayOnce) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *replayOnce) SetDeadline(time.Time) error      { return nil }
func (c *replayOnce) SetReadDeadline(time.Time) error  { return nil }
func (c *replayOnce) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "test" }
func (dummyAddr) String() string  { return "test" }

func TestReassembler_ReadsServerName(t *testing.T) {
	datagrams := captureInitials(t, "api.example.test", &tls.Config{NextProtos: []string{"h3"}})

	r := quicsniff.New()
	var hello []byte
	for _, dg := range datagrams {
		out, err := r.Feed(dg)
		if err != nil {
			require.ErrorIs(t, err, quicsniff.ErrNotInitial, "unexpected error on datagram")
			continue
		}
		if out != nil {
			hello = out
			break
		}
	}

	require.NotNil(t, hello, "the ClientHello was never completed")
	assert.Equal(t, "api.example.test", serverNameFrom(t, hello))
}

func TestReassembler_LargeClientHelloSpansPackets(t *testing.T) {
	// A long list of ALPN identifiers pushes the ClientHello past what one Initial packet
	// can carry, which is the case reassembly exists for.
	protos := make([]string, 0, 64)
	for i := range 64 {
		protos = append(protos, "padding-protocol-identifier-"+string(rune('a'+i%26))+"-"+string(rune('0'+i%10)))
	}
	protos = append(protos, "h3")

	datagrams := captureInitials(t, "big.example.test", &tls.Config{NextProtos: protos})

	r := quicsniff.New()
	var hello []byte
	for _, dg := range datagrams {
		out, err := r.Feed(dg)
		if err != nil && !errors.Is(err, quicsniff.ErrNotInitial) {
			t.Fatalf("feed: %v", err)
		}
		if out != nil {
			hello = out
			break
		}
	}

	require.NotNil(t, hello)
	assert.Equal(t, "big.example.test", serverNameFrom(t, hello))
	t.Logf("ClientHello of %d bytes reassembled from %d datagrams", len(hello), len(datagrams))
}

func TestReassembler_RejectsGarbage(t *testing.T) {
	r := quicsniff.New()

	_, err := r.Feed([]byte{0x40, 0x00, 0x00})
	assert.ErrorIs(t, err, quicsniff.ErrNotInitial, "a short header packet carries no Initial")

	// A long header naming a version whose keys are unknown.
	dg := make([]byte, 64)
	dg[0] = 0xc0
	binary.BigEndian.PutUint32(dg[1:5], 0xdeadbeef)
	_, err = quicsniff.New().Feed(dg)
	assert.ErrorIs(t, err, quicsniff.ErrUnsupportedVersion)
}

func TestParseLongHeader(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	scid := []byte{9, 10, 11, 12}
	packet := append([]byte{0xc3, 0x00, 0x00, 0x00, 0x01, byte(len(dcid))}, dcid...)
	packet = append(packet, byte(len(scid)))
	packet = append(packet, scid...)

	version, gotDCID, gotSCID, ok := quicsniff.ParseLongHeader(packet)
	require.True(t, ok)
	assert.Equal(t, quicsniff.Version1, version)
	assert.Equal(t, dcid, gotDCID)
	assert.Equal(t, scid, gotSCID)

	_, _, _, ok = quicsniff.ParseLongHeader([]byte{0x43, 0, 0, 0, 1, 0, 0})
	assert.False(t, ok, "a short header has no long header fields")
	_, _, _, ok = quicsniff.ParseLongHeader(packet[:10])
	assert.False(t, ok, "truncated inside the connection ID")
	tooLong := slices.Clone(packet)
	tooLong[5] = 21
	_, _, _, ok = quicsniff.ParseLongHeader(tooLong)
	assert.False(t, ok, "RFC 9000 caps a connection ID at 20 bytes")

	vn := slices.Clone(packet)
	vn[1], vn[2], vn[3], vn[4] = 0, 0, 0, 0
	version, _, _, ok = quicsniff.ParseLongHeader(vn)
	require.True(t, ok, "Version Negotiation keeps the version independent layout")
	assert.Equal(t, uint32(0), version)

	assert.True(t, quicsniff.IsInitial(0xc3, quicsniff.Version1))
	assert.False(t, quicsniff.IsInitial(0xc3, quicsniff.Version2), "the type bits moved in v2")
	assert.False(t, quicsniff.IsInitial(0xc3, 0x12345678))
}

// FuzzReassembler feeds arbitrary bytes to the QUIC Initial parser. Everything it reads is
// written by an unauthenticated peer, before any handshake has happened, so it is the part
// of the proxy most exposed to a hostile input.
func FuzzReassembler(f *testing.F) {
	for _, dg := range captureInitials(f, "seed.example.test", &tls.Config{NextProtos: []string{"h3"}}) {
		f.Add(dg)
	}
	f.Add([]byte{})
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00})
	f.Add([]byte{0x40, 0x00})

	f.Fuzz(func(t *testing.T, datagram []byte) {
		r := quicsniff.New()
		hello, err := r.Feed(datagram)
		if err != nil {
			if hello != nil {
				t.Fatalf("a failed Feed returned %d bytes", len(hello))
			}
			return
		}
		if hello == nil {
			return
		}
		// A completed message is a ClientHello whose declared length matches what was
		// handed back, or the caller would parse past the end of it.
		if len(hello) < 4 {
			t.Fatalf("completed message is only %d bytes", len(hello))
		}
		if hello[0] != 0x01 {
			t.Fatalf("completed message has type 0x%02x, want 0x01", hello[0])
		}
		declared := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3])
		if declared+4 != len(hello) {
			t.Fatalf("declared length %d does not match the %d bytes returned", declared+4, len(hello))
		}
	})
}

// A conformance case is one requirement of an RFC on the receiver of a client's Initial
// packets, checked against the Reassembler. A case that cannot apply states the reason
// instead of a scenario.
type conformanceCase struct {
	// id is the section of the source, "rfc9000/12.2/1".
	id string
	// name states what the client sends.
	name string
	// req is the requirement in the words of the RFC.
	req string
	// skip gives the reason the case does not apply.
	skip string
	run  func(t *testing.T)
}

func TestConformance(t *testing.T) {
	for _, tc := range conformance {
		t.Run(tc.id+" "+tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}
			t.Parallel()
			tc.run(t)
		})
	}
}

func readHex(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	out, err := hex.DecodeString(strings.Join(strings.Fields(string(b)), ""))
	require.NoError(t, err)
	return out
}

// rfcHello is the ClientHello of RFC 9001 Appendix A.2, its CRYPTO frame minus the four
// bytes of the frame header.
func rfcHello(t *testing.T) []byte { return readHex(t, "rfc9001-client-crypto.hex")[4:] }

// forgedHello is rfcHello for another server name, complete on its own, so a packet the
// receiver must discard shows by completing it.
func forgedHello(t *testing.T) []byte {
	t.Helper()
	hello := rfcHello(t)
	i := bytes.Index(hello, []byte("example.com"))
	require.Positive(t, i)
	copy(hello[i:], "exbmple.com")
	return hello
}

var rfcDCID = []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

const (
	typeInitial = iota
	type0RTT
	typeHandshake
)

// longPacket is a long header packet the test protects with the Initial keys of its
// destination connection ID, RFC 9001 section 5.
type longPacket struct {
	dcid    []byte
	scid    []byte
	token   []byte
	frames  []byte
	version uint32
	pn      uint32
	pnLen   int
	typ     int
	// unfixed clears the fixed bit before the packet is protected.
	unfixed bool
}

func initial(frames ...[]byte) longPacket {
	return longPacket{version: quicsniff.Version1, dcid: rfcDCID, pn: 2, pnLen: 4, frames: slices.Concat(frames...)}
}

func (p longPacket) protect(t *testing.T) []byte {
	t.Helper()
	salt, prefix, typ := saltV1, "quic ", byte(p.typ)
	if p.version == quicsniff.Version2 {
		// RFC 9369 section 3.2 rotates the type bits by one.
		salt, prefix, typ = saltV2, "quicv2 ", byte(p.typ+1)%4
	}
	secret, err := hkdf.Extract(sha256.New, p.dcid, salt)
	require.NoError(t, err)
	client := expandLabel(t, secret, "client in", 32)
	key := expandLabel(t, client, prefix+"key", 16)
	iv := expandLabel(t, client, prefix+"iv", 12)
	hp := expandLabel(t, client, prefix+"hp", 16)

	hdr := []byte{0xc0 | typ<<4 | byte(p.pnLen-1)}
	if p.unfixed {
		hdr[0] &^= 0x40
	}
	hdr = binary.BigEndian.AppendUint32(hdr, p.version)
	hdr = append(hdr, byte(len(p.dcid)))
	hdr = append(hdr, p.dcid...)
	hdr = append(hdr, byte(len(p.scid)))
	hdr = append(hdr, p.scid...)
	if p.typ == typeInitial {
		hdr = quicvarint.Append(hdr, uint64(len(p.token)))
		hdr = append(hdr, p.token...)
	}
	hdr = quicvarint.AppendWithLen(hdr, uint64(p.pnLen+len(p.frames)+16), 2)
	pnOffset := len(hdr)
	for i := p.pnLen - 1; i >= 0; i-- {
		hdr = append(hdr, byte(p.pn>>(8*i)))
	}

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
	for i := range p.pnLen {
		out[pnOffset+i] ^= mask[1+i]
	}
	return out
}

var (
	saltV1 = []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
	}
	saltV2 = []byte{
		0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
	}
)

func expandLabel(t *testing.T, secret []byte, label string, length int) []byte {
	t.Helper()
	full := "tls13 " + label
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	require.NoError(t, err)
	return out
}

func cryptoFrame(offset int, data []byte) []byte {
	b := quicvarint.Append([]byte{0x06}, uint64(offset))
	b = quicvarint.Append(b, uint64(len(data)))
	return append(b, data...)
}

// paddedHello grows hello to size bytes with a padding extension, RFC 7685.
func paddedHello(t *testing.T, hello []byte, size int) []byte {
	t.Helper()
	pad := size - len(hello) - 4
	require.Positive(t, pad)
	out := slices.Clone(hello)
	out = binary.BigEndian.AppendUint16(out, 21)
	out = binary.BigEndian.AppendUint16(out, uint16(pad))
	out = append(out, make([]byte, pad)...)

	body := len(out) - 4
	out[1], out[2], out[3] = byte(body>>16), byte(body>>8), byte(body)
	// The extensions start past the version, the random, the session ID, the cipher
	// suites and the compression methods.
	pos := 4 + 2 + 32
	pos += 1 + int(out[pos])
	pos += 2 + int(binary.BigEndian.Uint16(out[pos:]))
	pos += 1 + int(out[pos])
	binary.BigEndian.PutUint16(out[pos:], uint16(len(out)-pos-2))
	return out
}

// wantHello feeds the datagrams in order and wants the last one to complete hello.
func wantHello(t *testing.T, hello []byte, datagrams ...[]byte) {
	t.Helper()
	r := quicsniff.New()
	for i, dg := range datagrams {
		out, err := r.Feed(dg)
		require.NoError(t, err)
		if i < len(datagrams)-1 {
			require.Nil(t, out, "the ClientHello completed at datagram %d", i)
			continue
		}
		require.Equal(t, hello, out)
	}
}

// wantDiscarded feeds a packet the receiver must discard, then the ClientHello, and wants
// the ClientHello read as if the discarded packet had never arrived.
func wantDiscarded(t *testing.T, discarded []byte) {
	t.Helper()
	hello := rfcHello(t)
	r := quicsniff.New()
	out, _ := r.Feed(discarded)
	require.Nil(t, out)
	out, err := r.Feed(initial(cryptoFrame(0, hello)).protect(t))
	require.NoError(t, err)
	require.Equal(t, hello, out)
}

func wantRefused(t *testing.T, datagram []byte) {
	t.Helper()
	out, err := quicsniff.New().Feed(datagram)
	require.ErrorIs(t, err, quicsniff.ErrMalformed)
	require.Nil(t, out)
}

var conformance = []conformanceCase{
	{
		id: "rfc9001/A.2", name: "the client Initial of the appendix",
		req: "The client sends an Initial packet. The unprotected payload of this packet contains the following CRYPTO frame, plus enough PADDING frames to make a 1162-byte payload.",
		run: func(t *testing.T) {
			hello := rfcHello(t)
			packet := readHex(t, "rfc9001-client-initial.hex")
			p := initial(readHex(t, "rfc9001-client-crypto.hex"))
			p.frames = append(p.frames, make([]byte, 1162-len(p.frames))...)
			require.Equal(t, packet, p.protect(t), "the test protects a packet as the appendix does")
			wantHello(t, hello, packet)
		},
	},
	{
		id: "rfc9369/A.2", name: "the QUIC v2 client Initial of the appendix",
		req: "The client sends an Initial packet. The unprotected payload of this packet contains the following CRYPTO frame, plus enough PADDING frames to make a 1162-byte payload.",
		run: func(t *testing.T) {
			hello := rfcHello(t)
			packet := readHex(t, "rfc9369-client-initial.hex")
			p := initial(readHex(t, "rfc9001-client-crypto.hex"))
			p.version = quicsniff.Version2
			p.frames = append(p.frames, make([]byte, 1162-len(p.frames))...)
			require.Equal(t, packet, p.protect(t), "the test protects a packet as the appendix does")
			wantHello(t, hello, packet)
		},
	},
	{
		id: "rfc9001/5.4.1", name: "packet numbers of one to four bytes",
		req: "The Packet Number field is one to four bytes long. The packet number is protected using the least significant bits of the first byte of the mask.",
		run: func(t *testing.T) {
			hello := rfcHello(t)
			for n := 1; n <= 4; n++ {
				p := initial(cryptoFrame(0, hello))
				p.pnLen, p.pn = n, 1
				wantHello(t, hello, p.protect(t))
			}
		},
	},
	{
		id: "rfc9001/5.4.2", name: "an Initial too short for the header protection sample",
		req: "An endpoint MUST discard packets that are not long enough to contain a complete sample.",
		run: func(t *testing.T) {
			p := initial([]byte{0x01, 0x00, 0x00})
			p.pnLen = 1
			packet := p.protect(t)
			packet = packet[:len(packet)-1]
			// The Length field follows the empty token, and now counts 19 bytes.
			packet[16], packet[17] = 0x40, 19
			wantDiscarded(t, packet)
		},
	},
	{
		id: "rfc9001/5.3", name: "an Initial whose authentication tag fails",
		req: "Failure to unprotect a packet does not necessarily indicate the existence of a protocol error in a peer or an attack.",
		run: func(t *testing.T) {
			packet := initial(cryptoFrame(0, forgedHello(t))).protect(t)
			packet[len(packet)-1] ^= 0xff
			wantDiscarded(t, packet)
		},
	},
	{
		id: "rfc9001/5.2", name: "an Initial protected with the keys of another connection ID",
		req: "Initial packets apply the packet protection process, but use a secret derived from the Destination Connection ID field from the client's first Initial packet.",
		run: func(t *testing.T) {
			p := initial(cryptoFrame(0, forgedHello(t)))
			p.dcid = bytes.Repeat([]byte{0xaa}, 8)
			packet := p.protect(t)
			copy(packet[6:14], rfcDCID)
			wantDiscarded(t, packet)
		},
	},
	{
		id: "rfc9000/12.2/1", name: "an Initial coalesced with a Handshake packet",
		req: "Receivers MUST be able to process coalesced packets.",
		run: func(t *testing.T) {
			hello := rfcHello(t)
			hs := initial(make([]byte, 40))
			hs.typ = typeHandshake
			wantHello(t, hello, slices.Concat(initial(cryptoFrame(0, hello)).protect(t), hs.protect(t)))
		},
	},
	{
		id: "rfc9000/12.2/2", name: "an Initial coalesced with a 0-RTT packet",
		req: "Receivers MUST be able to process coalesced packets.",
		run: func(t *testing.T) {
			hello := rfcHello(t)
			zero := initial(make([]byte, 40))
			zero.typ = type0RTT
			wantHello(t, hello, slices.Concat(initial(cryptoFrame(0, hello)).protect(t), zero.protect(t)))
		},
	},
	{
		id: "rfc9000/12.2/3", name: "the ClientHello over two coalesced Initials",
		req: "The receiver of coalesced QUIC packets MUST individually process each QUIC packet and separately acknowledge them, as if they were received as the payload of different UDP datagrams.",
		run: func(t *testing.T) {
			hello := rfcHello(t)
			first := initial(cryptoFrame(0, hello[:100]))
			second := initial(cryptoFrame(100, hello[100:]))
			second.pn = 3
			wantHello(t, hello, slices.Concat(first.protect(t), second.protect(t)))
		},
	},
	{
		id: "rfc9000/12.2/6", name: "an Initial followed by a short header packet",
		req: "A packet with a short header does not include a length, so it can only be the last packet included in a UDP datagram.",
		run: func(t *testing.T) {
			hello := rfcHello(t)
			short := append([]byte{0x40}, bytes.Repeat([]byte{0x5a}, 40)...)
			wantHello(t, hello, slices.Concat(initial(cryptoFrame(0, hello)).protect(t), short))
		},
	},
	{
		id: "rfc9000/12.2/4", name: "an Initial that fails authentication, coalesced before a valid one",
		req: "If decryption fails (because the keys are not available or for any other reason), the receiver MAY either discard or buffer the packet for later processing and MUST attempt to process the remaining packets.",
		run: func(t *testing.T) {
			hello := rfcHello(t)
			forged := initial(cryptoFrame(0, forgedHello(t)))
			forged.pn = 1
			bad := forged.protect(t)
			bad[len(bad)-1] ^= 0xff
			wantHello(t, hello, slices.Concat(bad, initial(cryptoFrame(0, hello)).protect(t)))
		},
	},
	{
		id: "rfc9000/12.2/5", name: "an Initial of another connection ID coalesced after the first",
		req: "Senders MUST NOT coalesce QUIC packets with different connection IDs into a single UDP datagram. Receivers SHOULD ignore any subsequent packets with a different Destination Connection ID than the first packet in the datagram.",
		run: func(t *testing.T) {
			hello := rfcHello(t)
			other := initial(cryptoFrame(100, hello[100:]))
			other.dcid = bytes.Repeat([]byte{0xaa}, 8)
			r := quicsniff.New()
			out, _ := r.Feed(slices.Concat(initial(cryptoFrame(0, hello[:100])).protect(t), other.protect(t)))
			require.Nil(t, out, "the ClientHello completed from a packet of another connection")
		},
	},
	{
		id: "rfc9000/12.4/1", name: "PADDING, PING and ACK frames around the CRYPTO frame",
		req: "The payload of this packet contains CRYPTO frames and could contain PING, PADDING, or ACK frames.",
		run: func(t *testing.T) {
			hello := rfcHello(t)
			ack := []byte{0x02, 0x05, 0x00, 0x01, 0x00, 0x01, 0x02}
			ackECN := []byte{0x03, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03}
			wantHello(t, hello, initial([]byte{0x01}, ack, cryptoFrame(0, hello), ackECN, make([]byte, 100)).protect(t))
		},
	},
	{
		id: "rfc9000/12.4/2", name: "a CONNECTION_CLOSE of type 0x1c in an Initial",
		req: "Only a CONNECTION_CLOSE frame of type 0x1c can appear in Initial or Handshake packets.",
		run: func(t *testing.T) {
			closeFrame := []byte{0x1c, 0x0a, 0x00, 0x00}
			out, err := quicsniff.New().Feed(initial(closeFrame, make([]byte, 40)).protect(t))
			require.NoError(t, err)
			require.Nil(t, out)
		},
	},
	{
		id: "rfc9000/12.4/3", name: "a STREAM frame in an Initial",
		req: "An endpoint MUST treat receipt of a frame in a packet type that is not permitted as a connection error of type PROTOCOL_VIOLATION.",
		run: func(t *testing.T) {
			wantRefused(t, initial([]byte{0x08, 0x00, 0x61}, make([]byte, 40)).protect(t))
		},
	},
	{
		id: "rfc9000/12.4/4", name: "a frame of unknown type in an Initial",
		req: "An endpoint MUST treat the receipt of a frame of unknown type as a connection error of type FRAME_ENCODING_ERROR.",
		run: func(t *testing.T) {
			wantRefused(t, initial([]byte{0x40, 0x7f}, make([]byte, 40)).protect(t))
		},
	},
	{
		id: "rfc9000/12.4/5", name: "an Initial with no frames",
		req:  "An endpoint MUST treat receipt of a packet containing no frames as a connection error of type PROTOCOL_VIOLATION.",
		skip: "the demultiplexer delivers the packet to the terminating stack, which closes the connection",
	},
	{
		id: "rfc9000/7.5/1", name: "4096 bytes of CRYPTO data in reverse order",
		req: "Implementations MUST support buffering at least 4096 bytes of data received in out-of-order CRYPTO frames.",
		run: func(t *testing.T) {
			hello := paddedHello(t, rfcHello(t), 5000)
			var datagrams [][]byte
			for off := 4000; off >= 0; off -= 1000 {
				p := initial(cryptoFrame(off, hello[off:min(off+1000, len(hello))]))
				p.pn = uint32(10 - off/1000)
				datagrams = append(datagrams, p.protect(t))
			}
			wantHello(t, hello, datagrams...)
		},
	},
	{
		id: "rfc9000/7.5/2", name: "a ClientHello past the CRYPTO buffer",
		req: "If an endpoint's buffer is exceeded during the handshake, it can expand its buffer temporarily to complete the handshake. If an endpoint does not expand its buffer, it MUST close the connection with a CRYPTO_BUFFER_EXCEEDED error code.",
		run: func(t *testing.T) {
			wantRefused(t, initial(cryptoFrame(64*1024, []byte("late"))).protect(t))
		},
	},
	{
		id: "rfc9000/2.2/1", name: "CRYPTO data sent twice at the same offset",
		req: "An endpoint could receive data for a stream at the same stream offset multiple times. Data that has already been received can be discarded.",
		run: func(t *testing.T) {
			hello := rfcHello(t)
			first := initial(cryptoFrame(0, hello[:120]))
			again := initial(cryptoFrame(0, hello[:120]), cryptoFrame(120, hello[120:]))
			again.pn = 3
			wantHello(t, hello, first.protect(t), again.protect(t))
		},
	},
	{
		id: "rfc9000/2.2/2", name: "different CRYPTO data at an offset already received",
		req: "The data at a given offset MUST NOT change if it is sent multiple times; an endpoint MAY treat receipt of different data at the same offset within a stream as a connection error of type PROTOCOL_VIOLATION.",
		run: func(t *testing.T) {
			hello := rfcHello(t)
			changed := forgedHello(t)
			r := quicsniff.New()
			out, err := r.Feed(initial(cryptoFrame(0, hello[:120])).protect(t))
			require.NoError(t, err)
			require.Nil(t, out)
			again := initial(cryptoFrame(0, changed[:120]), cryptoFrame(120, hello[120:]))
			again.pn = 3
			out, err = r.Feed(again.protect(t))
			if err == nil {
				require.Equal(t, hello, out, "the ClientHello read is not the data received first")
			}
		},
	},
	{
		id: "rfc9000/17.2/1", name: "a connection ID of 20 bytes",
		req: "In QUIC version 1, this value MUST NOT exceed 20 bytes.",
		run: func(t *testing.T) {
			hello := rfcHello(t)
			p := initial(cryptoFrame(0, hello))
			p.dcid = bytes.Repeat([]byte{0x11}, 20)
			p.scid = bytes.Repeat([]byte{0x22}, 20)
			wantHello(t, hello, p.protect(t))
		},
	},
	{
		id: "rfc9000/17.2/2", name: "a connection ID of 21 bytes",
		req: "Endpoints that receive a version 1 long header with a value larger than 20 MUST drop the packet.",
		run: func(t *testing.T) {
			p := initial(cryptoFrame(0, forgedHello(t)))
			p.dcid = bytes.Repeat([]byte{0x11}, 21)
			wantDiscarded(t, p.protect(t))
		},
	},
	{
		id: "rfc9000/17.2/3", name: "an Initial with the fixed bit cleared",
		req: "Fixed Bit: The next bit (0x40) of byte 0 is set to 1, unless the packet is a Version Negotiation packet. Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded.",
		run: func(t *testing.T) {
			p := initial(cryptoFrame(0, forgedHello(t)))
			p.unfixed = true
			wantDiscarded(t, p.protect(t))
		},
	},
	{
		id: "rfc9000/17.2.2", name: "an Initial with the token of a Retry",
		req: "Token: The value of the token that was previously provided in a Retry packet or NEW_TOKEN frame.",
		run: func(t *testing.T) {
			hello := rfcHello(t)
			p := initial(cryptoFrame(0, hello))
			p.token = bytes.Repeat([]byte{0x7e}, 64)
			wantHello(t, hello, p.protect(t))
		},
	},
	{
		id: "rfc9000/14.1", name: "an Initial in a datagram of less than 1200 bytes",
		req:  "A server MUST discard an Initial packet that is carried in a UDP datagram with a payload that is smaller than the smallest allowed maximum datagram size of 1200 bytes.",
		skip: "the demultiplexer checks the size of the datagram before it feeds the Reassembler",
	},
	{
		id: "rfc9000/6.1", name: "a long header of an unsupported version",
		req:  "If a server receives a packet that indicates an unsupported version and if the packet is large enough to initiate a new connection for any supported version, the server SHOULD send a Version Negotiation packet.",
		skip: "the demultiplexer checks the version before it feeds the Reassembler",
	},
}
