// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package quicsniff_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/fox-toolkit/edge/internal/quicsniff"
	"github.com/quic-go/quic-go"
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
