// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"errors"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

// A destination pool serves one authority, so it keeps at most MaxIdleConnsPerHost idle
// connections. A shared pool serves every authority the proxy resolves itself and keeps
// MaxIdleConns.
func TestTransport_DestinationPoolIdleLimit(t *testing.T) {
	tr := DefaultTransport()
	for _, scheme := range []string{"http", "https"} {
		shared := newUpstreamPool(newUpstreamDialer(tr), scheme, "", nil)
		assert.Equal(t, tr.MaxIdleConns, shared.h1.MaxIdleConns, scheme)
		assert.Equal(t, tr.MaxIdleConns, shared.h2.MaxIdleConns, scheme)
	}

	pool := newUpstreamPool(newUpstreamDialer(tr), "https", "127.0.0.1:443", nil)
	assert.Equal(t, tr.MaxIdleConnsPerHost, pool.h1.MaxIdleConns)
	assert.Equal(t, tr.MaxIdleConnsPerHost, pool.h2.MaxIdleConns)

	pool = newUpstreamPool(newUpstreamDialer(tr), "http", "127.0.0.1:80", nil)
	assert.Equal(t, tr.MaxIdleConnsPerHost, pool.h2.MaxIdleConns, "the h2c transport")

	tr.MaxIdleConnsPerHost = 0
	pool = newUpstreamPool(newUpstreamDialer(tr), "https", "127.0.0.1:443", nil)
	assert.Equal(t, http.DefaultMaxIdleConnsPerHost, pool.h1.MaxIdleConns)
}

// The kernel hands an ICMP message received for a connected UDP socket to its next read or
// write as an error, on which quic-go ends the transport. The socket the proxy dials an h3
// upstream on skips it, as the unconnected socket every QUIC server reads from never sees one.
func TestTransport_ConnectedSocketSkipsICMPErrors(t *testing.T) {
	// A datagram to a loopback port nobody listens on draws an ICMP port unreachable.
	closed, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	target := closed.LocalAddr().(*net.UDPAddr)
	require.NoError(t, closed.Close())

	raw, err := net.DialUDP("udp4", nil, target)
	require.NoError(t, err)
	defer raw.Close()
	_, err = raw.Write([]byte("x"))
	require.NoError(t, err)
	require.NoError(t, raw.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = raw.Read(make([]byte, 1))
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Skipf("the platform does not report an ICMP error on a connected socket: %v", err)
	}

	sock, err := net.DialUDP("udp4", nil, target)
	require.NoError(t, err)
	defer sock.Close()
	pc := packetConnOf(sock).(*connectedUDPConn)
	timesOut := func(err error) {
		t.Helper()
		var nerr net.Error
		require.ErrorAs(t, err, &nerr)
		assert.True(t, nerr.Timeout(), "the read must end on its deadline, not on the ICMP error: %v", err)
	}

	// The batched read quic-go uses where the platform reports ECN.
	_, err = pc.WriteTo([]byte("x"), nil)
	require.NoError(t, err)
	require.NoError(t, sock.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	msgs := []ipv4.Message{{Buffers: [][]byte{make([]byte, 1)}, OOB: make([]byte, 64)}}
	_, err = pc.ReadBatch(msgs, 0)
	timesOut(err)

	// The plain read it falls back to elsewhere.
	_, _, err = pc.WriteMsgUDP([]byte("x"), nil, nil)
	require.NoError(t, err)
	require.NoError(t, sock.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	_, _, err = pc.ReadFrom(make([]byte, 1))
	timesOut(err)

	// A write may be the call that meets the error, and it goes through on a retry. Each write
	// path gets a socket of its own, as the kernel hands a socket one error at a time.
	_, err = pc.WriteTo([]byte("x"), nil)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	_, err = pc.WriteTo([]byte("x"), nil)
	require.NoError(t, err)
	require.NoError(t, sock.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	_, _, err = pc.ReadFrom(make([]byte, 1))
	timesOut(err)

	sock2, err := net.DialUDP("udp4", nil, target)
	require.NoError(t, err)
	defer sock2.Close()
	pc2 := packetConnOf(sock2).(*connectedUDPConn)
	_, _, err = pc2.WriteMsgUDP([]byte("x"), nil, nil)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	_, _, err = pc2.WriteMsgUDP([]byte("x"), nil, nil)
	require.NoError(t, err)
	require.NoError(t, sock2.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	_, _, err = pc2.ReadFrom(make([]byte, 1))
	timesOut(err)

	// The socket a datagram flow reads and writes, and any other connected socket the dialer
	// returns for QUIC, go through noICMPConn.
	other, err := net.DialUDP("udp4", nil, target)
	require.NoError(t, err)
	defer other.Close()
	dc := noICMPConn{other}
	_, err = dc.Write([]byte("x"))
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	_, err = dc.Write([]byte("x"))
	require.NoError(t, err)
	require.NoError(t, other.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	_, err = dc.Read(make([]byte, 1))
	timesOut(err)

	cc := packetConnOf(struct{ net.Conn }{other})
	_, err = cc.WriteTo([]byte("x"), nil)
	require.NoError(t, err)
	require.NoError(t, other.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
	_, _, err = cc.ReadFrom(make([]byte, 1))
	timesOut(err)
}
