// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// newHTTP3Transport builds the upstream transport used when a client speaks HTTP/3 and
// [Transport.AllowHTTP3] is on.
func newHTTP3Transport(t *Transport) (http.RoundTripper, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if t.TLSClientConfig != nil {
		tlsCfg = t.TLSClientConfig.Clone()
		if tlsCfg.MinVersion < tls.VersionTLS13 {
			// QUIC requires TLS 1.3; a lower floor inherited from the TCP configuration
			// would make every handshake fail.
			tlsCfg.MinVersion = tls.VersionTLS13
		}
	}
	if t.RootCAs != nil {
		tlsCfg.RootCAs = t.RootCAs
	}
	if t.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}

	return &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  t.IdleConnTimeout,
			KeepAlivePeriod: 0,
		},
		DisableCompression: true,
		Dial: func(ctx context.Context, addr string, cfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			// A transparently redirected request goes back to the address the client had
			// resolved. The server name stays the one in the request, so the certificate is
			// still checked against the authority the client asked for.
			if ap, ok := ctx.Value(upstreamAddrKey{}).(netip.AddrPort); ok && ap.IsValid() {
				addr = ap.String()
			}
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			pc, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}
			conn, err := quic.Dial(ctx, pc, udpAddr, cfg, qcfg)
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
			return conn, nil
		},
	}, nil
}
