// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package quicsniff_test

import (
	"crypto/tls"
	"testing"

	"github.com/fox-toolkit/edge/internal/quicsniff"
)

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
