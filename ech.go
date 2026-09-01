// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"fmt"
)

// extensionECH is the encrypted_client_hello extension type. A real offer and the GREASE
// variant share it and are indistinguishable by design.
const extensionECH = 0xfe0d

var (
	errECHOffered      = fmt.Errorf("%w, the ClientHello offers Encrypted Client Hello", ErrConnectionRejected)
	errECHUnverifiable = fmt.Errorf("%w, the ClientHello cannot be checked for Encrypted Client Hello", ErrConnectionRejected)
)

// checkECH classifies the TLS records of a client's first flight. A ClientHello it cannot
// read is refused like one offering the extension, since the origin may read it fine and
// letting it through would make the check evadable by malforming the hello.
func checkECH(raw []byte) error {
	msg := handshakeFromRecords(raw)
	if msg == nil {
		return errECHUnverifiable
	}
	offered, ok := offersECH(msg)
	if !ok {
		return errECHUnverifiable
	}
	if offered {
		return errECHOffered
	}
	return nil
}

// handshakeFromRecords strips the record layer from raw and returns the first handshake
// message, or nil when the records do not hold a complete one.
func handshakeFromRecords(raw []byte) []byte {
	const recordHeader = 5
	var msg []byte
	for len(raw) > 0 {
		if len(raw) < recordHeader || raw[0] != tlsHandshakeRecord {
			return nil
		}
		n := int(raw[3])<<8 | int(raw[4])
		if n == 0 || len(raw) < recordHeader+n {
			return nil
		}
		msg = append(msg, raw[recordHeader:recordHeader+n]...)
		raw = raw[recordHeader+n:]
	}
	if len(msg) < 4 {
		return nil
	}
	want := 4 + (int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3]))
	if len(msg) < want {
		return nil
	}
	return msg[:want]
}

// offersECH reports whether the ClientHello handshake message msg offers the
// encrypted_client_hello extension. ok is false when msg does not parse as a complete
// ClientHello, which a caller enforcing the refusal must treat as an offer rather than
// an absence.
func offersECH(msg []byte) (offered, ok bool) {
	if len(msg) < 4 || msg[0] != 0x01 {
		return false, false
	}
	body := msg[4:]
	if int(msg[1])<<16|int(msg[2])<<8|int(msg[3]) != len(body) {
		return false, false
	}

	// legacy_version and random.
	if len(body) < 34 {
		return false, false
	}
	b := body[34:]

	// session_id.
	if len(b) < 1 {
		return false, false
	}
	n := int(b[0])
	b = b[1:]
	if len(b) < n {
		return false, false
	}
	b = b[n:]

	// cipher_suites.
	if len(b) < 2 {
		return false, false
	}
	n = int(b[0])<<8 | int(b[1])
	b = b[2:]
	if len(b) < n {
		return false, false
	}
	b = b[n:]

	// compression_methods.
	if len(b) < 1 {
		return false, false
	}
	n = int(b[0])
	b = b[1:]
	if len(b) < n {
		return false, false
	}
	b = b[n:]

	if len(b) == 0 {
		// A ClientHello without an extensions block cannot offer any extension.
		return false, true
	}
	if len(b) < 2 || int(b[0])<<8|int(b[1]) != len(b)-2 {
		return false, false
	}
	b = b[2:]
	for len(b) > 0 {
		if len(b) < 4 {
			return false, false
		}
		typ := int(b[0])<<8 | int(b[1])
		n = int(b[2])<<8 | int(b[3])
		b = b[4:]
		if len(b) < n {
			return false, false
		}
		if typ == extensionECH {
			return true, true
		}
		b = b[n:]
	}
	return false, true
}

// inspectECH refuses the connection when the bytes waiting in pc are a TLS ClientHello
// offering Encrypted Client Hello. Bytes that are not a TLS handshake pass untouched, and
// a read error is left for the caller's own reads to surface.
func inspectECH(pc *peekConn) error {
	head, err := pc.Peek(1)
	if err != nil {
		return nil
	}
	if head[0] != tlsHandshakeRecord {
		return nil
	}
	raw, err := peekHandshakeRecords(pc.r)
	if err != nil {
		return errECHUnverifiable
	}
	return checkECH(raw)
}
