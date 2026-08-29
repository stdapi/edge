// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

// Package quicsniff reads the TLS ClientHello out of QUIC Initial packets.
//
// A forward proxy has to decide what to do with a QUIC connection before it answers, and the
// only thing in the first datagram that says where the client is going is the server name in
// its ClientHello. That ClientHello is encrypted, but an Initial packet is protected with
// keys derived from the connection ID it carries in clear, so anyone on the path can read it.
// That is by design: RFC 9001 calls Initial protection a defence against off-path injection
// and blind tampering, not confidentiality.
//
// Reassembly is required rather than optional. A ClientHello offering post-quantum key shares
// runs past the ~1200 byte Initial the client is allowed to send, so it arrives split across
// several packets and CRYPTO frames.
package quicsniff

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Errors reported by [Reassembler.Feed].
var (
	// ErrNotInitial is returned for a datagram that carries no QUIC Initial packet, which
	// includes every short header packet of an established connection.
	ErrNotInitial = errors.New("quicsniff: no QUIC Initial packet in datagram")
	// ErrUnsupportedVersion is returned for a QUIC version whose initial keys are not known.
	ErrUnsupportedVersion = errors.New("quicsniff: unsupported QUIC version")
	// ErrMalformed is returned when a packet cannot be parsed or authenticated.
	ErrMalformed = errors.New("quicsniff: malformed QUIC Initial packet")
)

// maxCryptoBytes bounds how much CRYPTO data one connection may buffer before being given
// up on. A ClientHello has no business being larger, and the buffer is filled straight from
// the network by an unauthenticated peer.
const maxCryptoBytes = 64 * 1024

// Version numbers of the QUIC versions whose initial keys are known.
const (
	Version1 uint32 = 0x00000001
	Version2 uint32 = 0x6b3343cf
)

// initialSalt values from RFC 9001 section 5.2 and RFC 9369 section 3.3.1.
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

// Reassembler collects the CRYPTO stream of one QUIC connection until the ClientHello it
// carries is complete. A Reassembler follows a single client and is not safe for concurrent
// use.
type Reassembler struct {
	crypto   []byte
	received []bool
	filled   int
	total    int
	done     bool
}

// New returns a Reassembler for one connection.
func New() *Reassembler {
	return &Reassembler{}
}

// Feed parses the Initial packets in a datagram and returns the ClientHello handshake
// message once every byte of it has arrived. It returns a nil message and a nil error while
// the message is still incomplete.
//
// The returned bytes are the TLS handshake message, starting with the ClientHello type byte,
// with no record layer around it: QUIC carries handshake messages in CRYPTO frames rather
// than in TLS records.
func (r *Reassembler) Feed(datagram []byte) ([]byte, error) {
	if r.done {
		return nil, nil
	}

	var sawInitial bool
	rest := datagram
	for len(rest) > 0 {
		pkt, remainder, err := splitPacket(rest)
		if err != nil {
			if sawInitial || errors.Is(err, ErrNotInitial) {
				// Either the Initial was already found, or what follows is a short header
				// packet. Coalesced packets past a malformed one cannot be located, so the
				// datagram ends here.
				break
			}
			return nil, err
		}
		rest = remainder

		if !pkt.isInitial {
			continue
		}
		sawInitial = true

		payload, err := decryptInitial(pkt)
		if err != nil {
			return nil, err
		}
		if err := r.collect(payload); err != nil {
			return nil, err
		}
	}

	if !sawInitial {
		return nil, ErrNotInitial
	}
	if r.total == 0 || r.filled < r.total {
		return nil, nil
	}

	r.done = true
	return r.crypto[:r.total], nil
}

// collect walks the frames of a decrypted Initial payload and records the CRYPTO data.
func (r *Reassembler) collect(payload []byte) error {
	for len(payload) > 0 {
		frameType, n := readVarint(payload)
		if n == 0 {
			return ErrMalformed
		}
		payload = payload[n:]

		switch frameType {
		case 0x00, 0x01:
			// PADDING and PING carry nothing. PADDING is a run of zero bytes, each read as
			// its own frame, which is what the loop already does.

		case 0x02, 0x03: // ACK
			var err error
			if payload, err = skipACK(payload, frameType == 0x03); err != nil {
				return err
			}

		case 0x06: // CRYPTO
			offset, n := readVarint(payload)
			if n == 0 {
				return ErrMalformed
			}
			payload = payload[n:]

			length, n := readVarint(payload)
			if n == 0 {
				return ErrMalformed
			}
			payload = payload[n:]

			if length > uint64(len(payload)) {
				return ErrMalformed
			}
			data := payload[:length]
			payload = payload[length:]

			if err := r.store(offset, data); err != nil {
				return err
			}

		case 0x1c, 0x1d: // CONNECTION_CLOSE, nothing left to learn
			return nil

		default:
			// An Initial packet may only carry the frames above (RFC 9000 section 17.2.2).
			return fmt.Errorf("%w: frame type 0x%x in an Initial packet", ErrMalformed, frameType)
		}
	}
	return nil
}

// store writes CRYPTO data at its offset in the reassembly buffer, growing it as needed and
// learning the total handshake message length as soon as its header has arrived.
func (r *Reassembler) store(offset uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	end := offset + uint64(len(data))
	if end > maxCryptoBytes {
		return fmt.Errorf("%w: ClientHello larger than %d bytes", ErrMalformed, maxCryptoBytes)
	}

	if int(end) > len(r.crypto) {
		grown := make([]byte, end)
		copy(grown, r.crypto)
		r.crypto = grown

		seen := make([]bool, end)
		copy(seen, r.received)
		r.received = seen
	}

	copy(r.crypto[offset:end], data)
	for i := offset; i < end; i++ {
		if !r.received[i] {
			r.received[i] = true
			r.filled++
		}
	}

	if r.total == 0 && r.filled >= 4 && allReceived(r.received[:4]) {
		if r.crypto[0] != 0x01 {
			return fmt.Errorf("%w: first handshake message is not a ClientHello", ErrMalformed)
		}
		length := int(r.crypto[1])<<16 | int(r.crypto[2])<<8 | int(r.crypto[3])
		r.total = length + 4
		if r.total > maxCryptoBytes {
			return fmt.Errorf("%w: ClientHello larger than %d bytes", ErrMalformed, maxCryptoBytes)
		}
	}

	return nil
}

func allReceived(b []bool) bool {
	for _, ok := range b {
		if !ok {
			return false
		}
	}
	return true
}

// packet is one QUIC long header packet located inside a datagram.
type packet struct {
	dcid []byte
	// raw is the packet from its first byte to the end of its payload.
	raw []byte
	// pnOffset is where the packet number starts within raw.
	pnOffset  int
	version   uint32
	isInitial bool
}

// splitPacket locates the first QUIC packet in b and returns what follows it. Datagrams
// commonly coalesce an Initial with a Handshake or 0-RTT packet.
func splitPacket(b []byte) (packet, []byte, error) {
	if len(b) == 0 {
		return packet{}, nil, ErrMalformed
	}
	if b[0]&0x80 == 0 {
		// A short header packet belongs to an established connection and runs to the end of
		// the datagram. It is checked before the length so a stray short packet is reported
		// as carrying no Initial rather than as malformed.
		return packet{}, nil, ErrNotInitial
	}
	if len(b) < 7 {
		return packet{}, nil, ErrMalformed
	}

	version := binary.BigEndian.Uint32(b[1:5])
	pos := 5

	dcidLen := int(b[pos])
	pos++
	if dcidLen > 20 || pos+dcidLen > len(b) {
		return packet{}, nil, ErrMalformed
	}
	dcid := b[pos : pos+dcidLen]
	pos += dcidLen

	if pos >= len(b) {
		return packet{}, nil, ErrMalformed
	}
	scidLen := int(b[pos])
	pos++
	if scidLen > 20 || pos+scidLen > len(b) {
		return packet{}, nil, ErrMalformed
	}
	pos += scidLen

	isInitial, err := isInitialPacket(b[0], version)
	if err != nil {
		return packet{}, nil, err
	}

	if isInitial {
		tokenLen, n := readVarint(b[pos:])
		if n == 0 {
			return packet{}, nil, ErrMalformed
		}
		pos += n

		size, ok := fitsIn(tokenLen, len(b)-pos)
		if !ok {
			return packet{}, nil, ErrMalformed
		}
		pos += size
	}

	length, n := readVarint(b[pos:])
	if n == 0 {
		return packet{}, nil, ErrMalformed
	}
	pos += n

	size, ok := fitsIn(length, len(b)-pos)
	if !ok {
		return packet{}, nil, ErrMalformed
	}
	end := pos + size

	return packet{
		isInitial: isInitial,
		version:   version,
		dcid:      dcid,
		raw:       b[:end],
		pnOffset:  pos,
	}, b[end:], nil
}

// isInitialPacket reports whether a long header packet is an Initial. The type bits moved
// between QUIC v1 and v2 so that a middlebox keyed on v1 would not recognize v2 traffic.
func isInitialPacket(first byte, version uint32) (bool, error) {
	typ := (first & 0x30) >> 4
	switch version {
	case Version1:
		return typ == 0x00, nil
	case Version2:
		return typ == 0x01, nil
	default:
		return false, fmt.Errorf("%w: 0x%08x", ErrUnsupportedVersion, version)
	}
}

// decryptInitial removes header protection and authenticated encryption from an Initial
// packet, returning its frames.
func decryptInitial(pkt packet) ([]byte, error) {
	keys, err := initialKeys(pkt.version, pkt.dcid)
	if err != nil {
		return nil, err
	}

	raw := pkt.raw
	// The sample used for header protection starts four bytes past the packet number, which
	// is where it would be if the number took its maximum length.
	sampleOffset := pkt.pnOffset + 4
	if sampleOffset+16 > len(raw) {
		return nil, ErrMalformed
	}

	block, err := aes.NewCipher(keys.hp)
	if err != nil {
		return nil, err
	}
	var mask [16]byte
	block.Encrypt(mask[:], raw[sampleOffset:sampleOffset+16])

	header := make([]byte, pkt.pnOffset, len(raw))
	copy(header, raw[:pkt.pnOffset])
	header[0] = raw[0] ^ (mask[0] & 0x0f)

	pnLen := int(header[0]&0x03) + 1
	if pkt.pnOffset+pnLen > len(raw) {
		return nil, ErrMalformed
	}

	// A packet number is one to four bytes, so its mask always fits within the block the
	// header protection produced.
	pnMask := mask[1 : 1+pnLen]

	var pn uint64
	for i, m := range pnMask {
		b := raw[pkt.pnOffset+i] ^ m
		header = append(header, b)
		pn = pn<<8 | uint64(b)
	}

	ciphertext := raw[pkt.pnOffset+pnLen:]
	if len(ciphertext) < 16 {
		return nil, ErrMalformed
	}

	aead, err := cipher.NewGCM(mustCipher(keys.key))
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, len(keys.iv))
	copy(nonce, keys.iv)
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], binary.BigEndian.Uint64(nonce[len(nonce)-8:])^pn)

	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return plaintext, nil
}

func mustCipher(key []byte) cipher.Block {
	block, err := aes.NewCipher(key)
	if err != nil {
		// The key length is fixed by the derivation above, so this cannot happen.
		panic(fmt.Sprintf("quicsniff: bad initial key: %v", err))
	}
	return block
}

type keys struct {
	key []byte
	iv  []byte
	hp  []byte
}

// initialKeys derives the client's Initial protection keys from the destination connection
// ID, as specified in RFC 9001 section 5.2.
func initialKeys(version uint32, dcid []byte) (keys, error) {
	var (
		salt     []byte
		keyLabel string
		ivLabel  string
		hpLabel  string
	)
	switch version {
	case Version1:
		salt, keyLabel, ivLabel, hpLabel = saltV1, "quic key", "quic iv", "quic hp"
	case Version2:
		salt, keyLabel, ivLabel, hpLabel = saltV2, "quicv2 key", "quicv2 iv", "quicv2 hp"
	default:
		return keys{}, fmt.Errorf("%w: 0x%08x", ErrUnsupportedVersion, version)
	}

	initialSecret, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return keys{}, err
	}
	clientSecret, err := expandLabel(initialSecret, "client in", 32)
	if err != nil {
		return keys{}, err
	}

	k, err := expandLabel(clientSecret, keyLabel, 16)
	if err != nil {
		return keys{}, err
	}
	iv, err := expandLabel(clientSecret, ivLabel, 12)
	if err != nil {
		return keys{}, err
	}
	hp, err := expandLabel(clientSecret, hpLabel, 16)
	if err != nil {
		return keys{}, err
	}
	return keys{key: k, iv: iv, hp: hp}, nil
}

// expandLabel is HKDF-Expand-Label from RFC 8446 section 7.1, with an empty context.
func expandLabel(secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	if length <= 0 || length > math.MaxUint16 || len(full) > math.MaxUint8 {
		return nil, fmt.Errorf("quicsniff: cannot derive %q of %d bytes", label, length)
	}

	info := make([]byte, 0, 3+len(full)+1)
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	// Guarded above: the label is shorter than 256 bytes.
	info = append(info, byte(len(full))) //nolint:gosec // bounded by the check above
	info = append(info, full...)
	info = append(info, 0) // empty context
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

// fitsIn converts a length read off the wire into an int, reporting whether it is within
// limit. Everything the parser reads is attacker controlled, so a length is never converted
// before it has been bounded.
func fitsIn(v uint64, limit int) (int, bool) {
	if limit < 0 || v > uint64(math.MaxInt32) || int(v) > limit {
		return 0, false
	}
	return int(v), true
}

// skipACK advances past an ACK frame, whose variable shape has to be walked to find where
// the next frame starts.
func skipACK(b []byte, ecn bool) ([]byte, error) {
	// Largest acknowledged, then ACK delay.
	for range 2 {
		var err error
		if b, err = skipVarint(b); err != nil {
			return nil, err
		}
	}

	count, n := readVarint(b)
	if n == 0 {
		return nil, ErrMalformed
	}
	b = b[n:]

	// First ACK range, then one gap and length per additional range. A hostile count is
	// bounded by the payload: every iteration consumes at least two bytes.
	fields := 1 + 2*count
	for range fields {
		var err error
		if b, err = skipVarint(b); err != nil {
			return nil, err
		}
	}

	if ecn {
		// ECT(0), ECT(1) and ECN-CE counts.
		for range 3 {
			var err error
			if b, err = skipVarint(b); err != nil {
				return nil, err
			}
		}
	}
	return b, nil
}

func skipVarint(b []byte) ([]byte, error) {
	_, n := readVarint(b)
	if n == 0 {
		return nil, ErrMalformed
	}
	return b[n:], nil
}

// readVarint decodes a QUIC variable length integer and returns the number of bytes it used,
// or zero when b is too short.
func readVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	length := 1 << (b[0] >> 6)
	if len(b) < length {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, length
}
