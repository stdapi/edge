// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

// Package socks5 encodes and decodes the messages of SOCKS Protocol Version 5, RFC 1928, and
// of its username/password authentication, RFC 1929. It has no policy. Which methods are
// offered, which commands are served and where a datagram goes are the caller's.
package socks5

import (
	"errors"
	"io"
	"net/netip"
	"strconv"
)

// Version is the protocol version every message starts with.
const Version = 5

// The authentication methods of RFC 1928 section 3, and the answer given when the client
// offers none the server accepts.
const (
	MethodNoAuth       = 0x00
	MethodPassword     = 0x02
	MethodNoAcceptable = 0xFF
)

// The commands of RFC 1928 section 4.
const (
	CmdConnect   = 0x01
	CmdBind      = 0x02
	CmdAssociate = 0x03
)

// The address types of RFC 1928 section 5.
const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// passwordVersion is the version of the username/password sub-negotiation, RFC 1929.
const passwordVersion = 1

// MaxDatagramHeader is the longest header of a datagram, RFC 1928 section 7.
const MaxDatagramHeader = 4 + 1 + 255 + 2

var (
	ErrVersion     = errors.New("socks5: unsupported version")
	ErrAddressType = errors.New("socks5: unsupported address type")
	ErrNameLength  = errors.New("socks5: a name must be 1 to 255 bytes")
	ErrFragmented  = errors.New("socks5: fragmented datagram")
	ErrShort       = errors.New("socks5: short message")
	ErrCredentials = errors.New("socks5: a username and a password must be 1 to 255 bytes each")
	ErrAuthFailed  = errors.New("socks5: authentication failed")
)

// Reply is the REP field of a reply, RFC 1928 section 6, and the error a client returns for
// any value but [Succeeded].
type Reply byte

const (
	Succeeded Reply = iota
	GeneralFailure
	NotAllowed
	NetworkUnreachable
	HostUnreachable
	ConnectionRefused
	TTLExpired
	CommandNotSupported
	AddressTypeNotSupported
)

func (r Reply) String() string {
	switch r {
	case Succeeded:
		return "succeeded"
	case GeneralFailure:
		return "general SOCKS server failure"
	case NotAllowed:
		return "connection not allowed by ruleset"
	case NetworkUnreachable:
		return "network unreachable"
	case HostUnreachable:
		return "host unreachable"
	case ConnectionRefused:
		return "connection refused"
	case TTLExpired:
		return "TTL expired"
	case CommandNotSupported:
		return "command not supported"
	case AddressTypeNotSupported:
		return "address type not supported"
	default:
		return "reply " + strconv.Itoa(int(r))
	}
}

func (r Reply) Error() string { return "socks5: " + r.String() }

// Addr is the address of a request, a reply or a datagram, a domain name or an IP address
// with a port. Name is set for a domain name and IP otherwise.
type Addr struct {
	IP   netip.Addr
	Name string
	Port uint16
}

// String returns the address as host:port, bracketing an IPv6 address.
func (a Addr) String() string {
	if a.Name != "" {
		return a.Name + ":" + strconv.Itoa(int(a.Port))
	}
	return netip.AddrPortFrom(a.IP, a.Port).String()
}

// AddrPort returns the IP address and the port, and false for a domain name.
func (a Addr) AddrPort() (netip.AddrPort, bool) {
	if a.Name != "" || !a.IP.IsValid() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a.IP, a.Port), true
}

// encodedLen returns the size of the address on the wire, ATYP included.
func (a Addr) encodedLen() int {
	switch {
	case a.Name != "":
		return 1 + 1 + len(a.Name) + 2
	case a.IP.Is4():
		return 1 + 4 + 2
	default:
		return 1 + 16 + 2
	}
}

func (a Addr) valid() error {
	if a.Name != "" {
		if len(a.Name) > 255 {
			return ErrNameLength
		}
		return nil
	}
	if !a.IP.IsValid() {
		return ErrAddressType
	}
	return nil
}

func (a Addr) appendTo(b []byte) []byte {
	switch {
	case a.Name != "":
		//nolint:gosec // valid bounds the name to 255 bytes.
		b = append(b, atypDomain, byte(len(a.Name)))
		b = append(b, a.Name...)
	case a.IP.Is4():
		ip := a.IP.As4()
		b = append(b, atypIPv4)
		b = append(b, ip[:]...)
	default:
		ip := a.IP.As16()
		b = append(b, atypIPv6)
		b = append(b, ip[:]...)
	}
	//nolint:gosec // the two halves of a uint16.
	return append(b, byte(a.Port>>8), byte(a.Port))
}

// readAddr reads an address whose ATYP is atyp, the rest of it still on r.
func readAddr(r io.Reader, atyp byte, buf []byte) (Addr, error) {
	var a Addr
	switch atyp {
	case atypIPv4:
		if _, err := io.ReadFull(r, buf[:4+2]); err != nil {
			return Addr{}, err
		}
		a.IP = netip.AddrFrom4([4]byte(buf[:4]))
		a.Port = uint16(buf[4])<<8 | uint16(buf[5])
	case atypIPv6:
		if _, err := io.ReadFull(r, buf[:16+2]); err != nil {
			return Addr{}, err
		}
		a.IP = netip.AddrFrom16([16]byte(buf[:16]))
		a.Port = uint16(buf[16])<<8 | uint16(buf[17])
	case atypDomain:
		if _, err := io.ReadFull(r, buf[:1]); err != nil {
			return Addr{}, err
		}
		l := int(buf[0])
		if l == 0 {
			return Addr{}, ErrNameLength
		}
		if _, err := io.ReadFull(r, buf[:l+2]); err != nil {
			return Addr{}, err
		}
		a.Name = string(buf[:l])
		a.Port = uint16(buf[l])<<8 | uint16(buf[l+1])
	default:
		return Addr{}, ErrAddressType
	}
	return a, nil
}

// ReadMethods reads the greeting of a client and returns the methods it offers.
func ReadMethods(r io.Reader) ([]byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	if head[0] != Version {
		return nil, ErrVersion
	}
	if head[1] == 0 {
		return nil, ErrShort
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(r, methods); err != nil {
		return nil, err
	}
	return methods, nil
}

// WriteMethod answers a greeting with the method selected, [MethodNoAcceptable] for none.
func WriteMethod(w io.Writer, method byte) error {
	_, err := w.Write([]byte{Version, method})
	return err
}

// WriteMethods sends a greeting offering methods.
func WriteMethods(w io.Writer, methods ...byte) error {
	if len(methods) == 0 || len(methods) > 255 {
		return ErrShort
	}
	b := make([]byte, 0, 2+len(methods))
	//nolint:gosec // bounded above.
	b = append(b, Version, byte(len(methods)))
	_, err := w.Write(append(b, methods...))
	return err
}

// ReadMethod reads the method a server selected.
func ReadMethod(r io.Reader) (byte, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	if b[0] != Version {
		return 0, ErrVersion
	}
	return b[1], nil
}

// ReadCredentials reads the username and password of RFC 1929.
func ReadCredentials(r io.Reader) (username, password string, err error) {
	var buf [256]byte
	if _, err = io.ReadFull(r, buf[:2]); err != nil {
		return "", "", err
	}
	if buf[0] != passwordVersion {
		return "", "", ErrVersion
	}
	l := int(buf[1])
	if _, err = io.ReadFull(r, buf[:l+1]); err != nil {
		return "", "", err
	}
	username = string(buf[:l])
	l = int(buf[l])
	if _, err = io.ReadFull(r, buf[:l]); err != nil {
		return "", "", err
	}
	return username, string(buf[:l]), nil
}

// WriteCredentialsStatus answers the credentials, RFC 1929 section 2.
func WriteCredentialsStatus(w io.Writer, ok bool) error {
	status := byte(1)
	if ok {
		status = 0
	}
	_, err := w.Write([]byte{passwordVersion, status})
	return err
}

// WriteCredentials sends a username and a password, RFC 1929, and returns [ErrCredentials]
// without writing when either is empty or longer than 255 bytes.
func WriteCredentials(w io.Writer, username, password string) error {
	if len(username) == 0 || len(username) > 255 || len(password) == 0 || len(password) > 255 {
		return ErrCredentials
	}
	b := make([]byte, 0, 3+len(username)+len(password))
	//nolint:gosec // both bounded above.
	b = append(b, passwordVersion, byte(len(username)))
	b = append(b, username...)
	//nolint:gosec // both bounded above.
	b = append(b, byte(len(password)))
	_, err := w.Write(append(b, password...))
	return err
}

// ReadCredentialsStatus reads the answer to the credentials, [ErrAuthFailed] when refused.
func ReadCredentialsStatus(r io.Reader) error {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	if b[0] != passwordVersion {
		return ErrVersion
	}
	if b[1] != 0 {
		return ErrAuthFailed
	}
	return nil
}

// ReadRequest reads a request and returns its command and address.
func ReadRequest(r io.Reader) (cmd byte, addr Addr, err error) {
	var buf [255 + 2]byte
	if _, err = io.ReadFull(r, buf[:4]); err != nil {
		return 0, Addr{}, err
	}
	if buf[0] != Version {
		return 0, Addr{}, ErrVersion
	}
	cmd = buf[1]
	addr, err = readAddr(r, buf[3], buf[:])
	return cmd, addr, err
}

// WriteRequest sends a request for cmd on addr.
func WriteRequest(w io.Writer, cmd byte, addr Addr) error {
	if err := addr.valid(); err != nil {
		return err
	}
	b := make([]byte, 0, 3+addr.encodedLen())
	b = append(b, Version, cmd, 0)
	_, err := w.Write(addr.appendTo(b))
	return err
}

// ReadReply reads a reply and returns its code and bound address. A code other than
// [Succeeded] is returned as the error.
func ReadReply(r io.Reader) (Reply, Addr, error) {
	var buf [255 + 2]byte
	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return 0, Addr{}, err
	}
	if buf[0] != Version {
		return 0, Addr{}, ErrVersion
	}
	rep := Reply(buf[1])
	addr, err := readAddr(r, buf[3], buf[:])
	if err != nil {
		return rep, Addr{}, err
	}
	if rep != Succeeded {
		return rep, addr, rep
	}
	return rep, addr, nil
}

// WriteReply sends a reply with bnd as its bound address.
func WriteReply(w io.Writer, rep Reply, bnd Addr) error {
	if err := bnd.valid(); err != nil {
		return err
	}
	b := make([]byte, 0, 3+bnd.encodedLen())
	b = append(b, Version, byte(rep), 0)
	_, err := w.Write(bnd.appendTo(b))
	return err
}

// Datagram is a parsed datagram, RFC 1928 section 7. Name and Payload alias the bytes it
// was parsed from, and Name is nil for an IP address.
type Datagram struct {
	IP      netip.Addr
	Name    []byte
	Payload []byte
	Port    uint16
}

func (d Datagram) Addr() Addr {
	return Addr{Name: string(d.Name), IP: d.IP, Port: d.Port}
}

// ParseDatagram splits a datagram into its destination and its payload without copying
// either. Reassembly is optional and not done, so a fragment is refused with [ErrFragmented].
func ParseDatagram(b []byte) (Datagram, error) {
	if len(b) < 4 {
		return Datagram{}, ErrShort
	}
	if b[2] != 0 {
		return Datagram{}, ErrFragmented
	}
	var d Datagram
	n := 4
	switch b[3] {
	case atypIPv4:
		if len(b) < n+4+2 {
			return Datagram{}, ErrShort
		}
		d.IP = netip.AddrFrom4([4]byte(b[n : n+4]))
		n += 4
	case atypIPv6:
		if len(b) < n+16+2 {
			return Datagram{}, ErrShort
		}
		d.IP = netip.AddrFrom16([16]byte(b[n : n+16]))
		n += 16
	case atypDomain:
		if len(b) < n+1 {
			return Datagram{}, ErrShort
		}
		l := int(b[n])
		n++
		if l == 0 {
			return Datagram{}, ErrNameLength
		}
		if len(b) < n+l+2 {
			return Datagram{}, ErrShort
		}
		d.Name = b[n : n+l]
		n += l
	default:
		return Datagram{}, ErrAddressType
	}
	d.Port = uint16(b[n])<<8 | uint16(b[n+1])
	d.Payload = b[n+2:]
	return d, nil
}

// DatagramHeaderLen returns the size of the header AppendDatagramHeader writes for addr.
func DatagramHeaderLen(addr Addr) int { return 3 + addr.encodedLen() }

// AppendDatagramHeader appends the header of a datagram addressed to or from addr.
func AppendDatagramHeader(b []byte, addr Addr) []byte {
	b = append(b, 0, 0, 0)
	return addr.appendTo(b)
}
