// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package socks5

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestRequest_RoundTrip(t *testing.T) {
	addrs := []Addr{
		{IP: netip.MustParseAddr("10.0.0.1"), Port: 443},
		{IP: netip.MustParseAddr("2001:db8::1"), Port: 8443},
		{Name: "example.test", Port: 80},
		{Name: strings.Repeat("a", 255), Port: 1},
	}
	for _, want := range addrs {
		var buf bytes.Buffer
		if err := WriteRequest(&buf, CmdConnect, want); err != nil {
			t.Fatalf("write %v: %v", want, err)
		}
		cmd, got, err := ReadRequest(&buf)
		if err != nil {
			t.Fatalf("read %v: %v", want, err)
		}
		if cmd != CmdConnect || got != want {
			t.Fatalf("got %d %v, want %d %v", cmd, got, CmdConnect, want)
		}
		if buf.Len() != 0 {
			t.Fatalf("%d bytes left after %v", buf.Len(), want)
		}
	}
}

func TestReply_ErrorOnFailure(t *testing.T) {
	var buf bytes.Buffer
	bnd := Addr{IP: netip.IPv4Unspecified(), Port: 0}
	if err := WriteReply(&buf, NotAllowed, bnd); err != nil {
		t.Fatal(err)
	}
	rep, got, err := ReadReply(&buf)
	if !errors.Is(err, NotAllowed) || rep != NotAllowed || got != bnd {
		t.Fatalf("got %v %v %v", rep, got, err)
	}

	buf.Reset()
	if err := WriteReply(&buf, Succeeded, bnd); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadReply(&buf); err != nil {
		t.Fatal(err)
	}
}

func TestMethods_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMethods(&buf, MethodNoAuth, MethodPassword); err != nil {
		t.Fatal(err)
	}
	methods, err := ReadMethods(&buf)
	if err != nil || !bytes.Equal(methods, []byte{MethodNoAuth, MethodPassword}) {
		t.Fatalf("got %v %v", methods, err)
	}
	if err := WriteMethod(&buf, MethodPassword); err != nil {
		t.Fatal(err)
	}
	if m, err := ReadMethod(&buf); err != nil || m != MethodPassword {
		t.Fatalf("got %d %v", m, err)
	}
	if _, err := ReadMethods(bytes.NewReader([]byte{4, 1, 0})); !errors.Is(err, ErrVersion) {
		t.Fatalf("got %v, want ErrVersion", err)
	}
}

func TestCredentials_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	long := strings.Repeat("p", 255)
	if err := WriteCredentials(&buf, "alice", long); err != nil {
		t.Fatal(err)
	}
	user, pass, err := ReadCredentials(&buf)
	if err != nil || user != "alice" || pass != long {
		t.Fatalf("got %q %q %v", user, pass, err)
	}
	buf.Reset()
	for _, c := range [][2]string{{strings.Repeat("u", 256), "p"}, {"", "p"}, {"u", ""}} {
		if err := WriteCredentials(&buf, c[0], c[1]); !errors.Is(err, ErrCredentials) {
			t.Fatalf("username of %d bytes and password of %d bytes: got %v, want ErrCredentials", len(c[0]), len(c[1]), err)
		}
	}
	if buf.Len() != 0 {
		t.Fatalf("refused credentials wrote %x", buf.Bytes())
	}

	buf.Reset()
	if err := WriteCredentialsStatus(&buf, false); err != nil {
		t.Fatal(err)
	}
	if err := ReadCredentialsStatus(&buf); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("got %v, want ErrAuthFailed", err)
	}
	if err := WriteCredentialsStatus(&buf, true); err != nil {
		t.Fatal(err)
	}
	if err := ReadCredentialsStatus(&buf); err != nil {
		t.Fatal(err)
	}
}

func TestDatagram_RoundTrip(t *testing.T) {
	addr := Addr{Name: "dns.test", Port: 53}
	payload := []byte("query")
	b := AppendDatagramHeader(nil, addr)
	if len(b) != DatagramHeaderLen(addr) {
		t.Fatalf("header is %d bytes, DatagramHeaderLen reports %d", len(b), DatagramHeaderLen(addr))
	}
	b = append(b, payload...)
	got, err := ParseDatagram(b)
	if err != nil || got.Addr() != addr || !bytes.Equal(got.Payload, payload) {
		t.Fatalf("got %v %q %v", got, got.Payload, err)
	}

	b[2] = 1
	if _, err := ParseDatagram(b); !errors.Is(err, ErrFragmented) {
		t.Fatalf("got %v, want ErrFragmented", err)
	}
	if _, err := ParseDatagram(b[:3]); !errors.Is(err, ErrShort) {
		t.Fatalf("got %v, want ErrShort", err)
	}
}

func TestAddr_String(t *testing.T) {
	cases := map[Addr]string{
		{IP: netip.MustParseAddr("::1"), Port: 53}:      "[::1]:53",
		{IP: netip.MustParseAddr("127.0.0.1"), Port: 1}: "127.0.0.1:1",
		{Name: "example.test", Port: 443}:               "example.test:443",
	}
	for addr, want := range cases {
		if got := addr.String(); got != want {
			t.Errorf("%v: got %q, want %q", addr, got, want)
		}
	}
}

func FuzzParseDatagram(f *testing.F) {
	f.Add(AppendDatagramHeader(nil, Addr{Name: "a", Port: 1}))
	f.Add(AppendDatagramHeader(nil, Addr{IP: netip.IPv6Unspecified(), Port: 1}))
	f.Fuzz(func(t *testing.T, b []byte) {
		dg, err := ParseDatagram(b)
		if err != nil {
			return
		}
		again := AppendDatagramHeader(nil, dg.Addr())
		again = append(again, dg.Payload...)
		// The reserved bytes are not read, so they are not re-encoded.
		b[0], b[1] = 0, 0
		if !bytes.Equal(again, b) {
			t.Fatalf("datagram %x re-encodes as %x", b, again)
		}
	})
}

func FuzzReadRequest(f *testing.F) {
	var seed bytes.Buffer
	_ = WriteRequest(&seed, CmdAssociate, Addr{Name: "example.test", Port: 1080})
	f.Add(seed.Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		cmd, addr, err := ReadRequest(bytes.NewReader(b))
		if err != nil {
			return
		}
		var again bytes.Buffer
		if err := WriteRequest(&again, cmd, addr); err != nil {
			t.Fatalf("request %x read as %d %v cannot be written: %v", b, cmd, addr, err)
		}
		b[2] = 0
		if !bytes.HasPrefix(b, again.Bytes()) {
			t.Fatalf("request %x re-encodes as %x", b, again.Bytes())
		}
	})
}
