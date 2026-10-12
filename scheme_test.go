package edge

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type h2Frames struct {
	types  []http2.FrameType
	blocks [][]hpack.HeaderField
	data   []string
}

// readSchemeConn reads what a schemeConn hands the server, decoding each header block.
func readSchemeConn(t *testing.T, c net.Conn) h2Frames {
	t.Helper()
	preface := make([]byte, len(http2.ClientPreface))
	_, err := io.ReadFull(c, preface)
	require.NoError(t, err)
	require.Equal(t, http2.ClientPreface, string(preface))

	rd := http2.NewFramer(nil, c)
	rd.SetMaxReadFrameSize(h2MaxReadFrameSize)
	dec := hpack.NewDecoder(h2HeaderTableSize, nil)
	dec.SetMaxStringLength(4 << 20)
	var got h2Frames
	var block []byte
	for {
		f, err := rd.ReadFrame()
		if errors.Is(err, io.EOF) {
			return got
		}
		require.NoError(t, err)
		got.types = append(got.types, f.Header().Type)
		ended := false
		switch f := f.(type) {
		case *http2.HeadersFrame:
			block = append(block[:0], f.HeaderBlockFragment()...)
			ended = f.HeadersEnded()
		case *http2.ContinuationFrame:
			block = append(block, f.HeaderBlockFragment()...)
			ended = f.HeadersEnded()
		case *http2.DataFrame:
			got.data = append(got.data, string(f.Data()))
		}
		if ended {
			fields, err := dec.DecodeFull(block)
			require.NoError(t, err)
			got.blocks = append(got.blocks, fields)
		}
	}
}

func sensitive(name, value string) hpack.HeaderField {
	return hpack.HeaderField{Name: name, Value: value, Sensitive: true}
}

func TestSchemeConn_EveryRequestGetsItsSchemeField(t *testing.T) {
	cli, srv := net.Pipe()
	defer func() { _ = srv.Close() }()
	written := make(chan error, 1)
	go func() {
		defer func() { _ = cli.Close() }()
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		block := func(fields ...hpack.HeaderField) []byte {
			buf.Reset()
			for _, f := range fields {
				_ = enc.WriteField(f)
			}
			return bytes.Clone(buf.Bytes())
		}
		fr := http2.NewFramer(cli, nil)
		first := block(hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "a.test"), hf(":path", "/"), hf("x-kept", "one"))
		second := block(hf(":method", "GET"), hf(":scheme", "https"), hf(":authority", "a.test"), hf(":path", "/"), hf("x-kept", "one"))
		written <- errors.Join(
			func() error { _, err := io.WriteString(cli, http2.ClientPreface); return err }(),
			fr.WriteSettings(),
			fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: 1, BlockFragment: first[:3], EndStream: true, PadLength: 7,
				Priority: http2.PriorityParam{Weight: 15},
			}),
			fr.WriteContinuation(1, true, first[3:]),
			fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: second, EndHeaders: true, PadLength: 3}),
			fr.WriteData(3, false, []byte("body")),
			fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: 3, BlockFragment: block(hf("x-kept", "one"), hf("x-trailer", "two")), EndHeaders: true, EndStream: true,
			}),
			fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: 5, BlockFragment: block(hf(":method", "CONNECT"), hf(":authority", "b.test:443")), EndHeaders: true,
			}),
		)
	}()

	got := readSchemeConn(t, newSchemeConn(srv, 1<<20))
	require.NoError(t, <-written)

	assert.Equal(t, []http2.FrameType{
		http2.FrameSettings, http2.FrameHeaders, http2.FrameContinuation, http2.FrameHeaders,
		http2.FrameData, http2.FrameHeaders, http2.FrameHeaders,
	}, got.types)
	require.Len(t, got.blocks, 4)
	assert.Equal(t, []hpack.HeaderField{
		hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "a.test"), hf(":path", "/"), hf("x-kept", "one"), sensitive(schemeName, "h"),
	}, got.blocks[0])
	assert.Equal(t, []hpack.HeaderField{
		hf(":method", "GET"), hf(":scheme", "https"), hf(":authority", "a.test"), hf(":path", "/"), hf("x-kept", "one"), sensitive(schemeName, "s"),
	}, got.blocks[1])
	assert.Equal(t, []hpack.HeaderField{hf("x-kept", "one"), hf("x-trailer", "two")}, got.blocks[2])
	assert.Equal(t, []hpack.HeaderField{hf(":method", "CONNECT"), hf(":authority", "b.test:443"), sensitive(schemeName, "-")}, got.blocks[3])
	assert.Equal(t, []string{"body"}, got.data)
}

func TestSchemeConn_FullFrameEndsWithAContinuation(t *testing.T) {
	var buf bytes.Buffer
	encode := func(n int) []byte {
		buf.Reset()
		enc := hpack.NewEncoder(&buf)
		for _, f := range []hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "https"), hf(":authority", "a.test"), hf(":path", "/"), hf("x-big", strings.Repeat("a", n))} {
			_ = enc.WriteField(f)
		}
		return bytes.Clone(buf.Bytes())
	}
	// A padded HEADERS frame is the pad length, the block and the padding.
	n := h2MaxReadFrameSize
	block := encode(n)
	pad := h2MaxReadFrameSize - 1 - len(block)
	for pad < 0 || pad > 255 {
		n += (pad - 128) * 8 / 5
		block = encode(n)
		pad = h2MaxReadFrameSize - 1 - len(block)
	}

	cli, srv := net.Pipe()
	defer func() { _ = srv.Close() }()
	written := make(chan error, 1)
	go func() {
		defer func() { _ = cli.Close() }()
		fr := http2.NewFramer(cli, nil)
		written <- errors.Join(
			func() error { _, err := io.WriteString(cli, http2.ClientPreface); return err }(),
			fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true, PadLength: uint8(pad),
			}),
		)
	}()

	got := readSchemeConn(t, newSchemeConn(srv, 4<<20))
	require.NoError(t, <-written)

	assert.Equal(t, []http2.FrameType{http2.FrameHeaders, http2.FrameContinuation}, got.types)
	require.Len(t, got.blocks, 1)
	assert.Equal(t, sensitive(schemeName, "s"), got.blocks[0][len(got.blocks[0])-1])
}

func TestSchemeConn_ShortHTTP1RequestIsNotHeld(t *testing.T) {
	cli, srv := net.Pipe()
	defer func() { _ = cli.Close() }()
	defer func() { _ = srv.Close() }()
	const req = "GET / HTTP/1.1\r\n\r\n"
	go func() { _, _ = io.WriteString(cli, req) }()

	sc := newSchemeConn(srv, 1<<20)
	require.NoError(t, sc.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 64)
	n, err := io.ReadAtLeast(sc, buf, len(req))
	require.NoError(t, err)
	assert.Equal(t, req, string(buf[:n]))
}

func TestSchemeConn_PassesUnchanged(t *testing.T) {
	var truncated bytes.Buffer
	require.NoError(t, http2.NewFramer(&truncated, nil).WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: hpRequest(hpHTTP, []byte{0x00}, hpackStr("x-abc"), []byte{0x0f}), EndHeaders: true, EndStream: true,
	}))
	oversized := []byte{byte((h2MaxReadFrameSize + 1) >> 16), 0, 1, h2FrameHeaders, h2FlagEndHeaders, 0, 0, 0, 1}
	oversized = append(oversized, hpRequest(hpHTTP)...)

	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{name: "a truncated block", frame: truncated.Bytes()},
		{name: "a frame larger than the server reads", frame: oversized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := net.Pipe()
			defer func() { _ = srv.Close() }()
			wire := slices.Concat([]byte(http2.ClientPreface), tc.frame)
			go func() {
				_, _ = cli.Write(wire)
				_ = cli.Close()
			}()
			got, err := io.ReadAll(newSchemeConn(srv, 1<<20))
			require.NoError(t, err)
			assert.Equal(t, wire, got)
		})
	}
}

func TestSchemeConn_HeldFrameResumesAfterADeadline(t *testing.T) {
	cli, srv := net.Pipe()
	defer func() { _ = cli.Close() }()
	defer func() { _ = srv.Close() }()
	var frame bytes.Buffer
	block := hpRequest(hpHTTPS, hpLiteral("x-a", "1"))
	require.NoError(t, http2.NewFramer(&frame, nil).WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true,
	}))
	wire := slices.Concat([]byte(http2.ClientPreface), frame.Bytes())
	half := len(http2.ClientPreface) + 9 + len(block)/2
	go func() { _, _ = cli.Write(wire[:half]) }()

	sc := newSchemeConn(srv, 1<<20)
	preface := make([]byte, len(http2.ClientPreface))
	_, err := io.ReadFull(sc, preface)
	require.NoError(t, err)
	require.NoError(t, sc.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	n, err := sc.Read(make([]byte, 64))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	assert.Zero(t, n)

	require.NoError(t, sc.SetReadDeadline(time.Now().Add(5*time.Second)))
	go func() { _, _ = cli.Write(wire[half:]) }()
	f, err := http2.NewFramer(nil, sc).ReadFrame()
	require.NoError(t, err)
	h, ok := f.(*http2.HeadersFrame)
	require.True(t, ok)
	fields, err := hpack.NewDecoder(h2HeaderTableSize, nil).DecodeFull(h.HeaderBlockFragment())
	require.NoError(t, err)
	assert.Equal(t, []hpack.HeaderField{
		hf(":method", "GET"), hf(":scheme", "https"), hf(":path", "/"), hf(":authority", "origin.test"), hf("x-a", "1"), sensitive(schemeName, "s"),
	}, fields)
}

// eofConn returns io.EOF with its last bytes.
type eofConn struct {
	net.Conn
	r *bytes.Reader
}

func (c *eofConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err == nil && c.r.Len() == 0 {
		err = io.EOF
	}
	return n, err
}

func TestSchemeConn_FrameEndingWithEOFGetsItsField(t *testing.T) {
	var wire bytes.Buffer
	wire.WriteString(http2.ClientPreface)
	require.NoError(t, http2.NewFramer(&wire, nil).WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: hpRequest(hpHTTPS, hpLiteral("x-big", strings.Repeat("a", 10<<10))), EndHeaders: true, EndStream: true,
	}))

	got := readSchemeConn(t, newSchemeConn(&eofConn{r: bytes.NewReader(wire.Bytes())}, 1<<20))
	require.Len(t, got.blocks, 1)
	assert.Equal(t, sensitive(schemeName, "s"), got.blocks[0][len(got.blocks[0])-1])
}

func TestSchemeConn_LargeFrameIsReleased(t *testing.T) {
	cli, srv := net.Pipe()
	defer func() { _ = srv.Close() }()
	written := make(chan error, 1)
	go func() {
		defer func() { _ = cli.Close() }()
		fr := http2.NewFramer(cli, nil)
		written <- errors.Join(
			func() error { _, err := io.WriteString(cli, http2.ClientPreface); return err }(),
			fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: 1, BlockFragment: hpRequest(hpHTTPS, hpLiteral("x-big", strings.Repeat("a", 2*schemeOutKeep))), EndHeaders: true, EndStream: true,
			}),
			fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: hpRequest(hpHTTP), EndHeaders: true, EndStream: true}),
		)
	}()

	sc := newSchemeConn(srv, 1<<20)
	got := readSchemeConn(t, sc)
	require.NoError(t, <-written)

	require.Len(t, got.blocks, 2)
	assert.Equal(t, sensitive(schemeName, "s"), got.blocks[0][len(got.blocks[0])-1])
	assert.Equal(t, sensitive(schemeName, "h"), got.blocks[1][len(got.blocks[1])-1])
	assert.LessOrEqual(t, cap(schemeConnOf(sc).out), schemeOutKeep)
}

func BenchmarkSchemeConn(b *testing.B) {
	var wire, block bytes.Buffer
	wire.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&wire, nil)
	enc := hpack.NewEncoder(&block)
	for i := range 1000 {
		block.Reset()
		for _, f := range []hpack.HeaderField{
			hf(":method", "GET"), hf(":scheme", "https"), hf(":authority", "origin.test"), hf(":path", fmt.Sprintf("/items/%d", i)),
			hf("user-agent", "bench/1.0"), hf("accept", "*/*"), hf("accept-language", "en"), hf("cache-control", "no-cache"),
			hf("x-request-id", fmt.Sprintf("%08d", i)), hf("cookie", "session=0123456789abcdef"),
		} {
			require.NoError(b, enc.WriteField(f))
		}
		require.NoError(b, fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID: uint32(2*i + 1), BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true,
		}))
	}
	data := wire.Bytes()
	conn := new(bytesConn)
	preface := make([]byte, len(http2.ClientPreface))
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		conn.r.Reset(data)
		sc := newSchemeConn(conn, 1<<20)
		if _, err := io.ReadFull(sc, preface); err != nil {
			b.Fatal(err)
		}
		rd := http2.NewFramer(nil, sc)
		for {
			if _, err := rd.ReadFrame(); err != nil {
				if !errors.Is(err, io.EOF) {
					b.Fatal(err)
				}
				break
			}
		}
	}
}

func TestServe_HTTP2SchemeReachesTheHandler(t *testing.T) {
	p := testProxy(t)
	type seen struct{ scheme, field, added string }
	got := make(chan seen, 2)
	p.MustAdd("origin.test/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		got <- seen{c.Scheme(), c.Header("Edge-Scheme"), c.Header(schemeHeader)}
		return Text(http.StatusOK, "ok"), nil
	})
	h := dialH2(t, startProxy(t, p))

	h.headers(t, 1, true, hf(":method", "GET"), hf(":scheme", "https"), hf(":authority", "origin.test"), hf(":path", "/"))
	assert.Equal(t, "ok", string(h.reply(t, 1).body))
	assert.Equal(t, seen{scheme: "https"}, <-got)

	h.headers(t, 3, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"),
		hf("edge-scheme", "s"))
	assert.Equal(t, "ok", string(h.reply(t, 3).body))
	assert.Equal(t, seen{scheme: "http", field: "s"}, <-got, "the field the client sent is its own")
}

func TestServe_HTTP2InvalidFieldResetsItsStreamAlone(t *testing.T) {
	p := testProxy(t)
	p.MustAdd("origin.test/*{any}", func(*HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, "ok"), nil
	})
	h := dialH2(t, startProxy(t, p))

	h.headers(t, 1, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"),
		hf("X-Upper", "v"))
	got := h.reply(t, 1)
	assert.True(t, got.reset)
	assert.Equal(t, http2.ErrCodeProtocol, got.rst)

	h.headers(t, 3, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"))
	assert.Equal(t, "ok", string(h.reply(t, 3).body))
}

func TestServe_HTTP2HeaderListPastTheLimitIsAnswered431(t *testing.T) {
	p := testProxy(t, WithMaxHeaderBytes(1024))
	p.MustAdd("origin.test/*{any}", func(*HTTPCtx) (*http.Response, error) {
		return Text(http.StatusOK, "ok"), nil
	})
	h := dialH2(t, startProxy(t, p))

	fields := []hpack.HeaderField{hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/")}
	for i := range 20 {
		fields = append(fields, hf("x-big-"+string(rune('a'+i)), strings.Repeat("v", 100)))
	}
	h.headers(t, 1, true, fields...)
	status, _ := h2Field(h.reply(t, 1).fields, ":status")
	assert.Equal(t, "431", status)

	h.headers(t, 3, true, hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "origin.test"), hf(":path", "/"))
	assert.Equal(t, "ok", string(h.reply(t, 3).body))
}

func TestServe_HTTP2OverpaddedHeadersIgnoresItsContinuations(t *testing.T) {
	b := newHPACKBench(t, viaH2C)
	c := b.dial(t)
	frag := hpRequest(hpHTTP)
	require.NoError(t, c.fr.WriteRawFrame(http2.FrameHeaders, http2.FlagHeadersEndStream|http2.FlagHeadersPadded, 1,
		append([]byte{byte(len(frag) + 1)}, frag...)))
	require.NoError(t, c.fr.WriteContinuation(1, true, []byte{0x00, 0x05}))
	got := c.outcome(t, 1)
	if isConnError(got, http2.ErrCodeProtocol) {
		return
	}
	require.True(t, got.reset, "%+v", got)
	b.served(t, c, 3, hpRequest(hpHTTP), "http")
}

func TestConformanceHPACK(t *testing.T) { runConformance(t, hpackConformance) }

const (
	viaH2C           = "h2c"
	viaConnectH2     = "connect-h2"
	viaRedirectedH2  = "redirected-h2"
	viaRedirectedH2C = "redirected-h2c"
)

var hpackFronts = []string{viaH2C, viaH2, viaConnectH2, viaRedirectedH2, viaRedirectedH2C}

func eachHPACKFront(t *testing.T, run func(t *testing.T, front string)) {
	t.Helper()
	eachH2Front(t, hpackFronts, run)
}

// startHPACKFront serves p on front: the explicit front over plaintext or TLS, the explicit
// front for a CONNECT tunnel, or a transparent front whose connections were headed to port 443
// or to unroutedDestination.
func startHPACKFront(t *testing.T, front string, p *Proxy, ca *CA) string {
	t.Helper()
	switch front {
	case viaH2:
		addr, _ := startProxyTLS(t, p, ca)
		return addr
	case viaRedirectedH2:
		return startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
			return netip.MustParseAddrPort("192.0.2.1:443"), nil
		})
	case viaRedirectedH2C:
		return startTransparentRedirected(t, p, func(net.Conn) (netip.AddrPort, error) {
			return unroutedDestination, nil
		})
	}
	return startProxy(t, p)
}

// dialH2Front returns a connection to front at addr on which HTTP/2 starts with the client
// preface. A CONNECT tunnel or a transparent TLS connection is opened for name.
func dialH2Front(t *testing.T, front, addr string, ca *CA, name string) net.Conn {
	t.Helper()
	var c net.Conn
	switch front {
	case viaH2:
		c = dialFront(t, netip.MustParseAddrPort(addr), ca, viaH2)
	case viaConnectH2:
		c = connectRaw(t, addr, name+":443")
	default:
		var err error
		c, err = net.DialTimeout("tcp", addr, 5*time.Second)
		require.NoError(t, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.SetDeadline(time.Now().Add(10*time.Second)))
	if front == viaConnectH2 || front == viaRedirectedH2 {
		tc := tls.Client(c, &tls.Config{ServerName: name, RootCAs: poolOf(ca), NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
		require.NoError(t, tc.Handshake())
		require.Equal(t, "h2", tc.ConnectionState().NegotiatedProtocol)
		c = tc
	}
	return c
}

// dialH2Wire serves p on front and returns an HTTP/2 connection to it past the client preface.
func dialH2Wire(t *testing.T, front string, p *Proxy, name string) *h2Wire {
	t.Helper()
	c := dialH2Front(t, front, startHPACKFront(t, front, p, p.cfg.ca), p.cfg.ca, name)
	_, err := io.WriteString(c, http2.ClientPreface)
	require.NoError(t, err)
	h := newH2Wire(c)
	require.NoError(t, h.fr.WriteSettings())
	return h
}

// frontScheme returns sent, or the scheme of the connection on a connection edge terminates.
func frontScheme(front, sent string) string {
	switch front {
	case viaConnectH2, viaRedirectedH2:
		return "https"
	case viaRedirectedH2C:
		return "http"
	}
	return sent
}

type hpackSeen struct {
	header http.Header
	scheme string
	host   string
	path   string
}

type hpackBench struct {
	seen  chan hpackSeen
	ca    *CA
	front string
	addr  string
}

func newHPACKBench(t *testing.T, front string, opts ...ProxyOption) *hpackBench {
	t.Helper()
	ca, err := GenerateCA()
	require.NoError(t, err)
	p := testProxyWithCA(t, ca, opts...)
	b := &hpackBench{seen: make(chan hpackSeen, 32), ca: ca, front: front}
	p.MustAdd("+{any}/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		r := c.Request()
		// The trailers of a request must reach the server before its stream is closed.
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return nil, err
		}
		b.seen <- hpackSeen{header: r.Header.Clone(), scheme: c.Scheme(), host: c.Host(), path: r.URL.Path}
		return Text(http.StatusOK, "ok"), nil
	})
	b.addr = startHPACKFront(t, front, p, ca)
	return b
}

func (b *hpackBench) dial(t *testing.T) *hpackConn {
	t.Helper()
	return b.dialFor(t, "origin.test")
}

// dialFor is dial with a TLS connection opened for name.
func (b *hpackBench) dialFor(t *testing.T, name string) *hpackConn {
	t.Helper()
	return dialHPACK(t, b.front, b.addr, b.ca, name)
}

func (b *hpackBench) next(t *testing.T) hpackSeen {
	t.Helper()
	select {
	case s := <-b.seen:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("the handler was not reached")
		return hpackSeen{}
	}
}

func (b *hpackBench) none(t *testing.T) {
	t.Helper()
	select {
	case s := <-b.seen:
		t.Fatalf("the handler was reached with %+v", s)
	default:
	}
}

// served sends block as a request on stream and returns what the handler received.
func (b *hpackBench) served(t *testing.T, c *hpackConn, stream uint32, block []byte, scheme string) hpackSeen {
	t.Helper()
	c.block(t, stream, block)
	require.Equal(t, h2Outcome{status: "200"}, c.outcome(t, stream))
	s := b.next(t)
	assert.Equal(t, b.scheme(scheme), s.scheme)
	assert.Empty(t, s.header.Values(schemeHeader))
	return s
}

func (b *hpackBench) scheme(sent string) string { return frontScheme(b.front, sent) }

type hpackConn struct {
	*h2Wire
	settings map[http2.SettingID]uint32
}

func dialHPACK(t *testing.T, front, addr string, ca *CA, name string) *hpackConn {
	t.Helper()
	c := dialH2Front(t, front, addr, ca, name)
	_, err := io.WriteString(c, http2.ClientPreface)
	require.NoError(t, err)

	fr := http2.NewFramer(c, c)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	require.NoError(t, fr.WriteSettings())
	f, err := fr.ReadFrame()
	require.NoError(t, err)
	sf, ok := f.(*http2.SettingsFrame)
	require.True(t, ok && !sf.IsAck(), "the server preface is a SETTINGS frame")
	settings := make(map[http2.SettingID]uint32)
	require.NoError(t, sf.ForeachSetting(func(s http2.Setting) error { settings[s.ID] = s.Val; return nil }))
	require.NoError(t, fr.WriteSettingsAck())
	return &hpackConn{h2Wire: &h2Wire{fr: fr}, settings: settings}
}

func (c *hpackConn) block(t *testing.T, stream uint32, block []byte) {
	t.Helper()
	require.NoError(t, c.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: stream, BlockFragment: block, EndHeaders: true, EndStream: true,
	}))
}

func (c *hpackConn) setting(id http2.SettingID, initial uint32) uint32 {
	if v, ok := c.settings[id]; ok {
		return v
	}
	return initial
}

type h2Outcome struct {
	status string
	rst    http2.ErrCode
	goaway http2.ErrCode
	reset  bool
	away   bool
	closed bool
}

// outcome reads until stream ends or is reset, or the connection fails. Stream 0 stands for
// the first stream to end.
func (c *hpackConn) outcome(t *testing.T, stream uint32) h2Outcome {
	t.Helper()
	var o h2Outcome
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			require.False(t, isTimeout(err), "no frame before the deadline")
			o.closed = true
			return o
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				require.NoError(t, c.fr.WriteSettingsAck())
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				require.NoError(t, c.fr.WritePing(true, f.Data))
			}
		case *http2.GoAwayFrame:
			o.away, o.goaway = true, f.ErrCode
			for err == nil {
				_, err = c.fr.ReadFrame()
			}
			o.closed = !isTimeout(err)
			return o
		case *http2.RSTStreamFrame:
			if stream == 0 || f.StreamID == stream {
				o.reset, o.rst = true, f.ErrCode
				return o
			}
		case *http2.MetaHeadersFrame:
			if stream == 0 || f.StreamID == stream {
				if o.status == "" {
					o.status, _ = h2Field(f.Fields, ":status")
				}
				if f.StreamEnded() {
					return o
				}
			}
		case *http2.DataFrame:
			if (stream == 0 || f.StreamID == stream) && f.StreamEnded() {
				return o
			}
		}
	}
}

// orGeneric reports whether got is want or one of the generic codes RFC 9113 section 5.4
// allows in its place.
func orGeneric(got, want http2.ErrCode) bool {
	return got == want || got == http2.ErrCodeProtocol || got == http2.ErrCodeInternal
}

// isConnError reports whether o is a GOAWAY of type code followed by the end of the
// connection.
func isConnError(o h2Outcome, code http2.ErrCode) bool {
	return o.away && o.closed && orGeneric(o.goaway, code)
}

// isMalformed reports whether o is an outcome RFC 9113 section 8.1.1 allows for a malformed
// request, a 4xx response, a stream error of type PROTOCOL_ERROR or that stream error treated
// as a connection error.
func isMalformed(o h2Outcome) bool {
	switch {
	case o.away:
		return isConnError(o, http2.ErrCodeProtocol)
	case o.reset:
		return orGeneric(o.rst, http2.ErrCodeProtocol)
	}
	return len(o.status) == 3 && o.status[0] == '4'
}

func assertConnError(t *testing.T, o h2Outcome, code http2.ErrCode) {
	t.Helper()
	assert.True(t, isConnError(o, code), "a connection error of type %v, got %+v", code, o)
}

func assertMalformed(t *testing.T, o h2Outcome) {
	t.Helper()
	assert.True(t, isMalformed(o), "a malformed request outcome, got %+v", o)
}

// hpackInt encodes n on an N-bit prefix below the pattern bits of first, RFC 7541 section 5.1.
func hpackInt(first byte, prefix uint, n uint64) []byte {
	limit := uint64(1)<<prefix - 1
	if n < limit {
		return []byte{first | byte(n)}
	}
	b := []byte{first | byte(limit)}
	for n -= limit; n >= 128; n >>= 7 {
		b = append(b, byte(n%128+128))
	}
	return append(b, byte(n))
}

func hpackStr(s string) []byte { return append(hpackInt(0, 7, uint64(len(s))), s...) }

func hpackHuffman(code ...byte) []byte { return append(hpackInt(0x80, 7, uint64(len(code))), code...) }

func hpIndexed(i uint64) []byte { return hpackInt(0x80, 7, i) }

func hpLiteral(name, value string) []byte {
	return slices.Concat([]byte{0x00}, hpackStr(name), hpackStr(value))
}

func hpIndexing(name, value string) []byte {
	return slices.Concat([]byte{0x40}, hpackStr(name), hpackStr(value))
}

func hpNeverIndexed(name, value string) []byte {
	return slices.Concat([]byte{0x10}, hpackStr(name), hpackStr(value))
}

func hpSizeUpdate(n uint64) []byte { return hpackInt(0x20, 5, n) }

// hpRequest is a GET for origin.test whose :scheme is encoded as scheme, followed by fields.
// Its own field lines leave the dynamic table untouched.
func hpRequest(scheme []byte, fields ...[]byte) []byte {
	head := slices.Concat([]byte{0x82}, scheme, []byte{0x84}, hpackInt(0x00, 4, 1), hpackStr("origin.test"))
	return slices.Concat(append([][]byte{head}, fields...)...)
}

var (
	hpHTTP  = []byte{0x86}
	hpHTTPS = []byte{0x87}
)

func hpackVector(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "rfc7541-"+name+".hex"))
	require.NoError(t, err)
	out, err := hex.DecodeString(strings.Join(strings.Fields(string(b)), ""))
	require.NoError(t, err)
	return out
}

// maxFrameRequest is a request in one padded HEADERS frame of exactly size octets, ending
// with a field line called name.
func maxFrameRequest(t *testing.T, size int, name string) http2.HeadersFrameParam {
	t.Helper()
	head := hpRequest(hpHTTPS)
	n := size - 1 - len(head) - len(hpLiteral(name, ""))
	for range 2 {
		block := slices.Concat(head, hpLiteral(name, strings.Repeat("a", n)))
		if pad := size - 1 - len(block); pad >= 0 && pad <= 255 {
			return http2.HeadersFrameParam{
				StreamID: 1, BlockFragment: block, EndHeaders: true, EndStream: true, PadLength: uint8(pad),
			}
		}
		n -= 8
	}
	t.Fatal("no padding fits the frame")
	return http2.HeadersFrameParam{}
}

type hpackStory struct {
	Cases []struct {
		Wire string `json:"wire"`
	} `json:"cases"`
}

const hpackNeverIndexed = "edge forwards fields through http.Header, which has no never-indexed representation, and net/http's HTTP/2 encoders index any field not marked sensitive that fits the table"

// hpackConformance lists the requirements RFC 7541 and RFC 9113 place on the field blocks of
// HTTP/2 requests, checked with a raw client on each of hpackFronts.
var hpackConformance = []conformanceCase{
	// RFC 7541 section 2.1, header list ordering.
	{
		id: "rfc7541/2.1/1", name: "a request with three values of one field and two edge-scheme field lines of its own",
		req: "A decoder MUST order header fields in the decoded header list according to their ordering in the header block.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				c.block(t, 1, hpRequest(hpHTTP, hpLiteral("x-a", "1"), hpLiteral("edge-scheme", "s"), hpLiteral("x-b", "2"),
					hpLiteral("x-a", "3"), hpLiteral("edge-scheme", "h"), hpLiteral("x-a", "4")))
				require.Equal(t, h2Outcome{status: "200"}, c.outcome(t, 1))
				s := b.next(t)
				assert.Equal(t, b.scheme("http"), s.scheme)
				assert.Equal(t, []string{"1", "3", "4"}, s.header.Values("X-A"))
				assert.Equal(t, []string{"2"}, s.header.Values("X-B"))
				assert.Equal(t, []string{"s", "h"}, s.header.Values("Edge-Scheme"))
			})
		},
	},

	// RFC 7541 section 2.3, indexing tables.
	{
		id: "rfc7541/2.3.2/1", name: "two requests inserting the same field, then a request referencing both entries",
		req: "Therefore, duplicate entries MUST NOT be treated as an error by a decoder.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				b.served(t, c, 1, hpRequest(hpHTTP, hpIndexing("x-dup", "v")), "http")
				b.served(t, c, 3, hpRequest(hpHTTP, hpIndexing("x-dup", "v")), "http")
				s := b.served(t, c, 5, hpRequest(hpHTTP, hpIndexed(62), hpIndexed(63)), "http")
				assert.Equal(t, []string{"v", "v"}, s.header.Values("X-Dup"))
			})
		},
	},
	{
		id: "rfc7541/2.3.3/1", name: "an indexed field past the end of the dynamic table",
		req: "Indices strictly greater than the sum of the lengths of both tables MUST be treated as a decoding error.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				c.block(t, 1, hpRequest(hpHTTP, hpIndexed(70)))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeCompression)
				b.none(t)
			})
		},
	},
	{
		id: "rfc7541/2.3.3/2", name: "a literal whose name index is past the end of the dynamic table",
		req: "Indices strictly greater than the sum of the lengths of both tables MUST be treated as a decoding error.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				c.block(t, 1, hpRequest(hpHTTP, slices.Concat(hpackInt(0x00, 4, 70), hpackStr("v"))))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeCompression)
				b.none(t)
			})
		},
	},

	// RFC 7541 section 3.2, header field representation processing.
	{
		id: "rfc7541/3.2/1", name: "the four representations of Appendix C.2 in one request, then a request referencing the indexed one",
		req: "To ensure that the decoding will successfully produce a header list, a decoder MUST obey the following rules.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				first := slices.Concat(hpackVector(t, "c2.4"), hpHTTP, hpackVector(t, "c2.2"), hpackInt(0x00, 4, 1), hpackStr("origin.test"),
					hpackVector(t, "c2.1"), hpackVector(t, "c2.3"))
				s := b.served(t, c, 1, first, "http")
				assert.Equal(t, "/sample/path", s.path)
				assert.Equal(t, []string{"custom-header"}, s.header.Values("Custom-Key"))
				assert.Equal(t, []string{"secret"}, s.header.Values("Password"))

				s = b.served(t, c, 3, hpRequest(hpHTTP, hpIndexed(62)), "http")
				assert.Equal(t, []string{"custom-header"}, s.header.Values("Custom-Key"))
			})
		},
	},
	{
		id: "rfc7541/3.2/2", name: "the three requests of Appendix C.3 on one connection",
		req: "To ensure that the decoding will successfully produce a header list, a decoder MUST obey the following rules.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dialFor(t, "www.example.com")
				s := b.served(t, c, 1, hpackVector(t, "c3.1"), "http")
				assert.Equal(t, hpackSeen{header: http.Header{}, scheme: b.scheme("http"), host: "www.example.com", path: "/"}, s)
				s = b.served(t, c, 3, hpackVector(t, "c3.2"), "http")
				assert.Equal(t, hpackSeen{header: http.Header{"Cache-Control": {"no-cache"}}, scheme: b.scheme("http"), host: "www.example.com", path: "/"}, s)
				s = b.served(t, c, 5, hpackVector(t, "c3.3"), "https")
				assert.Equal(t, hpackSeen{header: http.Header{"Custom-Key": {"custom-value"}}, scheme: b.scheme("https"), host: "www.example.com", path: "/index.html"}, s)
			})
		},
	},
	{
		id: "rfc7541/3.2/3", name: "the three requests of Appendix C.4 on one connection",
		req: "To ensure that the decoding will successfully produce a header list, a decoder MUST obey the following rules.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dialFor(t, "www.example.com")
				s := b.served(t, c, 1, hpackVector(t, "c4.1"), "http")
				assert.Equal(t, hpackSeen{header: http.Header{}, scheme: b.scheme("http"), host: "www.example.com", path: "/"}, s)
				s = b.served(t, c, 3, hpackVector(t, "c4.2"), "http")
				assert.Equal(t, hpackSeen{header: http.Header{"Cache-Control": {"no-cache"}}, scheme: b.scheme("http"), host: "www.example.com", path: "/"}, s)
				s = b.served(t, c, 5, hpackVector(t, "c4.3"), "https")
				assert.Equal(t, hpackSeen{header: http.Header{"Custom-Key": {"custom-value"}}, scheme: b.scheme("https"), host: "www.example.com", path: "/index.html"}, s)
			})
		},
	},
	{
		id: "rfc7541/3.2/4", name: "an nghttp2 story of ten requests shrinking and growing the table, then a request",
		req: "To ensure that the decoding will successfully produce a header list, a decoder MUST obey the following rules.",
		run: func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "hpack-test-case", "nghttp2-change-table-size-story_08.json"))
			require.NoError(t, err)
			var story hpackStory
			require.NoError(t, json.Unmarshal(raw, &story))
			require.Len(t, story.Cases, 10)
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				// Every request of the story has a Connection field, which RFC 9113 section 8.2.2
				// makes malformed.
				for i, cs := range story.Cases {
					block, err := hex.DecodeString(cs.Wire)
					require.NoError(t, err)
					stream := uint32(2*i + 1)
					c.block(t, stream, block)
					got := c.outcome(t, stream)
					require.True(t, isMalformed(got), "case %d: %+v", i, got)
					if got.away {
						return
					}
				}
				b.none(t)
				b.served(t, c, 21, hpRequest(hpHTTP), "http")
			})
		},
	},

	// RFC 7541 section 4, dynamic table management.
	{
		id: "rfc7541/4.3/1", name: "a dynamic table size update to 0, then a reference to an entry inserted before",
		req: "Whenever the maximum size for the dynamic table is reduced, entries are evicted from the end of the dynamic table until the size of the dynamic table is less than or equal to the maximum size.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				b.served(t, c, 1, hpRequest(hpHTTP, hpIndexing("x-a", "1")), "http")
				c.block(t, 3, slices.Concat(hpSizeUpdate(0), hpSizeUpdate(4096), hpRequest(hpHTTP, hpIndexed(62))))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeCompression)
				b.none(t)
			})
		},
	},
	{
		id: "rfc7541/4.3/2", name: "a block opening with the size updates of Appendix C.1.1 and C.1.2, then references to the entries inserted before and after",
		req: "Whenever the maximum size for the dynamic table is reduced, entries are evicted from the end of the dynamic table until the size of the dynamic table is less than or equal to the maximum size.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				b.served(t, c, 1, hpRequest(hpHTTP, hpIndexing("x-a", "1")), "http")
				ten, big := hpackVector(t, "c1.1"), hpackVector(t, "c1.2")
				ten[0] |= 0x20
				big[0] |= 0x20
				b.served(t, c, 3, slices.Concat(ten, big, hpRequest(hpHTTPS, hpIndexing("x-b", "2"))), "https")
				s := b.served(t, c, 5, hpRequest(hpHTTP, hpIndexed(62)), "http")
				assert.Equal(t, []string{"2"}, s.header.Values("X-B"))
				c.block(t, 7, hpRequest(hpHTTP, hpIndexed(63)))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeCompression)
				b.none(t)
			})
		},
	},
	{
		id: "rfc7541/4.4/1", name: "an entry of the size of the table, then a reference to it",
		req: "If the size of the new entry is less than or equal to the maximum size, that entry is added to the table.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				size := int(c.setting(http2.SettingHeaderTableSize, 4096))
				value := strings.Repeat("m", size-32-len("x-max"))
				b.served(t, c, 1, hpRequest(hpHTTP, hpIndexing("x-max", value)), "http")
				s := b.served(t, c, 3, hpRequest(hpHTTP, hpIndexed(62)), "http")
				assert.Equal(t, []string{value}, s.header.Values("X-Max"))
			})
		},
	},
	{
		id: "rfc7541/4.4/2", name: "an entry larger than the table, then a reference to an entry inserted before",
		req: "It is not an error to attempt to add an entry that is larger than the maximum size; an attempt to add an entry larger than the maximum size causes the table to be emptied of all existing entries and results in an empty table.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				size := int(c.setting(http2.SettingHeaderTableSize, 4096))
				b.served(t, c, 1, hpRequest(hpHTTP, hpIndexing("x-a", "1")), "http")
				s := b.served(t, c, 3, hpRequest(hpHTTP, hpIndexing("x-big", strings.Repeat("b", size))), "http")
				assert.Len(t, s.header.Get("X-Big"), size)
				c.block(t, 5, hpRequest(hpHTTP, hpIndexed(62)))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeCompression)
				b.none(t)
			})
		},
	},

	// RFC 7541 section 5, primitive type representations.
	{
		id: "rfc7541/5.1/1", name: "an index encoded on eleven octets",
		req: "Integer encodings that exceed implementation limits -- in value or octet length -- MUST be treated as decoding errors.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				c.block(t, 1, hpRequest(hpHTTP, []byte{0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeCompression)
				b.none(t)
			})
		},
	},
	{
		id: "rfc7541/5.2/1", name: "a Huffman string padded with eleven bits",
		req: "A padding strictly longer than 7 bits MUST be treated as a decoding error.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				c.block(t, 1, hpRequest(hpHTTP, slices.Concat([]byte{0x40}, hpackStr("x-h"), hpackHuffman(0x1f, 0xff))))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeCompression)
				b.none(t)
			})
		},
	},
	{
		id: "rfc7541/5.2/2", name: "a Huffman string padded with zero bits",
		req: "A padding not corresponding to the most significant bits of the code for the EOS symbol MUST be treated as a decoding error.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				c.block(t, 1, hpRequest(hpHTTP, slices.Concat([]byte{0x40}, hpackStr("x-h"), hpackHuffman(0x18))))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeCompression)
				b.none(t)
			})
		},
	},
	{
		id: "rfc7541/5.2/3", name: "a Huffman string containing the EOS symbol",
		req: "A Huffman-encoded string literal containing the EOS symbol MUST be treated as a decoding error.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				c.block(t, 1, hpRequest(hpHTTP, slices.Concat([]byte{0x40}, hpackStr("x-h"), hpackHuffman(0x1f, 0xff, 0xff, 0xff, 0xff))))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeCompression)
				b.none(t)
			})
		},
	},

	// RFC 7541 section 6, binary format.
	{
		id: "rfc7541/6.1/1", name: "an indexed field of index 0",
		req: "It MUST be treated as a decoding error if found in an indexed header field representation.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				c.block(t, 1, hpRequest(hpHTTP, hpIndexed(0)))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeCompression)
				b.none(t)
			})
		},
	},
	{
		id: "rfc7541/6.2.3/1", name: "a field the client and the origin send as never-indexed literals",
		req:  "Intermediaries MUST use the same representation for encoding this header field.",
		skip: hpackNeverIndexed,
	},
	{
		id: "rfc7541/6.3/1", name: "a dynamic table size update above SETTINGS_HEADER_TABLE_SIZE",
		req: "A value that exceeds this limit MUST be treated as a decoding error.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				size := uint64(c.setting(http2.SettingHeaderTableSize, 4096))
				c.block(t, 1, slices.Concat(hpSizeUpdate(size+1), hpRequest(hpHTTP)))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeCompression)
				b.none(t)
			})
		},
	},

	// RFC 7541 section 7.1.3, never-indexed literals.
	{
		id: "rfc7541/7.1.3/1", name: "a field the client and the origin send as never-indexed literals, and the dynamic tables it leaves",
		req:  "An intermediary MUST NOT re-encode a value that uses the never-indexed literal representation with another representation that would index it.",
		skip: hpackNeverIndexed,
	},

	// RFC 9113 section 4.3, field section compression and decompression.
	{
		id: "rfc9113/4.3/1", name: "a field block ending sixteen octets before the end of a field value",
		req: "A decoding error in a field block MUST be treated as a connection error (Section 5.4.1) of type COMPRESSION_ERROR.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				c.block(t, 1, hpRequest(hpHTTP, []byte{0x00}, hpackStr("x-abc"), []byte{0x10}))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeCompression)
				b.none(t)
			})
		},
	},
	{
		id: "rfc9113/4.3/2", name: "a field block ending fifteen octets before the end of a field value",
		req: "A decoding error in a field block MUST be treated as a connection error (Section 5.4.1) of type COMPRESSION_ERROR.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				c.block(t, 1, hpRequest(hpHTTP, []byte{0x00}, hpackStr("x-abc"), []byte{0x0f}))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeCompression)
				b.none(t)
			})
		},
	},
	{
		id: "rfc9113/4.3/3", name: "trailers inserting a field, then a request referencing it",
		req: "A receiver MUST terminate the connection with a connection error (Section 5.4.1) of type COMPRESSION_ERROR if it does not decompress a field block.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				require.NoError(t, c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hpRequest(hpHTTP), EndHeaders: true}))
				require.NoError(t, c.fr.WriteData(1, false, []byte("body")))
				require.NoError(t, c.fr.WriteHeaders(http2.HeadersFrameParam{
					StreamID: 1, BlockFragment: hpIndexing("x-trailer", "t"), EndHeaders: true, EndStream: true,
				}))
				require.Equal(t, h2Outcome{status: "200"}, c.outcome(t, 1))
				b.next(t)
				s := b.served(t, c, 3, hpRequest(hpHTTP, hpIndexed(62)), "http")
				assert.Equal(t, []string{"t"}, s.header.Values("X-Trailer"))
			})
		},
	},
	{
		id: "rfc9113/4.3/4", name: "a padded HEADERS frame with the PRIORITY flag and three CONTINUATION frames splitting field lines",
		req: "A receiving endpoint reassembles the field block by concatenating its fragments and then decompresses the block to reconstruct the field section.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				block := hpRequest(hpHTTPS, hpIndexing("x-a", "1"), hpLiteral("x-b", strings.Repeat("b", 200)),
					slices.Concat([]byte{0x00}, hpackStr("x-c"), hpackHuffman(0x1f)))
				require.NoError(t, c.fr.WriteHeaders(http2.HeadersFrameParam{
					StreamID: 1, BlockFragment: block[:6], EndStream: true, PadLength: 7,
					Priority: http2.PriorityParam{StreamDep: 0, Weight: 15},
				}))
				require.NoError(t, c.fr.WriteContinuation(1, false, block[6:22]))
				require.NoError(t, c.fr.WriteContinuation(1, false, block[22:len(block)-100]))
				require.NoError(t, c.fr.WriteContinuation(1, true, block[len(block)-100:]))
				require.Equal(t, h2Outcome{status: "200"}, c.outcome(t, 1))
				s := b.next(t)
				assert.Equal(t, b.scheme("https"), s.scheme)
				assert.Equal(t, []string{"1"}, s.header.Values("X-A"))
				assert.Equal(t, []string{strings.Repeat("b", 200)}, s.header.Values("X-B"))
				assert.Equal(t, []string{"a"}, s.header.Values("X-C"))
				assert.Empty(t, s.header.Values(schemeHeader))

				s = b.served(t, c, 3, hpRequest(hpHTTP, hpIndexed(62)), "http")
				assert.Equal(t, []string{"1"}, s.header.Values("X-A"))
			})
		},
	},

	// RFC 9113 section 5, streams.
	{
		id: "rfc9113/5.1.1/1", name: "a request on stream 3 after a request on stream 5 refused as malformed",
		req:  "An endpoint that receives an unexpected stream identifier MUST respond with a connection error (Section 5.4.1) of type PROTOCOL_ERROR.",
		skip: "net/http's HTTP/2 server resets a malformed request without raising its highest stream identifier, so it accepts a lower stream after it, net/http/internal/http2/server.go",
	},
	{
		id: "rfc9113/5.4.2/1", name: "a field block inserting a field on a stream reset as malformed, then a request referencing it",
		req: "The peer that sends the RST_STREAM frame MUST be prepared to receive any frames that were sent or enqueued for sending by the remote peer.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				require.NoError(t, c.fr.WriteHeaders(http2.HeadersFrameParam{
					StreamID: 1, BlockFragment: hpRequest(hpHTTP, hpLiteral("X-Upper", "v")), EndHeaders: true,
				}))
				got := c.outcome(t, 1)
				require.True(t, isMalformed(got), "%+v", got)
				if got.away {
					return
				}
				require.NoError(t, c.fr.WriteHeaders(http2.HeadersFrameParam{
					StreamID: 1, BlockFragment: hpIndexing("x-trailer", "t"), EndHeaders: true, EndStream: true,
				}))
				s := b.served(t, c, 3, hpRequest(hpHTTP, hpIndexed(62)), "http")
				assert.Equal(t, []string{"t"}, s.header.Values("X-Trailer"))
			})
		},
	},
	{
		id: "rfc9113/5.4.2/2", name: "a HEADERS frame whose padding is the length of its payload reset as a stream error, then a request",
		req: "A stream error is an error related to a specific stream that does not affect processing of other streams.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				block := hpRequest(hpHTTP)
				require.NoError(t, c.fr.WriteRawFrame(http2.FrameHeaders, http2.FlagHeadersEndHeaders|http2.FlagHeadersEndStream|http2.FlagHeadersPadded, 1,
					append([]byte{byte(len(block) + 1)}, block...)))
				got := c.outcome(t, 1)
				if isConnError(got, http2.ErrCodeProtocol) {
					return
				}
				require.True(t, got.reset, "%+v", got)
				b.none(t)
				b.served(t, c, 3, hpRequest(hpHTTP), "http")
			})
		},
	},

	// RFC 9113 section 6.2, HEADERS.
	{
		id: "rfc9113/6.2/1", name: "a request in a padded HEADERS frame",
		req: "The total number of padding octets is determined by the value of the Pad Length field.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				require.NoError(t, c.fr.WriteHeaders(http2.HeadersFrameParam{
					StreamID: 1, BlockFragment: hpRequest(hpHTTPS, hpLiteral("x-a", "1")), EndHeaders: true, EndStream: true, PadLength: 16,
				}))
				require.Equal(t, h2Outcome{status: "200"}, c.outcome(t, 1))
				s := b.next(t)
				assert.Equal(t, b.scheme("https"), s.scheme)
				assert.Equal(t, []string{"1"}, s.header.Values("X-A"))
				assert.Empty(t, s.header.Values(schemeHeader))
			})
		},
	},
	{
		id: "rfc9113/6.2/2", name: "a PRIORITY frame between a HEADERS frame and its CONTINUATION",
		req: "A receiver MUST treat the receipt of any other type of frame or a frame on a different stream as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				block := hpRequest(hpHTTP)
				require.NoError(t, c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:5], EndStream: true}))
				require.NoError(t, c.fr.WritePriority(1, http2.PriorityParam{Weight: 15}))
				require.NoError(t, c.fr.WriteContinuation(1, true, block[5:]))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeProtocol)
				b.none(t)
			})
		},
	},
	{
		id: "rfc9113/6.2/3", name: "a HEADERS frame on stream 3 between a HEADERS frame on stream 1 and its CONTINUATION",
		req: "A receiver MUST treat the receipt of any other type of frame or a frame on a different stream as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				block := hpRequest(hpHTTP)
				require.NoError(t, c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:5], EndStream: true}))
				c.block(t, 3, block)
				require.NoError(t, c.fr.WriteContinuation(1, true, block[5:]))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeProtocol)
				b.none(t)
			})
		},
	},
	{
		id: "rfc9113/6.2/4", name: "a HEADERS frame whose padding is the length of its payload",
		req:  "If the length of the padding is the length of the frame payload or greater, the recipient MUST treat this as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.",
		skip: "net/http's HTTP/2 framer answers a HEADERS frame whose padding is the length of its payload with a stream error, net/http/internal/http2/frame.go",
	},

	// RFC 9113 section 6.5.2, defined settings.
	{
		id: "rfc9113/6.5.2/1", name: "a dynamic table size update to SETTINGS_HEADER_TABLE_SIZE and entries filling the table",
		req: "This setting allows the sender to inform the remote endpoint of the maximum size of the compression table used to decode field blocks, in units of octets.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				size := int(c.setting(http2.SettingHeaderTableSize, 4096))
				require.Zero(t, size%16)
				var entries [][]byte
				for i := range 16 {
					name := fmt.Sprintf("x-fill-%02d", i)
					entries = append(entries, hpIndexing(name, strings.Repeat("f", size/16-32-len(name))))
				}
				b.served(t, c, 1, slices.Concat(hpSizeUpdate(uint64(size)), hpRequest(hpHTTP, entries...)), "http")
				s := b.served(t, c, 3, hpRequest(hpHTTP, hpIndexed(62), hpIndexed(77)), "http")
				assert.Len(t, s.header.Get("X-Fill-15"), size/16-32-len("x-fill-15"))
				assert.Len(t, s.header.Get("X-Fill-00"), size/16-32-len("x-fill-00"))
			})
		},
	},
	{
		id: "rfc9113/6.5.2/2", name: "a request in a HEADERS frame of SETTINGS_MAX_FRAME_SIZE octets",
		req: "This setting indicates the size of the largest frame payload that the sender is willing to receive, in units of octets.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front, WithMaxHeaderBytes(2<<20))
				c := b.dial(t)
				size := int(c.setting(http2.SettingMaxFrameSize, 16384))
				require.NoError(t, c.fr.WriteHeaders(maxFrameRequest(t, size, "x-big")))
				require.Equal(t, h2Outcome{status: "200"}, c.outcome(t, 1))
				s := b.next(t)
				assert.Equal(t, b.scheme("https"), s.scheme)
				assert.NotEmpty(t, s.header.Get("X-Big"))
				assert.Empty(t, s.header.Values(schemeHeader))
			})
		},
	},

	// RFC 9113 section 6.10, CONTINUATION.
	{
		id: "rfc9113/6.10/1", name: "a CONTINUATION frame after a HEADERS frame with END_HEADERS",
		req: "A recipient that observes violation of this rule MUST respond with a connection error (Section 5.4.1) of type PROTOCOL_ERROR.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				b.served(t, c, 1, hpRequest(hpHTTP), "http")
				require.NoError(t, c.fr.WriteContinuation(1, true, hpLiteral("x-a", "1")))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeProtocol)
			})
		},
	},
	{
		id: "rfc9113/6.10/2", name: "a CONTINUATION frame on stream 0 inside a field block",
		req: "If a CONTINUATION frame is received with a Stream Identifier field of 0x00, the recipient MUST respond with a connection error (Section 5.4.1) of type PROTOCOL_ERROR.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				block := hpRequest(hpHTTP)
				require.NoError(t, c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block[:5], EndStream: true}))
				require.NoError(t, c.fr.WriteRawFrame(http2.FrameContinuation, http2.FlagContinuationEndHeaders, 0, block[5:]))
				assertConnError(t, c.outcome(t, 0), http2.ErrCodeProtocol)
				b.none(t)
			})
		},
	},

	// RFC 9113 section 8.2, HTTP fields.
	{
		id: "rfc9113/8.2.1/1", name: "a request with an uppercase field name, then a request",
		req: "A request or response that contains a field that violates any of these conditions MUST be treated as malformed (Section 8.1.1).",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				c.block(t, 1, hpRequest(hpHTTP, hpLiteral("X-Upper", "v")))
				got := c.outcome(t, 1)
				assertMalformed(t, got)
				b.none(t)
				if !got.away {
					b.served(t, c, 3, hpRequest(hpHTTP), "http")
				}
			})
		},
	},
	{
		id: "rfc9113/8.2.1/2", name: "a request with an uppercase field name in a HEADERS frame of SETTINGS_MAX_FRAME_SIZE octets",
		req: "A request or response that contains a field that violates any of these conditions MUST be treated as malformed (Section 8.1.1).",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front, WithMaxHeaderBytes(2<<20))
				c := b.dial(t)
				size := int(c.setting(http2.SettingMaxFrameSize, 16384))
				require.NoError(t, c.fr.WriteHeaders(maxFrameRequest(t, size, "X-Big")))
				assertMalformed(t, c.outcome(t, 1))
				b.none(t)
			})
		},
	},

	// RFC 9113 section 8.3, HTTP control data.
	{
		id: "rfc9113/8.3.1/1", name: "a :scheme inserted into the dynamic table, then requests referencing it",
		req: "The \":scheme\" pseudo-header field includes the scheme portion of the request target.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				b.served(t, c, 1, hpRequest(slices.Concat(hpackInt(0x40, 6, 6), hpackStr("https"))), "https")
				b.served(t, c, 3, hpRequest(hpIndexed(62)), "https")
				b.served(t, c, 5, hpRequest(hpHTTP), "http")
				b.served(t, c, 7, hpRequest(hpIndexed(62)), "https")
			})
		},
	},
	{
		id: "rfc9113/8.3.1/2", name: "a request on stream 3 with an edge-scheme field of its own, after a request on stream 5 refused as malformed",
		req: "The \":scheme\" pseudo-header field includes the scheme portion of the request target.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front)
				c := b.dial(t)
				c.block(t, 5, hpRequest(hpHTTP, hpLiteral("X-Upper", "v")))
				got := c.outcome(t, 5)
				require.True(t, isMalformed(got), "%+v", got)
				if got.away {
					return
				}
				c.block(t, 3, hpRequest(hpHTTP, hpLiteral("edge-scheme", "s")))
				got = c.outcome(t, 3)
				if isConnError(got, http2.ErrCodeProtocol) {
					return
				}
				if got == (h2Outcome{status: "400"}) {
					b.none(t)
					return
				}
				require.Equal(t, h2Outcome{status: "200"}, got)
				s := b.next(t)
				assert.Equal(t, b.scheme("http"), s.scheme)
			})
		},
	},

	// RFC 9113 section 10.5.1, limits on field block size.
	{
		id: "rfc9113/10.5.1/1", name: "a field section over SETTINGS_MAX_HEADER_LIST_SIZE inserting a field, then a request referencing it",
		req: "The field block MUST be processed to ensure a consistent connection state, unless the connection is closed.",
		run: func(t *testing.T) {
			eachHPACKFront(t, func(t *testing.T, front string) {
				b := newHPACKBench(t, front, WithMaxHeaderBytes(1024))
				c := b.dial(t)
				size := int(c.setting(http2.SettingMaxHeaderListSize, 0))
				require.NotZero(t, size)
				c.block(t, 1, hpRequest(hpHTTP, hpIndexing("x-small", "1"), hpLiteral("x-long", strings.Repeat("v", size))))
				got := c.outcome(t, 1)
				b.none(t)
				if got.closed {
					return
				}
				require.Equal(t, h2Outcome{status: "431"}, got)
				s := b.served(t, c, 3, hpRequest(hpHTTP, hpIndexed(62)), "http")
				assert.Equal(t, []string{"1"}, s.header.Values("X-Small"))
			})
		},
	},
}

func TestSchemeConn_RefusedConnectionStaysRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	p := testProxy(t)
	own, err := p.srv.fwd.up.dialRaw(t.Context(), "tcp", ln.Addr().String())
	require.NoError(t, err)
	srv, err := ln.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	require.NoError(t, srv.SetDeadline(time.Now().Add(5*time.Second)))
	c := newSchemeConn(srv, 1<<20)
	schemeConnOf(c).p = p

	_, err = io.WriteString(own, "GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	require.NoError(t, err)
	b := make([]byte, 64)
	n, err := c.Read(b)
	require.ErrorIs(t, err, errFromItself)
	require.Zero(t, n)
	require.NoError(t, own.Close())
	n, err = c.Read(b)
	assert.ErrorIs(t, err, errFromItself)
	assert.Zero(t, n, "a read after the refusal returned %q", b[:n])
}
