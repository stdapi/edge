package edge

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
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
		hf(":method", "GET"), hf(":scheme", "http"), hf(":authority", "a.test"), hf(":path", "/"), hf("x-kept", "one"), sensitive("edge-scheme", "h"),
	}, got.blocks[0])
	assert.Equal(t, []hpack.HeaderField{
		hf(":method", "GET"), hf(":scheme", "https"), hf(":authority", "a.test"), hf(":path", "/"), hf("x-kept", "one"), sensitive("edge-scheme", "s"),
	}, got.blocks[1])
	assert.Equal(t, []hpack.HeaderField{hf("x-kept", "one"), hf("x-trailer", "two")}, got.blocks[2])
	assert.Equal(t, []hpack.HeaderField{hf(":method", "CONNECT"), hf(":authority", "b.test:443"), sensitive("edge-scheme", "-")}, got.blocks[3])
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
	assert.Equal(t, sensitive("edge-scheme", "s"), got.blocks[0][len(got.blocks[0])-1])
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

func TestServe_HTTP2SchemeReachesTheHandler(t *testing.T) {
	p := testProxy(t)
	type seen struct{ scheme, field string }
	got := make(chan seen, 2)
	p.MustAdd("origin.test/*{any}", func(c *HTTPCtx) (*http.Response, error) {
		got <- seen{c.Scheme(), c.Header(schemeHeader)}
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
