// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package h2tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// A conformance case is one requirement of an RFC checked against the client, as the peer
// sees it. The table is the catalogue: h2spec's cases first, under its own keys, then the
// scenarios of Go's HTTP/2 transport tests that apply to a client of CONNECT streams. A case
// that cannot apply states the reason instead of a scenario, so every requirement of the
// sources is accounted for in one place.
type conformanceCase struct {
	// id is the key in the source, "http2/6.5.2/1" in h2spec.
	id string
	// name states what the peer sends.
	name string
	// req is the requirement in the words of the RFC.
	req string
	// skip gives the reason the case does not apply, or where the client departs from it.
	skip string
	run  func(t *testing.T, p *peer)
}

func TestConformance(t *testing.T) {
	for _, tc := range conformance {
		t.Run(tc.id+" "+tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}
			t.Parallel()
			tc.run(t, newPeer(t))
		})
	}
}

// str is an HPACK string literal, huff the same Huffman-coded, RFC 7541 section 5.2.
func str(v string) []byte { return append([]byte{byte(len(v))}, v...) }

func huff(v string) []byte {
	b := hpack.AppendHuffmanString(nil, v)
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// bigBlock is a header block past one frame, Huffman coding included.
func bigBlock(p *peer) []byte {
	return p.block(status("200"), hpack.HeaderField{Name: "x-pad", Value: strings.Repeat("a", 30000)})
}

var conformance = []conformanceCase{
	// h2spec generic: what an endpoint accepts.
	{
		id: "generic/1/1", name: "the client sends the connection preface",
		req: "The client connection preface starts with a sequence of 24 octets, followed by a SETTINGS frame.",
		run: func(t *testing.T, p *peer) { p.wantAlive() },
	},
	{
		id: "generic/2/1", name: "PRIORITY on an idle stream",
		req: "The endpoint MUST accept PRIORITY frame.",
		run: func(t *testing.T, p *peer) {
			p.writePriority(101, http2.PriorityParam{Weight: 15})
			p.wantAlive()
		},
	},
	{
		id: "generic/2/2", name: "WINDOW_UPDATE on a stream the peer ended",
		req: "The endpoint MUST accept WINDOW_UPDATE frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writeWindowUpdate(id, 10)
			p.wantAlive()
		},
	},
	{
		id: "generic/2/3", name: "PRIORITY on a stream the peer ended",
		req: "The endpoint MUST accept PRIORITY frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writePriority(id, http2.PriorityParam{Weight: 15})
			p.wantAlive()
		},
	},
	{
		id: "generic/2/4", name: "RST_STREAM on a stream the peer ended",
		req: "The endpoint MUST accept RST_STREAM frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writeRST(id, http2.ErrCodeCancel)
			p.wantAlive()
			_, err := s.Write([]byte("late"))
			require.Error(t, err)
		},
	},
	{
		id: "generic/2/5", name: "PRIORITY on a closed stream",
		req: "The endpoint MUST accept PRIORITY frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, s.Close())
			p.wantRST(id, http2.ErrCodeCancel)
			p.writePriority(id, http2.PriorityParam{Weight: 15})
			p.wantAlive()
		},
	},
	{
		id: "generic/3.10/1", name: "the answer in HEADERS and one CONTINUATION",
		req: "The endpoint MUST accept CONTINUATION frame.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"), hpack.HeaderField{Name: "x-a", Value: "1"})
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			require.NoError(t, p.fr.WriteContinuation(id, true, block[1:]))
			_, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, "1", resp.Header.Get("x-a"))
		},
	},
	{
		id: "generic/3.10/2", name: "the answer in HEADERS and several CONTINUATIONs",
		req: "The endpoint MUST accept multiple CONTINUATION frames.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"), hpack.HeaderField{Name: "x-a", Value: "1"})
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			require.NoError(t, p.fr.WriteContinuation(id, false, block[1:2]))
			require.NoError(t, p.fr.WriteContinuation(id, true, block[2:]))
			_, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, "1", resp.Header.Get("x-a"))
		},
	},
	{
		id: "generic/3.1/1", name: "one DATA frame",
		req: "The endpoint MUST accept DATA frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, false, []byte("hello"))
			p.wantRead(s, []byte("hello"))
		},
	},
	{
		id: "generic/3.1/2", name: "several DATA frames",
		req: "The endpoint MUST accept multiple DATA frames.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, false, []byte("hel"))
			p.writeData(id, false, []byte("lo"))
			require.Equal(t, "hello", string(p.wantReadAll(s, 5)))
		},
	},
	{
		id: "generic/3.1/3", name: "a padded DATA frame",
		req: "The endpoint MUST accept DATA frame with padding.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, p.fr.WriteDataPadded(id, false, []byte("hello"), make([]byte, 7)))
			p.wantRead(s, []byte("hello"))
		},
	},
	{
		id: "generic/3.2/1", name: "the answer in one HEADERS frame",
		req: "The endpoint MUST accept HEADERS frame.",
		run: func(t *testing.T, p *peer) { p.connect() },
	},
	{
		id: "generic/3.2/2", name: "the answer in a padded HEADERS frame",
		req: "The endpoint MUST accept HEADERS frame with padding.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: id, BlockFragment: p.block(status("200")), EndHeaders: true, PadLength: 9,
			}))
			_, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		},
	},
	{
		id: "generic/3.2/3", name: "the answer in a HEADERS frame with priority",
		req: "The endpoint MUST accept HEADERS frame with priority.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: id, BlockFragment: p.block(status("200")), EndHeaders: true,
				Priority: http2.PriorityParam{StreamDep: 0, Weight: 15},
			}))
			_, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		},
	},
	{
		id: "generic/3.3/1", name: "PRIORITY with weight 1",
		req: "The endpoint MUST accept PRIORITY frame with priority 1.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writePriority(id, http2.PriorityParam{Weight: 0})
			p.wantAlive()
		},
	},
	{
		id: "generic/3.3/2", name: "PRIORITY with weight 256",
		req: "The endpoint MUST accept PRIORITY frame with priority 256.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writePriority(id, http2.PriorityParam{Weight: 255})
			p.wantAlive()
		},
	},
	{
		id: "generic/3.3/3", name: "PRIORITY with a stream dependency",
		req: "The endpoint MUST accept PRIORITY frame with stream dependency.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			_, id2 := p.connect()
			p.writePriority(id2, http2.PriorityParam{StreamDep: id, Weight: 15})
			p.wantAlive()
		},
	},
	{
		id: "generic/3.3/4", name: "PRIORITY with an exclusive dependency",
		req: "The endpoint MUST accept PRIORITY frame with exclusive.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			_, id2 := p.connect()
			p.writePriority(id2, http2.PriorityParam{StreamDep: id, Weight: 15, Exclusive: true})
			p.wantAlive()
		},
	},
	{
		id: "generic/3.3/5", name: "PRIORITY for an idle stream, then HEADERS on a lower one",
		req:  "The endpoint MUST respond the HEADER frame.",
		skip: "a server opens no stream toward a client, which disables push",
	},
	{
		id: "generic/3.4/1", name: "RST_STREAM",
		req: "The endpoint MUST accept RST_STREAM frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeRST(id, http2.ErrCodeCancel)
			p.wantReadCode(s, http2.ErrCodeCancel)
			p.wantAlive()
		},
	},
	{
		id: "generic/3.5/1", name: "SETTINGS",
		req: "The endpoint MUST accept SETTINGS frame.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100})
			p.wantSettingsAck()
		},
	},
	{
		id: "generic/3.7/1", name: "PING",
		req: "The endpoint MUST accept PING frame.",
		run: func(t *testing.T, p *peer) { p.wantAlive() },
	},
	{
		id: "generic/3.8/1", name: "GOAWAY",
		req: "The endpoint MUST accept GOAWAY frame.",
		run: func(t *testing.T, p *peer) {
			p.writeGoAway(0, http2.ErrCodeNo)
			p.wantGoAway(http2.ErrCodeNo)
			p.wantClosed()
			require.ErrorIs(t, p.c.Err(), ErrGoAway)
		},
	},
	{
		id: "generic/3.9/1", name: "WINDOW_UPDATE on the connection",
		req: "The endpoint MUST accept WINDOW_UPDATE frame.",
		run: func(t *testing.T, p *peer) {
			p.writeWindowUpdate(0, 1<<20)
			p.wantAlive()
		},
	},
	{
		id: "generic/3.9/2", name: "WINDOW_UPDATE on a stream",
		req: "The endpoint MUST accept WINDOW_UPDATE frame.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeWindowUpdate(id, 1<<20)
			p.wantAlive()
		},
	},
	{
		id: "generic/4/1", name: "a CONNECT answered, with DATA both ways",
		req: "The endpoint MUST respond to the request.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			_, err := s.Write([]byte("ping"))
			require.NoError(t, err)
			require.Equal(t, "ping", string(p.wantData(id).Data()))
			p.writeData(id, false, []byte("pong"))
			p.wantRead(s, []byte("pong"))
		},
	},
	{id: "generic/4/2", name: "a HEAD request", req: "The endpoint MUST respond to the request.", skip: "a client of CONNECT streams sends no other method"},
	{id: "generic/4/3", name: "a POST request", req: "The endpoint MUST respond to the request.", skip: "a client of CONNECT streams sends no other method"},
	{id: "generic/4/4", name: "a POST request with trailers", req: "The endpoint MUST respond to the request.", skip: "a client of CONNECT streams sends no other method"},
	{
		id: "generic/5/1", name: "an indexed field", req: "The endpoint MUST accept indexed header field representation",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, []byte{0x88}) },
	},
	{
		id: "generic/5/2", name: "a literal with incremental indexing, indexed name", req: "The endpoint MUST accept literal header field with incremental indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x48}, str("200"))) },
	},
	{
		id: "generic/5/3", name: "a literal with incremental indexing, indexed name, Huffman", req: "The endpoint MUST accept literal header field with incremental indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x48}, huff("200"))) },
	},
	{
		id: "generic/5/4", name: "a literal with incremental indexing, new name", req: "The endpoint MUST accept literal header field with incremental indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x40}, str(":status"), str("200"))) },
	},
	{
		id: "generic/5/5", name: "a literal with incremental indexing, new name, Huffman", req: "The endpoint MUST accept literal header field with incremental indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x40}, huff(":status"), huff("200"))) },
	},
	{
		id: "generic/5/6", name: "a literal without indexing, indexed name", req: "The endpoint MUST accept literal header field without indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x08}, str("200"))) },
	},
	{
		id: "generic/5/7", name: "a literal without indexing, indexed name, Huffman", req: "The endpoint MUST accept literal header field without indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x08}, huff("200"))) },
	},
	{
		id: "generic/5/8", name: "a literal without indexing, new name", req: "The endpoint MUST accept literal header field without indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x00}, str(":status"), str("200"))) },
	},
	{
		id: "generic/5/9", name: "a literal without indexing, new name, Huffman", req: "The endpoint MUST accept literal header field without indexing",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x00}, huff(":status"), huff("200"))) },
	},
	{
		id: "generic/5/10", name: "a literal never indexed, indexed name", req: "The endpoint MUST accept literal header field never indexed",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x18}, str("200"))) },
	},
	{
		id: "generic/5/11", name: "a literal never indexed, indexed name, Huffman", req: "The endpoint MUST accept literal header field never indexed",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x18}, huff("200"))) },
	},
	{
		id: "generic/5/12", name: "a literal never indexed, new name", req: "The endpoint MUST accept literal header field never indexed",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x10}, str(":status"), str("200"))) },
	},
	{
		id: "generic/5/13", name: "a literal never indexed, new name, Huffman", req: "The endpoint MUST accept literal header field never indexed",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, cat([]byte{0x10}, huff(":status"), huff("200"))) },
	},
	{
		id: "generic/5/14", name: "a dynamic table size update", req: "The endpoint MUST accept dynamic table size update",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, []byte{0x20, 0x88}) },
	},
	{
		id: "generic/5/15", name: "several dynamic table size updates", req: "The endpoint MUST accept multiple dynamic table size update",
		run: func(t *testing.T, p *peer) { wantAnswerBlock(t, p, []byte{0x20, 0x3f, 0xe1, 0x1f, 0x88}) },
	},

	// RFC 9113 section 3, starting HTTP/2.
	{
		id: "http2/3.5/1", name: "the peer's first frame is not SETTINGS",
		req: "The server connection preface consists of a potentially empty SETTINGS frame that MUST be the first frame the server sends in the HTTP/2 connection. Clients and servers MUST treat an invalid connection preface as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p = dialPeer(t)
			p.writePing(false, [8]byte{})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/3.5/2", name: "the peer is not HTTP/2",
		req: "The endpoint MUST terminate the TCP connection.",
		run: func(t *testing.T, p *peer) {
			p = dialPeer(t)
			o := p.open(Request{Authority: "origin.test:443"})
			_, err := p.nc.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
			require.NoError(t, err)
			p.wantClosed()
			_, _, err = o.wait(t)
			require.Error(t, err)
			require.NotErrorIs(t, err, context.DeadlineExceeded, "Open waited out its context on a peer that is not HTTP/2")
		},
	},

	// RFC 9113 section 4, frames.
	{
		id: "http2/4.1/1", name: "a frame of an unknown type",
		req: "Implementations MUST ignore and discard frames of unknown types.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(0xee, 0, 0, []byte{1, 2, 3})
			p.wantAlive()
		},
	},
	{
		id: "http2/4.1/2", name: "a frame with undefined flags",
		req: "Flags that have no defined semantics for a particular frame type MUST be ignored and MUST be left unset (0x00) when sending.",
		run: func(t *testing.T, p *peer) {
			data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
			p.writeRaw(http2.FramePing, 0xfe, 0, data[:])
			p.wantPingAck(data)
		},
	},
	{
		id: "http2/4.1/3", name: "a frame with the reserved bit set",
		req: "The semantics of this bit are undefined, and the bit MUST remain unset (0x00) when sending and MUST be ignored when receiving.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameSettings, 0, 1<<31, nil)
			p.wantSettingsAck()
		},
	},
	{
		id: "http2/4.2/1", name: "a DATA frame of 2^14 octets",
		req: "All implementations MUST be capable of receiving and minimally processing frames up to 2^14 octets in length.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, false, bytes.Repeat([]byte{7}, 1<<14))
			require.Equal(t, bytes.Repeat([]byte{7}, 1<<14), p.wantReadAll(s, 1<<14))
		},
	},
	{
		id: "http2/4.2/2", name: "a DATA frame past SETTINGS_MAX_FRAME_SIZE",
		req: "An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame exceeds the size defined in SETTINGS_MAX_FRAME_SIZE.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeData(id, false, make([]byte, 1<<14+1))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},
	{
		id: "http2/4.2/3", name: "a HEADERS frame past SETTINGS_MAX_FRAME_SIZE",
		req: "A frame size error in a frame that could alter the state of the entire connection MUST be treated as a connection error; this includes any frame carrying a field block.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeBlock(id, false, bigBlock(p))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},
	{
		id: "http2/4.3/1", name: "an invalid header block",
		req: "A decoding error in a field block MUST be treated as a connection error of type COMPRESSION_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeBlock(id, false, []byte{0xff, 0xff, 0xff, 0xff, 0xff})
			p.wantConnectionError(http2.ErrCodeCompression)
		},
	},
	{
		id: "http2/4.3/2", name: "PRIORITY in the middle of a header block",
		req: "Each field block is processed as a discrete unit. Field blocks MUST be transmitted as a contiguous sequence of frames, with no interleaved frames of any other type or from any other stream.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			p.writePriority(id, http2.PriorityParam{Weight: 15})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/4.3/3", name: "HEADERS on another stream in the middle of a header block",
		req: "Field blocks MUST be transmitted as a contiguous sequence of frames, with no interleaved frames of any other type or from any other stream.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.open(Request{Authority: "origin.test:443"})
			id2 := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			p.writeBlock(id2, false, block)
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},

	// RFC 9113 section 5, streams.
	{
		id: "http2/5.1.1/1", name: "HEADERS on an even stream id",
		req: "Streams initiated by a client MUST use odd-numbered stream identifiers. An endpoint that receives an unexpected stream identifier MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.connect()
			p.writeHeaders(2, false, status("200"))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/5.1.1/2", name: "a stream id below the previous one",
		req:  "The endpoint MUST respond with a connection error of type PROTOCOL_ERROR.",
		skip: "the order of new stream ids is a rule on the endpoint that opens streams, and a server opens none toward a client that disables push",
	},
	{
		id: "http2/5.1.2/1", name: "the client at the peer's concurrent stream limit",
		req: "Endpoints MUST NOT exceed the limit set by their peer.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1})
			p.wantSettingsAck()
			s, _ := p.connect()
			require.Eventually(t, func() bool { return !p.c.CanOpen() }, wantTimeout, time.Millisecond)
			_, _, err := p.open(Request{Authority: "origin.test:443"}).wait(t)
			require.ErrorIs(t, err, ErrStreamLimit)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS past the stream limit")
			require.NoError(t, s.Close())
			p.connect()
		},
	},
	{
		id: "http2/5.1/1", name: "DATA on an idle stream",
		req: "Receiving any frame other than HEADERS or PRIORITY on a stream in this state MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeData(101, false, []byte("x"))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/5.1/2", name: "RST_STREAM on an idle stream",
		req: "Receiving any frame other than HEADERS or PRIORITY on a stream in this state MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRST(101, http2.ErrCodeCancel)
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/5.1/3", name: "WINDOW_UPDATE on an idle stream",
		req: "Receiving any frame other than HEADERS or PRIORITY on a stream in this state MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeWindowUpdate(101, 1)
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/5.1/4", name: "CONTINUATION on an idle stream",
		req: "Receiving any frame other than HEADERS or PRIORITY on a stream in this state MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			require.NoError(t, p.fr.WriteContinuation(101, true, p.block(status("200"))))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/5.1/5", name: "DATA after the peer's END_STREAM",
		req: "If an endpoint receives additional frames, except for WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a stream that is in this state, it MUST respond with a stream error of type STREAM_CLOSED.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writeData(id, false, []byte("late"))
			p.wantStreamError(id, http2.ErrCodeStreamClosed)
		},
	},
	{
		id: "http2/5.1/6", name: "HEADERS after the peer's END_STREAM",
		req: "If an endpoint receives additional frames, except for WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a stream that is in this state, it MUST respond with a stream error of type STREAM_CLOSED.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writeHeaders(id, true, hpack.HeaderField{Name: "x-late", Value: "1"})
			p.wantStreamError(id, http2.ErrCodeStreamClosed)
		},
	},
	{
		id: "http2/5.1/7", name: "HEADERS and CONTINUATION after the peer's END_STREAM",
		req: "If an endpoint receives additional frames, except for WINDOW_UPDATE, PRIORITY, or RST_STREAM, for a stream that is in this state, it MUST respond with a stream error of type STREAM_CLOSED.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			block := p.block(hpack.HeaderField{Name: "x-late", Value: "1"})
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1], EndStream: true}))
			require.NoError(t, p.fr.WriteContinuation(id, true, block[1:]))
			p.wantStreamError(id, http2.ErrCodeStreamClosed)
		},
	},
	{
		id: "http2/5.1/8", name: "DATA after the client's RST_STREAM",
		req: "An endpoint MUST ignore frames that it receives on closed streams after it has sent a RST_STREAM frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, s.Close())
			p.wantRST(id, http2.ErrCodeCancel)
			p.writeData(id, false, []byte("late"))
			p.wantAlive()
		},
	},
	{
		id: "http2/5.1/9", name: "HEADERS after the client's RST_STREAM",
		req: "An endpoint MUST ignore frames that it receives on closed streams after it has sent a RST_STREAM frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, s.Close())
			p.wantRST(id, http2.ErrCodeCancel)
			p.writeHeaders(id, true, hpack.HeaderField{Name: "x-late", Value: "1"})
			p.wantAlive()
		},
	},
	{
		id: "http2/5.1/10", name: "HEADERS and CONTINUATION after the client's RST_STREAM",
		req: "An endpoint MUST ignore frames that it receives on closed streams after it has sent a RST_STREAM frame.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, s.Close())
			p.wantRST(id, http2.ErrCodeCancel)
			block := p.block(hpack.HeaderField{Name: "x-late", Value: "1"})
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1], EndStream: true}))
			require.NoError(t, p.fr.WriteContinuation(id, true, block[1:]))
			p.wantAlive()
		},
	},
	{
		id: "http2/5.1/11", name: "DATA on a stream that ended in both directions",
		req: "An endpoint MAY treat receipt of any other type of frame on a closed stream as a connection error of type STREAM_CLOSED. The client ignores the frame and credits its DATA back, as Go's transport does.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			ended(t, p, s, id)
			p.writeData(id, false, []byte("late"))
			var credited uint32
			for credited < 4 {
				credited += p.wantWindowUpdate(0)
			}
			p.wantAlive()
		},
	},
	{
		id: "http2/5.1/12", name: "HEADERS on a stream that ended in both directions",
		req: "An endpoint MAY treat receipt of any other type of frame on a closed stream as a connection error of type STREAM_CLOSED. The client ignores the frame, as Go's transport does.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			ended(t, p, s, id)
			p.writeHeaders(id, true, hpack.HeaderField{Name: "x-late", Value: "1"})
			p.wantAlive()
		},
	},
	{
		id: "http2/5.1/13", name: "CONTINUATION on a stream that ended in both directions",
		req: "An endpoint MAY treat receipt of any other type of frame on a closed stream as a connection error of type STREAM_CLOSED. The client ignores the frame, as Go's transport does.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			ended(t, p, s, id)
			block := p.block(hpack.HeaderField{Name: "x-late", Value: "1"})
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1], EndStream: true}))
			require.NoError(t, p.fr.WriteContinuation(id, true, block[1:]))
			p.wantAlive()
		},
	},
	{
		id: "http2/5.3.1/1", name: "HEADERS depending on its own stream",
		req: "A stream cannot depend on itself. An endpoint MUST treat this as a stream error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID: id, BlockFragment: p.block(status("200")), EndHeaders: true,
				Priority: http2.PriorityParam{StreamDep: id, Weight: 15},
			}))
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/5.3.1/2", name: "PRIORITY depending on its own stream",
		req: "A stream cannot depend on itself. An endpoint MUST treat this as a stream error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writePriority(id, http2.PriorityParam{StreamDep: id, Weight: 15})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/5.4.1/1", name: "a PING of the wrong length",
		req: "An endpoint that encounters a connection error SHOULD first send a GOAWAY frame with the stream identifier of the last stream that it successfully received from its peer. After sending the GOAWAY frame for an error condition, the endpoint MUST close the TCP connection.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FramePing, 0, 0, make([]byte, 7))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},
	{
		id: "http2/5.4.1/2", name: "the GOAWAY of a connection error names the last stream",
		req: "An endpoint that encounters a connection error SHOULD first send a GOAWAY frame with the stream identifier of the last stream that it successfully received from its peer.",
		run: func(t *testing.T, p *peer) {
			p.connect()
			p.writeRaw(http2.FramePing, 0, 0, make([]byte, 7))
			f := p.wantGoAway(http2.ErrCodeFrameSize)
			require.Equal(t, uint32(0), f.LastStreamID, "a client received no stream from its peer")
			p.wantClosed()
		},
	},
	{
		id: "http2/5.5/1", name: "an extension frame on a stream",
		req: "Implementations MUST ignore unknown or unsupported values in all extensible protocol elements.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeRaw(0xee, 0, id, []byte{1, 2, 3})
			p.wantAlive()
		},
	},
	{
		id: "http2/5.5/2", name: "an extension frame in the middle of a header block",
		req: "Extension frames that appear in the middle of a field block are not permitted; these MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			p.writeRaw(0xee, 0, id, []byte{1, 2, 3})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},

	// RFC 9113 section 6, frame definitions.
	{
		id: "http2/6.10/1", name: "HEADERS and several CONTINUATIONs",
		req: "Any number of CONTINUATION frames can be sent, as long as the preceding frame is on the same stream and is a HEADERS, PUSH_PROMISE, or CONTINUATION frame without the END_HEADERS flag set.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: nil}))
			require.NoError(t, p.fr.WriteContinuation(id, false, block[:1]))
			require.NoError(t, p.fr.WriteContinuation(id, false, nil))
			require.NoError(t, p.fr.WriteContinuation(id, true, block[1:]))
			_, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		},
	},
	{
		id: "http2/6.10/2", name: "another frame before END_HEADERS",
		req: "A receiver MUST treat the receipt of any other type of frame or a frame on a different stream as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			require.NoError(t, p.fr.WriteContinuation(id, false, nil))
			p.writeData(id, false, []byte("x"))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.10/3", name: "CONTINUATION on stream 0",
		req: "If a CONTINUATION frame is received with a Stream Identifier field of 0x00, the recipient MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			p.writeRaw(http2.FrameContinuation, http2.FlagContinuationEndHeaders, 0, block[1:])
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.10/4", name: "CONTINUATION after HEADERS with END_HEADERS",
		req: "A CONTINUATION frame MUST be preceded by a HEADERS, PUSH_PROMISE or CONTINUATION frame without the END_HEADERS flag set. A recipient that observes violation of this rule MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.answer(id)
			require.NoError(t, p.fr.WriteContinuation(id, true, p.block(hpack.HeaderField{Name: "x-a", Value: "1"})))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.10/5", name: "CONTINUATION after CONTINUATION with END_HEADERS",
		req: "A CONTINUATION frame MUST be preceded by a HEADERS, PUSH_PROMISE or CONTINUATION frame without the END_HEADERS flag set. A recipient that observes violation of this rule MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			require.NoError(t, p.fr.WriteContinuation(id, true, block[1:]))
			require.NoError(t, p.fr.WriteContinuation(id, true, p.block(hpack.HeaderField{Name: "x-a", Value: "1"})))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.10/6", name: "CONTINUATION after DATA",
		req: "A CONTINUATION frame MUST be preceded by a HEADERS, PUSH_PROMISE or CONTINUATION frame without the END_HEADERS flag set. A recipient that observes violation of this rule MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, false, []byte("x"))
			p.wantRead(s, []byte("x"))
			require.NoError(t, p.fr.WriteContinuation(id, true, p.block(hpack.HeaderField{Name: "x-a", Value: "1"})))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.1/1", name: "DATA on stream 0",
		req: "If a DATA frame is received whose Stream Identifier field is 0x00, the recipient MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameData, 0, 0, []byte("x"))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.1/2", name: "DATA on a stream the peer ended",
		req: "If a DATA frame is received whose stream is not in the \"open\" or \"half-closed (local)\" state, the recipient MUST respond with a stream error of type STREAM_CLOSED.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writeData(id, false, []byte("late"))
			p.wantStreamError(id, http2.ErrCodeStreamClosed)
		},
	},
	{
		id: "http2/6.1/3", name: "DATA with a pad length past its payload",
		req: "If the length of the padding is the length of the frame payload or greater, the recipient MUST treat this as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeRaw(http2.FrameData, http2.FlagDataPadded, id, []byte{10, 'a', 'b'})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.2/1", name: "HEADERS without END_HEADERS, then PRIORITY",
		req: "A HEADERS frame without the END_HEADERS flag set MUST be followed by a CONTINUATION frame for the same stream. A receiver MUST treat the receipt of any other type of frame or a frame on a different stream as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: p.block(status("200"))[:1]}))
			p.writePriority(id, http2.PriorityParam{Weight: 15})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.2/2", name: "HEADERS on another stream before END_HEADERS",
		req: "A HEADERS frame without the END_HEADERS flag set MUST be followed by a CONTINUATION frame for the same stream. A receiver MUST treat the receipt of any other type of frame or a frame on a different stream as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.open(Request{Authority: "origin.test:443"})
			id2 := p.wantHeaders().StreamID
			block := p.block(status("200"))
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:1]}))
			p.writeBlock(id2, false, block)
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.2/3", name: "HEADERS on stream 0",
		req: "If a HEADERS frame is received whose Stream Identifier field is 0x00, the recipient MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameHeaders, http2.FlagHeadersEndHeaders, 0, p.block(status("200")))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.2/4", name: "HEADERS with a pad length past its payload",
		req:  "Padding that exceeds the size remaining for the field block fragment MUST be treated as a PROTOCOL_ERROR.",
		skip: "the framer of x/net makes it a stream error on the stream, as Go's own server and transport do, before the client sees the frame",
	},
	{
		id: "http2/6.3/1", name: "PRIORITY on stream 0",
		req: "If a PRIORITY frame is received with a stream identifier of 0x00, the recipient MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FramePriority, 0, 0, make([]byte, 5))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.3/2", name: "PRIORITY of a length other than 5",
		req:  "A PRIORITY frame with a length other than 5 octets MUST be treated as a stream error of type FRAME_SIZE_ERROR.",
		skip: "the framer of x/net makes it a connection error of type FRAME_SIZE_ERROR, as Go's own server and transport do, before the client sees the frame",
	},
	{
		id: "http2/6.4/1", name: "RST_STREAM on stream 0",
		req: "If a RST_STREAM frame is received with a stream identifier of 0x0, the recipient MUST treat this as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameRSTStream, 0, 0, make([]byte, 4))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.4/2", name: "RST_STREAM on an idle stream",
		req: "RST_STREAM frames MUST NOT be sent for a stream in the \"idle\" state. If a RST_STREAM frame identifying an idle stream is received, the recipient MUST treat this as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.connect()
			p.writeRST(p.nextID, http2.ErrCodeCancel)
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.4/3", name: "RST_STREAM of a length other than 4",
		req: "A RST_STREAM frame with a length other than 4 octets MUST be treated as a connection error of type FRAME_SIZE_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeRaw(http2.FrameRSTStream, 0, id, make([]byte, 3))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},
	{
		id: "http2/6.5.2/1", name: "SETTINGS_ENABLE_PUSH of 2",
		req: "Any value other than 0 or 1 MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingEnablePush, Val: 2})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.5.2/2", name: "SETTINGS_INITIAL_WINDOW_SIZE past 2^31-1",
		req: "Values above the maximum flow-control window size of 2^31-1 MUST be treated as a connection error of type FLOW_CONTROL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 31})
			p.wantConnectionError(http2.ErrCodeFlowControl)
		},
	},
	{
		id: "http2/6.5.2/3", name: "SETTINGS_MAX_FRAME_SIZE below 2^14",
		req: "The initial value is 2^14 (16,384) octets. The value advertised by an endpoint MUST be between this initial value and the maximum allowed frame size (2^24-1 or 16,777,215 octets), inclusive. Values outside this range MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16383})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.5.2/4", name: "SETTINGS_MAX_FRAME_SIZE past 2^24-1",
		req: "Values outside this range MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: 1 << 24})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.5.2/5", name: "a SETTINGS parameter of an unknown identifier",
		req: "An endpoint that receives a SETTINGS frame with any unknown or unsupported identifier MUST ignore that setting.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: 0xff, Val: 1})
			p.wantSettingsAck()
			p.wantAlive()
		},
	},
	{
		id: "http2/6.5.3/1", name: "SETTINGS_INITIAL_WINDOW_SIZE twice in one frame",
		req: "The values in the SETTINGS frame MUST be processed in the order they appear, with no other frame processing between values.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 100})
			p.wantSettingsAck()
			s, id := p.connect()
			go func() { _, _ = s.Write(make([]byte, 150)) }()
			require.Len(t, p.wantData(id).Data(), 100)
			wantNothing[*http2.DataFrame](p, "DATA past the send window")
		},
	},
	{
		id: "http2/6.5.3/2", name: "SETTINGS is acknowledged",
		req: "Once all values have been processed, the recipient MUST immediately emit a SETTINGS frame with the ACK flag set.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100})
			p.wantSettingsAck()
		},
	},
	{
		id: "http2/6.5/1", name: "a SETTINGS ack with a payload",
		req: "Receipt of a SETTINGS frame with the ACK flag set and a length field value other than 0 MUST be treated as a connection error of type FRAME_SIZE_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameSettings, http2.FlagSettingsAck, 0, make([]byte, 6))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},
	{
		id: "http2/6.5/2", name: "SETTINGS on a stream",
		req: "If an endpoint receives a SETTINGS frame whose Stream Identifier field is anything other than 0x00, the endpoint MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameSettings, 0, 1, nil)
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.5/3", name: "SETTINGS of a length not a multiple of 6",
		req: "A SETTINGS frame with a length other than a multiple of 6 octets MUST be treated as a connection error of type FRAME_SIZE_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameSettings, 0, 0, make([]byte, 5))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},
	{
		id: "http2/6.7/1", name: "PING",
		req: "Receivers of a PING frame that does not include an ACK flag MUST send a PING frame with the ACK flag set in response, with an identical frame payload.",
		run: func(t *testing.T, p *peer) { p.wantAlive() },
	},
	{
		id: "http2/6.7/2", name: "a PING ack",
		req: "An endpoint MUST NOT respond to PING frames containing this flag.",
		run: func(t *testing.T, p *peer) {
			p.writePing(true, [8]byte{1})
			wantNothing[*http2.PingFrame](p, "an answer to a PING ack")
		},
	},
	{
		id: "http2/6.7/3", name: "PING on a stream",
		req: "If a PING frame is received with a Stream Identifier field value other than 0x00, the recipient MUST respond with a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeRaw(http2.FramePing, 0, id, make([]byte, 8))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.7/4", name: "PING of a length other than 8",
		req: "Receipt of a PING frame with a length field value other than 8 MUST be treated as a connection error of type FRAME_SIZE_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FramePing, 0, 0, make([]byte, 9))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},
	{
		id: "http2/6.8/1", name: "GOAWAY on a stream",
		req: "An endpoint MUST treat a GOAWAY frame with a stream identifier other than 0x00 as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeRaw(http2.FrameGoAway, 0, id, make([]byte, 8))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.9.1/1", name: "a send window of 1",
		req: "The sender MUST NOT send a flow-controlled frame with a length that exceeds the space available in either of the flow-control windows advertised by the receiver.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1})
			p.wantSettingsAck()
			s, id := p.connect()
			wrote := make(chan error, 1)
			go func() { _, err := s.Write(make([]byte, 10)); wrote <- err }()
			require.Len(t, p.wantData(id).Data(), 1)
			wantNothing[*http2.DataFrame](p, "DATA past the send window")
			p.writeWindowUpdate(id, 9)
			for got := 1; got < 10; {
				got += len(p.wantData(id).Data())
			}
			require.NoError(t, <-wrote)
		},
	},
	{
		id: "http2/6.9.1/2", name: "WINDOW_UPDATE past 2^31-1 on the connection",
		req: "If a sender receives a WINDOW_UPDATE that causes a flow-control window to exceed this maximum, it MUST terminate either the stream or the connection, as appropriate. For streams, the sender sends a RST_STREAM with an error code of FLOW_CONTROL_ERROR; for the connection, a GOAWAY frame with an error code of FLOW_CONTROL_ERROR is sent.",
		run: func(t *testing.T, p *peer) {
			p.writeWindowUpdate(0, 1<<31-1)
			p.wantConnectionError(http2.ErrCodeFlowControl)
		},
	},
	{
		id: "http2/6.9.1/3", name: "WINDOW_UPDATE past 2^31-1 on a stream",
		req: "For streams, the sender sends a RST_STREAM with an error code of FLOW_CONTROL_ERROR.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeWindowUpdate(id, 1<<31-1)
			p.wantStreamError(id, http2.ErrCodeFlowControl)
			p.wantReadCode(s, http2.ErrCodeFlowControl)
		},
	},
	{
		id: "http2/6.9.2/1", name: "SETTINGS_INITIAL_WINDOW_SIZE changed under an open stream",
		req: "When the value of SETTINGS_INITIAL_WINDOW_SIZE changes, a receiver MUST adjust the size of all stream flow-control windows that it maintains by the difference between the new value and the old value.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0})
			p.wantSettingsAck()
			s, id := p.connect()
			go func() { _, _ = s.Write(make([]byte, 5)) }()
			wantNothing[*http2.DataFrame](p, "DATA on a window of 0")
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 5})
			p.wantSettingsAck()
			require.Len(t, p.wantData(id).Data(), 5)
		},
	},
	{
		id: "http2/6.9.2/2", name: "SETTINGS_INITIAL_WINDOW_SIZE driving a send window negative",
		req: "A change to SETTINGS_INITIAL_WINDOW_SIZE can cause the available space in a flow-control window to become negative. A sender MUST track the negative flow-control window and MUST NOT send new flow-controlled frames until it receives WINDOW_UPDATE frames that cause the flow-control window to become positive.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 10})
			p.wantSettingsAck()
			s, id := p.connect()
			_, err := s.Write(make([]byte, 10))
			require.NoError(t, err)
			require.Len(t, p.wantData(id).Data(), 10)
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 5})
			p.wantSettingsAck()
			go func() { _, _ = s.Write(make([]byte, 3)) }()
			p.writeWindowUpdate(id, 5)
			wantNothing[*http2.DataFrame](p, "DATA on a window of 0")
			p.writeWindowUpdate(id, 3)
			require.Len(t, p.wantData(id).Data(), 3)
		},
	},
	{
		id: "http2/6.9.2/3", name: "SETTINGS_INITIAL_WINDOW_SIZE past 2^31-1",
		req: "An endpoint MUST treat a change to SETTINGS_INITIAL_WINDOW_SIZE that causes any flow-control window to exceed the maximum size as a connection error of type FLOW_CONTROL_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeWindowUpdate(id, 1<<30)
			p.writeSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 30})
			p.wantConnectionError(http2.ErrCodeFlowControl)
		},
	},
	{
		id: "http2/6.9/1", name: "WINDOW_UPDATE of 0 on the connection",
		req: "A receiver MUST treat the receipt of a WINDOW_UPDATE frame with a flow-control window increment of 0 as a stream error of type PROTOCOL_ERROR; errors on the connection flow-control window MUST be treated as a connection error.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameWindowUpdate, 0, 0, make([]byte, 4))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.9/2", name: "WINDOW_UPDATE of 0 on a stream",
		req: "A receiver MUST treat the receipt of a WINDOW_UPDATE frame with a flow-control window increment of 0 as a stream error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeRaw(http2.FrameWindowUpdate, 0, id, make([]byte, 4))
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/6.9/3", name: "WINDOW_UPDATE of a length other than 4",
		req: "A WINDOW_UPDATE frame with a length other than 4 octets MUST be treated as a connection error of type FRAME_SIZE_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameWindowUpdate, 0, 0, make([]byte, 5))
			p.wantConnectionError(http2.ErrCodeFrameSize)
		},
	},

	// RFC 9113 section 7, error codes.
	{
		id: "http2/7/1", name: "GOAWAY with an unknown error code",
		req: "Unknown or unsupported error codes MUST NOT trigger any special behavior. These MAY be treated by an implementation as being equivalent to INTERNAL_ERROR.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeGoAway(id, 0xff)
			p.wantClosed()
			_, err := p.read(s)
			require.Error(t, err)
			require.False(t, errors.Is(err, os.ErrDeadlineExceeded))
		},
	},
	{
		id: "http2/7/2", name: "RST_STREAM with an unknown error code",
		req: "Unknown or unsupported error codes MUST NOT trigger any special behavior.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeRST(id, 0xff)
			p.wantReadCode(s, 0xff)
			p.wantAlive()
		},
	},

	// RFC 9113 section 8, HTTP semantics.
	{
		id: "http2/8.1.2.1/1", name: "an unknown pseudo-header in the answer",
		req: "Endpoints MUST NOT generate pseudo-header fields other than those defined in this document. Endpoints MUST treat a request or response that contains undefined or invalid pseudo-header fields as malformed.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("200"), hpack.HeaderField{Name: ":foo", Value: "1"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.1.2.1/2", name: "a request pseudo-header in the answer",
		req: "Pseudo-header fields defined for requests MUST NOT appear in responses; pseudo-header fields defined for responses MUST NOT appear in requests.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("200"), hpack.HeaderField{Name: ":method", Value: "GET"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.1.2.1/3", name: "a pseudo-header in trailers",
		req: "Pseudo-header fields MUST NOT appear in a trailer section.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("404"))
			s, _, err := o.wait(t)
			require.NoError(t, err)
			p.writeHeaders(id, true, status("200"))
			p.wantStreamError(id, http2.ErrCodeProtocol)
			p.wantReadCode(s, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.1.2.1/4", name: "a pseudo-header after a regular field",
		req: "All pseudo-header fields MUST appear in a field block before all regular field lines. Any request or response that contains a pseudo-header field that appears in a field block after a regular field line MUST be treated as malformed.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, hpack.HeaderField{Name: "x-a", Value: "1"}, status("200"))
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.1.2.2/1", name: "a connection-specific field in the answer",
		req: "An endpoint MUST NOT generate an HTTP/2 message containing connection-specific header fields. Any message containing connection-specific header fields MUST be treated as malformed.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("200"), hpack.HeaderField{Name: "connection", Value: "close"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.1.2.2/2", name: "a TE other than trailers in the answer",
		req: "The only exception to this is the TE header field, which MAY be present in an HTTP/2 request; when it is, it MUST NOT contain any value other than \"trailers\".",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("200"), hpack.HeaderField{Name: "te", Value: "gzip"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.1.2.3/1", name: "an extended CONNECT with an empty :path",
		req: "This pseudo-header field MUST NOT be empty for \"http\" or \"https\" URIs.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
			p.wantSettingsAck()
			_, _, err := p.open(Request{Authority: "proxy.test", Protocol: "connect-udp", Scheme: "https"}).wait(t)
			require.ErrorIs(t, err, errNoTarget)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS of a refused request")
		},
	},
	{id: "http2/8.1.2.3/2", name: "a request without :method", req: "All HTTP/2 requests MUST include exactly one valid value for the :method, :scheme, and :path pseudo-header fields, unless they are CONNECT requests.", skip: "a rule on the requests a server receives, the client's own request is checked under rfc9113/8.5"},
	{id: "http2/8.1.2.3/3", name: "a request without :scheme", req: "All HTTP/2 requests MUST include exactly one valid value for the :method, :scheme, and :path pseudo-header fields, unless they are CONNECT requests.", skip: "a rule on the requests a server receives, the client's own request is checked under rfc9113/8.5"},
	{id: "http2/8.1.2.3/4", name: "a request without :path", req: "All HTTP/2 requests MUST include exactly one valid value for the :method, :scheme, and :path pseudo-header fields, unless they are CONNECT requests.", skip: "a rule on the requests a server receives, the client's own request is checked under rfc9113/8.5"},
	{id: "http2/8.1.2.3/5", name: "a request with two :method", req: "All HTTP/2 requests MUST include exactly one valid value for the :method, :scheme, and :path pseudo-header fields, unless they are CONNECT requests.", skip: "a rule on the requests a server receives, the client's own request is checked under rfc9113/8.5"},
	{id: "http2/8.1.2.3/6", name: "a request with two :scheme", req: "All HTTP/2 requests MUST include exactly one valid value for the :method, :scheme, and :path pseudo-header fields, unless they are CONNECT requests.", skip: "a rule on the requests a server receives, the client's own request is checked under rfc9113/8.5"},
	{id: "http2/8.1.2.3/7", name: "a request with two :path", req: "All HTTP/2 requests MUST include exactly one valid value for the :method, :scheme, and :path pseudo-header fields, unless they are CONNECT requests.", skip: "a rule on the requests a server receives, the client's own request is checked under rfc9113/8.5"},
	{id: "http2/8.1.2.6/1", name: "content-length against one DATA frame", req: "A request or response that is defined as having content is malformed if the value of a content-length header field does not equal the sum of the DATA frame payload lengths.", skip: "a CONNECT tunnel has no content, and a client MUST ignore a content-length in a 2xx answer to CONNECT, RFC 9110 section 9.3.6"},
	{id: "http2/8.1.2.6/2", name: "content-length against several DATA frames", req: "A request or response that is defined as having content is malformed if the value of a content-length header field does not equal the sum of the DATA frame payload lengths.", skip: "a CONNECT tunnel has no content, and a client MUST ignore a content-length in a 2xx answer to CONNECT, RFC 9110 section 9.3.6"},
	{
		id: "http2/8.1.2/1", name: "an uppercase field name in the answer",
		req: "A field name MUST NOT contain characters in the ranges 0x00-0x20, 0x41-0x5a, or 0x7f-0xff. A request or response containing uppercase characters in field names MUST be treated as malformed.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("200"), hpack.HeaderField{Name: "X-A", Value: "1"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.1/1", name: "a second HEADERS without END_STREAM",
		req: "A HEADERS frame with the END_STREAM flag set that carries an informational status code is malformed. Trailers ... consist of a HEADERS frame with the END_STREAM flag set. An endpoint that receives a HEADERS frame without the END_STREAM flag set after receiving the HEADERS frame that opens a request or after receiving a final (non-informational) status code MUST treat the corresponding request or response as malformed.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("404"))
			_, _, err := o.wait(t)
			require.NoError(t, err)
			p.writeHeaders(id, false, hpack.HeaderField{Name: "x-a", Value: "1"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "http2/8.2/1", name: "PUSH_PROMISE",
		req: "PUSH_PROMISE MUST NOT be sent if the SETTINGS_ENABLE_PUSH setting of the peer endpoint is set to 0. An endpoint that has set this setting and has received acknowledgment MUST treat the receipt of a PUSH_PROMISE frame as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			_, id := p.connect()
			p.writeRaw(http2.FramePushPromise, http2.FlagPushPromiseEndHeaders, id, cat([]byte{0, 0, 0, 2}, p.block(hpack.HeaderField{Name: ":method", Value: "GET"})))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},

	// h2spec hpack, RFC 7541: decoding errors end the connection with COMPRESSION_ERROR,
	// RFC 9113 section 4.3.
	{
		id: "hpack/2.3.3/1", name: "an indexed field past the tables",
		req: "Indices ... MUST be treated as a decoding error.",
		run: func(t *testing.T, p *peer) { wantCompressionError(t, p, []byte{0xff, 0x01}) },
	},
	{
		id: "hpack/2.3.3/2", name: "a literal whose name index is past the tables",
		req: "Indices ... MUST be treated as a decoding error.",
		run: func(t *testing.T, p *peer) { wantCompressionError(t, p, cat([]byte{0x7f, 0x01}, str("200"))) },
	},
	{
		id: "hpack/4.2/1", name: "a dynamic table size update at the end of the block",
		req: "This dynamic table size update MUST occur at the beginning of the first header block following the change to the dynamic table size.",
		run: func(t *testing.T, p *peer) {
			wantAnswerBlock(t, p, cat([]byte{0x88, 0x40}, str("x-a"), str("1")))
			wantCompressionError(t, p, []byte{0x88, 0x20})
		},
	},
	{
		id: "hpack/5.2/1", name: "a Huffman string padded by more than 7 bits",
		req: "A padding strictly longer than 7 bits MUST be treated as a decoding error.",
		run: func(t *testing.T, p *peer) {
			b := hpack.AppendHuffmanString(nil, "200")
			wantCompressionError(t, p, cat([]byte{0x08, 0x80 | byte(len(b)+1)}, b, []byte{0xff}))
		},
	},
	{
		id: "hpack/5.2/2", name: "a Huffman string padded with zeros",
		req: "A padding not corresponding to the most significant bits of the code for the EOS symbol MUST be treated as a decoding error.",
		run: func(t *testing.T, p *peer) { wantCompressionError(t, p, []byte{0x08, 0x81, 0x10}) },
	},
	{
		id: "hpack/5.2/3", name: "a Huffman string holding the EOS symbol",
		req: "A Huffman-encoded string literal containing the EOS symbol MUST be treated as a decoding error.",
		run: func(t *testing.T, p *peer) { wantCompressionError(t, p, []byte{0x08, 0x84, 0xff, 0xff, 0xff, 0xff}) },
	},
	{
		id: "hpack/6.1/1", name: "an indexed field of index 0",
		req: "The index value of 0 is not used. It MUST be treated as a decoding error if found in an indexed header field representation.",
		run: func(t *testing.T, p *peer) { wantCompressionError(t, p, []byte{0x80}) },
	},
	{
		id: "hpack/6.3/1", name: "a dynamic table size update past SETTINGS_HEADER_TABLE_SIZE",
		req: "The new maximum size MUST be lower than or equal to the limit determined by the protocol using HPACK. A value that exceeds this limit MUST be treated as a decoding error.",
		run: func(t *testing.T, p *peer) { wantCompressionError(t, p, []byte{0x3f, 0xe1, 0x3f, 0x88}) },
	},

	// RFC 8441, extended CONNECT.
	{
		id: "rfc8441/3/1", name: "SETTINGS_ENABLE_CONNECT_PROTOCOL of 2",
		req: "Upon receipt of SETTINGS_ENABLE_CONNECT_PROTOCOL with a value of 1, a client MAY use the Extended CONNECT ... Any value other than 0 or 1 MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 2})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc8441/3/2", name: "SETTINGS_ENABLE_CONNECT_PROTOCOL from 1 back to 0",
		req: "A sender MUST NOT send a SETTINGS_ENABLE_CONNECT_PROTOCOL parameter with the value of 0 after previously sending a value of 1.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
			p.wantSettingsAck()
			p.writeSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 0})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc8441/4/1", name: "an extended CONNECT before the setting",
		req: "A client MUST NOT send the extended CONNECT method to a server that has not advertised support.",
		run: func(t *testing.T, p *peer) {
			_, _, err := p.open(Request{Authority: "proxy.test", Protocol: "connect-udp", Scheme: "https", Path: "/.well-known/masque/udp/h/1/"}).wait(t)
			require.ErrorIs(t, err, ErrExtendedConnect)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS of an extended CONNECT the peer did not enable")
		},
	},
	{
		id: "rfc8441/4/2", name: "the pseudo-headers of an extended CONNECT",
		req: "A new pseudo-header field :protocol MAY be included on request HEADERS indicating the desired protocol of the tunnel created by CONNECT. On requests that contain the :protocol pseudo-header field, the :scheme and :path pseudo-header fields of the target URI MUST also be included. The :authority pseudo-header field contains the host and port to connect to.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
			p.wantSettingsAck()
			p.open(Request{Authority: "proxy.test", Protocol: "connect-udp", Scheme: "https", Path: "/.well-known/masque/udp/h/1/"})
			f := p.wantHeaders()
			require.Equal(t, "CONNECT", f.PseudoValue("method"))
			require.Equal(t, "connect-udp", f.PseudoValue("protocol"))
			require.Equal(t, "https", f.PseudoValue("scheme"))
			require.Equal(t, "/.well-known/masque/udp/h/1/", f.PseudoValue("path"))
			require.Equal(t, "proxy.test", f.PseudoValue("authority"))
		},
	},
	{
		id: "rfc8441/4/3", name: "an extended CONNECT without :scheme and :path",
		req: "On requests that contain the :protocol pseudo-header field, the :scheme and :path pseudo-header fields of the target URI MUST also be included.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
			p.wantSettingsAck()
			_, _, err := p.open(Request{Authority: "proxy.test", Protocol: "connect-udp"}).wait(t)
			require.ErrorIs(t, err, errNoTarget)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS of a refused request")
		},
	},

	// RFC 9113, what h2spec has no case for.
	{
		id: "rfc9113/6.5.2/1", name: "SETTINGS_ENABLE_PUSH of 1 from a server",
		req: "A server MUST NOT explicitly set this value to 1. A client MUST treat receipt of a SETTINGS frame with SETTINGS_ENABLE_PUSH set to 1 as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingEnablePush, Val: 1})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/8.5/1", name: "the pseudo-headers of a CONNECT",
		req: "The :method pseudo-header field is set to CONNECT. The :scheme and :path pseudo-header fields MUST be omitted. The :authority pseudo-header field contains the host and port to connect to.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			f := p.wantHeaders()
			require.Equal(t, "CONNECT", f.PseudoValue("method"))
			require.Equal(t, "origin.test:443", f.PseudoValue("authority"))
			require.Empty(t, f.PseudoValue("scheme"))
			require.Empty(t, f.PseudoValue("path"))
			require.Empty(t, f.PseudoValue("protocol"))
		},
	},
	{
		id: "rfc9113/8.5/2", name: "a CONNECT without an authority",
		req: "The :authority pseudo-header field contains the host and port to connect to. A CONNECT request that does not conform to these restrictions is malformed.",
		run: func(t *testing.T, p *peer) {
			_, _, err := p.open(Request{}).wait(t)
			require.ErrorIs(t, err, errNoAuthority)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS of a refused request")
		},
	},
	{
		id: "rfc9113/8.5/3", name: "trailers on a connected stream",
		req: "A CONNECT request that ... the proxy sends a 2xx (Successful) response ... After the initial HEADERS frame sent by each peer, all subsequent HEADERS frames MUST NOT be sent: DATA frames alone are sent on the stream from there on.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeHeaders(id, true, hpack.HeaderField{Name: "x-trailer", Value: "1"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
			p.wantReadCode(s, http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/8.1/1", name: "trailers after a refusal",
		req: "Trailers ... consist of a HEADERS frame with the END_STREAM flag set ... A response consists of ... a final HEADERS frame ... and optionally a trailer section.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("404"))
			s, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, http.StatusNotFound, resp.StatusCode)
			p.writeData(id, false, []byte("denied"))
			p.writeHeaders(id, true, hpack.HeaderField{Name: "x-trailer", Value: "1"})
			p.wantRead(s, []byte("denied"))
			p.wantReadError(s, io.EOF)
			p.wantAlive()
		},
	},
	{
		id: "rfc9113/8.1/2", name: "an informational answer before the final one",
		req: "A response is a series of zero or more informational (1xx) responses, each of which consists of a HEADERS frame, followed by the final response, which consists of a HEADERS frame.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("103"))
			p.answer(id)
			_, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		},
	},
	{
		id: "rfc9113/8.1/3", name: "an informational answer with END_STREAM",
		req: "A HEADERS frame with the END_STREAM flag set that carries an informational status code is malformed.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, true, status("103"))
			p.wantStreamError(id, http2.ErrCodeProtocol)
			_, _, err := o.wait(t)
			require.Error(t, err, "Open waits for an answer that cannot come")
		},
	},
	{
		id: "rfc9113/8.1/4", name: "DATA before the answer",
		req: "A response consists of ... the final response, which consists of a HEADERS frame, followed by zero or more DATA frames.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeData(id, true, []byte("early"))
			p.wantStreamError(id, http2.ErrCodeProtocol)
			_, _, err := o.wait(t)
			require.Error(t, err, "Open waits for an answer that cannot come")
		},
	},
	{
		id: "rfc9113/8.3.2/1", name: "a :status that is not three digits",
		req: "A single :status pseudo-header field is defined that carries the HTTP status code field. This pseudo-header field MUST be included in all responses, including interim responses.",
		run: func(t *testing.T, p *peer) {
			for _, bad := range []string{"0200", "+200", "20", "2O0", "099"} {
				o := p.open(Request{Authority: "origin.test:443"})
				id := p.wantHeaders().StreamID
				p.writeHeaders(id, false, status(bad))
				p.wantStreamError(id, http2.ErrCodeProtocol)
				_, _, err := o.wait(t)
				require.Error(t, err, "a :status of %q was taken as the answer", bad)
			}
		},
	},
	{
		id: "rfc9113/8.3.2/2", name: "an answer without :status",
		req: "This pseudo-header field MUST be included in all responses, including interim responses.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, hpack.HeaderField{Name: "x-a", Value: "1"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/8.2.1/1", name: "a field value with CR or LF from the caller",
		req: "A field value MUST NOT contain the zero value (ASCII NUL, 0x00), line feed (ASCII LF, 0x0a), or carriage return (ASCII CR, 0x0d) at any position.",
		run: func(t *testing.T, p *peer) {
			_, _, err := p.open(Request{Authority: "origin.test:443", Header: http.Header{"X-A": {"1\r\nx-b: 2"}}}).wait(t)
			require.ErrorIs(t, err, errInvalidHeader)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS of a refused request")
		},
	},
	{
		id: "rfc9113/8.2.1/2", name: "a field value with surrounding whitespace from the caller",
		req: "A field value MUST NOT start or end with an ASCII whitespace character (ASCII SP or HTAB, 0x20 or 0x09).",
		run: func(t *testing.T, p *peer) {
			_, _, err := p.open(Request{Authority: "origin.test:443", Header: http.Header{"X-A": {" 1"}}}).wait(t)
			require.ErrorIs(t, err, errInvalidHeader)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS of a refused request")
		},
	},
	{
		id: "rfc9113/8.2.2/1", name: "a connection-specific field from the caller",
		req: "An endpoint MUST NOT generate an HTTP/2 message containing connection-specific header fields.",
		run: func(t *testing.T, p *peer) {
			_, _, err := p.open(Request{Authority: "origin.test:443", Header: http.Header{"Connection": {"close"}}}).wait(t)
			require.ErrorIs(t, err, errInvalidHeader)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS of a refused request")
		},
	},
	{
		id: "rfc9113/6.8/1", name: "GOAWAY with open streams",
		req: "Once the GOAWAY is sent, the sender will ignore frames sent on streams initiated by the receiver if the stream has an identifier higher than the included last stream identifier. Receivers of a GOAWAY frame MUST NOT open additional streams on the connection.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeGoAway(id, http2.ErrCodeNo)
			require.Eventually(t, func() bool { return !p.c.CanOpen() }, wantTimeout, time.Millisecond)
			_, _, err := p.open(Request{Authority: "origin.test:443"}).wait(t)
			require.ErrorIs(t, err, ErrGoAway)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS after GOAWAY")
			p.writeData(id, false, []byte("still"))
			p.wantRead(s, []byte("still"))
			require.NoError(t, s.Close())
			p.wantGoAway(http2.ErrCodeNo)
			p.wantClosed()
		},
	},
	{
		id: "rfc9113/6.8/2", name: "GOAWAY ending the streams above its last stream id",
		req: "The last stream identifier in the GOAWAY frame contains the highest-numbered stream identifier for which the sender of the GOAWAY frame might have taken some action on or might yet take action on. All streams up to and including the identified stream might have been processed in some way. Activity on streams numbered higher than the last stream identifier cannot have been processed.",
		run: func(t *testing.T, p *peer) {
			s1, id1 := p.connect()
			s2, id2 := p.connect()
			p.writeGoAway(id1, http2.ErrCodeNo)
			p.wantReadError(s2, ErrGoAway)
			wantNothing[*http2.RSTStreamFrame](p, "RST_STREAM on a stream the peer will not process")
			p.writeData(id1, false, []byte("still"))
			p.wantRead(s1, []byte("still"))
			_ = id2
		},
	},
	{
		id: "rfc9113/6.8/3", name: "a second GOAWAY lowering the last stream id",
		req: "An endpoint MAY send multiple GOAWAY frames if circumstances change. ... Endpoints MUST NOT increase the value they send in the last stream identifier, since the peers might already have retried unprocessed requests on another connection.",
		run: func(t *testing.T, p *peer) {
			s1, id1 := p.connect()
			s2, id2 := p.connect()
			p.writeGoAway(id2, http2.ErrCodeNo)
			require.Eventually(t, func() bool { return !p.c.CanOpen() }, wantTimeout, time.Millisecond)
			p.writeGoAway(id1, http2.ErrCodeNo)
			p.wantReadError(s2, ErrGoAway)
			p.writeData(id1, false, []byte("still"))
			p.wantRead(s1, []byte("still"))
		},
	},
	{
		id: "rfc9113/6.9.1/1", name: "padding is credited back",
		req: "The entire DATA frame payload is included in flow control, including the Pad Length and Padding fields if present.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, p.fr.WriteDataPadded(id, false, []byte("hello"), make([]byte, 255)))
			p.wantRead(s, []byte("hello"))
			require.NoError(t, s.Close())
			p.wantRST(id, http2.ErrCodeCancel)
			var credited uint32
			for credited < 261 {
				credited += p.wantWindowUpdate(0)
			}
			require.Equal(t, uint32(261), credited)
		},
	},
	{
		id: "rfc9113/5.1/1", name: "RST_STREAM on a stream that ended in both directions",
		req: "An endpoint MUST NOT send a RST_STREAM in response to a RST_STREAM frame, to avoid looping. ... An endpoint MUST minimally process and then discard any frames it receives in this state.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, s.CloseWrite())
			f := p.wantData(id)
			require.True(t, f.StreamEnded())
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writeRST(id, http2.ErrCodeCancel)
			wantNothing[*http2.RSTStreamFrame](p, "RST_STREAM in answer to RST_STREAM")
			p.wantAlive()
		},
	},
	{
		id: "rfc9113/5.4.2/1", name: "a stream error ends that stream alone",
		req: "A stream error is an error related to a specific stream that does not affect processing of other streams. An endpoint that detects a stream error sends a RST_STREAM frame that contains the stream identifier of the stream where the error occurred.",
		run: func(t *testing.T, p *peer) {
			s1, id1 := p.connect()
			s2, id2 := p.connect()
			p.writeHeaders(id2, false, status("bad"))
			p.wantStreamError(id2, http2.ErrCodeProtocol)
			p.wantReadCode(s2, http2.ErrCodeProtocol)
			p.writeData(id1, false, []byte("on"))
			p.wantRead(s1, []byte("on"))
		},
	},

	{
		id: "rfc9113/5.1/2", name: "DATA on an even stream id",
		req: "Receiving any frame other than HEADERS or PRIORITY on a stream in this state MUST be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			p.connect()
			p.writeData(2, false, []byte("x"))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/5.1/3", name: "a WINDOW_UPDATE the framer refuses on an idle stream",
		req: "Receiving any frame other than HEADERS or PRIORITY on a stream in this state MUST be treated as a connection error of type PROTOCOL_ERROR. ... RST_STREAM frames MUST NOT be sent for a stream in the \"idle\" state.",
		run: func(t *testing.T, p *peer) {
			p.writeRaw(http2.FrameWindowUpdate, 0, 101, []byte{0, 0, 0, 0})
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/5.1/4", name: "HEADERS the framer refuses on a stream the server would open",
		req: "If this stream is initiated by the server, as described in Section 5.1.1, then receiving a HEADERS frame MUST also be treated as a connection error of type PROTOCOL_ERROR.",
		run: func(t *testing.T, p *peer) {
			// A regular field ahead of a pseudo-header, which the framer refuses on its own.
			p.writeHeaders(2, false, hpack.HeaderField{Name: "x-first", Value: "1"}, status("200"))
			p.wantConnectionError(http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/5.1/5", name: "a write on a stream the peer ended at once",
		req: "A stream that is \"half-closed (remote)\" can be used by the endpoint to send frames of any type.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, true, status("200"))
			s, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, 200, resp.StatusCode)
			n, err := s.Write([]byte("still open"))
			require.NoError(t, err)
			require.Equal(t, 10, n)
			require.Equal(t, "still open", string(p.wantData(id).Data()))
		},
	},
	{
		id: "rfc9113/5.1/6", name: "a WINDOW_UPDATE after the client's END_STREAM",
		req: "An endpoint can receive any type of frame in this state.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			require.NoError(t, s.CloseWrite())
			require.True(t, p.wantData(id).StreamEnded())
			p.writeWindowUpdate(id, 1024)
			p.wantAlive()
		},
	},
	{
		id: "rfc9113/4.2/2", name: "DATA split at the peer's frame size",
		req: "The size of a frame payload is limited by the maximum size that a receiver advertises in the SETTINGS_MAX_FRAME_SIZE setting.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(
				http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384},
				http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
			p.wantSettingsAck()
			s, id := p.connect()
			p.writeWindowUpdate(0, 1<<20)
			const total = 200 << 10
			go func() { _, _ = s.Write(make([]byte, total)) }()
			for sent := 0; sent < total; {
				f := p.wantData(id)
				require.LessOrEqual(t, int(f.Length), 16384)
				sent += int(f.Length)
			}
		},
	},
	{
		id: "rfc9113/4.2/1", name: "a request past the peer's frame size continues",
		req: "An endpoint MUST send an error code of FRAME_SIZE_ERROR if a frame exceeds the size defined in SETTINGS_MAX_FRAME_SIZE. ... Field blocks MUST be transmitted as a contiguous sequence of frames.",
		run: func(t *testing.T, p *peer) {
			p.fr.ReadMetaHeaders = nil
			o := p.open(Request{Authority: "origin.test:443", Header: http.Header{"X-Big": {strings.Repeat("{", 40<<10)}}})
			f := next[*http2.HeadersFrame](p, "HEADERS")
			require.False(t, f.HeadersEnded())
			require.LessOrEqual(t, len(f.HeaderBlockFragment()), 16384)
			block := bytes.Clone(f.HeaderBlockFragment())
			for {
				cf := next[*http2.ContinuationFrame](p, "CONTINUATION")
				require.LessOrEqual(t, len(cf.HeaderBlockFragment()), 16384)
				block = append(block, cf.HeaderBlockFragment()...)
				if cf.HeadersEnded() {
					break
				}
			}
			fields, err := hpack.NewDecoder(hpackTableSize, nil).DecodeFull(block)
			require.NoError(t, err)
			require.Equal(t, "CONNECT", fields[0].Value)
			p.answer(f.StreamID)
			_, _, err = o.wait(t)
			require.NoError(t, err)
		},
	},
	{
		id: "rfc9113/6.9.1/2", name: "DATA past the connection window",
		req: "A receiver MAY respond with a stream error or connection error of type FLOW_CONTROL_ERROR if it receives more data than it advertised. The client ends the connection.",
		run: func(t *testing.T, p *peer) {
			// Every stream window is exact, only their sum passes the connection window.
			for range connWindow/window + 1 {
				o := p.open(Request{Authority: "origin.test:443"})
				id := p.wantHeaders().StreamID
				p.answer(id)
				if _, _, err := o.wait(t); err != nil {
					break
				}
				for sent := 0; sent < window; sent += 16384 {
					if err := p.fr.WriteData(id, false, make([]byte, 16384)); err != nil {
						break
					}
				}
			}
			select {
			case <-p.c.Done():
			case <-time.After(wantTimeout):
				t.Fatal("the client took more stream windows than the connection window has")
			}
			var ce http2.ConnectionError
			require.ErrorAs(t, p.c.Err(), &ce)
			require.Equal(t, http2.ErrCodeFlowControl, http2.ErrCode(ce))
		},
	},
	{
		id: "rfc9113/6.8/5", name: "a retired connection leaves with GOAWAY",
		req: "An endpoint that wishes to shut down ... A GOAWAY frame might not immediately precede closing of the connection; a receiver of a GOAWAY that has no more use for the connection SHOULD still send a GOAWAY frame before terminating the connection. The error code NO_ERROR is used for a graceful shutdown.",
		run: func(t *testing.T, p *peer) {
			s, _ := p.connect()
			p.c.Retire()
			require.Eventually(t, func() bool { return !p.c.CanOpen() }, wantTimeout, time.Millisecond)
			_, _, err := p.open(Request{Authority: "origin.test:443"}).wait(t)
			require.ErrorIs(t, err, ErrGoAway)
			require.NoError(t, s.Close())
			p.wantGoAway(http2.ErrCodeNo)
			p.wantClosed()
			require.ErrorIs(t, p.c.Err(), ErrGoAway)
		},
	},
	{
		id: "rfc9113/6.8/6", name: "what a Write reported leaves ahead of a graceful GOAWAY",
		req: "GOAWAY allows an endpoint to gracefully stop accepting new streams while still finishing processing of previously established streams. A Write that returned reached the socket unless the connection failed.",
		run: func(t *testing.T, p *peer) {
			cli, srv := tcpPair(t)
			p = dialPeerOn(t, &slowConn{Conn: cli, delay: 400 * time.Millisecond}, srv)
			p.writeSettings()
			p.wantSettingsAck()
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.c.Retire()
			// The first write is in the write goroutine's hands, the second in the
			// buffer serve still owns when the CloseWrite drains the connection.
			_, err := s.Write([]byte("first"))
			require.NoError(t, err)
			_, err = s.Write([]byte("second"))
			require.NoError(t, err)
			require.NoError(t, s.CloseWrite())
			var got []byte
			for f := p.wantData(id); ; f = p.wantData(id) {
				got = append(got, f.Data()...)
				if f.StreamEnded() {
					break
				}
			}
			require.Equal(t, "firstsecond", string(got))
			p.wantGoAway(http2.ErrCodeNo)
			p.wantClosed()
		},
	},
	{
		id: "rfc9113/6.8/7", name: "the last END_STREAM leaves ahead of the answer to the peer's GOAWAY",
		req: "GOAWAY allows an endpoint to gracefully stop accepting new streams while still finishing processing of previously established streams.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeData(id, true, nil)
			p.wantReadError(s, io.EOF)
			p.writeGoAway(id, http2.ErrCodeNo)
			require.Eventually(t, func() bool { return !p.c.CanOpen() }, wantTimeout, time.Millisecond)
			require.NoError(t, s.CloseWrite())
			require.True(t, p.wantData(id).StreamEnded())
			p.wantGoAway(http2.ErrCodeNo)
			p.wantClosed()
		},
	},
	{
		id: "rfc9113/8.2.2/2", name: "a connection-specific field in trailers",
		req: "Any message containing connection-specific header fields MUST be treated as malformed. Clients MUST NOT accept a malformed response.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("403"))
			s, _, err := o.wait(t)
			require.NoError(t, err)
			p.writeHeaders(id, true, hpack.HeaderField{Name: "connection", Value: "keep-alive"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
			p.wantReadCode(s, http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/8.2.2/3", name: "a connection-specific field in an informational answer",
		req: "Any message containing connection-specific header fields MUST be treated as malformed. Clients MUST NOT accept a malformed response.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("103"), hpack.HeaderField{Name: "connection", Value: "keep-alive"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
			_, _, err := o.wait(t)
			require.Error(t, err)
		},
	},
	// Scenarios of Go's HTTP/2 transport tests that apply to a client of CONNECT streams
	// and that no case above covers.
	{
		id: "rfc9113/6.9/4", name: "the client credits what it reads",
		req: "Flow control is specific to a connection. ... A receiver ... sends WINDOW_UPDATE frames as it consumes data and frees up space in flow-control windows.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			const total = 3 * window
			done := make(chan []byte, 1)
			go func() { done <- p.wantReadAll(s, total) }()
			var sent, avail int
			avail = window
			for sent < total {
				n := min(avail, 16384, total-sent)
				if n == 0 {
					avail += int(p.wantWindowUpdate(id))
					continue
				}
				p.writeData(id, false, bytes.Repeat([]byte{byte(sent)}, n))
				sent += n
				avail -= n
			}
			select {
			case got := <-done:
				require.Len(t, got, total)
			case <-time.After(wantTimeout):
				t.Fatal("the reads did not complete")
			}
		},
	},
	{
		id: "rfc9113/6.5.2/2", name: "the request bounded by the peer's SETTINGS_MAX_HEADER_LIST_SIZE",
		req: "SETTINGS_MAX_HEADER_LIST_SIZE: This advisory setting informs a peer of the maximum field section size that the sender is prepared to accept, in octets.",
		run: func(t *testing.T, p *peer) {
			p.writeSettings(http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 300})
			p.wantSettingsAck()
			_, _, err := p.open(Request{Authority: "origin.test:443", Header: http.Header{"X-A": {strings.Repeat("a", 1000)}}}).wait(t)
			require.ErrorIs(t, err, errHeadersTooLarge)
			wantNothing[*http2.MetaHeadersFrame](p, "HEADERS past the peer's bound")
			p.connect()
		},
	},
	{
		id: "rfc9113/6.5.2/3", name: "an answer past the client's SETTINGS_MAX_HEADER_LIST_SIZE",
		req: "SETTINGS_MAX_HEADER_LIST_SIZE: This advisory setting informs a peer of the maximum field section size that the sender is prepared to accept, in octets.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			// Fields that fit a frame each, past the bound together, a decoder that stops
			// emitting rather than one refusing a string, RFC 9113 section 10.5.1.
			fields := []hpack.HeaderField{status("200")}
			for i := range 64 {
				fields = append(fields, hpack.HeaderField{Name: fmt.Sprintf("x-%02d", i), Value: strings.Repeat("{", 1000)})
			}
			block := p.block(fields...)
			require.NoError(t, p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block[:16384]}))
			for block = block[16384:]; len(block) > 16384; block = block[16384:] {
				require.NoError(t, p.fr.WriteContinuation(id, false, block[:16384]))
			}
			require.NoError(t, p.fr.WriteContinuation(id, true, block))
			p.wantStreamError(id, http2.ErrCodeEnhanceYourCalm)
			_, _, err := o.wait(t)
			require.Error(t, err)
		},
	},
	{
		id: "rfc7541/4.2/1", name: "the encoder signals the peer's table size",
		req: "This dynamic table size update MUST occur at the beginning of the first header block following the change to the dynamic table size.",
		run: func(t *testing.T, p *peer) {
			p.connect()
			p.writeSettings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 0})
			p.wantSettingsAck()
			p.fr.ReadMetaHeaders = nil
			p.open(Request{Authority: "origin.test:443"})
			f := next[*http2.HeadersFrame](p, "HEADERS")
			require.Equal(t, byte(0x20), f.HeaderBlockFragment()[0], "a dynamic table size update to 0 opens the block")
		},
	},
	{
		id: "rfc9113/6.8/4", name: "GOAWAY with an error code",
		req: "The error code ... contains the reason for closing the connection.",
		run: func(t *testing.T, p *peer) {
			s, id := p.connect()
			p.writeGoAway(id, http2.ErrCodeInternal)
			p.wantClosed()
			var ce http2.ConnectionError
			require.ErrorAs(t, p.c.Err(), &ce)
			require.Equal(t, http2.ErrCodeInternal, http2.ErrCode(ce))
			_, err := p.read(s)
			require.ErrorAs(t, err, &ce)
		},
	},
	{
		id: "rfc9113/5.4.2/2", name: "RST_STREAM before the answer",
		req: "RST_STREAM ... allows for immediate termination of a stream. ... The RST_STREAM frame contains a single unsigned, 32-bit integer identifying the error code. The error code indicates why the stream is being terminated.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeRST(id, http2.ErrCodeRefusedStream)
			_, _, err := o.wait(t)
			var se http2.StreamError
			require.ErrorAs(t, err, &se)
			require.Equal(t, http2.ErrCodeRefusedStream, se.Code)
			p.wantAlive()
		},
	},
	{
		id: "rfc9113/8.1/5", name: "many informational answers of unknown codes",
		req: "A response is a series of zero or more informational (1xx) responses, each of which consists of a HEADERS frame, followed by the final response.",
		run: func(t *testing.T, p *peer) {
			o := p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			for range 100 {
				p.writeHeaders(id, false, status("199"), hpack.HeaderField{Name: "x-hint", Value: strings.Repeat("h", 1000)})
			}
			p.answer(id)
			_, resp, err := o.wait(t)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		},
	},
	{
		id: "rfc9113/8.2.1/3", name: "a field value with CR or LF in the answer",
		req: "A field value MUST NOT contain the zero value (ASCII NUL, 0x00), line feed (ASCII LF, 0x0a), or carriage return (ASCII CR, 0x0d) at any position. ... A request or response that contains a field that violates any of these conditions MUST be treated as malformed.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("200"), hpack.HeaderField{Name: "x-a", Value: "1\r\nx-b: 2"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
	{
		id: "rfc9113/8.2.1/4", name: "an empty field name in the answer",
		req: "A field name MUST NOT contain characters in the ranges 0x00-0x20, 0x41-0x5a, or 0x7f-0xff. ... A request or response that contains a field that violates any of these conditions MUST be treated as malformed.",
		run: func(t *testing.T, p *peer) {
			p.open(Request{Authority: "origin.test:443"})
			id := p.wantHeaders().StreamID
			p.writeHeaders(id, false, status("200"), hpack.HeaderField{Name: "", Value: "1"})
			p.wantStreamError(id, http2.ErrCodeProtocol)
		},
	},
}

// ended closes s in both directions, the client's END_STREAM first.
func ended(t *testing.T, p *peer, s *Stream, id uint32) {
	t.Helper()
	require.NoError(t, s.CloseWrite())
	require.True(t, p.wantData(id).StreamEnded())
	p.writeData(id, true, nil)
	p.wantReadError(s, io.EOF)
}

// wantCompressionError sends block as the answer and wants the decoding error to end the
// connection, RFC 9113 section 4.3.
func wantCompressionError(t *testing.T, p *peer, block []byte) {
	t.Helper()
	p.open(Request{Authority: "origin.test:443"})
	id := p.wantHeaders().StreamID
	p.writeBlock(id, false, block)
	p.wantConnectionError(http2.ErrCodeCompression)
}

// wantAnswerBlock sends block as the answer and wants it decoded as a 200.
func wantAnswerBlock(t *testing.T, p *peer, block []byte) {
	t.Helper()
	o := p.open(Request{Authority: "origin.test:443"})
	id := p.wantHeaders().StreamID
	p.writeBlock(id, false, block)
	_, resp, err := o.wait(t)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
