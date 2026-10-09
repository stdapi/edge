// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// The gRPC conformance is checked against grpcurl, which drives the proxy with grpc-go's own
// client, so the test reads what a real client makes of a status the proxy wrote.
func requireGRPCurl(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("grpcurl")
	if err != nil {
		t.Skipf("no grpcurl on PATH: %v", err)
	}
	return path
}

func grpcConformanceOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	origin := httptest.NewUnstartedServer(grpcEchoHandler(nil))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	t.Cleanup(origin.Close)
	return origin
}

// grpcEchoHandler echoes every message, recording the protocol of each call on seen when it is
// given one.
func grpcEchoHandler(seen *recorder) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			seen.add(r.Proto)
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		src := &msgSource{r: r.Body, max: defaultMaxMessageBytes}
		for {
			payload, flag, err := src.next()
			if err != nil {
				break
			}
			_, _ = w.Write(appendGRPCFrame(nil, flag, payload))
			_ = rc.Flush()
		}
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
}

// grpc-go sends nothing to a proxy for a loopback address, so the origin is reached as
// example.com, the name in the httptest certificate, and the transport dials that name back
// to the loopback.
func grpcConformanceProxy(t *testing.T, origin *httptest.Server) (p *Proxy, target, proxyAddr, caFile string) {
	t.Helper()
	originURL, err := url.Parse(origin.URL)
	require.NoError(t, err)
	_, port := splitHostPort(originURL.Host)
	target = "example.com:" + port

	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	if origin.TLS != nil {
		tr.RootCAs = originPool(t, origin)
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == target {
			addr = originURL.Host
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	p, err = New(WithCA(ca), WithTransport(tr))
	require.NoError(t, err)
	return p, target, startProxy(t, p), writeCAFile(t, ca)
}

// runGRPCurl runs grpcurl through the proxy, in the clear when caFile is empty.
func runGRPCurl(t *testing.T, proxyAddr, caFile string, args ...string) (string, error) {
	t.Helper()
	bin := requireGRPCurl(t)
	full := []string{"-cacert", caFile}
	if caFile == "" {
		full = []string{"-plaintext"}
	}
	full = append(full,
		"-import-path", "testdata/grpc", "-proto", "echo.proto",
		"-max-time", "10",
	)
	full = append(full, args...)
	cmd := exec.Command(bin, full...)
	cmd.Env = append(os.Environ(), "HTTPS_PROXY=http://"+proxyAddr)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestConformanceGRPC_UnaryThroughForward(t *testing.T) {
	requireGRPCurl(t)
	origin := grpcConformanceOrigin(t)
	p, target, proxyAddr, caFile := grpcConformanceProxy(t, origin)
	p.MustAdd("example.com/pkg.Svc/Method", func(c *GRPCCtx) error { return c.Forward() })

	out, err := runGRPCurl(t, proxyAddr, caFile, "-d", `{"text":"hello"}`, target, "pkg.Svc/Method")
	require.NoError(t, err, out)
	assert.Contains(t, out, `"text": "hello"`)
}

// A real client in the clear: grpcurl opens a CONNECT tunnel and speaks HTTP/2 with prior
// knowledge inside it, and the origin is reached the same way.
func TestConformanceGRPC_UnaryThroughForwardInTheClear(t *testing.T) {
	requireGRPCurl(t)
	seen := new(recorder)
	origin := h2cOrigin(t, grpcEchoHandler(seen))
	p, target, proxyAddr, _ := grpcConformanceProxy(t, origin)
	p.MustAdd("example.com/pkg.Svc/Method", func(c *GRPCCtx) error { return c.Forward() })

	out, err := runGRPCurl(t, proxyAddr, "", "-d", `{"text":"hello"}`, target, "pkg.Svc/Method")
	require.NoError(t, err, out)
	assert.Contains(t, out, `"text": "hello"`)
	assert.Equal(t, []string{"HTTP/2.0"}, seen.all())
}

// A real client reads the status a handler ends an open call on, after the messages it let
// through.
func TestConformanceGRPC_FailMidStreamReadsAsTheStatus(t *testing.T) {
	requireGRPCurl(t)
	origin := grpcConformanceOrigin(t)
	p, target, proxyAddr, caFile := grpcConformanceProxy(t, origin)
	p.MustAdd("example.com/pkg.Svc/Stream", func(c *GRPCCtx) error {
		if err := c.Open(); err != nil {
			return err
		}
		m, err := c.Outbound().ReadMessage()
		if err != nil {
			return err
		}
		if err := m.Forward(); err != nil {
			return err
		}
		_ = c.CloseSend()
		if m, err = c.Inbound().ReadMessage(); err != nil {
			return err
		}
		if err := m.Forward(); err != nil {
			return err
		}
		return c.Fail(CodeResourceExhausted, "quota")
	})

	out, err := runGRPCurl(t, proxyAddr, caFile, "-d", `{"text":"a"}{"text":"b"}`, target, "pkg.Svc/Stream")
	require.Error(t, err, out)
	assert.Contains(t, out, `"text": "a"`, "the message forwarded before Fail")
	assert.NotContains(t, out, `"text": "b"`)
	assert.Contains(t, out, "Code: ResourceExhausted")
	assert.Contains(t, out, "Message: quota")
}

// A handler returning with the response stream still running is an Internal to a real
// client, where an absent status would have been a protocol error.
func TestConformanceGRPC_ReturnMidStreamReadsAsInternal(t *testing.T) {
	requireGRPCurl(t)
	origin := grpcConformanceOrigin(t)
	p, target, proxyAddr, caFile := grpcConformanceProxy(t, origin)
	p.MustAdd("example.com/pkg.Svc/Stream", func(c *GRPCCtx) error {
		if err := c.Open(); err != nil {
			return err
		}
		m, err := c.Outbound().ReadMessage()
		if err != nil {
			return err
		}
		if err := m.Forward(); err != nil {
			return err
		}
		if m, err = c.Inbound().ReadMessage(); err != nil {
			return err
		}
		return m.Forward()
	})

	out, err := runGRPCurl(t, proxyAddr, caFile, "-d", `{"text":"a"}{"text":"b"}`, target, "pkg.Svc/Stream")
	require.Error(t, err, out)
	assert.Contains(t, out, `"text": "a"`)
	assert.Contains(t, out, "Code: Internal")
}

// The origin's status crosses the proxy untouched when the handler lets the call end on it.
func TestConformanceGRPC_StreamThroughOpen(t *testing.T) {
	requireGRPCurl(t)
	origin := grpcConformanceOrigin(t)
	p, target, proxyAddr, caFile := grpcConformanceProxy(t, origin)
	p.MustAdd("example.com/pkg.Svc/Stream", func(c *GRPCCtx) error {
		if err := c.Open(); err != nil {
			return err
		}
		src := MergeMessages(c.Outbound(), c.Inbound())
		for {
			m, err := src.ReadMessage()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
			if err := m.Forward(); err != nil {
				return err
			}
		}
	})

	out, err := runGRPCurl(t, proxyAddr, caFile, "-d", `{"text":"a"}{"text":"b"}`, target, "pkg.Svc/Stream")
	require.NoError(t, err, out)
	assert.Equal(t, 2, strings.Count(out, `"text":`))
	assert.Contains(t, out, `"text": "a"`)
	assert.Contains(t, out, `"text": "b"`)
}

// lpm frames a Length-Prefixed-Message by hand, so the peers share no parser with the proxy.
func lpm(flag byte, payload string) []byte {
	b := []byte{flag, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[1:], uint32(len(payload)))
	return append(b, payload...)
}

type originCall struct {
	header    http.Header
	readErr   error
	method    string
	path      string
	authority string
	proto     string
	body      []byte
}

type grpcOrigin struct {
	srv   *httptest.Server
	calls chan originCall
}

func newGRPCOrigin(t *testing.T, h func(o *grpcOrigin, w http.ResponseWriter, r *http.Request)) *grpcOrigin {
	t.Helper()
	o := &grpcOrigin{calls: make(chan originCall, 8)}
	o.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h(o, w, r)
	}))
	o.srv.EnableHTTP2 = true
	o.srv.StartTLS()
	t.Cleanup(o.srv.Close)
	return o
}

func echoOrigin(t *testing.T) *grpcOrigin {
	t.Helper()
	return newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
		call := o.record(r)
		answerOK(w, call.body)
	})
}

func (o *grpcOrigin) record(r *http.Request) originCall {
	call := originCall{
		header: r.Header.Clone(), method: r.Method, path: r.URL.RequestURI(),
		authority: r.Host, proto: r.Proto,
	}
	call.body, call.readErr = io.ReadAll(r.Body)
	o.calls <- call
	return call
}

func (o *grpcOrigin) call(t *testing.T) originCall {
	t.Helper()
	select {
	case c := <-o.calls:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("the origin received no call")
		return originCall{}
	}
}

func (o *grpcOrigin) noCall(t *testing.T) {
	t.Helper()
	select {
	case c := <-o.calls:
		t.Fatalf("the origin received a call to %s", c.path)
	default:
	}
}

// answer flushes each chunk, so each leaves the origin in a DATA frame of its own.
func answer(w http.ResponseWriter, header, trailer []string, chunks ...[]byte) {
	h := w.Header()
	h.Set("Content-Type", "application/grpc")
	for i := 0; i+1 < len(header); i += 2 {
		h.Add(header[i], header[i+1])
	}
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	for _, c := range chunks {
		_, _ = w.Write(c)
		_ = rc.Flush()
	}
	for i := 0; i+1 < len(trailer); i += 2 {
		h.Add(http.TrailerPrefix+trailer[i], trailer[i+1])
	}
}

func answerOK(w http.ResponseWriter, chunks ...[]byte) {
	answer(w, nil, []string{"Grpc-Status", "0"}, chunks...)
}

type grpcBench struct {
	p         *Proxy
	origin    *grpcOrigin
	pool      *x509.CertPool
	proxyAddr string
	host      string
	authority string
}

func newGRPCBench(t *testing.T, origin *grpcOrigin, h GRPC, opts ...ProxyOption) *grpcBench {
	t.Helper()
	u, err := url.Parse(origin.srv.URL)
	require.NoError(t, err)
	ca, err := GenerateCA()
	require.NoError(t, err)
	tr := DefaultTransport()
	tr.RootCAs = originPool(t, origin.srv)
	p, err := New(append([]ProxyOption{WithCA(ca), WithTransport(tr)}, opts...)...)
	require.NoError(t, err)
	b := &grpcBench{p: p, origin: origin, pool: ca.CertPool(), host: originHost(u), authority: u.Host}
	if h != nil {
		p.MustAdd(b.host+"/*{method}", h)
	}
	b.proxyAddr = startProxy(t, p)
	return b
}

// grpcClient writes its own frames. The rows depend on DATA frame boundaries a net/http
// client chooses itself.
type grpcClient struct {
	t         *testing.T
	fr        *http2.Framer
	enc       *hpack.Encoder
	authority string
	buf       bytes.Buffer
	next      uint32
}

func (b *grpcBench) client(t *testing.T) *grpcClient {
	t.Helper()
	raw := connectRaw(t, b.proxyAddr, b.authority)
	tc := tls.Client(raw, &tls.Config{ServerName: b.host, RootCAs: b.pool, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	require.NoError(t, tc.Handshake())
	require.Equal(t, "h2", tc.ConnectionState().NegotiatedProtocol)
	require.NoError(t, tc.SetDeadline(time.Now().Add(10*time.Second)))
	_, err := io.WriteString(tc, http2.ClientPreface)
	require.NoError(t, err)
	c := &grpcClient{t: t, fr: http2.NewFramer(tc, tc), authority: b.authority, next: 1}
	c.enc = hpack.NewEncoder(&c.buf)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	c.fr.MaxHeaderListSize = 1 << 20
	require.NoError(t, c.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 30}))
	require.NoError(t, c.fr.WriteWindowUpdate(0, 1<<30))
	// A request body past 65535 bytes waits for the windows of the proxy's SETTINGS.
	for {
		f, err := c.fr.ReadFrame()
		require.NoError(t, err)
		if s, ok := f.(*http2.SettingsFrame); ok && !s.IsAck() {
			require.NoError(t, c.fr.WriteSettingsAck())
			return c
		}
	}
}

func (c *grpcClient) callFields(path, ct string, extra ...string) []hpack.HeaderField {
	f := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: path},
		{Name: ":authority", Value: c.authority},
		{Name: "te", Value: "trailers"},
		{Name: "content-type", Value: ct},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		f = append(f, hpack.HeaderField{Name: extra[i], Value: extra[i+1]})
	}
	return f
}

func (c *grpcClient) open(fields []hpack.HeaderField, end bool) uint32 {
	c.t.Helper()
	c.buf.Reset()
	for _, f := range fields {
		require.NoError(c.t, c.enc.WriteField(f))
	}
	id := c.next
	c.next += 2
	require.NoError(c.t, c.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: c.buf.Bytes(), EndHeaders: true, EndStream: end,
	}))
	return id
}

func (c *grpcClient) call(path string, extra ...string) uint32 {
	c.t.Helper()
	return c.open(c.callFields(path, "application/grpc", extra...), false)
}

func (c *grpcClient) data(id uint32, end bool, b []byte) {
	c.t.Helper()
	require.NoError(c.t, c.fr.WriteData(id, end, b))
}

func (c *grpcClient) unary(path string, body []byte, extra ...string) grpcResult {
	c.t.Helper()
	id := c.call(path, extra...)
	c.data(id, true, body)
	return c.await(id)
}

type grpcResult struct {
	blocks     [][]hpack.HeaderField
	data       []byte
	frames     int
	rst        http2.ErrCode
	reset      bool
	ended      bool
	endOnBlock bool
}

func field(block []hpack.HeaderField, name string) (string, bool) {
	for _, f := range block {
		if f.Name == name {
			return f.Value, true
		}
	}
	return "", false
}

func (r *grpcResult) header(name string) string {
	if len(r.blocks) == 0 {
		return ""
	}
	v, _ := field(r.blocks[0], name)
	return v
}

// trailer reads the last block, and a Trailers-Only response has a single block.
func (r *grpcResult) trailer(name string) string {
	if len(r.blocks) < 2 {
		return ""
	}
	v, _ := field(r.blocks[len(r.blocks)-1], name)
	return v
}

func (r *grpcResult) done() bool { return r.ended || r.reset }

func (c *grpcClient) step(id uint32, r *grpcResult) {
	c.t.Helper()
	f, err := c.fr.ReadFrame()
	require.NoError(c.t, err)
	switch f := f.(type) {
	case *http2.SettingsFrame:
		if !f.IsAck() {
			require.NoError(c.t, c.fr.WriteSettingsAck())
		}
	case *http2.PingFrame:
		if !f.IsAck() {
			require.NoError(c.t, c.fr.WritePing(true, f.Data))
		}
	case *http2.GoAwayFrame:
		c.t.Fatalf("GOAWAY %v", f.ErrCode)
	case *http2.MetaHeadersFrame:
		if f.StreamID == id {
			r.blocks = append(r.blocks, f.Fields)
			if f.StreamEnded() {
				r.ended, r.endOnBlock = true, true
			}
		}
	case *http2.DataFrame:
		if f.StreamID == id {
			r.data = append(r.data, f.Data()...)
			if len(f.Data()) > 0 {
				r.frames++
			}
			r.ended = f.StreamEnded()
		}
	case *http2.RSTStreamFrame:
		if f.StreamID == id {
			r.reset, r.rst = true, f.ErrCode
		}
	}
}

func (c *grpcClient) await(id uint32) grpcResult {
	c.t.Helper()
	var r grpcResult
	for !r.done() {
		c.step(id, &r)
	}
	return r
}

func (c *grpcClient) awaitData(id uint32, r *grpcResult, n int) {
	c.t.Helper()
	for len(r.data) < n && !r.done() {
		c.step(id, r)
	}
	require.Len(c.t, r.data, n)
}

func forwardCall(c *GRPCCtx) error { return c.Forward() }

func openCall(c *GRPCCtx) error {
	if err := c.Open(); err != nil {
		return err
	}
	src := MergeMessages(c.Outbound(), c.Inbound())
	for {
		m, err := src.ReadMessage()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := m.Forward(); err != nil {
			return err
		}
	}
}

// grpcModes are the two framing paths a relayed call takes, the gate of Forward and the
// message readers of Open.
var grpcModes = []struct {
	h    GRPC
	name string
}{
	{forwardCall, "Forward"},
	{openCall, "Open"},
}

func eachMode(t *testing.T, run func(t *testing.T, h GRPC)) {
	t.Helper()
	for _, m := range grpcModes {
		t.Run(m.name, func(t *testing.T) { run(t, m.h) })
	}
}

// streamOrigin echoes each chunk as it arrives, so a test can wait for one message before
// sending the next.
func streamOrigin(t *testing.T) *grpcOrigin {
	t.Helper()
	return newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		call := originCall{header: r.Header.Clone(), path: r.URL.RequestURI()}
		buf := make([]byte, 64<<10)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				call.body = append(call.body, buf[:n]...)
				_, _ = w.Write(buf[:n])
				_ = rc.Flush()
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				call.readErr = err
				select {
				case <-r.Context().Done():
				case <-time.After(5 * time.Second):
				}
				o.calls <- call
				return
			}
		}
		o.calls <- call
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
}

func grpcStatusOf(r grpcResult) string {
	if len(r.blocks) == 1 {
		return r.header("grpc-status")
	}
	return r.trailer("grpc-status")
}

// grpcConformanceCase is one requirement of the gRPC over HTTP/2 protocol or of the status code
// document, checked by a client and an origin scripted around the proxy. A case that cannot
// apply states the reason instead of a scenario.
type grpcConformanceCase struct {
	run func(t *testing.T)
	// id is the source and its section, "grpc/requests/1" in PROTOCOL-HTTP2.md.
	id string
	// name states what the peers send.
	name string
	// req is the requirement in the words of the source.
	req string
	// skip gives the reason the case does not apply.
	skip string
}

func TestConformanceGRPC(t *testing.T) {
	for _, tc := range grpcConformance {
		t.Run(tc.id+" "+tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}
			t.Parallel()
			tc.run(t)
		})
	}
}

const specialStatusMessage = "\t\ntest with whitespace\r\nand Unicode BMP ☺ and non-BMP 😈\t\n"

var grpcConformance = []grpcConformanceCase{
	{
		id: "grpc/requests/1", name: "a Call-Definition with every optional field, then one without any",
		req: "**Call-Definition** → Method Scheme Path [Authority] TE [Timeout] Content-Type [Message-Type] [Message-Encoding] [Message-Accept-Encoding] [User-Agent]",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, echoOrigin(t), h)
				c := b.client(t)
				full := c.callFields("/pkg.Svc/Method", "application/grpc+proto",
					"grpc-timeout", "1S", "grpc-message-type", "pkg.Request", "grpc-encoding", "identity",
					"grpc-accept-encoding", "gzip,identity", "user-agent", "grpc-go/1.2.3")
				id := c.open(full, false)
				c.data(id, true, lpm(0, "hello"))
				r := c.await(id)
				require.Equal(t, "0", grpcStatusOf(r))
				call := b.origin.call(t)
				assert.Equal(t, "POST", call.method)
				assert.Equal(t, "/pkg.Svc/Method", call.path)
				assert.Equal(t, b.authority, call.authority)
				assert.Equal(t, "HTTP/2.0", call.proto)
				assert.Equal(t, http.Header{
					"Te":                   {"trailers"},
					"Content-Type":         {"application/grpc+proto"},
					"Grpc-Timeout":         {"1S"},
					"Grpc-Message-Type":    {"pkg.Request"},
					"Grpc-Encoding":        {"identity"},
					"Grpc-Accept-Encoding": {"gzip,identity"},
					"User-Agent":           {"grpc-go/1.2.3"},
				}, call.header)
				assert.Equal(t, lpm(0, "hello"), call.body)

				r = c.unary("/pkg.Svc/Method", nil)
				require.Equal(t, "0", grpcStatusOf(r))
				call = b.origin.call(t)
				assert.Equal(t, http.Header{"Te": {"trailers"}, "Content-Type": {"application/grpc"}}, call.header, "the proxy added a field")
			})
		},
	},
	{
		id: "grpc/requests/2", name: "a call to the method in another case",
		req: "**Path** is case-sensitive.",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), nil)
			b.p.MustAdd(b.host+"/pkg.Svc/Method", forwardCall)
			c := b.client(t)
			r := c.unary("/pkg.svc/method", lpm(0, "x"))
			assert.Equal(t, "403", r.header(":status"))
			b.origin.noCall(t)
			r = c.unary("/pkg.Svc/Method", lpm(0, "x"))
			assert.Equal(t, "0", grpcStatusOf(r))
			assert.Equal(t, "/pkg.Svc/Method", b.origin.call(t).path)
		},
	},
	{
		id: "grpc/requests/3", name: "a call without te",
		req: "**TE** → \"te\" \"trailers\"  ; Used to detect incompatible proxies",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, echoOrigin(t), h)
				c := b.client(t)
				fields := c.callFields("/pkg.Svc/Method", "application/grpc")
				fields = append(fields[:4], fields[5:]...)
				id := c.open(fields, false)
				c.data(id, true, lpm(0, "x"))
				c.await(id)
				assert.Empty(t, b.origin.call(t).header.Values("Te"), "the proxy announced trailers the client did not")
			})
		},
	},
	{
		id: "grpc/requests/4", name: "grpc-timeout in each unit, at most 8 digits, and malformed",
		req: "**TimeoutValue** → {_positive integer as ASCII string of at most 8 digits_}",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(c *GRPCCtx) error {
				d, ok := c.Timeout()
				return c.Respond(CodeOK, fmt.Sprintf("%d %t", int64(d), ok))
			})
			c := b.client(t)
			for v, want := range map[string]string{
				"2H":         fmt.Sprintf("%d true", int64(2*time.Hour)),
				"2M":         fmt.Sprintf("%d true", int64(2*time.Minute)),
				"2S":         fmt.Sprintf("%d true", int64(2*time.Second)),
				"2m":         fmt.Sprintf("%d true", int64(2*time.Millisecond)),
				"2u":         fmt.Sprintf("%d true", int64(2*time.Microsecond)),
				"2n":         "2 true",
				"12345678S":  fmt.Sprintf("%d true", int64(12345678*time.Second)),
				"99999999H":  fmt.Sprintf("%d true", int64(math.MaxInt64)),
				"123456789S": "0 false",
				"2s":         "0 false",
				"2":          "0 false",
				"S":          "0 false",
				"-2S":        "0 false",
				"+2S":        "0 false",
				"2.5S":       "0 false",
			} {
				r := c.unary("/pkg.Svc/Method", nil, "grpc-timeout", v)
				assert.Equal(t, want, r.header("grpc-message"), "grpc-timeout %q", v)
			}
		},
	},
	{
		id: "grpc/requests/5", name: "a call without grpc-timeout",
		req: "If **Timeout** is omitted a server should assume an infinite timeout.",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(c *GRPCCtx) error {
				d, ok := c.Timeout()
				_, deadline := c.Context().Deadline()
				return c.Respond(CodeOK, fmt.Sprintf("%d %t %t", int64(d), ok, deadline))
			})
			r := b.client(t).unary("/pkg.Svc/Method", nil)
			assert.Equal(t, "0 false false", r.header("grpc-message"))
		},
	},
	{
		id: "grpc/requests/6", name: "the order of the request fields",
		req:  "Additionally implementations should send **Timeout** immediately after the reserved headers and they should send the **Call-Definition** headers before sending **Custom-Metadata**.",
		skip: "the fields of a forwarded call are encoded by net/http's HTTP/2 transport, which edge delegates the upstream request to",
	},
	{
		id: "grpc/requests/7", name: "each gRPC content type and its neighbours, with a gRPC and an HTTP entry on the path",
		req: "**Content-Type** → \"content-type\" \"application/grpc\" [(\"+proto\" / \"+json\" / {_custom_})]",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), nil)
			b.p.MustAdd(b.host+"/pkg.Svc/Method", func(c *GRPCCtx) error { return c.Respond(CodeOK, "grpc") })
			b.p.MustAdd(b.host+"/pkg.Svc/Method", func(c *HTTPCtx) (*http.Response, error) { return Status(http.StatusTeapot), nil })
			c := b.client(t)
			for ct, grpc := range map[string]bool{
				"application/grpc":               true,
				"Application/gRPC":               true,
				"application/grpc+proto":         true,
				"application/grpc+json":          true,
				"application/grpc+thrift":        true,
				"application/grpc;charset=utf-8": true,
				"application/grpc-web":           false,
				"application/grpcx":              false,
				"application/json":               false,
			} {
				id := c.open(c.callFields("/pkg.Svc/Method", ct), false)
				c.data(id, true, lpm(0, "x"))
				r := c.await(id)
				if grpc {
					assert.Equal(t, "grpc", r.header("grpc-message"), "content type %q", ct)
				} else {
					assert.Equal(t, "418", r.header(":status"), "content type %q", ct)
				}
			}
			b.origin.noCall(t)
		},
	},
	{
		id: "grpc/requests/8", name: "a call that is not gRPC on a path only a gRPC entry serves",
		req: "If **Content-Type** does not begin with \"application/grpc\", gRPC servers SHOULD respond with HTTP status of 415 (Unsupported Media Type).  This will prevent other HTTP/2 clients from interpreting a gRPC error response, which uses status 200 (OK), as successful.",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), forwardCall)
			c := b.client(t)
			for _, ct := range []string{"application/json", "application/grpc-web"} {
				id := c.open(c.callFields("/pkg.Svc/Method", ct), false)
				c.data(id, true, lpm(0, "x"))
				r := c.await(id)
				assert.NotEqual(t, "200", r.header(":status"), "content type %q", ct)
				assert.Empty(t, grpcStatusOf(r), "content type %q", ct)
			}
			b.origin.noCall(t)
		},
	},
	{
		id: "grpc/requests/9", name: "a compressed message under grpc-encoding, in both directions",
		req: "A **Compressed-Flag** value of 1 indicates that the binary octet sequence of **Message** is compressed using the mechanism declared by the **Message-Encoding** header.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w, []string{"Grpc-Encoding", "gzip", "Grpc-Accept-Encoding", "gzip"}, []string{"Grpc-Status", "0"}, call.body)
				})
				b := newGRPCBench(t, o, h)
				msg := lpm(1, "\x1f\x8b not gzip, the proxy never inflates")
				r := b.client(t).unary("/pkg.Svc/Method", msg, "grpc-encoding", "gzip", "grpc-accept-encoding", "gzip,identity")
				call := o.call(t)
				assert.Equal(t, "gzip", call.header.Get("Grpc-Encoding"))
				assert.Equal(t, "gzip,identity", call.header.Get("Grpc-Accept-Encoding"))
				assert.Equal(t, msg, call.body)
				assert.Equal(t, "gzip", r.header("grpc-encoding"))
				assert.Equal(t, "gzip", r.header("grpc-accept-encoding"))
				assert.Equal(t, msg, r.data)
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "grpc/requests/10", name: "a compressed message without grpc-encoding",
		req: "If the **Message-Encoding** header is omitted then the **Compressed-Flag** must be 0.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := echoOrigin(t)
				b := newGRPCBench(t, o, h)
				msg := lpm(1, "abc")
				r := b.client(t).unary("/pkg.Svc/Method", msg)
				assert.Equal(t, msg, o.call(t).body, "the endpoint decides on the flag")
				assert.Equal(t, msg, r.data)
			})
		},
	},
	{
		id: "grpc/requests/11", name: "a message whose flag is neither 0 nor 1",
		req: "**Compressed-Flag** → 0 / 1   ; encoded as 1 byte unsigned integer",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := echoOrigin(t)
				b := newGRPCBench(t, o, h)
				msg := lpm(2, "abc")
				b.client(t).unary("/pkg.Svc/Method", msg)
				if body := o.call(t).body; len(body) > 0 {
					assert.Equal(t, msg, body, "the origin read a flag the client did not send")
				}
			})
		},
	},
	{
		id: "grpc/requests/12", name: "messages compressed with a context each",
		req:  "Compression contexts are NOT maintained over message boundaries, implementations must create a new context for each message in the stream.",
		skip: "edge never decompresses a message, CLAUDE.md states that a body is never decompressed by the proxy",
	},
	{
		id: "grpc/requests/13", name: "custom_metadata, ASCII and binary values, padded and unpadded, echoed in headers and trailers",
		req: "**Custom-Metadata** → Binary-Header / ASCII-Header",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w,
						[]string{"X-Grpc-Test-Echo-Initial", r.Header.Get("X-Grpc-Test-Echo-Initial")},
						[]string{
							"Grpc-Status", "0",
							"X-Grpc-Test-Echo-Trailing-Bin", r.Header.Get("X-Grpc-Test-Echo-Trailing-Bin"),
							"X-Padded-Bin", "AQI=", "X-Unpadded-Bin", "AQI",
						},
						call.body)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, ""),
					"x-grpc-test-echo-initial", "test_initial_metadata_value",
					"x-grpc-test-echo-trailing-bin", "q6ur",
					"x-padded-bin", "AQI=", "x-unpadded-bin", "AQI")
				call := o.call(t)
				assert.Equal(t, "test_initial_metadata_value", call.header.Get("X-Grpc-Test-Echo-Initial"))
				assert.Equal(t, "q6ur", call.header.Get("X-Grpc-Test-Echo-Trailing-Bin"))
				assert.Equal(t, "AQI=", call.header.Get("X-Padded-Bin"))
				assert.Equal(t, "AQI", call.header.Get("X-Unpadded-Bin"))
				assert.Equal(t, "test_initial_metadata_value", r.header("x-grpc-test-echo-initial"))
				assert.Equal(t, "q6ur", r.trailer("x-grpc-test-echo-trailing-bin"))
				assert.Equal(t, "AQI=", r.trailer("x-padded-bin"))
				assert.Equal(t, "AQI", r.trailer("x-unpadded-bin"))
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "grpc/requests/14", name: "binary values padded and unpadded, decoded by DecodeBinaryMetadata",
		req: "Implementations MUST accept padded and un-padded values and should emit un-padded values.",
		run: func(t *testing.T) {
			for v, want := range map[string][]byte{
				"AQI=": {1, 2}, "AQI": {1, 2}, "AQID": {1, 2, 3}, "AQIDBA==": {1, 2, 3, 4}, "AQIDBA": {1, 2, 3, 4},
			} {
				got, err := DecodeBinaryMetadata(v)
				require.NoError(t, err, v)
				assert.Equal(t, want, got, v)
			}
		},
	},
	{
		id: "grpc/requests/15", name: "two binary values joined with a comma, decoded by DecodeBinaryMetadata",
		req:  "Implementations must split **Binary-Header**s on \",\" before decoding the Base64-encoded values.",
		skip: "DecodeBinaryMetadata decodes one value and the caller splits a field",
	},
	{
		id: "grpc/requests/16", name: "a metadata key sent three times, in both directions",
		req: "**Custom-Metadata** header order is not guaranteed to be preserved except for values with duplicate header names.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w, []string{"X-Dup", "c", "X-Dup", "b", "X-Dup", "a"}, []string{"Grpc-Status", "0"}, call.body)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, ""), "x-dup", "a", "x-dup", "b", "x-dup", "c")
				assert.Equal(t, []string{"a", "b", "c"}, o.call(t).header.Values("X-Dup"))
				var got []string
				for _, f := range r.blocks[0] {
					if f.Name == "x-dup" {
						got = append(got, f.Value)
					}
				}
				assert.Equal(t, []string{"c", "b", "a"}, got)
			})
		},
	},
	{
		id: "grpc/requests/17", name: "metadata under a grpc- key the protocol does not list, in both directions",
		req: "Header names starting with \"grpc-\" but not listed here are reserved for future GRPC use and should not be used by applications as **Custom-Metadata**.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w, []string{"Grpc-Future-Header", "h"}, []string{"Grpc-Status", "0", "Grpc-Future-Trailer", "t"}, call.body)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, ""), "grpc-future-request", "q")
				assert.Equal(t, "q", o.call(t).header.Get("Grpc-Future-Request"))
				assert.Equal(t, "h", r.header("grpc-future-header"))
				assert.Equal(t, "t", r.trailer("grpc-future-trailer"))
			})
		},
	},
	{
		id: "grpc/requests/18", name: "a metadata value outside ASCII-Value that HTTP accepts",
		req: "Implementations must not error due to receiving an invalid **ASCII-Value** that's a valid **field-value** in HTTP, but the precise behavior is not strictly defined: they may throw the value away or accept the value.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := echoOrigin(t)
				b := newGRPCBench(t, o, h)
				const v = "tab\tand obs-text \xc3\xa9"
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"), "x-odd", v)
				assert.Equal(t, "0", grpcStatusOf(r))
				if got := o.call(t).header.Values("X-Odd"); len(got) > 0 {
					assert.Equal(t, []string{v}, got)
				}
			})
		},
	},
	{
		id: "grpc/requests/19", name: "request headers past 8 KiB",
		req:  "Servers may limit the size of **Request-Headers**, with a default of 8 KiB suggested.",
		skip: "the bound on a request header block is WithMaxHeaderBytes, the same for every kind",
	},
	{
		id: "grpc/requests/20", name: "empty_unary, a message of zero bytes in both directions",
		req: "**Message** → \\*{binary octet}",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := echoOrigin(t)
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, ""))
				assert.Equal(t, lpm(0, ""), o.call(t).body)
				assert.Equal(t, lpm(0, ""), r.data)
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "grpc/requests/21", name: "the client half-closes with an empty DATA frame while the response streams",
		req: "In scenarios where the **Request** stream needs to be closed but no data remains to be sent implementations MUST send an empty DATA frame with this flag set.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/grpc")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(lpm(0, "first"))
					_ = http.NewResponseController(w).Flush()
					if call := o.record(r); call.readErr == nil {
						w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
					}
				})
				b := newGRPCBench(t, o, h)
				c := b.client(t)
				id := c.call("/pkg.Svc/Method")
				var r grpcResult
				c.awaitData(id, &r, len(lpm(0, "first")))
				c.data(id, true, nil)
				for !r.done() {
					c.step(id, &r)
				}
				call := o.call(t)
				assert.NoError(t, call.readErr)
				assert.Empty(t, call.body)
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "grpc/requests/22", name: "a request stream that ends inside its second message",
		req: "In some cases it is possible that the framing of the message stream has become corrupt and the RPC runtime will choose to use an **RST_STREAM** frame to indicate this state to its peer.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := echoOrigin(t)
				b := newGRPCBench(t, o, h)
				c := b.client(t)
				id := c.call("/pkg.Svc/Method")
				c.data(id, false, lpm(0, "one"))
				cut := lpm(0, "two")[:6]
				c.data(id, true, cut)
				c.await(id)
				if call := o.call(t); call.readErr == nil {
					assert.Equal(t, slices.Concat(lpm(0, "one"), cut), call.body, "the origin read a complete call the client cut short")
				}
			})
		},
	},
	{
		id: "grpc/responses/12", name: "a response stream that ends inside its second message, then an OK status",
		req: "In some cases it is possible that the framing of the message stream has become corrupt and the RPC runtime will choose to use an **RST_STREAM** frame to indicate this state to its peer.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				cut := lpm(0, "two")[:6]
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					answerOK(w, lpm(0, "one"), cut)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				if !r.reset && grpcStatusOf(r) == "0" {
					assert.Equal(t, slices.Concat(lpm(0, "one"), cut), r.data, "the client read a complete call the origin cut short")
				}
			})
		},
	},
	{
		id: "grpc/data-frames/1", name: "client_streaming, four messages in one DATA frame, in both directions",
		req: "DATA frame boundaries have no relation to **Length-Prefixed-Message** boundaries and implementations should make no assumptions about their alignment.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := echoOrigin(t)
				b := newGRPCBench(t, o, h)
				body := slices.Concat(lpm(0, "a"), lpm(0, "bb"), lpm(0, ""), lpm(0, "ccc"))
				r := b.client(t).unary("/pkg.Svc/Method", body)
				assert.Equal(t, body, o.call(t).body)
				assert.Equal(t, body, r.data)
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "grpc/data-frames/2", name: "one message cut inside its prefix and its payload, in both directions",
		req: "DATA frame boundaries have no relation to **Length-Prefixed-Message** boundaries and implementations should make no assumptions about their alignment.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				msg := lpm(0, "hello")
				cuts := [][]byte{msg[:1], msg[1:3], msg[3:6], msg[6:]}
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					answerOK(w, cuts...)
				})
				b := newGRPCBench(t, o, h)
				c := b.client(t)
				id := c.call("/pkg.Svc/Method")
				for _, cut := range cuts {
					c.data(id, false, cut)
				}
				c.data(id, true, nil)
				r := c.await(id)
				assert.Equal(t, msg, o.call(t).body)
				assert.Equal(t, msg, r.data)
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "grpc/data-frames/3", name: "large_unary, 271828 bytes up and 314159 bytes down",
		req: "DATA frame boundaries have no relation to **Length-Prefixed-Message** boundaries and implementations should make no assumptions about their alignment.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				down := lpm(0, strings.Repeat("d", 314159-5))
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					answerOK(w, down)
				})
				b := newGRPCBench(t, o, h)
				c := b.client(t)
				up := lpm(0, strings.Repeat("u", 271828-5))
				id := c.call("/pkg.Svc/Method")
				for chunk := range slices.Chunk(up, 16384) {
					c.data(id, false, chunk)
				}
				c.data(id, true, nil)
				r := c.await(id)
				assert.Equal(t, up, o.call(t).body)
				assert.Equal(t, down, r.data)
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "statuscodes/1", name: "a message past WithMaxMessageBytes, in each direction",
		req: "Sent or received message was larger than configured limit | RESOURCE_EXHAUSTED | Both",
		run: func(t *testing.T) {
			big := lpm(0, strings.Repeat("x", 17))
			o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
				call := o.record(r)
				if r.Header.Get("X-Big") != "" {
					answerOK(w, big)
					return
				}
				answerOK(w, call.body)
			})
			b := newGRPCBench(t, o, openCall, WithMaxMessageBytes(16))
			c := b.client(t)
			r := c.unary("/pkg.Svc/Method", big)
			assert.Equal(t, "8", grpcStatusOf(r), "a request message past the bound")
			r = c.unary("/pkg.Svc/Method", lpm(0, "small"), "x-big", "1")
			assert.Equal(t, "8", grpcStatusOf(r), "a response message past the bound")
			assert.Empty(t, r.data)
		},
	},
	{
		id: "grpc/responses/1", name: "server_streaming, headers, four messages and trailers",
		req: "For responses end-of-stream is indicated by the presence of the END_STREAM flag on the last received HEADERS frame that carries **Trailers**.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				msgs := [][]byte{lpm(0, strings.Repeat("a", 31415)), lpm(0, strings.Repeat("b", 9)), lpm(0, strings.Repeat("c", 2653)), lpm(0, strings.Repeat("d", 58979))}
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					answer(w, []string{"X-Initial", "i"}, []string{"Grpc-Status", "0", "Trace-Proto-Bin", "jher831yy13JHy3hc"}, msgs...)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "go"))
				require.Len(t, r.blocks, 2)
				assert.Equal(t, "200", r.header(":status"))
				assert.Equal(t, "application/grpc", r.header("content-type"))
				assert.Equal(t, "i", r.header("x-initial"))
				_, early := field(r.blocks[0], "grpc-status")
				assert.False(t, early, "the status arrived with the headers")
				assert.Equal(t, slices.Concat(msgs...), r.data)
				assert.True(t, r.endOnBlock, "the stream did not end on the trailers")
				assert.Equal(t, "0", r.trailer("grpc-status"))
				assert.Equal(t, "jher831yy13JHy3hc", r.trailer("trace-proto-bin"))
			})
		},
	},
	{
		id: "grpc/responses/2", name: "Respond with a message and an OK status",
		req: "Status must be sent in **Trailers** even if the status code is OK.",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(c *GRPCCtx) error { return c.Respond(CodeOK, "", []byte("a")) })
			r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
			require.Len(t, r.blocks, 2)
			_, early := field(r.blocks[0], "grpc-status")
			assert.False(t, early, "the status arrived with the headers")
			assert.Equal(t, lpm(0, "a"), r.data)
			assert.True(t, r.endOnBlock)
			assert.Equal(t, "0", r.trailer("grpc-status"))
			b.origin.noCall(t)
		},
	},
	{
		id: "grpc/responses/3", name: "unimplemented_method, the origin answers Trailers-Only",
		req: "**Response-Headers** & **Trailers-Only** are each delivered in a single HTTP2 HEADERS frame block. Most responses are expected to have both headers and trailers but **Trailers-Only** is permitted for calls that produce an immediate error.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					w.Header().Set("Content-Type", "application/grpc")
					w.Header().Set("Grpc-Status", "12")
					w.Header().Set("Grpc-Message", "unknown method")
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/grpc.testing.TestService/UnimplementedCall", lpm(0, ""))
				require.Len(t, r.blocks, 1, "a Trailers-Only response became headers and trailers")
				assert.True(t, r.endOnBlock)
				assert.Empty(t, r.data)
				assert.Equal(t, "200", r.header(":status"))
				assert.Equal(t, "12", r.header("grpc-status"))
				assert.Equal(t, "unknown method", r.header("grpc-message"))
			})
		},
	},
	{
		id: "grpc/responses/4", name: "Fail before Open answers Trailers-Only",
		req: "**Trailers-Only** → HTTP-Status Content-Type Trailers",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(c *GRPCCtx) error { return c.Fail(CodeNotFound, "missing") })
			r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
			require.Len(t, r.blocks, 1)
			assert.True(t, r.endOnBlock)
			assert.Empty(t, r.data)
			assert.Equal(t, "200", r.header(":status"))
			assert.Equal(t, "application/grpc", r.header("content-type"))
			assert.Equal(t, "5", r.header("grpc-status"))
			assert.Equal(t, "missing", r.header("grpc-message"))
			b.origin.noCall(t)
		},
	},
	{
		id: "grpc/responses/5", name: "special_status_message, a status message with whitespace, Unicode and a percent",
		req: "The value portion of **Status-Message** is conceptually a Unicode string description of the error, physically encoded as UTF-8 followed by percent-encoding.",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(c *GRPCCtx) error {
				if c.Request().Header.Get("X-Percent") != "" {
					return c.Fail(CodeUnknown, "100% done ~")
				}
				return c.Fail(CodeUnknown, specialStatusMessage)
			})
			c := b.client(t)
			r := c.unary("/pkg.Svc/Method", nil)
			assert.Equal(t, "2", r.header("grpc-status"))
			assert.Equal(t, "%09%0Atest with whitespace%0D%0Aand Unicode BMP %E2%98%BA and non-BMP %F0%9F%98%88%09%0A", r.header("grpc-message"))
			r = c.unary("/pkg.Svc/Method", nil, "x-percent", "1")
			assert.Equal(t, "100%25 done ~", r.header("grpc-message"))
		},
	},
	{
		id: "grpc/responses/6", name: "the origin's status message with broken percent-encodings",
		req: "When decoding invalid values, implementations MUST NOT error or throw away the message.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				const msg = "bad %zz, cut %E2%98 and 100%"
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w, nil, []string{"Grpc-Status", "13", "Grpc-Message", msg}, call.body)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				assert.Equal(t, "13", r.trailer("grpc-status"))
				assert.Equal(t, msg, r.trailer("grpc-message"))
			})
		},
	},
	{
		id: "grpc/responses/7", name: "the origin ends on a status with details",
		req: "**Status-Details** → \"grpc-status-details-bin\" {base64 encoded value} ; See notes below.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w, nil, []string{"Grpc-Status", "9", "Grpc-Message", "precondition", "Grpc-Status-Details-Bin", "CAkSDHByZWNvbmRpdGlvbg"}, call.body)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				assert.Equal(t, "9", r.trailer("grpc-status"))
				assert.Equal(t, "CAkSDHByZWNvbmRpdGlvbg", r.trailer("grpc-status-details-bin"))
			})
		},
	},
	{
		id: "grpc/responses/8", name: "Fail after the origin ended on a status with details",
		req: "If it contains a status code field, it MUST NOT contradict the **Status** header.",
		run: func(t *testing.T) {
			o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
				call := o.record(r)
				answer(w, nil, []string{"Grpc-Status", "9", "Grpc-Status-Details-Bin", "CAkSDHByZWNvbmRpdGlvbg"}, call.body)
			})
			b := newGRPCBench(t, o, func(c *GRPCCtx) error {
				if err := openCall(c); err != nil {
					return err
				}
				return c.Fail(CodeAborted, "aborted")
			})
			r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
			assert.Equal(t, lpm(0, "x"), r.data)
			require.Len(t, r.blocks, 2)
			assert.Equal(t, "10", r.trailer("grpc-status"))
			_, details := field(r.blocks[1], "grpc-status-details-bin")
			assert.False(t, details, "the details of the origin contradict the status of the proxy")
		},
	},
	{
		id: "grpc/responses/9", name: "Status-Details on an OK status",
		req:  "**Status-Details** is allowed only if **Status** is not OK.",
		skip: "edge sends grpc-status-details-bin only when relaying it, and the consumer verifies it",
	},
	{
		id: "grpc/responses/10", name: "the origin answers 200 and omits the status",
		req: "Implementations should expect broken deployments to send non-200 HTTP status codes in responses as well as a variety of non-GRPC content-types and to omit **Status** & **Status-Message**. Implementations must synthesize a **Status** & **Status-Message** to propagate to the application layer when this occurs.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w, nil, nil, call.body)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				assert.NotEqual(t, "0", grpcStatusOf(r), "the proxy made a call without a status succeed")
			})
		},
	},
	{
		id: "grpc/responses/11", name: "the origin answers 503 in HTML, which the status mapping reads as UNAVAILABLE",
		req: "Implementations should expect broken deployments to send non-200 HTTP status codes in responses as well as a variety of non-GRPC content-types and to omit **Status** & **Status-Message**. Implementations must synthesize a **Status** & **Status-Message** to propagate to the application layer when this occurs.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = io.WriteString(w, "<html>Service Unavailable</html>")
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				assert.Equal(t, "503", r.header(":status"))
				assert.Contains(t, []string{"", "14"}, grpcStatusOf(r), "the status the client reads contradicts the 503 of the origin")
			})
		},
	},
	{
		id: "grpc/responses/13", name: "response headers past 8 KiB",
		req:  "Clients may limit the size of **Response-Headers**, **Trailers**, and **Trailers-Only**, with a default of 8 KiB each suggested.",
		skip: "the bound on a response header block from the origin is net/http's transport, which edge delegates the upstream request to",
	},
	{
		id: "grpc/errors/1", name: "the entry is deleted between two messages of a call",
		req: "When an application or runtime error occurs during an RPC a **Status** and **Status-Message** are delivered in **Trailers**.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, streamOrigin(t), h)
				c := b.client(t)
				id := c.call("/pkg.Svc/Method")
				c.data(id, false, lpm(0, "one"))
				var r grpcResult
				c.awaitData(id, &r, len(lpm(0, "one")))
				_, err := b.p.Delete[GRPC](b.host + "/*{method}")
				require.NoError(t, err)
				c.data(id, true, lpm(0, "two"))
				for !r.done() {
					c.step(id, &r)
				}
				assert.Equal(t, lpm(0, "one"), r.data)
				require.Len(t, r.blocks, 2)
				assert.True(t, r.endOnBlock)
				assert.Equal(t, "14", r.trailer("grpc-status"))
				assert.Equal(t, "Unavailable", r.trailer("grpc-message"))
			})
		},
	},
	{
		id: "grpc/errors/2", name: "cancel_after_first_response, the client resets the stream with CANCEL",
		req: "Mapped to call cancellation when sent by a client.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, streamOrigin(t), h)
				c := b.client(t)
				id := c.call("/pkg.Svc/Method")
				c.data(id, false, lpm(0, "one"))
				var r grpcResult
				c.awaitData(id, &r, len(lpm(0, "one")))
				require.NoError(t, c.fr.WriteRSTStream(id, http2.ErrCodeCancel))
				assert.Error(t, b.origin.call(t).readErr, "the origin read a request stream the client never ended")
			})
		},
	},
	{
		id: "grpc/errors/3", name: "the origin resets the stream with INTERNAL_ERROR after one message",
		req: "RPC runtime implementations should interpret RST_STREAM as immediate full-closure of the stream and should propagate an error up to the calling application layer.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					w.Header().Set("Content-Type", "application/grpc")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(lpm(0, "one"))
					_ = http.NewResponseController(w).Flush()
					panic(http.ErrAbortHandler)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				if !r.reset {
					assert.Contains(t, []string{"", "13"}, grpcStatusOf(r), "INTERNAL_ERROR(2) maps to INTERNAL")
				}
			})
		},
	},
	{
		id: "interop/ping_pong", name: "four messages, each sent once the previous one came back",
		req: "This test verifies that full duplex bidi is supported.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				b := newGRPCBench(t, streamOrigin(t), h)
				c := b.client(t)
				id := c.call("/pkg.Svc/Method")
				var r grpcResult
				var want []byte
				for _, n := range []int{27182, 8, 1828, 45904} {
					msg := lpm(0, strings.Repeat("p", n))
					want = append(want, msg...)
					c.data(id, false, msg)
					c.awaitData(id, &r, len(want))
				}
				c.data(id, true, nil)
				for !r.done() {
					c.step(id, &r)
				}
				assert.Equal(t, want, r.data)
				assert.Equal(t, "0", grpcStatusOf(r))
			})
		},
	},
	{
		id: "grpc/connection/1", name: "the origin closes its connection after one message",
		req: "Some data transmitted (e.g., request metadata written to TCP connection) before connection breaks |\tUNAVAILABLE | Client",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					o.record(r)
					w.Header().Set("Content-Type", "application/grpc")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(lpm(0, "one"))
					_ = http.NewResponseController(w).Flush()
					o.srv.CloseClientConnections()
					<-r.Context().Done()
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				if !r.reset {
					assert.Equal(t, "14", grpcStatusOf(r))
				}
			})
		},
	},
	{
		id: "grpc/connection/2", name: "the connection to the origin fails",
		req:  "If a detectable connection failure occurs on the client all calls will be closed with an UNAVAILABLE status.",
		skip: "edge is the client of the origin, grpc/connection/1 checks the same failure",
	},
	{
		id: "grpc/connection/3", name: "GOAWAY from either peer",
		req:  "Clients should consider any stream initiated after the last successfully accepted stream as UNAVAILABLE and retry the call elsewhere.",
		skip: "GOAWAY is sent and read by net/http's HTTP/2 server and transport on each connection edge terminates",
	},
	{
		id: "grpc/connection/4", name: "PING from either peer",
		req:  "Both clients and servers can send a PING frame that the peer must respond to by precisely echoing what they received.",
		skip: "PING is answered by net/http's HTTP/2 server and transport on each connection edge terminates",
	},
	{
		id: "grpc/security/1", name: "the TLS version of each connection",
		req:  "The HTTP2 specification mandates the use of TLS 1.2 or higher when TLS is used with HTTP2.",
		skip: "TLS is negotiated by crypto/tls on both connections",
	},
	{
		id: "grpc/retries/1", name: "a call that cannot be proven to have started",
		req:  "Calls that cannot be proven to have started will not be retried.",
		skip: "a forwarded call is retried only by net/http's HTTP/2 transport, which edge delegates the upstream request to",
	},
	{
		id: "statuscodes/2", name: "status_code_and_message, Fail with every code of the table",
		req: "The value portion of **Status** is a decimal-encoded integer as an ASCII string, without any leading zeros.",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(c *GRPCCtx) error {
				n, err := strconv.Atoi(c.Request().Header.Get("X-Code"))
				if err != nil {
					return err
				}
				return c.Fail(Code(n), "test status message")
			})
			c := b.client(t)
			for n := range 17 {
				r := c.unary("/pkg.Svc/Method", lpm(0, ""), "x-code", strconv.Itoa(n))
				assert.Equal(t, strconv.Itoa(n), grpcStatusOf(r))
				assert.Equal(t, "test status message", r.header("grpc-message"))
			}
		},
	},
	{
		id: "statuscodes/3", name: "the origin ends on a code outside the table",
		req: "gRPC libraries that encounter values outside this range must either propagate them directly or convert them to UNKNOWN.",
		run: func(t *testing.T) {
			eachMode(t, func(t *testing.T, h GRPC) {
				o := newGRPCOrigin(t, func(o *grpcOrigin, w http.ResponseWriter, r *http.Request) {
					call := o.record(r)
					answer(w, nil, []string{"Grpc-Status", "42", "Grpc-Message", "future"}, call.body)
				})
				b := newGRPCBench(t, o, h)
				r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
				assert.Contains(t, []string{"42", "2"}, r.trailer("grpc-status"))
			})
		},
	},
	{
		id: "statuscodes/4", name: "the handler panics",
		req: "Server side application throws an exception (or does something other than returning a Status code to terminate an RPC) |\tUNKNOWN | Server",
		run: func(t *testing.T) {
			b := newGRPCBench(t, echoOrigin(t), func(*GRPCCtx) error { panic("boom") })
			r := b.client(t).unary("/pkg.Svc/Method", lpm(0, "x"))
			assert.Equal(t, "2", grpcStatusOf(r))
		},
	},
	{
		id: "statuscodes/5", name: "a call no entry matches",
		req:  "Method not found at server\t| UNIMPLEMENTED | Server",
		skip: "edge refuses a unit no entry matches with 403 on purpose, CLAUDE.md states that nothing passes by default",
	},
	{
		id: "statuscodes/6", name: "a deadline that expires in the proxy",
		req:  "Deadline expires before server returns status\t| DEADLINE_EXCEEDED | Both",
		skip: "edge forwards grpc-timeout to the origin and sets no deadline of its own, grpc/requests/5 checks it",
	},
	{
		id: "statuscodes/7", name: "a message the endpoint cannot decompress",
		req:  "Could not decompress, but compression algorithm supported (Client -> Server)\t| INTERNAL | Server",
		skip: "edge never decompresses a message, CLAUDE.md states that a body is never decompressed by the proxy",
	},
	{
		id: "statuscodes/8", name: "a payload the endpoint cannot parse, or a cardinality it does not expect",
		req:  "Error parsing request proto\t| INTERNAL | Server",
		skip: "edge never decodes a payload and has no notion of a method's cardinality, the endpoints decide both",
	},
	{
		id: "statuscodes/9", name: "credentials the server refuses",
		req:  "Incorrect Auth metadata ( Credentials failed to get metadata, Incompatible credentials set on channel and call, Invalid host set in `:authority` metadata, etc.) | UNAUTHENTICATED | Both",
		skip: "edge authenticates the proxy connection with WithProxyAuth before any call exists, the call metadata is the origin's to check",
	},
	{
		id: "statuscodes/10", name: "a flow-control violation or a keepalive timeout",
		req:  "Flow-control protocol violation |\tINTERNAL | Both",
		skip: "flow control and keepalive are net/http's HTTP/2 server and transport",
	},
	{
		id: "statuscodes/11", name: "a status the client cannot parse",
		req:  "Error parsing returned status\t| UNKNOWN | Client",
		skip: "edge never parses the status of the origin, statuscodes/3 checks that it crosses",
	},
	{
		id: "statuscodes/12", name: "the proxy shuts down during a call",
		req:  "Server shutting down\t| UNAVAILABLE | Server",
		skip: "a shutdown sends GOAWAY through net/http's HTTP/2 server or closes the connection, and the client maps the latter to UNAVAILABLE",
	},
}
