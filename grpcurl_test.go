// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func grpcurlOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	origin := httptest.NewUnstartedServer(grpcEchoHandler(nil))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	t.Cleanup(origin.Close)
	return origin
}

// grpc-go sends nothing to a proxy for a loopback address, so the origin is reached as
// example.com, the name in the httptest certificate, and the transport dials that name back
// to the loopback.
func grpcurlProxy(t *testing.T, origin *httptest.Server) (p *Proxy, target, proxyAddr, caFile string) {
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

func TestGRPCurl_UnaryThroughForward(t *testing.T) {
	requireGRPCurl(t)
	origin := grpcurlOrigin(t)
	p, target, proxyAddr, caFile := grpcurlProxy(t, origin)
	p.MustAdd("example.com/pkg.Svc/Method", func(c *GRPCCtx) error { return c.Forward() })

	out, err := runGRPCurl(t, proxyAddr, caFile, "-d", `{"text":"hello"}`, target, "pkg.Svc/Method")
	require.NoError(t, err, out)
	assert.Contains(t, out, `"text": "hello"`)
}

func TestGRPCurl_UnaryThroughForwardInTheClear(t *testing.T) {
	requireGRPCurl(t)
	seen := new(recorder)
	origin := h2cOrigin(t, grpcEchoHandler(seen))
	p, target, proxyAddr, _ := grpcurlProxy(t, origin)
	p.MustAdd("example.com/pkg.Svc/Method", func(c *GRPCCtx) error { return c.Forward() })

	out, err := runGRPCurl(t, proxyAddr, "", "-d", `{"text":"hello"}`, target, "pkg.Svc/Method")
	require.NoError(t, err, out)
	assert.Contains(t, out, `"text": "hello"`)
	assert.Equal(t, []string{"HTTP/2.0"}, seen.all())
}

func TestGRPCurl_FailMidStreamReadsAsTheStatus(t *testing.T) {
	requireGRPCurl(t)
	origin := grpcurlOrigin(t)
	p, target, proxyAddr, caFile := grpcurlProxy(t, origin)
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

func TestGRPCurl_ReturnMidStreamReadsAsInternal(t *testing.T) {
	requireGRPCurl(t)
	origin := grpcurlOrigin(t)
	p, target, proxyAddr, caFile := grpcurlProxy(t, origin)
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

func TestGRPCurl_StreamThroughOpen(t *testing.T) {
	requireGRPCurl(t)
	origin := grpcurlOrigin(t)
	p, target, proxyAddr, caFile := grpcurlProxy(t, origin)
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
