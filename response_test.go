// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	require.NotNil(t, resp.Body)
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	return string(b)
}

func TestResponse_Builders(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		resp := Status(http.StatusNoContent)
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		assert.Equal(t, "204 No Content", resp.Status)
		assert.Zero(t, resp.ContentLength)
		assert.Empty(t, readAll(t, resp))
	})

	t.Run("text", func(t *testing.T) {
		resp := Text(http.StatusTeapot, "short and stout")
		assert.Equal(t, MIMETextPlainCharsetUTF8, resp.Header.Get(HeaderContentType))
		assert.Equal(t, int64(15), resp.ContentLength)
		assert.Equal(t, "15", resp.Header.Get(HeaderContentLength))
		assert.Equal(t, "short and stout", readAll(t, resp))
	})

	t.Run("textf", func(t *testing.T) {
		assert.Equal(t, "run 42 failed", readAll(t, Textf(http.StatusOK, "run %d %s", 42, "failed")))
	})

	t.Run("html", func(t *testing.T) {
		resp := HTML(http.StatusOK, "<p>hi</p>")
		assert.Equal(t, MIMETextHTMLCharsetUTF8, resp.Header.Get(HeaderContentType))
	})

	t.Run("json", func(t *testing.T) {
		resp, err := JSON(http.StatusOK, map[string]int{"n": 1})
		require.NoError(t, err)
		assert.Equal(t, MIMEApplicationJSONCharsetUTF8, resp.Header.Get(HeaderContentType))
		assert.JSONEq(t, `{"n":1}`, readAll(t, resp))

		_, err = JSON(http.StatusOK, make(chan int))
		assert.Error(t, err, "an unencodable value must be reported, not swallowed")
	})

	t.Run("bytes", func(t *testing.T) {
		resp := Bytes(http.StatusOK, "application/octet-stream", []byte{1, 2, 3})
		assert.Equal(t, int64(3), resp.ContentLength)
	})

	t.Run("stream of unknown length", func(t *testing.T) {
		resp := Stream(http.StatusOK, "text/plain", strings.NewReader("streamed"), -1)
		assert.Equal(t, int64(-1), resp.ContentLength)
		assert.Empty(t, resp.Header.Get(HeaderContentLength), "an unknown length must not be announced")
		assert.Equal(t, "streamed", readAll(t, resp))
	})

	t.Run("redirect", func(t *testing.T) {
		resp := Redirect(http.StatusFound, "https://elsewhere.test/")
		assert.Equal(t, "https://elsewhere.test/", resp.Header.Get(HeaderLocation))
	})
}

func TestResponse_Rewrite(t *testing.T) {
	t.Run("fixes the length headers", func(t *testing.T) {
		resp := &http.Response{
			StatusCode:       http.StatusOK,
			Header:           http.Header{HeaderTransferEncoding: {"chunked"}, HeaderContentLength: {"999"}},
			Body:             io.NopCloser(strings.NewReader("original")),
			TransferEncoding: []string{"chunked"},
			ContentLength:    -1,
		}

		Rewrite(resp, []byte("replacement"))

		assert.Equal(t, int64(11), resp.ContentLength)
		assert.Equal(t, "11", resp.Header.Get(HeaderContentLength))
		assert.Empty(t, resp.Header.Get(HeaderTransferEncoding), "a chunked encoding must not survive a known length")
		assert.Nil(t, resp.TransferEncoding)
		assert.Equal(t, "replacement", readAll(t, resp))
	})

	t.Run("closes the previous body", func(t *testing.T) {
		body := &closeTracker{Reader: strings.NewReader("original")}
		resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: body}

		Rewrite(resp, []byte("new"))
		assert.True(t, body.closed, "the body being replaced must be closed or its connection leaks")
	})

	t.Run("leaves Content-Encoding alone", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{HeaderContentEncoding: {"gzip"}},
			Body:       io.NopCloser(strings.NewReader("x")),
		}
		Rewrite(resp, []byte("still encoded"))
		assert.Equal(t, "gzip", resp.Header.Get(HeaderContentEncoding),
			"only the caller knows whether the new body is still encoded")
	})

	t.Run("reader of unknown length", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{HeaderContentLength: {"8"}},
			Body:       io.NopCloser(strings.NewReader("original")),
		}
		RewriteReader(resp, strings.NewReader("streamed"), -1)
		assert.Empty(t, resp.Header.Get(HeaderContentLength))
		assert.Equal(t, "streamed", readAll(t, resp))
	})
}

func TestResponse_ReadBody(t *testing.T) {
	body := &closeTracker{Reader: strings.NewReader("payload")}
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: body}

	b, err := ReadBody(resp, 0)
	require.NoError(t, err)
	assert.Equal(t, "payload", string(b))
	assert.True(t, body.closed)

	limited := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("payload"))}
	b, err = ReadBody(limited, 3)
	require.NoError(t, err)
	assert.Equal(t, "pay", string(b), "the limit must bound what is read")

	b, err = ReadBody(nil, 0)
	require.NoError(t, err)
	assert.Nil(t, b)
}

func TestResponse_DecodeBody(t *testing.T) {
	t.Run("gzip", func(t *testing.T) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte("decoded payload"))
		require.NoError(t, zw.Close())

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{HeaderContentEncoding: {"gzip"}},
			Body:       io.NopCloser(bytes.NewReader(buf.Bytes())),
		}

		b, err := DecodeBody(resp, 0)
		require.NoError(t, err)
		assert.Equal(t, "decoded payload", string(b))
		assert.Empty(t, resp.Header.Get(HeaderContentEncoding),
			"the header must go with the encoding, or the client is told a lie")
	})

	t.Run("deflate", func(t *testing.T) {
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		_, _ = zw.Write([]byte("deflated"))
		require.NoError(t, zw.Close())

		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{HeaderContentEncoding: {"deflate"}},
			Body:       io.NopCloser(bytes.NewReader(buf.Bytes())),
		}
		b, err := DecodeBody(resp, 0)
		require.NoError(t, err)
		assert.Equal(t, "deflated", string(b))
	})

	t.Run("identity", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{HeaderContentEncoding: {"identity"}},
			Body:       io.NopCloser(strings.NewReader("plain")),
		}
		b, err := DecodeBody(resp, 0)
		require.NoError(t, err)
		assert.Equal(t, "plain", string(b))
		assert.Empty(t, resp.Header.Get(HeaderContentEncoding))
	})

	t.Run("unknown encoding is left as it is", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{HeaderContentEncoding: {"br"}},
			Body:       io.NopCloser(strings.NewReader("compressed")),
		}
		b, err := DecodeBody(resp, 0)
		require.NoError(t, err)
		assert.Equal(t, "compressed", string(b))
		assert.Equal(t, "br", resp.Header.Get(HeaderContentEncoding),
			"an encoding that was not undone must stay declared")
	})

	t.Run("corrupt gzip", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{HeaderContentEncoding: {"gzip"}},
			Body:       io.NopCloser(strings.NewReader("not gzip at all")),
		}
		_, err := DecodeBody(resp, 0)
		assert.Error(t, err)
	})
}

type closeTracker struct {
	io.Reader
	closed bool
}

func (c *closeTracker) Close() error {
	c.closed = true
	return nil
}
