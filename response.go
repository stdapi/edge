// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Status returns an empty response with the given status code.
func Status(code int) *http.Response {
	return newResponse(code, nil, http.NoBody, 0)
}

// Text returns a text/plain response.
func Text(code int, s string) *http.Response {
	h := http.Header{}
	h.Set(HeaderContentType, MIMETextPlainCharsetUTF8)
	return newResponse(code, h, io.NopCloser(strings.NewReader(s)), int64(len(s)))
}

// Textf returns a text/plain response with a formatted body.
func Textf(code int, format string, a ...any) *http.Response {
	return Text(code, fmt.Sprintf(format, a...))
}

// HTML returns a text/html response.
func HTML(code int, s string) *http.Response {
	h := http.Header{}
	h.Set(HeaderContentType, MIMETextHTMLCharsetUTF8)
	return newResponse(code, h, io.NopCloser(strings.NewReader(s)), int64(len(s)))
}

// JSON returns an application/json response holding the JSON encoding of v. It returns the
// marshalling error so a handler can propagate it with a single return.
func JSON(code int, v any) (*http.Response, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode json response: %w", err)
	}
	h := http.Header{}
	h.Set(HeaderContentType, MIMEApplicationJSONCharsetUTF8)
	return newResponse(code, h, io.NopCloser(bytes.NewReader(b)), int64(len(b))), nil
}

// Bytes returns a response with the given content type and body.
func Bytes(code int, contentType string, b []byte) *http.Response {
	h := http.Header{}
	if contentType != "" {
		h.Set(HeaderContentType, contentType)
	}
	return newResponse(code, h, io.NopCloser(bytes.NewReader(b)), int64(len(b)))
}

// Stream returns a response whose body is read from r as it is written to the client. Pass a
// negative length when it is not known ahead of time; the response is then sent chunked on
// HTTP/1.1.
func Stream(code int, contentType string, r io.Reader, length int64) *http.Response {
	h := http.Header{}
	if contentType != "" {
		h.Set(HeaderContentType, contentType)
	}
	rc, ok := r.(io.ReadCloser)
	if !ok {
		rc = io.NopCloser(r)
	}
	return newResponse(code, h, rc, length)
}

// Redirect returns a redirect response to location. code must be a 3xx.
func Redirect(code int, location string) *http.Response {
	h := http.Header{}
	h.Set(HeaderLocation, location)
	h.Set(HeaderContentType, MIMETextPlainCharsetUTF8)
	body := "redirecting to " + location
	return newResponse(code, h, io.NopCloser(strings.NewReader(body)), int64(len(body)))
}

// Rewrite replaces the body of resp with b and fixes up everything that describes its
// length: ContentLength, the Content-Length header and any chunked transfer encoding. The
// previous body is closed.
//
// Content-Encoding is left untouched, because only the caller knows whether b is still
// encoded. Use [DecodeBody] to read an encoded body and drop the header in one step.
func Rewrite(resp *http.Response, b []byte) *http.Response {
	if resp == nil {
		return Bytes(http.StatusOK, "", b)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.TransferEncoding = nil
	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	resp.Header.Del(HeaderTransferEncoding)
	resp.Header.Set(HeaderContentLength, strconv.Itoa(len(b)))
	return resp
}

// RewriteReader replaces the body of resp with r. Pass a negative length when it is not known
// ahead of time. The previous body is closed.
func RewriteReader(resp *http.Response, r io.Reader, length int64) *http.Response {
	if resp == nil {
		return Stream(http.StatusOK, "", r, length)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	rc, ok := r.(io.ReadCloser)
	if !ok {
		rc = io.NopCloser(r)
	}
	resp.Body = rc
	resp.ContentLength = length
	resp.TransferEncoding = nil
	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	resp.Header.Del(HeaderTransferEncoding)
	if length >= 0 {
		resp.Header.Set(HeaderContentLength, strconv.FormatInt(length, 10))
	} else {
		resp.Header.Del(HeaderContentLength)
	}
	return resp
}

// ReadBody reads and closes the body of resp, returning the raw bytes as they came off the
// wire. It reads at most limit bytes; pass a non-positive limit for no bound.
//
// The body is consumed: pass the result to [Rewrite] before returning resp, or the client
// gets an empty response.
func ReadBody(resp *http.Response, limit int64) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	defer func() { _ = resp.Body.Close() }()
	var r io.Reader = resp.Body
	if limit > 0 {
		r = io.LimitReader(r, limit)
	}
	return io.ReadAll(r)
}

// DecodeBody reads and closes the body of resp, decompressing it when Content-Encoding says
// it is gzip, deflate or identity, and removes the header so the decoded bytes can be handed
// straight to [Rewrite]. An unknown encoding is returned untouched with the header left in
// place. It reads at most limit decoded bytes; pass a non-positive limit for no bound.
func DecodeBody(resp *http.Response, limit int64) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}

	enc := ""
	if resp.Header != nil {
		enc = strings.ToLower(strings.TrimSpace(resp.Header.Get(HeaderContentEncoding)))
	}

	switch enc {
	case "", "identity":
		b, err := ReadBody(resp, limit)
		if err != nil {
			return nil, err
		}
		if resp.Header != nil {
			resp.Header.Del(HeaderContentEncoding)
		}
		return b, nil
	case "gzip":
		defer func() { _ = resp.Body.Close() }()
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("decode gzip body: %w", err)
		}
		defer func() { _ = zr.Close() }()
		b, err := readLimited(zr, limit)
		if err != nil {
			return nil, fmt.Errorf("decode gzip body: %w", err)
		}
		resp.Header.Del(HeaderContentEncoding)
		return b, nil
	case "deflate":
		defer func() { _ = resp.Body.Close() }()
		zr, err := zlib.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("decode deflate body: %w", err)
		}
		defer func() { _ = zr.Close() }()
		b, err := readLimited(zr, limit)
		if err != nil {
			return nil, fmt.Errorf("decode deflate body: %w", err)
		}
		resp.Header.Del(HeaderContentEncoding)
		return b, nil
	default:
		return ReadBody(resp, limit)
	}
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	if limit > 0 {
		r = io.LimitReader(r, limit)
	}
	return io.ReadAll(r)
}

func newResponse(code int, h http.Header, body io.ReadCloser, length int64) *http.Response {
	if h == nil {
		h = http.Header{}
	}
	if body == nil {
		body = http.NoBody
	}
	if length >= 0 {
		h.Set(HeaderContentLength, strconv.FormatInt(length, 10))
	}
	return &http.Response{
		Status:        strconv.Itoa(code) + " " + http.StatusText(code),
		StatusCode:    code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Body:          body,
		ContentLength: length,
	}
}
