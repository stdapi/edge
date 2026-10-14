// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type closeRecorder struct {
	r      io.Reader
	onRead func()
	closed bool
}

func (c *closeRecorder) Read(p []byte) (int, error) {
	if c.onRead != nil {
		c.onRead()
	}
	return c.r.Read(p)
}

func (c *closeRecorder) Close() error {
	c.closed = true
	return nil
}

type deadlineRecorder struct {
	http.ResponseWriter
	calls int
}

func (d *deadlineRecorder) SetReadDeadline(time.Time) error {
	d.calls++
	return nil
}

func TestH3Body_CloseAfterTheHandlerReturnedLeavesTheStream(t *testing.T) {
	w := &deadlineRecorder{ResponseWriter: httptest.NewRecorder()}
	rc := &closeRecorder{r: strings.NewReader("abc")}
	b := &h3Body{ReadCloser: rc, w: w}
	b.handlerReturned()
	require.NoError(t, b.Close())
	assert.Zero(t, w.calls)
	assert.False(t, rc.closed)
	_, err := b.Read(make([]byte, 1))
	assert.ErrorIs(t, err, http.ErrBodyReadAfterClose)
}

func TestH3Body_CloseWhileTheHandlerRunsSetsAReadDeadline(t *testing.T) {
	w := &deadlineRecorder{ResponseWriter: httptest.NewRecorder()}
	rc := &closeRecorder{r: strings.NewReader("abc")}
	b := &h3Body{ReadCloser: rc, w: w}
	require.NoError(t, b.Close())
	assert.Equal(t, 1, w.calls)
	assert.False(t, rc.closed)
}

func TestH3Body_EndReachedAsTheBodyClosesIsTheEnd(t *testing.T) {
	rc := &closeRecorder{r: strings.NewReader("")}
	b := &h3Body{ReadCloser: rc, w: httptest.NewRecorder()}
	rc.onRead = func() { _ = b.Close() }
	_, err := b.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

func TestRunKindHandler_LogsAPanicWithTheSessionContext(t *testing.T) {
	type key struct{}
	logs := &ctxHandler{}
	p := testProxy(t, WithLogger(slog.New(logs)))
	sess := newSession(p, context.WithValue(t.Context(), key{}, "session"), nil, Target{Host: "a.test", Port: "443"}, KindTCP, 0)

	err := runKindHandler(p, sess, func() error { panic("boom") })
	require.ErrorAs(t, err, new(*PanicError))

	ctxs := logs.contexts()
	require.Len(t, ctxs, 1)
	assert.Equal(t, "session", ctxs[0].Value(key{}))
}
