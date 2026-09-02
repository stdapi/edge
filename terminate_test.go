// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminatedTarget_PortIsCanonical(t *testing.T) {
	sess := newSession(nil, t.Context(), nil, Target{Scheme: "https", Host: "example.test", Port: "443"}, KindHTTP, HTTP11)
	target, ok := terminatedTarget(&http.Request{Host: "example.test:08443"}, sess)
	require.True(t, ok)
	assert.Equal(t, "8443", target.Port)

	_, ok = terminatedTarget(&http.Request{Host: "example.test:x"}, sess)
	assert.False(t, ok)
}
