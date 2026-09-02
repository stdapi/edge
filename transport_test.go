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

// A destination pool serves one authority, so it keeps at most MaxIdleConnsPerHost idle
// connections. The shared pool serves every authority the proxy resolves itself and keeps
// MaxIdleConns.
func TestTransport_DestinationPoolIdleLimit(t *testing.T) {
	tr := DefaultTransport()
	shared, err := newUpstreamPool(tr, "")
	require.NoError(t, err)
	assert.Equal(t, tr.MaxIdleConns, shared.h1.MaxIdleConns)
	assert.Equal(t, tr.MaxIdleConns, shared.h2.MaxIdleConns)

	pool, err := newUpstreamPool(tr, "127.0.0.1:443")
	require.NoError(t, err)
	assert.Equal(t, tr.MaxIdleConnsPerHost, pool.h1.MaxIdleConns)
	assert.Equal(t, tr.MaxIdleConnsPerHost, pool.h2.MaxIdleConns)

	tr.MaxIdleConnsPerHost = 0
	pool, err = newUpstreamPool(tr, "127.0.0.1:443")
	require.NoError(t, err)
	assert.Equal(t, http.DefaultMaxIdleConnsPerHost, pool.h1.MaxIdleConns)
}
