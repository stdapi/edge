// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The sniff decides on what the client wrote, however short, and only waits when what it has
// could still become a request line. A short first write that is not HTTP is answered at once,
// not at the timeout.
func TestSniff_ShortFirstWriteDecidesWithoutWaiting(t *testing.T) {
	cases := []struct {
		name  string
		write string
		want  bool
		waits bool
	}{
		{name: "redis ping", write: "PING\r\n", want: false},
		{name: "request line", write: "GET / HTTP/1.1\r\n", want: true},
		{name: "h2 preface", write: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", want: true},
		{name: "binary", write: "\x00\x01\x02", want: false},
		{name: "undecided prefix waits", write: "GET /", want: false, waits: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			go func() { _, _ = client.Write([]byte(tc.write)) }()

			pc := newPeekConn(server, nil, defaultPeekSize)
			_, err := pc.Peek(1)
			require.NoError(t, err)

			start := time.Now()
			got := sniffStreamCandidates(pc, 300*time.Millisecond)
			elapsed := time.Since(start)
			if tc.want {
				assert.Equal(t, []Kind{KindHTTP, KindTCP}, got)
			} else {
				assert.Equal(t, []Kind{KindTCP}, got)
			}
			if tc.waits {
				assert.GreaterOrEqual(t, elapsed, 300*time.Millisecond, "a prefix that may still be HTTP waits for more")
			} else {
				assert.Less(t, elapsed, 200*time.Millisecond, "decided on the bytes at hand")
			}
		})
	}
}
