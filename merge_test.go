// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

package edge

import (
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listSource yields its values in order, then final.
func listSource(vals []int, final error) func() (int, error) {
	i := 0
	return func() (int, error) {
		if i < len(vals) {
			v := vals[i]
			i++
			return v, nil
		}
		return 0, final
	}
}

// blockedSource never yields until unblock is closed.
func blockedSource(t *testing.T) func() (int, error) {
	unblock := make(chan struct{})
	t.Cleanup(func() { close(unblock) })
	return func() (int, error) {
		<-unblock
		return 0, io.EOF
	}
}

func TestMerge_ServesBothSourcesUntilBothEnd(t *testing.T) {
	m := &merged[int]{
		ctx: t.Context(),
		a:   listSource([]int{1, 2}, io.EOF),
		b:   listSource([]int{3}, io.EOF),
	}

	var got []int
	for {
		v, err := m.read()
		if err != nil {
			require.ErrorIs(t, err, io.EOF, "both sources done is the clean end")
			break
		}
		got = append(got, v)
	}
	assert.ElementsMatch(t, []int{1, 2, 3}, got)
}

func TestMerge_AFailureEndsTheMerge(t *testing.T) {
	boom := errors.New("boom")
	m := &merged[int]{
		ctx: t.Context(),
		a:   blockedSource(t),
		b:   listSource(nil, boom),
	}

	_, err := m.read()
	require.ErrorIs(t, err, boom)
}

func TestMerge_SourceHeldUntilTheNextRead(t *testing.T) {
	var reads atomic.Int32
	m := &merged[int]{
		ctx: t.Context(),
		a: func() (int, error) {
			return int(reads.Add(1)), nil
		},
		b: blockedSource(t),
	}

	v, err := m.read()
	require.NoError(t, err)
	require.Equal(t, 1, v)

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), reads.Load(), "the source must wait until the consumer moves on")

	v, err = m.read()
	require.NoError(t, err)
	require.Equal(t, 2, v)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(2), reads.Load())
}
