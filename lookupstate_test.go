// Copyright 2026 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

package edge

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookupState_RegexpIsResetBetweenLookups(t *testing.T) {
	re, err := compileAnchoredRegexp("[a-z/]+")
	require.NoError(t, err)
	n := &node{regexp: re, prog: compileProg(re)}
	s := new(lookupState)

	w := s.regexp(n)
	w.scanned, w.suffixed = true, true
	ends := s.ends(n, "a/b/c/d", 0, slashDelim)
	assert.Equal(t, 1, ends.Next(0))
	steps := ends.Steps()
	s.reset()

	got := s.regexp(n)
	assert.Same(t, w, got)
	assert.False(t, got.scanned)
	assert.False(t, got.suffixed)
	got.ends.Start(n.prog, strings.Clone("a/b/c/d"), 0, slashDelim)
	assert.Equal(t, 1, got.ends.Next(1))
	assert.Greater(t, got.ends.Steps(), steps)
}
