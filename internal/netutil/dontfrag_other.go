// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/fox-toolkit/edge/blob/master/LICENSE.txt.

//go:build !linux && !darwin

package netutil

import "errors"

func setDontFragment(int) error { return nil }

func dontFragment(int) (bool, error) { return false, errors.ErrUnsupported }
