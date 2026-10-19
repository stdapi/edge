// Copyright 2025 Sylvain Müller. All rights reserved.
// Mount of this source code is governed by a Apache-2.0 license that can be found
// at https://github.com/stdapi/edge/blob/main/LICENSE.txt.

//go:build !linux && !darwin

package netutil

import "errors"

func unsentBytes(int) (int, error) { return 0, errors.ErrUnsupported }
