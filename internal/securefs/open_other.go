//go:build !unix && !windows

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import (
	"fmt"
	"os"
)

// Platforms without a native no-follow open are fail-closed: accepting a path
// there would make the stable-descriptor guarantee platform-dependent.
func openFileNoFollow(path string, _ int, _ os.FileMode) (*os.File, error) {
	return nil, fmt.Errorf("safe no-follow file opening is unavailable on this platform: %s", path)
}
