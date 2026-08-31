//go:build !unix && !windows

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import "os"

// Platforms without an OS file locking primitive keep same-process safety
// through the caller's mutex but cannot serialize writers across processes.
func lockFile(*os.File) error { return nil }

func unlockFile(*os.File) {}
