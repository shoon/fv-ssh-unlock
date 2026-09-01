//go:build !unix && !windows

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import (
	"context"
	"os"
)

// Platforms without an OS file locking primitive keep same-process safety
// through the caller's mutex but cannot serialize writers across processes.
func lockFileContext(ctx context.Context, _ *os.File) error { return ctx.Err() }
func tryLockFile(*os.File) error                            { return nil }

func unlockFile(*os.File) {}
