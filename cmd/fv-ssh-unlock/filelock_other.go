//go:build !unix && !windows

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package main

import "os"

// The callback also holds an in-process mutex. Platforms without an OS file
// locking primitive retain same-process safety but cannot serialize enrollment
// across separate processes.
func lockKnownHostsFile(*os.File) error { return nil }
func unlockKnownHostsFile(*os.File)     {}
func tryLockDaemonFile(*os.File) error  { return nil }
