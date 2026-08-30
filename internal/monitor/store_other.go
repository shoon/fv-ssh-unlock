//go:build !unix && !windows

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package monitor

import "os"

func validatePrivateFile(os.FileInfo) error { return nil }

func replaceStateFile(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }
