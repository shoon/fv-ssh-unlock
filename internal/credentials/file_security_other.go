//go:build !linux

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import "os"

func platformSecureCredentialFile(string, *os.File, os.FileInfo) (bool, string) {
	return false, ""
}

func platformMemoryBackedCredentialFile(*os.File) (bool, string) {
	return false, ""
}

func platformSecureCredentialDirectory(string) (bool, string) {
	return false, ""
}
