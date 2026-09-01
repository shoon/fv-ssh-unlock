// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func assessCredentialFile(path string) ReferenceAssessment {
	resolved, err := resolveCredentialFileReference(path)
	if err != nil {
		return ReferenceAssessment{Details: err.Error()}
	}
	return assessCredentialPath(resolved)
}

func assessCredentialPath(path string) ReferenceAssessment {
	clean := filepath.Clean(path)
	file, err := openStableCredentialFile(clean)
	if err != nil {
		return ReferenceAssessment{Details: err.Error()}
	}
	defer func() { _ = file.Close() }()
	return assessCredentialHandle(clean, file)
}

func assessCredentialHandle(path string, file *os.File) ReferenceAssessment {
	clean := filepath.Clean(path)
	info, err := file.Stat()
	if err != nil {
		return ReferenceAssessment{Details: err.Error()}
	}
	if !info.Mode().IsRegular() {
		return ReferenceAssessment{Details: "credential path is not a regular, non-symbolic-link file"}
	}
	if info.Size() > maxCredentialFileSize {
		return ReferenceAssessment{Details: fmt.Sprintf("credential file exceeds %d bytes", maxCredentialFileSize)}
	}

	if directory := os.Getenv("CREDENTIALS_DIRECTORY"); directory != "" && pathWithin(directory, clean) {
		if secure, detail := platformSecureCredentialDirectory(directory); secure {
			if fileSecure, fileDetail := platformMemoryBackedCredentialFile(file); fileSecure {
				return ReferenceAssessment{
					Available: true,
					Secure:    true,
					Details:   "file is inside the systemd service credential directory; " + detail + "; " + fileDetail,
				}
			}
		}
	}
	if secure, detail := platformSecureCredentialFile(clean, file, info); secure {
		return ReferenceAssessment{Available: true, Secure: true, Details: detail}
	}
	return ReferenceAssessment{
		Available: true,
		Secure:    false,
		Details:   "file is plaintext on storage that is not verified as a service-scoped memory-backed credential mount",
	}
}

func detectedSecureFileDelivery() (bool, string) {
	if directory := os.Getenv("CREDENTIALS_DIRECTORY"); directory != "" {
		if secure, detail := platformSecureCredentialDirectory(directory); secure {
			return true, "systemd service credential directory detected; " + detail + "; other file paths are assessed when used"
		}
		if secure, detail := secureCredentialFileIn(directory); secure {
			return true, "systemd service credential detected; " + detail + "; other file paths are assessed when used"
		}
	}
	if secure, detail := platformSecureCredentialDirectory("/run/secrets"); secure {
		return true, detail + "; other file paths are assessed when used"
	}
	// Docker Swarm may mount each secret as an individual memory-backed file
	// while leaving the containing /run/secrets directory on the container's
	// root filesystem. Inspect bounded directory entries so the machine report
	// agrees with the reference-specific security check used by the daemon.
	if secure, detail := secureCredentialFileIn("/run/secrets"); secure {
		return true, detail + "; other file paths are assessed when used"
	}
	return false, "external file delivery by absolute path or systemd:<name>; secure for verified memory-backed service secret mounts, plaintext disk files require explicit opt-in"
}

func secureCredentialFileIn(directory string) (bool, string) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, ""
	}
	const maxEntries = 256
	for i, entry := range entries {
		if i >= maxEntries {
			break
		}
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		file, err := openStableCredentialFile(path)
		if err != nil {
			continue
		}
		info, statErr := file.Stat()
		if statErr == nil {
			if secure, detail := platformSecureCredentialFile(path, file, info); secure {
				_ = file.Close()
				return true, detail
			}
		}
		if err := file.Close(); err != nil {
			continue
		}
	}
	return false, ""
}

func pathWithin(base, path string) bool {
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return false
	}
	baseAbs, err = filepath.EvalSymlinks(baseAbs)
	if err != nil {
		return false
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	pathAbs, err = filepath.EvalSymlinks(pathAbs)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(baseAbs, pathAbs)
	if err != nil {
		return false
	}
	return rel != ".." && rel != "." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
