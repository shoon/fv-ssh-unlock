// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxCredentialFileSize = 4096

const systemdCredentialPrefix = "systemd:"

type fileProvider struct {
	allowUnsafe bool
}

func newFileProvider(allowUnsafe bool) Provider {
	return &fileProvider{allowUnsafe: allowUnsafe}
}

func (*fileProvider) Name() string { return ProviderFile }

func (p *fileProvider) Get(reference string) (string, error) {
	path, err := resolveCredentialFileReference(reference)
	if err != nil {
		return "", fmt.Errorf("credential file unavailable: %w", err)
	}
	assessment := assessCredentialPath(path)
	if !assessment.Available {
		return "", fmt.Errorf("credential file unavailable: %s", assessment.Details)
	}
	if !assessment.Secure && !p.allowUnsafe {
		return "", fmt.Errorf("%w: %s; use --allow-unsafe-credential-storage for this invocation only if plaintext disk storage is intentional",
			ErrUnsafeCredentialStorage, assessment.Details)
	}

	f, err := openStableCredentialFile(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxCredentialFileSize+1))
	if err != nil {
		return "", fmt.Errorf("read credential file: %w", err)
	}
	if len(data) > maxCredentialFileSize {
		return "", fmt.Errorf("credential file exceeds %d bytes", maxCredentialFileSize)
	}
	value := string(data)
	if strings.HasSuffix(value, "\r\n") {
		value = strings.TrimSuffix(value, "\r\n")
	} else {
		value = strings.TrimSuffix(value, "\n")
	}
	if value == "" {
		return "", errorsCredentialEmpty(reference)
	}
	return value, nil
}

func (*fileProvider) Store(string, string) error { return ErrProviderReadOnly }
func (*fileProvider) Delete(string) error        { return ErrProviderReadOnly }

func (*fileProvider) Assess(reference string) ReferenceAssessment {
	return assessCredentialFile(reference)
}

// NormalizeFileReference validates and canonicalizes an absolute credential
// path or a portable systemd:<credential-name> reference for configuration.
func NormalizeFileReference(reference string) (string, error) {
	if strings.HasPrefix(reference, systemdCredentialPrefix) {
		name := strings.TrimPrefix(reference, systemdCredentialPrefix)
		if err := validateSystemdCredentialName(name); err != nil {
			return "", err
		}
		return systemdCredentialPrefix + name, nil
	}
	clean := filepath.Clean(reference)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("credential file reference must be an absolute path or systemd:<credential-name>")
	}
	return clean, nil
}

func resolveCredentialFileReference(reference string) (string, error) {
	normalized, err := NormalizeFileReference(reference)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(normalized, systemdCredentialPrefix) {
		return normalized, nil
	}
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if directory == "" {
		return "", fmt.Errorf("CREDENTIALS_DIRECTORY is not set for systemd credential reference %q", reference)
	}
	if !filepath.IsAbs(filepath.Clean(directory)) {
		return "", fmt.Errorf("CREDENTIALS_DIRECTORY must be an absolute path")
	}
	return filepath.Join(filepath.Clean(directory), strings.TrimPrefix(normalized, systemdCredentialPrefix)), nil
}

func validateSystemdCredentialName(name string) error {
	if name == "" || len(name) > 128 {
		return fmt.Errorf("systemd credential name must contain 1 to 128 characters")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
		default:
			return fmt.Errorf("systemd credential name may contain only ASCII letters, numbers, dot, underscore, and hyphen")
		}
	}
	if name == "." || name == ".." {
		return fmt.Errorf("invalid systemd credential name %q", name)
	}
	return nil
}

func (*fileProvider) Report() ProviderReport {
	secure, details := detectedSecureFileDelivery()
	security := SecurityConditional
	if secure {
		security = SecuritySecure
	}
	return ProviderReport{
		Name:          ProviderFile,
		Built:         true,
		Available:     true,
		Persistent:    true,
		SecureStorage: secure,
		Security:      security,
		Details:       details,
	}
}

func errorsCredentialEmpty(path string) error {
	return fmt.Errorf("credential file is empty: %s", path)
}

func openStableCredentialFile(path string) (*os.File, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return nil, fmt.Errorf("credential file path must be absolute")
	}
	f, err := os.Open(clean)
	if err != nil {
		return nil, fmt.Errorf("open credential file: %w", err)
	}
	fail := func(err error) (*os.File, error) {
		_ = f.Close()
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	pathInfo, err := os.Lstat(clean)
	if err != nil {
		return fail(err)
	}
	if !opened.Mode().IsRegular() || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, pathInfo) {
		return fail(fmt.Errorf("credential path is not a stable regular file: %s", clean))
	}
	if opened.Size() > maxCredentialFileSize {
		return fail(fmt.Errorf("credential file exceeds %d bytes", maxCredentialFileSize))
	}
	return f, nil
}
