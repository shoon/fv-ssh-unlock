// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import (
	"errors"
	"fmt"
	"sort"
)

const (
	ProviderRuntime = "runtime"
	ProviderKeyring = "keyring"
	ProviderFile    = "file"
	ProviderTPM2    = "tpm2"
)

var (
	// ErrProviderReadOnly means that a provider can supply credentials but this
	// program intentionally does not persist credentials through it.
	ErrProviderReadOnly = errors.New("credential provider is read-only")
	// ErrProviderUnavailable means that the selected provider is not usable in
	// the current build or execution environment.
	ErrProviderUnavailable = errors.New("credential provider is unavailable")
	// ErrUnsafeCredentialStorage means that a plaintext-at-rest source was
	// refused because the operator did not explicitly allow it for this action.
	ErrUnsafeCredentialStorage = errors.New("unsafe credential storage is not enabled")
)

// SecurityClass describes how a provider handles credential persistence.
type SecurityClass string

const (
	SecuritySecure      SecurityClass = "secure"
	SecurityConditional SecurityClass = "conditional"
	SecurityRuntimeOnly SecurityClass = "runtime-only"
	SecurityUnavailable SecurityClass = "unavailable"
)

// ProviderReport is a stable, serializable description of a credential
// provider in the current build and execution environment.
type ProviderReport struct {
	Name          string        `json:"name"`
	Built         bool          `json:"built"`
	Available     bool          `json:"available"`
	Persistent    bool          `json:"persistent"`
	SecureStorage bool          `json:"secure_storage"`
	Security      SecurityClass `json:"security"`
	Details       string        `json:"details"`
}

// ReferenceAssessment reports whether a particular provider reference can be
// used and whether its credential is protected from plaintext-at-rest storage.
type ReferenceAssessment struct {
	Available bool
	Secure    bool
	Details   string
}

// Provider obtains credentials from one source. Store and Delete are included
// so the CLI can use the same abstraction for managed keyrings; externally
// provisioned and runtime providers deliberately return ErrProviderReadOnly.
type Provider interface {
	Name() string
	Get(reference string) (string, error)
	Store(reference, value string) error
	Delete(reference string) error
	Assess(reference string) ReferenceAssessment
	Report() ProviderReport
}

// Options controls security-sensitive provider behavior for one command
// invocation. Unsafe storage is never enabled persistently or implicitly.
type Options struct {
	AllowUnsafeCredentialStorage bool
}

// Registry contains the credential providers supported by this build.
type Registry struct {
	providers map[string]Provider
}

// NewRegistry constructs the standard provider set. TPM2 is reported as a
// capability separately until a complete sealing provider is implemented.
func NewRegistry(options Options) *Registry {
	providers := []Provider{
		newRuntimeProvider(),
		newKeyringProvider(),
		newFileProvider(options.AllowUnsafeCredentialStorage),
	}
	byName := make(map[string]Provider, len(providers))
	for _, provider := range providers {
		byName[provider.Name()] = provider
	}
	return &Registry{providers: byName}
}

// Provider returns the named provider.
func (r *Registry) Provider(name string) (Provider, error) {
	provider, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown credential provider %q", name)
	}
	return provider, nil
}

// Reports returns provider reports in stable display order, including the
// future TPM2 provider so operators can see both build and hardware status.
func (r *Registry) Reports() []ProviderReport {
	reports := make([]ProviderReport, 0, len(r.providers)+1)
	for _, provider := range r.providers {
		reports = append(reports, provider.Report())
	}
	reports = append(reports, tpm2ProviderReport())
	order := map[string]int{
		ProviderKeyring: 0,
		ProviderFile:    1,
		ProviderRuntime: 2,
		ProviderTPM2:    3,
	}
	sort.Slice(reports, func(i, j int) bool {
		return order[reports[i].Name] < order[reports[j].Name]
	})
	return reports
}

// HasSecureStorage reports whether this process can currently identify at
// least one usable persistent provider whose plaintext is not stored on disk.
func (r *Registry) HasSecureStorage() bool {
	for _, report := range r.Reports() {
		if report.Available && report.Persistent && report.SecureStorage {
			return true
		}
	}
	return false
}

type runtimeProvider struct{}

func newRuntimeProvider() Provider { return runtimeProvider{} }

func (runtimeProvider) Name() string { return ProviderRuntime }

func (runtimeProvider) Get(reference string) (string, error) {
	return GetEnvironment(reference)
}

func (runtimeProvider) Store(string, string) error { return ErrProviderReadOnly }
func (runtimeProvider) Delete(string) error        { return ErrProviderReadOnly }

func (runtimeProvider) Assess(reference string) ReferenceAssessment {
	_, err := GetEnvironment(reference)
	if err != nil {
		return ReferenceAssessment{Details: err.Error()}
	}
	return ReferenceAssessment{
		Available: true,
		Secure:    true,
		Details:   "credential is present in the current process environment",
	}
}

func (runtimeProvider) Report() ProviderReport {
	return ProviderReport{
		Name:       ProviderRuntime,
		Built:      true,
		Available:  true,
		Persistent: false,
		Security:   SecurityRuntimeOnly,
		Details:    "environment, standard input, or hidden prompt; the program does not persist the credential",
	}
}

type keyringProvider struct{}

func newKeyringProvider() Provider { return keyringProvider{} }

func (keyringProvider) Name() string { return ProviderKeyring }

func (keyringProvider) Get(reference string) (string, error) {
	if report := keyringProviderReport(); !report.Built {
		return "", fmt.Errorf("%w: %s", ErrProviderUnavailable, report.Details)
	}
	return Get(reference)
}

func (keyringProvider) Store(reference, value string) error {
	if report := keyringProviderReport(); !report.Available {
		return fmt.Errorf("%w: %s", ErrProviderUnavailable, report.Details)
	}
	return Set(reference, value)
}

func (keyringProvider) Delete(reference string) error {
	if report := keyringProviderReport(); !report.Built {
		return fmt.Errorf("%w: %s", ErrProviderUnavailable, report.Details)
	}
	return Delete(reference)
}

func (keyringProvider) Assess(string) ReferenceAssessment {
	report := keyringProviderReport()
	return ReferenceAssessment{
		Available: report.Available,
		Secure:    report.SecureStorage,
		Details:   report.Details,
	}
}

func (keyringProvider) Report() ProviderReport { return keyringProviderReport() }
