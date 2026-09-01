// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shoon/fv-ssh-unlock/internal/config"
)

func TestCompareDeviceInventories(t *testing.T) {
	current := []config.Device{
		{Name: "remove", Host: "192.0.2.1", User: "user", Port: 22},
		{Name: "update", Host: "192.0.2.2", User: "user", Port: 22},
		{Name: "same", Host: "192.0.2.3", User: "user", Port: 22},
	}
	desired := []config.Device{
		{Name: "same", Host: "192.0.2.3", User: "user", Port: 22},
		{Name: "update", Host: "192.0.2.20", User: "user", Port: 22, AutoUnlock: true},
		{Name: "add", Host: "192.0.2.4", User: "user", Port: 22},
	}
	report := compareDeviceInventories(current, desired)
	if !report.Changed || report.DeviceCount != 3 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if strings.Join(report.Added, ",") != "add" || strings.Join(report.Updated, ",") != "update" || strings.Join(report.Removed, ",") != "remove" {
		t.Fatalf("unexpected diff: %+v", report)
	}
}

func TestCompareDeviceInventoriesUnchanged(t *testing.T) {
	devices := []config.Device{{Name: "mac", Host: "192.0.2.1", User: "user", Port: 22}}
	report := compareDeviceInventories(devices, devices)
	if report.Changed {
		t.Fatalf("identical inventories reported changed: %+v", report)
	}
}

func TestReadDeclarativeConfigLimitsInput(t *testing.T) {
	_, err := readDeclarativeConfig(strings.NewReader(strings.Repeat("x", maxDeclarativeConfigSize+1)), "-")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestAppDataDirOverrideAndEnvironment(t *testing.T) {
	old := dataDirOverride
	t.Cleanup(func() { dataDirOverride = old })
	dataDirOverride = "relative"
	if _, err := appDataDir(); err == nil {
		t.Fatal("relative --data-dir must fail")
	}
	dataDirOverride = t.TempDir()
	if got, err := appDataDir(); err != nil || got != dataDirOverride {
		t.Fatalf("appDataDir() = %q, %v", got, err)
	}

	dataDirOverride = ""
	t.Setenv("FV_SSH_UNLOCK_DATA_DIR", "relative")
	if _, err := appDataDir(); err == nil {
		t.Fatal("relative FV_SSH_UNLOCK_DATA_DIR must fail")
	}
	absolute := t.TempDir()
	t.Setenv("FV_SSH_UNLOCK_DATA_DIR", filepath.Join(absolute, "nested", ".."))
	if got, err := appDataDir(); err != nil || got != absolute {
		t.Fatalf("environment appDataDir() = %q, %v", got, err)
	}
	if got, err := configPath(); err != nil || got != filepath.Join(absolute, "devices.json") {
		t.Fatalf("environment configPath() = %q, %v", got, err)
	}
}

func useCommandTestDataDir(t *testing.T) *config.Store {
	t.Helper()
	old := dataDirOverride
	dataDirOverride = privateDaemonTestDir(t)
	t.Cleanup(func() { dataDirOverride = old })
	store, err := configStore()
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestDeclarativeConfigCommandsRoundTripAndCheckMode(t *testing.T) {
	store := useCommandTestDataDir(t)
	current := []config.Device{{Name: "old", Host: "192.0.2.1", User: "admin", Port: 22}}
	if err := store.Save(current); err != nil {
		t.Fatal(err)
	}
	desired := []config.Device{{Name: "new", Host: "192.0.2.2", User: "admin", Port: 22}}
	encoded, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}

	check := newConfigApplyCommand()
	check.SetArgs([]string{"--file", "-", "--check", "--json"})
	check.SetIn(bytes.NewReader(encoded))
	var output bytes.Buffer
	check.SetOut(&output)
	check.SetErr(&output)
	check.SilenceUsage = true
	check.SilenceErrors = true
	if err := check.Execute(); err != nil {
		t.Fatal(err)
	}
	var report configApplyReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Changed || !report.CheckMode || strings.Join(report.Added, ",") != "new" || strings.Join(report.Removed, ",") != "old" {
		t.Fatalf("check report = %+v", report)
	}
	if unchanged, err := store.Load(); err != nil || len(unchanged) != 1 || unchanged[0].Name != "old" {
		t.Fatalf("check mode changed inventory: %+v, %v", unchanged, err)
	}

	apply := newConfigApplyCommand()
	apply.SetArgs([]string{"--file", "-"})
	apply.SetIn(bytes.NewReader(encoded))
	output.Reset()
	apply.SetOut(&output)
	apply.SetErr(&output)
	apply.SilenceUsage = true
	apply.SilenceErrors = true
	if err := apply.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Applied device inventory: +1 ~0 -1") {
		t.Fatalf("apply output = %q", output.String())
	}

	applyAgain := newConfigApplyCommand()
	applyAgain.SetArgs([]string{"--file", "-"})
	applyAgain.SetIn(bytes.NewReader(encoded))
	output.Reset()
	applyAgain.SetOut(&output)
	applyAgain.SetErr(&output)
	applyAgain.SilenceUsage = true
	applyAgain.SilenceErrors = true
	if err := applyAgain.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "already matches (1 device(s))") {
		t.Fatalf("unchanged output = %q", output.String())
	}

	export := newConfigExportCommand()
	output.Reset()
	export.SetOut(&output)
	export.SetErr(&output)
	export.SilenceUsage = true
	export.SilenceErrors = true
	if err := export.Execute(); err != nil {
		t.Fatal(err)
	}
	var exported []config.Device
	if err := json.Unmarshal(output.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported) != 1 || exported[0] != desired[0] {
		t.Fatalf("exported inventory = %+v", exported)
	}
}

func TestAutoUnlockConfigCommandEnablesDisablesAndRejectsAmbiguity(t *testing.T) {
	store := useCommandTestDataDir(t)
	device := config.Device{
		Name: "mac", Host: "192.0.2.1", User: "admin", Port: 22,
		Cred: "fvu-mac", CredentialSource: "keyring",
	}
	if err := store.Save([]config.Device{device}); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		flag string
		want bool
	}{
		{flag: "--enable", want: true},
		{flag: "--disable", want: false},
	} {
		cmd := newAutoUnlockConfigCommand()
		cmd.SetArgs([]string{"mac", test.flag})
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		devices, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if len(devices) != 1 || devices[0].AutoUnlock != test.want || !strings.Contains(output.String(), "Automatic unlock") {
			t.Fatalf("%s result = %+v, output %q", test.flag, devices, output.String())
		}
	}

	for name, args := range map[string][]string{
		"neither flag": {},
		"both flags":   {"--enable", "--disable"},
		"missing host": {"missing", "--enable"},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := newAutoUnlockConfigCommand()
			if name == "neither flag" {
				args = []string{"mac"}
			}
			cmd.SetArgs(args)
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			if err := cmd.Execute(); err == nil {
				t.Fatal("invalid auto-unlock invocation succeeded")
			}
		})
	}
}

func TestConfigApplyRejectsMissingAndMalformedInput(t *testing.T) {
	useCommandTestDataDir(t)
	for name, test := range map[string]struct {
		args  []string
		input string
	}{
		"missing file":   {args: nil},
		"unknown field":  {args: []string{"--file", "-"}, input: `[{"name":"mac","host":"192.0.2.1","user":"admin","unknown":true}]`},
		"trailing data":  {args: []string{"--file", "-"}, input: `[] []`},
		"invalid device": {args: []string{"--file", "-"}, input: `[{"name":"","host":"192.0.2.1","user":"admin"}]`},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := newConfigApplyCommand()
			cmd.SetArgs(test.args)
			cmd.SetIn(strings.NewReader(test.input))
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			if err := cmd.Execute(); err == nil {
				t.Fatal("invalid inventory was accepted")
			}
		})
	}

	path := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readDeclarativeConfig(strings.NewReader("ignored"), path); err != nil || string(got) != "[]" {
		t.Fatalf("file inventory = %q, %v", got, err)
	}
}
