// SPDX-License-Identifier: Apache-2.0

package main

import (
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
}
