//go:build unix

// SPDX-License-Identifier: Apache-2.0

package securefs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestStableOpenRejectsFIFOWithoutBlocking(t *testing.T) {
	directory := privateTestDir(t)
	fifo := filepath.Join(directory, "state.fifo")
	if err := unix.Mkfifo(fifo, FileMode); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "state-link")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{"fifo": fifo, "symlink-to-fifo": link} {
		t.Run(name, func(t *testing.T) {
			assertPromptOpenRejection(t, fifo, func() error {
				file, err := OpenStable(path, "test store")
				if file != nil {
					_ = file.Close()
				}
				return err
			})
		})
	}
	assertPromptOpenRejection(t, fifo, func() error {
		file, err := OpenPrivate(fifo, "test store", os.O_RDWR)
		if file != nil {
			_ = file.Close()
		}
		return err
	})
}

func assertPromptOpenRejection(t *testing.T, fifo string, open func() error) {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- open() }()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("non-regular path was accepted")
		}
	case <-time.After(time.Second):
		// Unblock a regressed O_RDONLY FIFO open so the test process can exit
		// cleanly after reporting the timeout.
		writer, _ := unix.Open(fifo, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if writer >= 0 {
			_ = unix.Close(writer)
		}
		<-result
		t.Fatal("opening a non-regular path blocked before validation")
	}
}
