// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package credentials

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// ReadPassword reads a password from stdin. When stdin is a terminal it reads
// without echoing and restores the terminal state even if the user presses
// Ctrl-C. When stdin is not a terminal (e.g. piped input) it reads a single
// line, which allows non-interactive use such as `... | fv-ssh-unlock ...`.
func ReadPassword() (string, error) {
	fd := int(os.Stdin.Fd())

	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}

	// Save the terminal state and restore it on interrupt so the shell is not
	// left with echo disabled if the user presses Ctrl-C mid-prompt.
	oldState, err := term.GetState(fd)
	if err == nil {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		done := make(chan struct{})
		defer func() {
			signal.Stop(sigCh)
			close(done)
		}()
		go func() {
			select {
			case <-sigCh:
				_ = term.Restore(fd, oldState)
				fmt.Fprintln(os.Stderr)
				os.Exit(1)
			case <-done:
			}
		}()
	}

	password, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr) // move to the next line after the (non-echoed) input
	if err != nil {
		return "", err
	}
	return string(password), nil
}
