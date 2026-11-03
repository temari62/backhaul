//go:build linux && cgo && gtk

package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// launchViaPkexec is the engine.Launcher for Linux: PolicyKit's pkexec shows
// the desktop's authorization prompt and runs the engine as root as its
// child, so pkexec stays alive exactly as long as the engine does. Its exit
// is reported through the returned channel: before the engine wrote its pid
// that means the prompt was refused or pkexec could not run it (exit 126 and
// 127), afterwards that the engine is gone.
//
// ctx is deliberately not used to kill the process: a stop goes through the
// stop file so the engine can put the network back first (internal/engine).
func launchViaPkexec(_ context.Context, exe string, args []string) (<-chan error, error) {
	pk, err := exec.LookPath("pkexec")
	if err != nil {
		return nil, errors.New("Backhaul needs pkexec (PolicyKit) to get administrator rights, and it isn't installed: sudo apt install policykit-1 — or run the app with sudo")
	}
	cmd := exec.Command(pk, append([]string{exe}, args...)...)
	var stderr tailBuffer
	cmd.Stderr = &stderr // pkexec's own complaints; the engine logs to its file
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start the engine: %w", err)
	}
	ch := make(chan error, 1)
	go func() {
		ch <- pkexecError(cmd.Wait(), stderr.String())
		close(ch)
	}()
	return ch, nil
}

// pkexecError words pkexec's exit for the user. The engine's own failures
// carry its exit code (1) and are explained by its marker file, which
// internal/engine prefers over this.
func pkexecError(err error, stderr string) error {
	if err == nil {
		return nil
	}
	var ex *exec.ExitError
	if errors.As(err, &ex) {
		switch ex.ExitCode() {
		case 126: // the dialog was dismissed
			return errors.New("Backhaul needs administrator rights for this: click the button again and enter your password")
		case 127: // not authorized, or no authentication agent in this session
			msg := strings.TrimSpace(stderr)
			if msg == "" {
				msg = "pkexec refused"
			}
			return fmt.Errorf("could not get administrator rights: %s (is this a desktop session with a PolicyKit agent?)", msg)
		}
	}
	return fmt.Errorf("the engine exited: %w", err)
}

// tailBuffer keeps the last few KB written to it.
type tailBuffer struct {
	mu sync.Mutex
	b  []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if n := len(t.b); n > 4096 {
		t.b = t.b[n-4096:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.b)
}
