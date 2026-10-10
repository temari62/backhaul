// Package osutil wraps OS-level helpers: running external commands with
// logging, privilege detection, and locating the invoking user's home.
package osutil

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// Runner executes external commands. It is an interface so platform code can
// be unit-tested with a fake.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
	RunStdin(ctx context.Context, stdin string, name string, args ...string) (string, error)
}

// Exec is the real Runner.
type Exec struct{}

// Run executes name with args and returns combined stdout/stderr.
func (Exec) Run(ctx context.Context, name string, args ...string) (string, error) {
	return run(ctx, "", name, args...)
}

// RunStdin is Run with stdin content.
func (Exec) RunStdin(ctx context.Context, stdin string, name string, args ...string) (string, error) {
	return run(ctx, stdin, name, args...)
}

func run(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// Once ctx ends and the process is killed, stop waiting for its output
	// pipes: a grandchild (e.g. a WMI/CIM helper behind a PowerShell cmdlet)
	// can hold them open forever and would otherwise block Run indefinitely.
	cmd.WaitDelay = 3 * time.Second
	HideWindow(cmd)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	slog.Debug("exec", "cmd", name, "args", args)
	err := cmd.Run()
	s := strings.TrimSpace(out.String())
	if err != nil {
		return s, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, s)
	}
	return s, nil
}

// Default is the Runner used by platform code.
var Default Runner = Exec{}

// Run is a shortcut for Default.Run.
func Run(ctx context.Context, name string, args ...string) (string, error) {
	return Default.Run(ctx, name, args...)
}

// RunStdin is a shortcut for Default.RunStdin.
func RunStdin(ctx context.Context, stdin, name string, args ...string) (string, error) {
	return Default.RunStdin(ctx, stdin, name, args...)
}

// PowerShell runs a PowerShell script non-interactively (Windows).
func PowerShell(ctx context.Context, script string) (string, error) {
	return Run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"$ErrorActionPreference='Stop'; "+script)
}

// Has reports whether an executable is on PATH.
func Has(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
