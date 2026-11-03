//go:build darwin && cgo

package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// launchViaOsascript is the engine.Launcher for macOS: `do shell script …
// with administrator privileges` shows the system password prompt. The
// engine is backgrounded with its output redirected, so osascript returns as
// soon as it is launched instead of waiting for it to end; from then on the
// engine is on its own (no exit channel), and internal/engine follows it
// through the state directory.
func launchViaOsascript(ctx context.Context, exe string, args []string) (<-chan error, error) {
	cmdline := shellQuote(exe)
	for _, a := range args {
		cmdline += " " + shellQuote(a)
	}
	script := fmt.Sprintf("do shell script %s with administrator privileges", asQuote(cmdline+" >/dev/null 2>&1 &"))
	if out, err := exec.CommandContext(ctx, "osascript", "-e", script).CombinedOutput(); err != nil {
		if strings.Contains(strings.ToLower(string(out)), "cancel") { // "User canceled. (-128)"
			return nil, errors.New("Backhaul needs administrator rights for this: click the button again and enter your password")
		}
		return nil, fmt.Errorf("could not start the engine: %s", strings.TrimSpace(string(out)))
	}
	return nil, nil
}

// shellQuote single-quotes s for /bin/sh.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// asQuote double-quotes s for an AppleScript string literal.
func asQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
