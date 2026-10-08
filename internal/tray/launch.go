package tray

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// FindBackhaul locates the backhaul CLI: next to the tray binary, else PATH.
func FindBackhaul() (string, error) {
	name := "backhaul"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if self, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(self), name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return exec.LookPath("backhaul")
}

// shellQuote single-quotes s for POSIX sh.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// shellLine renders argv as a POSIX shell command with output appended to log.
func shellLine(bin string, args []string, logPath string) string {
	parts := []string{shellQuote(bin)}
	for _, a := range args {
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ") + " >> " + shellQuote(logPath) + " 2>&1"
}
