//go:build !windows

package osutil

import (
	"os"
	"syscall"
)

// ProcessAlive reports whether a process with pid is running.
func ProcessAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
