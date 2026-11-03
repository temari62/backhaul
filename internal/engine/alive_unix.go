//go:build unix

package engine

import (
	"errors"
	"syscall"
)

// processAlive reports whether pid exists. EPERM counts as alive: the
// unprivileged app may not signal the root engine, but it does exist.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
