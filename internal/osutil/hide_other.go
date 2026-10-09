//go:build !windows

package osutil

import "os/exec"

// HideWindow is a no-op outside Windows.
func HideWindow(*exec.Cmd) {}
