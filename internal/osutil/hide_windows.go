//go:build windows

package osutil

import (
	"os/exec"
	"syscall"
)

// createNoWindow keeps console programs (PowerShell, netsh, …) launched from
// the GUI app from flashing a console window.
const createNoWindow = 0x08000000

// HideWindow makes cmd run without a visible console window.
func HideWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createNoWindow
}
