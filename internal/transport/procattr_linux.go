//go:build linux

package transport

import (
	"os/exec"
	"syscall"
)

// setProcAttr makes the kernel kill wstunnel if backhaul dies, so a crash
// never leaves an orphaned tunnel running.
func setProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
