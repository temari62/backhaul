//go:build !windows

package transport

import "os/exec"

func hideWindow(*exec.Cmd) {}
