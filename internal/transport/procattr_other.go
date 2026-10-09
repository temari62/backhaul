//go:build !linux && !windows

package transport

import "os/exec"

// setProcAttr is a no-op here.
// TODO(spec): use a kqueue NOTE_EXIT watcher on macOS so wstunnel dies with
// backhaul on crash (Linux uses Pdeathsig, Windows a Job Object).
func setProcAttr(*exec.Cmd) {}

func afterStart(*exec.Cmd) {}
