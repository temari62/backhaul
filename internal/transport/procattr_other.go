//go:build !linux

package transport

import "os/exec"

// setProcAttr is a no-op here.
// TODO(spec): use a Job Object (Windows) / kqueue NOTE_EXIT watcher (macOS)
// so wstunnel dies with backhaul on crash.
func setProcAttr(*exec.Cmd) {}
