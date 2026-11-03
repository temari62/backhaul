//go:build !linux

package tray

// HostAvailable: Windows and macOS always have a tray.
func HostAvailable() (ok bool, hint string) { return true, "" }
