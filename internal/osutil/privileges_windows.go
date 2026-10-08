//go:build windows

package osutil

import "golang.org/x/sys/windows"

// IsElevated reports whether the process token is elevated (UAC admin).
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
