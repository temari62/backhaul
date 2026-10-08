//go:build !windows

package osutil

import "os"

// IsElevated reports whether the process runs as root.
func IsElevated() bool { return os.Geteuid() == 0 }
