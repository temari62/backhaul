//go:build !windows

package osutil

// EnableVT is a no-op: Unix terminals interpret ANSI escapes natively.
func EnableVT() bool { return true }
