//go:build !windows

package wg

import "context"

// EnsureWintun is only needed on Windows.
func EnsureWintun(context.Context) error { return nil }

// WintunPath is only meaningful on Windows.
func WintunPath() (string, error) { return "", nil }

// WintunInstalled: not needed outside Windows.
func WintunInstalled() (string, bool) { return "", true }
