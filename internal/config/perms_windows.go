//go:build windows

package config

import (
	"fmt"
	"os"
)

// checkSecretPerms only checks existence on Windows: POSIX modes don't apply
// and the file inherits the user-profile ACL.
// TODO(spec): tighten with an explicit owner-only DACL on Windows.
func checkSecretPerms(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("secrets file: %w", err)
	}
	return nil
}
