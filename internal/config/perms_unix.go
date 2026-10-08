//go:build !windows

package config

import (
	"fmt"
	"os"
)

// checkSecretPerms refuses to load a secrets file readable by group/others.
func checkSecretPerms(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("secrets file: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has permissions %o; it must be 0600. Fix with: chmod 600 %s",
			path, st.Mode().Perm(), path)
	}
	return nil
}
