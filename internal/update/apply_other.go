//go:build !windows

package update

import "errors"

// Apply is Windows-only: other platforms update through their package manager
// or by replacing the binary, so this is not implemented.
func Apply(installerPath string) error {
	return errors.New("in-app update is only implemented on Windows")
}
