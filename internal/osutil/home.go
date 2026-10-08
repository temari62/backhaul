package osutil

import (
	"os"
	"os/user"
	"runtime"
)

// UserHome returns the home directory of the human user. When running under
// sudo it resolves SUDO_USER's home, so `sudo backhaul connect` reads the same
// ~/.config/backhaul as the unprivileged `backhaul setup` wrote.
func UserHome() (string, error) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		if su := os.Getenv("SUDO_USER"); su != "" && su != "root" {
			if u, err := user.Lookup(su); err == nil && u.HomeDir != "" {
				return u.HomeDir, nil
			}
		}
	}
	return os.UserHomeDir()
}
