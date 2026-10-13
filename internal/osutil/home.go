package osutil

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
)

// UserHome returns the home directory of the human user. When running under
// sudo or pkexec it resolves the invoking user's home, so `sudo backhaul
// connect` reads the same ~/.config/backhaul as the unprivileged
// `backhaul setup` wrote.
func UserHome() (string, error) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		if su := os.Getenv("SUDO_USER"); su != "" && su != "root" {
			if u, err := user.Lookup(su); err == nil && u.HomeDir != "" {
				return u.HomeDir, nil
			}
		}
		if uid := os.Getenv("PKEXEC_UID"); uid != "" && uid != "0" {
			if u, err := user.LookupId(uid); err == nil && u.HomeDir != "" {
				return u.HomeDir, nil
			}
		}
	}
	if h, err := os.UserHomeDir(); err == nil {
		return h, nil
	}
	// No $HOME, as for a systemd system service: ask the user database
	// (root → /root), so the service finds the config `backhaul setup` wrote.
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		return "", fmt.Errorf("can't find the home directory ($HOME is not set); set BACKHAUL_CONFIG_DIR or HOME")
	}
	return u.HomeDir, nil
}
