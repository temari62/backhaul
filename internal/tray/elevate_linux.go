//go:build linux

package tray

import (
	"fmt"
	"os"
	"os/exec"
)

// RunElevated runs `bin args...` as root via polkit's pkexec (graphical
// password prompt), with output appended to logPath. pkexec sets PKEXEC_UID,
// which backhaul uses to find the invoking user's config directory.
func RunElevated(bin string, args []string, logPath string, wait bool) error {
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command("pkexec", append([]string{bin}, args...)...)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		return fmt.Errorf("pkexec: %w (is polkit installed?)", err)
	}
	if !wait {
		go func() { cmd.Wait(); log.Close() }() // reap; keep running after the tray
		return nil
	}
	defer log.Close()
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%w (see log)", err)
	}
	return nil
}

// OpenFile opens path with its default application.
func OpenFile(path string) error { return exec.Command("xdg-open", path).Start() }
