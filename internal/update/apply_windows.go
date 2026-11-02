//go:build windows

package update

import (
	"fmt"
	"os"
	"os/exec"
)

// Apply launches the downloaded installer silently and returns. The installer
// runs on its own: it waits for this process to exit, replaces the installed
// files, and (with RestartApplication set in the .iss) relaunches Backhaul.
// The caller should shut the app down cleanly right after Apply returns nil.
//
// The flags are Inno Setup's: /VERYSILENT no UI, /SUPPRESSMSGBOXES no prompts,
// /NORESTART never reboot, /CLOSEAPPLICATIONS + /RESTARTAPPLICATIONS let it
// replace the running exe and start the new one.
func Apply(installerPath string) error {
	if _, err := os.Stat(installerPath); err != nil {
		return fmt.Errorf("installer not found: %w", err)
	}
	cmd := exec.Command(installerPath,
		"/VERYSILENT",
		"/SUPPRESSMSGBOXES",
		"/NORESTART",
		"/CLOSEAPPLICATIONS",
		"/RESTARTAPPLICATIONS",
	)
	// Detach: the installer must outlive this process so it can replace the exe.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting installer: %w", err)
	}
	return cmd.Process.Release()
}
