//go:build windows

package transport

import (
	"os/exec"

	"backhaul/internal/osutil"
)

// hideWindow: wstunnel/xray are console programs; launched from the GUI app
// they would otherwise show a console window for as long as they run.
func hideWindow(cmd *exec.Cmd) { osutil.HideWindow(cmd) }
