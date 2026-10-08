//go:build darwin

package tray

import (
	"fmt"
	"os/exec"
	"strings"
)

// RunElevated runs `bin args...` as root through the standard macOS
// administrator password dialog. Without wait, the command is backgrounded
// (`&`) so the dialog returns as soon as it has started.
func RunElevated(bin string, args []string, logPath string, wait bool) error {
	line := shellLine(bin, args, logPath)
	if !wait {
		line += " &"
	}
	// Embed the shell line in an AppleScript string literal.
	as := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(line)
	out, err := exec.Command("osascript", "-e", fmt.Sprintf(`do shell script "%s" with administrator privileges`, as)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// OpenFile opens path with its default application.
func OpenFile(path string) error { return exec.Command("open", path).Start() }
