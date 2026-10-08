package osutil

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// ErrNotPrivileged is returned by RequirePrivileges with an exact re-run hint.
type ErrNotPrivileged struct{ Hint string }

func (e *ErrNotPrivileged) Error() string {
	return "this command needs administrator/root privileges (it manages the tunnel interface, routes and firewall).\n" +
		"Re-run it as:\n\n    " + e.Hint + "\n"
}

// RequirePrivileges returns ErrNotPrivileged with the exact command to re-run
// when the current process is not elevated.
func RequirePrivileges() error {
	if IsElevated() {
		return nil
	}
	return &ErrNotPrivileged{Hint: ElevationHint()}
}

// ElevationHint renders the command line the user should run instead.
func ElevationHint() string {
	args := make([]string, 0, len(os.Args))
	for _, a := range os.Args {
		if strings.ContainsAny(a, " \t\"'") {
			a = fmt.Sprintf("%q", a)
		}
		args = append(args, a)
	}
	cmd := strings.Join(args, " ")
	if runtime.GOOS == "windows" {
		return "(from an elevated PowerShell / \"Run as administrator\")  " + cmd
	}
	return "sudo " + cmd
}
