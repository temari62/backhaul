package engine

import (
	"errors"

	"golang.org/x/sys/windows"
)

// stillActive is GetExitCodeProcess's code for a process that hasn't exited.
const stillActive = 259

// processAlive reports whether pid exists. No desktop app uses the engine on
// Windows (the app runs elevated as a whole); this keeps the package — and
// its tests — building everywhere. Access denied counts as alive: the
// process exists, it just isn't ours to query.
func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	defer windows.CloseHandle(h)
	var code uint32
	return windows.GetExitCodeProcess(h, &code) == nil && code == stillActive
}
