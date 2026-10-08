//go:build windows

package tray

import (
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// RunElevated starts `bin args...` through a UAC prompt ("runas"), hidden,
// with output appended to logPath. With wait it blocks until the command
// exits and returns an error on a non-zero exit code.
func RunElevated(bin string, args []string, logPath string, wait bool) error {
	quoted := []string{syscall.EscapeArg(bin)}
	for _, a := range args {
		quoted = append(quoted, syscall.EscapeArg(a))
	}
	// cmd /S /C ""prog" args >> "log" 2>&1" — /S strips exactly the outer quotes.
	line := fmt.Sprintf(`/S /C "%s >> %s 2>&1"`, strings.Join(quoted, " "), syscall.EscapeArg(logPath))

	info := &shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess | seeMaskNoAsync,
		lpVerb:       windows.StringToUTF16Ptr("runas"),
		lpFile:       windows.StringToUTF16Ptr("cmd.exe"),
		lpParameters: windows.StringToUTF16Ptr(line),
		nShow:        windows.SW_HIDE,
	}
	info.cbSize = uint32(sizeofShellExecuteInfo)
	if err := shellExecuteEx(info); err != nil {
		return fmt.Errorf("elevation was cancelled or failed: %w", err)
	}
	if info.hProcess == 0 {
		return nil
	}
	defer windows.CloseHandle(info.hProcess)
	if !wait {
		return nil
	}
	if _, err := windows.WaitForSingleObject(info.hProcess, windows.INFINITE); err != nil {
		return err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.hProcess, &code); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("exited with code %d (see log)", code)
	}
	return nil
}
