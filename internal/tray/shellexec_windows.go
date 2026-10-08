//go:build windows

package tray

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// SHELLEXECUTEINFOW mask flags.
const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
)

// shellExecuteInfo mirrors SHELLEXECUTEINFOW (natural alignment matches C).
type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         windows.Handle
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     windows.Handle
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    windows.Handle
	dwHotKey     uint32
	hIconOrMon   windows.Handle
	hProcess     windows.Handle
}

var sizeofShellExecuteInfo = unsafe.Sizeof(shellExecuteInfo{})

var procShellExecuteExW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

func shellExecuteEx(info *shellExecuteInfo) error {
	r, _, err := procShellExecuteExW.Call(uintptr(unsafe.Pointer(info)))
	if r == 0 {
		return err
	}
	return nil
}

// OpenFile opens path with its default application.
func OpenFile(path string) error {
	return windows.ShellExecute(0, windows.StringToUTF16Ptr("open"), windows.StringToUTF16Ptr(path), nil, nil, windows.SW_SHOWNORMAL)
}
