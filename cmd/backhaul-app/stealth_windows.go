//go:build windows

package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Stealth mode hides the tray icon. Backhaul keeps running; starting
// Backhaul.exe again shows the window (single-instance), and Settings has a
// Quit button.

var stealth atomic.Bool

// appSettings are the desktop app's own preferences (not tunnel config).
type appSettings struct {
	Stealth bool `json:"stealth"`
}

var (
	settingsMu   sync.Mutex
	settingsPath string
)

func loadSettings(dataDir string) appSettings {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	settingsPath = filepath.Join(dataDir, "settings.json")
	var s appSettings
	if b, err := os.ReadFile(settingsPath); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func saveSettings(s appSettings) error {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := settingsPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, settingsPath)
}

func setStealth(on bool) error {
	if err := saveSettings(appSettings{Stealth: on}); err != nil {
		return err
	}
	stealth.Store(on)
	applyTrayVisibility()
	return nil
}

var (
	shell32                      = windows.NewLazySystemDLL("shell32.dll")
	procShellNotifyIconW         = shell32.NewProc("Shell_NotifyIconW")
	procFindWindowExW            = user32.NewProc("FindWindowExW")
	procGetWindowThreadProcessId = user32.NewProc("GetWindowThreadProcessId")
)

// trayIconData is NOTIFYICONDATAW (Windows only accepts its known sizes).
type trayIconData struct {
	size             uint32
	wnd              uintptr
	id, flags, cbMsg uint32
	icon             uintptr
	tip              [128]uint16
	state, mask      uint32
	info             [256]uint16
	timeout, version uint32
	infoTitle        [64]uint16
	infoFlags        uint32
	guid             windows.GUID
	balloonIcon      uintptr
}

// trayWindow finds this process's systray message window (fyne.io/systray
// creates one of class "SystrayClass"; its icon has ID 100).
func trayWindow() uintptr {
	class, _ := windows.UTF16PtrFromString("SystrayClass")
	pid := uint32(os.Getpid())
	var h uintptr
	for {
		h, _, _ = procFindWindowExW.Call(0, h, uintptr(unsafe.Pointer(class)), 0)
		if h == 0 {
			return 0
		}
		var owner uint32
		procGetWindowThreadProcessId.Call(h, uintptr(unsafe.Pointer(&owner)))
		if owner == pid {
			return h
		}
	}
}

// applyTrayVisibility hides or shows the tray icon to match stealth mode.
// It is re-applied periodically: Explorer restarts re-add the icon.
func applyTrayVisibility() {
	h := trayWindow()
	if h == 0 {
		return
	}
	const nimModify, nifState, nisHidden = 1, 0x8, 0x1
	d := trayIconData{wnd: h, id: 100, flags: nifState, mask: nisHidden}
	d.size = uint32(unsafe.Sizeof(d))
	if stealth.Load() {
		d.state = nisHidden
	}
	if r, _, err := procShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&d))); r == 0 {
		trayWarnOnce.Do(func() { slog.Warn("could not change the tray icon's visibility", "err", err) })
	}
}

var trayWarnOnce sync.Once
