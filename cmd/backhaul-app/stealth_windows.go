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

var (
	procLoadImageW       = user32.NewProc("LoadImageW")
	procGetModuleHandleW = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW")
	// trayRemoved: stealth mode deleted the icon (as opposed to merely
	// marking it hidden, which the Windows 11 taskbar ignores).
	trayRemoved atomic.Bool
	// trayRefresh asks the tray loop to re-send the icon and tooltip after
	// the icon was added back.
	trayRefresh atomic.Bool
)

// applyTrayVisibility removes or restores the tray icon to match stealth
// mode. It is re-applied periodically: an Explorer restart makes the tray
// library add the icon again.
func applyTrayVisibility() {
	h := trayWindow()
	if h == 0 {
		return
	}
	const (
		nimAdd, nimDelete     = 0, 2
		nifMessage, nifIcon   = 0x1, 0x2
		trayID, trayCallback  = 100, 0x0400 + 1 // fyne.io/systray: icon ID and WM_USER+1
		imageIcon, lrShared   = 1, 0x8000
		appIconID, smallIconS = 1, 16
	)
	d := trayIconData{wnd: h, id: trayID}
	d.size = uint32(unsafe.Sizeof(d))
	if stealth.Load() {
		procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&d))) // fails harmlessly if already gone
		trayRemoved.Store(true)
		return
	}
	if !trayRemoved.Load() {
		return
	}
	// Add it back the way the tray library registers it, with the app icon;
	// the library then updates picture and tooltip as usual.
	d.flags, d.cbMsg = nifMessage|nifIcon, trayCallback
	self, _, _ := procGetModuleHandleW.Call(0) // this exe: its icon resource
	d.icon, _, _ = procLoadImageW.Call(self, appIconID, imageIcon, smallIconS, smallIconS, lrShared)
	if r, _, err := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&d))); r == 0 {
		trayWarnOnce.Do(func() { slog.Warn("could not show the tray icon again (restart Backhaul to get it back)", "err", err) })
		return
	}
	trayRemoved.Store(false)
	trayRefresh.Store(true)
}

var trayWarnOnce sync.Once
