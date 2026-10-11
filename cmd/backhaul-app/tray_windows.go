//go:build windows

package main

import (
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	"fyne.io/systray"
	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"

	"backhaul/internal/gui"
	"backhaul/internal/tray"
)

// quitting is set when the user chose Quit: from then on, closing the window
// really closes it instead of hiding it in the tray.
var quitting atomic.Bool

var (
	procSetWindowLongPtrW = user32.NewProc("SetWindowLongPtrW")
	procCallWindowProcW   = user32.NewProc("CallWindowProcW")
	origWndProc           uintptr
)

var (
	procGetWindowLongPtrW = user32.NewProc("GetWindowLongPtrW")
	procSetWindowPos      = user32.NewProc("SetWindowPos")
	procReleaseCapture    = user32.NewProc("ReleaseCapture")
	procSendMessageW      = user32.NewProc("SendMessageW")
	procDefWindowProcW    = user32.NewProc("DefWindowProcW")
)

const (
	wmClose, wmNCCalcSize, wmNCActivate, wmNCLButtonDown = 0x0010, 0x0083, 0x0086, 0x00A1
	swHide, swMinimize                                   = 0, 6
	htCaption                                            = 2
)

var (
	procSetWindowsHookExW   = user32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx = user32.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx      = user32.NewProc("CallNextHookEx")
	procGetClassNameW       = user32.NewProc("GetClassNameW")

	// startHidden: the window is cloaked (kept undrawn by Windows) while
	// WebView2 starts, so no empty or half-drawn window flashes up; showMain
	// or uncloak lifts it.
	startHidden atomic.Bool
)

const wmCreate = 0x0001

// cloak hides (or reveals) a window without changing its visibility state:
// Windows treats it as shown, it just isn't drawn.
func cloak(hwnd uintptr, on bool) {
	const dwmwaCloak = 13
	v := int32(0)
	if on {
		v = 1
	}
	procDwmSetWindowAttr.Call(hwnd, dwmwaCloak, uintptr(unsafe.Pointer(&v)), unsafe.Sizeof(v))
}

// frameProc is the window procedure installed in front of go-webview2's.
//
// It removes the native title bar (the page draws its own, with minimize and
// close buttons): answering WM_NCCALCSIZE with 0 lets the page cover the
// whole window, while the window keeps its caption and sizing styles, so
// Windows still gives it a shadow, rounded corners (Windows 11), Snap and
// Alt+Tab. Closing hides the window: Backhaul keeps sharing/connecting in
// the background, reachable from the tray icon.
var frameProc = windows.NewCallback(func(h, msg, wp, lp uintptr) uintptr {
	switch {
	case msg == wmClose && !quitting.Load():
		procShowWindow.Call(h, swHide)
		return 0
	case msg == wmNCCalcSize && wp != 0:
		return 0 // client area = whole window: no title bar
	case msg == wmNCActivate:
		// Don't let Windows repaint the (now hidden) frame on focus changes.
		r, _, _ := procDefWindowProcW.Call(h, msg, wp, ^uintptr(0))
		return r
	case msg == wmCreate && startHidden.Load():
		cloak(h, true) // before go-webview2 shows it
	}
	r, _, _ := procCallWindowProcW.Call(origWndProc, h, msg, wp, lp)
	return r
})

// hookMainWindow arranges for the main window to be frameless and hidden
// from the moment it is created (go-webview2 creates it with a title bar and
// shows it at once). Call before webview2.NewWithOptions, on the same
// thread; the returned function removes the hook.
func hookMainWindow() (unhook func()) {
	startHidden.Store(true)
	const whCBT, hcbtCreateWnd = 5, 3
	var hook uintptr
	cb := windows.NewCallback(func(code, wp, lp uintptr) uintptr {
		if code == hcbtCreateWnd && origWndProc == 0 {
			var buf [32]uint16
			n, _, _ := procGetClassNameW.Call(wp, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
			if windows.UTF16ToString(buf[:n]) == "webview" {
				origWndProc, _, _ = procSetWindowLongPtrW.Call(wp, ^uintptr(3) /* GWLP_WNDPROC */, frameProc)
			}
		}
		r, _, _ := procCallNextHookEx.Call(hook, code, wp, lp)
		return r
	})
	hook, _, _ = procSetWindowsHookExW.Call(whCBT, cb, 0, uintptr(windows.GetCurrentThreadId()))
	return func() { procUnhookWindowsHookEx.Call(hook) }
}

// customFrame finishes the frame once the window exists: no maximize (the
// app is a small fixed-layout window), and a frame recalculation in case the
// creation hook didn't run.
func customFrame(hwnd uintptr) {
	gwlStyle := ^uintptr(15) // GWL_STYLE = -16
	if origWndProc == 0 {
		origWndProc, _, _ = procSetWindowLongPtrW.Call(hwnd, ^uintptr(3), frameProc)
	}
	const wsMaximizeBox = 0x00010000
	style, _, _ := procGetWindowLongPtrW.Call(hwnd, gwlStyle)
	procSetWindowLongPtrW.Call(hwnd, gwlStyle, style&^wsMaximizeBox)
	const swpNoSize, swpNoMove, swpNoZOrder, swpFrameChanged = 0x1, 0x2, 0x4, 0x20
	procSetWindowPos.Call(hwnd, 0, 0, 0, 0, 0, swpNoSize|swpNoMove|swpNoZOrder|swpFrameChanged)
}

// showMain lifts the start-up cloak and shows the window.
func showMain(hwnd uintptr) {
	uncloak(hwnd)
	showWindow(hwnd)
}

// uncloak ends the start-up cloak without showing the window (used when
// starting in the tray: the window is hidden normally instead).
func uncloak(hwnd uintptr) {
	if startHidden.Swap(false) {
		cloak(hwnd, false)
	}
}

// beginDrag hands the mouse to Windows' own move (hit = HTCAPTION) or resize
// (HTLEFT … HTBOTTOMRIGHT) loop, as if the user had grabbed a real frame.
// Must run on the UI thread while the button is still down.
func beginDrag(hwnd uintptr, hit int) {
	if hit != htCaption && (hit < 10 || hit > 17) {
		return
	}
	procReleaseCapture.Call()
	procSendMessageW.Call(hwnd, wmNCLButtonDown, uintptr(hit), 0)
}

func showWindow(hwnd uintptr) {
	const swShow, swRestore = 5, 9
	procShowWindow.Call(hwnd, swShow)
	procShowWindow.Call(hwnd, swRestore)
	procSetForegroundWindow.Call(hwnd)
}

// runTray shows the tray icon (on its own OS thread with its own message
// loop) until quit is requested from its menu.
func runTray(w webview2.WebView, b *gui.Backend) {
	hwnd := uintptr(w.Window())
	quit := func() {
		quitting.Store(true)
		w.Dispatch(w.Terminate)
	}
	go func() {
		runtime.LockOSThread()
		systray.Run(func() {
			systray.SetIcon(tray.Icon(tray.Down))
			systray.SetTooltip("Backhaul")
			systray.SetOnTapped(func() { w.Dispatch(func() { showMain(hwnd) }) })
			status := systray.AddMenuItem("Backhaul: not running", "")
			status.Disable()
			systray.AddSeparator()
			open := systray.AddMenuItem("Open Backhaul", "Show the window")
			exit := systray.AddMenuItem("Quit", "Stop sharing/connecting, restore the network and exit")
			go func() {
				for {
					select {
					case <-open.ClickedCh:
						w.Dispatch(func() { showMain(hwnd) })
					case <-exit.ClickedCh:
						quit()
						return
					}
				}
			}()
			go func() {
				last := ""
				for !quitting.Load() {
					text, phase := trayStatus(b.State())
					if text != last {
						systray.SetIcon(tray.Icon(phase))
						systray.SetTooltip(text)
						status.SetTitle(text)
						last = text
					}
					time.Sleep(time.Second)
				}
			}()
		}, nil)
	}()
}

func trayStatus(v gui.View) (string, tray.Phase) {
	role := "Connect"
	if v.Running == gui.RoleServe {
		role = "Sharing"
	}
	switch v.Phase {
	case "up":
		if v.Running == gui.RoleServe {
			return "Backhaul: sharing — other PC connected", tray.Up
		}
		return "Backhaul: connected", tray.Up
	case "waiting":
		return "Backhaul: sharing — waiting for the other PC", tray.Up
	case "starting":
		return "Backhaul: " + map[string]string{"Sharing": "starting to share…", "Connect": "connecting…"}[role], tray.Starting
	case "reconnecting":
		return "Backhaul: reconnecting…", tray.Starting
	case "stopping":
		return "Backhaul: stopping…", tray.Starting
	}
	if v.Error != "" {
		return "Backhaul: stopped (error)", tray.Failed
	}
	return "Backhaul: not running", tray.Down
}
