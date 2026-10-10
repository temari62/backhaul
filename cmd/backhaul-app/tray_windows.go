//go:build windows

package main

import (
	"runtime"
	"sync/atomic"
	"time"

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

// closeToTray makes the window's close button hide it: Backhaul keeps
// sharing/connecting in the background, reachable from the tray icon.
func closeToTray(hwnd uintptr) {
	const wmClose, swHide = 0x0010, 0
	gwlpWndProc := ^uintptr(3) // GWLP_WNDPROC = -4
	cb := windows.NewCallback(func(h, msg, wp, lp uintptr) uintptr {
		if msg == wmClose && !quitting.Load() {
			procShowWindow.Call(h, swHide)
			return 0
		}
		r, _, _ := procCallWindowProcW.Call(origWndProc, h, msg, wp, lp)
		return r
	})
	origWndProc, _, _ = procSetWindowLongPtrW.Call(hwnd, gwlpWndProc, cb)
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
			systray.SetOnTapped(func() { w.Dispatch(func() { showWindow(hwnd) }) })
			status := systray.AddMenuItem("Backhaul: not running", "")
			status.Disable()
			systray.AddSeparator()
			open := systray.AddMenuItem("Open Backhaul", "Show the window")
			exit := systray.AddMenuItem("Quit", "Stop sharing/connecting, restore the network and exit")
			go func() {
				for {
					select {
					case <-open.ClickedCh:
						w.Dispatch(func() { showWindow(hwnd) })
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
