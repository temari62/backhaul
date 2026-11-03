//go:build linux && cgo && gtk

package main

import (
	"sync/atomic"
	"time"

	"fyne.io/systray"
	webview "github.com/webview/webview_go"

	"backhaul/internal/gui"
	"backhaul/internal/tray"
)

// quitting is set when the user chose Quit from the tray.
var quitting atomic.Bool

// runTray shows the tray icon until Quit is chosen from its menu, as the
// Windows app does. On Linux fyne's tray is a StatusNotifierItem over D-Bus
// with no GTK involvement, so it runs in its own goroutine beside webview's
// main loop; only window changes go back through Dispatch.
func runTray(w webview.WebView, b *gui.Backend) {
	win := w.Window()
	show := func() { w.Dispatch(func() { showWindow(win) }) }
	go systray.Run(func() {
		systray.SetIcon(tray.Icon(tray.Down))
		systray.SetTooltip("Backhaul")
		systray.SetOnTapped(show)
		status := systray.AddMenuItem("Backhaul: not running", "")
		status.Disable()
		systray.AddSeparator()
		open := systray.AddMenuItem("Open Backhaul", "Show the window")
		exit := systray.AddMenuItem("Quit", "Stop sharing/connecting, restore the network and exit")
		go func() {
			for {
				select {
				case <-open.ClickedCh:
					show()
				case <-exit.ClickedCh:
					quitting.Store(true)
					w.Dispatch(w.Terminate)
					return
				}
			}
		}()
		go func() {
			last := ""
			for !quitting.Load() {
				text, phase := gui.TrayStatus(b.State())
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
}
