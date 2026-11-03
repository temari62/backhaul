//go:build linux

package tray

import "github.com/godbus/dbus/v5"

// HostAvailable reports whether this desktop can show a tray icon at all: a
// StatusNotifier host must be registered on the session bus (KDE has one
// built in; GNOME only with the AppIndicator extension, which Ubuntu's own
// session ships enabled). Without one the icon is sent into the void and the
// app looks "invisible", so callers use this to say so — or to keep the
// window's close button meaning quit rather than hide-to-tray. hint says what
// to do when it isn't available.
func HostAvailable() (ok bool, hint string) {
	// The shared session connection: fyne's systray uses it too, so it is
	// deliberately not closed here.
	conn, err := dbus.SessionBus()
	if err != nil {
		return false, "no session D-Bus (" + err.Error() + "): the tray needs a desktop session"
	}
	v, err := conn.Object("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher").
		GetProperty("org.kde.StatusNotifierWatcher.IsStatusNotifierHostRegistered")
	if err == nil {
		if b, _ := v.Value().(bool); b {
			return true, ""
		}
	}
	return false, "this desktop has no system tray (no StatusNotifier host on D-Bus). On GNOME, enable the " +
		"AppIndicator extension — gnome-extensions enable ubuntu-appindicators@ubuntu.com — after " +
		"installing gnome-shell-extension-appindicator if needed, then log out and back in"
}
