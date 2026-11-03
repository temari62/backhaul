package gui

import "backhaul/internal/tray"

// TrayStatus words a View for the desktop apps' tray icon: the tooltip and
// status-line text, and the phase that picks the icon's status dot.
func TrayStatus(v View) (string, tray.Phase) {
	role := "Connect"
	if v.Running == RoleServe {
		role = "Sharing"
	}
	switch v.Phase {
	case "up":
		if v.Running == RoleServe {
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
