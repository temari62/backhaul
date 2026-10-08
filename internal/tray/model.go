// Package tray holds the platform-neutral parts of the backhaul-tray app:
// the status model behind the menu, generated status-dot icons, and the
// per-OS "run this backhaul command elevated" launchers.
package tray

import (
	"fmt"
	"time"

	"backhaul/internal/state"
)

// Phase is what the status dot shows.
type Phase int

const (
	Down     Phase = iota // grey: not running
	Starting              // amber: launched, not yet handshaking (or reconnecting)
	Up                    // green: healthy tunnel
	Failed                // red: a launch we started never came up
)

// View is everything the menu needs to render.
type View struct {
	Phase         Phase
	Status        string // first (disabled) menu line
	Tooltip       string
	CanConnect    bool
	CanDisconnect bool
}

// Inputs to Compute.
type Inputs struct {
	Runtime    *state.Runtime // nil if no runtime state
	Alive      bool           // runtime's PID is alive
	StaleAfter time.Duration  // runtime older than this = writer is gone
	LaunchedAt time.Time      // when the tray last launched connect (zero = never)
	LaunchWait time.Duration  // how long a launch may take before it counts as failed
	Now        time.Time
}

// Compute derives the view from runtime state.
func Compute(in Inputs) View {
	rt := in.Runtime
	running := rt != nil && in.Alive && rt.Fresh(in.StaleAfter)
	switch {
	case running && rt.Healthy:
		hs := "–"
		if !rt.LastHandshake.IsZero() {
			hs = in.Now.Sub(rt.LastHandshake).Round(time.Second).String() + " ago"
		}
		return View{Phase: Up, Status: fmt.Sprintf("● Connected via %s", rt.Endpoint), CanDisconnect: true,
			Tooltip: fmt.Sprintf("Backhaul: connected (%s)\nhandshake %s · kill-switch %v", rt.Mode, hs, rt.KillSwitch)}
	case running:
		msg := "Connecting…"
		if rt.Reconnects > 0 {
			msg = fmt.Sprintf("Reconnecting… (%d)", rt.Reconnects)
		}
		return View{Phase: Starting, Status: "◐ " + msg, CanDisconnect: true,
			Tooltip: "Backhaul: " + msg + "\nkill-switch keeps traffic blocked until the tunnel is back"}
	case !in.LaunchedAt.IsZero() && in.Now.Sub(in.LaunchedAt) < in.LaunchWait:
		return View{Phase: Starting, Status: "◐ Starting…", CanDisconnect: false, Tooltip: "Backhaul: starting"}
	case !in.LaunchedAt.IsZero():
		return View{Phase: Failed, Status: "✕ Connect failed — see log", CanConnect: true,
			Tooltip: "Backhaul: the last connect attempt did not come up; open the log"}
	default:
		return View{Phase: Down, Status: "○ Disconnected", CanConnect: true, Tooltip: "Backhaul: disconnected"}
	}
}
