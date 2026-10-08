//go:build !darwin || cgo

// Command backhaul-tray is the system-tray front end (M8): a status dot plus
// Connect/Disconnect. It runs unprivileged; it reads the tunnel's runtime
// state and launches `backhaul connect` / `backhaul disconnect` through the
// OS's elevation prompt. The tunnel runs independently, so quitting the tray
// does not drop the VPN.
package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"fyne.io/systray"

	"backhaul/internal/config"
	"backhaul/internal/osutil"
	"backhaul/internal/state"
	"backhaul/internal/tray"
)

const (
	pollInterval = 2 * time.Second
	launchWait   = 90 * time.Second // connect may download wstunnel on first run
)

type app struct {
	paths   config.Paths
	cfg     *config.Config
	bin     string
	logPath string

	mu         sync.Mutex
	launchedAt time.Time
	lastErr    string
	phase      tray.Phase

	status, connect, disconnect, openLog, quit *systray.MenuItem
}

func main() {
	systray.Run((&app{phase: -1}).onReady, func() {})
}

func (a *app) onReady() {
	systray.SetTitle("")
	systray.SetIcon(tray.Icon(tray.Down))
	a.status = systray.AddMenuItem("○ Disconnected", "")
	a.status.Disable()
	systray.AddSeparator()
	a.connect = systray.AddMenuItem("Connect", "Route all traffic through the exit node")
	a.disconnect = systray.AddMenuItem("Disconnect", "Stop the tunnel and restore the network")
	systray.AddSeparator()
	a.openLog = systray.AddMenuItem("Open log", "")
	a.quit = systray.AddMenuItem("Quit (tunnel keeps running)", "")

	if err := a.init(); err != nil {
		a.status.SetTitle("✕ " + err.Error())
		systray.SetIcon(tray.Icon(tray.Failed))
		a.connect.Disable()
		a.disconnect.Disable()
	} else {
		if a.cfg.Mode == config.ModeServe {
			a.connect.SetTitle("Start exit node")
			a.disconnect.SetTitle("Stop exit node")
		}
		a.refresh()
		go a.poll()
	}
	go a.handleClicks()
}

func (a *app) init() error {
	dir, err := config.DefaultDir()
	if err != nil {
		return err
	}
	a.paths = config.Paths{Dir: dir}
	a.logPath = dir + string(os.PathSeparator) + "tray.log"
	cfg, _, err := config.Load(a.paths)
	if err != nil {
		return fmt.Errorf("not set up — run `backhaul setup`")
	}
	a.cfg = cfg
	if a.bin, err = tray.FindBackhaul(); err != nil {
		return fmt.Errorf("backhaul CLI not found next to the tray or on PATH")
	}
	return nil
}

func (a *app) poll() {
	for range time.Tick(pollInterval) {
		a.refresh()
	}
}

func (a *app) refresh() {
	rt, ok, _ := state.Read(a.paths.State())
	in := tray.Inputs{
		StaleAfter: 3 * a.cfg.Health.Interval.Duration,
		LaunchWait: launchWait,
		Now:        time.Now(),
	}
	if ok {
		in.Runtime, in.Alive = rt, osutil.ProcessAlive(rt.PID)
	}
	a.mu.Lock()
	in.LaunchedAt = a.launchedAt
	if in.Runtime != nil && in.Alive {
		a.launchedAt = time.Time{} // the launch succeeded
	}
	lastErr := a.lastErr
	a.mu.Unlock()

	v := tray.Compute(in)
	status := v.Status
	if lastErr != "" && v.Phase != tray.Up && v.Phase != tray.Starting {
		status = "✕ " + lastErr
	}
	a.status.SetTitle(status)
	systray.SetTooltip(v.Tooltip)
	setEnabled(a.connect, v.CanConnect)
	setEnabled(a.disconnect, v.CanDisconnect)
	a.mu.Lock()
	changed := a.phase != v.Phase
	a.phase = v.Phase
	a.mu.Unlock()
	if changed {
		systray.SetIcon(tray.Icon(v.Phase))
	}
}

func (a *app) handleClicks() {
	for {
		select {
		case <-a.connect.ClickedCh:
			a.mu.Lock()
			a.launchedAt, a.lastErr = time.Now(), ""
			a.mu.Unlock()
			a.refresh()
			go a.run(false, a.cfg.Mode)
		case <-a.disconnect.ClickedCh:
			a.disconnect.Disable()
			go a.run(true, "disconnect")
		case <-a.openLog.ClickedCh:
			if f, err := os.OpenFile(a.logPath, os.O_CREATE|os.O_APPEND, 0o600); err == nil {
				f.Close()
			}
			_ = tray.OpenFile(a.logPath)
		case <-a.quit.ClickedCh:
			systray.Quit()
			return
		}
	}
}

// run launches `backhaul <sub> --config-dir <dir>` elevated.
func (a *app) run(wait bool, sub string) {
	err := tray.RunElevated(a.bin, []string{sub, "--config-dir", a.paths.Dir}, a.logPath, wait)
	a.mu.Lock()
	if err != nil {
		a.lastErr = sub + ": " + err.Error()
		a.launchedAt = time.Time{}
	}
	a.mu.Unlock()
	a.refresh()
}

func setEnabled(m *systray.MenuItem, on bool) {
	if on {
		m.Enable()
	} else {
		m.Disable()
	}
}
