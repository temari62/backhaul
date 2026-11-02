//go:build windows

package main

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"time"

	"backhaul/internal/update"
)

// pendingUpdate holds the newest version string once a background check finds
// one, so the tray can offer it. Empty means none found yet.
var pendingUpdate atomic.Value // string

// checkForUpdate asks GitHub whether a newer release exists.
func checkForUpdate(ctx context.Context) (update.Status, error) {
	return update.Check(ctx)
}

// applyUpdate downloads the latest installer, verifies it, launches it
// silently, then quits Backhaul so the installer can replace the running exe
// and relaunch it. It returns an error (without quitting) if anything fails,
// so the caller can tell the user.
func applyUpdate(ctx context.Context) error {
	rel, err := update.Latest(ctx)
	if err != nil {
		return err
	}
	dir := filepath.Join(appDataDir(), "updates")
	slog.Info("downloading update", "version", rel.Version)
	installer, err := update.Download(ctx, rel, dir)
	if err != nil {
		return err
	}
	slog.Info("launching installer", "path", installer)
	if err := update.Apply(installer); err != nil {
		return err
	}
	// Give the installer a moment to start waiting on us, then quit cleanly:
	// the network is restored on the way out (see main's StopAndWait).
	time.AfterFunc(500*time.Millisecond, func() { quitApp() })
	return nil
}

// startUpdateWatch runs one background check shortly after launch (skipped for
// dev builds) and records any newer version for the tray to surface.
func startUpdateWatch() {
	go func() {
		time.Sleep(8 * time.Second) // let startup settle; don't race the network
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		st, err := checkForUpdate(ctx)
		if err != nil {
			slog.Info("update check failed", "err", err)
			return
		}
		if st.Available {
			slog.Info("update available", "current", st.Current, "latest", st.Latest)
			pendingUpdate.Store(st.Latest)
			notifyUpdateAvailable(st.Latest)
		}
	}()
}
