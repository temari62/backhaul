// Package state persists the running tunnel's status to
// <config>/state/runtime.json so `backhaul status` and `backhaul doctor`
// (separate processes) can report on it.
package state

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"backhaul/internal/transport"
)

// Runtime is the snapshot written by serve/connect.
type Runtime struct {
	PID           int              `json:"pid"`
	Mode          string           `json:"mode"`
	Iface         string           `json:"iface"`
	Engine        string           `json:"engine"`
	Started       time.Time        `json:"started"`
	Updated       time.Time        `json:"updated"`
	Endpoint      string           `json:"endpoint,omitempty"`
	EndpointIP    string           `json:"endpoint_ip,omitempty"`
	RealIP        string           `json:"real_ip,omitempty"` // client's public IP before the tunnel
	KillSwitch    bool             `json:"killswitch"`
	IPv6Tunneled  bool             `json:"ipv6_tunneled"`
	LastHandshake time.Time        `json:"last_handshake"`
	RxBytes       int64            `json:"rx_bytes"`
	TxBytes       int64            `json:"tx_bytes"`
	RxRate        float64          `json:"rx_rate"` // bytes/s, sampled every few seconds
	TxRate        float64          `json:"tx_rate"`
	Healthy       bool             `json:"healthy"`
	LANIP         string           `json:"lan_ip,omitempty"` // exit node: where the router must forward the port
	Router        string           `json:"router,omitempty"` // exit node: port-forward status for humans
	Reconnects    int              `json:"reconnects"`
	Transport     transport.Status `json:"transport"`
}

// File is the runtime state path inside stateDir.
func File(stateDir string) string { return filepath.Join(stateDir, "runtime.json") }

// JournalFile is the undo journal path inside stateDir.
func JournalFile(stateDir string) string { return filepath.Join(stateDir, "undo.json") }

// StopFile is created by `backhaul disconnect` to ask a running serve/connect
// to tear down. A file (not a signal) works the same on every OS.
func StopFile(stateDir string) string { return filepath.Join(stateDir, "stop") }

// RequestStop asks the running instance to shut down. The file carries the
// request time, so validity never depends on deleting old requests (which
// can fail on Windows while a scanner holds the file).
func RequestStop(stateDir string) error {
	return os.WriteFile(StopFile(stateDir), []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0o600)
}

// stopRequestedSince reports whether a stop request newer than t exists.
func stopRequestedSince(stateDir string, t time.Time) bool {
	b, err := os.ReadFile(StopFile(stateDir))
	if err != nil {
		return false
	}
	ns, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return err == nil && ns >= t.UnixNano()
}

// WatchStop calls cancel once a stop request made after WatchStop started
// appears, polling every interval. Older (stale) requests are ignored.
func WatchStop(ctx context.Context, stateDir string, interval time.Duration, cancel context.CancelFunc) {
	start := time.Now()
	_ = os.Remove(StopFile(stateDir)) // tidy only; correctness doesn't depend on it
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if stopRequestedSince(stateDir, start) {
				_ = os.Remove(StopFile(stateDir))
				slog.Info("stop requested via `backhaul disconnect`")
				cancel()
				return
			}
		}
	}
}

// Write saves r atomically.
func Write(stateDir string, r *Runtime) error {
	r.Updated = time.Now()
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	// World-traversable so unprivileged `status` and the tray can read
	// runtime.json; secrets inside (undo journal, wg-quick conf, backups)
	// are individually 0600.
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	_ = os.Chmod(stateDir, 0o755) // the undo journal may have created it 0700
	p := File(stateDir)
	if err := os.WriteFile(p+".tmp", b, 0o644); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

// Read loads the runtime state; ok=false if absent.
func Read(stateDir string) (*Runtime, bool, error) {
	b, err := os.ReadFile(File(stateDir))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var r Runtime
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, false, err
	}
	return &r, true, nil
}

// Fresh reports whether the snapshot was updated within maxAge (i.e. the
// writer is probably still alive).
func (r *Runtime) Fresh(maxAge time.Duration) bool { return time.Since(r.Updated) < maxAge }

// Remove deletes the runtime state.
func Remove(stateDir string) { _ = os.Remove(File(stateDir)) }
