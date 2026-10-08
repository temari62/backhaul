// Package state persists the running tunnel's status to
// <config>/state/runtime.json so `backhaul status` and `backhaul doctor`
// (separate processes) can report on it.
package state

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	Healthy       bool             `json:"healthy"`
	Reconnects    int              `json:"reconnects"`
	Transport     transport.Status `json:"transport"`
}

// File is the runtime state path inside stateDir.
func File(stateDir string) string { return filepath.Join(stateDir, "runtime.json") }

// JournalFile is the undo journal path inside stateDir.
func JournalFile(stateDir string) string { return filepath.Join(stateDir, "undo.json") }

// Write saves r atomically.
func Write(stateDir string, r *Runtime) error {
	r.Updated = time.Now()
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
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
