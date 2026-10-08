// Package health watches the tunnel and reconnects it when WireGuard stops
// handshaking (§8), and provides the connectivity/leak probes used by doctor.
package health

import (
	"context"
	"log/slog"
	"time"

	"backhaul/internal/state"
	"backhaul/internal/transport"
	"backhaul/internal/wg"
)

// Options configure the monitor.
type Options struct {
	Interval         time.Duration
	HandshakeTimeout time.Duration
	StartupGrace     time.Duration
	BackoffMin       time.Duration
	BackoffMax       time.Duration
	// Reconnect enables auto-reconnect (client). The exit node only reports.
	Reconnect bool
	StateDir  string
}

// Monitor is the health loop.
type Monitor struct {
	Opts      Options
	Engine    wg.Engine
	Transport transport.Transport
	Runtime   *state.Runtime
}

// Healthy reports whether the last handshake is recent enough.
func Healthy(st wg.Stats, timeout time.Duration, now time.Time) bool {
	return !st.LastHandshake.IsZero() && now.Sub(st.LastHandshake) <= timeout
}

// Run loops until ctx is done. The kill-switch is deliberately left
// untouched during reconnects, so nothing leaks while the tunnel is down.
func (m *Monitor) Run(ctx context.Context) {
	start := time.Now()
	backoff := m.Opts.BackoffMin
	nextAttempt := time.Time{}
	t := time.NewTicker(m.Opts.Interval)
	defer t.Stop()
	for {
		now := time.Now()
		st, err := m.Engine.Stats()
		healthy := err == nil && Healthy(st, m.Opts.HandshakeTimeout, now)
		if m.Runtime != nil {
			m.Runtime.LastHandshake, m.Runtime.RxBytes, m.Runtime.TxBytes = st.LastHandshake, st.RxBytes, st.TxBytes
			m.Runtime.Healthy = healthy
			m.Runtime.Transport = m.Transport.Status()
			if err := state.Write(m.Opts.StateDir, m.Runtime); err != nil {
				slog.Debug("write runtime state", "err", err)
			}
		}
		switch {
		case healthy:
			backoff = m.Opts.BackoffMin
		case now.Sub(start) < m.Opts.StartupGrace:
			// Give the first handshake time to complete.
		case !m.Opts.Reconnect:
			slog.Debug("no recent handshake from peer", "last", st.LastHandshake)
		case now.After(nextAttempt):
			slog.Warn("tunnel looks dead; reconnecting", "last_handshake", st.LastHandshake, "next_backoff", backoff)
			m.Transport.Restart()
			if err := m.Engine.Kick(); err != nil {
				slog.Warn("re-apply wireguard peer", "err", err)
			}
			if m.Runtime != nil {
				m.Runtime.Reconnects++
			}
			nextAttempt = now.Add(backoff)
			backoff = min(backoff*2, m.Opts.BackoffMax)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
