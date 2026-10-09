// Package health watches the tunnel and reconnects it when it stops carrying
// traffic (§8), measures throughput, and provides the connectivity/leak
// probes used by doctor.
package health

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
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
	// Check, if set, runs on every tick while unhealthy and every
	// CheckEvery-th tick while healthy (e.g. the client's route guard).
	Check      func(ctx context.Context)
	CheckEvery int
	// LinkDown, if set, reports that the transport currently has no working
	// connection to the peer; the tunnel then counts as unhealthy at once
	// instead of after HandshakeTimeout.
	LinkDown func() bool
	// Probe, if set, actively tests the tunnel end to end each tick (e.g. a
	// DNS query to the exit node through the tunnel). ProbeFailures
	// consecutive failures (default 2) make the tunnel unhealthy.
	Probe         func(ctx context.Context) error
	ProbeFailures int
	// OnDown runs once when a working tunnel stops working; OnUp when it
	// recovers, with the outage length.
	OnDown func(ctx context.Context, st wg.Stats)
	OnUp   func(outage time.Duration)
}

// Monitor is the health loop.
type Monitor struct {
	Opts      Options
	Engine    wg.Engine
	Transport transport.Transport
	Runtime   *state.Runtime

	mu sync.Mutex // guards Runtime (written by the loop and the speed sampler)
}

// Healthy reports whether the last handshake is recent enough.
func Healthy(st wg.Stats, timeout time.Duration, now time.Time) bool {
	return !st.LastHandshake.IsZero() && now.Sub(st.LastHandshake) <= timeout
}

// Run loops until ctx is done. The kill-switch is deliberately left
// untouched during reconnects, so nothing leaks while the tunnel is down.
func (m *Monitor) Run(ctx context.Context) {
	if m.Runtime != nil {
		go m.sampleSpeed(ctx)
	}
	start := time.Now()
	backoff := m.Opts.BackoffMin
	nextAttempt := time.Time{}
	threshold := m.Opts.ProbeFailures
	if threshold <= 0 {
		threshold = 2
	}
	var (
		probeFails  int
		everHealthy bool
		down        bool
		downSince   time.Time
	)
	t := time.NewTicker(m.Opts.Interval)
	defer t.Stop()
	for tick := 0; ; tick++ {
		now := time.Now()
		st, err := m.Engine.Stats()
		healthy := err == nil && Healthy(st, m.Opts.HandshakeTimeout, now) && (m.Opts.LinkDown == nil || !m.Opts.LinkDown())
		if m.Opts.Probe != nil {
			if perr := m.Opts.Probe(ctx); perr != nil {
				probeFails++
				slog.Debug("liveness probe failed", "err", perr, "consecutive", probeFails)
			} else {
				probeFails = 0
			}
			healthy = healthy && probeFails < threshold
		}
		if m.Opts.Check != nil && (!healthy || m.Opts.CheckEvery <= 1 || tick%m.Opts.CheckEvery == 0) {
			m.Opts.Check(ctx)
		}
		// Outage bookkeeping (not before the tunnel ever worked or the
		// startup grace ran out).
		switch {
		case healthy && down:
			down = false
			if m.Opts.OnUp != nil {
				m.Opts.OnUp(now.Sub(downSince))
			}
		case !healthy && !down && (everHealthy || now.Sub(start) >= m.Opts.StartupGrace):
			down, downSince = true, now
			if m.Opts.OnDown != nil {
				m.Opts.OnDown(ctx, st)
			}
		}
		if healthy {
			everHealthy = true
		}
		m.mu.Lock()
		if m.Runtime != nil {
			m.Runtime.LastHandshake, m.Runtime.RxBytes, m.Runtime.TxBytes = st.LastHandshake, st.RxBytes, st.TxBytes
			m.Runtime.Healthy = healthy
			m.Runtime.Transport = m.Transport.Status()
			if err := state.Write(m.Opts.StateDir, m.Runtime); err != nil {
				slog.Debug("write runtime state", "err", err)
			}
		}
		m.mu.Unlock()
		switch {
		case healthy:
			backoff = m.Opts.BackoffMin
		case now.Sub(start) < m.Opts.StartupGrace && !everHealthy:
			// Give the first handshake time to complete.
		case !m.Opts.Reconnect:
			slog.Debug("no recent handshake from peer", "last", st.LastHandshake)
		case now.After(nextAttempt):
			slog.Warn("tunnel is not carrying traffic; reconnecting", "last_handshake", st.LastHandshake, "next_backoff", backoff)
			m.Transport.Restart()
			if err := m.Engine.Kick(); err != nil {
				slog.Warn("re-apply wireguard peer", "err", err)
			}
			m.mu.Lock()
			if m.Runtime != nil {
				m.Runtime.Reconnects++
			}
			m.mu.Unlock()
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

// Speed sampling: rates for the app every SpeedInterval, a summary line in
// the log every SpeedLogInterval.
const (
	SpeedInterval    = 2 * time.Second
	SpeedLogInterval = time.Minute
)

// sampleSpeed measures tunnel throughput from WireGuard's byte counters.
func (m *Monitor) sampleSpeed(ctx context.Context) {
	t := time.NewTicker(SpeedInterval)
	defer t.Stop()
	var (
		last     wg.Stats
		lastAt   time.Time
		w        SpeedWindow
		windowAt = time.Now()
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		st, err := m.Engine.Stats()
		if err != nil {
			continue
		}
		now := time.Now()
		if !lastAt.IsZero() {
			rx, tx := Rate(last.RxBytes, st.RxBytes, now.Sub(lastAt)), Rate(last.TxBytes, st.TxBytes, now.Sub(lastAt))
			w.Add(rx, tx)
			m.mu.Lock()
			m.Runtime.RxRate, m.Runtime.TxRate = rx, tx
			m.Runtime.RxBytes, m.Runtime.TxBytes = st.RxBytes, st.TxBytes
			if err := state.Write(m.Opts.StateDir, m.Runtime); err != nil {
				slog.Debug("write runtime state", "err", err)
			}
			m.mu.Unlock()
		}
		last, lastAt = st, now
		if now.Sub(windowAt) >= SpeedLogInterval {
			slog.Info("traffic in the last minute", "download_avg", HumanRate(w.AvgRx()), "download_peak", HumanRate(w.PeakRx),
				"upload_avg", HumanRate(w.AvgTx()), "upload_peak", HumanRate(w.PeakTx))
			w, windowAt = SpeedWindow{}, now
		}
	}
}

// Rate is bytes per second between two counter readings (0 if the counter
// went backwards, e.g. after a device restart).
func Rate(prev, cur int64, dt time.Duration) float64 {
	if cur < prev || dt <= 0 {
		return 0
	}
	return float64(cur-prev) / dt.Seconds()
}

// SpeedWindow aggregates rate samples.
type SpeedWindow struct {
	n              int
	sumRx, sumTx   float64
	PeakRx, PeakTx float64
}

// Add records one sample.
func (w *SpeedWindow) Add(rx, tx float64) {
	w.n++
	w.sumRx += rx
	w.sumTx += tx
	w.PeakRx, w.PeakTx = max(w.PeakRx, rx), max(w.PeakTx, tx)
}

// AvgRx is the mean download rate.
func (w *SpeedWindow) AvgRx() float64 {
	if w.n == 0 {
		return 0
	}
	return w.sumRx / float64(w.n)
}

// AvgTx is the mean upload rate.
func (w *SpeedWindow) AvgTx() float64 {
	if w.n == 0 {
		return 0
	}
	return w.sumTx / float64(w.n)
}

// HumanRate formats bytes/s as "1.2 MB/s".
func HumanRate(bps float64) string {
	switch {
	case bps >= 1<<20:
		return fmt.Sprintf("%.1f MB/s", bps/(1<<20))
	case bps >= 1<<10:
		return fmt.Sprintf("%.0f KB/s", bps/(1<<10))
	default:
		return fmt.Sprintf("%.0f B/s", bps)
	}
}
