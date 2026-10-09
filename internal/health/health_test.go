package health

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"backhaul/internal/transport"
	"backhaul/internal/wg"
)

type fakeEngine struct {
	mu    sync.Mutex
	hs    time.Time
	kicks int
}

func (f *fakeEngine) Up(context.Context, wg.Settings) error { return nil }
func (f *fakeEngine) Name() string                          { return "wg0" }
func (f *fakeEngine) Down(context.Context) error            { return nil }
func (f *fakeEngine) Stats() (wg.Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return wg.Stats{LastHandshake: f.hs}, nil
}
func (f *fakeEngine) Kick() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kicks++
	return nil
}

type fakeTransport struct {
	mu       sync.Mutex
	restarts int
}

func (f *fakeTransport) Kind() string                { return "fake" }
func (f *fakeTransport) Start(context.Context) error { return nil }
func (f *fakeTransport) Stop() error                 { return nil }
func (f *fakeTransport) Status() transport.Status    { return transport.Status{Kind: "fake"} }
func (f *fakeTransport) Restart()                    { f.mu.Lock(); f.restarts++; f.mu.Unlock() }
func (f *fakeTransport) count() int                  { f.mu.Lock(); defer f.mu.Unlock(); return f.restarts }

func TestHealthy(t *testing.T) {
	now := time.Now()
	if Healthy(wg.Stats{}, time.Minute, now) {
		t.Fatal("never-handshaked tunnel is not healthy")
	}
	if !Healthy(wg.Stats{LastHandshake: now.Add(-30 * time.Second)}, time.Minute, now) {
		t.Fatal("recent handshake should be healthy")
	}
	if Healthy(wg.Stats{LastHandshake: now.Add(-2 * time.Minute)}, time.Minute, now) {
		t.Fatal("stale handshake should be unhealthy")
	}
}

func TestMonitorReconnectsDeadTunnelWithBackoff(t *testing.T) {
	eng, tr := &fakeEngine{}, &fakeTransport{}
	m := &Monitor{
		Opts: Options{Interval: 10 * time.Millisecond, HandshakeTimeout: time.Second, StartupGrace: 0,
			BackoffMin: 50 * time.Millisecond, BackoffMax: 100 * time.Millisecond, Reconnect: true},
		Engine: eng, Transport: tr,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	m.Run(ctx)
	n := tr.count()
	// ~400ms with 50→100ms backoff: a handful of attempts, not one per 10ms tick.
	if n < 2 || n > 8 {
		t.Fatalf("restarts=%d; want backoff-limited reconnects", n)
	}
	if eng.kicks != n {
		t.Fatalf("kicks=%d restarts=%d", eng.kicks, n)
	}
}

func TestMonitorLeavesHealthyTunnelAlone(t *testing.T) {
	eng, tr := &fakeEngine{hs: time.Now()}, &fakeTransport{}
	m := &Monitor{Opts: Options{Interval: 10 * time.Millisecond, HandshakeTimeout: time.Minute,
		BackoffMin: time.Millisecond, BackoffMax: time.Millisecond, Reconnect: true}, Engine: eng, Transport: tr}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	m.Run(ctx)
	if tr.count() != 0 {
		t.Fatal("healthy tunnel was restarted")
	}
}

// countingEngine counts health ticks (one Stats call per tick).
type countingEngine struct {
	fakeEngine
	ticks int
}

func (c *countingEngine) Stats() (wg.Stats, error) { c.ticks++; return c.fakeEngine.Stats() }

func TestCheckCadence(t *testing.T) {
	run := func(hs time.Time) (calls, ticks int) {
		eng := &countingEngine{fakeEngine: fakeEngine{hs: hs}}
		m := &Monitor{Opts: Options{Interval: 5 * time.Millisecond, HandshakeTimeout: time.Minute,
			BackoffMin: time.Hour, BackoffMax: time.Hour, StartupGrace: time.Hour,
			Check: func(context.Context) { calls++ }, CheckEvery: 5}, Engine: eng, Transport: &fakeTransport{}}
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		m.Run(ctx)
		return calls, eng.ticks
	}
	if calls, ticks := run(time.Time{}); calls != ticks {
		t.Fatalf("unhealthy: check must run on every tick (%d calls, %d ticks)", calls, ticks)
	}
	calls, ticks := run(time.Now())
	if want := (ticks + 4) / 5; calls != want {
		t.Fatalf("healthy: check must run every 5th tick (%d calls, %d ticks, want %d)", calls, ticks, want)
	}
}

func TestLinkDownOverridesFreshHandshake(t *testing.T) {
	eng, tr := &fakeEngine{hs: time.Now()}, &fakeTransport{}
	m := &Monitor{Opts: Options{Interval: 10 * time.Millisecond, HandshakeTimeout: time.Minute,
		BackoffMin: 20 * time.Millisecond, BackoffMax: 50 * time.Millisecond, Reconnect: true,
		LinkDown: func() bool { return true }}, Engine: eng, Transport: tr}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	m.Run(ctx)
	if tr.count() == 0 {
		t.Fatal("a down link must trigger reconnects even with a recent handshake")
	}
}

// A tunnel that still has a fresh handshake but stops answering the
// end-to-end probe (the "shows Connected but nothing works" case) must be
// detected, reconnected, and its recovery reported — each exactly once.
func TestProbeDetectsSilentOutageAndRecovery(t *testing.T) {
	eng, tr := &fakeEngine{hs: time.Now()}, &fakeTransport{}
	var mu sync.Mutex
	tick, downs, ups := 0, 0, 0
	var outage time.Duration
	m := &Monitor{Opts: Options{Interval: 10 * time.Millisecond, HandshakeTimeout: time.Minute,
		BackoffMin: 5 * time.Millisecond, BackoffMax: 10 * time.Millisecond, Reconnect: true,
		Probe: func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			tick++
			if tick > 3 && tick <= 10 { // working, then silent for 7 ticks, then back
				return errors.New("dns timeout")
			}
			return nil
		},
		OnDown: func(context.Context, wg.Stats) { mu.Lock(); downs++; mu.Unlock() },
		OnUp:   func(d time.Duration) { mu.Lock(); ups++; outage = d; mu.Unlock() },
	}, Engine: eng, Transport: tr}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	m.Run(ctx)
	mu.Lock()
	defer mu.Unlock()
	if downs != 1 || ups != 1 {
		t.Fatalf("downs=%d ups=%d, want 1 and 1", downs, ups)
	}
	if outage <= 0 {
		t.Fatal("outage length not reported")
	}
	if tr.count() == 0 {
		t.Fatal("silent outage must trigger reconnects")
	}
}

func TestRatesAndFormatting(t *testing.T) {
	if r := Rate(1000, 3048, 2*time.Second); r != 1024 {
		t.Fatalf("rate %v", r)
	}
	if Rate(5000, 10, time.Second) != 0 {
		t.Fatal("counter reset must give 0, not a negative rate")
	}
	var w SpeedWindow
	w.Add(100, 10)
	w.Add(300, 30)
	if w.AvgRx() != 200 || w.PeakRx != 300 || w.AvgTx() != 20 {
		t.Fatalf("%+v", w)
	}
	for bps, want := range map[float64]string{512: "512 B/s", 2048: "2 KB/s", 1.5 * (1 << 20): "1.5 MB/s"} {
		if got := HumanRate(bps); got != want {
			t.Errorf("%v → %q want %q", bps, got, want)
		}
	}
}
