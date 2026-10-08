package health

import (
	"context"
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
