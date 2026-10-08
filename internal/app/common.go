// Package app orchestrates serve and connect: pre-flight, bring-up order,
// supervision, and — above all — exact teardown (§13).
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"time"

	"backhaul/internal/config"
	"backhaul/internal/doctor"
	"backhaul/internal/osutil"
	"backhaul/internal/state"
	"backhaul/internal/undo"
	"backhaul/internal/wg"
)

// TeardownTimeout bounds the restore pass so a hung command can't block exit.
const TeardownTimeout = 60 * time.Second

// StopPollInterval is how often serve/connect check for `backhaul disconnect`.
const StopPollInterval = time.Second

// Disconnect asks a running serve/connect to tear down and waits until it
// has restored the system (its runtime state disappears) or wait elapses.
func Disconnect(ctx context.Context, p config.Paths, wait time.Duration) error {
	if err := osutil.RequirePrivileges(); err != nil {
		return err
	}
	rt, ok, err := state.Read(p.State())
	if err != nil {
		return err
	}
	if !ok || !osutil.ProcessAlive(rt.PID) {
		state.Remove(p.State())
		return errors.New("backhaul is not running")
	}
	if err := state.RequestStop(p.State()); err != nil {
		return err
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if _, ok, _ := state.Read(p.State()); !ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(StopPollInterval / 2):
		}
	}
	return fmt.Errorf("backhaul (pid %d) did not stop within %s", rt.PID, wait)
}

// Env bundles what serve/connect need.
type Env struct {
	Cfg     *config.Config
	Sec     *config.Secrets
	Paths   config.Paths
	Verbose bool
}

// Recover replays an undo journal left by a crashed run. Safe to call anytime.
func Recover(ctx context.Context, p config.Paths) (int, error) {
	return undo.Recover(ctx, state.JournalFile(p.State()))
}

// preflight checks privileges, recovers from a previous crash, and runs the
// doctor pre-flight subset; any FAIL aborts before the system is touched.
func (e *Env) preflight(ctx context.Context) error {
	if err := osutil.RequirePrivileges(); err != nil {
		return err
	}
	if rt, ok, _ := state.Read(e.Paths.State()); ok && rt.Fresh(3*e.Cfg.Health.Interval.Duration) && osutil.ProcessAlive(rt.PID) {
		return fmt.Errorf("backhaul %s already running (pid %d); stop it first", rt.Mode, rt.PID)
	}
	if n, err := Recover(ctx, e.Paths); err != nil {
		slog.Warn("recovery pass had errors (continuing)", "err", err)
	} else if n > 0 {
		slog.Info("restored system state from previous unclean exit", "steps", n)
	}
	d := &doctor.Doctor{Cfg: e.Cfg, Paths: e.Paths}
	rs := d.Preflight(ctx)
	if doctor.Failed(rs) {
		doctor.Print(os.Stderr, rs)
		return errors.New("pre-flight checks failed (see above)")
	}
	return nil
}

// cleanup is a LIFO stack of in-process teardown steps (closing the TUN,
// stopping wstunnel, …) that run after the system-change journal is unwound.
type cleanup []func(context.Context)

func (c *cleanup) push(f func(context.Context)) { *c = append(*c, f) }

// teardown unwinds the journal (routes, DNS, firewall, NAT) and then the
// in-process cleanup stack, with a fresh context because the run context is
// already cancelled when we get here.
func teardown(j *undo.Journal, c cleanup) {
	ctx, cancel := context.WithTimeout(context.Background(), TeardownTimeout)
	defer cancel()
	slog.Info("restoring original network configuration")
	err := j.Unwind(ctx)
	for i := len(c) - 1; i >= 0; i-- {
		c[i](ctx)
	}
	if err != nil {
		slog.Warn("some restore steps failed; run `backhaul doctor --recover` or inspect manually", "err", err)
	} else {
		slog.Info("system restored")
	}
}

// resolveEndpoint picks one IP for host (IPv4 preferred) so the host route,
// kill-switch exception and the pinned dialer all agree on the address.
func resolveEndpoint(ctx context.Context, host string, timeout time.Duration) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a, nil
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			return ip.Unmap(), nil
		}
	}
	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve %s: no addresses", host)
	}
	return ips[0], nil
}

func wgAddresses(c *config.Config, withV6 bool) ([]netip.Prefix, error) {
	a4, err := c.IfaceAddr4()
	if err != nil {
		return nil, err
	}
	out := []netip.Prefix{a4}
	if withV6 {
		a6, ok, err := c.IfaceAddr6()
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, a6)
		}
	}
	return out, nil
}

func ensureEngineDeps(ctx context.Context, c *config.Config) error {
	if c.WireGuard.Engine == config.EngineEmbedded {
		return wg.EnsureWintun(ctx)
	}
	return nil
}
