//go:build darwin

package nat

import (
	"context"
	"errors"
	"strings"

	"backhaul/internal/osutil"
	"backhaul/internal/undo"
)

// The stock /etc/pf.conf includes `nat-anchor "com.apple/*"`.
const pfAnchor = "com.apple/250.backhaul-nat"

// DefaultWAN returns the interface of the default route.
func DefaultWAN(ctx context.Context) (string, error) {
	out, err := osutil.Run(ctx, "route", "-n", "get", "default")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && k == "interface" {
			return strings.TrimSpace(v), nil
		}
	}
	return "", errors.New("no default route")
}

func setSysctl(ctx context.Context, key, val string, j *undo.Journal) error {
	old, err := osutil.Run(ctx, "sysctl", "-n", key)
	if err != nil {
		return err
	}
	if strings.TrimSpace(old) == val {
		return nil
	}
	_ = j.Push(undo.Exec("restore "+key, "sysctl", "-w", key+"="+strings.TrimSpace(old)))
	_, err = osutil.Run(ctx, "sysctl", "-w", key+"="+val)
	return err
}

func enable(ctx context.Context, p Plan, j *undo.Journal) error {
	if err := setSysctl(ctx, "net.inet.ip.forwarding", "1", j); err != nil {
		return err
	}
	if p.Subnet6.IsValid() {
		if err := setSysctl(ctx, "net.inet6.ip6.forwarding", "1", j); err != nil {
			return err
		}
	}
	_ = j.Push(undo.Exec("flush NAT anchor", "pfctl", "-a", pfAnchor, "-F", "all"))
	if _, err := osutil.RunStdin(ctx, PfRules(p), "pfctl", "-a", pfAnchor, "-f", "-"); err != nil {
		return err
	}
	out, err := osutil.Run(ctx, "pfctl", "-E")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(out, "\n") {
		if _, tok, ok := strings.Cut(line, "Token :"); ok {
			_ = j.Push(undo.Exec("release pf reference", "pfctl", "-X", strings.TrimSpace(tok)))
		}
	}
	return nil
}

// Available: pf NAT is always present on macOS.
func Available(context.Context) bool { return true }

// AllowInbound is a no-op on macOS: the application firewall (if enabled)
// prompts the user to allow wstunnel the first time it listens.
func AllowInbound(context.Context, int, *undo.Journal) error { return nil }
