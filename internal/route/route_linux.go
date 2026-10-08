//go:build linux

package route

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"backhaul/internal/osutil"
	"backhaul/internal/undo"
)

const nftTable = "backhaul_ks"

type linuxManager struct{}

func newManager() Manager { return linuxManager{} }

// ConfigureInterface assigns addresses and MTU and sets the link up.
func ConfigureInterface(ctx context.Context, iface string, addrs []netip.Prefix, mtu int) error {
	if _, err := osutil.Run(ctx, "ip", "link", "set", "dev", iface, "mtu", strconv.Itoa(mtu)); err != nil {
		return err
	}
	for _, a := range addrs {
		fam := "-4"
		if a.Addr().Is6() {
			fam = "-6"
		}
		if _, err := osutil.Run(ctx, "ip", fam, "addr", "replace", a.String(), "dev", iface); err != nil {
			return err
		}
	}
	_, err := osutil.Run(ctx, "ip", "link", "set", "dev", iface, "up")
	return err
}

// gatewayFor asks the kernel how it currently reaches dst: "via GW dev DEV".
func gatewayFor(ctx context.Context, dst netip.Addr) (via, dev string, err error) {
	fam := "-4"
	if dst.Is6() {
		fam = "-6"
	}
	out, err := osutil.Run(ctx, "ip", fam, "route", "get", dst.String())
	if err != nil {
		return "", "", err
	}
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "via":
			via = f[i+1]
		case "dev":
			dev = f[i+1]
		}
	}
	if dev == "" {
		return "", "", fmt.Errorf("cannot determine route to %s from %q", dst, out)
	}
	return via, dev, nil
}

func (linuxManager) Apply(ctx context.Context, p Plan, j *undo.Journal) error {
	// 1. Pin the exit endpoint to the physical path (avoids the routing loop).
	//    Must happen before the split routes, or `ip route get` returns the tunnel.
	for _, ep := range p.Endpoints {
		ep = ep.Unmap()
		if ep.IsLoopback() {
			continue
		}
		via, dev, err := gatewayFor(ctx, ep)
		if err != nil {
			return fmt.Errorf("find physical route to endpoint: %w", err)
		}
		fam := "-4"
		if ep.Is6() {
			fam = "-6"
		}
		args := []string{fam, "route", "add", HostPrefix(ep).String()}
		if via != "" {
			args = append(args, "via", via)
		}
		args = append(args, "dev", dev)
		if _, err := osutil.Run(ctx, "ip", args...); err != nil {
			if !strings.Contains(err.Error(), "File exists") {
				return err
			}
			slog.Debug("endpoint host route already exists", "dst", ep)
			continue
		}
		del := append([]string{"ip"}, args...)
		del[3] = "del"
		_ = j.Push(undo.Exec("remove endpoint host route", del...))
	}

	// 2. Split default routes via the tunnel.
	for _, pf := range SplitV4 {
		if _, err := osutil.Run(ctx, "ip", "-4", "route", "add", pf.String(), "dev", p.Iface); err != nil {
			return err
		}
		_ = j.Push(undo.Exec("remove split route", "ip", "-4", "route", "del", pf.String(), "dev", p.Iface))
	}
	if p.IPv6 {
		if err := addV6Routes(ctx, p.Iface, j); err != nil {
			slog.Warn("IPv6 tunneling failed; disabling IPv6 for this session to prevent leaks", "err", err)
			p.IPv6 = false
		}
	}
	if !p.IPv6 {
		if err := disableIPv6(ctx, j); err != nil {
			return fmt.Errorf("disable IPv6: %w", err)
		}
	}

	// 3. DNS.
	if len(p.DNS) > 0 {
		if err := setDNS(ctx, p, j); err != nil {
			return fmt.Errorf("set DNS: %w", err)
		}
	}

	// 4. Kill-switch.
	if p.KillSwitch {
		if err := killSwitch(ctx, p, j); err != nil {
			return fmt.Errorf("kill-switch: %w", err)
		}
	}
	return nil
}

func addV6Routes(ctx context.Context, iface string, j *undo.Journal) error {
	for _, pf := range SplitV6 {
		if _, err := osutil.Run(ctx, "ip", "-6", "route", "add", pf.String(), "dev", iface); err != nil {
			return err
		}
		_ = j.Push(undo.Exec("remove split route v6", "ip", "-6", "route", "del", pf.String(), "dev", iface))
	}
	return nil
}

func disableIPv6(ctx context.Context, j *undo.Journal) error {
	const key = "net.ipv6.conf.all.disable_ipv6"
	old, err := osutil.Run(ctx, "sysctl", "-n", key)
	if err != nil {
		return err
	}
	_ = j.Push(undo.Exec("restore IPv6 setting", "sysctl", "-w", key+"="+strings.TrimSpace(old)))
	_, err = osutil.Run(ctx, "sysctl", "-w", key+"=1")
	return err
}

func setDNS(ctx context.Context, p Plan, j *undo.Journal) error {
	useResolved := p.DNSMethod == "resolved"
	if p.DNSMethod == "" || p.DNSMethod == "auto" {
		if osutil.Has("resolvectl") {
			_, err := osutil.Run(ctx, "resolvectl", "status")
			useResolved = err == nil
		}
	}
	if useResolved {
		_ = j.Push(undo.Exec("revert resolved link DNS", "resolvectl", "revert", p.Iface))
		args := []string{"dns", p.Iface}
		for _, d := range p.DNS {
			args = append(args, d.String())
		}
		if _, err := osutil.Run(ctx, "resolvectl", args...); err != nil {
			return err
		}
		// "~." makes this link the route for every domain.
		// TODO(spec): other links with DefaultRoute=yes may still be
		// consulted by systemd-resolved; the kill-switch blocks those queries.
		if _, err := osutil.Run(ctx, "resolvectl", "domain", p.Iface, "~."); err != nil {
			return err
		}
		_, _ = osutil.Run(ctx, "resolvectl", "default-route", p.Iface, "yes")
		_, _ = osutil.Run(ctx, "resolvectl", "flush-caches")
		return nil
	}
	// Fallback: rewrite /etc/resolv.conf, keeping a backup for restore.
	const rc = "/etc/resolv.conf"
	orig, err := os.ReadFile(rc)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	backup := filepath.Join(filepath.Dir(j.Path()), "resolv.conf.backup")
	if err := os.WriteFile(backup, orig, 0o600); err != nil {
		return err
	}
	_ = j.Push(undo.Action{Desc: "restore /etc/resolv.conf", Kind: undo.KindRestoreFile, Path: rc, Backup: backup})
	var b strings.Builder
	b.WriteString("# Written by backhaul for the duration of the tunnel; restored on disconnect.\n")
	for _, d := range p.DNS {
		fmt.Fprintf(&b, "nameserver %s\n", d)
	}
	return os.WriteFile(rc, []byte(b.String()), 0o644)
}

func killSwitch(ctx context.Context, p Plan, j *undo.Journal) error {
	if osutil.Has("nft") {
		_, _ = osutil.Run(ctx, "nft", "delete", "table", "inet", nftTable) // stale leftover
		_ = j.Push(undo.Exec("remove kill-switch", "nft", "delete", "table", "inet", nftTable))
		_, err := osutil.RunStdin(ctx, NftKillSwitch(nftTable, p), "nft", "-f", "-")
		return err
	}
	if !osutil.Has("iptables") {
		return errors.New("neither nft nor iptables found; install nftables or run with --no-killswitch")
	}
	return iptablesKillSwitch(ctx, p, j)
}

// iptablesKillSwitch is the legacy fallback: a BACKHAUL_KS chain jumped to
// from OUTPUT, for both iptables and ip6tables.
func iptablesKillSwitch(ctx context.Context, p Plan, j *undo.Journal) error {
	v4, v6 := splitFamilies(p.Endpoints)
	port := strconv.Itoa(p.EndpointPort)
	for _, t := range []struct {
		bin string
		eps []netip.Addr
	}{{"iptables", v4}, {"ip6tables", v6}} {
		if !osutil.Has(t.bin) {
			continue
		}
		const ch = "BACKHAUL_KS"
		_ = j.Push(undo.Exec("delete kill-switch chain", t.bin, "-X", ch))
		_ = j.Push(undo.Exec("flush kill-switch chain", t.bin, "-F", ch))
		_ = j.Push(undo.Exec("unhook kill-switch", t.bin, "-D", "OUTPUT", "-j", ch))
		rules := [][]string{
			{"-N", ch},
			{"-A", ch, "-o", "lo", "-j", "ACCEPT"},
			{"-A", ch, "-o", p.Iface, "-j", "ACCEPT"},
		}
		for _, ep := range t.eps {
			rules = append(rules, []string{"-A", ch, "-d", ep.String(), "-p", "tcp", "--dport", port, "-j", "ACCEPT"})
		}
		if t.bin == "iptables" {
			rules = append(rules, []string{"-A", ch, "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"})
		} else {
			rules = append(rules,
				[]string{"-A", ch, "-p", "udp", "--sport", "546", "--dport", "547", "-j", "ACCEPT"},
				[]string{"-A", ch, "-p", "ipv6-icmp", "-j", "ACCEPT"})
		}
		rules = append(rules, []string{"-A", ch, "-j", "DROP"}, []string{"-I", "OUTPUT", "1", "-j", ch})
		for _, r := range rules {
			if _, err := osutil.Run(ctx, t.bin, r...); err != nil {
				return err
			}
		}
	}
	return nil
}
