//go:build linux

package nat

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"backhaul/internal/osutil"
	"backhaul/internal/undo"
)

const nftTable = "backhaul_nat"

// DefaultWAN returns the interface of the IPv4 default route.
func DefaultWAN(ctx context.Context) (string, error) {
	out, err := osutil.Run(ctx, "ip", "-4", "route", "show", "default")
	if err != nil {
		return "", err
	}
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1], nil
		}
	}
	return "", errors.New("no IPv4 default route")
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
	if err := setSysctl(ctx, "net.ipv4.ip_forward", "1", j); err != nil {
		return fmt.Errorf("enable IPv4 forwarding: %w", err)
	}
	if p.Subnet6.IsValid() {
		if err := setSysctl(ctx, "net.ipv6.conf.all.forwarding", "1", j); err != nil {
			return fmt.Errorf("enable IPv6 forwarding: %w", err)
		}
	}
	backend := p.Backend
	if backend == "" {
		backend = "iptables"
		if osutil.Has("nft") {
			backend = "nftables"
		}
	}
	if backend == "nftables" {
		_, _ = osutil.Run(ctx, "nft", "delete", "table", "inet", nftTable)
		_ = j.Push(undo.Exec("remove NAT table", "nft", "delete", "table", "inet", nftTable))
		if _, err := osutil.RunStdin(ctx, NftRules(nftTable, p), "nft", "-f", "-"); err != nil {
			return err
		}
	} else if err := iptablesNAT(ctx, p, j); err != nil {
		return err
	}
	// A FORWARD policy of DROP set by iptables (Docker, ufw) would still
	// drop our packets even with the nft accept, so open the path there too.
	// Only when such a policy exists: touching iptables otherwise creates
	// tables that outlive our rules, and teardown would not be exact.
	if osutil.Has("iptables") && forwardPolicyDrop(ctx) {
		for _, r := range [][]string{
			{"FORWARD", "-i", p.Iface, "-j", "ACCEPT"},
			{"FORWARD", "-o", p.Iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		} {
			if _, err := osutil.Run(ctx, "iptables", append([]string{"-I"}, r...)...); err == nil {
				_ = j.Push(undo.Exec("remove forward rule", append([]string{"iptables", "-D"}, r...)...))
			}
		}
	}
	return nil
}

// forwardPolicyDrop reports whether an iptables FORWARD chain drops by default.
func forwardPolicyDrop(ctx context.Context) bool {
	if osutil.Has("nft") {
		out, err := osutil.Run(ctx, "nft", "list", "chain", "ip", "filter", "FORWARD")
		return err == nil && strings.Contains(out, "policy drop")
	}
	out, err := osutil.Run(ctx, "iptables", "-S", "FORWARD")
	return err == nil && strings.Contains(out, "-P FORWARD DROP")
}

func iptablesNAT(ctx context.Context, p Plan, j *undo.Journal) error {
	type rule struct {
		bin  string
		args []string
	}
	rules := []rule{{"iptables", []string{"-t", "nat", "POSTROUTING", "-s", p.Subnet4.Masked().String(), "-o", p.WAN, "-j", "MASQUERADE"}}}
	if p.Subnet6.IsValid() && osutil.Has("ip6tables") {
		rules = append(rules, rule{"ip6tables", []string{"-t", "nat", "POSTROUTING", "-s", p.Subnet6.Masked().String(), "-o", p.WAN, "-j", "MASQUERADE"}})
	}
	for _, r := range rules {
		// -t nat must precede the command verb.
		add := append([]string{r.args[0], r.args[1], "-A"}, r.args[2:]...)
		del := append([]string{r.bin, r.args[0], r.args[1], "-D"}, r.args[2:]...)
		if _, err := osutil.Run(ctx, r.bin, add...); err != nil {
			return err
		}
		_ = j.Push(undo.Exec("remove masquerade", del...))
	}
	return nil
}
