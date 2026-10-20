//go:build linux

package nat

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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
	// A DROP policy set by iptables (Docker, ufw) would still drop our packets
	// even with the nft accepts, so open the path there too: forwarding, and
	// input from the tunnel (the DNS forwarder listens on the tunnel IP).
	fwd := [][]string{
		{"-i", p.Iface, "-j", "ACCEPT"},
		{"-o", p.Iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
	in := [][]string{{"-i", p.Iface, "-j", "ACCEPT"}}
	insertAccept(ctx, "iptables", "FORWARD", fwd, j)
	insertAccept(ctx, "iptables", "INPUT", in, j)
	if p.Subnet6.IsValid() {
		insertAccept(ctx, "ip6tables", "FORWARD", fwd, j)
		insertAccept(ctx, "ip6tables", "INPUT", in, j)
	}
	return nil
}

// insertAccept puts rules at the top of an iptables chain, journaling their
// removal, but only if the chain drops by default: touching iptables
// otherwise creates tables that outlive our rules, and teardown would not be
// exact.
func insertAccept(ctx context.Context, bin, chain string, rules [][]string, j *undo.Journal) {
	if !osutil.Has(bin) || !chainPolicyDrop(ctx, bin, chain) {
		return
	}
	for _, r := range rules {
		args := append([]string{chain}, r...)
		if _, err := osutil.Run(ctx, bin, append([]string{"-I"}, args...)...); err == nil {
			_ = j.Push(undo.Exec("remove "+strings.ToLower(chain)+" rule", append([]string{bin, "-D"}, args...)...))
		}
	}
}

// chainPolicyDrop reports whether an iptables (bin "iptables") or ip6tables
// chain drops by default, e.g. ufw's INPUT.
func chainPolicyDrop(ctx context.Context, bin, chain string) bool {
	if osutil.Has("nft") {
		family := "ip"
		if bin == "ip6tables" {
			family = "ip6"
		}
		out, err := osutil.Run(ctx, "nft", "list", "chain", family, "filter", chain)
		return err == nil && strings.Contains(out, "policy drop")
	}
	out, err := osutil.Run(ctx, bin, "-S", chain)
	return err == nil && strings.Contains(out, "-P "+chain+" DROP")
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

// Available: kernel NAT is always present on Linux.
func Available(context.Context) bool { return true }

// AllowInbound opens TCP port for the exit node's listener when an iptables
// INPUT policy drops by default (ufw). Firewalls kept purely in nftables
// (e.g. firewalld's nftables backend) are not handled.
func AllowInbound(ctx context.Context, port int, j *undo.Journal) error {
	r := [][]string{{"-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"}}
	insertAccept(ctx, "iptables", "INPUT", r, j)
	insertAccept(ctx, "ip6tables", "INPUT", r, j)
	return nil
}
