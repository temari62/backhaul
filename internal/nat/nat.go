// Package nat enables IP forwarding and masquerading on the exit node so
// tunnel traffic leaves with the exit node's public IP. All changes are
// journaled for exact restore.
package nat

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"backhaul/internal/undo"
)

// Plan describes the NAT to install.
type Plan struct {
	Iface   string       // tunnel interface
	Subnet4 netip.Prefix // tunnel IPv4 subnet
	Subnet6 netip.Prefix // tunnel IPv6 subnet (zero = none)
	WAN     string       // egress interface ("" = auto-detect default route)
	Backend string       // linux: "nftables" | "iptables" | "" (auto)
}

// Enable turns on forwarding + NAT.
func Enable(ctx context.Context, p Plan, j *undo.Journal) error {
	if p.WAN == "" {
		wan, err := DefaultWAN(ctx)
		if err != nil {
			return fmt.Errorf("detect internet interface (set serve.wan_interface): %w", err)
		}
		p.WAN = wan
	}
	return enable(ctx, p, j)
}

// NftRules renders the Linux nftables NAT/forward table.
func NftRules(table string, p Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", table)
	b.WriteString("  chain postrouting {\n    type nat hook postrouting priority 100; policy accept;\n")
	fmt.Fprintf(&b, "    ip saddr %s oifname %q masquerade\n", p.Subnet4.Masked(), p.WAN)
	if p.Subnet6.IsValid() {
		fmt.Fprintf(&b, "    ip6 saddr %s oifname %q masquerade\n", p.Subnet6.Masked(), p.WAN)
	}
	b.WriteString("  }\n")
	b.WriteString("  chain forward {\n    type filter hook forward priority 0; policy accept;\n")
	// Clamp TCP MSS to the path MTU: the tunnel MTU is smaller than Ethernet.
	fmt.Fprintf(&b, "    iifname %q tcp flags syn tcp option maxseg size set rt mtu\n", p.Iface)
	fmt.Fprintf(&b, "    oifname %q tcp flags syn tcp option maxseg size set rt mtu\n", p.Iface)
	fmt.Fprintf(&b, "    iifname %q accept\n", p.Iface)
	fmt.Fprintf(&b, "    oifname %q ct state established,related accept\n", p.Iface)
	b.WriteString("  }\n}\n")
	return b.String()
}

// PfRules renders the macOS pf NAT anchor.
func PfRules(p Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "nat on %s inet from %s to any -> (%s)\n", p.WAN, p.Subnet4.Masked(), p.WAN)
	if p.Subnet6.IsValid() {
		fmt.Fprintf(&b, "nat on %s inet6 from %s to any -> (%s)\n", p.WAN, p.Subnet6.Masked(), p.WAN)
	}
	return b.String()
}
