// Package route installs the client-side full-tunnel routing, DNS override
// and kill-switch (§7), with Linux/macOS/Windows implementations behind one
// interface. Every change is journaled in an undo.Journal before (or, for
// additive changes, immediately after) it is applied, so teardown — and
// crash recovery — restore the machine exactly.
package route

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"backhaul/internal/undo"
)

// Plan describes what connect mode wants installed.
type Plan struct {
	Iface        string       // tunnel interface (real OS name)
	Endpoints    []netip.Addr // exit/relay IPs that must stay on the physical NIC
	EndpointPort int          // TCP port of the transport (443)
	DNS          []netip.Addr // resolvers reached through the tunnel
	DNSMethod    string       // linux: "auto" | "resolved" | "resolv.conf"
	IPv6         bool         // tunnel ::/0 (else IPv6 is disabled for the session)
	KillSwitch   bool
}

// Manager applies a Plan. Teardown is journal.Unwind.
type Manager interface {
	Apply(ctx context.Context, p Plan, j *undo.Journal) error
}

// New returns the Manager for this OS.
func New() Manager { return newManager() }

// Split routes that beat the existing default route without deleting it.
var (
	SplitV4 = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	SplitV6 = []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")}
)

// HostPrefix returns a /32 or /128 for a.
func HostPrefix(a netip.Addr) netip.Prefix {
	return netip.PrefixFrom(a, a.BitLen())
}

// splitFamilies separates v4 and v6 addresses (ignoring loopback, which never
// needs a host route).
func splitFamilies(addrs []netip.Addr) (v4, v6 []netip.Addr) {
	for _, a := range addrs {
		a = a.Unmap()
		switch {
		case a.IsLoopback():
		case a.Is4():
			v4 = append(v4, a)
		default:
			v6 = append(v6, a)
		}
	}
	return
}

// Complement returns inclusive "lo-hi" ranges covering the whole address
// family except the given addresses. Used for Windows Firewall block rules,
// which cannot express "everything but X" any other way.
func Complement(v6 bool, except []netip.Addr) []string {
	lo := netip.IPv4Unspecified()
	hi := netip.AddrFrom4([4]byte{255, 255, 255, 255})
	if v6 {
		lo = netip.IPv6Unspecified()
		hi = netip.AddrFrom16([16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	}
	var ex []netip.Addr
	for _, a := range except {
		a = a.Unmap()
		if a.Is6() == v6 {
			ex = append(ex, a)
		}
	}
	sort.Slice(ex, func(i, j int) bool { return ex[i].Less(ex[j]) })
	var out []string
	cur := lo
	for _, e := range ex {
		if e.Less(cur) {
			continue
		}
		if cur.Less(e) {
			out = append(out, cur.String()+"-"+e.Prev().String())
		}
		if e == hi {
			return out
		}
		cur = e.Next()
	}
	out = append(out, cur.String()+"-"+hi.String())
	return out
}

// NftKillSwitch renders the Linux nftables kill-switch table.
func NftKillSwitch(table string, p Plan) string {
	v4, v6 := splitFamilies(p.Endpoints)
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n  chain output {\n", table)
	b.WriteString("    type filter hook output priority 0; policy drop;\n")
	b.WriteString("    oifname \"lo\" accept\n")
	fmt.Fprintf(&b, "    oifname %q accept\n", p.Iface)
	if len(v4) > 0 {
		fmt.Fprintf(&b, "    ip daddr { %s } tcp dport %d accept\n", joinAddrs(v4), p.EndpointPort)
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "    ip6 daddr { %s } tcp dport %d accept\n", joinAddrs(v6), p.EndpointPort)
	}
	// Keep the physical link alive (DHCP lease renewal, IPv6 neighbour discovery).
	b.WriteString("    udp sport 68 udp dport 67 accept\n")
	b.WriteString("    udp sport 546 udp dport 547 accept\n")
	b.WriteString("    icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept\n")
	b.WriteString("  }\n}\n")
	return b.String()
}

// PfKillSwitch renders the macOS pf anchor rules for the kill-switch.
func PfKillSwitch(p Plan) string {
	v4, v6 := splitFamilies(p.Endpoints)
	var b strings.Builder
	b.WriteString("pass out quick on lo0 all\n")
	fmt.Fprintf(&b, "pass out quick on %s all\n", p.Iface)
	for _, a := range v4 {
		fmt.Fprintf(&b, "pass out quick inet proto tcp from any to %s port %d\n", a, p.EndpointPort)
	}
	for _, a := range v6 {
		fmt.Fprintf(&b, "pass out quick inet6 proto tcp from any to %s port %d\n", a, p.EndpointPort)
	}
	b.WriteString("pass out quick inet proto udp from any port 68 to any port 67\n")
	b.WriteString("pass out quick inet6 proto udp from any port 546 to any port 547\n")
	b.WriteString("pass out quick inet6 proto icmp6 all icmp6-type { routersol, neighbrsol, neighbradv }\n")
	b.WriteString("block drop out quick all\n")
	return b.String()
}

func joinAddrs(as []netip.Addr) string {
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}

// psArgv wraps a PowerShell script as an undo-journal argv.
func psArgv(script string) []string {
	return []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script}
}

// psQuote single-quotes a string for PowerShell.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
