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
	"regexp"
	"sort"
	"strings"

	"backhaul/internal/undo"
)

// Plan describes what connect mode wants installed.
type Plan struct {
	Iface        string       // tunnel interface (real OS name)
	Endpoints    []netip.Addr // exit/relay IPs that must stay on the physical NIC
	TunnelAddrs  []netip.Addr // this side's tunnel IPs (Windows kill-switch matches on source address)
	EndpointPort int          // TCP port of the transport (443)
	DNS          []netip.Addr // resolvers reached through the tunnel
	DNSMethod    string       // linux: "auto" | "resolved" | "resolv.conf"
	IPv6         bool         // tunnel ::/0 (else IPv6 is disabled for the session)
	KillSwitch   bool
}

// Manager applies a Plan. Teardown is journal.Unwind.
type Manager interface {
	Apply(ctx context.Context, p Plan, j *undo.Journal) error
	// RepairEndpoint re-pins the route to the exit node through the real
	// network if it now goes through our own tunnel (another VPN reset its
	// adapter, Wi-Fi changed, ...). It reports whether it changed anything.
	RepairEndpoint(ctx context.Context, p Plan, j *undo.Journal) (bool, error)
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

// v6Embedded4 are the IPv6 blocks that embed IPv4 addresses (IPv4-compatible
// ::/96 and IPv4-mapped ::ffff:0:0/96). Windows Firewall applies IPv6 ranges
// covering them to IPv4 traffic as well, so a "block all IPv6 except X" range
// that includes them silently blocks every IPv4 destination too — which is
// how the kill switch once blocked the exit node itself.
var v6Embedded4 = [][2]netip.Addr{
	{netip.MustParseAddr("::"), netip.MustParseAddr("::ffff:ffff")},
	{netip.MustParseAddr("::ffff:0:0"), netip.MustParseAddr("::ffff:ffff:ffff")},
}

// Complement returns inclusive "lo-hi" ranges covering the whole address
// family except the given addresses (and, for IPv6, except the blocks that
// embed IPv4 addresses). Used for Windows Firewall block rules, which cannot
// express "everything but X" any other way.
func Complement(v6 bool, except []netip.Addr) []string {
	lo := netip.IPv4Unspecified()
	hi := netip.AddrFrom4([4]byte{255, 255, 255, 255})
	var ex [][2]netip.Addr
	if v6 {
		lo = netip.IPv6Unspecified()
		hi = netip.AddrFrom16([16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
		ex = append(ex, v6Embedded4...)
	}
	for _, a := range except {
		a = a.Unmap()
		if a.Is6() == v6 {
			ex = append(ex, [2]netip.Addr{a, a})
		}
	}
	sort.Slice(ex, func(i, j int) bool { return ex[i][0].Less(ex[j][0]) })
	var out []string
	cur := lo
	for _, r := range ex {
		if r[1].Less(cur) {
			continue // already past this exclusion
		}
		if cur.Less(r[0]) {
			out = append(out, cur.String()+"-"+r[0].Prev().String())
		}
		if r[1] == hi {
			return out
		}
		cur = r[1].Next()
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

// RemoveFirewallGroupScript deletes every Windows Firewall rule in group and
// succeeds (exit 0) when there is none — Remove-NetFirewallRule alone fails
// on an empty match, which made undo steps report spurious errors.
func RemoveFirewallGroupScript(group string) string {
	return fmt.Sprintf(`$r = @(Get-NetFirewallRule -Group %s -ErrorAction SilentlyContinue); if ($r.Count) { $r | Remove-NetFirewallRule }`, psQuote(group))
}

// WindowsKillSwitchScript renders the PowerShell that installs the Windows
// kill-switch. Instead of naming adapters (fragile: hidden adapters are
// rejected, new ones would be missed) it blocks outbound traffic whose
// *source* is not one of the tunnel's own addresses, unless it goes to the
// exit endpoint. Tunnel traffic is sourced from the tunnel IP and passes;
// anything leaving through Wi-Fi/Ethernet is sourced from a LAN address and
// is blocked, on every adapter, present or future. Loopback is never
// filtered by Windows Firewall. Block rules beat allow rules, so existing
// allow rules can't punch holes. UDP excludes DHCP server ports (67, 547) so
// the physical link keeps its lease.
func WindowsKillSwitchScript(group string, p Plan) string {
	list := func(rs []string) string {
		q := make([]string, len(rs))
		for i, r := range rs {
			q[i] = psQuote(r)
		}
		return "@(" + strings.Join(q, ",") + ")"
	}
	// One rule set per address family: mixing families in one rule let
	// Windows apply IPv6 ranges to IPv4 traffic.
	return fmt.Sprintf(`
$v4 = @{ Group = %[1]s; Direction = 'Outbound'; Action = 'Block'; Profile = 'Any'; LocalAddress = %[2]s; RemoteAddress = %[3]s }
$v6 = @{ Group = %[1]s; Direction = 'Outbound'; Action = 'Block'; Profile = 'Any'; LocalAddress = %[4]s; RemoteAddress = %[5]s }
New-NetFirewallRule -Name 'backhaul-ks-tcp4'  -DisplayName 'Backhaul kill-switch (TCP, IPv4)'  -Protocol TCP @v4 | Out-Null
New-NetFirewallRule -Name 'backhaul-ks-udp4'  -DisplayName 'Backhaul kill-switch (UDP, IPv4)'  -Protocol UDP -RemotePort @('1-66','68-65535') @v4 | Out-Null
New-NetFirewallRule -Name 'backhaul-ks-icmp4' -DisplayName 'Backhaul kill-switch (ICMP, IPv4)' -Protocol ICMPv4 @v4 | Out-Null
New-NetFirewallRule -Name 'backhaul-ks-tcp6'  -DisplayName 'Backhaul kill-switch (TCP, IPv6)'  -Protocol TCP @v6 | Out-Null
New-NetFirewallRule -Name 'backhaul-ks-udp6'  -DisplayName 'Backhaul kill-switch (UDP, IPv6)'  -Protocol UDP -RemotePort @('1-546','548-65535') @v6 | Out-Null
New-NetFirewallRule -Name 'backhaul-ks-icmp6' -DisplayName 'Backhaul kill-switch (ICMP, IPv6)' -Protocol ICMPv6 @v6 | Out-Null
`, psQuote(group),
		list(Complement(false, p.TunnelAddrs)), list(Complement(false, p.Endpoints)),
		list(Complement(true, p.TunnelAddrs)), list(Complement(true, p.Endpoints)))
}

// EndpointRouteState is what a route check concluded.
type EndpointRouteState int

const (
	EndpointRouteOK      EndpointRouteState = iota // traffic to the exit node uses a real network path
	EndpointRouteRepair                            // it goes through our own tunnel: repin via Gateway
	EndpointRouteOffline                           // no usable non-tunnel route (offline)
)

// EndpointRouteCheck is the parsed result of the Windows check script.
type EndpointRouteCheck struct {
	State   EndpointRouteState
	IfIndex string
	NextHop string
}

// WindowsEndpointRouteScript prints "ok" if traffic to ep doesn't go
// through tun, otherwise "<ifIndex> <nextHop>" of the best default route not
// via tun, or "none".
func WindowsEndpointRouteScript(ep netip.Addr, tun string) string {
	def, fam := "0.0.0.0/0", "IPv4"
	if ep.Is6() {
		def, fam = "::/0", "IPv6"
	}
	return fmt.Sprintf(`
$r = Find-NetRoute -RemoteIPAddress %[1]s -ErrorAction SilentlyContinue | Where-Object { $_.NextHop } | Select-Object -First 1
if ($r -and $r.InterfaceAlias -ne %[2]s) { 'ok'; exit }
$best = Get-NetRoute -DestinationPrefix '%[3]s' -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -ne %[2]s } |
  Sort-Object { $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily %[4]s).InterfaceMetric } | Select-Object -First 1
if (-not $best) { 'none'; exit }
"$($best.ifIndex) $($best.NextHop)"`, psQuote(ep.String()), psQuote(tun), def, fam)
}

// ParseEndpointRouteCheck parses WindowsEndpointRouteScript output.
func ParseEndpointRouteCheck(out string) (EndpointRouteCheck, error) {
	f := strings.Fields(out)
	switch {
	case len(f) == 1 && f[0] == "ok":
		return EndpointRouteCheck{State: EndpointRouteOK}, nil
	case len(f) == 1 && f[0] == "none":
		return EndpointRouteCheck{State: EndpointRouteOffline}, nil
	case len(f) == 2:
		return EndpointRouteCheck{State: EndpointRouteRepair, IfIndex: f[0], NextHop: f[1]}, nil
	}
	return EndpointRouteCheck{}, fmt.Errorf("unexpected route check output %q", out)
}

// WindowsOtherVPNScript lists active virtual adapters (other than ours) that
// hold a full-tunnel route — i.e. another VPN that will fight over routing.
// Hyper-V/VMware/VirtualBox switches are physical uplinks in disguise and
// are ignored.
func WindowsOtherVPNScript(own string) string {
	return fmt.Sprintf(`
$idx = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1') -and $_.InterfaceAlias -ne %[1]s } |
  Select-Object -ExpandProperty ifIndex -Unique)
Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
  Where-Object { $idx -contains $_.ifIndex -and -not $_.HardwareInterface -and $_.Status -eq 'Up' -and
                 $_.InterfaceDescription -notmatch 'Hyper-V Virtual Ethernet|VMware|VirtualBox|Bridge' } |
  ForEach-Object { $_.Name + ' (' + $_.InterfaceDescription + ')' }`, psQuote(own))
}

// vpnIfaceRE matches Unix interface names used by VPN software.
var vpnIfaceRE = regexp.MustCompile(`^(tun|tap|wg|ppp|utun|ipsec|proton|nordlynx|zt|tailscale|nebula)`)

// UnixOtherVPNs extracts foreign VPN interfaces carrying full-tunnel routes
// from route-table lines (Linux `ip -4 route show`, macOS `netstat -rn -f inet`).
func UnixOtherVPNs(routeTable, own string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(routeTable, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "default", "0.0.0.0/1", "128.0.0.0/1", "0/1", "128.0/1":
		default:
			continue
		}
		iface := ""
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "dev" {
				iface = f[i+1]
			}
		}
		if iface == "" { // macOS netstat: interface is the last-but-one or last column
			iface = f[len(f)-1]
			if !vpnIfaceRE.MatchString(iface) && len(f) > 1 {
				iface = f[len(f)-2]
			}
		}
		if iface == own || !vpnIfaceRE.MatchString(iface) || seen[iface] {
			continue
		}
		seen[iface] = true
		out = append(out, iface)
	}
	return out
}

// errOffline means there is no non-tunnel path to the exit node right now.
var errOffline = fmt.Errorf("no network path to the exit node outside the tunnel (offline, or the network changed)")
