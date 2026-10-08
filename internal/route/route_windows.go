//go:build windows

package route

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"backhaul/internal/osutil"
	"backhaul/internal/undo"
)

const fwGroup = "backhaul"

type windowsManager struct{}

func newManager() Manager { return windowsManager{} }

// ConfigureInterface assigns addresses/MTU on the Wintun adapter and gives
// it the lowest metric so its DNS and routes win.
func ConfigureInterface(ctx context.Context, iface string, addrs []netip.Prefix, mtu int) error {
	name := "name=" + iface
	// The adapter can take a moment to appear to netsh after creation.
	var err error
	for i := 0; i < 10; i++ {
		if _, err = osutil.Run(ctx, "netsh", "interface", "ipv4", "set", "subinterface", iface, "mtu="+strconv.Itoa(mtu), "store=active"); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if a.Addr().Is4() {
			if _, err := osutil.Run(ctx, "netsh", "interface", "ipv4", "set", "address", name, "source=static",
				"address="+a.Addr().String(), "mask="+v4Mask(a.Bits()), "store=active"); err != nil {
				return err
			}
		} else {
			if _, err := osutil.Run(ctx, "netsh", "interface", "ipv6", "add", "address", "interface="+iface,
				"address="+a.String(), "store=active"); err != nil {
				return err
			}
		}
	}
	_, _ = osutil.Run(ctx, "netsh", "interface", "ipv4", "set", "interface", iface, "metric=1")
	_, _ = osutil.Run(ctx, "netsh", "interface", "ipv6", "set", "interface", iface, "metric=1")
	return nil
}

func v4Mask(bits int) string {
	m := ^uint32(0) << (32 - bits)
	if bits == 0 {
		m = 0
	}
	return fmt.Sprintf("%d.%d.%d.%d", m>>24, (m>>16)&0xff, (m>>8)&0xff, m&0xff)
}

// gatewayFor asks Windows which interface/next hop currently reaches dst.
func gatewayFor(ctx context.Context, dst netip.Addr) (ifIndex, nextHop string, err error) {
	out, err := osutil.PowerShell(ctx, fmt.Sprintf(
		`$r = Find-NetRoute -RemoteIPAddress %s | Where-Object { $_.NextHop } | Select-Object -First 1; "$($r.InterfaceIndex) $($r.NextHop)"`,
		psQuote(dst.String())))
	if err != nil {
		return "", "", err
	}
	f := strings.Fields(out)
	if len(f) != 2 {
		return "", "", fmt.Errorf("cannot determine route to %s (got %q)", dst, out)
	}
	return f[0], f[1], nil
}

func (windowsManager) Apply(ctx context.Context, p Plan, j *undo.Journal) error {
	for _, ep := range p.Endpoints {
		ep = ep.Unmap()
		if ep.IsLoopback() {
			continue
		}
		idx, gw, err := gatewayFor(ctx, ep)
		if err != nil {
			return fmt.Errorf("find physical route to endpoint: %w", err)
		}
		fam := "ipv4"
		if ep.Is6() {
			fam = "ipv6"
		}
		args := []string{"interface", fam, "add", "route", "prefix=" + HostPrefix(ep).String(),
			"interface=" + idx, "nexthop=" + gw, "store=active"}
		if _, err := osutil.Run(ctx, "netsh", args...); err != nil {
			if !strings.Contains(strings.ToLower(err.Error()), "exists") {
				return err
			}
			continue
		}
		del := append([]string{"netsh"}, args...)
		del[3] = "delete"
		_ = j.Push(undo.Exec("remove endpoint host route", del...))
	}
	for _, pf := range SplitV4 {
		args := []string{"interface", "ipv4", "add", "route", "prefix=" + pf.String(), "interface=" + p.Iface, "nexthop=0.0.0.0", "metric=0", "store=active"}
		if _, err := osutil.Run(ctx, "netsh", args...); err != nil {
			return err
		}
		del := append([]string{"netsh"}, args...)
		del[3] = "delete"
		_ = j.Push(undo.Exec("remove split route", del...))
	}
	if p.IPv6 {
		for _, pf := range SplitV6 {
			args := []string{"interface", "ipv6", "add", "route", "prefix=" + pf.String(), "interface=" + p.Iface, "nexthop=::", "metric=0", "store=active"}
			if _, err := osutil.Run(ctx, "netsh", args...); err != nil {
				slog.Warn("IPv6 tunneling failed; disabling IPv6 for this session to prevent leaks", "err", err)
				p.IPv6 = false
				break
			}
			del := append([]string{"netsh"}, args...)
			del[3] = "delete"
			_ = j.Push(undo.Exec("remove split route v6", del...))
		}
	}
	if !p.IPv6 {
		// Unbind IPv6 from every physical adapter that currently has it enabled.
		out, err := osutil.PowerShell(ctx, fmt.Sprintf(
			`(Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object { $_.Enabled -and $_.Name -ne %s }).Name -join "|"`, psQuote(p.Iface)))
		if err != nil {
			return fmt.Errorf("disable IPv6: %w", err)
		}
		for _, name := range strings.Split(out, "|") {
			if name = strings.TrimSpace(name); name == "" {
				continue
			}
			_ = j.Push(undo.Exec("re-enable IPv6 on "+name, psArgv(fmt.Sprintf(
				`Enable-NetAdapterBinding -Name %s -ComponentID ms_tcpip6`, psQuote(name)))...))
			if _, err := osutil.PowerShell(ctx, fmt.Sprintf(`Disable-NetAdapterBinding -Name %s -ComponentID ms_tcpip6`, psQuote(name))); err != nil {
				return err
			}
		}
	}
	if len(p.DNS) > 0 {
		servers := make([]string, len(p.DNS))
		for i, d := range p.DNS {
			servers[i] = psQuote(d.String())
		}
		list := strings.Join(servers, ",")
		// NRPT "." sends every query to the tunnel resolver regardless of
		// Windows' per-interface "smart multi-homed" resolution.
		_ = j.Push(undo.Exec("remove NRPT rule", psArgv(
			`Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'backhaul' } | Remove-DnsClientNrptRule -Force; Clear-DnsClientCache`)...))
		if _, err := osutil.PowerShell(ctx, fmt.Sprintf(
			`Set-DnsClientServerAddress -InterfaceAlias %s -ServerAddresses %s; Add-DnsClientNrptRule -Namespace '.' -NameServers %s -Comment 'backhaul'; Clear-DnsClientCache`,
			psQuote(p.Iface), list, list)); err != nil {
			return err
		}
	}
	if p.KillSwitch {
		if err := killSwitch(ctx, p, j); err != nil {
			return err
		}
	}
	return nil
}

// killSwitch blocks outbound traffic on every non-tunnel adapter except to
// the exit endpoint. Windows Firewall block rules override allow rules, so
// pre-existing allow rules (e.g. Core Networking DNS) cannot leak.
// TODO(spec): spec suggests raw WFP; firewall rules via PowerShell are far
// simpler to restore. Adapters added mid-session are not covered.
func killSwitch(ctx context.Context, p Plan, j *undo.Journal) error {
	_ = j.Push(undo.Exec("remove kill-switch rules", psArgv(
		fmt.Sprintf(`Remove-NetFirewallRule -Group %s -ErrorAction SilentlyContinue`, psQuote(fwGroup)))...))

	// Firewall rules only apply when the profile is enabled; enable and remember.
	out, err := osutil.PowerShell(ctx, `(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Name -join "|"`)
	if err != nil {
		return err
	}
	for _, prof := range strings.Split(out, "|") {
		if prof = strings.TrimSpace(prof); prof == "" {
			continue
		}
		_ = j.Push(undo.Exec("restore firewall profile "+prof, psArgv(fmt.Sprintf(`Set-NetFirewallProfile -Name %s -Enabled False`, psQuote(prof)))...))
		if _, err := osutil.PowerShell(ctx, fmt.Sprintf(`Set-NetFirewallProfile -Name %s -Enabled True`, psQuote(prof))); err != nil {
			return err
		}
	}

	ranges := append(Complement(false, p.Endpoints), Complement(true, p.Endpoints)...)
	quoted := make([]string, len(ranges))
	for i, r := range ranges {
		quoted[i] = psQuote(r)
	}
	remote := "@(" + strings.Join(quoted, ",") + ")"
	// UDP rule excludes DHCP server ports (67 v4, 547 v6) so the physical lease survives.
	script := fmt.Sprintf(`
$ifs = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -ne %[1]s } | Select-Object -ExpandProperty Name)
$common = @{ Group = %[2]s; Direction = 'Outbound'; Action = 'Block'; InterfaceAlias = $ifs; RemoteAddress = %[3]s }
New-NetFirewallRule -Name 'backhaul-ks-tcp'  -DisplayName 'Backhaul kill-switch (TCP)'  -Protocol TCP @common | Out-Null
New-NetFirewallRule -Name 'backhaul-ks-udp'  -DisplayName 'Backhaul kill-switch (UDP)'  -Protocol UDP -RemotePort @('1-66','68-546','548-65535') @common | Out-Null
New-NetFirewallRule -Name 'backhaul-ks-icmp' -DisplayName 'Backhaul kill-switch (ICMP)' -Protocol ICMPv4 @common | Out-Null
New-NetFirewallRule -Name 'backhaul-ks-icmp6' -DisplayName 'Backhaul kill-switch (ICMPv6)' -Protocol ICMPv6 @common | Out-Null
`, psQuote(p.Iface), psQuote(fwGroup), remote)
	_, err = osutil.PowerShell(ctx, script)
	return err
}
