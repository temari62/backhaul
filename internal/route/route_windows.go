//go:build windows

package route

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"backhaul/internal/osutil"
	"backhaul/internal/undo"
	"backhaul/internal/wfp"
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
	type uplink struct{ idx, gw string }
	uplinks := map[string]uplink{} // per family: a Cloudflare pool has many endpoints
	for _, ep := range p.Endpoints {
		ep = ep.Unmap()
		if ep.IsLoopback() {
			continue
		}
		fam := "ipv4"
		if ep.Is6() {
			fam = "ipv6"
		}
		u, ok := uplinks[fam]
		if !ok {
			idx, gw, err := gatewayFor(ctx, ep)
			if err != nil {
				return fmt.Errorf("find physical route to endpoint: %w", err)
			}
			u = uplink{idx, gw}
			uplinks[fam] = u
		}
		idx, gw := u.idx, u.gw
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
		_ = j.Push(undo.ExecBestEffort("remove endpoint host route", del...))
	}
	for _, pf := range SplitV4 {
		args := []string{"interface", "ipv4", "add", "route", "prefix=" + pf.String(), "interface=" + p.Iface, "nexthop=0.0.0.0", "metric=0", "store=active"}
		if _, err := osutil.Run(ctx, "netsh", args...); err != nil {
			return err
		}
		del := append([]string{"netsh"}, args...)
		del[3] = "delete"
		_ = j.Push(undo.ExecBestEffort("remove split route", del...))
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
			_ = j.Push(undo.ExecBestEffort("remove split route v6", del...))
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

// killSwitch blocks all traffic except through the tunnel adapter, from
// Backhaul itself and the programs in p.PermitApps (which carry the tunnel to
// the exit node), on loopback, and for DHCP / IPv6 neighbour discovery.
//
// It uses Windows Filtering Platform filters in a dynamic session (package
// wfp) rather than Windows Firewall rules: on a user's PC, firewall rules
// started blocking the exit node about a minute after being installed. The
// filters vanish by themselves when Backhaul exits, so there is nothing to
// undo after a crash. If they can't be installed, the session continues
// without a kill switch (KillSwitchActive reports false) rather than failing.
func killSwitch(ctx context.Context, p Plan, j *undo.Journal) error {
	// Rules from versions that used Windows Firewall.
	remove := RemoveFirewallGroupScript(fwGroup)
	_, _ = osutil.PowerShell(ctx, remove)

	luid, err := wfp.InterfaceLUID(p.Iface)
	if err == nil {
		var self string
		if self, err = os.Executable(); err == nil {
			err = wfp.Enable(wfp.Options{TunLUID: luid, PermitApps: append([]string{self}, p.PermitApps...),
				PermitServices: []string{"NlaSvc"}, AllowLAN: true})
		}
	}
	if err != nil {
		slog.Error("could not install the kill switch; continuing without it", "err", err)
	}
	return nil
}

// EnableKillSwitch (re)installs the kill switch for p.
func EnableKillSwitch(ctx context.Context, p Plan) error {
	_ = killSwitch(ctx, p, nil)
	if !wfp.Enabled() {
		return errors.New("kill switch not installed (see the log)")
	}
	return nil
}

// NetworkFacts summarises what Windows thinks of each network: its category
// and whether it has internet access (per Windows' connectivity check), and
// what kind of adapter each active one is.
func NetworkFacts(ctx context.Context) string {
	out, err := osutil.PowerShell(ctx, `
$c = Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { "$($_.InterfaceAlias): $($_.NetworkCategory), IPv4=$($_.IPv4Connectivity)" }
$a = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | ForEach-Object { "$($_.Name)=$($_.InterfaceDescription)" }
"networks: $($c -join '; ') | adapters: $($a -join '; ')"`)
	if err != nil {
		return "unknown (" + err.Error() + ")"
	}
	return strings.TrimSpace(out)
}

// KillSwitchActive reports whether the kill switch is installed.
func KillSwitchActive() bool { return wfp.Enabled() }

func (windowsManager) RepairEndpoint(ctx context.Context, p Plan, j *undo.Journal) (bool, error) {
	repaired := false
	for _, ep := range p.Endpoints {
		ep = ep.Unmap()
		if ep.IsLoopback() {
			continue
		}
		out, err := osutil.PowerShell(ctx, WindowsEndpointRouteScript(ep, p.Iface))
		if err != nil {
			return repaired, err
		}
		chk, err := ParseEndpointRouteCheck(out)
		if err != nil {
			return repaired, err
		}
		switch chk.State {
		case EndpointRouteOK:
			continue
		case EndpointRouteOffline:
			return repaired, errOffline
		}
		fam := "ipv4"
		if ep.Is6() {
			fam = "ipv6"
		}
		// Drop a stale pin (e.g. via an adapter that was reset), then re-pin.
		_, _ = osutil.PowerShell(ctx, fmt.Sprintf(`Remove-NetRoute -DestinationPrefix %s -Confirm:$false -ErrorAction SilentlyContinue`,
			psQuote(HostPrefix(ep).String())))
		args := []string{"interface", fam, "add", "route", "prefix=" + HostPrefix(ep).String(),
			"interface=" + chk.IfIndex, "nexthop=" + chk.NextHop, "store=active"}
		if _, err := osutil.Run(ctx, "netsh", args...); err != nil {
			return repaired, err
		}
		del := append([]string{"netsh"}, args...)
		del[3] = "delete"
		_ = j.Push(undo.ExecBestEffort("remove endpoint host route", del...))
		repaired = true
	}
	return repaired, nil
}

// OtherVPNs lists other active VPN adapters that hold full-tunnel routes.
func OtherVPNs(ctx context.Context, own string) ([]string, error) {
	out, err := osutil.PowerShell(ctx, WindowsOtherVPNScript(own))
	if err != nil {
		return nil, err
	}
	var vpns []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			vpns = append(vpns, l)
		}
	}
	return vpns, nil
}

// EndpointPath describes how Windows currently routes traffic to ep.
func EndpointPath(ctx context.Context, ep netip.Addr) string {
	out, err := osutil.PowerShell(ctx, fmt.Sprintf(
		`$r = Find-NetRoute -RemoteIPAddress %s | Where-Object { $_.NextHop } | Select-Object -First 1; "$($r.InterfaceAlias) via $($r.NextHop)"`,
		psQuote(ep.String())))
	if err != nil {
		return "unknown (" + err.Error() + ")"
	}
	return strings.TrimSpace(out)
}

// DisableKillSwitch removes the kill-switch rules now (the undo journal
// still runs the same idempotent removal at teardown).
func DisableKillSwitch(context.Context) error {
	wfp.Disable()
	return nil
}
