//go:build windows

package nat

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"backhaul/internal/osutil"
	"backhaul/internal/undo"
)

const natName = "backhaul"

// DefaultWAN returns the alias of the interface holding the default route.
func DefaultWAN(ctx context.Context) (string, error) {
	out, err := osutil.PowerShell(ctx,
		`(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias`)
	if err != nil {
		return "", err
	}
	if out = strings.TrimSpace(out); out == "" {
		return "", fmt.Errorf("no IPv4 default route")
	}
	return out, nil
}

// Available reports whether WinNAT exists. It ships only with the Hyper-V /
// Containers networking stack, so plain Windows 10/11 desktops lack it.
func Available(ctx context.Context) bool {
	out, err := osutil.PowerShell(ctx,
		`if (Get-CimClass -Namespace root/StandardCimv2 -ClassName MSFT_NetNat -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }`)
	return err == nil && strings.TrimSpace(out) == "yes"
}

const fwGroup = "backhaul-serve"

// AllowInbound opens TCP port in Windows Firewall for the exit node's
// listener (wstunnel). Without it, inbound connections are silently dropped.
func AllowInbound(ctx context.Context, port int, j *undo.Journal) error {
	remove := fmt.Sprintf(`$r = @(Get-NetFirewallRule -Group '%s' -ErrorAction SilentlyContinue); if ($r.Count) { $r | Remove-NetFirewallRule }`, fwGroup)
	_, _ = osutil.PowerShell(ctx, remove)
	_ = j.Push(undo.Exec("remove inbound firewall rule", "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", remove))
	_, err := osutil.PowerShell(ctx, fmt.Sprintf(
		`New-NetFirewallRule -Name 'backhaul-serve-in' -DisplayName 'Backhaul exit node (TCP %d)' -Group '%s' -Direction Inbound -Protocol TCP -LocalPort %d -Action Allow -Profile Any | Out-Null`,
		port, fwGroup, port))
	return err
}

func enable(ctx context.Context, p Plan, j *undo.Journal) error {
	// WinNAT (New-NetNat) masquerades the internal prefix out of any interface.
	// Editions without it use serve.nat_mode = "userspace" instead. WinNAT
	// also allows only one NAT network, so Docker/Hyper-V NATs can conflict.
	if !Available(ctx) {
		return fmt.Errorf("WinNAT (New-NetNat) is not available on this Windows edition; set serve.nat_mode = %q (or \"auto\")", "userspace")
	}
	// try/catch: Get-NetNat itself throws when the WinNAT class is missing,
	// which -ErrorAction can't suppress; undo must never fail on that.
	removeNAT := fmt.Sprintf(`try { Get-NetNat -Name '%s' -ErrorAction Stop | Remove-NetNat -Confirm:$false } catch {}`, natName)
	_, _ = osutil.PowerShell(ctx, removeNAT)
	_ = j.Push(undo.Exec("remove WinNAT", "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", removeNAT))
	if _, err := osutil.PowerShell(ctx, fmt.Sprintf(`New-NetNat -Name '%s' -InternalIPInterfaceAddressPrefix '%s' | Out-Null`,
		natName, p.Subnet4.Masked())); err != nil {
		return fmt.Errorf("New-NetNat failed (another NAT network may exist — see Get-NetNat; or use serve.nat_mode = \"userspace\"): %w", err)
	}
	if p.Subnet6.IsValid() {
		slog.Warn("IPv6 NAT is not supported by WinNAT; tunneled IPv6 from the client will not reach the internet (it will not leak either)")
	}
	for _, alias := range []string{p.Iface, p.WAN} {
		old, err := osutil.PowerShell(ctx, fmt.Sprintf(`(Get-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4).Forwarding`, alias))
		if err != nil {
			return err
		}
		if strings.TrimSpace(old) == "Enabled" {
			continue
		}
		_ = j.Push(undo.Exec("restore forwarding on "+alias, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			fmt.Sprintf(`Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 -Forwarding Disabled`, alias)))
		if _, err := osutil.PowerShell(ctx, fmt.Sprintf(`Set-NetIPInterface -InterfaceAlias '%s' -AddressFamily IPv4 -Forwarding Enabled`, alias)); err != nil {
			return err
		}
	}
	return nil
}
