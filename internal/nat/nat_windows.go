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

func enable(ctx context.Context, p Plan, j *undo.Journal) error {
	// WinNAT (New-NetNat) masquerades the internal prefix out of any interface.
	// TODO(spec): ICS fallback for Windows editions without WinNAT; WinNAT
	// also allows only one NAT network, so Docker/Hyper-V NATs can conflict.
	_, _ = osutil.PowerShell(ctx, fmt.Sprintf(`Get-NetNat -Name '%s' -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false`, natName))
	_ = j.Push(undo.Exec("remove WinNAT", "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf(`Get-NetNat -Name '%s' -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false`, natName)))
	if _, err := osutil.PowerShell(ctx, fmt.Sprintf(`New-NetNat -Name '%s' -InternalIPInterfaceAddressPrefix '%s' | Out-Null`,
		natName, p.Subnet4.Masked())); err != nil {
		return fmt.Errorf("New-NetNat failed (another NAT network may exist — see Get-NetNat): %w", err)
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
