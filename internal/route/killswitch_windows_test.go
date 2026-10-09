//go:build windows

package route

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
)

func ps(t *testing.T, script string) (string, error) {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "powershell.exe", "-NoProfile", "-NonInteractive",
		"-Command", "$ErrorActionPreference='Stop'; "+script).CombinedOutput()
	return string(out), err
}

// Runs the real kill-switch script through the real Windows Firewall cmdlets
// with -WhatIf: every parameter, address range and splat is validated by
// Windows, but no rule is created and no admin rights are needed.
func TestWindowsKillSwitchScriptIsAcceptedByWindows(t *testing.T) {
	script := strings.ReplaceAll(WindowsKillSwitchScript("backhaul-test", ksPlan()), "| Out-Null", "-WhatIf")
	out, err := ps(t, script)
	if err != nil {
		t.Fatalf("Windows rejected the kill-switch rules: %v\n%s", err, out)
	}
	if n := strings.Count(out, "What if: New-NetFirewallRule"); n != 6 {
		t.Fatalf("expected 4 rules, got %d:\n%s", n, out)
	}
}

// Undo must succeed when there is nothing to remove (it used to fail and
// log a spurious "some restore steps failed").
func TestRemoveFirewallGroupScriptSucceedsWhenEmpty(t *testing.T) {
	if out, err := ps(t, RemoveFirewallGroupScript("backhaul-test-nonexistent-group")); err != nil {
		t.Fatalf("removal of an empty group failed: %v\n%s", err, out)
	}
}

// The route-guard check runs read-only against this machine's real routing
// table: a public IP must be "ok" when the pretend tunnel isn't involved, and
// must need repair (or be offline) when the real uplink plays the tunnel.
func TestWindowsEndpointRouteScriptAgainstRealTable(t *testing.T) {
	ep := netip.MustParseAddr("8.8.8.8")
	out, err := ps(t, WindowsEndpointRouteScript(ep, "backhaul-no-such-iface"))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if chk, err := ParseEndpointRouteCheck(out); err != nil || chk.State != EndpointRouteOK {
		t.Fatalf("expected ok, got %+v %v (%q)", chk, err, out)
	}
	alias, err := ps(t, `(Find-NetRoute -RemoteIPAddress '8.8.8.8' | Where-Object { $_.NextHop } | Select-Object -First 1).InterfaceAlias`)
	if err != nil || strings.TrimSpace(alias) == "" {
		t.Skipf("no default route here: %v %q", err, alias)
	}
	out, err = ps(t, WindowsEndpointRouteScript(ep, strings.TrimSpace(alias)))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	chk, err := ParseEndpointRouteCheck(out)
	if err != nil || chk.State == EndpointRouteOK {
		t.Fatalf("pretending the uplink is the tunnel must not be ok: %+v %v (%q)", chk, err, out)
	}
	t.Logf("uplink %q as tunnel → %+v", strings.TrimSpace(alias), chk)
}

func TestWindowsOtherVPNScriptRuns(t *testing.T) {
	out, err := ps(t, WindowsOtherVPNScript("wg0"))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	t.Logf("other VPNs on this machine: %q", strings.TrimSpace(out))
}
