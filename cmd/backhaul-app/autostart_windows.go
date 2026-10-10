//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"backhaul/internal/osutil"
)

// Start with Windows: a scheduled task that runs Backhaul at sign-in with
// administrator rights (a Run-key entry would ask for permission every time)
// and the --autostart flag, which starts it in the tray and starts sharing.
const (
	taskName      = "Backhaul"
	autostartFlag = "--autostart"
)

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func autostartEnabled() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := osutil.PowerShell(ctx, fmt.Sprintf(
		`$t = Get-ScheduledTask -TaskName %s -ErrorAction SilentlyContinue; if ($t) { 'yes' } else { 'no' }`, psQuote(taskName)))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "yes", nil
}

func setAutostart(on bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if !on {
		_, err := osutil.PowerShell(ctx, fmt.Sprintf(
			`Unregister-ScheduledTask -TaskName %s -Confirm:$false -ErrorAction SilentlyContinue`, psQuote(taskName)))
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// No time limit (the default would end Backhaul after 3 days), runs on
	// battery, and waits 20s after sign-in so the network is up.
	_, err = osutil.PowerShell(ctx, fmt.Sprintf(`
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute %s -Argument %s
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$trigger.Delay = 'PT20S'
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName %s -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Starts Backhaul and its exit node at sign-in' -Force | Out-Null`,
		psQuote(exe), psQuote(autostartFlag), psQuote(taskName)))
	return err
}

// refreshAutostart keeps an existing task pointing at this exe (e.g. after
// Backhaul.exe was moved or updated in a new folder).
func refreshAutostart() {
	if on, err := autostartEnabled(); err == nil && on {
		_ = setAutostart(true)
	}
}

func launchedByAutostart() bool {
	for _, a := range os.Args[1:] {
		if a == autostartFlag {
			return true
		}
	}
	return false
}
