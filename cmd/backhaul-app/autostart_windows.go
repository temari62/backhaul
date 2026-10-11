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
		`if (@(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -eq %s }).Count) { 'yes' } else { 'no' }`, psQuote(taskName)))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "yes", nil
}

func setAutostart(on bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if !on {
		// Look the task up first: the scheduled-task cmdlets fail on a missing
		// task even with -ErrorAction SilentlyContinue when errors are fatal.
		_, err := osutil.PowerShell(ctx, unregisterScript(taskName))
		if err != nil {
			return fmt.Errorf("could not turn off starting with Windows: %w", err)
		}
		return nil
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

// unregisterScript removes the task if it exists and checks it is gone.
func unregisterScript(name string) string {
	return fmt.Sprintf(`
$t = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -eq %[1]s })
foreach ($x in $t) { Unregister-ScheduledTask -TaskName $x.TaskName -TaskPath $x.TaskPath -Confirm:$false }
if (@(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -eq %[1]s }).Count) { throw 'the task is still registered' }`, psQuote(name))
}
