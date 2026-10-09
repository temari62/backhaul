package gui

import (
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"backhaul/internal/app"
	"backhaul/internal/config"
	"backhaul/internal/doctor"
	"backhaul/internal/osutil"
)

func TestSetupPairImportResetFlow(t *testing.T) {
	b := &Backend{Base: t.TempDir()}
	v := b.State()
	if v.Serve.Configured || v.Connect.Configured || v.Phase != "idle" {
		t.Fatalf("fresh state: %+v", v)
	}
	if _, err := b.SetupServe("", 443, ""); err == nil {
		t.Fatal("empty endpoint accepted")
	}
	p, err := b.SetupServe("203.0.113.5", 443, "")
	if err != nil {
		t.Fatal(err)
	}
	if p.Code == "" || !strings.HasPrefix(p.QR, "data:image/png;base64,") {
		t.Fatalf("pairing: %+v", p)
	}
	again, err := b.GetPairing()
	if err != nil || again.Code != p.Code {
		t.Fatalf("saved pairing mismatch: %v", err)
	}
	if err := b.ImportPairing("garbage"); err == nil {
		t.Fatal("garbage pairing accepted")
	}
	if err := b.ImportPairing(p.Code); err != nil {
		t.Fatal(err)
	}
	v = b.State()
	if v.Serve.PairingID == "" || v.Serve.PairingID != v.Connect.PairingID {
		t.Fatalf("pairing IDs differ after import: %q vs %q", v.Serve.PairingID, v.Connect.PairingID)
	}
	if !v.Serve.Configured || !v.Connect.Configured || v.Connect.Endpoint != "203.0.113.5" || !v.Connect.KillSwitch {
		t.Fatalf("after setup: %+v", v)
	}
	if v.Serve.Dir == v.Connect.Dir {
		t.Fatal("roles must use separate profiles")
	}
	if err := b.SetKillSwitch(false); err != nil {
		t.Fatal(err)
	}
	if b.State().Connect.KillSwitch {
		t.Fatal("kill-switch not saved")
	}
	if err := b.Reset(RoleConnect); err != nil {
		t.Fatal(err)
	}
	if b.State().Connect.Configured || !b.State().Serve.Configured {
		t.Fatal("reset removed the wrong profile")
	}
}

func TestAdoptsCLIProfileInBaseDir(t *testing.T) {
	base := t.TempDir()
	res, err := app.SetupExitNode(config.Paths{Dir: base}, app.ExitNodeOptions{
		Endpoint: "198.51.100.1", Port: 443, Subnet: "10.9.0.0/24", ReachMode: config.ReachPortForward})
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Save(config.Paths{Dir: base}, res.Config, res.Secrets); err != nil {
		t.Fatal(err)
	}
	b := &Backend{Base: base}
	if b.ProfileDir(RoleServe) != base {
		t.Fatal("CLI exit-node profile not adopted")
	}
	if b.ProfileDir(RoleConnect) != filepath.Join(base, RoleConnect) {
		t.Fatal("client profile should live in its own subdir")
	}
	if !b.State().Serve.Configured {
		t.Fatal("adopted profile not reported")
	}
}

func TestLogBuffer(t *testing.T) {
	lb := NewLogBuffer(3, nil, slog.LevelInfo)
	l := slog.New(lb).With("role", "serve")
	for i := 0; i < 5; i++ {
		l.Info("tick", "n", i)
	}
	l.Debug("hidden")
	got := lb.After(0)
	if len(got) != 3 || got[0].Seq != 3 || !strings.Contains(got[2].Text, "n=4") || !strings.Contains(got[2].Text, "role=serve") {
		t.Fatalf("%+v", got)
	}
	if len(lb.After(5)) != 0 {
		t.Fatal("After must exclude seen lines")
	}
}

func TestFriendlyPrivilegeError(t *testing.T) {
	msg := friendly(&osutil.ErrNotPrivileged{Hint: "sudo backhaul connect"})
	if strings.Contains(msg, "sudo") || !strings.Contains(msg, "administrator") {
		t.Fatalf("got %q", msg)
	}
}

func TestFriendlyPreflightErrors(t *testing.T) {
	pin := &app.PreflightError{Failed: []doctor.Result{{Name: doctor.CheckTLSPin, Detail: "server presents AA, pinned BB"}}}
	if msg := friendly(pin); !strings.Contains(msg, "Reset") || !strings.Contains(msg, "pairing code") {
		t.Fatalf("pin mismatch: %q", msg)
	}
	tcp := &app.PreflightError{Failed: []doctor.Result{{Name: doctor.CheckEndpointTCP, Detail: "cannot reach exit node on :443"}}}
	if msg := friendly(tcp); !strings.Contains(msg, "router forwards") || !strings.Contains(msg, ":443") {
		t.Fatalf("unreachable: %q", msg)
	}
	if got := pin.Error(); !strings.Contains(got, "TLS fingerprint") || strings.Contains(got, "see above") {
		t.Fatalf("error text: %q", got)
	}
}

func TestCondensePowerShell(t *testing.T) {
	raw := "install routes: powershell.exe -NoProfile -NonInteractive -Command $ErrorActionPreference='Stop';\n$common = @{ ... }\nNew-NetFirewallRule ... | Out-Null\n: exit status 1: New-NetFirewallRule : The specified interface was not found on the system.\nAt line:4 char:1\n+ New-NetFirewallRule ..."
	got := condensePowerShell(raw)
	want := "install routes: New-NetFirewallRule : The specified interface was not found on the system. (details in Activity)"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	if plain := condensePowerShell("dial tcp: timeout"); plain != "dial tcp: timeout" {
		t.Fatalf("non-PowerShell errors must pass through, got %q", plain)
	}
}

func TestFriendlyOtherVPN(t *testing.T) {
	e := &app.PreflightError{Failed: []doctor.Result{{Name: doctor.CheckOtherVPN, Detail: "another VPN is connected: Astrill (Astrill VPN Adapter)"}}}
	if msg := friendly(e); !strings.Contains(msg, "Astrill") || !strings.Contains(msg, "Disconnect it first") {
		t.Fatalf("got %q", msg)
	}
}
