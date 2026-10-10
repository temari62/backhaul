package wfp

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The probe mode: when run as a child with BACKHAUL_WFP_PROBE=addr, dial it
// and report via the exit code.
func TestMain(m *testing.M) {
	if addr := os.Getenv("BACKHAUL_WFP_PROBE"); addr != "" {
		c, err := net.DialTimeout("tcp", addr, 4*time.Second)
		if err != nil {
			os.Exit(1)
		}
		c.Close()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func probe(t *testing.T, exe, addr string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe)
	cmd.Env = append(os.Environ(), "BACKHAUL_WFP_PROBE="+addr)
	return cmd.Run() == nil
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	out.Close()
}

// The kill switch, scoped to two throwaway copies of this test binary so
// the machine running the test keeps its network: the "blocked" copy may
// only use loopback; the "allowed" copy (a PermitApps entry, like Backhaul
// itself) may connect anywhere; removing the kill switch restores access.
func TestKillSwitchBlocksAllButPermittedApps(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated (administrator) test run")
	}
	external := os.Getenv("BACKHAUL_WFP_TARGET")
	if external == "" {
		external = "1.1.1.1:443"
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	blocked, allowed := filepath.Join(dir, "probe-blocked.exe"), filepath.Join(dir, "probe-allowed.exe")
	copyFile(t, self, blocked)
	copyFile(t, self, allowed)
	if !probe(t, blocked, external) {
		t.Skipf("no direct internet access to %s from this machine", external)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { go ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	if err := Enable(Options{PermitApps: []string{allowed}, ScopeApps: []string{blocked, allowed}}); err != nil {
		t.Fatal(err)
	}
	defer Disable()
	if !Enabled() {
		t.Fatal("not enabled")
	}
	if probe(t, blocked, external) {
		t.Fatal("kill switch let a non-permitted program out")
	}
	if !probe(t, blocked, ln.Addr().String()) {
		t.Fatal("kill switch blocked loopback")
	}
	if !probe(t, allowed, external) {
		t.Fatal("kill switch blocked a permitted program")
	}
	Disable()
	if !probe(t, blocked, external) {
		t.Fatal("still blocked after Disable")
	}
}

func TestInterfaceLUID(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) == 0 {
		t.Skip("no interfaces")
	}
	luid, err := InterfaceLUID(ifs[0].Name)
	if err != nil || luid == 0 {
		t.Fatalf("LUID of %q = %d, %v", ifs[0].Name, luid, err)
	}
	if _, err := InterfaceLUID("no-such-adapter-xyz"); err == nil {
		t.Fatal("expected an error for a missing adapter")
	}
}

// Without administrator rights Enable must fail cleanly (the caller then
// connects without the kill switch) and leave nothing installed.
func TestEnableFailsCleanlyWithoutAdmin(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("elevated")
	}
	self, _ := os.Executable()
	if err := Enable(Options{PermitApps: []string{self}, ScopeApps: []string{self}}); err == nil {
		Disable()
		t.Fatal("expected access denied")
	} else {
		t.Log(err)
	}
	if Enabled() {
		t.Fatal("left enabled after failure")
	}
}
