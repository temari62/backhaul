package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run executes the CLI in-process, capturing stdout.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	root := newRootCmd()
	root.SetArgs(args)
	root.SetOut(w)
	err := root.ExecuteContext(context.Background())
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String(), err
}

// TestSetupPairingSmoke is the M1 smoke test: exit-node setup → pairing blob
// → client import → both configs load, keys line up, doctor runs.
func TestSetupPairingSmoke(t *testing.T) {
	srvDir, cliDir := t.TempDir(), t.TempDir()
	out, err := run(t, "--config-dir", srvDir, "setup", "--yes", "--role", "serve",
		"--endpoint", "127.0.0.1", "--port", "443", "--subnet6", "")
	if err != nil {
		t.Fatalf("serve setup: %v\n%s", err, out)
	}
	if !strings.Contains(out, "PAIRING BLOB") {
		t.Fatalf("no blob printed:\n%s", out)
	}
	pairing := filepath.Join(srvDir, "pairing.txt")
	if _, err := os.Stat(pairing); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, "--config-dir", srvDir, "setup", "--yes", "--role", "serve", "--endpoint", "x"); err == nil {
		t.Fatal("setup must refuse to overwrite without --force")
	}

	if out, err := run(t, "--config-dir", cliDir, "setup", "--import", "@"+pairing); err != nil {
		t.Fatalf("import: %v\n%s", err, out)
	}

	srvKeys, err := run(t, "--config-dir", srvDir, "keys", "show")
	if err != nil {
		t.Fatal(err)
	}
	cliKeys, err := run(t, "--config-dir", cliDir, "keys", "show")
	if err != nil {
		t.Fatal(err)
	}
	own := func(s string) string { return strings.Fields(strings.Split(s, "\n")[0])[5] }
	peer := func(s string) string { return strings.Fields(strings.Split(s, "\n")[1])[3] }
	if own(srvKeys) != peer(cliKeys) || own(cliKeys) != peer(srvKeys) {
		t.Fatalf("public keys do not cross-match:\n%s\n%s", srvKeys, cliKeys)
	}
	for _, s := range []string{srvKeys, cliKeys} {
		if strings.Contains(s, "private") {
			t.Fatal("keys show must not print private keys")
		}
	}

	// serve/connect refuse to run in the wrong mode (before needing privileges).
	if _, err := run(t, "--config-dir", cliDir, "serve"); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("serve on a client config: %v", err)
	}

	// status works without a running tunnel.
	out, err = run(t, "--config-dir", cliDir, "status", "--no-ip")
	if err != nil || !strings.Contains(out, "DOWN") {
		t.Fatalf("status: %v\n%s", err, out)
	}
}
