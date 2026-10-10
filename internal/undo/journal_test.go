package undo

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestUnwindRestoresInReverse(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "resolv.conf")
	backup := filepath.Join(dir, "resolv.backup")
	os.WriteFile(target, []byte("original"), 0o644)
	os.WriteFile(backup, []byte("original"), 0o600)
	tmp := filepath.Join(dir, "generated.conf")

	j := Open(filepath.Join(dir, "undo.json"))
	j.Push(Action{Desc: "restore", Kind: KindRestoreFile, Path: target, Backup: backup})
	os.WriteFile(target, []byte("changed"), 0o644)
	j.Push(Action{Desc: "rm", Kind: KindRemoveFile, Path: tmp})
	os.WriteFile(tmp, []byte("x"), 0o600)

	if _, err := os.Stat(j.Path()); err != nil {
		t.Fatal("journal not persisted before unwind")
	}
	if err := j.Unwind(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "original" {
		t.Fatalf("not restored: %q", b)
	}
	for _, p := range []string{tmp, backup, j.Path()} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s should be gone", p)
		}
	}
}

func TestRecoverReplaysCrashedJournal(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "leftover")
	os.WriteFile(tmp, []byte("x"), 0o600)
	// Simulate a crash: a journal is written, the process dies.
	j := Open(filepath.Join(dir, "undo.json"))
	j.Push(Action{Desc: "rm", Kind: KindRemoveFile, Path: tmp})

	n, err := Recover(context.Background(), j.Path())
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("leftover not removed")
	}
	if n, _ := Recover(context.Background(), j.Path()); n != 0 {
		t.Fatal("recover not idempotent")
	}
}

func TestUnwindContinuesPastFailures(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "f")
	os.WriteFile(tmp, nil, 0o600)
	j := Open(filepath.Join(dir, "undo.json"))
	j.Push(Action{Desc: "rm", Kind: KindRemoveFile, Path: tmp})
	j.Push(Action{Desc: "fails", Kind: KindExec, Argv: []string{"backhaul-definitely-not-a-command"}})
	if err := j.Unwind(context.Background()); err == nil {
		t.Fatal("expected aggregated error")
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("later step skipped after earlier failure")
	}
}

// A hung step must not block the rest of the restore, and must stay in the
// journal so the next start retries it.
func TestUnwindBoundsHungStepAndKeepsItForRetry(t *testing.T) {
	old := StepTimeout
	StepTimeout = time.Second
	defer func() { StepTimeout = old }()
	dir := t.TempDir()
	gone := filepath.Join(dir, "temp-file")
	os.WriteFile(gone, []byte("x"), 0o600)
	hang := []string{"sleep", "30"}
	if runtime.GOOS == "windows" {
		hang = []string{"ping", "-n", "30", "127.0.0.1"}
	}
	j := Open(filepath.Join(dir, "undo.json"))
	j.Push(Action{Desc: "remove temp", Kind: KindRemoveFile, Path: gone})
	j.Push(Exec("hung step", hang...))

	start := time.Now()
	if err := j.Unwind(context.Background()); err == nil {
		t.Fatal("expected the timed-out step to be reported")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("unwind took %s; a hung step must be cut off", d)
	}
	if _, err := os.Stat(gone); !os.IsNotExist(err) {
		t.Fatal("the step after the hung one did not run")
	}
	b, err := os.ReadFile(j.Path())
	if err != nil {
		t.Fatalf("journal should be kept for retry: %v", err)
	}
	var left []Action
	json.Unmarshal(b, &left)
	if len(left) != 1 || left[0].Desc != "hung step" {
		t.Fatalf("journal = %+v, want only the hung step", left)
	}
}
