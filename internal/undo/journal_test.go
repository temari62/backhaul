package undo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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
