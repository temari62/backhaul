package state

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestWatchStop(t *testing.T) {
	dir := t.TempDir()
	// A stale request from an earlier run must not stop a new one.
	if err := RequestStop(dir); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	go func() {
		WatchStop(ctx, dir, 10*time.Millisecond, cancel)
		close(stopped)
	}()
	time.Sleep(50 * time.Millisecond)
	if ctx.Err() != nil {
		t.Fatal("stale stop file cancelled the new run")
	}
	RequestStop(dir)
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("stop request not noticed")
	}
	if ctx.Err() == nil {
		t.Fatal("context not cancelled")
	}
}

func TestStaleRequestIgnoredEvenIfUndeletable(t *testing.T) {
	dir := t.TempDir()
	start := time.Now()
	// Simulate a request from an earlier run that could not be deleted.
	os.WriteFile(StopFile(dir), []byte("1"), 0o600)
	if stopRequestedSince(dir, start) {
		t.Fatal("stale request honoured")
	}
	RequestStop(dir)
	if !stopRequestedSince(dir, start) {
		t.Fatal("fresh request ignored")
	}
}

func TestRuntimeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if _, ok, _ := Read(dir); ok {
		t.Fatal("unexpected state")
	}
	Write(dir, &Runtime{PID: 42, Iface: "wg0"})
	r, ok, err := Read(dir)
	if err != nil || !ok || r.PID != 42 || !r.Fresh(time.Minute) {
		t.Fatalf("%+v %v %v", r, ok, err)
	}
	Remove(dir)
	if _, ok, _ := Read(dir); ok {
		t.Fatal("not removed")
	}
}
