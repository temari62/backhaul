package app

import (
	"context"
	"testing"
	"time"
)

// A cleanup step that never returns (e.g. a tunnel adapter close stuck in
// the driver) must be abandoned so Disconnect always finishes.
func TestRunBoundedAbandonsHungStep(t *testing.T) {
	old := CleanupStepTimeout
	CleanupStepTimeout = 200 * time.Millisecond
	defer func() { CleanupStepTimeout = old }()
	block := make(chan struct{})
	defer close(block)
	start := time.Now()
	runBounded(context.Background(), cleanupStep{"hang", func(context.Context) { <-block }})
	ran := false
	runBounded(context.Background(), cleanupStep{"next", func(context.Context) { ran = true }})
	if d := time.Since(start); d > 2*time.Second || !ran {
		t.Fatalf("took %s, next step ran=%v", d, ran)
	}
	runBounded(context.Background(), cleanupStep{"panics", func(context.Context) { panic("boom") }})
}
