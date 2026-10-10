//go:build windows

package route

import (
	"context"
	"strings"
	"testing"
	"time"
)

// NetworkFacts is read-only; it must run cleanly and report both parts.
func TestNetworkFactsReadsState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	got := NetworkFacts(ctx)
	t.Log(got)
	if !strings.HasPrefix(got, "networks: ") || !strings.Contains(got, "| adapters: ") {
		t.Fatalf("unexpected %q", got)
	}
}
