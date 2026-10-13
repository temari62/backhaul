package health

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// A probe must return by its timeout even when the DNS server never answers
// (a stuck lookup once froze connecting and disconnecting).
func TestResolveViaReturnsOnTime(t *testing.T) {
	start := time.Now()
	_, err := ResolveVia(context.Background(), netip.MustParseAddr("10.255.255.1"), "example.com", time.Second)
	if err == nil {
		t.Fatal("expected an error from an unreachable DNS server")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %s; the probe must give up on time", d)
	}
}
