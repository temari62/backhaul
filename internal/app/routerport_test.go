package app

import (
	"context"
	"strings"
	"testing"

	"backhaul/internal/config"
)

// A VPS has a public address and no home router: no UPnP search, just a
// reminder about its firewall.
func TestOpenRouterPortSkipsRouterOnPublicAddress(t *testing.T) {
	c := config.Default()
	c.Transport.Port = 443
	msg, stop := openRouterPort(context.Background(), c, "203.0.113.10", nil)
	if stop != nil || !strings.Contains(msg, "public address") {
		t.Fatalf("got %q (stop=%v)", msg, stop != nil)
	}
	c.Reachability.UPnP = false // private address: the manual hint, no UPnP
	if msg, _ := openRouterPort(context.Background(), c, "192.168.88.13", nil); !strings.Contains(msg, "192.168.88.13") {
		t.Fatalf("got %q", msg)
	}
}
