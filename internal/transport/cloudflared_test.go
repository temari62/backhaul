package transport

import (
	"context"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCloudflaredLogLines(t *testing.T) {
	ready := "2026-10-13T08:00:01Z INF Registered tunnel connection connIndex=0 connection=abc event=0 ip=198.41.200.13 location=lax05 protocol=quic"
	if !cloudflaredReadyRE.MatchString(ready) {
		t.Fatal("ready line not recognised")
	}
	if got := tail(ready); !strings.HasPrefix(got, "Registered tunnel connection connIndex=0") {
		t.Fatalf("tail = %q", got)
	}
	errLine := "2026-10-13T08:00:01Z ERR Failed to serve tunnel connection error=\"timeout\""
	if !cloudflaredLevelRE.MatchString(errLine) || tail(errLine) != `Failed to serve tunnel connection error="timeout"` {
		t.Fatalf("error line: %q", tail(errLine))
	}
	if slices.Contains(CloudflaredArgs(), "--token") {
		t.Fatal("the token must not be on the command line")
	}
}

// The real cloudflared, given a bad token, must not come up, and its own
// reason must reach the activity log.
func TestCloudflaredRejectsBadToken(t *testing.T) {
	bin := os.Getenv("BACKHAUL_TEST_CLOUDFLARED")
	if bin == "" {
		t.Skip("set BACKHAUL_TEST_CLOUDFLARED to a cloudflared binary")
	}
	var logs strings.Builder
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&lockedWriter{w: &logs}, nil)))
	defer slog.SetDefault(old)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s := NewCloudflared(CloudflaredOptions{Binary: bin, Token: "not-a-real-token",
		ReadyTimeout: 5 * time.Second, BackoffMin: time.Second, BackoffMax: 2 * time.Second})
	err := s.Start(ctx)
	s.Stop()
	if err == nil {
		t.Fatal("a bad token must not come up")
	}
	if got := logs.String(); !strings.Contains(got, "token is not valid") {
		t.Fatalf("the reason must reach the activity log; got:\n%s", got)
	}
}

type lockedWriter struct {
	mu sync.Mutex
	w  *strings.Builder
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
