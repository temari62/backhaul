package transport

import (
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CloudflaredOptions configures the exit node's Cloudflare Tunnel.
type CloudflaredOptions struct {
	Binary string
	Token  string // tunnel token (passed in the environment, never on the command line)
	ReadyTimeout,
	BackoffMin, BackoffMax time.Duration
}

var (
	cloudflaredReadyRE = regexp.MustCompile(`Registered tunnel connection`)
	cloudflaredLevelRE = regexp.MustCompile(`\s(ERR|WRN)\s`)
)

// Cloudflared supervises `cloudflared tunnel run`: it keeps outgoing
// connections to Cloudflare open, and Cloudflare sends the clients'
// traffic for the tunnel's hostname down them to the local wstunnel server.
type Cloudflared struct {
	*Supervisor
	mu      sync.Mutex
	problem string // cloudflared's latest complaint, cleared when connected
}

// NewCloudflared creates the supervised cloudflared.
func NewCloudflared(o CloudflaredOptions) *Cloudflared {
	c := &Cloudflared{}
	c.Supervisor = NewSupervisor(ProcSpec{
		Kind: "cloudflared", Role: RoleServer, Binary: o.Binary,
		Args: CloudflaredArgs(),
		Env:  []string{"TUNNEL_TOKEN=" + o.Token},
		// Only our token: drop any TUNNEL_TOKEN inherited from the environment.
		DropEnv:      []string{"TUNNEL_TOKEN"},
		ReadyRE:      cloudflaredReadyRE,
		OnLine:       c.onLine,
		ReadyTimeout: o.ReadyTimeout, BackoffMin: o.BackoffMin, BackoffMax: o.BackoffMax,
	})
	return c
}

// Problem is cloudflared's latest complaint since it last connected.
func (c *Cloudflared) Problem() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.problem
}

// CloudflaredArgs is the command line (the token comes from TUNNEL_TOKEN).
func CloudflaredArgs() []string {
	return []string{"tunnel", "--no-autoupdate", "run"}
}

// onLine surfaces connection events and problems in the activity log.
func (c *Cloudflared) onLine(line string) {
	msg := ""
	switch {
	case cloudflaredReadyRE.MatchString(line):
		slog.Info("Cloudflare Tunnel connected", "detail", tail(line))
		c.mu.Lock()
		c.problem = ""
		c.mu.Unlock()
		return
	case cloudflaredLevelRE.MatchString(line):
		msg = tail(line)
	case !strings.Contains(line, " INF ") && !strings.Contains(line, " DBG ") &&
		!strings.HasPrefix(line, "See '") && strings.TrimSpace(line) != "":
		// Start-up failures are plain text without a level, e.g. "Provided
		// Tunnel token is not valid." (followed by a help hint).
		msg = strings.TrimSpace(line)
	default:
		return
	}
	slog.Warn("cloudflared: " + msg)
	c.mu.Lock()
	c.problem = msg
	c.mu.Unlock()
}

// tail drops cloudflared's timestamp and level prefix.
func tail(line string) string {
	if m := cloudflaredLevelRE.FindStringIndex(line); m != nil {
		return strings.TrimSpace(line[m[1]:])
	}
	if i := strings.Index(line, " INF "); i >= 0 {
		return strings.TrimSpace(line[i+5:])
	}
	return strings.TrimSpace(line)
}
