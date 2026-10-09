package transport

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
)

// Wstunnel roles.
const (
	RoleServer        = "server"         // exit node, port-forward mode: wss listener on :443
	RoleClient        = "client"         // laptop 1: local UDP → wss → exit node
	RoleReverseClient = "reverse-client" // exit node, relay mode: holds an outbound wss to the VPS
)

// WstunnelOptions configures one wstunnel child process.
type WstunnelOptions struct {
	Binary string
	Role   string

	// Server role.
	ListenAddr string // "0.0.0.0"
	Port       int    // 443
	CertFile   string
	KeyFile    string
	RestrictTo string // only allow tunnels to this "ip:port" (the WG UDP port)

	// Client / reverse-client roles.
	ServerURL string // e.g. "ws://127.0.0.1:41234" (the pinned-TLS proxy)
	LocalUDP  string // client: "127.0.0.1:51821"
	RemoteUDP string // client: target on the far side; reverse: local WG "127.0.0.1:51820"
	RelayBind string // reverse: UDP bind on the relay, "127.0.0.1:51820"

	PathPrefix   string
	ReadyTimeout time.Duration
	BackoffMin   time.Duration
	BackoffMax   time.Duration
	Verbose      bool
}

// Args renders the wstunnel command line (exported for tests and doctor).
func (o WstunnelOptions) Args() []string {
	lvl := "INFO"
	if o.Verbose {
		lvl = "DEBUG"
	}
	switch o.Role {
	case RoleServer:
		a := []string{"server", "--log-lvl", lvl, "--restrict-to", o.RestrictTo}
		if o.CertFile != "" {
			a = append(a, "--tls-certificate", o.CertFile, "--tls-private-key", o.KeyFile)
		}
		if o.PathPrefix != "" {
			a = append(a, "--restrict-http-upgrade-path-prefix", o.PathPrefix)
		}
		return append(a, fmt.Sprintf("wss://%s:%d", hostForURL(o.ListenAddr), o.Port))
	case RoleClient:
		a := []string{"client", "--log-lvl", lvl,
			"-L", fmt.Sprintf("udp://%s:%s?timeout_sec=0", o.LocalUDP, o.RemoteUDP)}
		if o.PathPrefix != "" {
			a = append(a, "--http-upgrade-path-prefix", o.PathPrefix)
		}
		return append(a, o.ServerURL)
	case RoleReverseClient:
		a := []string{"client", "--log-lvl", lvl,
			"-R", fmt.Sprintf("udp://%s:%s?timeout_sec=0", o.RelayBind, o.RemoteUDP)}
		if o.PathPrefix != "" {
			a = append(a, "--http-upgrade-path-prefix", o.PathPrefix)
		}
		return append(a, o.ServerURL)
	}
	return nil
}

func hostForURL(h string) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]"
	}
	return h
}

// readyRE matches wstunnel's "Starting wstunnel server listening on …" and
// "Starting UDP server listening cnx on …" log lines (verified on v10.7.1).
var readyRE = regexp.MustCompile(`(?i)listening (cnx )?on`)

// acceptRE matches wstunnel server's per-connection log line
// (cnx{peer="1.2.3.4:5678"}: ... Accepting connection), verified on v10.7.1.
var acceptRE = regexp.MustCompile(`peer="([^"]+)".*Accepting connection`)

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Wstunnel is the supervised wstunnel transport.
type Wstunnel = Supervisor

// NewWstunnel builds a supervised wstunnel transport.
func NewWstunnel(o WstunnelOptions) *Supervisor {
	spec := ProcSpec{
		Kind: "wstunnel", Role: o.Role, Binary: o.Binary, Args: o.Args(),
		// wstunnel rejects NO_COLOR=1 (it wants true/false), so force it.
		DropEnv: []string{"NO_COLOR", "RUST_LOG"}, Env: []string{"NO_COLOR=true"},
		ReadyRE: readyRE, LocalUDP: o.LocalUDP,
		ReadyTimeout: o.ReadyTimeout, BackoffMin: o.BackoffMin, BackoffMax: o.BackoffMax,
		// Reverse clients log no "listening" line. TODO(spec): heuristic.
		ReadyWhenAlive: o.Role == RoleReverseClient,
	}
	if o.Role == RoleServer {
		spec.OnLine = func(line string) {
			if m := acceptRE.FindStringSubmatch(line); m != nil {
				slog.Info("incoming connection to the exit node", "from", m[1])
			}
		}
	}
	return NewSupervisor(spec)
}

func filterEnv(env []string, drop ...string) []string {
	out := env[:0:0]
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		keep := true
		for _, d := range drop {
			if strings.EqualFold(k, d) {
				keep = false
			}
		}
		if keep {
			out = append(out, kv)
		}
	}
	return out
}
