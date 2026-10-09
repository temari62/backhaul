package transport

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RealityOptions configures an Xray process carrying WireGuard's UDP over
// VLESS + REALITY. REALITY makes the exit node indistinguishable from a real
// HTTPS website (the "target", e.g. www.amazon.com): a censor that connects
// or watches sees that site's genuine certificate, while only a client
// holding the exit node's REALITY public key and the VLESS UUID gets the
// tunnel. This is what currently survives the Great Firewall's active
// probing and traffic classification, where TLS-with-own-certificate tunnels
// (like plain wstunnel) get blocked within minutes.
type RealityOptions struct {
	Binary     string
	Role       string // RoleServer | RoleClient
	ConfigPath string // written with 0600 (contains secrets)

	// Server.
	ListenAddr string
	Port       int
	PrivateKey string // x25519, base64url

	// Client.
	ServerAddr  string // exit node IP
	ServerPort  int
	PublicKey   string // x25519, base64url
	Fingerprint string // uTLS client fingerprint, e.g. "chrome"
	LocalUDP    string // "127.0.0.1:51821": WireGuard sends here

	// Both.
	UUID       string // VLESS user id (secret)
	ShortID    string // hex, up to 16 chars
	ServerName string // SNI of the impersonated site, e.g. "www.amazon.com"
	Target     string // where unauthenticated visitors are sent, e.g. "www.amazon.com:443"
	RemoteUDP  string // client: exit node's WireGuard port as seen there, "127.0.0.1:51820"

	ReadyTimeout time.Duration
	BackoffMin   time.Duration
	BackoffMax   time.Duration
}

type jsonObj = map[string]any

// Config renders the Xray JSON configuration.
func (o RealityOptions) Config() ([]byte, error) {
	var cfg jsonObj
	switch o.Role {
	case RoleServer:
		cfg = jsonObj{
			"log": jsonObj{"loglevel": "info"},
			"inbounds": []jsonObj{{
				"listen": o.ListenAddr, "port": o.Port, "protocol": "vless",
				"settings": jsonObj{"clients": []jsonObj{{"id": o.UUID, "flow": ""}}, "decryption": "none"},
				"streamSettings": jsonObj{"network": "tcp", "security": "reality", "realitySettings": jsonObj{
					"show": false, "target": o.Target, "xver": 0,
					"serverNames": []string{o.ServerName}, "privateKey": o.PrivateKey, "shortIds": []string{o.ShortID},
				}},
			}},
			// Only the paired client (UUID + REALITY key) can use the tunnel,
			// the same trust as holding its WireGuard key.
			// TODO(spec): restrict destinations to the WireGuard port once
			// routing rules are verified to work with XUDP-multiplexed UDP.
			"outbounds": []jsonObj{{"protocol": "freedom", "tag": "direct"}},
		}
	case RoleClient:
		host, port, err := splitHostPort(o.RemoteUDP)
		if err != nil {
			return nil, fmt.Errorf("remote UDP %q: %w", o.RemoteUDP, err)
		}
		lhost, lport, err := splitHostPort(o.LocalUDP)
		if err != nil {
			return nil, fmt.Errorf("local UDP %q: %w", o.LocalUDP, err)
		}
		cfg = jsonObj{
			"log": jsonObj{"loglevel": "info"},
			"inbounds": []jsonObj{{
				"listen": lhost, "port": lport, "protocol": "dokodemo-door",
				"settings": jsonObj{"address": host, "port": port, "network": "udp"},
			}},
			"outbounds": []jsonObj{{
				"protocol": "vless",
				"settings": jsonObj{"vnext": []jsonObj{{
					"address": o.ServerAddr, "port": o.ServerPort,
					"users": []jsonObj{{"id": o.UUID, "encryption": "none", "flow": ""}},
				}}},
				"streamSettings": jsonObj{"network": "tcp", "security": "reality", "realitySettings": jsonObj{
					"serverName": o.ServerName, "fingerprint": o.Fingerprint,
					"publicKey": o.PublicKey, "shortId": o.ShortID, "spiderX": "/",
				}},
			}},
		}
	default:
		return nil, fmt.Errorf("unknown xray role %q", o.Role)
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func splitHostPort(s string) (string, int, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	n, err := strconv.Atoi(p)
	return h, n, err
}

// xrayReadyRE matches "core: Xray 26.3.27 started" (verified on v26.3.27).
var xrayReadyRE = regexp.MustCompile(`core: Xray .* started`)

// NewReality writes the Xray config and returns the supervised transport.
func NewReality(o RealityOptions) (*Supervisor, error) {
	b, err := o.Config()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(o.ConfigPath), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(o.ConfigPath, b, 0o600); err != nil {
		return nil, err
	}
	return NewSupervisor(ProcSpec{
		Kind: "reality", Role: o.Role, Binary: o.Binary, Args: []string{"run", "-c", o.ConfigPath},
		ReadyRE: xrayReadyRE, LocalUDP: o.LocalUDP,
		ReadyTimeout: o.ReadyTimeout, BackoffMin: o.BackoffMin, BackoffMax: o.BackoffMax,
		OnLine:    xrayLogHandler(o.Role),
		RestartOn: map[string]*regexp.Regexp{RoleClient: xrayCutRE}[o.Role],
	}), nil
}

// xrayProbeRE matches the exit node's note about a visitor without the key
// (e.g. a censor's active probe), who was shown the camouflage site.
var xrayProbeRE = regexp.MustCompile(`REALITY: processed invalid connection from ([^:\s]+(?::\d+)?)`)

// xrayAcceptRE matches Xray's access-log line for an accepted connection.
var xrayAcceptRE = regexp.MustCompile(`from (\S+) accepted `)

// xrayLogHandler returns the per-line hook for a role: on the exit node it
// also reports each accepted tunnel connection and where it came from.
func xrayLogHandler(role string) func(string) {
	return func(line string) {
		if role == RoleServer {
			if m := xrayAcceptRE.FindStringSubmatch(line); m != nil {
				slog.Info("incoming connection to the exit node", "from", m[1])
				return
			}
		}
		xrayLogLine(line)
	}
}

// xrayLogLine surfaces the Xray log lines that matter; everything else stays
// at debug level. Xray runs at "info" so failed dials are visible.
func xrayLogLine(line string) {
	low := strings.ToLower(line)
	switch {
	case xrayReadyRE.MatchString(line):
	case xrayProbeRE.MatchString(line):
		slog.Info("a visitor without the key was shown the camouflage site (normal for scanners; frequent ones can be the censor probing)",
			"from", xrayProbeRE.FindStringSubmatch(line)[1])
	case strings.Contains(line, "[Error]") || strings.Contains(line, "[Warning]") ||
		strings.Contains(low, "failed") || strings.Contains(low, "rejected"):
		slog.Warn("xray: " + line)
	}
}

// xrayCutRE matches the client's report that the network killed its
// connection to the exit node (verified wording on Windows: "wsasend: An
// existing connection was forcibly closed by the remote host").
var xrayCutRE = regexp.MustCompile(`(?i)forcibly closed|connection reset|broken pipe|failed to transfer (request|response) payload`)
