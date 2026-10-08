// Package wg brings the WireGuard interface up and down and applies peer
// configuration. Two backends: "embedded" (userspace wireguard-go + TUN,
// configured over UAPI) and "wg-quick" (system tools).
package wg

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"backhaul/internal/config"
	"backhaul/internal/keys"
	"backhaul/internal/undo"
)

// Settings is everything needed to bring up one interface with one peer.
type Settings struct {
	Interface     string
	PrivateKey    string // base64; never logged
	PresharedKey  string // base64; never logged
	PeerPublicKey string
	ListenPort    int    // 0 = random (client)
	PeerEndpoint  string // "127.0.0.1:51821" (client); "" (server learns it)
	AllowedIPs    []string
	Keepalive     int
	MTU           int
	Addresses     []netip.Prefix
	StateDir      string        // where wg-quick writes its config
	Journal       *undo.Journal // crash-recovery journal
}

// Stats is a point-in-time view of the single peer.
type Stats struct {
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
	Endpoint      string
}

// Engine is a WireGuard backend.
type Engine interface {
	Up(ctx context.Context, s Settings) error
	// Name is the real OS interface name (macOS assigns utunN).
	Name() string
	Stats() (Stats, error)
	// Kick re-applies the peer so WireGuard initiates a fresh handshake
	// (used after the transport reconnects).
	Kick() error
	Down(ctx context.Context) error
}

// New returns the engine selected in config.
func New(engine string) (Engine, error) {
	switch engine {
	case config.EngineEmbedded:
		return &Embedded{}, nil
	case config.EngineWGQuick:
		return newWGQuick()
	default:
		return nil, fmt.Errorf("unknown wireguard engine %q", engine)
	}
}

// uapiConfig renders the WireGuard UAPI "set" body for s.
func uapiConfig(s Settings, includeInterface bool) (string, error) {
	var b strings.Builder
	if includeInterface {
		priv, err := keys.Hex(s.PrivateKey)
		if err != nil {
			return "", fmt.Errorf("private key: %w", err)
		}
		fmt.Fprintf(&b, "private_key=%s\n", priv)
		fmt.Fprintf(&b, "listen_port=%d\n", s.ListenPort)
		b.WriteString("replace_peers=true\n")
	}
	pub, err := keys.Hex(s.PeerPublicKey)
	if err != nil {
		return "", fmt.Errorf("peer public key: %w", err)
	}
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	if s.PresharedKey != "" {
		psk, err := keys.Hex(s.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("preshared key: %w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	if s.PeerEndpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", s.PeerEndpoint)
	}
	if s.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", s.Keepalive)
	}
	b.WriteString("replace_allowed_ips=true\n")
	for _, a := range s.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", a)
	}
	return b.String(), nil
}

// parseUAPIStats extracts single-peer stats from a UAPI "get" response.
func parseUAPIStats(get string) Stats {
	var st Stats
	var sec, nsec int64
	for _, line := range strings.Split(get, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "last_handshake_time_sec":
			sec = n
		case "last_handshake_time_nsec":
			nsec = n
		case "rx_bytes":
			st.RxBytes = n
		case "tx_bytes":
			st.TxBytes = n
		case "endpoint":
			st.Endpoint = v
		}
	}
	if sec > 0 {
		st.LastHandshake = time.Unix(sec, nsec)
	}
	return st
}
