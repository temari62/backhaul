// Package config loads, validates and writes Backhaul's TOML configuration
// (~/.config/backhaul/config.toml) and its secrets file (secrets.toml, 0600).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"backhaul/internal/osutil"
)

// Modes.
const (
	ModeServe   = "serve"
	ModeConnect = "connect"
)

// WireGuard engines.
const (
	EngineEmbedded = "embedded"
	EngineWGQuick  = "wg-quick"
)

// Reachability modes (§3).
const (
	ReachPortForward = "port-forward"
	ReachRelay       = "relay"
	ReachRendezvous  = "rendezvous" // mode C: stub only in v1
)

// Duration is a time.Duration that (un)marshals as a Go duration string ("10s").
type Duration struct{ time.Duration }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// D is a helper to construct a Duration.
func D(v time.Duration) Duration { return Duration{v} }

// Config mirrors §9 of the spec, plus the knobs needed to avoid magic numbers.
type Config struct {
	Mode         string       `toml:"mode"`
	WireGuard    WireGuard    `toml:"wireguard"`
	Peer         Peer         `toml:"peer"`
	Transport    Transport    `toml:"transport"`
	Reachability Reachability `toml:"reachability"`
	DDNS         DDNS         `toml:"ddns"`
	Client       Client       `toml:"client"`
	Serve        Serve        `toml:"serve"`
	Health       Health       `toml:"health"`
}

// WireGuard holds data-plane settings.
type WireGuard struct {
	Engine     string `toml:"engine"`
	Interface  string `toml:"interface"` // "wg0"; on macOS the kernel picks utunN
	Subnet     string `toml:"subnet"`
	SelfIP     string `toml:"self_ip"`
	Subnet6    string `toml:"subnet6"`
	SelfIP6    string `toml:"self_ip6"`
	ListenPort int    `toml:"listen_port"` // serve: WG UDP port (local only, wstunnel forwards to it)
	MTU        int    `toml:"mtu"`
	Keepalive  int    `toml:"keepalive"`
}

// Peer is the other machine.
type Peer struct {
	PublicKey  string   `toml:"public_key"`
	AllowedIPs []string `toml:"allowed_ips,omitempty"` // serve mode: the client's tunnel IPs
}

// Transport configures the obfuscating wrapper (wstunnel).
type Transport struct {
	Kind            string   `toml:"kind"`
	Endpoint        string   `toml:"endpoint"`    // connect: exit node hostname/IP
	Port            int      `toml:"port"`        // WSS port (443)
	TLSSHA256       string   `toml:"tls_sha256"`  // pinned cert fingerprint
	ListenAddr      string   `toml:"listen_addr"` // serve: wstunnel bind address
	PathPrefix      string   `toml:"path_prefix"` // shared HTTP upgrade path; unknown paths are rejected
	CertFile        string   `toml:"cert_file,omitempty"`
	KeyFile         string   `toml:"key_file,omitempty"`
	LocalUDPPort    int      `toml:"local_udp_port"`  // connect: wstunnel local UDP listener
	RemoteUDPPort   int      `toml:"remote_udp_port"` // connect: the exit node's WireGuard UDP port
	WstunnelPath    string   `toml:"wstunnel_path,omitempty"`
	WstunnelVersion string   `toml:"wstunnel_version,omitempty"`
	DialTimeout     Duration `toml:"dial_timeout"`
	ReadyTimeout    Duration `toml:"ready_timeout"`
	BackoffMin      Duration `toml:"backoff_min"`
	BackoffMax      Duration `toml:"backoff_max"`
}

// Reachability selects how the client reaches the exit node (§3).
type Reachability struct {
	Mode  string `toml:"mode"`
	Relay Relay  `toml:"relay"`
}

// Relay is mode B: a VPS running `wstunnel server` that both laptops dial.
type Relay struct {
	Host       string `toml:"host"`
	Port       int    `toml:"port"`
	RemotePort int    `toml:"remote_port"` // UDP port opened on the VPS loopback by the exit node's reverse tunnel
	TLSSHA256  string `toml:"tls_sha256"`
}

// DDNS configures the optional dynamic DNS updater (serve mode).
type DDNS struct {
	Provider string   `toml:"provider"` // "duckdns" | "cloudflare" | ""
	Domain   string   `toml:"domain"`   // full hostname to update
	ZoneID   string   `toml:"zone_id,omitempty"`
	Interval Duration `toml:"interval"`
}

// Client holds connect-mode leak-prevention settings.
type Client struct {
	KillSwitch     bool   `toml:"killswitch"`
	TunnelIPv6     bool   `toml:"tunnel_ipv6"`
	DNS            string `toml:"dns"`
	DNSMethod      string `toml:"dns_method"`                 // linux: "auto" | "resolved" | "resolv.conf"
	ExpectedExitIP string `toml:"expected_exit_ip,omitempty"` // for doctor; defaults to the endpoint's resolved IP
}

// Serve holds exit-node settings.
type Serve struct {
	DNSForwarder bool   `toml:"dns_forwarder"` // answer DNS on the tunnel IP:53
	DNSUpstream  string `toml:"dns_upstream"`  // where the forwarder sends queries
	WANInterface string `toml:"wan_interface,omitempty"`
	NATBackend   string `toml:"nat_backend,omitempty"` // linux: "nftables" | "iptables" | "" (auto)
}

// Health configures probes and the reconnect loop (§8).
type Health struct {
	Interval         Duration `toml:"interval"`
	HandshakeTimeout Duration `toml:"handshake_timeout"`
	StartupGrace     Duration `toml:"startup_grace"`
	ProbeTimeout     Duration `toml:"probe_timeout"`
	IPCheckURL       string   `toml:"ip_check_url"`
	IPv6CheckURL     string   `toml:"ipv6_check_url"`
	DNSLeakName      string   `toml:"dns_leak_name"`
	BackoffMin       Duration `toml:"backoff_min"`
	BackoffMax       Duration `toml:"backoff_max"`
}

// Default returns a Config pre-filled with every default. Loading decodes on
// top of it, so omitted keys keep these values.
func Default() *Config {
	return &Config{
		Mode: ModeConnect,
		WireGuard: WireGuard{
			Engine:     EngineEmbedded,
			Interface:  "wg0",
			Subnet:     "10.9.0.0/24",
			SelfIP:     "10.9.0.2/32",
			Subnet6:    "fd09:b4c0::/64",
			SelfIP6:    "fd09:b4c0::2/128",
			ListenPort: 51820,
			MTU:        1280, // TODO(spec): conservative MTU for WG-over-WSS-over-TCP; tune per network.
			Keepalive:  25,
		},
		Transport: Transport{
			Kind:            "wstunnel",
			Port:            443,
			ListenAddr:      "0.0.0.0",
			LocalUDPPort:    51821,
			RemoteUDPPort:   51820,
			WstunnelVersion: DefaultWstunnelVersion,
			DialTimeout:     D(10 * time.Second),
			ReadyTimeout:    D(15 * time.Second),
			BackoffMin:      D(1 * time.Second),
			BackoffMax:      D(60 * time.Second),
		},
		Reachability: Reachability{
			Mode:  ReachPortForward,
			Relay: Relay{Port: 443, RemotePort: 51820},
		},
		DDNS: DDNS{Interval: D(5 * time.Minute)},
		Client: Client{
			KillSwitch: true,
			TunnelIPv6: true,
			DNS:        "10.9.0.1",
			DNSMethod:  "auto",
		},
		Serve: Serve{
			DNSForwarder: true,
			DNSUpstream:  "1.1.1.1:53", // TODO(spec): spec doesn't name an upstream; Cloudflare chosen as a sane default.
		},
		Health: Health{
			Interval:         D(10 * time.Second),
			HandshakeTimeout: D(180 * time.Second), // WG rekeys every 120s; 3 min without one = dead
			StartupGrace:     D(30 * time.Second),
			ProbeTimeout:     D(10 * time.Second),
			IPCheckURL:       "https://api.ipify.org",
			IPv6CheckURL:     "https://api6.ipify.org",
			DNSLeakName:      "whoami.akamai.net",
			BackoffMin:       D(2 * time.Second),
			BackoffMax:       D(2 * time.Minute),
		},
	}
}

// DefaultWstunnelVersion is the wstunnel release auto-downloaded when none is
// installed. Its per-platform SHA-256 sums are pinned in internal/transport.
const DefaultWstunnelVersion = "10.7.1"

// Secrets live in secrets.toml with 0600 perms. Never log them.
type Secrets struct {
	PrivateKey   string `toml:"private_key"`
	PresharedKey string `toml:"preshared_key"`
	DDNSToken    string `toml:"ddns_token,omitempty"`
}

// LogValue redacts secrets if a Secrets value ever reaches slog.
func (Secrets) LogValue() any { return "[REDACTED]" }

// String redacts secrets for fmt.
func (Secrets) String() string { return "Secrets{[REDACTED]}" }

// Paths locates Backhaul's files.
type Paths struct{ Dir string }

// DefaultDir is ~/.config/backhaul (honoring $BACKHAUL_CONFIG_DIR and sudo).
func DefaultDir() (string, error) {
	if d := os.Getenv("BACKHAUL_CONFIG_DIR"); d != "" {
		return d, nil
	}
	home, err := osutil.UserHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "backhaul"), nil
}

func (p Paths) Config() string  { return filepath.Join(p.Dir, "config.toml") }
func (p Paths) Secrets() string { return filepath.Join(p.Dir, "secrets.toml") }
func (p Paths) Pairing() string { return filepath.Join(p.Dir, "pairing.txt") }
func (p Paths) TLSDir() string  { return filepath.Join(p.Dir, "tls") }
func (p Paths) Cert() string    { return filepath.Join(p.TLSDir(), "cert.pem") }
func (p Paths) Key() string     { return filepath.Join(p.TLSDir(), "key.pem") }
func (p Paths) State() string   { return filepath.Join(p.Dir, "state") }
func (p Paths) Bin() string     { return filepath.Join(p.Dir, "bin") }

// Load reads config.toml and secrets.toml and validates them.
func Load(p Paths) (*Config, *Secrets, error) {
	cfg := Default()
	md, err := toml.DecodeFile(p.Config(), cfg)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("no config at %s — run `backhaul setup` first", p.Config())
		}
		return nil, nil, fmt.Errorf("parse %s: %w", p.Config(), err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, nil, fmt.Errorf("%s: unknown keys: %s", p.Config(), strings.Join(keys, ", "))
	}
	sec := &Secrets{}
	if err := checkSecretPerms(p.Secrets()); err != nil {
		return nil, nil, err
	}
	if _, err := toml.DecodeFile(p.Secrets(), sec); err != nil {
		return nil, nil, fmt.Errorf("read secrets %s: %w", p.Secrets(), err)
	}
	if cfg.Transport.CertFile == "" {
		cfg.Transport.CertFile = p.Cert()
	}
	if cfg.Transport.KeyFile == "" {
		cfg.Transport.KeyFile = p.Key()
	}
	if err := Validate(cfg, sec); err != nil {
		return nil, nil, err
	}
	return cfg, sec, nil
}

// Save writes config.toml (0644) and secrets.toml (0600), creating the dir (0700).
func Save(p Paths, cfg *Config, sec *Secrets) error {
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("# Backhaul configuration. Private keys and tokens live in secrets.toml (0600).\n")
	enc := toml.NewEncoder(&buf)
	enc.Indent = ""
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	if err := WriteFileAtomic(p.Config(), buf.Bytes(), 0o644); err != nil {
		return err
	}
	buf.Reset()
	buf.WriteString("# Backhaul secrets. Keep this file private (0600). Never share it.\n")
	if err := toml.NewEncoder(&buf).Encode(sec); err != nil {
		return err
	}
	return WriteFileAtomic(p.Secrets(), buf.Bytes(), 0o600)
}

// WriteFileAtomic writes via a temp file + rename so a crash never leaves a
// half-written config.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ParsePrefixHost parses "10.9.0.2/32" (or a bare IP) into an address.
func ParsePrefixHost(s string) (netip.Addr, error) {
	if !strings.Contains(s, "/") {
		return netip.ParseAddr(s)
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Addr{}, err
	}
	return p.Addr(), nil
}

// IfaceAddr4 returns the IPv4 address to assign to the tunnel interface: the
// self IP with the subnet's prefix length (so the subnet is on-link).
func (c *Config) IfaceAddr4() (netip.Prefix, error) {
	return ifaceAddr(c.WireGuard.SelfIP, c.WireGuard.Subnet)
}

// IfaceAddr6 is IfaceAddr4 for IPv6; ok=false when v6 is not configured.
func (c *Config) IfaceAddr6() (p netip.Prefix, ok bool, err error) {
	if c.WireGuard.SelfIP6 == "" || c.WireGuard.Subnet6 == "" {
		return netip.Prefix{}, false, nil
	}
	p, err = ifaceAddr(c.WireGuard.SelfIP6, c.WireGuard.Subnet6)
	return p, err == nil, err
}

func ifaceAddr(self, subnet string) (netip.Prefix, error) {
	a, err := ParsePrefixHost(self)
	if err != nil {
		return netip.Prefix{}, err
	}
	sn, err := netip.ParsePrefix(subnet)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, sn.Bits()), nil
}

// DNSServers parses client.dns ("10.9.0.1" or "10.9.0.1, fd09:b4c0::1").
func (c *Config) DNSServers() ([]netip.Addr, error) {
	var out []netip.Addr
	for _, f := range strings.FieldsFunc(c.Client.DNS, func(r rune) bool { return r == ',' || r == ' ' }) {
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("client.dns: %w", err)
		}
		out = append(out, a)
	}
	return out, nil
}

// RemoteHost returns the host/port the client's transport dials, accounting
// for relay mode.
func (c *Config) RemoteHost() (host string, port int, fingerprint string) {
	if c.Reachability.Mode == ReachRelay {
		return c.Reachability.Relay.Host, c.Reachability.Relay.Port, c.Reachability.Relay.TLSSHA256
	}
	return c.Transport.Endpoint, c.Transport.Port, c.Transport.TLSSHA256
}
