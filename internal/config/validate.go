package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

var fingerprintRE = regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`)

// ValidFingerprint reports whether s is an uppercase colon-separated SHA-256.
func ValidFingerprint(s string) bool { return fingerprintRE.MatchString(s) }

// ValidKey reports whether s is a base64 WireGuard key (32 bytes).
func ValidKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

// Validate checks a config + secrets pair and returns every problem found.
func Validate(c *Config, s *Secrets) error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	switch c.Mode {
	case ModeServe, ModeConnect:
	default:
		add("mode must be %q or %q, got %q", ModeServe, ModeConnect, c.Mode)
	}
	switch c.WireGuard.Engine {
	case EngineEmbedded, EngineWGQuick:
	default:
		add("wireguard.engine must be %q or %q", EngineEmbedded, EngineWGQuick)
	}
	if c.WireGuard.Interface == "" {
		add("wireguard.interface must not be empty")
	}
	checkSubnet := func(name, subnet, selfKey, self string, v6 bool) {
		sn, err := netip.ParsePrefix(subnet)
		if err != nil {
			add("wireguard.%s: %v", name, err)
			return
		}
		if sn.Addr().Is6() != v6 {
			add("wireguard.%s: wrong address family", name)
		}
		a, err := ParsePrefixHost(self)
		if err != nil {
			add("wireguard.%s: %v", selfKey, err)
			return
		}
		if !sn.Contains(a) {
			add("wireguard.%s %s is not inside %s", selfKey, a, sn)
		}
	}
	checkSubnet("subnet", c.WireGuard.Subnet, "self_ip", c.WireGuard.SelfIP, false)
	if c.WireGuard.Subnet6 != "" || c.WireGuard.SelfIP6 != "" {
		checkSubnet("subnet6", c.WireGuard.Subnet6, "self_ip6", c.WireGuard.SelfIP6, true)
	}
	if c.WireGuard.MTU < 576 || c.WireGuard.MTU > 9000 {
		add("wireguard.mtu %d out of range 576..9000", c.WireGuard.MTU)
	}
	if c.WireGuard.Keepalive < 0 || c.WireGuard.Keepalive > 65535 {
		add("wireguard.keepalive out of range")
	}
	checkPort := func(name string, p int) {
		if p < 1 || p > 65535 {
			add("%s %d out of range 1..65535", name, p)
		}
	}
	checkPort("wireguard.listen_port", c.WireGuard.ListenPort)
	checkPort("transport.port", c.Transport.Port)
	checkPort("transport.local_udp_port", c.Transport.LocalUDPPort)
	checkPort("transport.remote_udp_port", c.Transport.RemoteUDPPort)

	if !ValidKey(c.Peer.PublicKey) {
		add("peer.public_key is not a valid WireGuard key")
	}
	if s != nil {
		if !ValidKey(s.PrivateKey) {
			add("secrets: private_key is not a valid WireGuard key")
		}
		if s.PresharedKey != "" && !ValidKey(s.PresharedKey) {
			add("secrets: preshared_key is not a valid WireGuard key")
		}
	}
	if c.Transport.Kind != "wstunnel" {
		add("transport.kind %q unsupported (v1 ships wstunnel only)", c.Transport.Kind)
	}
	if c.Transport.PathPrefix != "" && !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(c.Transport.PathPrefix) {
		add("transport.path_prefix may only contain [A-Za-z0-9_-]")
	}

	switch c.Reachability.Mode {
	case ReachPortForward:
	case ReachRelay:
		if c.Reachability.Relay.Host == "" {
			add("reachability.relay.host is required when reachability.mode = %q", ReachRelay)
		}
		checkPort("reachability.relay.port", c.Reachability.Relay.Port)
		checkPort("reachability.relay.remote_port", c.Reachability.Relay.RemotePort)
		if c.Reachability.Relay.TLSSHA256 != "" && !ValidFingerprint(c.Reachability.Relay.TLSSHA256) {
			add("reachability.relay.tls_sha256 must look like AB:CD:...(32 bytes)")
		}
	case ReachRendezvous:
		add("reachability.mode %q is not implemented in v1", ReachRendezvous)
	default:
		add("reachability.mode must be %q or %q", ReachPortForward, ReachRelay)
	}

	switch c.DDNS.Provider {
	case "", "duckdns", "cloudflare":
	default:
		add("ddns.provider must be \"duckdns\", \"cloudflare\" or empty")
	}
	if c.DDNS.Provider != "" {
		if c.DDNS.Domain == "" {
			add("ddns.domain is required when ddns.provider is set")
		}
		if s != nil && s.DDNSToken == "" {
			add("secrets: ddns_token is required when ddns.provider is set")
		}
		if c.DDNS.Provider == "cloudflare" && c.DDNS.ZoneID == "" {
			add("ddns.zone_id is required for cloudflare")
		}
	}

	if c.Mode == ModeConnect {
		if c.Reachability.Mode == ReachPortForward {
			if c.Transport.Endpoint == "" {
				add("transport.endpoint is required in connect mode")
			}
			if !ValidFingerprint(c.Transport.TLSSHA256) {
				add("transport.tls_sha256 must be a pinned SHA-256 fingerprint (AB:CD:...)")
			}
		} else if c.Reachability.Mode == ReachRelay && !ValidFingerprint(c.Reachability.Relay.TLSSHA256) {
			add("reachability.relay.tls_sha256 must be pinned in connect mode")
		}
		if _, err := c.DNSServers(); err != nil {
			errs = append(errs, err)
		}
		switch c.Client.DNSMethod {
		case "", "auto", "resolved", "resolv.conf":
		default:
			add(`client.dns_method must be "auto", "resolved" or "resolv.conf"`)
		}
		if c.Client.ExpectedExitIP != "" {
			if _, err := netip.ParseAddr(c.Client.ExpectedExitIP); err != nil {
				add("client.expected_exit_ip: %v", err)
			}
		}
	}
	if c.Mode == ModeServe {
		if len(c.Peer.AllowedIPs) == 0 {
			add("peer.allowed_ips is required in serve mode (the client's tunnel IPs)")
		}
		for _, a := range c.Peer.AllowedIPs {
			if _, err := netip.ParsePrefix(a); err != nil {
				add("peer.allowed_ips: %v", err)
			}
		}
		if c.Serve.DNSForwarder {
			if _, err := netip.ParseAddrPort(c.Serve.DNSUpstream); err != nil {
				add("serve.dns_upstream must be ip:port: %v", err)
			}
		}
		switch c.Serve.NATMode {
		case "", NATAuto, NATSystem, NATUserspace:
		default:
			add(`serve.nat_mode must be "auto", "system" or "userspace"`)
		}
		if c.Serve.UDPIdle.Duration < 0 {
			add("serve.udp_idle must be >= 0")
		}
		switch c.Serve.NATBackend {
		case "", "nftables", "iptables":
		default:
			add("serve.nat_backend must be \"nftables\", \"iptables\" or empty")
		}
	}
	for name, d := range map[string]Duration{
		"health.interval": c.Health.Interval, "health.handshake_timeout": c.Health.HandshakeTimeout,
		"health.probe_timeout": c.Health.ProbeTimeout, "transport.dial_timeout": c.Transport.DialTimeout,
		"transport.ready_timeout": c.Transport.ReadyTimeout,
	} {
		if d.Duration <= 0 {
			add("%s must be > 0", name)
		}
	}
	if c.Transport.BackoffMin.Duration <= 0 || c.Transport.BackoffMax.Duration < c.Transport.BackoffMin.Duration {
		add("transport.backoff_min must be > 0 and <= backoff_max")
	}
	if c.Health.BackoffMin.Duration <= 0 || c.Health.BackoffMax.Duration < c.Health.BackoffMin.Duration {
		add("health.backoff_min must be > 0 and <= backoff_max")
	}
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = "  - " + e.Error()
	}
	return errors.New("invalid configuration:\n" + strings.Join(msgs, "\n"))
}
