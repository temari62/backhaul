// Package pairing encodes the one-time pairing blob (base64 TOML) that the
// exit node hands to the client during `backhaul setup` (§6.1 step 4).
package pairing

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"

	"backhaul/internal/config"
)

// Version is bumped on incompatible blob changes.
const Version = 1

// Blob is everything the client needs. It contains the client's private key
// and the PSK, so it must be moved over a trusted channel and then deleted.
type Blob struct {
	Version int `toml:"version"`

	ServerPublicKey  string `toml:"server_public_key"`
	ClientPrivateKey string `toml:"client_private_key"`
	PresharedKey     string `toml:"preshared_key"`

	Subnet    string `toml:"subnet"`
	ServerIP  string `toml:"server_ip"`
	ClientIP  string `toml:"client_ip"`
	Subnet6   string `toml:"subnet6,omitempty"`
	ServerIP6 string `toml:"server_ip6,omitempty"`
	ClientIP6 string `toml:"client_ip6,omitempty"`
	MTU       int    `toml:"mtu"`
	Keepalive int    `toml:"keepalive"`

	Endpoint     string `toml:"endpoint"`
	Port         int    `toml:"port"`
	ServerWGPort int    `toml:"server_wg_port"`
	TLSSHA256    string `toml:"tls_sha256"`
	PathPrefix   string `toml:"path_prefix"`

	// REALITY transport (empty TransportKind = wstunnel, for older codes).
	TransportKind      string `toml:"transport_kind,omitempty"`
	RealityServerName  string `toml:"reality_server_name,omitempty"`
	RealityTarget      string `toml:"reality_target,omitempty"`
	RealityPublicKey   string `toml:"reality_public_key,omitempty"`
	RealityShortID     string `toml:"reality_short_id,omitempty"`
	RealityUUID        string `toml:"reality_uuid,omitempty"`
	RealityFingerprint string `toml:"reality_fingerprint,omitempty"`

	ReachMode       string `toml:"reach_mode"`
	RelayHost       string `toml:"relay_host,omitempty"`
	RelayPort       int    `toml:"relay_port,omitempty"`
	RelayRemotePort int    `toml:"relay_remote_port,omitempty"`
	RelayTLSSHA256  string `toml:"relay_tls_sha256,omitempty"`
}

// Encode renders the blob as single-line base64 TOML.
func Encode(b *Blob) (string, error) {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// Decode parses a blob, tolerating whitespace/newlines from copy-paste.
func Decode(s string) (*Blob, error) {
	s = strings.Join(strings.Fields(s), "")
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("pairing blob is not valid base64: %w", err)
	}
	var b Blob
	if _, err := toml.Decode(string(raw), &b); err != nil {
		return nil, fmt.Errorf("pairing blob is not valid TOML: %w", err)
	}
	if b.Version != Version {
		return nil, fmt.Errorf("pairing blob version %d, this build understands %d", b.Version, Version)
	}
	if !config.ValidKey(b.ServerPublicKey) || !config.ValidKey(b.ClientPrivateKey) || !config.ValidKey(b.PresharedKey) {
		return nil, errors.New("pairing blob contains an invalid key")
	}
	return &b, nil
}

// ClientConfig turns a blob into a connect-mode config + secrets.
func (b *Blob) ClientConfig() (*config.Config, *config.Secrets) {
	c := config.Default()
	c.Mode = config.ModeConnect
	c.WireGuard.Subnet = b.Subnet
	c.WireGuard.SelfIP = b.ClientIP
	c.WireGuard.Subnet6 = b.Subnet6
	c.WireGuard.SelfIP6 = b.ClientIP6
	if b.MTU > 0 {
		c.WireGuard.MTU = b.MTU
	}
	c.WireGuard.Keepalive = b.Keepalive
	c.Peer.PublicKey = b.ServerPublicKey
	c.Transport.Endpoint = b.Endpoint
	c.Transport.Port = b.Port
	if b.ServerWGPort > 0 {
		c.Transport.RemoteUDPPort = b.ServerWGPort
	}
	c.Transport.TLSSHA256 = b.TLSSHA256
	c.Transport.PathPrefix = b.PathPrefix
	if b.TransportKind == config.TransportReality {
		c.Transport.Kind = config.TransportReality
		c.Transport.Reality = config.Reality{ServerName: b.RealityServerName, Target: b.RealityTarget,
			PublicKey: b.RealityPublicKey, ShortID: b.RealityShortID, Fingerprint: b.RealityFingerprint}
		if c.Transport.Reality.Fingerprint == "" {
			c.Transport.Reality.Fingerprint = config.Default().Transport.Reality.Fingerprint
		}
	}
	c.Reachability.Mode = b.ReachMode
	if b.ReachMode == config.ReachRelay {
		c.Reachability.Relay = config.Relay{
			Host: b.RelayHost, Port: b.RelayPort, RemotePort: b.RelayRemotePort, TLSSHA256: b.RelayTLSSHA256,
		}
	}
	dns := []string{hostOnly(b.ServerIP)}
	if b.ServerIP6 != "" {
		dns = append(dns, hostOnly(b.ServerIP6))
	}
	c.Client.DNS = strings.Join(dns, ", ")
	c.Client.TunnelIPv6 = b.Subnet6 != ""
	return c, &config.Secrets{PrivateKey: b.ClientPrivateKey, PresharedKey: b.PresharedKey, RealityUUID: b.RealityUUID}
}

func hostOnly(s string) string {
	if a, err := config.ParsePrefixHost(s); err == nil {
		return a.String()
	}
	return s
}
