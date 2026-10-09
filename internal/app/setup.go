package app

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"

	"backhaul/internal/config"
	"backhaul/internal/keys"
	"backhaul/internal/pairing"
	"backhaul/internal/tlspin"
)

// ExitNodeOptions are the wizard's answers for the exit node.
type ExitNodeOptions struct {
	Endpoint  string // public hostname (DDNS) or IP the client dials
	Port      int
	Subnet    string
	Subnet6   string // "" disables IPv6 in the tunnel
	ReachMode string
	Relay     config.Relay
	DDNS      config.DDNS
	DDNSToken string
	// Transport is config.TransportWstunnel (default) or config.TransportReality.
	Transport string
	// RealityServerName/Target override the impersonated site (REALITY only).
	RealityServerName, RealityTarget string
}

// SetupResult is what the exit-node setup produced.
type SetupResult struct {
	Config      *config.Config
	Secrets     *config.Secrets
	Blob        string
	Fingerprint string
}

// SetupExitNode generates both keypairs, the PSK, the TLS cert and the
// exit-node config, plus the pairing blob for the client. Nothing is written
// except the TLS cert/key; the caller saves config and blob.
func SetupExitNode(p config.Paths, o ExitNodeOptions) (*SetupResult, error) {
	sn4, err := netip.ParsePrefix(o.Subnet)
	if err != nil || !sn4.Addr().Is4() || sn4.Bits() > 30 {
		return nil, fmt.Errorf("subnet %q must be an IPv4 prefix of /30 or larger", o.Subnet)
	}
	sn4 = sn4.Masked()
	srv4, cli4 := sn4.Addr().Next(), sn4.Addr().Next().Next()
	var sn6 netip.Prefix
	var srv6, cli6 netip.Addr
	if o.Subnet6 != "" {
		if sn6, err = netip.ParsePrefix(o.Subnet6); err != nil || !sn6.Addr().Is6() {
			return nil, fmt.Errorf("subnet6 %q must be an IPv6 prefix", o.Subnet6)
		}
		sn6 = sn6.Masked()
		srv6, cli6 = sn6.Addr().Next(), sn6.Addr().Next().Next()
	}

	srvKeys, err := keys.NewPair()
	if err != nil {
		return nil, err
	}
	cliKeys, err := keys.NewPair()
	if err != nil {
		return nil, err
	}
	psk, err := keys.NewPresharedKey()
	if err != nil {
		return nil, err
	}
	prefix, err := randomToken(12)
	if err != nil {
		return nil, err
	}
	fp, err := tlspin.GenerateSelfSigned(o.Endpoint, p.Cert(), p.Key())
	if err != nil {
		return nil, fmt.Errorf("generate TLS certificate: %w", err)
	}

	c := config.Default()
	c.Mode = config.ModeServe
	c.WireGuard.Subnet = sn4.String()
	c.WireGuard.SelfIP = netip.PrefixFrom(srv4, 32).String()
	c.WireGuard.Subnet6, c.WireGuard.SelfIP6 = "", ""
	c.Peer.PublicKey = cliKeys.Public
	c.Peer.AllowedIPs = []string{netip.PrefixFrom(cli4, 32).String()}
	if sn6.IsValid() {
		c.WireGuard.Subnet6 = sn6.String()
		c.WireGuard.SelfIP6 = netip.PrefixFrom(srv6, 128).String()
		c.Peer.AllowedIPs = append(c.Peer.AllowedIPs, netip.PrefixFrom(cli6, 128).String())
	}
	c.Transport.Endpoint = o.Endpoint
	c.Transport.Port = o.Port
	c.Transport.TLSSHA256 = fp
	c.Transport.PathPrefix = prefix
	c.Reachability.Mode = o.ReachMode
	if o.ReachMode == config.ReachRelay {
		c.Reachability.Relay = o.Relay
	}
	c.DDNS = o.DDNS
	if c.DDNS.Interval.Duration == 0 {
		c.DDNS.Interval = config.Default().DDNS.Interval
	}
	c.Client = config.Client{} // client-only section; keep the serve config uncluttered
	sec := &config.Secrets{PrivateKey: srvKeys.Private, PresharedKey: psk, DDNSToken: o.DDNSToken}

	b := &pairing.Blob{
		Version:         pairing.Version,
		ServerPublicKey: srvKeys.Public, ClientPrivateKey: cliKeys.Private, PresharedKey: psk,
		Subnet: sn4.String(), ServerIP: netip.PrefixFrom(srv4, 32).String(), ClientIP: netip.PrefixFrom(cli4, 32).String(),
		MTU: c.WireGuard.MTU, Keepalive: c.WireGuard.Keepalive,
		Endpoint: o.Endpoint, Port: o.Port, ServerWGPort: c.WireGuard.ListenPort,
		TLSSHA256: fp, PathPrefix: prefix, ReachMode: o.ReachMode,
	}
	if sn6.IsValid() {
		b.Subnet6, b.ServerIP6, b.ClientIP6 = sn6.String(), netip.PrefixFrom(srv6, 128).String(), netip.PrefixFrom(cli6, 128).String()
	}
	if o.ReachMode == config.ReachRelay {
		b.RelayHost, b.RelayPort, b.RelayRemotePort, b.RelayTLSSHA256 = o.Relay.Host, o.Relay.Port, o.Relay.RemotePort, o.Relay.TLSSHA256
	}
	if o.Transport == config.TransportReality {
		if err := setupReality(c, sec, b, o); err != nil {
			return nil, err
		}
	}
	blob, err := pairing.Encode(b)
	if err != nil {
		return nil, err
	}

	// Validate both sides before handing anything to the user.
	if err := config.Validate(c, sec); err != nil {
		return nil, fmt.Errorf("generated exit-node config: %w", err)
	}
	back, err := pairing.Decode(blob)
	if err != nil {
		return nil, fmt.Errorf("pairing blob round-trip: %w", err)
	}
	cc, cs := back.ClientConfig()
	if err := config.Validate(cc, cs); err != nil {
		return nil, fmt.Errorf("generated client config: %w", err)
	}
	return &SetupResult{Config: c, Secrets: sec, Blob: blob, Fingerprint: fp}, nil
}

// ImportBlob converts a pairing blob into a validated client config.
func ImportBlob(blob string) (*config.Config, *config.Secrets, error) {
	b, err := pairing.Decode(blob)
	if err != nil {
		return nil, nil, err
	}
	c, s := b.ClientConfig()
	if err := config.Validate(c, s); err != nil {
		return nil, nil, err
	}
	return c, s, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// setupReality generates the REALITY credentials and records them in the
// exit node's config/secrets and in the pairing blob.
func setupReality(c *config.Config, sec *config.Secrets, b *pairing.Blob, o ExitNodeOptions) error {
	kp, err := keys.NewRealityPair()
	if err != nil {
		return err
	}
	uuid, err := keys.NewUUID()
	if err != nil {
		return err
	}
	sid, err := keys.NewShortID()
	if err != nil {
		return err
	}
	r := config.Default().Transport.Reality
	if o.RealityServerName != "" {
		r.ServerName = o.RealityServerName
		r.Target = o.RealityServerName + ":443"
	}
	if o.RealityTarget != "" {
		r.Target = o.RealityTarget
	}
	r.PublicKey, r.ShortID = kp.Public, sid
	c.Transport.Kind, c.Transport.Reality = config.TransportReality, r
	sec.RealityPrivateKey, sec.RealityUUID = kp.Private, uuid
	b.TransportKind = config.TransportReality
	b.RealityServerName, b.RealityTarget, b.RealityFingerprint = r.ServerName, r.Target, r.Fingerprint
	b.RealityPublicKey, b.RealityShortID, b.RealityUUID = kp.Public, sid, uuid
	return nil
}
