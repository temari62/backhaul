package app

import (
	"encoding/base64"
	"strings"
	"testing"

	"backhaul/internal/config"
	"backhaul/internal/keys"
	"backhaul/internal/tlspin"
)

func TestSetupExitNodeAndImport(t *testing.T) {
	p := config.Paths{Dir: t.TempDir()}
	res, err := SetupExitNode(p, ExitNodeOptions{
		Endpoint: "myhome.duckdns.org", Port: 443, Subnet: "10.9.0.0/24", Subnet6: "fd09:b4c0::/64",
		ReachMode: config.ReachPortForward,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := res.Config
	if srv.WireGuard.SelfIP != "10.9.0.1/32" || srv.Peer.AllowedIPs[0] != "10.9.0.2/32" || srv.Peer.AllowedIPs[1] != "fd09:b4c0::2/128" {
		t.Fatalf("server addressing: %+v %+v", srv.WireGuard, srv.Peer)
	}
	if fp, _ := tlspin.FileFingerprint(p.Cert()); fp != res.Fingerprint {
		t.Fatal("cert on disk does not match pinned fingerprint")
	}

	cli, cliSec, err := ImportBlob(res.Blob)
	if err != nil {
		t.Fatal(err)
	}
	// The two sides must agree on keys.
	srvPub, _ := keys.PublicFromPrivate(res.Secrets.PrivateKey)
	cliPub, _ := keys.PublicFromPrivate(cliSec.PrivateKey)
	if cli.Peer.PublicKey != srvPub || srv.Peer.PublicKey != cliPub || cliSec.PresharedKey != res.Secrets.PresharedKey {
		t.Fatal("key exchange mismatch")
	}
	if cli.Transport.TLSSHA256 != res.Fingerprint || cli.Transport.PathPrefix != srv.Transport.PathPrefix {
		t.Fatal("transport pin/prefix mismatch")
	}
	if cli.WireGuard.SelfIP != "10.9.0.2/32" || cli.Client.DNS != "10.9.0.1, fd09:b4c0::1" || cli.Transport.RemoteUDPPort != srv.WireGuard.ListenPort {
		t.Fatalf("client config: %+v %+v", cli.WireGuard, cli.Client)
	}
}

func TestSetupExitNodeNoIPv6AndRelay(t *testing.T) {
	p := config.Paths{Dir: t.TempDir()}
	fp := "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
	res, err := SetupExitNode(p, ExitNodeOptions{
		Endpoint: "203.0.113.5", Port: 8443, Subnet: "10.77.0.0/24", ReachMode: config.ReachRelay,
		Relay: config.Relay{Host: "vps.example.com", Port: 443, RemotePort: 51820, TLSSHA256: fp},
	})
	if err != nil {
		t.Fatal(err)
	}
	cli, _, err := ImportBlob(res.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if cli.Client.TunnelIPv6 || cli.WireGuard.SelfIP6 != "" {
		t.Fatal("IPv6 should be off when no subnet6 is given")
	}
	host, port, pin := cli.RemoteHost()
	if host != "vps.example.com" || port != 443 || pin != fp {
		t.Fatalf("relay remote: %s %d %s", host, port, pin)
	}
}

func TestSetupRejectsBadSubnet(t *testing.T) {
	if _, err := SetupExitNode(config.Paths{Dir: t.TempDir()}, ExitNodeOptions{Endpoint: "x", Port: 443, Subnet: "10.9.0.0/31", ReachMode: config.ReachPortForward}); err == nil {
		t.Fatal("expected error for /31")
	}
}

func TestSetupRealityPairing(t *testing.T) {
	p := config.Paths{Dir: t.TempDir()}
	res, err := SetupExitNode(p, ExitNodeOptions{Endpoint: "50.46.184.113", Port: 443, Subnet: "10.9.0.0/24",
		ReachMode: config.ReachPortForward, Transport: config.TransportReality})
	if err != nil {
		t.Fatal(err)
	}
	srv, ssec := res.Config, res.Secrets
	if srv.Transport.Kind != config.TransportReality || ssec.RealityPrivateKey == "" || ssec.RealityUUID == "" {
		t.Fatalf("server not configured for REALITY: %+v", srv.Transport)
	}
	cli, csec, err := ImportBlob(res.Blob)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := keys.RealityPublicFromPrivate(ssec.RealityPrivateKey)
	if cli.Transport.Kind != config.TransportReality || cli.Transport.Reality.PublicKey != pub ||
		cli.Transport.Reality.ShortID != srv.Transport.Reality.ShortID || csec.RealityUUID != ssec.RealityUUID ||
		cli.Transport.Reality.ServerName != "www.amazon.com" {
		t.Fatalf("client REALITY settings don't match the exit node:\n%+v\n%+v", cli.Transport.Reality, srv.Transport.Reality)
	}
	raw, _ := base64.StdEncoding.DecodeString(res.Blob)
	if csec.RealityPrivateKey != "" || len(raw) == 0 || strings.Contains(string(raw), ssec.RealityPrivateKey) {
		t.Fatal("the exit node's REALITY private key must never leave it")
	}
}
