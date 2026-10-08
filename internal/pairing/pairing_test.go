package pairing

import (
	"encoding/base64"
	"strings"
	"testing"

	"backhaul/internal/config"
	"backhaul/internal/keys"
)

func blob(t *testing.T) *Blob {
	srv, _ := keys.NewPair()
	cli, _ := keys.NewPair()
	psk, _ := keys.NewPresharedKey()
	return &Blob{
		Version: Version, ServerPublicKey: srv.Public, ClientPrivateKey: cli.Private, PresharedKey: psk,
		Subnet: "10.9.0.0/24", ServerIP: "10.9.0.1/32", ClientIP: "10.9.0.2/32",
		Subnet6: "fd09:b4c0::/64", ServerIP6: "fd09:b4c0::1/128", ClientIP6: "fd09:b4c0::2/128",
		MTU: 1280, Keepalive: 25, Endpoint: "myhome.duckdns.org", Port: 443, ServerWGPort: 51999,
		TLSSHA256: strings.TrimSuffix(strings.Repeat("0F:", 32), ":"), PathPrefix: "abc123",
		ReachMode: config.ReachPortForward,
	}
}

func TestRoundTrip(t *testing.T) {
	b := blob(t)
	s, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	// Copy-paste mangling: line breaks and indentation must be tolerated.
	mangled := "  " + s[:20] + "\n  " + s[20:] + "\n"
	got, err := Decode(mangled)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *b {
		t.Fatalf("round trip mismatch:\n%+v\n%+v", got, b)
	}
	c, sec := got.ClientConfig()
	if err := config.Validate(c, sec); err != nil {
		t.Fatal(err)
	}
	if c.Client.DNS != "10.9.0.1, fd09:b4c0::1" || c.Transport.RemoteUDPPort != 51999 || !c.Client.TunnelIPv6 {
		t.Fatalf("unexpected client config: dns=%q port=%d v6=%v", c.Client.DNS, c.Transport.RemoteUDPPort, c.Client.TunnelIPv6)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	for name, in := range map[string]string{
		"not base64": "%%%",
		"not toml":   base64.StdEncoding.EncodeToString([]byte("= = =")),
		"wrong ver":  base64.StdEncoding.EncodeToString([]byte("version = 99")),
		"bad keys":   base64.StdEncoding.EncodeToString([]byte("version = 1\nserver_public_key = 'x'")),
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
