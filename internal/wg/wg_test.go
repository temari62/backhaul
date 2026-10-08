package wg

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"backhaul/internal/keys"
)

func settings(t *testing.T) Settings {
	a, _ := keys.NewPair()
	b, _ := keys.NewPair()
	psk, _ := keys.NewPresharedKey()
	return Settings{
		Interface: "wg0", PrivateKey: a.Private, PresharedKey: psk, PeerPublicKey: b.Public,
		PeerEndpoint: "127.0.0.1:51821", AllowedIPs: []string{"0.0.0.0/0", "::/0"}, Keepalive: 25, MTU: 1280,
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.9.0.2/24")},
	}
}

func TestUAPIConfig(t *testing.T) {
	s := settings(t)
	cfg, err := uapiConfig(s, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"private_key=", "listen_port=0", "replace_peers=true", "public_key=", "preshared_key=",
		"endpoint=127.0.0.1:51821", "persistent_keepalive_interval=25", "allowed_ip=0.0.0.0/0", "allowed_ip=::/0"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(cfg, s.PrivateKey) {
		t.Error("UAPI must use hex keys, not base64")
	}
	peerOnly, _ := uapiConfig(s, false)
	if strings.Contains(peerOnly, "private_key") {
		t.Error("kick config must not touch the interface")
	}
}

func TestParseUAPIStats(t *testing.T) {
	st := parseUAPIStats("public_key=ab\nendpoint=127.0.0.1:51821\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\nrx_bytes=10\ntx_bytes=20\nerrno=0\n")
	if !st.LastHandshake.Equal(time.Unix(1700000000, 5)) || st.RxBytes != 10 || st.TxBytes != 20 || st.Endpoint != "127.0.0.1:51821" {
		t.Fatalf("%+v", st)
	}
	if !parseUAPIStats("last_handshake_time_sec=0\n").LastHandshake.IsZero() {
		t.Fatal("zero handshake should be zero time")
	}
}

func TestRenderWGQuick(t *testing.T) {
	s := settings(t)
	conf := renderWGQuick(s)
	for _, want := range []string{"Table = off", "Address = 10.9.0.2/24", "MTU = 1280", "Endpoint = 127.0.0.1:51821", "AllowedIPs = 0.0.0.0/0, ::/0"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "DNS") {
		t.Error("DNS must be handled by internal/route, not wg-quick")
	}
}
