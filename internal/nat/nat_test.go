package nat

import (
	"net/netip"
	"strings"
	"testing"
)

func TestNftRules(t *testing.T) {
	s := NftRules("backhaul_nat", Plan{Iface: "wg0", WAN: "eth0",
		Subnet4: netip.MustParsePrefix("10.9.0.1/24"), Subnet6: netip.MustParsePrefix("fd09:b4c0::1/64")})
	for _, want := range []string{
		`ip saddr 10.9.0.0/24 oifname "eth0" masquerade`,
		`ip6 saddr fd09:b4c0::/64 oifname "eth0" masquerade`,
		"maxseg size set rt mtu",
		`iifname "wg0" accept`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
}

func TestPfRulesNoV6(t *testing.T) {
	s := PfRules(Plan{WAN: "en0", Subnet4: netip.MustParsePrefix("10.9.0.0/24")})
	if s != "nat on en0 inet from 10.9.0.0/24 to any -> (en0)\n" {
		t.Fatalf("got %q", s)
	}
}
