package route

import (
	"net/netip"
	"strings"
	"testing"
)

func ksPlan() Plan {
	return Plan{Iface: "wg0", EndpointPort: 443,
		Endpoints:   addrs("50.46.184.113"),
		TunnelAddrs: []netip.Addr{netip.MustParseAddr("10.9.0.2"), netip.MustParseAddr("fd09:b4c0::2")}}
}

func TestWindowsKillSwitchScript(t *testing.T) {
	s := WindowsKillSwitchScript("backhaul", ksPlan())
	for _, want := range []string{
		"'0.0.0.0-10.9.0.1','10.9.0.3-255.255.255.255'",                           // every source but the tunnel IP
		"'::1:0:0-::fffe:ffff:ffff','::1:0:0:0-fd09:b4c0::1','fd09:b4c0::3-ffff:", // IPv6 likewise, never touching IPv4-mapped space
		"'0.0.0.0-50.46.184.112','50.46.184.114-255.255.255.255'",                 // every destination but the exit node
		"Profile = 'Any'",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "InterfaceAlias") || strings.Contains(s, "Get-NetAdapter") {
		t.Error("must not depend on adapter names (hidden adapters break New-NetFirewallRule)")
	}
}

func TestParseEndpointRouteCheck(t *testing.T) {
	for out, want := range map[string]EndpointRouteCheck{
		"ok\r\n":             {State: EndpointRouteOK},
		"none":               {State: EndpointRouteOffline},
		"12 192.168.1.1\r\n": {State: EndpointRouteRepair, IfIndex: "12", NextHop: "192.168.1.1"},
	} {
		got, err := ParseEndpointRouteCheck(out)
		if err != nil || got != want {
			t.Errorf("%q: got %+v, %v", out, got, err)
		}
	}
	if _, err := ParseEndpointRouteCheck("garbage output here"); err == nil {
		t.Error("garbage accepted")
	}
}

func TestUnixOtherVPNs(t *testing.T) {
	linux := `default via 192.168.1.1 dev wlan0 proto dhcp metric 600
0.0.0.0/1 dev tun0 scope link
128.0.0.0/1 dev tun0 scope link
0.0.0.0/1 dev wg0 scope link
10.9.0.0/24 dev wg0 proto kernel scope link src 10.9.0.2`
	if got := UnixOtherVPNs(linux, "wg0"); len(got) != 1 || got[0] != "tun0" {
		t.Fatalf("linux: %v", got)
	}
	mac := `Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGScg          en0
0/1                10.8.0.1           UGScg        utun5
128.0/1            10.8.0.1           UGScg        utun5`
	if got := UnixOtherVPNs(mac, "utun3"); len(got) != 1 || got[0] != "utun5" {
		t.Fatalf("mac: %v", got)
	}
	if got := UnixOtherVPNs(mac, "utun5"); len(got) != 0 {
		t.Fatalf("own interface reported: %v", got)
	}
}

// The bug behind "kill switch blocks the exit node": IPv6 ranges that cover
// IPv4-mapped/compatible space make Windows block IPv4 destinations too.
func TestComplementNeverCoversIPv4EmbeddedSpace(t *testing.T) {
	inRange := func(r string, a netip.Addr) bool {
		lo, hi, _ := strings.Cut(r, "-")
		l, h := netip.MustParseAddr(lo), netip.MustParseAddr(hi)
		return !a.Less(l) && !h.Less(a)
	}
	probes := []netip.Addr{
		netip.MustParseAddr("::ffff:50.46.184.113"), netip.MustParseAddr("::ffff:0.0.0.0"),
		netip.MustParseAddr("::ffff:255.255.255.255"), netip.MustParseAddr("::50.46.184.113"),
	}
	for _, except := range [][]netip.Addr{nil, addrs("fd09:b4c0::2"), addrs("2001:db8::1", "50.46.184.113")} {
		for _, r := range Complement(true, except) {
			for _, p := range probes {
				if inRange(r, p) {
					t.Fatalf("IPv6 range %s covers IPv4-embedded address %s", r, p)
				}
			}
		}
	}
	// And real IPv6 space is still covered (the kill switch must block it).
	all := Complement(true, nil)
	for _, a := range []string{"2001:db8::5", "fe80::1", "fd00::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		hit := false
		for _, r := range all {
			hit = hit || inRange(r, netip.MustParseAddr(a))
		}
		if !hit {
			t.Fatalf("%s not covered by %v", a, all)
		}
	}
	// IPv4: the exit node is excluded, everything else covered.
	for _, r := range Complement(false, addrs("50.46.184.113")) {
		if inRange(r, netip.MustParseAddr("50.46.184.113")) {
			t.Fatal("exit node inside an IPv4 block range")
		}
	}
}
