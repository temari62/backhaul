package route

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

func TestComplement(t *testing.T) {
	got := Complement(false, addrs("203.0.113.7", "::1"))
	want := []string{"0.0.0.0-203.0.113.6", "203.0.113.8-255.255.255.255"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if got := Complement(false, nil); !reflect.DeepEqual(got, []string{"0.0.0.0-255.255.255.255"}) {
		t.Fatalf("empty: %v", got)
	}
	if got := Complement(false, addrs("0.0.0.0", "255.255.255.255")); !reflect.DeepEqual(got, []string{"0.0.0.1-255.255.255.254"}) {
		t.Fatalf("edges: %v", got)
	}
	if got := Complement(true, addrs("2001:db8::1")); len(got) != 2 || !strings.HasPrefix(got[1], "2001:db8::2-") {
		t.Fatalf("v6: %v", got)
	}
}

func TestNftKillSwitch(t *testing.T) {
	s := NftKillSwitch("backhaul_ks", Plan{Iface: "wg0", Endpoints: addrs("203.0.113.7", "127.0.0.1"), EndpointPort: 443})
	for _, want := range []string{"policy drop", `oifname "wg0" accept`, "ip daddr { 203.0.113.7 } tcp dport 443 accept", `oifname "lo" accept`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "127.0.0.1") {
		t.Error("loopback endpoint should not get a rule")
	}
}

func TestPfKillSwitch(t *testing.T) {
	s := PfKillSwitch(Plan{Iface: "utun4", Endpoints: addrs("2001:db8::7"), EndpointPort: 443})
	if !strings.Contains(s, "pass out quick on utun4 all") || !strings.Contains(s, "inet6 proto tcp from any to 2001:db8::7 port 443") ||
		!strings.HasSuffix(s, "block drop out quick all\n") {
		t.Fatalf("bad rules:\n%s", s)
	}
}

func TestHostPrefix(t *testing.T) {
	if HostPrefix(netip.MustParseAddr("1.2.3.4")).String() != "1.2.3.4/32" ||
		HostPrefix(netip.MustParseAddr("2001:db8::1")).String() != "2001:db8::1/128" {
		t.Fatal("bad host prefix")
	}
}
