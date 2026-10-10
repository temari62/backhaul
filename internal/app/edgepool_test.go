package app

import (
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"backhaul/internal/tlspin"
)

func TestEdgeCandidates(t *testing.T) {
	resolved := []netip.Addr{netip.MustParseAddr("172.67.207.229"), netip.MustParseAddr("104.21.5.9"), netip.MustParseAddr("2606:4700::1")}
	got := edgeCandidates(resolved, rand.New(rand.NewPCG(1, 2)))
	if got[0] != resolved[0] || got[1] != resolved[1] {
		t.Fatalf("hostname's own addresses must come first: %v", got)
	}
	seen := map[netip.Addr]bool{}
	sameNet := 0
	for _, a := range got {
		if !a.Is4() || seen[a] {
			t.Fatalf("want unique IPv4 only: %v", got)
		}
		seen[a] = true
		inCF := false
		for _, pf := range cloudflareRanges {
			inCF = inCF || pf.Contains(a)
		}
		if b := a.As4(); b[0] == 172 && b[1] == 67 && b[2] == 207 && a != resolved[0] {
			sameNet++
		}
		if !inCF {
			t.Fatalf("%s is not in Cloudflare's ranges", a)
		}
		if b := a.As4()[3]; b == 0 || b == 255 {
			t.Fatalf("network/broadcast-looking address %s", a)
		}
	}
	if sameNet == 0 || len(got) < 10 {
		t.Fatalf("pool too small or lacks same-/24 neighbours: %v", got)
	}
}

func TestEdgePoolSwitchesOncePerFailure(t *testing.T) {
	a, b, c := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")
	p := newEdgePool([]netip.Addr{a, b, c}, 443)
	first := p.Current()
	p.Trouble(first, "cut")
	p.Trouble(first, "dial failed") // a second report about the old address must not skip b
	if p.Addr() != b {
		t.Fatalf("now %s, want %s", p.Addr(), b)
	}
	p.Trouble(p.Current(), "x")
	p.Trouble(p.Current(), "x")
	if p.Addr() != a {
		t.Fatalf("should wrap around to the first address, got %s", p.Addr())
	}
	single := newEdgePool([]netip.Addr{a}, 443)
	single.Trouble(single.Current(), "x")
	if single.Addr() != a {
		t.Fatal("single-address pool changed")
	}
}

// End to end through the proxy: a blocked first address (nothing listening)
// makes the proxy move to the next one, and the next connection gets through.
func TestProxyMovesPastBlockedAddress(t *testing.T) {
	good, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { go good.Close() }()
	go func() {
		for {
			c, err := good.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(time.Second); c.Close() }()
		}
	}()
	port := good.Addr().(*net.TCPAddr).Port
	dead, _ := net.Listen("tcp", "127.0.0.2:"+strconv.Itoa(port))
	if dead != nil {
		dead.Close() // free again: dials to 127.0.0.2 are refused
	}
	p := newEdgePool([]netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}, port)
	proxy, err := tlspin.NewProxy(p.Current, "vpn.example.test", "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	proxy.OnTrouble = p.Trouble
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go proxy.Serve(ctx)
	defer proxy.Close()

	c, err := net.Dial("tcp", proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for p.Addr() != netip.MustParseAddr("127.0.0.1") {
		if time.Now().After(deadline) {
			t.Fatal("proxy did not move past the refused address")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
