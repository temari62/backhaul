package app

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"backhaul/internal/config"
)

// edgePool is the set of addresses the client may connect to, and which one
// is in use. In Cloudflare mode it holds many Cloudflare addresses: any of
// them answers for your hostname, and China's firewall blocks a single
// address (for this client, for minutes) after it flags a connection, so
// moving to another address gets the tunnel back immediately. For the other
// disguises it holds just the exit node's address and never switches.
type edgePool struct {
	mu    sync.Mutex
	addrs []netip.Addr
	port  int
	cur   int
}

func newEdgePool(addrs []netip.Addr, port int) *edgePool {
	return &edgePool{addrs: addrs, port: port}
}

// All returns every address (routes and the kill switch must allow them all).
func (p *edgePool) All() []netip.Addr { return append([]netip.Addr(nil), p.addrs...) }

// Addr is the address in use now.
func (p *edgePool) Addr() netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.addrs[p.cur]
}

// Current is the "ip:port" to dial now.
func (p *edgePool) Current() string { return netip.AddrPortFrom(p.Addr(), uint16(p.port)).String() }

// Trouble reports that addr ("ip:port") failed or was cut, and moves on to
// the next address — unless another failure already moved past it.
func (p *edgePool) Trouble(addr, why string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.addrs) < 2 || netip.AddrPortFrom(p.addrs[p.cur], uint16(p.port)).String() != addr {
		return
	}
	p.cur = (p.cur + 1) % len(p.addrs)
	slog.Warn("switching to another Cloudflare address", "from", addr, "to", p.addrs[p.cur], "why", why)
}

// cloudflareRanges are Cloudflare's anycast ranges that serve proxied
// hostnames (https://www.cloudflare.com/ips/). Any address in them answers
// for any proxied site, chosen by the TLS server name; the client still
// verifies the certificate for your hostname, so a wrong address is merely
// skipped.
var cloudflareRanges = []netip.Prefix{
	netip.MustParsePrefix("104.16.0.0/13"),
	netip.MustParsePrefix("104.24.0.0/14"),
	netip.MustParsePrefix("172.64.0.0/13"),
	netip.MustParsePrefix("188.114.96.0/20"),
}

// edgeCandidates builds the Cloudflare address pool: the hostname's own
// addresses first, then other addresses in the same /24s, then addresses
// from Cloudflare's other ranges — so a block on one address, or one block
// of addresses, still leaves somewhere to go.
func edgeCandidates(resolved []netip.Addr, rnd *rand.Rand) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	add := func(a netip.Addr) {
		if a.IsValid() && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	var v4 []netip.Addr
	for _, a := range resolved {
		if a = a.Unmap(); a.Is4() {
			v4 = append(v4, a)
			add(a)
		}
	}
	for _, a := range v4 {
		for i := 0; i < 2; i++ {
			b := a.As4()
			b[3] = byte(1 + rnd.IntN(254))
			add(netip.AddrFrom4(b))
		}
	}
	for _, pf := range cloudflareRanges {
		for i := 0; i < 2; i++ {
			add(randomHost(pf, rnd))
		}
	}
	return out
}

// randomHost picks an address in pf that doesn't end in .0 or .255.
func randomHost(pf netip.Prefix, rnd *rand.Rand) netip.Addr {
	base := pf.Masked().Addr().As4()
	n := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	size := uint32(1) << (32 - pf.Bits())
	for {
		v := n + rnd.Uint32N(size)
		if b := byte(v); b != 0 && b != 255 {
			return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		}
	}
}

// cloudflarePool is the pinned edge addresses if configured, otherwise the
// automatic pool built around the hostname's own addresses.
func cloudflarePool(ctx context.Context, c *config.Config, host string, port int) (*edgePool, error) {
	if pinned := c.Transport.PinnedEdges(); len(pinned) > 0 {
		var addrs []netip.Addr
		for _, s := range pinned {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("transport.edge_ip(s): %w", err)
			}
			addrs = append(addrs, a)
		}
		return newEdgePool(addrs, port), nil
	}
	resolved, err := resolveAll(ctx, host, c.Transport.DialTimeout.Duration)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	addrs := edgeCandidates(resolved, rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0)))
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: no IPv4 addresses", host)
	}
	slog.Info("Cloudflare addresses to use (switches automatically if one is blocked)", "first", addrs[0], "count", len(addrs))
	return newEdgePool(addrs, port), nil
}

// resolveAll returns every address of host (or host itself if it's an IP).
func resolveAll(ctx context.Context, host string, timeout time.Duration) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// cloudflareDialTimeout: a blocked Cloudflare address shows up as a dial
// timeout; give up on it quickly, as there are others to try.
const cloudflareDialTimeout = 5 * time.Second
