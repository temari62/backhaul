package health

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"backhaul/internal/ddns"
)

// EgressIP fetches the public IP seen by checkURL. network is "tcp", "tcp4"
// or "tcp6" to force an address family.
func EgressIP(ctx context.Context, checkURL, network string, timeout time.Duration) (netip.Addr, error) {
	d := &net.Dialer{Timeout: timeout}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout: timeout,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: timeout}
	s, err := ddns.PublicIP(ctx, c, checkURL)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(s)
}

// ResolveSystem looks up name with the OS resolver (what apps use).
func ResolveSystem(ctx context.Context, name string) ([]string, error) {
	r := &net.Resolver{}
	return r.LookupHost(ctx, name)
}

// ResolveVia looks up name by querying server ("10.9.0.1") directly.
func ResolveVia(ctx context.Context, server netip.Addr, name string, timeout time.Duration) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, netip.AddrPortFrom(server, 53).String())
		},
	}
	return r.LookupHost(ctx, name)
}

// DNSLeak compares what a "whoami" name (which answers with the IP of the
// recursive resolver asking for it) resolves to through the system resolver
// vs. directly through the tunnel resolver. Different answers mean system DNS
// is not going through the tunnel.
func DNSLeak(ctx context.Context, tunnelDNS netip.Addr, whoami string, timeout time.Duration) (leak bool, detail string, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	sys, err := ResolveSystem(ctx, whoami)
	if err != nil {
		return false, "", fmt.Errorf("system resolver: %w", err)
	}
	tun, err := ResolveVia(ctx, tunnelDNS, whoami, timeout)
	if err != nil {
		return false, "", fmt.Errorf("tunnel resolver %s: %w", tunnelDNS, err)
	}
	sort.Strings(sys)
	sort.Strings(tun)
	s, t := strings.Join(sys, ","), strings.Join(tun, ",")
	if s != t {
		return true, fmt.Sprintf("system resolver egress %s ≠ tunnel resolver egress %s", s, t), nil
	}
	return false, "resolver egress " + s, nil
}

// LocalAddrs returns every address on local interfaces except skipIface.
func LocalAddrs(skipIface string) map[netip.Addr]string {
	out := map[netip.Addr]string{}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Name == skipIface {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				out[p.Addr().Unmap()] = i.Name
			}
		}
	}
	return out
}
