// Package doctor runs pre-flight and live diagnostics (§8) and prints each
// result with a concrete remedy. serve/connect run the pre-flight subset.
package doctor

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"time"

	"backhaul/internal/config"
	"backhaul/internal/health"
	"backhaul/internal/osutil"
	"backhaul/internal/state"
	"backhaul/internal/tlspin"
	"backhaul/internal/transport"
	"backhaul/internal/wg"
)

// Status of a check.
type Status string

const (
	Pass Status = "PASS"
	Fail Status = "FAIL"
	Warn Status = "WARN"
	Skip Status = "SKIP"
)

// Result of one check.
type Result struct {
	Name   string
	Status Status
	Detail string
	Remedy string
}

// Doctor holds what checks need.
type Doctor struct {
	Cfg   *config.Config
	Paths config.Paths
}

// Preflight runs the checks serve/connect need before touching the system.
func (d *Doctor) Preflight(ctx context.Context) []Result {
	rs := []Result{d.privileges()}
	if d.Cfg.Mode == config.ModeConnect {
		rs = append(rs, d.endpointReachable(ctx)...)
	} else if d.Cfg.Reachability.Mode == config.ReachPortForward {
		rs = append(rs, d.portFree())
	}
	return rs
}

// All runs every applicable check.
func (d *Doctor) All(ctx context.Context) []Result {
	rs := []Result{d.privileges(), d.wstunnelInstalled()}
	if runtime.GOOS == "windows" && d.Cfg.WireGuard.Engine == config.EngineEmbedded {
		rs = append(rs, d.wintun())
	}
	rt, running := d.running()
	if d.Cfg.Mode == config.ModeConnect {
		rs = append(rs, d.endpointReachable(ctx)...)
	} else {
		if !running && d.Cfg.Reachability.Mode == config.ReachPortForward {
			rs = append(rs, d.portFree())
		}
		rs = append(rs, d.ddnsPointsHere(ctx))
	}
	if !running {
		rs = append(rs, Result{Name: "live tunnel checks", Status: Skip,
			Detail: "backhaul is not running", Remedy: "start `backhaul " + d.Cfg.Mode + "` in another terminal and re-run `backhaul doctor`"})
		return rs
	}
	rs = append(rs, d.handshake(rt))
	if d.Cfg.Mode == config.ModeConnect {
		rs = append(rs, d.ipLeak(ctx, rt), d.dnsLeak(ctx), d.ipv6Leak(ctx, rt))
	}
	return rs
}

// Failed reports whether any result is a failure.
func Failed(rs []Result) bool {
	for _, r := range rs {
		if r.Status == Fail {
			return true
		}
	}
	return false
}

// Print renders results as a checklist.
func Print(w io.Writer, rs []Result) {
	for _, r := range rs {
		fmt.Fprintf(w, "[%s] %s", r.Status, r.Name)
		if r.Detail != "" {
			fmt.Fprintf(w, " — %s", r.Detail)
		}
		fmt.Fprintln(w)
		if r.Remedy != "" && (r.Status == Fail || r.Status == Warn || r.Status == Skip) {
			fmt.Fprintf(w, "       ↳ %s\n", r.Remedy)
		}
	}
}

func (d *Doctor) running() (*state.Runtime, bool) {
	rt, ok, err := state.Read(d.Paths.State())
	if err != nil || !ok {
		return nil, false
	}
	return rt, rt.Fresh(3 * d.Cfg.Health.Interval.Duration)
}

func (d *Doctor) privileges() Result {
	if osutil.IsElevated() {
		return Result{Name: "privileges", Status: Pass, Detail: "running elevated"}
	}
	return Result{Name: "privileges", Status: Warn, Detail: "not running as admin/root",
		Remedy: "serve/connect need it: " + osutil.ElevationHint()}
}

func (d *Doctor) wstunnelInstalled() Result {
	if p, ok := transport.FindWstunnel(d.Cfg, d.Paths.Bin()); ok {
		return Result{Name: "wstunnel binary", Status: Pass, Detail: p}
	}
	return Result{Name: "wstunnel binary", Status: Warn, Detail: "not installed",
		Remedy: "it is downloaded (checksum-verified) on first serve/connect; or set transport.wstunnel_path"}
}

func (d *Doctor) wintun() Result {
	p, _ := wg.WintunPath()
	if _, err := os.Stat(p); err == nil {
		return Result{Name: "wintun driver", Status: Pass, Detail: p}
	}
	return Result{Name: "wintun driver", Status: Warn, Detail: "wintun.dll not next to backhaul.exe",
		Remedy: "it is downloaded (checksum-verified) on first serve/connect"}
}

func (d *Doctor) endpointReachable(ctx context.Context) []Result {
	host, port, fp := d.Cfg.RemoteHost()
	timeout := d.Cfg.Transport.DialTimeout.Duration
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(rctx, host)
	if err != nil {
		return []Result{{Name: "endpoint DNS", Status: Fail, Detail: fmt.Sprintf("cannot resolve %s: %v", host, err),
			Remedy: "check transport.endpoint and that your DDNS updater is running on the exit node"}}
	}
	rs := []Result{{Name: "endpoint DNS", Status: Pass, Detail: fmt.Sprintf("%s → %v", host, ips)}}
	addr := net.JoinHostPort(ips[0], strconv.Itoa(port))
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return append(rs, Result{Name: "endpoint TCP reachability", Status: Fail,
			Detail: fmt.Sprintf("cannot reach exit node on :%d — is the port forwarded / DDNS pointing correctly? (%v)", port, err),
			Remedy: fmt.Sprintf("on the router, forward TCP %d to the exit node's LAN IP; confirm `backhaul serve` is running; confirm %s resolves to the exit node's public IP", port, host)})
	}
	c.Close()
	rs = append(rs, Result{Name: "endpoint TCP reachability", Status: Pass, Detail: addr})
	got, err := tlspin.Probe(rctx, addr, host)
	switch {
	case err != nil:
		rs = append(rs, Result{Name: "TLS fingerprint", Status: Fail, Detail: err.Error(),
			Remedy: "something on that port is not speaking TLS — is another service using it?"})
	case got != tlspin.Normalize(fp):
		rs = append(rs, Result{Name: "TLS fingerprint", Status: Fail, Detail: fmt.Sprintf("server presents %s, pinned %s", got, fp),
			Remedy: "if you regenerated the exit node's cert, re-pair with `backhaul setup --import`; otherwise this may be a MITM — do not connect"})
	default:
		rs = append(rs, Result{Name: "TLS fingerprint", Status: Pass, Detail: "matches pinned certificate"})
	}
	return rs
}

func (d *Doctor) portFree() Result {
	addr := net.JoinHostPort(d.Cfg.Transport.ListenAddr, strconv.Itoa(d.Cfg.Transport.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return Result{Name: "listen port free", Status: Fail, Detail: fmt.Sprintf("%s: %v", addr, err),
			Remedy: "stop the service using the port (web server?) or change transport.port on both machines"}
	}
	ln.Close()
	return Result{Name: "listen port free", Status: Pass, Detail: addr}
}

func (d *Doctor) ddnsPointsHere(ctx context.Context) Result {
	host := d.Cfg.Transport.Endpoint
	if d.Cfg.Reachability.Mode != config.ReachPortForward || host == "" {
		return Result{Name: "DDNS / endpoint points here", Status: Skip, Detail: "not in port-forward mode"}
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return Result{Name: "DDNS / endpoint points here", Status: Skip, Detail: "endpoint is a literal IP"}
	}
	timeout := d.Cfg.Health.ProbeTimeout.Duration
	pub, err := health.EgressIP(ctx, d.Cfg.Health.IPCheckURL, "tcp4", timeout)
	if err != nil {
		return Result{Name: "DDNS / endpoint points here", Status: Warn, Detail: "cannot fetch public IP: " + err.Error()}
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(rctx, host)
	if err != nil {
		return Result{Name: "DDNS / endpoint points here", Status: Fail, Detail: err.Error(),
			Remedy: "configure [ddns] or point the hostname's A record at " + pub.String()}
	}
	for _, ip := range ips {
		if ip == pub.String() {
			return Result{Name: "DDNS / endpoint points here", Status: Pass, Detail: host + " → " + ip}
		}
	}
	return Result{Name: "DDNS / endpoint points here", Status: Fail, Detail: fmt.Sprintf("%s → %v but this machine's public IP is %s", host, ips, pub),
		Remedy: "update DNS (enable [ddns]) — the client will dial the wrong address"}
}

func (d *Doctor) handshake(rt *state.Runtime) Result {
	st, err := wg.StatsViaWgctrl(rt.Iface)
	if err != nil {
		st = wg.Stats{LastHandshake: rt.LastHandshake} // fall back to the runtime snapshot
	}
	if st.LastHandshake.IsZero() {
		return Result{Name: "WireGuard handshake", Status: Fail, Detail: "no handshake yet",
			Remedy: "check that both sides have matching keys (re-pair) and that the transport is ready (`backhaul status`)"}
	}
	age := time.Since(st.LastHandshake).Round(time.Second)
	if age > d.Cfg.Health.HandshakeTimeout.Duration {
		return Result{Name: "WireGuard handshake", Status: Fail, Detail: fmt.Sprintf("last handshake %s ago", age),
			Remedy: "the tunnel is stalled; the health loop will reconnect — check the exit node's logs"}
	}
	return Result{Name: "WireGuard handshake", Status: Pass, Detail: fmt.Sprintf("%s ago", age)}
}

func (d *Doctor) ipLeak(ctx context.Context, rt *state.Runtime) Result {
	ip, err := health.EgressIP(ctx, d.Cfg.Health.IPCheckURL, "tcp4", d.Cfg.Health.ProbeTimeout.Duration)
	if err != nil {
		return Result{Name: "IP leak test", Status: Fail, Detail: "cannot fetch egress IP: " + err.Error(),
			Remedy: "the tunnel may be down (kill-switch blocking) — check `backhaul status`"}
	}
	if rt.RealIP != "" && ip.String() == rt.RealIP {
		return Result{Name: "IP leak test", Status: Fail, Detail: "egress IP " + ip.String() + " is this machine's real IP",
			Remedy: "routing is not going through the tunnel; restart `backhaul connect` and check its logs"}
	}
	want := d.Cfg.Client.ExpectedExitIP
	if want == "" && d.Cfg.Reachability.Mode == config.ReachPortForward {
		want = rt.EndpointIP
	}
	if want != "" && ip.String() != want {
		return Result{Name: "IP leak test", Status: Fail, Detail: fmt.Sprintf("egress IP %s, expected exit IP %s", ip, want),
			Remedy: "if the exit node's public IP differs from its endpoint IP, set client.expected_exit_ip"}
	}
	return Result{Name: "IP leak test", Status: Pass, Detail: "egress IP " + ip.String()}
}

func (d *Doctor) dnsLeak(ctx context.Context) Result {
	dns, err := d.Cfg.DNSServers()
	if err != nil || len(dns) == 0 {
		return Result{Name: "DNS leak test", Status: Skip, Detail: "client.dns not set"}
	}
	leak, detail, err := health.DNSLeak(ctx, dns[0], d.Cfg.Health.DNSLeakName, d.Cfg.Health.ProbeTimeout.Duration)
	switch {
	case err != nil:
		return Result{Name: "DNS leak test", Status: Fail, Detail: err.Error(),
			Remedy: "is serve.dns_forwarder enabled on the exit node?"}
	case leak:
		return Result{Name: "DNS leak test", Status: Fail, Detail: detail,
			Remedy: "system DNS is bypassing the tunnel; restart connect, and keep the kill-switch on"}
	default:
		return Result{Name: "DNS leak test", Status: Pass, Detail: detail}
	}
}

func (d *Doctor) ipv6Leak(ctx context.Context, rt *state.Runtime) Result {
	ip, err := health.EgressIP(ctx, d.Cfg.Health.IPv6CheckURL, "tcp6", d.Cfg.Health.ProbeTimeout.Duration)
	if err != nil {
		// No IPv6 path at all (disabled or blocked by the kill-switch) cannot leak.
		return Result{Name: "IPv6 leak test", Status: Pass, Detail: "no IPv6 egress (" + err.Error() + ")"}
	}
	if iface, ok := health.LocalAddrs(rt.Iface)[ip]; ok {
		return Result{Name: "IPv6 leak test", Status: Fail, Detail: fmt.Sprintf("IPv6 egress %s is this machine's own address on %s", ip, iface),
			Remedy: "set client.tunnel_ipv6 = false (disables v6 for the session) and reconnect"}
	}
	return Result{Name: "IPv6 leak test", Status: Pass, Detail: "IPv6 egress " + ip.String() + " (not a local address)"}
}
