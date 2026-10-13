// Package doctor runs pre-flight and live diagnostics (§8) and prints each
// result with a concrete remedy. serve/connect run the pre-flight subset.
package doctor

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"time"

	"backhaul/internal/config"
	"backhaul/internal/health"
	"backhaul/internal/osutil"
	"backhaul/internal/route"
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
		rs = append(rs, d.otherVPN(ctx))
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
		rs = append(rs, d.otherVPN(ctx))
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
	if p, ok := wg.WintunInstalled(); ok {
		return Result{Name: "wintun driver", Status: Pass, Detail: p}
	}
	return Result{Name: "wintun driver", Status: Warn, Detail: "wintun.dll not installed yet",
		Remedy: "it is downloaded (checksum-verified) on first connect, or bundled in Backhaul.exe"}
}

func (d *Doctor) endpointReachable(ctx context.Context) []Result {
	host, port, fp := d.Cfg.RemoteHost()
	timeout := d.Cfg.Transport.DialTimeout.Duration
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var ips []string
	var err error
	if e := d.Cfg.Transport.EdgeIP; e != "" && d.Cfg.Transport.Kind == config.TransportCloudflare {
		ips = []string{e} // pinned Cloudflare edge address
	} else if ips, err = net.DefaultResolver.LookupHost(rctx, host); err != nil {
		return []Result{{Name: CheckEndpointDNS, Status: Fail, Detail: fmt.Sprintf("cannot resolve %s: %v", host, err),
			Remedy: "check transport.endpoint and that your DDNS updater is running on the exit node"}}
	}
	rs := []Result{{Name: CheckEndpointDNS, Status: Pass, Detail: fmt.Sprintf("%s → %v", host, ips)}}
	addr := net.JoinHostPort(ips[0], strconv.Itoa(port))
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return append(rs, Result{Name: CheckEndpointTCP, Status: Fail,
			Detail: fmt.Sprintf("cannot reach exit node on :%d — is the port forwarded / DDNS pointing correctly? (%v)", port, err),
			Remedy: fmt.Sprintf("on the router, forward TCP %d to the exit node's LAN IP; confirm `backhaul serve` is running; confirm %s resolves to the exit node's public IP", port, host)})
	}
	c.Close()
	rs = append(rs, Result{Name: CheckEndpointTCP, Status: Pass, Detail: addr})
	switch d.Cfg.Transport.Kind {
	case config.TransportReality:
		return append(rs, d.realityCamouflage(rctx, addr))
	case config.TransportCloudflare:
		return append(rs, d.cloudflareChecks(rctx, addr)...)
	}
	got, err := tlspin.Probe(rctx, addr, host)
	switch {
	case err != nil:
		rs = append(rs, Result{Name: CheckTLSPin, Status: Fail, Detail: err.Error(),
			Remedy: "something on that port is not speaking TLS — is another service using it?"})
	case got != tlspin.Normalize(fp):
		rs = append(rs, Result{Name: CheckTLSPin, Status: Fail, Detail: fmt.Sprintf("server presents %s, pinned %s", got, fp),
			Remedy: "if you regenerated the exit node's cert, re-pair with `backhaul setup --import`; otherwise this may be a MITM — do not connect"})
	default:
		rs = append(rs, Result{Name: CheckTLSPin, Status: Pass, Detail: "matches pinned certificate"})
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
	if d.Cfg.Transport.Kind == config.TransportCloudflare {
		// A proxied record resolves to Cloudflare, not to this PC, by design.
		return Result{Name: "DDNS / endpoint points here", Status: Skip, Detail: "Cloudflare mode: the hostname resolves to Cloudflare"}
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

// Names of checks other packages react to.
const (
	CheckEndpointDNS = "endpoint DNS"
	CheckEndpointTCP = "endpoint TCP reachability"
	CheckTLSPin      = "TLS fingerprint"
)

// CheckOtherVPN detects another active full-tunnel VPN on the client.
const CheckOtherVPN = "other VPN"

func (d *Doctor) otherVPN(ctx context.Context) Result {
	vpns, err := route.OtherVPNs(ctx, d.Cfg.WireGuard.Interface)
	switch {
	case err != nil:
		return Result{Name: CheckOtherVPN, Status: Skip, Detail: "could not inspect routes: " + err.Error()}
	case len(vpns) == 0:
		return Result{Name: CheckOtherVPN, Status: Pass, Detail: "none active"}
	case d.Cfg.Client.AllowOtherVPN:
		return Result{Name: CheckOtherVPN, Status: Warn, Detail: "running inside: " + strings.Join(vpns, ", ")}
	}
	return Result{Name: CheckOtherVPN, Status: Fail,
		Detail: "another VPN is connected: " + strings.Join(vpns, ", "),
		Remedy: "disconnect it first — two VPNs fight over the routing table. Backhaul already disguises its traffic as HTTPS. (To run Backhaul inside it deliberately, set client.allow_other_vpn = true.)"}
}

// CheckRealityCamouflage verifies a REALITY exit node is up and disguised.
const CheckRealityCamouflage = "REALITY camouflage"

// realityCamouflage connects like any visitor would (no key) and expects the
// impersonated site's genuine, valid certificate — which only happens when
// the exit node's Xray is running and relaying to its target.
func (d *Doctor) realityCamouflage(ctx context.Context, addr string) Result {
	sni := d.Cfg.Transport.Reality.ServerName
	dl := tls.Dialer{NetDialer: &net.Dialer{Timeout: d.Cfg.Transport.DialTimeout.Duration},
		Config: &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12}}
	c, err := dl.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{Name: CheckRealityCamouflage, Status: Fail, Detail: err.Error(),
			Remedy: "make sure the exit node is Sharing with the REALITY transport (a different program may be on that port)"}
	}
	c.Close()
	return Result{Name: CheckRealityCamouflage, Status: Pass, Detail: "exit node presents a valid certificate for " + sni}
}

// Checks for the Cloudflare transport.
const (
	CheckCloudflareTLS    = "Cloudflare certificate"
	CheckCloudflareOrigin = "Cloudflare → exit node"
)

// cloudflareChecks verifies, through Cloudflare, that (1) the hostname is
// served by a valid certificate and (2) Cloudflare can reach the exit node.
// wstunnel answers a plain HTTPS request with 400; Cloudflare reports its
// own trouble reaching the origin with 52x codes.
func (d *Doctor) cloudflareChecks(ctx context.Context, addr string) []Result {
	host := d.Cfg.Transport.Endpoint
	cert := d.validCert(ctx, CheckCloudflareTLS, addr, host)
	if cert.Status != Pass {
		cert.Remedy = "make sure the DNS record for " + host + " exists and is proxied (orange cloud) in Cloudflare"
		return []Result{cert}
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: d.Cfg.Transport.DialTimeout.Duration}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
	}
	defer tr.CloseIdleConnections()
	// Ask on the exit node's own port (Cloudflare forwards edge port N to
	// origin port N), and wait long enough for Cloudflare's own verdict: it
	// reports an unreachable exit node (522) only after about 20 seconds.
	_, port, _ := net.SplitHostPort(addr)
	url := "https://" + host + "/"
	if port != "" && port != "443" {
		url = "https://" + net.JoinHostPort(host, port) + "/"
	}
	client := &http.Client{Transport: tr, Timeout: cloudflareOriginWait}
	resp, err := client.Get(url)
	if err != nil {
		return []Result{cert, {Name: CheckCloudflareOrigin, Status: Fail, Detail: err.Error(),
			Remedy: "Cloudflare gave no answer in time. Usually that means it cannot reach your exit node: check that the exit node PC is on and Sharing, and that your home internet works"}}
	}
	resp.Body.Close()
	r := cloudflareOriginResult(resp.StatusCode)
	r.Remedy = strings.ReplaceAll(r.Remedy, "TCP 443", "TCP "+orDefault(port, "443"))
	return []Result{cert, r}
}

// cloudflareOriginWait is how long to wait for Cloudflare's answer.
var cloudflareOriginWait = 30 * time.Second

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// cloudflareOriginResult interprets the status Cloudflare returned.
func cloudflareOriginResult(code int) Result {
	r := Result{Name: CheckCloudflareOrigin, Detail: fmt.Sprintf("HTTP %d", code)}
	switch code {
	case 521, 522, 523:
		r.Status, r.Remedy = Fail, "Cloudflare cannot reach your exit node: check that the exit node PC is on and Sharing, that your home internet works, and that the router forwards TCP 443 to it"
	case 524:
		r.Status, r.Remedy = Fail, "the exit node accepted the connection but did not answer in time"
	case 525, 526:
		r.Status, r.Remedy = Fail, "Cloudflare's SSL/TLS mode must be \"Full\" (not Flexible or Full strict); set the exit node up again with your API token, or change it in the Cloudflare dashboard"
	case 520, 527:
		r.Status, r.Remedy = Fail, "Cloudflare got an unexpected answer from the exit node"
	default:
		r.Status, r.Detail = Pass, fmt.Sprintf("Cloudflare reaches the exit node (HTTP %d)", code)
	}
	return r
}

// validCert passes when addr presents a certificate valid for sni.
func (d *Doctor) validCert(ctx context.Context, name, addr, sni string) Result {
	dl := tls.Dialer{NetDialer: &net.Dialer{Timeout: d.Cfg.Transport.DialTimeout.Duration},
		Config: &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12}}
	c, err := dl.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Result{Name: name, Status: Fail, Detail: err.Error()}
	}
	c.Close()
	return Result{Name: name, Status: Pass, Detail: "valid certificate for " + sni}
}
