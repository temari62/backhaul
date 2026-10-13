package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
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
	"backhaul/internal/undo"
	"backhaul/internal/wg"
)

// Connect runs the client (§6.3) until ctx is cancelled, then restores the
// machine's routes/DNS/firewall exactly.
func Connect(ctx context.Context, e *Env, killSwitch bool) (err error) {
	c := e.Cfg
	if err := e.preflight(ctx, true); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go state.WatchStop(ctx, e.Paths.State(), StopPollInterval, cancel)
	host, port, fingerprint := c.RemoteHost()
	var pool *edgePool
	if c.Transport.Kind == config.TransportCloudflare {
		fingerprint = "" // verify Cloudflare's real certificate instead of pinning
		pool, err = cloudflarePool(ctx, c, host, port)
	} else {
		var ip netip.Addr
		ip, err = resolveEndpoint(ctx, host, c.Transport.DialTimeout.Duration)
		pool = newEdgePool([]netip.Addr{ip}, port)
	}
	if err != nil {
		return err
	}
	epIP := pool.Addr()
	rt := &state.Runtime{
		PID: os.Getpid(), Mode: config.ModeConnect, Engine: c.WireGuard.Engine, Started: time.Now(),
		Endpoint: host, EndpointIP: epIP.String(), KillSwitch: killSwitch, IPv6Tunneled: c.Client.TunnelIPv6,
	}
	// Record the real public IP *before* tunnelling so doctor can prove it changed.
	if ip, err := health.EgressIP(ctx, c.Health.IPCheckURL, "tcp4", c.Health.ProbeTimeout.Duration); err == nil {
		rt.RealIP = ip.String()
	}
	if err := ensureEngineDeps(ctx, c); err != nil {
		return err
	}

	j := undo.Open(state.JournalFile(e.Paths.State()))
	var cl cleanup
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
		teardown(j, cl)
		state.Remove(e.Paths.State())
	}()

	// 1. Transport → local UDP listener that WireGuard sends to.
	localUDP := "127.0.0.1:" + strconv.Itoa(c.Transport.LocalUDPPort)
	tr, linkDown, directApps, err := e.connectTransport(ctx, &cl, host, pool, fingerprint, localUDP)
	if err != nil {
		return err
	}
	cl.push("stop transport", func(context.Context) { tr.Stop() })

	// 2. WireGuard, peer endpoint = the local wstunnel listener.
	eng, err := wg.New(c.WireGuard.Engine)
	if err != nil {
		return err
	}
	addrs, err := wgAddresses(c, c.Client.TunnelIPv6)
	if err != nil {
		return err
	}
	allowed := []string{"0.0.0.0/0"}
	if c.Client.TunnelIPv6 {
		allowed = append(allowed, "::/0")
	}
	if err := eng.Up(ctx, wg.Settings{
		Interface: c.WireGuard.Interface, PrivateKey: e.Sec.PrivateKey, PresharedKey: e.Sec.PresharedKey,
		PeerPublicKey: c.Peer.PublicKey, PeerEndpoint: localUDP, AllowedIPs: allowed,
		Keepalive: c.WireGuard.Keepalive, MTU: c.WireGuard.MTU, Addresses: addrs,
		StateDir: e.Paths.State(), Journal: j,
	}); err != nil {
		return err
	}
	cl.push("close tunnel adapter", func(ctx context.Context) { eng.Down(ctx) })
	rt.Iface = eng.Name()

	// 3. Routes, DNS, kill-switch.
	dns, _ := c.DNSServers()
	if !c.Client.TunnelIPv6 {
		dns = only4(dns)
	}
	mgr := route.New()
	plan := route.Plan{
		Iface: eng.Name(), Endpoints: pool.All(), EndpointPort: port, TunnelAddrs: hostAddrs(addrs),
		DNS: dns, DNSMethod: c.Client.DNSMethod, IPv6: c.Client.TunnelIPv6, KillSwitch: killSwitch, PermitApps: directApps,
	}
	if err := mgr.Apply(ctx, plan, j); err != nil {
		return fmt.Errorf("install routes: %w", err)
	}
	if killSwitch {
		cl.push("remove kill switch", func(ctx context.Context) { _ = route.DisableKillSwitch(ctx) })
	}
	switch {
	case !killSwitch:
	case !route.KillSwitchActive():
		killSwitch = false
	case !killSwitchLetsExitNodeThrough(ctx, epIP, port, c.Transport.DialTimeout.Duration):
		killSwitch = false
	case runtime.GOOS == "windows" && !killSwitchLetsTunnelThrough(ctx, tunnelProbe(c, dns), c.Health.ProbeName, dns):
		killSwitch = false
	}
	rt.KillSwitch = killSwitch
	if killSwitch && runtime.GOOS == "windows" {
		go func() { // baseline for comparing with an outage
			select {
			case <-ctx.Done():
			case <-time.After(45 * time.Second):
				slog.Info("network state with the kill switch on", "facts", route.NetworkFacts(ctx))
			}
		}()
	}
	slog.Info("connected — all traffic now exits via the exit node",
		"iface", eng.Name(), "endpoint", host, "endpoint_ip", epIP, "killswitch", killSwitch)
	if !killSwitch {
		slog.Warn("kill-switch disabled: if the tunnel drops, traffic will use your real IP")
	}

	// 4. Health loop until Ctrl+C / SIGTERM.
	(&health.Monitor{
		Opts: health.Options{
			Interval: c.Health.Interval.Duration, HandshakeTimeout: c.Health.HandshakeTimeout.Duration,
			StartupGrace: c.Health.StartupGrace.Duration, BackoffMin: c.Health.BackoffMin.Duration,
			BackoffMax: c.Health.BackoffMax.Duration, Reconnect: true, StateDir: e.Paths.State(),
			Check: routeGuard(mgr, func() route.Plan {
				q := plan
				q.Endpoints = []netip.Addr{pool.Addr()} // only the address in use needs checking
				return q
			}, j, eng, tr), CheckEvery: routeGuardEvery, LinkDown: linkDown,
			Probe: tunnelProbe(c, dns), ProbeFailures: c.Health.ProbeFailures,
			OnDown: func(ctx context.Context, st wg.Stats) {
				if !diagnoseOutage(ctx, pool.Addr(), port, st, tr) && killSwitch && runtime.GOOS == "windows" {
					// The kill switch always lets Backhaul itself through, so it can't be
					// what blocks the exit node; just record the network state.
					slog.Warn("network state at the outage", "facts", route.NetworkFacts(ctx))
				}
			},
			OnUp: func(d time.Duration) {
				slog.Info("tunnel is carrying traffic again", "outage", d.Round(time.Second))
			},
		},
		Engine: eng, Transport: tr, Runtime: rt,
	}).Run(ctx)
	slog.Info("shutting down")
	return nil
}

func only4(as []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range as {
		if a.Is4() {
			out = append(out, a)
		}
	}
	return out
}

func hostAddrs(ps []netip.Prefix) []netip.Addr {
	out := make([]netip.Addr, len(ps))
	for i, p := range ps {
		out[i] = p.Addr()
	}
	return out
}

// routeGuardEvery: while the tunnel is healthy, verify the route to the exit
// node every N health ticks (every tick while it is not).
const routeGuardEvery = 6

// routeGuard keeps the exit node reachable outside the tunnel. If something
// changes the routing table under us — another VPN resetting its adapter, a
// Wi-Fi switch moving the default gateway — the pinned host route breaks and
// tunnel traffic would loop into the tunnel itself. The guard re-pins it
// through the current real uplink and kicks the transport to reconnect now.
func routeGuard(mgr route.Manager, plan func() route.Plan, j *undo.Journal, eng wg.Engine, tr transport.Transport) func(context.Context) {
	last := ""
	return func(ctx context.Context) {
		repaired, err := mgr.RepairEndpoint(ctx, plan(), j)
		switch {
		case err != nil:
			if msg := err.Error(); msg != last {
				slog.Warn("route guard: cannot reach the exit node outside the tunnel", "err", err)
				last = msg
			}
		case repaired:
			slog.Warn("the route to the exit node broke (another VPN changed the routing table, or the network changed); re-pinned it and reconnecting")
			last = ""
			tr.Restart()
			if err := eng.Kick(); err != nil {
				slog.Debug("kick wireguard", "err", err)
			}
		default:
			last = ""
		}
	}
}

// connectTransport starts the client transport for the configured kind and
// returns it plus a "link is down" probe (nil if the transport has none).
func (e *Env) connectTransport(ctx context.Context, cl *cleanup, host string, pool *edgePool,
	fingerprint, localUDP string) (transport.Transport, func() bool, []string, error) {
	c := e.Cfg
	epIP, port := pool.Addr(), pool.port
	remoteUDP := "127.0.0.1:" + strconv.Itoa(c.Transport.RemoteUDPPort)
	if c.Reachability.Mode == config.ReachRelay {
		remoteUDP = "127.0.0.1:" + strconv.Itoa(c.Reachability.Relay.RemotePort)
	}

	if c.Transport.Kind == config.TransportReality {
		xp, err := transport.EnsureXray(ctx, c, e.Paths.Bin())
		if err != nil {
			return nil, nil, nil, err
		}
		r := c.Transport.Reality
		cfgPath := filepath.Join(e.Paths.State(), "xray-client.json")
		tr, err := transport.NewReality(transport.RealityOptions{
			Binary: xp, Role: transport.RoleClient, ConfigPath: cfgPath,
			ServerAddr: epIP.String(), ServerPort: port, PublicKey: r.PublicKey, Fingerprint: r.Fingerprint,
			LocalUDP: localUDP, RemoteUDP: remoteUDP,
			UUID: e.Sec.RealityUUID, ShortID: r.ShortID, ServerName: r.ServerName, Target: r.Target,
			ReadyTimeout: c.Transport.ReadyTimeout.Duration, BackoffMin: c.Transport.BackoffMin.Duration,
			BackoffMax: c.Transport.BackoffMax.Duration,
		})
		if err != nil {
			return nil, nil, nil, err
		}
		cl.push("remove xray config", func(context.Context) { os.Remove(cfgPath) }) // contains secrets
		if err := tr.Start(ctx); err != nil {
			slog.Warn("transport not ready yet; continuing (it keeps retrying)", "err", err)
		}
		return tr, nil, []string{xp}, nil
	}

	// wstunnel: pinned-TLS proxy + wstunnel client.
	dialTimeout := c.Transport.DialTimeout.Duration
	if c.Transport.Kind == config.TransportCloudflare && dialTimeout > cloudflareDialTimeout {
		dialTimeout = cloudflareDialTimeout
	}
	proxy, err := tlspin.NewProxy(pool.Current, host, fingerprint, dialTimeout)
	if err != nil {
		return nil, nil, nil, err
	}
	proxy.OnTrouble = pool.Trouble
	go proxy.Serve(ctx)
	cl.push("close TLS proxy", func(context.Context) { proxy.Close() })
	hostHeader := ""
	if c.Transport.Kind == config.TransportCloudflare {
		hostHeader = host // Cloudflare routes by Host; wstunnel itself dials our local proxy
	}
	if c.Transport.Client != config.ClientWstunnel {
		// Built-in client (default): no wstunnel.exe on this PC.
		tr := transport.NewWSClient(transport.WSClientOptions{
			ServerAddr: proxy.Addr(), HostHeader: hostHeader, PathPrefix: c.Transport.PathPrefix,
			LocalUDP: localUDP, RemoteUDP: remoteUDP, DialTimeout: dialTimeout,
			BackoffMin: c.Transport.BackoffMin.Duration, BackoffMax: c.Transport.BackoffMax.Duration,
		})
		if err := tr.Start(ctx); err != nil {
			return nil, nil, nil, err
		}
		return tr, proxy.Down, nil, nil
	}
	wstPath, err := transport.EnsureWstunnel(ctx, c, e.Paths.Bin())
	if err != nil {
		return nil, nil, nil, err
	}
	tr := transport.NewWstunnel(transport.WstunnelOptions{
		Binary: wstPath, Role: transport.RoleClient,
		ServerURL: "ws://" + proxy.Addr(), LocalUDP: localUDP, RemoteUDP: remoteUDP, HostHeader: hostHeader,
		PathPrefix: c.Transport.PathPrefix, ReadyTimeout: c.Transport.ReadyTimeout.Duration,
		BackoffMin: c.Transport.BackoffMin.Duration, BackoffMax: c.Transport.BackoffMax.Duration,
		Verbose: e.Verbose,
	})
	if err := tr.Start(ctx); err != nil {
		if errors.Is(proxy.LastError(), tlspin.ErrMismatch) {
			tr.Stop()
			return nil, nil, nil, proxy.LastError()
		}
		slog.Warn("transport not ready yet; continuing (it keeps retrying)", "err", err)
	}
	return tr, proxy.Down, nil, nil
}

// probeTimeout bounds one liveness probe (it must fit in a health tick).
const probeTimeout = 4 * time.Second

// tunnelProbe resolves a name through the tunnel's DNS server (the exit node
// relays it), proving the whole path — transport, WireGuard, exit node —
// works end to end. A fresh handshake alone doesn't: a blocked transport
// can leave WireGuard looking "connected" for minutes.
func tunnelProbe(c *config.Config, dns []netip.Addr) func(context.Context) error {
	if len(dns) == 0 || c.Health.ProbeName == "" {
		return nil
	}
	server := dns[0]
	return func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		_, err := health.ResolveVia(ctx, server, c.Health.ProbeName, probeTimeout)
		return err
	}
}

// diagnoseOutage records, at the moment the tunnel stops working, the facts
// that tell the causes apart: can this PC still open a direct connection to
// the exit node, which way does that traffic route, and what did WireGuard
// and the transport last see.
//
// It reports whether the exit node (or Cloudflare) answered directly.
func diagnoseOutage(ctx context.Context, ep netip.Addr, port int, st wg.Stats, tr transport.Transport) bool {
	addr := netip.AddrPortFrom(ep, uint16(port)).String()
	start := time.Now()
	direct := "reachable"
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		direct = "NOT reachable: " + err.Error()
	} else {
		conn.Close()
		direct += fmt.Sprintf(" in %s", time.Since(start).Round(time.Millisecond))
	}
	hs := "never"
	if !st.LastHandshake.IsZero() {
		hs = time.Since(st.LastHandshake).Round(time.Second).String() + " ago"
	}
	slog.Warn("tunnel stopped carrying traffic — diagnosis",
		"exit_node_direct_tcp", direct, "route_to_exit_node", route.EndpointPath(ctx, ep),
		"last_handshake", hs, "rx_bytes", st.RxBytes, "tx_bytes", st.TxBytes,
		"transport", tr.Status().State, "transport_restarts", tr.Status().Restarts)
	if err != nil {
		slog.Warn("this PC cannot open a new connection to the exit node right now, although it could when connecting. " +
			"That points to the network between the PCs (e.g. China's firewall temporarily blocking the exit node's address) rather than the exit node.")
	} else {
		slog.Warn("the exit node is still reachable directly, so the tunnel itself stalled; reconnecting")
	}
	return err == nil
}

// killSwitchLetsTunnelThrough is a second self-test (Windows): other
// programs' traffic must flow through the tunnel. It compares a DNS lookup
// through the tunnel made by Backhaul with the same lookup made by another
// program; if only Backhaul's works, the kill switch is blocking the tunnel,
// and staying "protected" would mean staying offline.
func killSwitchLetsTunnelThrough(ctx context.Context, ownProbe func(context.Context) error, name string, dns []netip.Addr) bool {
	if ownProbe == nil || len(dns) == 0 {
		return true
	}
	// First wait for the tunnel to work at all, tested from Backhaul itself
	// (which the kill switch always lets through).
	up := false
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && ctx.Err() == nil; {
		if ownProbe(ctx) == nil {
			up = true
			break
		}
		time.Sleep(time.Second)
	}
	if !up {
		slog.Debug("kill-switch tunnel test skipped: the tunnel isn't carrying traffic yet")
		return true
	}
	// Then the same lookup from another program, as any app would do it.
	script := fmt.Sprintf(`Resolve-DnsName -Name '%s' -Server '%s' -DnsOnly -QuickTimeout | Out-Null`,
		strings.ReplaceAll(name, "'", "''"), dns[0])
	var err error
	for i := 0; i < 3; i++ {
		if _, err = osutil.PowerShell(ctx, script); err == nil {
			slog.Debug("kill-switch tunnel test passed")
			return true
		}
	}
	if ownProbe(ctx) != nil {
		return true // the tunnel itself went down meanwhile; nothing to conclude
	}
	slog.Error("the kill switch blocks other programs from using the tunnel on this PC; turning it off for this session so you stay connected — please report this",
		"err", err)
	_ = route.DisableKillSwitch(ctx)
	return false
}

// killSwitchLetsExitNodeThrough is a self-test run right after the kill
// switch is installed: a fresh connection to the exit node must still work
// (the transport needs it to reconnect). If the kill switch blocks it — as a
// Windows Firewall quirk once did — staying "protected" would only mean
// staying offline, so the kill switch is removed for this session, loudly.
func killSwitchLetsExitNodeThrough(ctx context.Context, ep netip.Addr, port int, timeout time.Duration) bool {
	addr := netip.AddrPortFrom(ep, uint16(port)).String()
	c, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", addr)
	if err == nil {
		c.Close()
		slog.Info("kill switch active; the exit node is still reachable for reconnects")
		return true
	}
	slog.Error("the kill switch blocks connections to the exit node on this PC; turning it off for this session so you stay connected — please report this",
		"exit_node", addr, "err", err)
	if derr := route.DisableKillSwitch(ctx); derr != nil {
		slog.Warn("could not remove the kill switch", "err", derr)
	}
	return false
}
