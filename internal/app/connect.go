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
	"strconv"
	"time"

	"backhaul/internal/config"
	"backhaul/internal/health"
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
	epIP, err := resolveEndpoint(ctx, host, c.Transport.DialTimeout.Duration)
	if err != nil {
		return err
	}
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
	tr, linkDown, err := e.connectTransport(ctx, &cl, host, epIP, port, fingerprint, localUDP)
	if err != nil {
		return err
	}
	cl.push(func(context.Context) { tr.Stop() })

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
	cl.push(func(ctx context.Context) { eng.Down(ctx) })
	rt.Iface = eng.Name()

	// 3. Routes, DNS, kill-switch.
	dns, _ := c.DNSServers()
	if !c.Client.TunnelIPv6 {
		dns = only4(dns)
	}
	mgr := route.New()
	plan := route.Plan{
		Iface: eng.Name(), Endpoints: []netip.Addr{epIP}, EndpointPort: port, TunnelAddrs: hostAddrs(addrs),
		DNS: dns, DNSMethod: c.Client.DNSMethod, IPv6: c.Client.TunnelIPv6, KillSwitch: killSwitch,
	}
	if err := mgr.Apply(ctx, plan, j); err != nil {
		return fmt.Errorf("install routes: %w", err)
	}
	if killSwitch && !killSwitchLetsExitNodeThrough(ctx, epIP, port, c.Transport.DialTimeout.Duration) {
		killSwitch = false
		rt.KillSwitch = false
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
			Check: routeGuard(mgr, plan, j, eng, tr), CheckEvery: routeGuardEvery, LinkDown: linkDown,
			Probe: tunnelProbe(c, dns), ProbeFailures: c.Health.ProbeFailures,
			OnDown: func(ctx context.Context, st wg.Stats) { diagnoseOutage(ctx, epIP, port, st, tr) },
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
func routeGuard(mgr route.Manager, plan route.Plan, j *undo.Journal, eng wg.Engine, tr transport.Transport) func(context.Context) {
	last := ""
	return func(ctx context.Context) {
		repaired, err := mgr.RepairEndpoint(ctx, plan, j)
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
func (e *Env) connectTransport(ctx context.Context, cl *cleanup, host string, epIP netip.Addr, port int,
	fingerprint, localUDP string) (transport.Transport, func() bool, error) {
	c := e.Cfg
	remoteUDP := "127.0.0.1:" + strconv.Itoa(c.Transport.RemoteUDPPort)
	if c.Reachability.Mode == config.ReachRelay {
		remoteUDP = "127.0.0.1:" + strconv.Itoa(c.Reachability.Relay.RemotePort)
	}

	if c.Transport.Kind == config.TransportReality {
		xp, err := transport.EnsureXray(ctx, c, e.Paths.Bin())
		if err != nil {
			return nil, nil, err
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
			return nil, nil, err
		}
		cl.push(func(context.Context) { os.Remove(cfgPath) }) // contains secrets
		if err := tr.Start(ctx); err != nil {
			slog.Warn("transport not ready yet; continuing (it keeps retrying)", "err", err)
		}
		return tr, nil, nil
	}

	// wstunnel: pinned-TLS proxy + wstunnel client.
	wstPath, err := transport.EnsureWstunnel(ctx, c, e.Paths.Bin())
	if err != nil {
		return nil, nil, err
	}
	remote := netip.AddrPortFrom(epIP, uint16(port)).String()
	proxy, err := tlspin.NewProxy(func() string { return remote }, host, fingerprint, c.Transport.DialTimeout.Duration)
	if err != nil {
		return nil, nil, err
	}
	go proxy.Serve(ctx)
	cl.push(func(context.Context) { proxy.Close() })
	tr := transport.NewWstunnel(transport.WstunnelOptions{
		Binary: wstPath, Role: transport.RoleClient,
		ServerURL: "ws://" + proxy.Addr(), LocalUDP: localUDP, RemoteUDP: remoteUDP,
		PathPrefix: c.Transport.PathPrefix, ReadyTimeout: c.Transport.ReadyTimeout.Duration,
		BackoffMin: c.Transport.BackoffMin.Duration, BackoffMax: c.Transport.BackoffMax.Duration,
		Verbose: e.Verbose,
	})
	if err := tr.Start(ctx); err != nil {
		if errors.Is(proxy.LastError(), tlspin.ErrMismatch) {
			tr.Stop()
			return nil, nil, proxy.LastError()
		}
		slog.Warn("transport not ready yet; continuing (it keeps retrying)", "err", err)
	}
	return tr, proxy.Down, nil
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
func diagnoseOutage(ctx context.Context, ep netip.Addr, port int, st wg.Stats, tr transport.Transport) {
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
