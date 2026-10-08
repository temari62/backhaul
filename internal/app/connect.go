package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
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
	wstPath, err := transport.EnsureWstunnel(ctx, c, e.Paths.Bin())
	if err != nil {
		return err
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

	// 1. Pinned-TLS proxy + wstunnel client → local UDP listener.
	remote := netip.AddrPortFrom(epIP, uint16(port)).String()
	proxy, err := tlspin.NewProxy(func() string { return remote }, host, fingerprint, c.Transport.DialTimeout.Duration)
	if err != nil {
		return err
	}
	go proxy.Serve(ctx)
	cl.push(func(context.Context) { proxy.Close() })

	remoteUDP := "127.0.0.1:" + strconv.Itoa(c.Transport.RemoteUDPPort)
	if c.Reachability.Mode == config.ReachRelay {
		remoteUDP = "127.0.0.1:" + strconv.Itoa(c.Reachability.Relay.RemotePort)
	}
	localUDP := "127.0.0.1:" + strconv.Itoa(c.Transport.LocalUDPPort)
	tr := transport.NewWstunnel(transport.WstunnelOptions{
		Binary: wstPath, Role: transport.RoleClient,
		ServerURL: "ws://" + proxy.Addr(), LocalUDP: localUDP, RemoteUDP: remoteUDP,
		PathPrefix: c.Transport.PathPrefix, ReadyTimeout: c.Transport.ReadyTimeout.Duration,
		BackoffMin: c.Transport.BackoffMin.Duration, BackoffMax: c.Transport.BackoffMax.Duration,
		Verbose: e.Verbose,
	})
	if err := tr.Start(ctx); err != nil {
		if errors.Is(proxy.LastError(), tlspin.ErrMismatch) {
			return proxy.LastError()
		}
		slog.Warn("transport not ready yet; continuing (it keeps retrying)", "err", err)
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
	if err := route.New().Apply(ctx, route.Plan{
		Iface: eng.Name(), Endpoints: []netip.Addr{epIP}, EndpointPort: port,
		DNS: dns, DNSMethod: c.Client.DNSMethod, IPv6: c.Client.TunnelIPv6, KillSwitch: killSwitch,
	}, j); err != nil {
		return fmt.Errorf("install routes: %w", err)
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
