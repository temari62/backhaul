package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"time"

	"backhaul/internal/config"
	"backhaul/internal/ddns"
	"backhaul/internal/dnsfwd"
	"backhaul/internal/health"
	"backhaul/internal/nat"
	"backhaul/internal/state"
	"backhaul/internal/tlspin"
	"backhaul/internal/transport"
	"backhaul/internal/undo"
	"backhaul/internal/wg"
)

// Serve runs the exit node (§6.2) until ctx is cancelled, then removes NAT
// rules and the interface, leaving the machine as found.
func Serve(ctx context.Context, e *Env) (err error) {
	c := e.Cfg
	if err := e.preflight(ctx); err != nil {
		return err
	}
	wstPath, err := transport.EnsureWstunnel(ctx, c, e.Paths.Bin())
	if err != nil {
		return err
	}
	if err := ensureEngineDeps(ctx, c); err != nil {
		return err
	}
	rt := &state.Runtime{PID: os.Getpid(), Mode: config.ModeServe, Engine: c.WireGuard.Engine,
		Started: time.Now(), Endpoint: c.Transport.Endpoint}

	j := undo.Open(state.JournalFile(e.Paths.State()))
	var cl cleanup
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
		teardown(j, cl)
		state.Remove(e.Paths.State())
	}()

	// 1. WireGuard with the client as the sole peer.
	eng, err := wg.New(c.WireGuard.Engine)
	if err != nil {
		return err
	}
	_, hasV6, _ := c.IfaceAddr6()
	addrs, err := wgAddresses(c, hasV6)
	if err != nil {
		return err
	}
	if err := eng.Up(ctx, wg.Settings{
		Interface: c.WireGuard.Interface, PrivateKey: e.Sec.PrivateKey, PresharedKey: e.Sec.PresharedKey,
		PeerPublicKey: c.Peer.PublicKey, ListenPort: c.WireGuard.ListenPort, AllowedIPs: c.Peer.AllowedIPs,
		MTU: c.WireGuard.MTU, Addresses: addrs, StateDir: e.Paths.State(), Journal: j,
	}); err != nil {
		return err
	}
	cl.push(func(ctx context.Context) { eng.Down(ctx) })
	rt.Iface = eng.Name()

	// 2. Forwarding + NAT to the internet interface.
	sn4, _ := netip.ParsePrefix(c.WireGuard.Subnet)
	var sn6 netip.Prefix
	if hasV6 {
		sn6, _ = netip.ParsePrefix(c.WireGuard.Subnet6)
	}
	if err := nat.Enable(ctx, nat.Plan{Iface: eng.Name(), Subnet4: sn4, Subnet6: sn6,
		WAN: c.Serve.WANInterface, Backend: c.Serve.NATBackend}, j); err != nil {
		return fmt.Errorf("enable NAT: %w", err)
	}

	// 3. DNS forwarder on the tunnel IP, so client DNS exits here too.
	if c.Serve.DNSForwarder {
		for _, a := range addrs {
			listen := netip.AddrPortFrom(a.Addr(), 53).String()
			f, err := dnsfwd.Listen(listen, c.Serve.DNSUpstream)
			if err != nil {
				slog.Warn("dns forwarder failed; clients must use a public resolver (set client.dns)", "addr", listen, "err", err)
				continue
			}
			go f.Serve(ctx)
		}
	}

	// 4. Transport: wstunnel server on :443, or (relay mode) an outbound
	//    reverse tunnel to the VPS.
	wgLocal := "127.0.0.1:" + strconv.Itoa(c.WireGuard.ListenPort)
	opts := transport.WstunnelOptions{
		Binary: wstPath, PathPrefix: c.Transport.PathPrefix,
		ReadyTimeout: c.Transport.ReadyTimeout.Duration, BackoffMin: c.Transport.BackoffMin.Duration,
		BackoffMax: c.Transport.BackoffMax.Duration, Verbose: e.Verbose,
	}
	if c.Reachability.Mode == config.ReachRelay {
		r := c.Reachability.Relay
		ip, err := resolveEndpoint(ctx, r.Host, c.Transport.DialTimeout.Duration)
		if err != nil {
			return err
		}
		remote := netip.AddrPortFrom(ip, uint16(r.Port)).String()
		proxy, err := tlspin.NewProxy(func() string { return remote }, r.Host, r.TLSSHA256, c.Transport.DialTimeout.Duration)
		if err != nil {
			return err
		}
		go proxy.Serve(ctx)
		cl.push(func(context.Context) { proxy.Close() })
		opts.Role, opts.ServerURL = transport.RoleReverseClient, "ws://"+proxy.Addr()
		opts.RelayBind, opts.RemoteUDP = "127.0.0.1:"+strconv.Itoa(r.RemotePort), wgLocal
	} else {
		opts.Role = transport.RoleServer
		opts.ListenAddr, opts.Port = c.Transport.ListenAddr, c.Transport.Port
		opts.CertFile, opts.KeyFile = c.Transport.CertFile, c.Transport.KeyFile
		opts.RestrictTo = wgLocal
	}
	tr := transport.NewWstunnel(opts)
	if err := tr.Start(ctx); err != nil {
		slog.Warn("transport not ready yet (it keeps retrying)", "err", err)
	}
	cl.push(func(context.Context) { tr.Stop() })

	// 5. DDNS updater.
	if c.DDNS.Provider != "" {
		u, err := ddns.New(ddns.Options{Provider: c.DDNS.Provider, Domain: c.DDNS.Domain, Token: e.Sec.DDNSToken,
			ZoneID: c.DDNS.ZoneID, IPCheckURL: c.Health.IPCheckURL})
		if err != nil {
			return err
		}
		go ddns.Run(ctx, u, c.DDNS.Interval.Duration)
	}

	slog.Info("exit node ready", "iface", eng.Name(), "transport", opts.Role,
		"port", c.Transport.Port, "reachability", c.Reachability.Mode)

	// 6. Supervise and report health until Ctrl+C / SIGTERM.
	(&health.Monitor{
		Opts: health.Options{
			Interval: c.Health.Interval.Duration, HandshakeTimeout: c.Health.HandshakeTimeout.Duration,
			StartupGrace: c.Health.StartupGrace.Duration, BackoffMin: c.Health.BackoffMin.Duration,
			BackoffMax: c.Health.BackoffMax.Duration, Reconnect: false, StateDir: e.Paths.State(),
		},
		Engine: eng, Transport: tr, Runtime: rt,
	}).Run(ctx)
	slog.Info("shutting down")
	return nil
}
