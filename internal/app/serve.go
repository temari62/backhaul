package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"backhaul/internal/config"
	"backhaul/internal/ddns"
	"backhaul/internal/dnsfwd"
	"backhaul/internal/health"
	"backhaul/internal/nat"
	"backhaul/internal/netstack"
	"backhaul/internal/osutil"
	"backhaul/internal/state"
	"backhaul/internal/tlspin"
	"backhaul/internal/transport"
	"backhaul/internal/undo"
	"backhaul/internal/upnp"
	"backhaul/internal/wg"
)

// Serve runs the exit node (§6.2) until ctx is cancelled, then removes NAT
// rules and the interface, leaving the machine as found.
func Serve(ctx context.Context, e *Env) (err error) {
	c := e.Cfg
	userspace, err := resolveNATMode(ctx, c)
	if err != nil {
		return err
	}
	if err := e.preflight(ctx, serveNeedsPrivileges(c, userspace)); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go state.WatchStop(ctx, e.Paths.State(), StopPollInterval, cancel)
	if !userspace {
		if err := ensureEngineDeps(ctx, c); err != nil {
			return err
		}
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
	settings := wg.Settings{
		Interface: c.WireGuard.Interface, PrivateKey: e.Sec.PrivateKey, PresharedKey: e.Sec.PresharedKey,
		PeerPublicKey: c.Peer.PublicKey, ListenPort: c.WireGuard.ListenPort, AllowedIPs: c.Peer.AllowedIPs,
		MTU: c.WireGuard.MTU, Addresses: addrs, StateDir: e.Paths.State(), Journal: j,
	}
	if userspace {
		// Userspace NAT: WireGuard feeds an in-process TCP/IP stack that
		// re-originates every flow from this process. DNS to our tunnel IP
		// is relayed to the upstream inside that stack.
		own := make([]netip.Addr, len(addrs))
		for i, a := range addrs {
			own[i] = a.Addr()
		}
		upstream := ""
		if c.Serve.DNSForwarder {
			upstream = c.Serve.DNSUpstream
		}
		dev, err := netstack.New(netstack.Options{Addresses: own, MTU: c.WireGuard.MTU, DNSUpstream: upstream,
			DialTimeout: c.Transport.DialTimeout.Duration, UDPIdle: c.Serve.UDPIdle.Duration})
		if err != nil {
			return fmt.Errorf("userspace NAT: %w", err)
		}
		settings.TUN = dev
	}
	if err := eng.Up(ctx, settings); err != nil {
		return err
	}
	cl.push("close tunnel adapter", func(ctx context.Context) { eng.Down(ctx) })
	rt.Iface = eng.Name()

	// 2. Let the client in through the OS firewall (Windows blocks inbound by default).
	if c.Reachability.Mode == config.ReachPortForward {
		if osutil.IsElevated() {
			if err := nat.AllowInbound(ctx, c.Transport.Port, j); err != nil {
				slog.Warn("could not add inbound firewall rule; the client may be blocked", "port", c.Transport.Port, "err", err)
			}
		} else if runtime.GOOS == "windows" {
			slog.Warn("not elevated: cannot open the Windows Firewall for inbound TCP; if the client can't connect, run serve once as administrator or allow wstunnel.exe when Windows asks",
				"port", c.Transport.Port)
		}
	}

	// 3. Forwarding + NAT to the internet interface (system mode only).
	if !userspace {
		sn4, _ := netip.ParsePrefix(c.WireGuard.Subnet)
		var sn6 netip.Prefix
		if hasV6 {
			sn6, _ = netip.ParsePrefix(c.WireGuard.Subnet6)
		}
		if err := nat.Enable(ctx, nat.Plan{Iface: eng.Name(), Subnet4: sn4, Subnet6: sn6,
			WAN: c.Serve.WANInterface, Backend: c.Serve.NATBackend}, j); err != nil {
			return fmt.Errorf("enable NAT: %w", err)
		}
	}

	// 4. DNS forwarder on the tunnel IP, so client DNS exits here too.
	if c.Serve.DNSForwarder && !userspace {
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

	// 4. Transport: REALITY (Xray) or wstunnel server on :443, or (relay
	//    mode) an outbound wstunnel reverse tunnel to the VPS.
	tr, opts, err := e.serveTransport(ctx, &cl)
	if err != nil {
		return err
	}
	if err := tr.Start(ctx); err != nil {
		slog.Warn("transport not ready yet (it keeps retrying)", "err", err)
	}
	cl.push("stop transport", func(context.Context) { tr.Stop() })

	// 5. Router: forward the port automatically (UPnP) and detect CGNAT.
	if c.Reachability.Mode == config.ReachPortForward {
		rt.LANIP = osutil.LANIP()
		var stop func()
		rt.Router, stop = openRouterPort(ctx, c, rt.LANIP, func(s string) { rt.Router = s })
		if stop != nil {
			cl.push("close router port", func(context.Context) { stop() })
		}
	}

	// 6. DDNS updater.
	if c.DDNS.Provider != "" {
		u, err := ddns.New(ddns.Options{Provider: c.DDNS.Provider, Domain: c.DDNS.Domain, Token: e.Sec.DDNSToken,
			ZoneID: c.DDNS.ZoneID, Proxied: c.DDNS.Proxied, IPCheckURL: c.Health.IPCheckURL})
		if err != nil {
			return err
		}
		go ddns.Run(ctx, u, c.DDNS.Interval.Duration)
	}

	natMode := config.NATSystem
	if userspace {
		natMode = config.NATUserspace
	}
	slog.Info("exit node ready", "iface", eng.Name(), "nat", natMode, "transport", opts.Role,
		"port", c.Transport.Port, "reachability", c.Reachability.Mode)

	// 7. Supervise and report health until Ctrl+C / SIGTERM.
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

// resolveNATMode decides between system NAT and userspace NAT.
func resolveNATMode(ctx context.Context, c *config.Config) (userspace bool, err error) {
	switch c.Serve.NATMode {
	case config.NATUserspace:
		userspace = true
	case config.NATSystem:
		userspace = false
	default: // auto
		userspace = !nat.Available(ctx)
		if userspace {
			slog.Info("system NAT is not available on this OS edition; using userspace NAT (set serve.nat_mode to override)")
		}
	}
	if userspace && c.WireGuard.Engine != config.EngineEmbedded {
		return false, fmt.Errorf(`userspace NAT requires wireguard.engine = %q`, config.EngineEmbedded)
	}
	return userspace, nil
}

// serveNeedsPrivileges: system NAT always needs admin/root. Userspace NAT
// only does on Unix when binding a port below 1024.
func serveNeedsPrivileges(c *config.Config, userspace bool) bool {
	if !userspace {
		return true
	}
	if runtime.GOOS == "windows" || c.Reachability.Mode == config.ReachRelay {
		return false
	}
	return c.Transport.Port < 1024
}

// upnpTimeout bounds router discovery + mapping at startup.
const upnpTimeout = 8 * time.Second

// upnpRetryEvery is how often to ask the router again when it didn't answer.
const upnpRetryEvery = 2 * time.Minute

// openRouterPort tries to forward the exit node's port on the home router via
// UPnP and returns a human-readable status (shown by the app and status), plus
// a stop func that removes the mapping. It never fails serve: without UPnP the
// user just gets precise manual instructions. If the router doesn't answer,
// it keeps asking in the background; onChange reports a later success.
func openRouterPort(ctx context.Context, c *config.Config, lanIP string, onChange func(string)) (string, func()) {
	port := c.Transport.Port
	manual := fmt.Sprintf("Forward TCP %d on your router to %s (this PC)", port, lanIP)
	if a, err := netip.ParseAddr(lanIP); err == nil && a.IsGlobalUnicast() && !a.IsPrivate() && !upnp.BehindCarrierNAT(lanIP) {
		// A server (e.g. a VPS) with a public address: no home router.
		slog.Info("this machine has a public address; no router port forward needed", "address", lanIP, "port", port)
		return fmt.Sprintf("This machine has a public address (%s); make sure TCP %d is allowed in its firewall.", lanIP, port), nil
	}
	if !c.Reachability.UPnP || lanIP == "" {
		slog.Info("router port forward needed", "port", port, "to", lanIP)
		return manual, nil
	}
	dctx, cancel := context.WithTimeout(ctx, upnpTimeout)
	defer cancel()
	m, err := upnp.Open(dctx, port, lanIP)
	if ce := (*upnp.ConflictError)(nil); errors.As(err, &ce) {
		alt := "another port"
		if c.Transport.Kind == config.TransportCloudflare {
			alt = "another Cloudflare port (2053, 2083, 2087, 2096 or 8443)"
		}
		msg := fmt.Sprintf("Your router already sends port %d to another PC (%s), probably your other exit node: "+
			"one internet address can give a port to only one PC. Stop that exit node, or set this one up again with %s "+
			"(Share → Reset…, then Advanced → Port).", port, holderOr(ce), alt)
		slog.Error(msg)
		return msg, nil
	}
	if err != nil {
		slog.Warn("could not open the router port automatically; will keep trying (or forward it manually)", "port", port, "to", lanIP, "reason", err)
		// The router may still be starting up (e.g. after a power cut) or
		// missed the request: keep asking in the background.
		rctx, rcancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			t := time.NewTicker(upnpRetryEvery)
			defer t.Stop()
			for {
				select {
				case <-rctx.Done():
					return
				case <-t.C:
				}
				dctx, cancel := context.WithTimeout(rctx, upnpTimeout)
				m, err := upnp.Open(dctx, port, lanIP)
				cancel()
				if err != nil {
					continue
				}
				slog.Info("router port opened automatically (UPnP)", "public", fmt.Sprintf("%s:%d", m.ExternalIP, port), "to", fmt.Sprintf("%s:%d", lanIP, port))
				if onChange != nil {
					onChange(fmt.Sprintf("Router port %d opened automatically (UPnP) → %s", port, lanIP))
				}
				m.KeepAlive(rctx)
				return
			}
		}()
		return manual + " — automatic setup (UPnP) didn't work yet (" + err.Error() + "); Backhaul keeps trying every 2 minutes.",
			func() { rcancel(); <-done }
	}
	kctx, kcancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.KeepAlive(kctx); close(done) }()
	stop := func() { kcancel(); <-done }

	if m.ExternalIP != "" && upnp.BehindCarrierNAT(m.ExternalIP) {
		slog.Error("carrier-grade NAT detected: the internet can't reach this PC, port forwarding cannot work",
			"router_wan_ip", m.ExternalIP)
		return fmt.Sprintf("Your router's internet address is %s: your ISP uses carrier-grade NAT, so the other PC can't reach this one. "+
			"Ask your ISP for a public IP address, or use relay mode.", m.ExternalIP), stop
	}
	if ep, err := netip.ParseAddr(c.Transport.Endpoint); err == nil && m.ExternalIP != "" && ep.String() != m.ExternalIP {
		slog.Warn("the exit node address in the pairing differs from the router's public IP; the client will dial the wrong address",
			"pairing", ep, "router_public_ip", m.ExternalIP)
	}
	slog.Info("router port opened automatically (UPnP)", "public", fmt.Sprintf("%s:%d", m.ExternalIP, port), "to", fmt.Sprintf("%s:%d", lanIP, port))
	return fmt.Sprintf("Router port %d opened automatically (UPnP) → %s", port, lanIP), stop
}

// serveTransport builds the exit node's transport for the configured kind.
// The returned options describe the wstunnel role (for logging).
func (e *Env) serveTransport(ctx context.Context, cl *cleanup) (transport.Transport, transport.WstunnelOptions, error) {
	c := e.Cfg
	wgLocal := "127.0.0.1:" + strconv.Itoa(c.WireGuard.ListenPort)
	if c.Transport.Kind == config.TransportReality {
		xp, err := transport.EnsureXray(ctx, c, e.Paths.Bin())
		if err != nil {
			return nil, transport.WstunnelOptions{}, err
		}
		r := c.Transport.Reality
		cfgPath := filepath.Join(e.Paths.State(), "xray-server.json")
		tr, err := transport.NewReality(transport.RealityOptions{
			Binary: xp, Role: transport.RoleServer, ConfigPath: cfgPath,
			ListenAddr: c.Transport.ListenAddr, Port: c.Transport.Port, PrivateKey: e.Sec.RealityPrivateKey,
			UUID: e.Sec.RealityUUID, ShortID: r.ShortID, ServerName: r.ServerName, Target: r.Target,
			ReadyTimeout: c.Transport.ReadyTimeout.Duration, BackoffMin: c.Transport.BackoffMin.Duration,
			BackoffMax: c.Transport.BackoffMax.Duration,
		})
		if err != nil {
			return nil, transport.WstunnelOptions{}, err
		}
		cl.push("remove xray config", func(context.Context) { os.Remove(cfgPath) }) // contains secrets
		return tr, transport.WstunnelOptions{Role: "reality-server"}, nil
	}

	wstPath, err := transport.EnsureWstunnel(ctx, c, e.Paths.Bin())
	if err != nil {
		return nil, transport.WstunnelOptions{}, err
	}
	opts := transport.WstunnelOptions{
		Binary: wstPath, PathPrefix: c.Transport.PathPrefix,
		ReadyTimeout: c.Transport.ReadyTimeout.Duration, BackoffMin: c.Transport.BackoffMin.Duration,
		BackoffMax: c.Transport.BackoffMax.Duration, Verbose: e.Verbose,
	}
	if c.Reachability.Mode == config.ReachRelay {
		r := c.Reachability.Relay
		ip, err := resolveEndpoint(ctx, r.Host, c.Transport.DialTimeout.Duration)
		if err != nil {
			return nil, opts, err
		}
		remote := netip.AddrPortFrom(ip, uint16(r.Port)).String()
		proxy, err := tlspin.NewProxy(func() string { return remote }, r.Host, r.TLSSHA256, c.Transport.DialTimeout.Duration)
		if err != nil {
			return nil, opts, err
		}
		go proxy.Serve(ctx)
		cl.push("close TLS proxy", func(context.Context) { proxy.Close() })
		opts.Role, opts.ServerURL = transport.RoleReverseClient, "ws://"+proxy.Addr()
		opts.RelayBind, opts.RemoteUDP = "127.0.0.1:"+strconv.Itoa(r.RemotePort), wgLocal
	} else {
		opts.Role = transport.RoleServer
		opts.ListenAddr, opts.Port = c.Transport.ListenAddr, c.Transport.Port
		opts.CertFile, opts.KeyFile = c.Transport.CertFile, c.Transport.KeyFile
		opts.RestrictTo = wgLocal
	}
	return transport.NewWstunnel(opts), opts, nil
}

func holderOr(ce *upnp.ConflictError) string {
	if ce.Holder == "" {
		return "address unknown"
	}
	return ce.Holder
}
