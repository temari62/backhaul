// Package gui is the OS-neutral backend of the Backhaul desktop app: it owns
// the two profiles (exit node and client), runs serve/connect in-process,
// and exposes a small API the web UI calls.
package gui

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"

	"backhaul/internal/app"
	"backhaul/internal/config"
	"backhaul/internal/ddns"
	"backhaul/internal/doctor"
	"backhaul/internal/health"
	"backhaul/internal/osutil"
	"backhaul/internal/state"
)

// Roles.
const (
	RoleServe   = config.ModeServe
	RoleConnect = config.ModeConnect
)

// TransportCFTunnel is the setup choice "Cloudflare Tunnel": the Cloudflare
// disguise with an outgoing tunnel instead of a router port forward.
const TransportCFTunnel = "cftunnel"

// Backend is safe for concurrent use.
type Backend struct {
	Base    string                     // ~/.config/backhaul
	Logs    *LogBuffer                 //
	Prepare func(*config.Config) error // e.g. point at bundled wstunnel
	Verbose bool
	// IPCheckURL overrides the public-IP service (tests).
	IPCheckURL string

	mu       sync.Mutex
	running  string // role currently running ("" = none)
	stopping bool
	cancel   context.CancelFunc
	done     chan struct{}
	lastErr  string
	egress   string
	egressAt time.Time

	migrateOnce sync.Once
}

// ProfileDir returns the config dir for a role. A config made by the CLI in
// the base dir is adopted for its own mode; otherwise each role gets its own
// subdirectory, so one PC can hold both an exit-node and a client profile.
func (b *Backend) ProfileDir(role string) string {
	if role == RoleConnect {
		return b.connectDir() // the selected exit node
	}
	if c, err := readMode(b.Base); err == nil && c == role {
		return b.Base
	}
	return filepath.Join(b.Base, role)
}

func readMode(dir string) (string, error) {
	cfg, _, err := config.Load(config.Paths{Dir: dir})
	if err != nil {
		return "", err
	}
	return cfg.Mode, nil
}

func (b *Backend) paths(role string) config.Paths { return config.Paths{Dir: b.ProfileDir(role)} }

// RoleView describes one profile for the UI.
type RoleView struct {
	Configured bool   `json:"configured"`
	Endpoint   string `json:"endpoint,omitempty"`
	LANIP      string `json:"lanIp,omitempty"` // exit node: where the router must forward the port
	Transport  string `json:"transport,omitempty"`
	PairingID  string `json:"pairingId,omitempty"` // first bytes of the exit node cert fingerprint; equal on both PCs when paired
	Port       int    `json:"port,omitempty"`
	KillSwitch bool   `json:"killswitch"`
	HasPairing bool   `json:"hasPairing"`
	ConfigErr  string `json:"configError,omitempty"`
	Dir        string `json:"dir"`
}

// View is the whole UI state, polled by the page.
type View struct {
	Admin     bool     `json:"admin"`
	Serve     RoleView `json:"serve"`
	Connect   RoleView `json:"connect"`
	Running   string   `json:"running"` // "", "serve", "connect"
	Phase     string   `json:"phase"`   // idle, starting, waiting, up, reconnecting, stopping
	Error     string   `json:"error,omitempty"`
	Handshake string   `json:"handshake,omitempty"`
	Rx        int64    `json:"rx"`
	Tx        int64    `json:"tx"`
	RxRate    float64  `json:"rxRate"` // bytes/s through the tunnel, live
	TxRate    float64  `json:"txRate"`
	Egress    string   `json:"egress,omitempty"`
	NAT       string   `json:"nat,omitempty"`
	Uptime    string   `json:"uptime,omitempty"`
	Router    string   `json:"router,omitempty"` // exit node: port-forward status
	Nodes     []Node   `json:"nodes"`            // saved exit nodes (Connect list)
}

func (b *Backend) roleView(role string) RoleView {
	p := b.paths(role)
	v := RoleView{Dir: p.Dir}
	if _, err := os.Stat(p.Config()); err != nil {
		return v
	}
	cfg, _, err := config.Load(p)
	if err != nil {
		msg, _, _ := strings.Cut(err.Error(), "\n")
		v.ConfigErr = msg
		return v
	}
	v.Configured = true
	v.Transport = cfg.Transport.Kind
	if cfg.Reachability.Mode == config.ReachCFTunnel {
		v.Transport = TransportCFTunnel
	}
	host, port, _ := cfg.RemoteHost()
	v.Endpoint, v.Port, v.KillSwitch = host, port, cfg.Client.KillSwitch
	v.PairingID = pairingID(cfg)
	if role == RoleServe {
		v.Endpoint, v.Port = cfg.Transport.Endpoint, cfg.Transport.Port
		v.LANIP = osutil.LANIP()
		_, err := os.Stat(p.Pairing())
		v.HasPairing = err == nil
	}
	return v
}

// State returns the current view.
func (b *Backend) State() View {
	v := View{Admin: osutil.IsElevated(), Serve: b.roleView(RoleServe), Connect: b.roleView(RoleConnect), Phase: "idle", Nodes: b.Nodes()}
	b.mu.Lock()
	v.Running, v.Error = b.running, b.lastErr
	stopping := b.stopping
	b.mu.Unlock()
	if v.Running == "" {
		return v
	}
	v.Phase = "starting"
	if stopping {
		v.Phase = "stopping"
	}
	if rt, ok, _ := state.Read(b.paths(v.Running).State()); ok {
		if !rt.LastHandshake.IsZero() {
			v.Handshake = time.Since(rt.LastHandshake).Round(time.Second).String() + " ago"
		}
		v.Rx, v.Tx = rt.RxBytes, rt.TxBytes
		v.RxRate, v.TxRate = rt.RxRate, rt.TxRate
		v.Uptime = time.Since(rt.Started).Round(time.Second).String()
		v.NAT = rt.Iface
		v.Router = rt.Router
		if !stopping {
			switch {
			case rt.Healthy:
				v.Phase = "up"
			case v.Running == RoleServe:
				v.Phase = "waiting" // exit node is ready; no client handshake yet
			case rt.Reconnects > 0:
				v.Phase = "reconnecting"
			}
		}
	}
	if v.Running == RoleConnect && v.Phase == "up" {
		v.Egress = b.cachedEgress()
	}
	return v
}

// cachedEgress refreshes the public IP in the background every 30s.
func (b *Backend) cachedEgress() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if time.Since(b.egressAt) > 30*time.Second {
		b.egressAt = time.Now()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ip, err := health.EgressIP(ctx, config.Default().Health.IPCheckURL, "tcp4", 10*time.Second)
			b.mu.Lock()
			if err == nil {
				b.egress = ip.String()
			}
			b.mu.Unlock()
		}()
	}
	return b.egress
}

// DetectPublicIP is used to prefill the exit-node setup form.
func (b *Backend) DetectPublicIP() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return ddns.PublicIP(ctx, http.DefaultClient, config.Default().Health.IPCheckURL)
}

// Pairing is the exit node's pairing code plus a QR image.
type Pairing struct {
	Code string `json:"code"`
	QR   string `json:"qr"` // data: URL (PNG)
}

// SetupServe creates (or replaces) the exit-node profile.
func (b *Backend) SetupServe(endpoint string, port int, transportKind, cloudflareToken string) (Pairing, error) {
	if transportKind == "" {
		transportKind = config.TransportReality
	}
	endpoint = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(endpoint), "https://"), "http://"), "/"))
	if endpoint == "" {
		return Pairing{}, errors.New("enter this PC's public IP address or hostname")
	}
	if port < 1 || port > 65535 {
		return Pairing{}, errors.New("port must be between 1 and 65535")
	}
	if err := b.notRunning(RoleServe); err != nil {
		return Pairing{}, err
	}
	tunnel := transportKind == TransportCFTunnel
	if tunnel {
		transportKind, port = config.TransportCloudflare, 443 // the client dials Cloudflare on 443
	}
	opts := app.ExitNodeOptions{Endpoint: endpoint, Port: port,
		Subnet: "10.9.0.0/24", Subnet6: "fd09:b4c0::/64", ReachMode: config.ReachPortForward, Transport: transportKind}
	if tunnel {
		if _, err := netip.ParseAddr(endpoint); err == nil || !strings.Contains(endpoint, ".") {
			return Pairing{}, errors.New("enter the hostname you want on Cloudflare, e.g. home.yourdomain.com")
		}
		token := strings.TrimSpace(cloudflareToken)
		if token == "" {
			return Pairing{}, errors.New("paste your Cloudflare API token (see the steps in the help)")
		}
		if err := b.notRunning(RoleServe); err != nil {
			return Pairing{}, err
		}
		tr, err := app.PrepareCloudflareTunnel(context.Background(), token, endpoint, config.DefaultCFTunnelLocalPort)
		if err != nil {
			return Pairing{}, fmt.Errorf("Cloudflare Tunnel: %w", err)
		}
		opts.CloudflareZoneID, opts.CloudflareTunnelID, opts.CloudflareTunnelToken = tr.ZoneID, tr.TunnelID, tr.TunnelToken
	} else if transportKind == config.TransportCloudflare {
		if _, err := netip.ParseAddr(endpoint); err == nil || !strings.Contains(endpoint, ".") {
			return Pairing{}, errors.New("enter the hostname you want on Cloudflare, e.g. vpn.yourdomain.com")
		}
		if !config.CloudflarePorts[port] {
			return Pairing{}, errors.New("Cloudflare only forwards ports 443, 2053, 2083, 2087, 2096 and 8443 — use 443")
		}
		token := strings.TrimSpace(cloudflareToken)
		if token == "" {
			return Pairing{}, errors.New("paste your Cloudflare API token (see the steps in the help)")
		}
		ipURL := b.IPCheckURL
		if ipURL == "" {
			ipURL = config.Default().Health.IPCheckURL
		}
		cf, err := app.PrepareCloudflare(context.Background(), token, endpoint, ipURL)
		if err != nil {
			return Pairing{}, fmt.Errorf("Cloudflare: %w", err)
		}
		opts.CloudflareZoneID, opts.CloudflareToken = cf.ZoneID, token
	}
	p := b.paths(RoleServe)
	res, err := app.SetupExitNode(p, opts)
	if err != nil {
		return Pairing{}, err
	}
	if err := config.Save(p, res.Config, res.Secrets); err != nil {
		return Pairing{}, err
	}
	if err := config.WriteFileAtomic(p.Pairing(), []byte(res.Blob+"\n"), 0o600); err != nil {
		return Pairing{}, err
	}
	slog.Info("exit node configured", "endpoint", endpoint, "port", port, "disguise", transportKind)
	return pairingView(res.Blob)
}

// GetPairing returns the saved pairing code.
func (b *Backend) GetPairing() (Pairing, error) {
	raw, err := os.ReadFile(b.paths(RoleServe).Pairing())
	if err != nil {
		return Pairing{}, errors.New("no pairing code saved — set up the exit node again to create one")
	}
	return pairingView(strings.TrimSpace(string(raw)))
}

func pairingView(blob string) (Pairing, error) {
	code, err := qr.Encode(blob, qr.L)
	if err != nil {
		return Pairing{Code: blob}, nil // the text still works
	}
	code.Scale = 4
	return Pairing{Code: blob, QR: "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())}, nil
}

// ImportPairing adds an exit node from a pairing code and selects it.
func (b *Backend) ImportPairing(blob string) error {
	_, err := b.AddNode(blob, "")
	return err
}

// SetKillSwitch sets the kill-switch preference (for every saved exit node).
func (b *Backend) SetKillSwitch(on bool) error {
	if err := b.notRunning(RoleConnect); err != nil {
		return err
	}
	for _, id := range b.nodeIDs() {
		p := config.Paths{Dir: b.nodeDir(id)}
		cfg, sec, err := config.Load(p)
		if err != nil {
			continue
		}
		cfg.Client.KillSwitch = on
		if err := config.Save(p, cfg, sec); err != nil {
			return err
		}
	}
	return nil
}

// Reset forgets a role's profile (keys, certificate, pairing); for Connect,
// the selected exit node.
func (b *Backend) Reset(role string) error {
	if err := b.notRunning(role); err != nil {
		return err
	}
	if role == RoleConnect {
		if id := b.selectedNode(); id != "" {
			return b.RemoveNode(id)
		}
		return nil
	}
	dir := b.ProfileDir(role)
	if dir == b.Base {
		// CLI-made profile in the base dir: remove only its files.
		for _, f := range []string{"config.toml", "secrets.toml", "pairing.txt"} {
			os.Remove(filepath.Join(dir, f))
		}
		os.RemoveAll(filepath.Join(dir, "tls"))
		return nil
	}
	return os.RemoveAll(dir)
}

func (b *Backend) notRunning(role string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.running == role {
		return errors.New("stop it first")
	}
	return nil
}

// Start runs serve or connect in the background.
func (b *Backend) Start(role string) error {
	if role != RoleServe && role != RoleConnect {
		return fmt.Errorf("unknown role %q", role)
	}
	p := b.paths(role)
	cfg, sec, err := config.Load(p)
	if err != nil {
		return err
	}
	if b.Prepare != nil {
		if err := b.Prepare(cfg); err != nil {
			return err
		}
	}
	b.mu.Lock()
	if b.running != "" {
		b.mu.Unlock()
		return fmt.Errorf("%s is already running", b.running)
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.running, b.stopping, b.cancel, b.lastErr = role, false, cancel, ""
	b.done = make(chan struct{})
	done := b.done
	b.egress, b.egressAt = "", time.Time{}
	b.mu.Unlock()

	env := &app.Env{Cfg: cfg, Sec: sec, Paths: p, Verbose: b.Verbose}
	go func() {
		defer close(done)
		var err error
		if role == RoleServe {
			err = app.Serve(ctx, env)
		} else {
			err = app.Connect(ctx, env, cfg.Client.KillSwitch)
		}
		b.mu.Lock()
		if err != nil && !errors.Is(err, context.Canceled) {
			b.lastErr = friendly(err)
			slog.Error(role+" stopped", "err", err)
		}
		b.running, b.stopping, b.cancel = "", false, nil
		b.mu.Unlock()
	}()
	return nil
}

// Stop asks the running role to tear down; it returns immediately.
func (b *Backend) Stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cancel != nil {
		b.stopping = true
		b.cancel()
	}
}

// StopAndWait stops and waits (bounded) for the network to be restored.
// Called when the window closes.
func (b *Backend) StopAndWait(timeout time.Duration) {
	b.mu.Lock()
	done := b.done
	b.mu.Unlock()
	b.Stop()
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// ClearError dismisses the last error.
func (b *Backend) ClearError() {
	b.mu.Lock()
	b.lastErr = ""
	b.mu.Unlock()
}

// friendly rewrites CLI-oriented errors for the desktop app.
func friendly(err error) string {
	var np *osutil.ErrNotPrivileged
	if errors.As(err, &np) {
		return "Backhaul needs administrator rights for this. Close Backhaul, start it again and choose \"Yes\" when Windows asks for permission."
	}
	var pe *app.PreflightError
	if errors.As(err, &pe) {
		if _, ok := pe.Has(doctor.CheckTLSPin); ok {
			return "This PC's pairing doesn't match the exit node any more (the exit node was set up again, or something is intercepting the connection). " +
				"On the exit node, click \"Show pairing code\". Then here, in Connect, click \"Reset…\" and paste the new code. The Pairing IDs on both PCs should then match."
		}
		if r, ok := pe.Has(doctor.CheckOtherVPN); ok {
			return "Another VPN is connected on this PC (" + strings.TrimPrefix(r.Detail, "another VPN is connected: ") + "). " +
				"Disconnect it first: two VPNs fight over the network settings and both break. Backhaul already disguises its traffic as normal HTTPS, so it doesn't need another VPN underneath."
		}
		if r, ok := pe.Has(doctor.CheckEndpointTCP); ok {
			return "Can't reach the exit node (" + r.Detail + "). Check that: Backhaul on the exit node says \"Sharing\"; your router forwards TCP " +
				"to the exit node PC; and you're testing from a different network (e.g. a phone hotspot) — many routers can't connect to their own public IP from inside the home network."
		}
		if r, ok := pe.Has(doctor.CheckCloudflareOrigin); ok {
			return "Cloudflare can't reach your exit node (" + r.Detail + "). On the exit node PC, check that it's on and Backhaul shows Sharing, " +
				"that your home internet works, and that the router still forwards the port. If your home internet address changed while the exit node " +
				"wasn't sharing, starting sharing updates Cloudflare. Turning on \"Start with Windows\" on the exit node avoids this after restarts."
		}
		if r, ok := pe.Has(doctor.CheckEndpointDNS); ok {
			return "Can't find the exit node's address: " + r.Detail + ". Check the hostname, or your internet connection."
		}
	}
	return condensePowerShell(err.Error())
}

// condensePowerShell turns "install routes: powershell.exe … <script> … :
// exit status 1: New-NetFirewallRule : The specified interface was not
// found …" into "install routes: New-NetFirewallRule : The specified
// interface was not found on the system." (the full text stays in the log).
func condensePowerShell(msg string) string {
	i := strings.Index(msg, "powershell.exe ")
	if i < 0 {
		return msg
	}
	prefix := strings.TrimSuffix(strings.TrimSpace(msg[:i]), ":")
	rest := msg[i:]
	if j := strings.LastIndex(rest, "exit status "); j >= 0 {
		rest = rest[j:]
		if k := strings.Index(rest, ": "); k >= 0 {
			rest = rest[k+2:]
		}
	}
	line, _, _ := strings.Cut(strings.TrimSpace(rest), "\n")
	if prefix != "" {
		return prefix + ": " + line + " (details in Activity)"
	}
	return line + " (details in Activity)"
}
