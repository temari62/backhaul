package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"backhaul/internal/app"
	"backhaul/internal/config"
	"backhaul/internal/ddns"
	"backhaul/internal/osutil"
	"backhaul/internal/pairing"
	"backhaul/internal/tlspin"
)

type setupFlags struct {
	importBlob string
	role       string
	endpoint   string
	port       int
	subnet     string
	subnet6    string
	reach      string
	relay      config.Relay
	ddns       config.DDNS
	ddnsToken  string
	yes        bool
	force      bool
	qr         bool
	transport  string
}

func setupCmd(g *globals) *cobra.Command {
	f := &setupFlags{}
	d := config.Default()
	c := &cobra.Command{
		Use:   "setup",
		Short: "One-time wizard: generate keys/cert/config and the pairing blob",
		Long: `Run once, ideally on an unrestricted network.

On the exit node (Laptop 2):   backhaul setup
  → writes the serve config and prints a pairing blob (also saved to pairing.txt).
On the client (Laptop 1):      backhaul setup --import <blob>   (or --import @pairing.txt)`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSetup(cmd.Context(), g, f, cmd.Flags().Changed("subnet6"))
		},
	}
	fl := c.Flags()
	fl.StringVar(&f.importBlob, "import", "", "pairing blob from the exit node (or @file to read it from a file)")
	fl.StringVar(&f.role, "role", "", `which machine this is: "serve" (exit node) or "connect" (client)`)
	fl.StringVar(&f.endpoint, "endpoint", "", "exit node: public hostname (DDNS) or IP the client will dial")
	fl.IntVar(&f.port, "port", d.Transport.Port, "exit node: public TCP port for wstunnel")
	fl.StringVar(&f.subnet, "subnet", d.WireGuard.Subnet, "tunnel IPv4 subnet (server .1, client .2)")
	fl.StringVar(&f.subnet6, "subnet6", "fd09:b4c0::/64", `tunnel IPv6 subnet ("" disables IPv6 tunnelling)`)
	fl.StringVar(&f.reach, "reach", config.ReachPortForward, `reachability: "port-forward" or "relay"`)
	fl.StringVar(&f.relay.Host, "relay-host", "", "relay mode: VPS hostname")
	fl.IntVar(&f.relay.Port, "relay-port", d.Reachability.Relay.Port, "relay mode: VPS wstunnel port")
	fl.IntVar(&f.relay.RemotePort, "relay-remote-port", d.Reachability.Relay.RemotePort, "relay mode: UDP port opened on the VPS loopback")
	fl.StringVar(&f.relay.TLSSHA256, "relay-fingerprint", "", "relay mode: VPS wstunnel cert SHA-256 (AB:CD:...)")
	fl.StringVar(&f.ddns.Provider, "ddns-provider", "", `exit node: "duckdns", "cloudflare" or ""`)
	fl.StringVar(&f.ddns.Domain, "ddns-domain", "", "exit node: hostname to keep updated")
	fl.StringVar(&f.ddns.ZoneID, "ddns-zone", "", "cloudflare zone ID")
	fl.StringVar(&f.ddnsToken, "ddns-token", "", "DDNS API token (stored in secrets.toml)")
	fl.BoolVarP(&f.yes, "yes", "y", false, "non-interactive: accept defaults, never prompt")
	fl.BoolVar(&f.force, "force", false, "overwrite an existing config")
	fl.BoolVar(&f.qr, "qr", false, "exit node: also print the pairing blob as a terminal QR code")
	fl.StringVar(&f.transport, "transport", config.TransportWstunnel, `exit node: "wstunnel", or "reality" (VLESS+REALITY via Xray: impersonates www.amazon.com; best against China's firewall)`)
	return c
}

func pairingCmd(g *globals) *cobra.Command {
	var showQR bool
	c := &cobra.Command{
		Use:   "pairing",
		Short: "Re-print the exit node's pairing blob from pairing.txt (optionally as a QR code)",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			p, err := g.paths()
			if err != nil {
				return err
			}
			b, err := os.ReadFile(p.Pairing())
			if err != nil {
				return fmt.Errorf("%w — pairing.txt exists only on the exit node until you delete it; re-run `backhaul setup --force` to re-pair", err)
			}
			blob := strings.TrimSpace(string(b))
			fmt.Println(blob)
			if showQR {
				return printQR(blob)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&showQR, "qr", false, "print as a terminal QR code")
	return c
}

func printQR(blob string) error {
	osutil.EnableVT()
	fmt.Println("\nScan this QR code to copy the blob. It contains a private key, so keep the screen private:")
	return pairing.WriteQR(os.Stdout, blob)
}

type prompter struct {
	in  *bufio.Reader
	out io.Writer
	off bool
}

func (p *prompter) ask(q, def string) string {
	if p.off {
		return def
	}
	if def != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", q, def)
	} else {
		fmt.Fprintf(p.out, "%s: ", q)
	}
	line, _ := p.in.ReadString('\n')
	if line = strings.TrimSpace(line); line == "" {
		return def
	}
	return line
}

func runSetup(ctx context.Context, g *globals, f *setupFlags, subnet6Set bool) error {
	p, err := g.paths()
	if err != nil {
		return err
	}
	if _, err := os.Stat(p.Config()); err == nil && !f.force {
		return fmt.Errorf("%s already exists; pass --force to overwrite (this will invalidate the existing pairing)", p.Config())
	}
	pr := &prompter{in: bufio.NewReader(os.Stdin), out: os.Stdout, off: f.yes}

	if f.importBlob != "" {
		return importSetup(p, f.importBlob)
	}
	role := f.role
	if role == "" {
		if f.yes {
			return errors.New("--role is required with --yes")
		}
		fmt.Println("Which machine is this?")
		fmt.Println("  1) exit node (Laptop 2, at home — traffic will exit here)")
		fmt.Println("  2) client    (Laptop 1 — traffic will be routed through the exit node)")
		switch pr.ask("Choose 1 or 2", "1") {
		case "1", "serve":
			role = config.ModeServe
		case "2", "connect":
			role = config.ModeConnect
		default:
			return errors.New("please answer 1 or 2")
		}
	}
	if role == config.ModeConnect {
		if f.yes {
			return errors.New("client setup needs the exit node's pairing blob: backhaul setup --import <blob>")
		}
		fmt.Println("\nSet up the exit node first (`backhaul setup` there), then paste the pairing blob it printed.")
		blob := pr.ask("Pairing blob", "")
		if blob == "" {
			return errors.New("no pairing blob given")
		}
		return importSetup(p, blob)
	}
	if role != config.ModeServe {
		return fmt.Errorf("--role must be %q or %q", config.ModeServe, config.ModeConnect)
	}

	// Exit node wizard.
	endpoint := f.endpoint
	if endpoint == "" {
		def := ""
		if ip, err := detectPublicIP(ctx); err == nil {
			def = ip
		}
		fmt.Println("\nThe client needs a stable address for this machine. A DDNS hostname (e.g. myhome.duckdns.org)")
		fmt.Println("is best because home IPs change; your current public IP works for testing.")
		endpoint = pr.ask("Public hostname or IP of this exit node", def)
	}
	if endpoint == "" {
		return errors.New("an endpoint hostname/IP is required (--endpoint)")
	}
	port := f.port
	if !f.yes && f.port == config.Default().Transport.Port {
		if v, err := strconv.Atoi(pr.ask("Public TCP port (forward it on your router)", strconv.Itoa(port))); err == nil {
			port = v
		}
	}
	subnet := pr.ask("Tunnel IPv4 subnet", f.subnet)
	subnet6 := f.subnet6
	if !subnet6Set {
		subnet6 = pr.ask(`Tunnel IPv6 subnet ("none" to disable)`, subnet6)
	}
	if subnet6 == "none" {
		subnet6 = ""
	}
	reach := f.reach
	relay := f.relay
	if reach == config.ReachRelay {
		if relay.Host == "" {
			relay.Host = pr.ask("Relay VPS hostname", "")
		}
		if relay.TLSSHA256 == "" {
			relay.TLSSHA256 = pr.ask("Relay VPS wstunnel cert fingerprint (AB:CD:...)", "")
		}
		relay.TLSSHA256 = tlspin.Normalize(relay.TLSSHA256)
	}
	dd, token := f.ddns, f.ddnsToken
	if dd.Provider == "" && !f.yes && reach == config.ReachPortForward {
		if v := pr.ask(`Dynamic DNS provider ("duckdns", "cloudflare" or blank for none)`, ""); v != "" {
			dd.Provider = v
		}
	}
	if dd.Provider != "" {
		if dd.Domain == "" {
			dd.Domain = pr.ask("DDNS hostname to update", endpoint)
		}
		if dd.Provider == "cloudflare" && dd.ZoneID == "" {
			dd.ZoneID = pr.ask("Cloudflare zone ID", "")
		}
		if token == "" {
			token = pr.ask("DDNS API token (stored in secrets.toml, 0600)", "")
		}
	}

	res, err := app.SetupExitNode(p, app.ExitNodeOptions{
		Endpoint: endpoint, Port: port, Subnet: subnet, Subnet6: subnet6,
		ReachMode: reach, Relay: relay, DDNS: dd, DDNSToken: token, Transport: f.transport,
	})
	if err != nil {
		return err
	}
	if err := config.Save(p, res.Config, res.Secrets); err != nil {
		return err
	}
	if err := config.WriteFileAtomic(p.Pairing(), []byte(res.Blob+"\n"), 0o600); err != nil {
		return err
	}
	printExitNodeNextSteps(p, res, port, reach)
	if f.qr {
		return printQR(res.Blob)
	}
	return nil
}

func importSetup(p config.Paths, blob string) error {
	if strings.HasPrefix(blob, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(blob, "@"))
		if err != nil {
			return err
		}
		blob = string(b)
	}
	cfg, sec, err := app.ImportBlob(blob)
	if err != nil {
		return err
	}
	if err := config.Save(p, cfg, sec); err != nil {
		return err
	}
	host, port, fp := cfg.RemoteHost()
	fmt.Printf(`
Client configured: %s

  exit endpoint:  %s:%d
  pinned TLS:     %s
  kill-switch:    on (disable per-session with --no-killswitch)

Next steps:
  1. Delete the pairing blob/file you copied here — it contains this machine's private key.
  2. Make sure the exit node is running:  sudo backhaul serve
  3. Check reachability from here:        backhaul doctor
  4. Connect:                             %s
`, p.Config(), host, port, fp, elevated("backhaul connect"))
	return nil
}

func printExitNodeNextSteps(p config.Paths, res *app.SetupResult, port int, reach string) {
	fmt.Printf(`
Exit node configured: %s
TLS certificate fingerprint (SHA-256, pinned by the client):
  %s

=== PAIRING BLOB (also saved to %s, mode 0600) ===
%s
===================================================

The blob contains the client's private key. Move it over a trusted channel
(USB stick, Signal, scp), then delete pairing.txt. On the client run:

  backhaul setup --import <blob>

Next steps on this machine:
`, p.Config(), res.Fingerprint, p.Pairing(), res.Blob)
	if reach == config.ReachRelay {
		fmt.Printf(`  1. On the relay VPS run wstunnel server, e.g.:
       wstunnel server --restrict-http-upgrade-path-prefix %s wss://0.0.0.0:%d
  2. Start the exit node:   %s
`, res.Config.Transport.PathPrefix, res.Config.Reachability.Relay.Port, elevated("backhaul serve"))
		return
	}
	lan := "<this machine's LAN IP>"
	if ip := lanIP(); ip != "" {
		lan = ip
	}
	fmt.Printf(`  1. On your home router, forward TCP %d → %s:%d (and give this machine a DHCP reservation).
  2. Make sure %s keeps pointing at your home IP (configure [ddns] or your DNS provider).
  3. Start the exit node:   %s
  4. Verify:                backhaul doctor
`, port, lan, port, res.Config.Transport.Endpoint, elevated("backhaul serve"))
}

func elevated(cmd string) string {
	if os.PathSeparator == '\\' {
		return cmd + "   (from an elevated terminal)"
	}
	return "sudo " + cmd
}

func detectPublicIP(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return ddns.PublicIP(ctx, http.DefaultClient, config.Default().Health.IPCheckURL)
}

// lanIP finds the primary LAN address (no packets are sent by a UDP "dial").
func lanIP() string {
	c, err := net.Dial("udp", "192.0.2.1:9") // TEST-NET-1; only used for route selection
	if err != nil {
		return ""
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}
