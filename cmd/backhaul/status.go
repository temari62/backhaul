package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"backhaul/internal/app"
	"backhaul/internal/config"
	"backhaul/internal/health"
	"backhaul/internal/keys"
	"backhaul/internal/state"
	"backhaul/internal/wg"
)

func statusCmd(g *globals) *cobra.Command {
	var asJSON, noIP bool
	c := &cobra.Command{
		Use:   "status",
		Short: "Show tunnel state, handshake age, egress IP, bytes in/out and transport state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := g.paths()
			if err != nil {
				return err
			}
			cfg, _, err := config.Load(p)
			if err != nil {
				return err
			}
			rt, ok, err := state.Read(p.State())
			if err != nil {
				return err
			}
			up := ok && rt.Fresh(3*cfg.Health.Interval.Duration) && app.ProcessAlive(rt.PID)
			out := map[string]any{"mode": cfg.Mode, "up": up}
			if ok && up {
				// Prefer live numbers from the device; fall back to the snapshot.
				if st, err := wg.StatsViaWgctrl(rt.Iface); err == nil {
					rt.LastHandshake, rt.RxBytes, rt.TxBytes = st.LastHandshake, st.RxBytes, st.TxBytes
				}
				out["runtime"] = rt
			}
			var egress string
			if !noIP {
				if ip, err := health.EgressIP(cmd.Context(), cfg.Health.IPCheckURL, "tcp4", cfg.Health.ProbeTimeout.Duration); err == nil {
					egress = ip.String()
				} else {
					egress = "unavailable (" + err.Error() + ")"
				}
				out["egress_ip"] = egress
			}
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			if !up {
				fmt.Printf("backhaul (%s): DOWN — not running\n", cfg.Mode)
				if egress != "" {
					fmt.Printf("  egress IP:       %s\n", egress)
				}
				return nil
			}
			hs := "never"
			if !rt.LastHandshake.IsZero() {
				hs = time.Since(rt.LastHandshake).Round(time.Second).String() + " ago"
			}
			health := "healthy"
			if !rt.Healthy {
				health = "NO RECENT HANDSHAKE"
			}
			fmt.Printf("backhaul (%s): UP — %s\n", cfg.Mode, health)
			fmt.Printf("  interface:       %s (%s engine), pid %d, up %s\n", rt.Iface, rt.Engine, rt.PID, time.Since(rt.Started).Round(time.Second))
			if rt.Endpoint != "" {
				fmt.Printf("  endpoint:        %s (%s)\n", rt.Endpoint, rt.EndpointIP)
			}
			fmt.Printf("  last handshake:  %s\n", hs)
			fmt.Printf("  bytes in/out:    %s / %s\n", human(rt.RxBytes), human(rt.TxBytes))
			fmt.Printf("  transport:       %s %s (restarts %d)\n", rt.Transport.Kind, rt.Transport.State, rt.Transport.Restarts)
			if rt.Transport.LastError != "" {
				fmt.Printf("  transport error: %s\n", rt.Transport.LastError)
			}
			if cfg.Mode == config.ModeConnect {
				fmt.Printf("  kill-switch:     %v   ipv6 tunnelled: %v   reconnects: %d\n", rt.KillSwitch, rt.IPv6Tunneled, rt.Reconnects)
			}
			if egress != "" {
				fmt.Printf("  egress IP:       %s\n", egress)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	c.Flags().BoolVar(&noIP, "no-ip", false, "skip the external egress-IP lookup")
	return c
}

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func keysCmd(g *globals) *cobra.Command {
	c := &cobra.Command{Use: "keys", Short: "Show or generate WireGuard keys"}
	c.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print this machine's and the peer's public keys",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			p, err := g.paths()
			if err != nil {
				return err
			}
			cfg, sec, err := config.Load(p)
			if err != nil {
				return err
			}
			pub, err := keys.PublicFromPrivate(sec.PrivateKey)
			if err != nil {
				return err
			}
			fmt.Printf("this machine (%s) public key: %s\n", cfg.Mode, pub)
			fmt.Printf("peer public key:                %s\n", cfg.Peer.PublicKey)
			fmt.Printf("preshared key:                  %v\n", map[bool]string{true: "set", false: "not set"}[sec.PresharedKey != ""])
			return nil
		},
	}, &cobra.Command{
		Use:   "generate",
		Short: "Print a fresh WireGuard keypair and preshared key (for manual setups)",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			kp, err := keys.NewPair()
			if err != nil {
				return err
			}
			psk, err := keys.NewPresharedKey()
			if err != nil {
				return err
			}
			fmt.Printf("private_key   = %s\npublic_key    = %s\npreshared_key = %s\n", kp.Private, kp.Public, psk)
			return nil
		},
	})
	return c
}
