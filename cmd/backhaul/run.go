package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"backhaul/internal/app"
	"backhaul/internal/config"
)

func loadEnv(g *globals, wantMode string) (*app.Env, error) {
	p, err := g.paths()
	if err != nil {
		return nil, err
	}
	cfg, sec, err := config.Load(p)
	if err != nil {
		return nil, err
	}
	if wantMode != "" && cfg.Mode != wantMode {
		return nil, fmt.Errorf("%s is configured for mode %q; this command needs %q (re-run `backhaul setup`)",
			p.Config(), cfg.Mode, wantMode)
	}
	return &app.Env{Cfg: cfg, Sec: sec, Paths: p, Verbose: g.verbose}, nil
}

func serveCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the exit node (Laptop 2): terminate the tunnel and NAT traffic to the internet",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			env, err := loadEnv(g, config.ModeServe)
			if err != nil {
				return err
			}
			return app.Serve(cmd.Context(), env)
		},
	}
}

func connectCmd(g *globals) *cobra.Command {
	var noKill bool
	c := &cobra.Command{
		Use:   "connect",
		Short: "Run the client (Laptop 1): route all traffic through the exit node",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			env, err := loadEnv(g, config.ModeConnect)
			if err != nil {
				return err
			}
			return app.Connect(cmd.Context(), env, env.Cfg.Client.KillSwitch && !noKill)
		},
	}
	c.Flags().BoolVar(&noKill, "no-killswitch", false, "do not block non-tunnel traffic if the tunnel drops (your real IP can leak)")
	return c
}

func disconnectCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "disconnect",
		Short: "Stop a running serve/connect (from another terminal, a service or the tray) and wait for it to restore the system",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := g.paths()
			if err != nil {
				return err
			}
			if err := app.Disconnect(cmd.Context(), p, app.TeardownTimeout+10*time.Second); err != nil {
				return err
			}
			fmt.Println("disconnected; original network configuration restored")
			return nil
		},
	}
}
