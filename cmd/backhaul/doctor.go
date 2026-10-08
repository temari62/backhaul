package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"backhaul/internal/app"
	"backhaul/internal/config"
	"backhaul/internal/doctor"
	"backhaul/internal/osutil"
)

func doctorCmd(g *globals) *cobra.Command {
	var recover bool
	c := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose privileges, reachability, TLS pin, handshake and IP/DNS/IPv6 leaks",
		Long: `Runs every applicable check and prints PASS/FAIL with a remedy.
Live checks (handshake, leak tests) run when serve/connect is active.

--recover restores routes/DNS/firewall/NAT left behind by a crashed run.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := g.paths()
			if err != nil {
				return err
			}
			if recover {
				if err := osutil.RequirePrivileges(); err != nil {
					return err
				}
				n, err := app.Recover(cmd.Context(), p)
				if err != nil {
					return err
				}
				fmt.Printf("recovery: replayed %d restore step(s)\n", n)
				return nil
			}
			cfg, _, err := config.Load(p)
			if err != nil {
				return err
			}
			d := &doctor.Doctor{Cfg: cfg, Paths: p}
			rs := d.All(cmd.Context())
			doctor.Print(os.Stdout, rs)
			if doctor.Failed(rs) {
				return errors.New("doctor found problems")
			}
			return nil
		},
	}
	c.Flags().BoolVar(&recover, "recover", false, "undo system changes left by a crashed serve/connect")
	return c
}
