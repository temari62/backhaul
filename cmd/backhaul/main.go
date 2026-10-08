// Command backhaul is a self-hosted two-machine personal VPN: `serve` on the
// exit node, `connect` on the client. WireGuard is the data plane; wstunnel
// (WebSocket over TLS on :443) carries it through restrictive networks.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"backhaul/internal/config"
	"backhaul/internal/osutil"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

type globals struct {
	configDir string
	verbose   bool
}

func (g *globals) paths() (config.Paths, error) {
	if g.configDir != "" {
		return config.Paths{Dir: g.configDir}, nil
	}
	d, err := config.DefaultDir()
	return config.Paths{Dir: d}, err
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := newRootCmd().ExecuteContext(ctx)
	stop()
	if err != nil {
		var np *osutil.ErrNotPrivileged
		if errors.As(err, &np) {
			fmt.Fprintln(os.Stderr, np.Error())
			os.Exit(77)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	g := &globals{}
	root := &cobra.Command{
		Use:           "backhaul",
		Short:         "Route this machine's traffic through your own home exit node",
		Long:          "Backhaul is a self-hosted two-machine VPN. Run `backhaul setup` on the exit node first, then `backhaul setup --import <blob>` on the client.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version,
		PersistentPreRun: func(*cobra.Command, []string) {
			lvl := slog.LevelInfo
			if g.verbose {
				lvl = slog.LevelDebug
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
		},
	}
	root.PersistentFlags().StringVar(&g.configDir, "config-dir", "", "config directory (default ~/.config/backhaul, or $BACKHAUL_CONFIG_DIR)")
	root.PersistentFlags().BoolVarP(&g.verbose, "verbose", "v", false, "debug logging (secrets are never logged)")
	root.AddCommand(setupCmd(g), serveCmd(g), connectCmd(g), statusCmd(g), keysCmd(g), doctorCmd(g))
	return root
}
