// Package engine runs serve/connect as root in a separate process on behalf
// of a desktop app whose own window stays unprivileged (the macOS and Linux
// apps).
//
// A GUI process running as root is unsupported on macOS (it cannot even see
// the user's pasteboard) and a poor fit on Linux (no Wayland display, root-
// owned files in the user's home), and only serve/connect need root. So they
// run in an "engine": the app's own binary re-launched with --engine through
// the platform's administrator prompt (osascript on macOS, pkexec on Linux;
// one prompt per Start). The two sides talk through the profile's state
// directory, the way the CLI's `backhaul status`/`disconnect` already do:
//
//	runtime.json  engine → app   status (world-readable; gui.Backend.State reads it)
//	stop          app → engine   stop request (state.RequestStop; the engine's WatchStop acts on it)
//	engine.pid    engine → app   the engine is up
//	engine.err    engine → app   the engine exited; contents = the error ("" = clean stop)
//	engine.log    engine → app   the engine's log, tailed into the Activity panel
//
// The app creates the state directory first, so it stays owned by the user
// and the app can keep writing the stop file beside the engine's root-owned
// files (unlinking those is allowed too: it owns the directory).
package engine

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"backhaul/internal/app"
	"backhaul/internal/config"
	"backhaul/internal/gui"
)

const (
	pidFile    = "engine.pid"
	errFile    = "engine.err"
	logFile    = "engine.log"
	startLimit = 30 * time.Second // the engine must report its pid within this
)

// IsInvocation reports whether this process was started as the engine
// (`exe --engine …`). Apps check it first thing in main and hand os.Args[2:]
// to Main.
func IsInvocation() bool { return len(os.Args) > 1 && os.Args[1] == "--engine" }

// Main is the privileged side: it runs one role for one profile until
// stopped, then exits. It never returns.
func Main(args []string) {
	fs := flag.NewFlagSet("engine", flag.ContinueOnError)
	role := fs.String("role", "", "serve or connect")
	dir := fs.String("dir", "", "profile directory")
	parent := fs.Int("parent", 0, "the app's pid; the engine stops when it is gone")
	nat := fs.String("nat", "", "BACKHAUL_NAT_MODE override")
	if err := fs.Parse(args); err != nil || *dir == "" || (*role != gui.RoleServe && *role != gui.RoleConnect) {
		fmt.Fprintln(os.Stderr, "usage: --engine -role serve|connect -dir DIR -parent PID [-nat MODE]")
		os.Exit(2)
	}
	p := config.Paths{Dir: *dir}
	stateDir := p.State()
	_ = os.MkdirAll(stateDir, 0o755)

	// Log to a file the app tails. Reusing LogBuffer as the handler gives the
	// same "time LEVEL text" lines as the app's own log, which drainLog parses.
	logf, err := os.OpenFile(filepath.Join(stateDir, logFile), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		exit(stateDir, err)
	}
	slog.SetDefault(slog.New(gui.NewLogBuffer(1, logf, slog.LevelInfo)))

	if os.Geteuid() != 0 {
		exit(stateDir, errors.New("the engine must run as root"))
	}
	if err := os.WriteFile(filepath.Join(stateDir, pidFile), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		exit(stateDir, err)
	}
	cfg, sec, err := config.Load(p)
	if err != nil {
		exit(stateDir, err)
	}
	if *nat != "" {
		cfg.Serve.NATMode = *nat
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// SIGHUP too: under pkexec the engine shares the app's session, so a
	// closed terminal must still tear the network down rather than kill it.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() { <-sig; slog.Info("engine: signal received, stopping"); cancel() }()
	if *parent > 0 {
		// The app is gone (quit or crashed): put the network back rather than
		// run on headless.
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if !processAlive(*parent) {
						slog.Info("engine: the app has quit, restoring the network")
						cancel()
						return
					}
				}
			}
		}()
	}

	env := &app.Env{Cfg: cfg, Sec: sec, Paths: p}
	slog.Info("engine started", "role", *role, "profile", *dir, "pid", os.Getpid())
	if *role == gui.RoleServe {
		err = app.Serve(ctx, env)
	} else {
		err = app.Connect(ctx, env, cfg.Client.KillSwitch)
	}
	if errors.Is(err, context.Canceled) {
		err = nil // a requested stop is a clean exit
	}
	exit(stateDir, err)
}

// exit reports the outcome to the app (engine.err; "" = clean) and exits.
// Written via rename so the app never sees a partial file.
func exit(stateDir string, err error) {
	msg, code := "", 0
	if err != nil {
		msg, code = err.Error(), 1
		slog.Error("engine stopped", "err", err)
	}
	p := filepath.Join(stateDir, errFile)
	_ = os.WriteFile(p+".tmp", []byte(msg), 0o644)
	_ = os.Rename(p+".tmp", p)
	os.Exit(code)
}
