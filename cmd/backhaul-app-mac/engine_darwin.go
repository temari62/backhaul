//go:build darwin && cgo

// The macOS app keeps its GUI unprivileged. A GUI process running as root is
// unsupported by Apple and, among other things, is cut off from the user's
// pasteboard — which is why paste into the app's fields silently did nothing
// while the app re-launched itself as root. Only serve/connect need root, so
// they run in a separate "engine" process: this same binary re-launched with
// --engine through osascript's administrator prompt (one password prompt per
// Start). The two sides talk through the profile's state directory, the way
// the CLI's `backhaul status`/`disconnect` already do:
//
//	runtime.json  engine → GUI   status (world-readable; gui.Backend.State reads it)
//	stop          GUI → engine   stop request (state.RequestStop; the engine's WatchStop acts on it)
//	engine.pid    engine → GUI   the engine is up
//	engine.err    engine → GUI   the engine exited; contents = the error ("" = clean stop)
//	engine.log    engine → GUI   the engine's log, tailed into the Activity panel
//
// The GUI creates the state directory first, so it stays owned by the user
// and the GUI can keep writing the stop file beside the engine's root-owned
// files (unlinking those is allowed too: it owns the directory).
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"backhaul/internal/app"
	"backhaul/internal/config"
	"backhaul/internal/gui"
	"backhaul/internal/state"
)

const (
	enginePIDFile = "engine.pid"
	engineErrFile = "engine.err"
	engineLogFile = "engine.log"
	engineStart   = 30 * time.Second // the engine must report its pid within this
)

// isEngineInvocation reports whether this process was started as the engine.
func isEngineInvocation() bool { return len(os.Args) > 1 && os.Args[1] == "--engine" }

// engineMain is the privileged side: it runs one role for one profile until
// stopped, then exits. It never returns.
func engineMain(args []string) {
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

	// Log to a file the GUI tails. Reusing LogBuffer as the handler gives the
	// same "time LEVEL text" lines as the app's own log, which drainLog parses.
	logf, err := os.OpenFile(filepath.Join(stateDir, engineLogFile), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		exitEngine(stateDir, err)
	}
	slog.SetDefault(slog.New(gui.NewLogBuffer(1, logf, slog.LevelInfo)))

	if os.Geteuid() != 0 {
		exitEngine(stateDir, errors.New("the engine must run as root"))
	}
	if err := os.WriteFile(filepath.Join(stateDir, enginePIDFile), []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		exitEngine(stateDir, err)
	}
	cfg, sec, err := config.Load(p)
	if err != nil {
		exitEngine(stateDir, err)
	}
	if *nat != "" {
		cfg.Serve.NATMode = *nat
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
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
	exitEngine(stateDir, err)
}

// exitEngine reports the outcome to the GUI (engine.err; "" = clean) and
// exits. Written via rename so the GUI never sees a partial file.
func exitEngine(stateDir string, err error) {
	msg, code := "", 0
	if err != nil {
		msg, code = err.Error(), 1
		slog.Error("engine stopped", "err", err)
	}
	p := filepath.Join(stateDir, engineErrFile)
	_ = os.WriteFile(p+".tmp", []byte(msg), 0o644)
	_ = os.Rename(p+".tmp", p)
	os.Exit(code)
}

// processAlive reports whether pid exists. EPERM counts as alive: the
// unprivileged GUI may not signal the root engine, but it does exist.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// runElevated is gui.Backend.Run for macOS: it starts the engine as root and
// returns once it has exited. Cancelling ctx asks it to stop (the stop file)
// and then waits for its teardown, so the network is restored before Start
// reports the role as stopped.
func runElevated(logs *gui.LogBuffer) func(ctx context.Context, role string, env *app.Env) error {
	return func(ctx context.Context, role string, env *app.Env) error {
		stateDir := env.Paths.State()
		// Own the state dir before root writes into it (see the file comment).
		if err := os.MkdirAll(stateDir, 0o755); err != nil {
			return err
		}
		pidPath := filepath.Join(stateDir, enginePIDFile)
		errPath := filepath.Join(stateDir, engineErrFile)
		logPath := filepath.Join(stateDir, engineLogFile)
		for _, f := range []string{pidPath, errPath, logPath} {
			_ = os.Remove(f) // a previous run's markers
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		cmdline := fmt.Sprintf("%s --engine -role %s -dir %s -parent %d", shellQuote(exe), role, shellQuote(env.Paths.Dir), os.Getpid())
		if m := os.Getenv("BACKHAUL_NAT_MODE"); m != "" {
			cmdline += " -nat " + shellQuote(m)
		}
		// Backgrounded with its output redirected, so `do shell script` returns
		// as soon as the engine is launched instead of waiting for it to end.
		script := fmt.Sprintf("do shell script %s with administrator privileges", asQuote(cmdline+" >/dev/null 2>&1 &"))
		slog.Info("asking for administrator rights to start the engine", "role", role)
		if out, err := exec.CommandContext(ctx, "osascript", "-e", script).CombinedOutput(); err != nil {
			if strings.Contains(strings.ToLower(string(out)), "cancel") { // "User canceled. (-128)"
				return errors.New("Backhaul needs administrator rights for this: click the button again and enter your password")
			}
			return fmt.Errorf("could not start the engine: %s", strings.TrimSpace(string(out)))
		}

		pid, err := waitForPID(pidPath, errPath)
		if err != nil {
			return err
		}
		slog.Info("engine running", "pid", pid)
		stopTail := tailLog(logPath, logs)
		defer stopTail()

		stopAsked := false
		var deadline time.Time
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			if msg, ok := readMarker(errPath); ok {
				if msg == "" {
					return nil
				}
				return errors.New(msg)
			}
			if !stopAsked && ctx.Err() != nil {
				stopAsked = true
				deadline = time.Now().Add(app.MaxShutdown)
				if err := state.RequestStop(stateDir); err != nil {
					return fmt.Errorf("could not ask the engine to stop: %w", err)
				}
				slog.Info("asked the engine to stop")
			}
			if stopAsked && time.Now().After(deadline) {
				return fmt.Errorf("the engine (pid %d) did not stop within %s", pid, app.MaxShutdown)
			}
			if !processAlive(pid) {
				time.Sleep(time.Second) // give exitEngine's marker a moment to land
				if msg, ok := readMarker(errPath); ok && msg != "" {
					return errors.New(msg)
				} else if ok {
					return nil
				}
				return errors.New("the engine stopped unexpectedly (details in Activity)")
			}
			<-t.C
		}
	}
}

// waitForPID waits for the engine to write its pid, or to fail first.
func waitForPID(pidPath, errPath string) (int, error) {
	deadline := time.Now().Add(engineStart)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(pidPath); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
				return pid, nil
			}
		}
		if msg, ok := readMarker(errPath); ok {
			if msg == "" {
				msg = "the engine exited at once"
			}
			return 0, errors.New(msg)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return 0, fmt.Errorf("the engine did not start within %s (details in Activity)", engineStart)
}

// readMarker reads engine.err; ok=false while the engine is still running.
func readMarker(p string) (msg string, ok bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// tailLog copies new lines of the engine's log into the activity panel until
// the returned func is called (which also drains the final teardown lines).
func tailLog(path string, logs *gui.LogBuffer) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		var off int64
		t := time.NewTicker(400 * time.Millisecond)
		defer t.Stop()
		for {
			off = drainLog(path, off, logs)
			select {
			case <-ctx.Done():
				drainLog(path, off, logs)
				return
			case <-t.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}

// drainLog reads whole lines after off ("time LEVEL text", as LogBuffer
// writes them) into logs and returns the new offset. A partial last line is
// left for the next call.
func drainLog(path string, off int64, logs *gui.LogBuffer) int64 {
	f, err := os.Open(path)
	if err != nil {
		return off
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return off
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return off
	}
	end := bytes.LastIndexByte(b, '\n')
	if end < 0 {
		return off
	}
	for _, line := range strings.Split(string(b[:end]), "\n") {
		if line == "" {
			continue
		}
		_, rest, ok := strings.Cut(line, " ") // drop the timestamp
		if !ok {
			continue
		}
		level, text, _ := strings.Cut(strings.TrimLeft(rest, " "), " ")
		logs.Add(level, strings.TrimLeft(text, " "))
	}
	return off + int64(end) + 1
}
