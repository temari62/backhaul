package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"backhaul/internal/app"
	"backhaul/internal/gui"
	"backhaul/internal/state"
)

// A Launcher starts exe with args as root, through the platform's
// authorization prompt, and returns as soon as it is launched. A launcher
// that stays the engine's parent (pkexec) also returns a channel that
// delivers its exit — the prompt was refused, or the engine is gone — and
// then closes; a fire-and-forget launcher (osascript) returns nil instead.
// Errors a launcher returns or delivers are shown to the user as they are,
// so word them for the user.
type Launcher func(ctx context.Context, exe string, args []string) (exited <-chan error, err error)

// Run returns a gui.Backend.Run that starts the engine as root with launch
// and returns once it has exited. Cancelling ctx asks it to stop (the stop
// file) and then waits for its teardown, so the network is restored before
// Start reports the role as stopped. The engine's log is copied into logs.
func Run(logs *gui.LogBuffer, launch Launcher) func(ctx context.Context, role string, env *app.Env) error {
	return func(ctx context.Context, role string, env *app.Env) error {
		stateDir := env.Paths.State()
		// Own the state dir before root writes into it (see the package comment).
		if err := os.MkdirAll(stateDir, 0o755); err != nil {
			return err
		}
		pidPath := filepath.Join(stateDir, pidFile)
		errPath := filepath.Join(stateDir, errFile)
		logPath := filepath.Join(stateDir, logFile)
		for _, f := range []string{pidPath, errPath, logPath} {
			_ = os.Remove(f) // a previous run's markers
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		args := []string{"--engine", "-role", role, "-dir", env.Paths.Dir, "-parent", strconv.Itoa(os.Getpid())}
		if m := os.Getenv("BACKHAUL_NAT_MODE"); m != "" {
			args = append(args, "-nat", m)
		}
		slog.Info("asking for administrator rights to start the engine", "role", role)
		exited, err := launch(ctx, exe, args)
		if err != nil {
			return err
		}

		pid, err := waitForPID(pidPath, errPath, exited)
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
			gone := !processAlive(pid)
			select {
			case <-exited: // a nil channel never fires; a closed one always does
				gone = true
			default:
			}
			if gone {
				time.Sleep(time.Second) // give exit's marker a moment to land
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

// waitForPID waits for the engine to write its pid, or to fail first: its
// own error marker, or the launcher ending (the prompt refused, usually).
func waitForPID(pidPath, errPath string, exited <-chan error) (int, error) {
	deadline := time.Now().Add(startLimit)
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
		select {
		case err := <-exited:
			time.Sleep(time.Second) // the engine's own reason, if it got that far
			if msg, ok := readMarker(errPath); ok && msg != "" {
				return 0, errors.New(msg)
			}
			if err != nil {
				return 0, err
			}
			return 0, errors.New("the engine exited at once")
		case <-time.After(200 * time.Millisecond):
		}
	}
	return 0, fmt.Errorf("the engine did not start within %s (details in Activity)", startLimit)
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
