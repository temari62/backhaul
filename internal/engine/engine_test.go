package engine

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"backhaul/internal/app"
	"backhaul/internal/config"
	"backhaul/internal/gui"
	"backhaul/internal/state"
)

// fakeEngine stands in for the privileged side: it writes the markers a real
// engine writes, in order, from a goroutine. Its "pid" is this test process,
// which processAlive reports as alive on every OS.
type fakeEngine struct {
	stateDir string
	logs     *gui.LogBuffer
	env      *app.Env
}

func newFake(t *testing.T) *fakeEngine {
	t.Helper()
	dir := t.TempDir()
	env := &app.Env{Paths: config.Paths{Dir: dir}}
	return &fakeEngine{stateDir: env.Paths.State(), logs: gui.NewLogBuffer(100, nil, slog.LevelInfo), env: env}
}

func (f *fakeEngine) write(name, body string) {
	if err := os.WriteFile(filepath.Join(f.stateDir, name), []byte(body), 0o644); err != nil {
		panic(err)
	}
}

func (f *fakeEngine) up() { f.write(pidFile, strconv.Itoa(os.Getpid())) }

func (f *fakeEngine) log(line string) {
	p := filepath.Join(f.stateDir, logFile)
	fh, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		panic(err)
	}
	defer fh.Close()
	_, _ = fh.WriteString(line + "\n")
}

// run calls Run with a launcher that hands the engine role to engine.
func (f *fakeEngine) run(ctx context.Context, exited <-chan error, launchErr error, engine func()) error {
	launch := func(_ context.Context, exe string, args []string) (<-chan error, error) {
		if exe == "" || args[0] != "--engine" || args[2] != gui.RoleServe || args[4] != f.env.Paths.Dir {
			return nil, errors.New("bad launch: " + strings.Join(args, " "))
		}
		if launchErr != nil {
			return nil, launchErr
		}
		if engine != nil {
			go engine()
		}
		return exited, nil
	}
	return Run(f.logs, launch)(ctx, gui.RoleServe, f.env)
}

func (f *fakeEngine) text() string {
	var lines []string
	for _, l := range f.logs.After(0) {
		lines = append(lines, l.Level+" "+l.Text)
	}
	return strings.Join(lines, "\n")
}

// A clean life: up, log lines, stop requested, clean exit — with the log
// lines in Activity and nil returned only after the engine's exit marker.
func TestRunLifecycle(t *testing.T) {
	f := newFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	var stoppedAt time.Time
	err := f.run(ctx, nil, nil, func() {
		f.up()
		f.log("2026-11-03T10:00:00Z INFO engine started role=serve")
		time.Sleep(700 * time.Millisecond)
		cancel()
		for !fileExists(state.StopFile(f.stateDir)) {
			time.Sleep(50 * time.Millisecond)
		}
		f.log("2026-11-03T10:00:01Z INFO stop requested")
		time.Sleep(300 * time.Millisecond)
		stoppedAt = time.Now()
		f.write(errFile, "")
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stoppedAt.IsZero() {
		t.Fatal("Run returned before the engine had exited")
	}
	if got := f.text(); !strings.Contains(got, "INFO engine started role=serve") || !strings.Contains(got, "INFO stop requested") {
		t.Fatalf("engine log lines missing from Activity:\n%s", got)
	}
}

// The engine's own error (its marker) is what the user sees.
func TestRunEngineError(t *testing.T) {
	f := newFake(t)
	err := f.run(context.Background(), nil, nil, func() {
		f.up()
		time.Sleep(600 * time.Millisecond)
		f.write(errFile, "serve: port 443 is taken")
	})
	if err == nil || err.Error() != "serve: port 443 is taken" {
		t.Fatalf("err = %v", err)
	}
}

// The launcher's errors come straight back: refused at launch, or (pkexec)
// reported through the exit channel before the engine ever came up.
func TestRunLauncherErrors(t *testing.T) {
	f := newFake(t)
	refused := errors.New("Backhaul needs administrator rights for this")
	if err := f.run(context.Background(), nil, refused, nil); !errors.Is(err, refused) {
		t.Fatalf("launch error: got %v", err)
	}
	ch := make(chan error, 1)
	ch <- errors.New("pkexec: not authorized")
	close(ch)
	start := time.Now()
	if err := f.run(context.Background(), ch, nil, nil); err == nil || err.Error() != "pkexec: not authorized" {
		t.Fatalf("exit channel error: got %v", err)
	} else if time.Since(start) > 10*time.Second {
		t.Fatal("an exited launcher must not be waited on until the start limit")
	}
}

// A parent-style launcher (pkexec) ending after the engine was up means the
// engine is gone; without a marker that is an unexpected stop.
func TestRunLauncherExitAfterStart(t *testing.T) {
	f := newFake(t)
	ch := make(chan error)
	err := f.run(context.Background(), ch, nil, func() {
		f.up()
		time.Sleep(600 * time.Millisecond)
		close(ch)
	})
	if err == nil || !strings.Contains(err.Error(), "stopped unexpectedly") {
		t.Fatalf("err = %v", err)
	}
}

func TestIsInvocation(t *testing.T) {
	old := os.Args
	defer func() { os.Args = old }()
	os.Args = []string{"app", "--engine", "-role", "serve"}
	if !IsInvocation() {
		t.Fatal("--engine not recognised")
	}
	os.Args = []string{"app"}
	if IsInvocation() {
		t.Fatal("plain launch taken for the engine")
	}
}

func TestProcessAlive(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Fatal("this process is alive")
	}
	if processAlive(1<<30 - 1) {
		t.Fatal("an absurd pid should not be alive")
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
