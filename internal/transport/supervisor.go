package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"time"
)

// ProcSpec describes a transport child process (wstunnel, xray, …).
type ProcSpec struct {
	Kind, Role string
	Binary     string
	Args       []string
	DropEnv    []string // environment variables to remove
	Env        []string // extra KEY=VALUE pairs
	ReadyRE    *regexp.Regexp
	// ReadyWhenAlive treats surviving a third of ReadyTimeout as ready (for
	// processes that print nothing useful on readiness).
	ReadyWhenAlive bool
	OnLine         func(line string) // optional per-log-line hook
	// RestartOn restarts the process at once when a log line matches (e.g.
	// "the network reset our connection"), instead of waiting for the
	// health loop to notice the stall. Debounced.
	RestartOn    *regexp.Regexp
	LocalUDP     string
	ReadyTimeout time.Duration
	BackoffMin   time.Duration
	BackoffMax   time.Duration
}

// Supervisor runs a ProcSpec, restarting it with exponential backoff
// whenever it exits. It implements Transport.
type Supervisor struct {
	spec ProcSpec

	mu        sync.Mutex
	status    Status
	cancelRun context.CancelFunc // kills the current child
	ready     chan struct{}
	stopped   chan struct{}
	stop      context.CancelFunc
	lastAuto  time.Time // last RestartOn-triggered restart
}

// NewSupervisor builds a supervised transport process.
func NewSupervisor(s ProcSpec) *Supervisor {
	return &Supervisor{spec: s, status: Status{Kind: s.Kind, State: StateStopped, LocalUDP: s.LocalUDP}}
}

// Kind implements Transport.
func (w *Supervisor) Kind() string { return w.spec.Kind }

// Status implements Transport.
func (w *Supervisor) Status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

func (w *Supervisor) setState(state string, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.State = state
	w.status.Since = time.Now()
	if err != nil {
		w.status.LastError = err.Error()
	}
}

// Start implements Transport.
func (w *Supervisor) Start(ctx context.Context) error {
	if w.spec.Binary == "" {
		return fmt.Errorf("%s binary not set", w.spec.Kind)
	}
	ctx, w.stop = context.WithCancel(ctx)
	w.ready = make(chan struct{}, 1)
	w.stopped = make(chan struct{})
	go w.supervise(ctx)
	select {
	case <-w.ready:
		return nil
	case <-time.After(w.spec.ReadyTimeout):
		return fmt.Errorf("%s not ready after %s (still retrying): %s", w.spec.Kind, w.spec.ReadyTimeout, w.Status().LastError)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Restart implements Transport: kill the child; the supervisor relaunches it.
func (w *Supervisor) Restart() {
	w.mu.Lock()
	cancel := w.cancelRun
	w.mu.Unlock()
	if cancel != nil {
		slog.Info("restarting transport", "kind", w.spec.Kind)
		cancel()
	}
}

// Stop implements Transport.
func (w *Supervisor) Stop() error {
	if w.stop == nil {
		return nil
	}
	w.stop()
	<-w.stopped
	w.setState(StateStopped, nil)
	return nil
}

func (w *Supervisor) supervise(ctx context.Context) {
	defer close(w.stopped)
	backoff := w.spec.BackoffMin
	for {
		start := time.Now()
		err := w.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > w.spec.BackoffMax {
			backoff = w.spec.BackoffMin // it ran healthily for a while; reset
		}
		w.mu.Lock()
		w.status.Restarts++
		w.mu.Unlock()
		w.setState(StateBackoff, err)
		slog.Warn(w.spec.Kind+" exited; restarting", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, w.spec.BackoffMax)
	}
}

func (w *Supervisor) runOnce(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	w.mu.Lock()
	w.cancelRun = cancel
	w.mu.Unlock()

	cmd := exec.CommandContext(ctx, w.spec.Binary, w.spec.Args...)
	cmd.Env = append(filterEnv(os.Environ(), w.spec.DropEnv...), w.spec.Env...)
	cmd.WaitDelay = 3 * time.Second
	setProcAttr(cmd)
	hideWindow(cmd)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	w.setState(StateStarting, nil)
	slog.Debug("starting "+w.spec.Kind, "args", w.spec.Args)
	if err := cmd.Start(); err != nil {
		pw.Close()
		return fmt.Errorf("start %s: %w", w.spec.Kind, err)
	}
	afterStart(cmd)
	readyTimer := time.AfterFunc(w.spec.ReadyTimeout/3, func() {
		if w.spec.ReadyWhenAlive && ctx.Err() == nil {
			w.markReady()
		}
	})
	defer readyTimer.Stop()
	var lastLine string
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			line := ansiRE.ReplaceAllString(sc.Text(), "")
			lastLine = line
			slog.Debug(w.spec.Kind, "log", line)
			if w.spec.RestartOn != nil && w.spec.RestartOn.MatchString(line) && w.restartAllowed() {
				slog.Warn("the network cut the connection to the exit node; reconnecting now", "kind", w.spec.Kind)
				go w.Restart()
			}
			if w.spec.OnLine != nil {
				w.spec.OnLine(line)
			}
			if w.spec.ReadyRE != nil && w.spec.ReadyRE.MatchString(line) {
				w.markReady()
			}
		}
	}()
	err := cmd.Wait()
	pw.Close()
	<-scanDone
	if err == nil {
		err = errors.New(w.spec.Kind + " exited")
	}
	if lastLine != "" {
		err = fmt.Errorf("%w (last log: %s)", err, lastLine)
	}
	return err
}

func (w *Supervisor) markReady() {
	w.mu.Lock()
	first := w.status.State != StateReady
	w.status.State = StateReady
	w.status.Since = time.Now()
	w.mu.Unlock()
	if first {
		slog.Info("transport ready", "kind", w.spec.Kind, "role", w.spec.Role)
	}
	select {
	case w.ready <- struct{}{}:
	default:
	}
}

// restartDebounce stops a burst of matching log lines from causing a burst
// of restarts.
const restartDebounce = 5 * time.Second

func (w *Supervisor) restartAllowed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if time.Since(w.lastAuto) < restartDebounce {
		return false
	}
	w.lastAuto = time.Now()
	return true
}
