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
	"strings"
	"sync"
	"time"
)

// Wstunnel roles.
const (
	RoleServer        = "server"         // exit node, port-forward mode: wss listener on :443
	RoleClient        = "client"         // laptop 1: local UDP → wss → exit node
	RoleReverseClient = "reverse-client" // exit node, relay mode: holds an outbound wss to the VPS
)

// WstunnelOptions configures one wstunnel child process.
type WstunnelOptions struct {
	Binary string
	Role   string

	// Server role.
	ListenAddr string // "0.0.0.0"
	Port       int    // 443
	CertFile   string
	KeyFile    string
	RestrictTo string // only allow tunnels to this "ip:port" (the WG UDP port)

	// Client / reverse-client roles.
	ServerURL string // e.g. "ws://127.0.0.1:41234" (the pinned-TLS proxy)
	LocalUDP  string // client: "127.0.0.1:51821"
	RemoteUDP string // client: target on the far side; reverse: local WG "127.0.0.1:51820"
	RelayBind string // reverse: UDP bind on the relay, "127.0.0.1:51820"

	PathPrefix   string
	ReadyTimeout time.Duration
	BackoffMin   time.Duration
	BackoffMax   time.Duration
	Verbose      bool
}

// Args renders the wstunnel command line (exported for tests and doctor).
func (o WstunnelOptions) Args() []string {
	lvl := "INFO"
	if o.Verbose {
		lvl = "DEBUG"
	}
	switch o.Role {
	case RoleServer:
		a := []string{"server", "--log-lvl", lvl, "--restrict-to", o.RestrictTo}
		if o.CertFile != "" {
			a = append(a, "--tls-certificate", o.CertFile, "--tls-private-key", o.KeyFile)
		}
		if o.PathPrefix != "" {
			a = append(a, "--restrict-http-upgrade-path-prefix", o.PathPrefix)
		}
		return append(a, fmt.Sprintf("wss://%s:%d", hostForURL(o.ListenAddr), o.Port))
	case RoleClient:
		a := []string{"client", "--log-lvl", lvl,
			"-L", fmt.Sprintf("udp://%s:%s?timeout_sec=0", o.LocalUDP, o.RemoteUDP)}
		if o.PathPrefix != "" {
			a = append(a, "--http-upgrade-path-prefix", o.PathPrefix)
		}
		return append(a, o.ServerURL)
	case RoleReverseClient:
		a := []string{"client", "--log-lvl", lvl,
			"-R", fmt.Sprintf("udp://%s:%s?timeout_sec=0", o.RelayBind, o.RemoteUDP)}
		if o.PathPrefix != "" {
			a = append(a, "--http-upgrade-path-prefix", o.PathPrefix)
		}
		return append(a, o.ServerURL)
	}
	return nil
}

func hostForURL(h string) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]"
	}
	return h
}

// readyRE matches wstunnel's "Starting wstunnel server listening on …" and
// "Starting UDP server listening cnx on …" log lines (verified on v10.7.1).
var readyRE = regexp.MustCompile(`(?i)listening (cnx )?on`)

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Wstunnel supervises a wstunnel child process, restarting it with
// exponential backoff whenever it exits.
type Wstunnel struct {
	opts WstunnelOptions

	mu        sync.Mutex
	status    Status
	cancelRun context.CancelFunc // kills the current child
	ready     chan struct{}
	stopped   chan struct{}
	stop      context.CancelFunc
}

// NewWstunnel builds a supervised wstunnel transport.
func NewWstunnel(o WstunnelOptions) *Wstunnel {
	return &Wstunnel{opts: o, status: Status{Kind: "wstunnel", State: StateStopped, LocalUDP: o.LocalUDP}}
}

// Kind implements Transport.
func (w *Wstunnel) Kind() string { return "wstunnel" }

// Status implements Transport.
func (w *Wstunnel) Status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

func (w *Wstunnel) setState(state string, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.State = state
	w.status.Since = time.Now()
	if err != nil {
		w.status.LastError = err.Error()
	}
}

// Start implements Transport.
func (w *Wstunnel) Start(ctx context.Context) error {
	if w.opts.Binary == "" {
		return errors.New("wstunnel binary not set")
	}
	ctx, w.stop = context.WithCancel(ctx)
	w.ready = make(chan struct{}, 1)
	w.stopped = make(chan struct{})
	go w.supervise(ctx)
	select {
	case <-w.ready:
		return nil
	case <-time.After(w.opts.ReadyTimeout):
		return fmt.Errorf("wstunnel not ready after %s (still retrying): %s", w.opts.ReadyTimeout, w.Status().LastError)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Restart implements Transport: kill the child; the supervisor relaunches it.
func (w *Wstunnel) Restart() {
	w.mu.Lock()
	cancel := w.cancelRun
	w.mu.Unlock()
	if cancel != nil {
		slog.Info("restarting transport", "kind", "wstunnel")
		cancel()
	}
}

// Stop implements Transport.
func (w *Wstunnel) Stop() error {
	if w.stop == nil {
		return nil
	}
	w.stop()
	<-w.stopped
	w.setState(StateStopped, nil)
	return nil
}

func (w *Wstunnel) supervise(ctx context.Context) {
	defer close(w.stopped)
	backoff := w.opts.BackoffMin
	for {
		start := time.Now()
		err := w.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > w.opts.BackoffMax {
			backoff = w.opts.BackoffMin // it ran healthily for a while; reset
		}
		w.mu.Lock()
		w.status.Restarts++
		w.mu.Unlock()
		w.setState(StateBackoff, err)
		slog.Warn("wstunnel exited; restarting", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, w.opts.BackoffMax)
	}
}

func (w *Wstunnel) runOnce(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	w.mu.Lock()
	w.cancelRun = cancel
	w.mu.Unlock()

	args := w.opts.Args()
	cmd := exec.CommandContext(ctx, w.opts.Binary, args...)
	// wstunnel rejects NO_COLOR=1 (it wants true/false), so force it.
	cmd.Env = append(filterEnv(os.Environ(), "NO_COLOR", "RUST_LOG"), "NO_COLOR=true")
	cmd.WaitDelay = 3 * time.Second
	setProcAttr(cmd)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	w.setState(StateStarting, nil)
	slog.Debug("starting wstunnel", "args", args)
	if err := cmd.Start(); err != nil {
		pw.Close()
		return fmt.Errorf("start wstunnel: %w", err)
	}
	readyTimer := time.AfterFunc(w.opts.ReadyTimeout/3, func() {
		// Reverse clients log no "listening" line; treat surviving the first
		// third of the ready timeout as ready. TODO(spec): heuristic.
		if w.opts.Role == RoleReverseClient && ctx.Err() == nil {
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
			slog.Debug("wstunnel", "log", line)
			if readyRE.MatchString(line) {
				w.markReady()
			}
		}
	}()
	err := cmd.Wait()
	pw.Close()
	<-scanDone
	if err == nil {
		err = errors.New("wstunnel exited")
	}
	if lastLine != "" {
		err = fmt.Errorf("%w (last log: %s)", err, lastLine)
	}
	return err
}

func (w *Wstunnel) markReady() {
	w.mu.Lock()
	first := w.status.State != StateReady
	w.status.State = StateReady
	w.status.Since = time.Now()
	w.mu.Unlock()
	if first {
		slog.Info("transport ready", "kind", "wstunnel", "role", w.opts.Role)
	}
	select {
	case w.ready <- struct{}{}:
	default:
	}
}

func filterEnv(env []string, drop ...string) []string {
	out := env[:0:0]
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		keep := true
		for _, d := range drop {
			if strings.EqualFold(k, d) {
				keep = false
			}
		}
		if keep {
			out = append(out, kv)
		}
	}
	return out
}
