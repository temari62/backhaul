// Package undo is a persisted journal of system changes and how to revert
// them. Every routing/DNS/firewall/NAT change is recorded *before* it is
// applied, so a crashed run can be reverted by a recovery pass on next start
// (`backhaul connect|serve` and `backhaul doctor --recover` call Recover).
package undo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"backhaul/internal/osutil"
)

// Kinds of undo actions.
const (
	KindExec        = "exec"         // run Argv (with optional Stdin)
	KindRestoreFile = "restore-file" // copy Backup over Path, then delete Backup
	KindRemoveFile  = "remove-file"  // delete Path
)

// Action reverts one change.
type Action struct {
	Desc   string   `json:"desc"`
	Kind   string   `json:"kind"`
	Argv   []string `json:"argv,omitempty"`
	Stdin  string   `json:"stdin,omitempty"`
	Path   string   `json:"path,omitempty"`
	Backup string   `json:"backup,omitempty"`
	// BestEffort marks steps whose target may already be gone (e.g. a route
	// on an interface that has disappeared): failure is expected, not logged.
	BestEffort bool `json:"best_effort,omitempty"`
}

// Exec builds an exec action.
func Exec(desc string, argv ...string) Action { return Action{Desc: desc, Kind: KindExec, Argv: argv} }

// Journal is safe for concurrent use.
type Journal struct {
	path    string
	mu      sync.Mutex
	actions []Action
}

// Open returns a journal persisted at path. It does not load existing entries;
// call Recover first to revert a previous crashed session.
func Open(path string) *Journal { return &Journal{path: path} }

// Path returns the journal file.
func (j *Journal) Path() string { return j.path }

// Push records an undo action and flushes the journal to disk.
func (j *Journal) Push(a Action) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.actions = append(j.actions, a)
	return j.flushLocked()
}

// Len returns the number of pending actions.
func (j *Journal) Len() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.actions)
}

func (j *Journal) flushLocked() error { return j.writeLocked(j.actions) }

func (j *Journal) writeLocked(actions []Action) error {
	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(actions, "", "  ")
	if err != nil {
		return err
	}
	tmp := j.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, j.path)
}

// StepTimeout bounds each undo step, so one hung command (a stuck
// PowerShell/WMI call) cannot hold up the steps after it.
var StepTimeout = 20 * time.Second

// Unwind runs all actions in reverse order. Errors are logged and collected
// but never stop the unwind — partial restore beats none. Steps that ran out
// of time stay in the journal so the next start (Recover) retries them.
func (j *Journal) Unwind(ctx context.Context) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	var errs []error
	var retry []Action // in descending journal order
	for i := len(j.actions) - 1; i >= 0; i-- {
		a := j.actions[i]
		sctx, cancel := context.WithTimeout(ctx, StepTimeout)
		err := run(sctx, a)
		timedOut := err != nil && sctx.Err() != nil
		cancel()
		switch {
		case err == nil:
			slog.Debug("undo step ok", "step", a.Desc)
		case timedOut:
			slog.Warn("undo step timed out; it will be retried the next time Backhaul starts", "step", a.Desc)
			retry = append(retry, a)
			errs = append(errs, fmt.Errorf("%s: timed out", a.Desc))
		case a.BestEffort:
			slog.Debug("best-effort undo step skipped", "step", a.Desc, "err", err)
		default:
			slog.Warn("undo step failed", "step", a.Desc, "err", err)
			errs = append(errs, err)
		}
		j.actions = j.actions[:i]
		_ = j.writeLocked(pending(j.actions, retry))
	}
	if len(retry) == 0 {
		_ = os.Remove(j.path)
	}
	return errors.Join(errs...)
}

// pending is what is still left to undo: the unrun prefix, then the retries
// back in their original (ascending) order.
func pending(unrun, retry []Action) []Action {
	out := append([]Action(nil), unrun...)
	for k := len(retry) - 1; k >= 0; k-- {
		out = append(out, retry[k])
	}
	return out
}

// Recover reverts a journal left behind by a crashed run. It returns the
// number of actions replayed.
func Recover(ctx context.Context, path string) (int, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var actions []Action
	if err := json.Unmarshal(b, &actions); err != nil {
		return 0, fmt.Errorf("corrupt undo journal %s: %w (inspect and delete it manually)", path, err)
	}
	if len(actions) == 0 {
		_ = os.Remove(path)
		return 0, nil
	}
	slog.Warn("found changes from a previous run that did not exit cleanly; restoring", "steps", len(actions))
	j := &Journal{path: path, actions: actions}
	return len(actions), j.Unwind(ctx)
}

func run(ctx context.Context, a Action) error {
	switch a.Kind {
	case KindExec:
		if len(a.Argv) == 0 {
			return nil
		}
		_, err := osutil.RunStdin(ctx, a.Stdin, a.Argv[0], a.Argv[1:]...)
		return err
	case KindRestoreFile:
		b, err := os.ReadFile(a.Backup)
		if err != nil {
			return err
		}
		if err := os.WriteFile(a.Path, b, 0o644); err != nil {
			return err
		}
		return os.Remove(a.Backup)
	case KindRemoveFile:
		err := os.Remove(a.Path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	default:
		return fmt.Errorf("unknown undo kind %q", a.Kind)
	}
}

// ExecBestEffort is Exec for steps that may legitimately fail at undo time.
func ExecBestEffort(desc string, argv ...string) Action {
	a := Exec(desc, argv...)
	a.BestEffort = true
	return a
}
