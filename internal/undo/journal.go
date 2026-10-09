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

func (j *Journal) flushLocked() error {
	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(j.actions, "", "  ")
	if err != nil {
		return err
	}
	tmp := j.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, j.path)
}

// Unwind runs all actions in reverse order. Errors are logged and collected
// but never stop the unwind — partial restore beats none.
func (j *Journal) Unwind(ctx context.Context) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	var errs []error
	for i := len(j.actions) - 1; i >= 0; i-- {
		if err := run(ctx, j.actions[i]); err != nil && j.actions[i].BestEffort {
			slog.Debug("best-effort undo step skipped", "step", j.actions[i].Desc, "err", err)
		} else if err != nil {
			slog.Warn("undo step failed", "step", j.actions[i].Desc, "err", err)
			errs = append(errs, err)
		} else {
			slog.Debug("undo step ok", "step", j.actions[i].Desc)
		}
		j.actions = j.actions[:i]
		_ = j.flushLocked()
	}
	_ = os.Remove(j.path)
	return errors.Join(errs...)
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
