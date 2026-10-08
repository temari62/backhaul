//go:build !linux && !darwin && !windows

package nat

import (
	"context"
	"errors"

	"backhaul/internal/undo"
)

var errUnsupported = errors.New("NAT is not implemented on this OS")

// DefaultWAN is unsupported here.
func DefaultWAN(context.Context) (string, error) { return "", errUnsupported }

func enable(context.Context, Plan, *undo.Journal) error { return errUnsupported }

// Available: no system NAT implementation on this OS.
func Available(context.Context) bool { return false }

// AllowInbound is a no-op here.
func AllowInbound(context.Context, int, *undo.Journal) error { return nil }
