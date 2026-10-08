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
