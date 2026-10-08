//go:build !linux && !darwin && !windows

package route

import (
	"context"
	"errors"
	"net/netip"

	"backhaul/internal/undo"
)

var errUnsupported = errors.New("routing is not implemented on this OS")

type otherManager struct{}

func newManager() Manager { return otherManager{} }

// ConfigureInterface is unsupported here.
func ConfigureInterface(context.Context, string, []netip.Prefix, int) error { return errUnsupported }

func (otherManager) Apply(context.Context, Plan, *undo.Journal) error { return errUnsupported }
