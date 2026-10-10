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

func (otherManager) RepairEndpoint(context.Context, Plan, *undo.Journal) (bool, error) {
	return false, errUnsupported
}

// OtherVPNs is unsupported here.
func OtherVPNs(context.Context, string) ([]string, error) { return nil, nil }

// EndpointPath is unsupported here.
func EndpointPath(context.Context, netip.Addr) string { return "unknown" }

// DisableKillSwitch is unsupported here.
func DisableKillSwitch(context.Context) error { return errUnsupported }

// KillSwitchActive is false: there is no kill switch here.
func KillSwitchActive() bool { return false }
