//go:build !windows

package route

import (
	"context"
	"errors"
)

// EnableKillSwitch re-installation is only needed on Windows.
func EnableKillSwitch(context.Context, Plan) error {
	return errors.New("not implemented on this OS")
}

// NetworkFacts is only implemented on Windows.
func NetworkFacts(context.Context) string { return "" }
