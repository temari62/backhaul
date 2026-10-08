package wg

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"backhaul/internal/route"
)

// Embedded runs wireguard-go in-process on a TUN device.
type Embedded struct {
	mu       sync.Mutex
	settings Settings
	tdev     tun.Device
	dev      *device.Device
	uapi     net.Listener
	name     string
}

// Up creates the TUN, assigns addresses/MTU, configures the peer and starts
// a UAPI listener so `wg show` / wgctrl / `backhaul status` can inspect it.
func (e *Embedded) Up(ctx context.Context, s Settings) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	name := s.Interface
	if runtime.GOOS == "darwin" && !strings.HasPrefix(name, "utun") {
		name = "utun" // macOS only allows utun[N]; the kernel picks N
	}
	tdev := s.TUN
	userspace := tdev != nil
	if !userspace {
		var err error
		if tdev, err = tun.CreateTUN(name, s.MTU); err != nil {
			return fmt.Errorf("create TUN %q: %w%s", name, err, tunHint())
		}
	}
	real, err := tdev.Name()
	if err != nil {
		tdev.Close()
		return err
	}
	e.tdev, e.name, e.settings = tdev, real, s

	logger := &device.Logger{
		Verbosef: func(f string, a ...any) { slog.Debug("wireguard: "+fmt.Sprintf(f, a...), "iface", real) },
		Errorf:   func(f string, a ...any) { slog.Warn("wireguard: "+fmt.Sprintf(f, a...), "iface", real) },
	}
	e.dev = device.NewDevice(tdev, NewLoopbackBind(), logger)

	cfg, err := uapiConfig(s, true)
	if err != nil {
		e.closeLocked()
		return err
	}
	if err := e.dev.IpcSet(cfg); err != nil {
		e.closeLocked()
		return fmt.Errorf("configure wireguard: %w", err)
	}
	if !userspace {
		if err := route.ConfigureInterface(ctx, real, s.Addresses, s.MTU); err != nil {
			e.closeLocked()
			return fmt.Errorf("configure interface %s: %w", real, err)
		}
	}
	if err := e.dev.Up(); err != nil {
		e.closeLocked()
		return fmt.Errorf("bring up wireguard: %w", err)
	}
	if userspace {
		// No OS interface to inspect; status uses the runtime snapshot.
		slog.Info("wireguard up", "engine", "embedded", "nat", "userspace", "listen_port", s.ListenPort)
		return nil
	}
	if l, err := uapiListen(real); err != nil {
		// Expected on Windows unless running as SYSTEM (the pipe must be
		// SYSTEM-owned). `status`/`doctor` fall back to the runtime snapshot.
		slog.Debug("UAPI listener unavailable; status uses runtime snapshots", "err", err)
	} else {
		e.uapi = l
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go e.dev.IpcHandle(c)
			}
		}()
	}
	slog.Info("wireguard up", "iface", real, "engine", "embedded", "listen_port", s.ListenPort)
	return nil
}

// Name returns the real interface name.
func (e *Embedded) Name() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.name
}

// Stats reads peer stats straight from the in-process device.
func (e *Embedded) Stats() (Stats, error) {
	e.mu.Lock()
	dev := e.dev
	e.mu.Unlock()
	if dev == nil {
		return Stats{}, fmt.Errorf("wireguard is down")
	}
	get, err := dev.IpcGet()
	if err != nil {
		return Stats{}, err
	}
	return parseUAPIStats(get), nil
}

// Kick re-applies peer settings, forcing a new handshake attempt.
func (e *Embedded) Kick() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dev == nil {
		return fmt.Errorf("wireguard is down")
	}
	cfg, err := uapiConfig(e.settings, false)
	if err != nil {
		return err
	}
	return e.dev.IpcSet(cfg)
}

// Down closes the device; the OS removes the TUN with its addresses/routes.
func (e *Embedded) Down(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closeLocked()
	return nil
}

func (e *Embedded) closeLocked() {
	if e.uapi != nil {
		e.uapi.Close()
		e.uapi = nil
	}
	if e.dev != nil {
		e.dev.Close() // also closes the TUN
		e.dev = nil
	} else if e.tdev != nil {
		e.tdev.Close()
	}
	e.tdev = nil
}
