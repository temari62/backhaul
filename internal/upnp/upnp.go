// Package upnp asks the home router (UPnP IGD) to forward the exit node's
// port automatically, and detects carrier-grade NAT (where no port forward
// can ever work). Everything is best-effort: routers without UPnP just get
// a clear "forward it manually" message.
package upnp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
)

const (
	// Lease is renewed well before it expires, so a crashed backhaul leaves
	// the router mapping behind for at most this long.
	Lease         = 60 * time.Minute
	renewInterval = 20 * time.Minute
	description   = "Backhaul exit node"
)

// gateway is the subset shared by WANIPConnection1/2 and WANPPPConnection1.
type gateway interface {
	AddPortMappingCtx(ctx context.Context, remoteHost string, extPort uint16, proto string, intPort uint16,
		intClient string, enabled bool, desc string, lease uint32) error
	DeletePortMappingCtx(ctx context.Context, remoteHost string, extPort uint16, proto string) error
	GetExternalIPAddressCtx(ctx context.Context) (string, error)
}

// discover finds UPnP internet gateways on the LAN.
func discover(ctx context.Context) []gateway {
	var gws []gateway
	if cs, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx); err == nil {
		for _, c := range cs {
			gws = append(gws, c)
		}
	}
	if cs, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx); err == nil {
		for _, c := range cs {
			gws = append(gws, c)
		}
	}
	if cs, _, err := internetgateway2.NewWANPPPConnection1ClientsCtx(ctx); err == nil {
		for _, c := range cs {
			gws = append(gws, c)
		}
	}
	return gws
}

// Mapping is an open router port forward.
type Mapping struct {
	gw         gateway
	port       uint16
	lanIP      string
	lease      uint32
	ExternalIP string // the router's WAN address ("" if it wouldn't say)
}

// ErrNoGateway means no UPnP-capable router answered.
var ErrNoGateway = errors.New("no UPnP router found (UPnP may be disabled on the router)")

// ErrTimeout means the router didn't finish answering within the deadline.
var ErrTimeout = errors.New("no answer from the router in time")

// Open forwards TCP port on the router to lanIP:port. It returns by ctx's
// deadline even if the network stack doesn't honour it (some Windows
// Winsock providers ignore socket deadlines); a mapping that completes after
// we gave up is removed again.
func Open(ctx context.Context, port int, lanIP string) (*Mapping, error) {
	type result struct {
		m   *Mapping
		err error
	}
	var (
		mu        sync.Mutex
		abandoned bool
	)
	ch := make(chan result, 1)
	go func() {
		m, err := open(context.WithoutCancel(ctx), port, lanIP)
		mu.Lock()
		defer mu.Unlock()
		if abandoned {
			if err == nil { // arrived after we gave up: nobody owns it, undo it
				dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = m.gw.DeletePortMappingCtx(dctx, "", m.port, "TCP")
			}
			return
		}
		ch <- result{m, err}
	}()
	select {
	case r := <-ch:
		return r.m, r.err
	case <-ctx.Done():
		mu.Lock()
		defer mu.Unlock()
		select {
		case r := <-ch: // finished just in time
			return r.m, r.err
		default:
			abandoned = true
			return nil, ErrTimeout
		}
	}
}

func open(ctx context.Context, port int, lanIP string) (*Mapping, error) {
	gws := discover(ctx)
	if len(gws) == 0 {
		return nil, ErrNoGateway
	}
	var lastErr error
	for _, gw := range gws {
		m := &Mapping{gw: gw, port: uint16(port), lanIP: lanIP, lease: uint32(Lease / time.Second)}
		if err := m.add(ctx); err != nil {
			lastErr = err
			continue
		}
		if ip, err := gw.GetExternalIPAddressCtx(ctx); err == nil {
			m.ExternalIP = strings.TrimSpace(ip)
		}
		return m, nil
	}
	return nil, fmt.Errorf("router refused the port forward: %w", lastErr)
}

func (m *Mapping) add(ctx context.Context) error {
	err := m.gw.AddPortMappingCtx(ctx, "", m.port, "TCP", m.port, m.lanIP, true, description, m.lease)
	if err != nil && m.lease != 0 {
		// Some routers only accept permanent mappings (UPnP error 725).
		m.lease = 0
		err = m.gw.AddPortMappingCtx(ctx, "", m.port, "TCP", m.port, m.lanIP, true, description, 0)
	}
	return err
}

// KeepAlive renews the lease until ctx is done, then removes the mapping.
func (m *Mapping) KeepAlive(ctx context.Context) {
	if m.lease != 0 {
		t := time.NewTicker(renewInterval)
		defer t.Stop()
	loop:
		for {
			select {
			case <-ctx.Done():
				break loop
			case <-t.C:
				rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				if err := m.add(rctx); err != nil {
					slog.Warn("could not renew the router port forward", "err", err)
				}
				cancel()
			}
		}
	} else {
		<-ctx.Done()
	}
	dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.gw.DeletePortMappingCtx(dctx, "", m.port, "TCP"); err != nil {
		slog.Debug("remove router port forward", "err", err)
	} else {
		slog.Info("router port forward removed", "port", m.port)
	}
}

// cgnat is RFC 6598 shared address space used by carrier-grade NAT.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// BehindCarrierNAT reports whether a router WAN address means the ISP puts
// the connection behind carrier-grade NAT (or another NAT layer), in which
// case inbound connections can't be forwarded at all.
func BehindCarrierNAT(wanIP string) bool {
	a, err := netip.ParseAddr(wanIP)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return cgnat.Contains(a) || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}
