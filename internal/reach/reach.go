// Package reach holds reachability helpers beyond port forwarding.
//
// Mode A (port-forward + DDNS) lives in config/ddns; mode B (relay) is
// implemented as a wstunnel reverse tunnel in app.Serve. Mode C
// (rendezvous / NAT hole-punching) is out of scope for v1 — this is its
// interface stub.
package reach

import (
	"context"
	"errors"
	"net/netip"
)

// ErrNotImplemented is returned by the v1 rendezvous stub.
var ErrNotImplemented = errors.New("rendezvous/hole-punching (reachability mode C) is not implemented in v1")

// Rendezvous discovers a directly reachable address for the peer by
// coordinating through a third party (STUN/relay signalling).
type Rendezvous interface {
	// Publish advertises this node's reflexive address under id.
	Publish(ctx context.Context, id string) error
	// Lookup returns the peer's candidate addresses for id.
	Lookup(ctx context.Context, id string) ([]netip.AddrPort, error)
}

// Stub is the v1 placeholder.
// TODO(spec): implement mode C (e.g. STUN + a tiny signalling endpoint).
type Stub struct{}

func (Stub) Publish(context.Context, string) error                    { return ErrNotImplemented }
func (Stub) Lookup(context.Context, string) ([]netip.AddrPort, error) { return nil, ErrNotImplemented }
