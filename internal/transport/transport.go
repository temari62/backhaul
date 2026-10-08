// Package transport wraps WireGuard's UDP in an obfuscating carrier. v1 ships
// wstunnel (WebSocket over TLS on :443); the Transport interface exists so a
// second method (udp2raw, native Go WS, …) can be added and switched to when
// the primary is blocked (§8 "transport fallback hook").
package transport

import (
	"context"
	"time"
)

// States reported by Status.
const (
	StateStopped  = "stopped"
	StateStarting = "starting"
	StateReady    = "ready"
	StateBackoff  = "backoff"
)

// Status is a snapshot of a transport.
type Status struct {
	Kind      string    `json:"kind"`
	State     string    `json:"state"`
	Since     time.Time `json:"since"`
	Restarts  int       `json:"restarts"`
	LastError string    `json:"last_error,omitempty"`
	// LocalUDP is where WireGuard should send packets (client side).
	LocalUDP string `json:"local_udp,omitempty"`
}

// Transport carries WireGuard UDP between the two machines.
type Transport interface {
	// Kind names the implementation ("wstunnel").
	Kind() string
	// Start launches and supervises the transport. It returns once the
	// transport reports ready or the ready timeout elapses (the supervisor
	// keeps retrying in the background either way).
	Start(ctx context.Context) error
	// Restart forces a reconnect (used by the health loop).
	Restart()
	Status() Status
	// Stop terminates the transport and waits for it to exit.
	Stop() error
}
