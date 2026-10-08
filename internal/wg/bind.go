package wg

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// bindCloseTimeout bounds socket Close. Some Windows Winsock layered service
// providers never complete a cancelled read, which makes Close block.
const bindCloseTimeout = 2 * time.Second

// LoopbackBind is a minimal WireGuard UDP bind on 127.0.0.1.
//
// Backhaul's WireGuard only ever talks to the local wstunnel process, so a
// loopback socket is all it needs. Compared with wireguard-go's default bind
// it (a) never exposes the WireGuard port beyond this machine and (b) uses
// only plain sendto/recvfrom, avoiding the Windows RIO / WSASendMsg paths
// that third-party Winsock LSPs (some VPN/proxy/AV products) break with
// "wsasendmsg: An invalid argument was supplied".
type LoopbackBind struct {
	mu   sync.Mutex
	conn *net.UDPConn
}

// NewLoopbackBind returns an unopened bind.
func NewLoopbackBind() *LoopbackBind { return &LoopbackBind{} }

type loopEndpoint netip.AddrPort

func (e loopEndpoint) ClearSrc()           {}
func (e loopEndpoint) SrcToString() string { return "" }
func (e loopEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e loopEndpoint) DstToBytes() []byte {
	b, _ := netip.AddrPort(e).MarshalBinary()
	return b
}
func (e loopEndpoint) DstIP() netip.Addr { return netip.AddrPort(e).Addr() }
func (e loopEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

// Open implements conn.Bind.
func (b *LoopbackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.conn = c
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, ap, err := c.ReadFromUDPAddrPort(packets[0])
		b.mu.Lock()
		closed := b.conn != c
		b.mu.Unlock()
		if closed {
			return 0, net.ErrClosed // woken by Close
		}
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = loopEndpoint(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

// Close implements conn.Bind.
func (b *LoopbackBind) Close() error {
	b.mu.Lock()
	c := b.conn
	b.conn = nil
	b.mu.Unlock()
	if c == nil {
		return nil
	}
	// Wake the blocked reader with a datagram to ourselves: wireguard-go
	// waits for its receive loop to exit, and on hosts where Close can't
	// cancel a pending read that wait would otherwise never end.
	if w, err := net.DialUDP("udp4", nil, c.LocalAddr().(*net.UDPAddr)); err == nil {
		_, _ = w.Write([]byte{0})
		w.Close()
	}
	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	select {
	case err := <-done:
		return err
	case <-time.After(bindCloseTimeout):
		return nil
	}
}

// SetMark implements conn.Bind (no-op: loopback traffic needs no fwmark).
func (b *LoopbackBind) SetMark(uint32) error { return nil }

// Send implements conn.Bind.
func (b *LoopbackBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(loopEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	c := b.conn
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := c.WriteToUDPAddrPort(buf, netip.AddrPort(e)); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint implements conn.Bind. Only loopback endpoints are valid.
func (b *LoopbackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	if !ap.Addr().Unmap().IsLoopback() {
		return nil, errors.New("backhaul's WireGuard only talks to the local transport (127.0.0.1)")
	}
	return loopEndpoint(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())), nil
}

// BatchSize implements conn.Bind.
func (b *LoopbackBind) BatchSize() int { return 1 }
