// Package netstack is the exit node's userspace NAT: a WireGuard TUN device
// backed by gVisor's TCP/IP stack (the same stack wireguard-go's netstack
// uses). Every TCP connection and UDP flow the client sends is terminated in
// that stack and re-originated as an ordinary outbound socket from this
// process, so traffic leaves with the exit node's IP without any OS NAT,
// route changes, TUN driver or (on Windows) administrator rights.
//
// Trade-offs vs. system NAT: ICMP (ping) is not forwarded, and throughput is
// lower. Queries to the exit node's own tunnel IP on port 53 are relayed to
// the configured DNS upstream, replacing the OS-level DNS forwarder.
package netstack

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID = 1
	// tcpMaxInFlight bounds half-open forwarded TCP connections.
	tcpMaxInFlight = 1024
	// channelSize is the link endpoint's outbound packet queue.
	channelSize = 1024
)

// Options configure the exit stack.
type Options struct {
	Addresses   []netip.Addr  // the exit node's tunnel IPs (10.9.0.1, fd09:b4c0::1)
	MTU         int           // must match the WireGuard MTU
	DNSUpstream string        // "1.1.1.1:53": target for queries to our own tunnel IP:53 ("" = refuse)
	DialTimeout time.Duration // outbound TCP connect timeout
	UDPIdle     time.Duration // close idle UDP flows after this long
	// Dial makes outbound connections (tests override it). Default net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Device implements wireguard-go's tun.Device on top of a gVisor stack.
type Device struct {
	opts     Options
	ep       *channel.Endpoint
	stack    *stack.Stack
	events   chan tun.Event
	incoming chan *buffer.View
	notify   *channel.NotificationHandle
	done     chan struct{}
	once     sync.Once
	own      map[netip.Addr]bool
}

// New builds the stack and installs the TCP/UDP forwarders.
func New(o Options) (*Device, error) {
	if o.Dial == nil {
		d := &net.Dialer{Timeout: o.DialTimeout}
		o.Dial = d.DialContext
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		// Must be false: with promiscuous mode, HandleLocal makes gVisor
		// adopt each packet's source as a temporary local address and then
		// drop the packet as "from ourselves".
		HandleLocal: false,
	})
	d := &Device{
		opts:     o,
		ep:       channel.New(channelSize, uint32(o.MTU), ""),
		stack:    s,
		events:   make(chan tun.Event, 10),
		incoming: make(chan *buffer.View),
		done:     make(chan struct{}),
		own:      map[netip.Addr]bool{},
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, fmt.Errorf("enable TCP SACK: %v", err)
	}
	d.notify = d.ep.AddNotify(d)
	if err := s.CreateNIC(nicID, d.ep); err != nil {
		return nil, fmt.Errorf("create NIC: %v", err)
	}
	// Accept packets for any destination (we are the client's whole internet)
	// and allow replies sourced from those destinations.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("promiscuous mode: %v", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("spoofing: %v", err)
	}
	for _, a := range o.Addresses {
		proto := ipv4.ProtocolNumber
		if a.Is6() {
			proto = ipv6.ProtocolNumber
		}
		if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol: proto, AddressWithPrefix: tcpip.AddrFromSlice(a.AsSlice()).WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("add address %s: %v", a, err)
		}
		d.own[a] = true
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	tcpFwd := tcp.NewForwarder(s, 0, tcpMaxInFlight, d.forwardTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, d.forwardUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	d.events <- tun.EventUp
	return d, nil
}

// target maps a flow's destination (as seen by the client) to the address
// we dial. ok=false means the flow is refused.
func (d *Device) target(id stack.TransportEndpointID) (addr string, ok bool) {
	ip, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	ip = ip.Unmap()
	switch {
	case d.own[ip] && id.LocalPort == 53 && d.opts.DNSUpstream != "":
		return d.opts.DNSUpstream, true // the client's DNS server is us
	case d.own[ip], ip.IsLoopback(), ip.IsUnspecified(), ip.IsMulticast():
		// Never let the tunnel reach this machine's own loopback services
		// (wstunnel, the WireGuard port, …).
		return "", false
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(id.LocalPort))), true
}

func (d *Device) forwardTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst, ok := d.target(id)
	if !ok {
		r.Complete(true)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), d.opts.DialTimeout)
		out, err := d.opts.Dial(ctx, "tcp", dst)
		cancel()
		if err != nil {
			slog.Debug("userspace NAT: tcp dial failed", "dst", dst, "err", err)
			r.Complete(true) // RST, like an unreachable host behind real NAT
			return
		}
		var wq waiter.Queue
		ep, tErr := r.CreateEndpoint(&wq)
		if tErr != nil {
			r.Complete(true)
			out.Close()
			return
		}
		r.Complete(false)
		in := gonet.NewTCPConn(&wq, ep)
		pipe(in, out)
	}()
}

func (d *Device) forwardUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dst, ok := d.target(id)
	if !ok {
		return
	}
	var wq waiter.Queue
	ep, tErr := r.CreateEndpoint(&wq)
	if tErr != nil {
		return
	}
	in := gonet.NewUDPConn(&wq, ep)
	go func() {
		defer in.Close()
		out, err := d.opts.Dial(context.Background(), "udp", dst)
		if err != nil {
			slog.Debug("userspace NAT: udp dial failed", "dst", dst, "err", err)
			return
		}
		defer out.Close()
		idle := d.opts.UDPIdle
		done := make(chan struct{}, 2)
		relay := func(dstC, srcC net.Conn) {
			buf := make([]byte, 65535)
			for {
				_ = srcC.SetReadDeadline(time.Now().Add(idle))
				n, err := srcC.Read(buf)
				if err != nil {
					done <- struct{}{}
					return
				}
				if _, err := dstC.Write(buf[:n]); err != nil {
					done <- struct{}{}
					return
				}
			}
		}
		go relay(out, in)
		go relay(in, out)
		<-done
	}()
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite() // propagate half-close
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	// Give the other direction a moment to drain, then tear down.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	a.Close()
	b.Close()
}

// --- tun.Device ---

func (d *Device) File() *os.File           { return nil }
func (d *Device) MTU() (int, error)        { return d.opts.MTU, nil }
func (d *Device) Name() (string, error)    { return "userspace", nil }
func (d *Device) Events() <-chan tun.Event { return d.events }
func (d *Device) BatchSize() int           { return 1 }

// Read hands WireGuard the next packet the stack wants to send to the client.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case v := <-d.incoming:
		n, err := v.Read(bufs[0][offset:])
		v.Release()
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		return 1, nil
	case <-d.done:
		return 0, os.ErrClosed
	}
}

// Write injects decrypted packets from the client into the stack.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		p := b[offset:]
		if len(p) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
		switch p[0] >> 4 {
		case 4:
			d.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			d.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			pkb.DecRef()
			return 0, syscall.EAFNOSUPPORT
		}
		pkb.DecRef()
	}
	return len(bufs), nil
}

// WriteNotify is called by the channel endpoint when the stack emits a packet.
func (d *Device) WriteNotify() {
	pkt := d.ep.Read()
	if pkt == nil {
		return
	}
	v := pkt.ToView()
	pkt.DecRef()
	select {
	case d.incoming <- v:
	case <-d.done:
		v.Release()
	}
}

// Close tears the stack down (safe to call more than once).
func (d *Device) Close() error {
	d.once.Do(func() {
		close(d.done)
		d.stack.RemoveNIC(nicID)
		d.stack.Close()
		d.ep.RemoveNotify(d.notify)
		d.ep.Close()
		close(d.events)
	})
	return nil
}
