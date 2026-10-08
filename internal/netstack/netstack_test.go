package netstack

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// fakeNet records outbound dials and answers them with an echo that
// prefixes replies with the dialled address.
type fakeNet struct {
	mu    sync.Mutex
	dials []string
}

func (f *fakeNet) dial(_ context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, network+" "+addr)
	f.mu.Unlock()
	a, b := net.Pipe()
	go func() {
		defer b.Close()
		buf := make([]byte, 2048)
		for {
			n, err := b.Read(buf)
			if err != nil {
				return
			}
			if _, err := b.Write([]byte(addr + "|" + string(buf[:n]))); err != nil {
				return
			}
		}
	}()
	return a, nil
}

// clientStack is a second gVisor stack standing in for the client laptop,
// connected to the exit device as WireGuard would be (raw IP packets).
func clientStack(t *testing.T, exit *Device) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(256, 1280, "")
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatal(err)
	}
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(netip.MustParseAddr("10.9.0.2").AsSlice()).WithPrefix()}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); s.Close() })
	go func() { // client → exit
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			pkt.DecRef()
			exit.Write([][]byte{v.AsSlice()}, 0)
			v.Release()
		}
	}()
	go func() { // exit → client
		buf := [][]byte{make([]byte, 2048)}
		sizes := []int{0}
		for {
			if _, err := exit.Read(buf, sizes, 0); err != nil {
				return
			}
			pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: bufferFrom(buf[0][:sizes[0]])})
			ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
			pkb.DecRef()
		}
	}()
	return s
}

func newExit(t *testing.T, f *fakeNet) *Device {
	d, err := New(Options{
		Addresses: []netip.Addr{netip.MustParseAddr("10.9.0.1")}, MTU: 1280,
		DNSUpstream: "198.51.100.53:53", DialTimeout: 2 * time.Second, UDPIdle: 5 * time.Second, Dial: f.dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func full(ip string, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(netip.MustParseAddr(ip).AsSlice()), Port: port}
}

func roundTrip(t *testing.T, c net.Conn, msg string) string {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func TestTCPIsReoriginated(t *testing.T) {
	f := &fakeNet{}
	cs := clientStack(t, newExit(t, f))
	c, err := gonet.DialTCP(cs, full("203.0.113.10", 443), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := roundTrip(t, c, "hello"); got != "203.0.113.10:443|hello" {
		t.Fatalf("got %q", got)
	}
}

func TestUDPAndDNSRedirect(t *testing.T) {
	f := &fakeNet{}
	cs := clientStack(t, newExit(t, f))
	for _, tc := range []struct{ dst, want string }{
		{"203.0.113.20", "203.0.113.20:53|q1"}, // public resolver: dialled directly
		{"10.9.0.1", "198.51.100.53:53|q2"},    // our tunnel IP:53 → DNS upstream
	} {
		local := full("10.9.0.2", 0)
		remote := full(tc.dst, 53)
		c, err := gonet.DialUDP(cs, &local, &remote, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatal(err)
		}
		if got := roundTrip(t, c, strings.Split(tc.want, "|")[1]); got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.dst, got, tc.want)
		}
		c.Close()
	}
}

func TestRefusesExitNodeServices(t *testing.T) {
	f := &fakeNet{}
	cs := clientStack(t, newExit(t, f))
	for _, dst := range []string{"10.9.0.1", "127.0.0.1"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := gonet.DialContextTCP(ctx, cs, full(dst, 51820), ipv4.ProtocolNumber)
		cancel()
		if err == nil {
			c.Close()
			t.Fatalf("connection to %s:51820 was allowed", dst)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.dials) != 0 {
		t.Fatalf("refused flows must not be dialled: %v", f.dials)
	}
}
