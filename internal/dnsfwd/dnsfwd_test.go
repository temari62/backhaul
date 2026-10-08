package dnsfwd

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestRelaysUDP(t *testing.T) {
	// Fake upstream: echoes the query with a marker byte appended.
	up, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { go up.Close() }() // async: some Windows LSPs block Close during a pending read
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			up.WriteTo(append(buf[:n:n], '!'), from)
		}
	}()

	f, err := Listen("127.0.0.1:0", up.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Serve(ctx)

	c, err := net.Dial("udp", f.pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { go c.Close() }()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("query"))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "query!" {
		t.Fatalf("got %q, %v", buf[:n], err)
	}
}
