package transport

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Cloudflare routes by the HTTP Host header, so in Cloudflare mode wstunnel
// must send Host: <hostname> even though it dials our local proxy. This
// records the upgrade request the real wstunnel sends.
func TestWstunnelSendsCustomHostHeader(t *testing.T) {
	bin := wstunnelBinary(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { go ln.Close() }()
	got := make(chan *http.Request, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		if req, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
			got <- req
		}
	}()
	lp, _ := net.ListenPacket("udp", "127.0.0.1:0")
	local := lp.LocalAddr().String()
	lp.Close()
	o := WstunnelOptions{Binary: bin, Role: RoleClient, LocalUDP: local, RemoteUDP: "127.0.0.1:51820",
		ServerURL: "ws://" + ln.Addr().String(), PathPrefix: "myprefix", HostHeader: "vpn.example.com",
		ReadyTimeout: 10 * time.Second, BackoffMin: time.Second, BackoffMax: 2 * time.Second}
	s := NewWstunnel(o)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	c, _ := net.Dial("udp", local)
	defer c.Close()
	c.Write([]byte{1, 2, 3}) // wstunnel opens the WebSocket on the first packet
	select {
	case req := <-got:
		if req.Host != "vpn.example.com" {
			t.Fatalf("Host = %q (all headers: %v)", req.Host, req.Header)
		}
		if !strings.HasPrefix(req.URL.Path, "/myprefix") || !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
			t.Fatalf("unexpected upgrade request: %s %v", req.URL, req.Header)
		}
		t.Logf("upgrade request: GET %s Host=%s", req.URL.Path, req.Host)
	case <-ctx.Done():
		t.Fatal("no upgrade request received")
	}
}
