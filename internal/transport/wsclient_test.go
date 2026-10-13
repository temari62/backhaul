package transport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"backhaul/internal/tlspin"
)

// The token must look like the real wstunnel v10.7.1 client's (header and
// claims below were captured from it). The server doesn't check the
// signature: TestWSClientEndToEnd proves it accepts these tokens.
func TestTunnelJWTMatchesWstunnel(t *testing.T) {
	const captured = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjAxYTEzM2JhLTUyN2UtNzU0MC1iZDJkLTNlMjdkMTQ5NzAwZSIsInAiOnsiVWRwIjp7InRpbWVvdXQiOm51bGx9fSwiciI6IjEyNy4wLjAuMSIsInJwIjo1MTgyMH0.ofZ5CmMxgXw_b_KuRSoKFppnkPpIEwipbc2HJ42AKfo"
	parts := strings.Split(captured, ".")

	tok, err := tunnelJWT("127.0.0.1:51820")
	if err != nil {
		t.Fatal(err)
	}
	p := strings.Split(tok, ".")
	if len(p) != 3 || p[0] != parts[0] {
		t.Fatalf("header differs: %s", tok)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(p[1])
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["r"] != "127.0.0.1" || claims["rp"] != float64(51820) || len(claims["id"].(string)) != 36 {
		t.Fatalf("claims: %s", raw)
	}
	if string(mustJSON(claims["p"])) != `{"Udp":{"timeout":null}}` {
		t.Fatalf("protocol claim: %s", mustJSON(claims["p"]))
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// TestWSClientEndToEnd: datagrams go through the built-in client → pinned
// TLS proxy → the real wstunnel server (self-signed cert, path prefix) →
// UDP echo, and back; then again after a forced reconnect.
func TestWSClientEndToEnd(t *testing.T) {
	bin := wstunnelBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { go echo.Close() }()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(buf[:n], from)
		}
	}()

	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	fp, err := tlspin.GenerateSelfSigned("127.0.0.1", cert, key)
	if err != nil {
		t.Fatal(err)
	}
	wssPort := freePort(t, "tcp")
	srv := NewWstunnel(WstunnelOptions{Binary: bin, PathPrefix: "secretprefix", ReadyTimeout: 15 * time.Second,
		BackoffMin: 200 * time.Millisecond, BackoffMax: 2 * time.Second,
		Role: RoleServer, ListenAddr: "127.0.0.1", Port: wssPort, CertFile: cert, KeyFile: key, RestrictTo: echo.LocalAddr().String()})
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	proxy, err := tlspin.NewProxy(func() string { return "127.0.0.1:" + strconv.Itoa(wssPort) }, "127.0.0.1", fp, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	go proxy.Serve(ctx)
	defer proxy.Close()

	local := "127.0.0.1:" + strconv.Itoa(freePort(t, "udp"))
	cli := NewWSClient(WSClientOptions{ServerAddr: proxy.Addr(), HostHeader: "vpn.example.test", PathPrefix: "secretprefix",
		LocalUDP: local, RemoteUDP: echo.LocalAddr().String(), BackoffMin: 200 * time.Millisecond, BackoffMax: time.Second})
	if err := cli.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer cli.Stop()

	c, err := net.Dial("udp", local)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { go c.Close() }()
	got := make(chan string, 16)
	go func() { // goroutine reads: socket deadlines don't fire on some Windows hosts
		buf := make([]byte, 2048)
		for {
			n, err := c.Read(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				t.Logf("read: %v (continuing)", err)
				time.Sleep(20 * time.Millisecond)
				continue
			}
			got <- string(buf[:n])
		}
	}()
	roundTrip := func(msg string) {
		t.Helper()
		deadline := time.After(15 * time.Second)
		tick := time.NewTicker(300 * time.Millisecond)
		defer tick.Stop()
		c.Write([]byte(msg))
		for {
			select {
			case g := <-got:
				if g == msg {
					return
				}
				t.Logf("unexpected reply %q", g)
			case <-tick.C:
				c.Write([]byte(msg))
			case <-deadline:
				t.Fatalf("no echo for %q (client %+v, proxy err %v, server %+v)", msg, cli.Status(), proxy.LastError(), srv.Status())
			}
		}
	}
	roundTrip("handshake-initiation")
	big := strings.Repeat("x", 1400) // WireGuard-sized datagram (16-bit length frame)
	roundTrip(big)

	cli.Restart()
	roundTrip("after-restart")
	if cli.Status().Restarts != 1 {
		t.Fatalf("restarts = %d", cli.Status().Restarts)
	}
}
