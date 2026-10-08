package transport

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"backhaul/internal/tlspin"
)

func TestArgs(t *testing.T) {
	srv := WstunnelOptions{Role: RoleServer, ListenAddr: "0.0.0.0", Port: 443, CertFile: "c", KeyFile: "k",
		RestrictTo: "127.0.0.1:51820", PathPrefix: "p"}.Args()
	want := []string{"server", "--log-lvl", "INFO", "--restrict-to", "127.0.0.1:51820", "--tls-certificate", "c",
		"--tls-private-key", "k", "--restrict-http-upgrade-path-prefix", "p", "wss://0.0.0.0:443"}
	if !slices.Equal(srv, want) {
		t.Fatalf("server args %v", srv)
	}
	cli := WstunnelOptions{Role: RoleClient, LocalUDP: "127.0.0.1:51821", RemoteUDP: "127.0.0.1:51820",
		ServerURL: "ws://127.0.0.1:9", PathPrefix: "p"}.Args()
	if !slices.Contains(cli, "udp://127.0.0.1:51821:127.0.0.1:51820?timeout_sec=0") || cli[len(cli)-1] != "ws://127.0.0.1:9" {
		t.Fatalf("client args %v", cli)
	}
	rev := WstunnelOptions{Role: RoleReverseClient, RelayBind: "127.0.0.1:51820", RemoteUDP: "127.0.0.1:51820", ServerURL: "ws://x"}.Args()
	if !slices.Contains(rev, "-R") {
		t.Fatalf("reverse args %v", rev)
	}
	if got := (WstunnelOptions{Role: RoleServer, ListenAddr: "::", Port: 443}).Args(); got[len(got)-1] != "wss://[::]:443" {
		t.Fatalf("v6 listen %v", got)
	}
}

func TestReadyRE(t *testing.T) {
	for _, l := range []string{
		"INFO wstunnel::tunnel::server::server: Starting wstunnel server listening on 127.0.0.1:18443",
		"INFO wstunnel::protocols::udp::server: Starting UDP server listening cnx on 127.0.0.1:51998 with cnx timeout of 0s",
	} {
		if !readyRE.MatchString(l) {
			t.Errorf("not matched: %s", l)
		}
	}
}

func wstunnelBinary(t *testing.T) string {
	if p := os.Getenv("BACKHAUL_TEST_WSTUNNEL"); p != "" {
		return p
	}
	if p, err := exec.LookPath("wstunnel"); err == nil {
		return p
	}
	t.Skip("wstunnel not available (set BACKHAUL_TEST_WSTUNNEL)")
	return ""
}

func freePort(t *testing.T, network string) int {
	if network == "udp" {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestEndToEndUDPOverPinnedWSS is the M3 smoke test: a UDP "WireGuard"
// datagram goes client → wstunnel client → pinned TLS proxy → wstunnel
// server (self-signed cert, path-prefix restricted) → UDP echo, and back.
func TestEndToEndUDPOverPinnedWSS(t *testing.T) {
	bin := wstunnelBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Close asynchronously: on hosts with certain Winsock LSPs, closing a
	// socket with a pending read blocks until the read completes.
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
	common := WstunnelOptions{Binary: bin, PathPrefix: "secretprefix", ReadyTimeout: 15 * time.Second,
		BackoffMin: 200 * time.Millisecond, BackoffMax: 2 * time.Second}

	so := common
	so.Role, so.ListenAddr, so.Port, so.CertFile, so.KeyFile, so.RestrictTo = RoleServer, "127.0.0.1", wssPort, cert, key, echo.LocalAddr().String()
	srv := NewWstunnel(so)
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
	co := common
	co.Role, co.ServerURL, co.LocalUDP, co.RemoteUDP = RoleClient, "ws://"+proxy.Addr(), local, echo.LocalAddr().String()
	cli := NewWstunnel(co)
	if err := cli.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer cli.Stop()

	roundTrip := func(msg string) {
		t.Helper()
		c, err := net.Dial("udp", local)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		buf := make([]byte, 64)
		for i := 0; i < 20; i++ {
			c.Write([]byte(msg))
			c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if n, err := c.Read(buf); err == nil && string(buf[:n]) == msg {
				return
			}
		}
		t.Fatalf("no echo for %q through the tunnel (client: %+v, server: %+v, proxy: %v)", msg, cli.Status(), srv.Status(), proxy.LastError())
	}
	roundTrip("handshake-initiation")

	// Supervisor: a forced restart must come back and carry traffic again.
	cli.Restart()
	deadline := time.Now().Add(15 * time.Second)
	for cli.Status().Restarts == 0 || cli.Status().State != StateReady {
		if time.Now().After(deadline) {
			t.Fatalf("client did not restart: %+v", cli.Status())
		}
		time.Sleep(100 * time.Millisecond)
	}
	roundTrip("after-restart")
}
