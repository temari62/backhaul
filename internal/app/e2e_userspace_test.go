package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
	wgnetstack "golang.zx2c4.com/wireguard/tun/netstack"

	"backhaul/internal/config"
	"backhaul/internal/keys"
	"backhaul/internal/state"
	"backhaul/internal/tlspin"
	"backhaul/internal/transport"
	"backhaul/internal/wg"
)

func freePort(t *testing.T, network string) int {
	t.Helper()
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
	p := l.Addr().(*net.TCPAddr).Port
	go l.Close() // async: some Windows LSPs block Close
	return p
}

// TestE2EUserspaceExit runs the real exit node (app.Serve, userspace NAT,
// real wstunnel) and an in-process client (wireguard-go on its own netstack,
// real wstunnel client, pinned-TLS proxy), then fetches a public IP-echo
// service through the tunnel using the tunnel's DNS. Needs no privileges and
// changes nothing on the host, but needs internet access:
//
//	BACKHAUL_E2E=1 BACKHAUL_TEST_WSTUNNEL=/path/to/wstunnel go test ./internal/app -run E2E -v
func TestE2EUserspaceExit(t *testing.T) {
	wst := os.Getenv("BACKHAUL_TEST_WSTUNNEL")
	if os.Getenv("BACKHAUL_E2E") == "" || wst == "" {
		t.Skip("set BACKHAUL_E2E=1 and BACKHAUL_TEST_WSTUNNEL to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// --- exit node ---
	srvPaths := config.Paths{Dir: t.TempDir()}
	wssPort, wgPort := freePort(t, "tcp"), freePort(t, "udp")
	res, err := SetupExitNode(srvPaths, ExitNodeOptions{Endpoint: "127.0.0.1", Port: wssPort,
		Subnet: "10.9.0.0/24", ReachMode: config.ReachPortForward})
	if err != nil {
		t.Fatal(err)
	}
	sc := res.Config
	sc.Serve.NATMode = config.NATUserspace
	sc.Transport.WstunnelPath = wst
	sc.Transport.ListenAddr = "127.0.0.1"
	sc.Transport.CertFile, sc.Transport.KeyFile = srvPaths.Cert(), srvPaths.Key()
	sc.WireGuard.ListenPort = wgPort
	sc.Health.Interval = config.D(time.Second)

	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(serveCtx, &Env{Cfg: sc, Sec: res.Secrets, Paths: srvPaths}) }()
	waitFor(t, 30*time.Second, "exit node runtime state", func() bool {
		_, ok, _ := state.Read(srvPaths.State())
		return ok
	})

	// --- client (in-process, no OS changes) ---
	cc, cs, err := ImportBlob(res.Blob)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := tlspin.NewProxy(func() string { return "127.0.0.1:" + strconv.Itoa(wssPort) }, "127.0.0.1", cc.Transport.TLSSHA256, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	go proxy.Serve(ctx)
	defer proxy.Close()
	localUDP := "127.0.0.1:" + strconv.Itoa(freePort(t, "udp"))
	tr := transport.NewWstunnel(transport.WstunnelOptions{Binary: wst, Role: transport.RoleClient,
		ServerURL: "ws://" + proxy.Addr(), LocalUDP: localUDP, RemoteUDP: "127.0.0.1:" + strconv.Itoa(wgPort),
		PathPrefix: cc.Transport.PathPrefix, ReadyTimeout: 15 * time.Second, BackoffMin: 200 * time.Millisecond, BackoffMax: 2 * time.Second})
	if err := tr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()

	tdev, tnet, err := wgnetstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.9.0.2")}, []netip.Addr{netip.MustParseAddr("10.9.0.1")}, cc.WireGuard.MTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, wg.NewLoopbackBind(), device.NewLogger(device.LogLevelError, "client: "))
	defer func() { go dev.Close() }() // async: some Windows LSPs block socket Close
	priv, _ := keys.Hex(cs.PrivateKey)
	pub, _ := keys.Hex(cc.Peer.PublicKey)
	psk, _ := keys.Hex(cs.PresharedKey)
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=%s\npersistent_keepalive_interval=5\nallowed_ip=0.0.0.0/0\n",
		priv, pub, psk, localUDP)); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}

	// --- through the tunnel: DNS via 10.9.0.1 (relayed upstream) + HTTPS ---
	tunnelHTTP := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: tnet.DialContext}}
	var viaTunnel string
	deadline := time.Now().Add(45 * time.Second)
	for {
		if viaTunnel, err = get(tunnelHTTP, sc.Health.IPCheckURL); err == nil {
			break
		}
		if time.Now().After(deadline) {
			rt, _, _ := state.Read(srvPaths.State())
			st, _ := dev.IpcGet()
			t.Fatalf("HTTPS through the tunnel: %v\nserver runtime: %+v\nclient wg: %s\ntransport: %+v proxy err: %v",
				err, rt, st, tr.Status(), proxy.LastError())
		}
		time.Sleep(time.Second)
	}
	direct, err := get(http.DefaultClient, sc.Health.IPCheckURL)
	if err != nil {
		t.Fatalf("direct IP check: %v", err)
	}
	t.Logf("egress via tunnel = %s, exit node's own egress = %s", viaTunnel, direct)
	if viaTunnel != direct {
		t.Fatalf("tunnel egress %s ≠ exit node egress %s", viaTunnel, direct)
	}
	addrs, err := tnet.LookupHost("example.com")
	if err != nil || len(addrs) == 0 {
		t.Fatalf("DNS through the tunnel: %v %v", addrs, err)
	}

	// Server saw the handshake and traffic.
	waitFor(t, 10*time.Second, "server handshake in runtime state", func() bool {
		rt, ok, _ := state.Read(srvPaths.State())
		return ok && rt.Healthy && rt.RxBytes > 0
	})

	// --- clean shutdown via `disconnect`'s mechanism ---
	if err := state.RequestStop(srvPaths.State()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("serve returned %v", err)
		}
	case <-time.After(30 * time.Second):
		stopServe()
		pprof.Lookup("goroutine").WriteTo(os.Stderr, 1)
		t.Fatal("serve did not stop on request")
	}
	if _, ok, _ := state.Read(srvPaths.State()); ok {
		t.Fatal("runtime state left behind")
	}
	if _, err := os.Stat(state.JournalFile(srvPaths.State())); err == nil {
		t.Fatal("undo journal left behind")
	}
}

func get(c *http.Client, url string) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", resp.Status)
	}
	return strings.TrimSpace(string(b)), nil
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(300 * time.Millisecond)
	}
}
