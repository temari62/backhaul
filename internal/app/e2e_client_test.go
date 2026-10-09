package app

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
	wgnetstack "golang.zx2c4.com/wireguard/tun/netstack"

	"backhaul/internal/config"
	"backhaul/internal/keys"
	"backhaul/internal/tlspin"
	"backhaul/internal/transport"
	"backhaul/internal/wg"
)

// userspaceClient is a full Backhaul client that changes nothing on the host:
// pinned-TLS proxy + real wstunnel client + wireguard-go on its own netstack.
type userspaceClient struct {
	net   *wgnetstack.Net
	dev   *device.Device
	tr    *transport.Wstunnel
	proxy *tlspin.Proxy
}

func startUserspaceClient(t *testing.T, ctx context.Context, cc *config.Config, cs *config.Secrets, wst string) *userspaceClient {
	t.Helper()
	host, port, pin := cc.RemoteHost()
	proxy, err := tlspin.NewProxy(func() string { return host + ":" + strconv.Itoa(port) }, host, pin, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	go proxy.Serve(ctx)
	localUDP := "127.0.0.1:" + strconv.Itoa(freePort(t, "udp"))
	tr := transport.NewWstunnel(transport.WstunnelOptions{Binary: wst, Role: transport.RoleClient,
		ServerURL: "ws://" + proxy.Addr(), LocalUDP: localUDP, RemoteUDP: "127.0.0.1:" + strconv.Itoa(cc.Transport.RemoteUDPPort),
		PathPrefix: cc.Transport.PathPrefix, ReadyTimeout: 15 * time.Second, BackoffMin: 200 * time.Millisecond, BackoffMax: 2 * time.Second})
	if err := tr.Start(ctx); err != nil {
		t.Fatal(err)
	}
	self, _ := config.ParsePrefixHost(cc.WireGuard.SelfIP)
	dns, _ := cc.DNSServers()
	tdev, tnet, err := wgnetstack.CreateNetTUN([]netip.Addr{self}, dns[:1], cc.WireGuard.MTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, wg.NewLoopbackBind(), device.NewLogger(device.LogLevelError, "client: "))
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
	return &userspaceClient{net: tnet, dev: dev, tr: tr, proxy: proxy}
}

func (c *userspaceClient) http() *http.Client {
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DialContext: c.net.DialContext}}
}

// fetchUntil retries GET url through the tunnel until it succeeds or d elapses.
func (c *userspaceClient) fetchUntil(url string, d time.Duration) (string, error) {
	deadline := time.Now().Add(d)
	for {
		body, err := get(c.http(), url)
		if err == nil || time.Now().After(deadline) {
			return body, err
		}
		time.Sleep(time.Second)
	}
}

func (c *userspaceClient) close() {
	go c.dev.Close() // async: some Windows LSPs block socket Close
	c.tr.Stop()
	c.proxy.Close()
}

// TestE2EClientAgainstRunningExit connects a userspace client to an exit node
// that is already running elsewhere (e.g. started from the desktop app), using
// a client profile directory, and keeps traffic flowing for a while:
//
//	BACKHAUL_E2E_CLIENT_DIR=<client profile> BACKHAUL_TEST_WSTUNNEL=... go test ./internal/app -run ClientAgainst -v
func TestE2EClientAgainstRunningExit(t *testing.T) {
	dir, wst := os.Getenv("BACKHAUL_E2E_CLIENT_DIR"), os.Getenv("BACKHAUL_TEST_WSTUNNEL")
	if dir == "" || wst == "" {
		t.Skip("set BACKHAUL_E2E_CLIENT_DIR and BACKHAUL_TEST_WSTUNNEL to run")
	}
	cc, cs, err := config.Load(config.Paths{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := startUserspaceClient(t, ctx, cc, cs, wst)
	defer c.close()
	ip, err := c.fetchUntil(cc.Health.IPCheckURL, 45*time.Second)
	if err != nil {
		t.Fatalf("through the tunnel: %v", err)
	}
	t.Logf("egress via the running exit node: %s", ip)
	// Keep some traffic flowing so the exit node shows a live, healthy peer.
	for i := 0; i < 8; i++ {
		get(c.http(), cc.Health.IPCheckURL)
		time.Sleep(time.Second)
	}
}
