package app

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"backhaul/internal/config"
	"backhaul/internal/osutil"
	"backhaul/internal/state"
)

// TestE2ECloudflareTunnelExit runs the real exit node in Cloudflare Tunnel
// mode (userspace NAT, real wstunnel, real cloudflared with a token that
// Cloudflare won't accept) and connects a client to the local port where
// cloudflared delivers the tunnel's traffic — everything but Cloudflare
// itself. The exit node must serve only on 127.0.0.1 and skip the router.
//
//	BACKHAUL_E2E=1 BACKHAUL_TEST_WSTUNNEL=... BACKHAUL_TEST_CLOUDFLARED=... go test ./internal/app -run CloudflareTunnel -v
func TestE2ECloudflareTunnelExit(t *testing.T) {
	wst, cfd := os.Getenv("BACKHAUL_TEST_WSTUNNEL"), os.Getenv("BACKHAUL_TEST_CLOUDFLARED")
	if os.Getenv("BACKHAUL_E2E") == "" || wst == "" || cfd == "" {
		t.Skip("set BACKHAUL_E2E=1, BACKHAUL_TEST_WSTUNNEL and BACKHAUL_TEST_CLOUDFLARED to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	srvPaths := config.Paths{Dir: t.TempDir()}
	localPort, wgPort := freePort(t, "tcp"), freePort(t, "udp")
	res, err := SetupExitNode(srvPaths, ExitNodeOptions{Endpoint: "home.example.test", Port: 443,
		Subnet: "10.9.0.0/24", ReachMode: config.ReachPortForward, Transport: config.TransportCloudflare,
		CloudflareTunnelID: "tun-test", CloudflareTunnelToken: "not-a-real-token"})
	if err != nil {
		t.Fatal(err)
	}
	sc := res.Config
	if sc.Reachability.Mode != config.ReachCFTunnel {
		t.Fatalf("reach mode %q", sc.Reachability.Mode)
	}
	sc.Reachability.CFTunnel.LocalPort = localPort
	sc.Reachability.CFTunnel.CloudflaredPath = cfd
	sc.Serve.NATMode = config.NATUserspace
	sc.Transport.WstunnelPath = wst
	sc.Transport.CertFile, sc.Transport.KeyFile = srvPaths.Cert(), srvPaths.Key()
	sc.WireGuard.ListenPort = wgPort
	sc.Health.Interval = config.D(time.Second)

	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	go Serve(serveCtx, &Env{Cfg: sc, Sec: res.Secrets, Paths: srvPaths})
	var rt *state.Runtime
	waitFor(t, 45*time.Second, "exit node runtime state", func() bool {
		r, ok, _ := state.Read(srvPaths.State())
		rt = r
		return ok
	})
	if rt.Router == "" || rt.LANIP != "" {
		t.Fatalf("tunnel mode must skip the router step and say so: router %q lan %q", rt.Router, rt.LANIP)
	}
	// The Share tab must tell the truth: not connected, and why.
	waitFor(t, 20*time.Second, "tunnel status naming cloudflared's reason", func() bool {
		r, ok, _ := state.Read(srvPaths.State())
		return ok && strings.Contains(r.Router, "token is not valid")
	})

	// wstunnel listens on loopback only.
	if lan := osutil.LANIP(); lan != "" {
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(lan, strconv.Itoa(localPort)), 2*time.Second); err == nil {
			c.Close()
			t.Fatalf("the exit node is reachable on %s:%d; it must only listen on 127.0.0.1", lan, localPort)
		}
	}

	// The client, connected where cloudflared would deliver the traffic. It
	// checks the exit node's own certificate, as Cloudflare's edge would.
	cc, cs, err := ImportBlob(res.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if cc.Transport.Kind != config.TransportCloudflare || cc.Transport.Port != 443 {
		t.Fatalf("client should see a plain Cloudflare exit node: %+v", cc.Transport)
	}
	cc.Transport.Endpoint, cc.Transport.Port = "127.0.0.1", localPort
	cc.Transport.RemoteUDPPort = wgPort
	c := startUserspaceClient(t, ctx, cc, cs, wst)
	defer c.close()
	if _, err := c.fetchUntil(sc.Health.IPCheckURL, 45*time.Second); err != nil {
		t.Fatalf("HTTPS through the exit node's tunnel port: %v", err)
	}
}
