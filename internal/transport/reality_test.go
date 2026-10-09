package transport

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"backhaul/internal/keys"
)

func realityPair(t *testing.T, serverPort int, remoteUDP, localUDP string) (srv, cli RealityOptions) {
	t.Helper()
	kp, _ := keys.NewRealityPair()
	uuid, _ := keys.NewUUID()
	sid, _ := keys.NewShortID()
	dir := t.TempDir()
	common := RealityOptions{UUID: uuid, ShortID: sid, ServerName: "www.amazon.com", Target: "www.amazon.com:443",
		ReadyTimeout: 15 * time.Second, BackoffMin: 200 * time.Millisecond, BackoffMax: 2 * time.Second}
	srv, cli = common, common
	srv.Role, srv.ListenAddr, srv.Port, srv.PrivateKey = RoleServer, "127.0.0.1", serverPort, kp.Private
	srv.ConfigPath = filepath.Join(dir, "server.json")
	cli.Role, cli.ServerAddr, cli.ServerPort, cli.PublicKey = RoleClient, "127.0.0.1", serverPort, kp.Public
	cli.Fingerprint, cli.LocalUDP, cli.RemoteUDP = "chrome", localUDP, remoteUDP
	cli.ConfigPath = filepath.Join(dir, "client.json")
	return srv, cli
}

func TestRealityConfigShape(t *testing.T) {
	srv, cli := realityPair(t, 443, "127.0.0.1:51820", "127.0.0.1:51821")
	var s, c map[string]any
	sb, err := srv.Config()
	if err != nil {
		t.Fatal(err)
	}
	cb, err := cli.Config()
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(sb, &s)
	json.Unmarshal(cb, &c)
	in := s["inbounds"].([]any)[0].(map[string]any)
	rs := in["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	if in["protocol"] != "vless" || rs["privateKey"] != srv.PrivateKey || rs["target"] != "www.amazon.com:443" {
		t.Fatalf("server config: %s", sb)
	}
	cin := c["inbounds"].([]any)[0].(map[string]any)
	cs := cin["settings"].(map[string]any)
	if cin["protocol"] != "dokodemo-door" || cs["port"] != float64(51820) || cs["network"] != "udp" || cin["port"] != float64(51821) {
		t.Fatalf("client config: %s", cb)
	}
	if strings.Contains(string(cb), srv.PrivateKey) {
		t.Fatal("client config must never contain the server's private key")
	}
}

func xrayBinary(t *testing.T) string {
	if p := os.Getenv("BACKHAUL_TEST_XRAY"); p != "" {
		return p
	}
	if p, err := exec.LookPath("xray"); err == nil {
		return p
	}
	t.Skip("xray not available (set BACKHAUL_TEST_XRAY)")
	return ""
}

// Xray's own config checker accepts what we generate.
func TestRealityConfigsAcceptedByXray(t *testing.T) {
	bin := xrayBinary(t)
	srv, cli := realityPair(t, 443, "127.0.0.1:51820", "127.0.0.1:51821")
	for _, o := range []RealityOptions{srv, cli} {
		if _, err := NewReality(o); err != nil { // writes the config file
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "run", "-test", "-c", o.ConfigPath).CombinedOutput()
		if err != nil {
			t.Fatalf("xray rejected the %s config: %v\n%s", o.Role, err, out)
		}
		if st, _ := os.Stat(o.ConfigPath); st != nil && st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
			t.Fatalf("config with secrets is %o, want 0600", st.Mode().Perm())
		}
	}
}

// End to end: UDP through VLESS+REALITY and back. Needs internet (REALITY
// relays its handshake via the target site). Runs in CI on Linux; on Windows
// hosts whose Winsock LSPs break socket deadlines REALITY's server stalls, so
// it is opt-in there.
func TestRealityEndToEndUDP(t *testing.T) {
	bin := xrayBinary(t)
	if os.Getenv("BACKHAUL_TEST_REALITY_E2E") == "" {
		t.Skip("set BACKHAUL_TEST_REALITY_E2E=1 (needs internet)")
	}
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
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	lp, _ := net.ListenPacket("udp", "127.0.0.1:0")
	local := lp.LocalAddr().String()
	lp.Close()

	srv, cli := realityPair(t, port, echo.LocalAddr().String(), local)
	srv.Binary, cli.Binary = bin, bin
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s, err := NewReality(srv)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	c, err := NewReality(cli)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	conn, _ := net.Dial("udp", local)
	defer conn.Close()
	buf := make([]byte, 64)
	for i := 0; i < 30; i++ {
		msg := "wg-" + strconv.Itoa(i)
		conn.Write([]byte(msg))
		conn.SetReadDeadline(time.Now().Add(time.Second))
		if n, err := conn.Read(buf); err == nil && string(buf[:n]) == msg {
			return
		}
	}
	t.Fatalf("no echo through VLESS+REALITY (server: %+v, client: %+v)", s.Status(), c.Status())
}

func TestXrayLogLineClassification(t *testing.T) {
	for line, want := range map[string]bool{
		"2026/10/09 06:30:12 [Info] transport/internet/tcp: REALITY: processed invalid connection from 1.2.3.4:56183: authentication failed": true,
		"2026/10/09 06:31:54 [Info] [123] app/proxyman/outbound: failed to process outbound traffic > dial tcp: i/o timeout":                 true,
		"2026/10/09 06:29:55 [Warning] core: Xray 26.3.27 started":                                                                           false,
		"2026/10/09 06:31:54 [Info] [123] proxy/vless/outbound: tunneling request to udp:127.0.0.1:51820":                                    false,
	} {
		if got := xrayProbeRE.MatchString(line) || strings.Contains(strings.ToLower(line), "failed"); got != want && !xrayReadyRE.MatchString(line) {
			t.Errorf("%q: surfaced=%v want %v", line, got, want)
		}
	}
	if m := xrayProbeRE.FindStringSubmatch("REALITY: processed invalid connection from 1.2.3.4:56183: x"); m == nil || m[1] != "1.2.3.4:56183" {
		t.Fatalf("probe source not extracted: %v", m)
	}
}

func TestXrayAcceptRE(t *testing.T) {
	m := xrayAcceptRE.FindStringSubmatch("2026/10/09 06:31:54.451461 from 203.0.113.7:51334 accepted udp:127.0.0.1:51820 [direct]")
	if m == nil || m[1] != "203.0.113.7:51334" {
		t.Fatalf("got %v", m)
	}
}

func TestXrayCutRE(t *testing.T) {
	cut := "2026/10/09 08:18:48 [Info] [2482068391] app/proxyman/outbound: failed to process outbound traffic > proxy/vless/outbound: connection ends > proxy/vless/outbound: failed to transfer request payload > write tcp 192.168.100.71:52034->50.46.184.113:443: wsasend: An existing connection was forcibly closed by the remote host."
	if !xrayCutRE.MatchString(cut) {
		t.Fatal("the real cut message from the user's log must trigger a restart")
	}
	if xrayCutRE.MatchString("2026/10/09 08:19:48 [Info] proxy/vless/outbound: tunneling request to udp:127.0.0.1:51820 via 50.46.184.113:443") {
		t.Fatal("normal traffic must not trigger a restart")
	}
}
