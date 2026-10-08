package config

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func key(t *testing.T) string {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.String()
}

func validConnect(t *testing.T) (*Config, *Secrets) {
	c := Default()
	c.Peer.PublicKey = key(t)
	c.Transport.Endpoint = "myhome.duckdns.org"
	c.Transport.TLSSHA256 = strings.TrimSuffix(strings.Repeat("AB:", 32), ":")
	return c, &Secrets{PrivateKey: key(t), PresharedKey: key(t)}
}

func TestDefaultConnectValid(t *testing.T) {
	c, s := validConnect(t)
	if err := Validate(c, s); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCatchesProblems(t *testing.T) {
	cases := map[string]func(c *Config, s *Secrets){
		"mode":            func(c *Config, _ *Secrets) { c.Mode = "bogus" },
		"engine":          func(c *Config, _ *Secrets) { c.WireGuard.Engine = "kernel" },
		"self_ip outside": func(c *Config, _ *Secrets) { c.WireGuard.SelfIP = "10.8.0.2/32" },
		"subnet family":   func(c *Config, _ *Secrets) { c.WireGuard.Subnet6 = "10.0.0.0/8" },
		"bad peer key":    func(c *Config, _ *Secrets) { c.Peer.PublicKey = "nope" },
		"bad priv key":    func(_ *Config, s *Secrets) { s.PrivateKey = "AAAA" },
		"no endpoint":     func(c *Config, _ *Secrets) { c.Transport.Endpoint = "" },
		"bad fingerprint": func(c *Config, _ *Secrets) { c.Transport.TLSSHA256 = "ab:cd" },
		"port":            func(c *Config, _ *Secrets) { c.Transport.Port = 70000 },
		"dns":             func(c *Config, _ *Secrets) { c.Client.DNS = "not-an-ip" },
		"rendezvous":      func(c *Config, _ *Secrets) { c.Reachability.Mode = ReachRendezvous },
		"relay no host":   func(c *Config, _ *Secrets) { c.Reachability.Mode = ReachRelay },
		"ddns no token":   func(c *Config, _ *Secrets) { c.DDNS.Provider = "duckdns"; c.DDNS.Domain = "x.duckdns.org" },
		"backoff":         func(c *Config, _ *Secrets) { c.Health.BackoffMax = D(0) },
		"path prefix":     func(c *Config, _ *Secrets) { c.Transport.PathPrefix = "a/b" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c, s := validConnect(t)
			mutate(c, s)
			if err := Validate(c, s); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestServeNeedsAllowedIPs(t *testing.T) {
	c, s := validConnect(t)
	c.Mode = ModeServe
	if err := Validate(c, s); err == nil || !strings.Contains(err.Error(), "allowed_ips") {
		t.Fatalf("want allowed_ips error, got %v", err)
	}
	c.Peer.AllowedIPs = []string{"10.9.0.2/32"}
	if err := Validate(c, s); err != nil {
		t.Fatal(err)
	}
}

func TestSaveLoadRoundTripAndPerms(t *testing.T) {
	p := Paths{Dir: t.TempDir()}
	c, s := validConnect(t)
	c.Client.KillSwitch = false
	if err := Save(p, c, s); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p.Secrets())
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("secrets perms %o", st.Mode().Perm())
		}
	}
	c2, s2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Peer.PublicKey != c.Peer.PublicKey || s2.PrivateKey != s.PrivateKey || c2.Client.KillSwitch {
		t.Fatal("round trip mismatch")
	}
	if c2.Health.Interval != c.Health.Interval {
		t.Fatal("durations did not round trip")
	}
	// Secrets never stringify.
	if strings.Contains(s2.String(), s.PrivateKey) {
		t.Fatal("secrets leaked via String()")
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	p := Paths{Dir: t.TempDir()}
	c, s := validConnect(t)
	if err := Save(p, c, s); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(p.Config(), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("\n[typo]\nkillswich = true\n")
	f.Close()
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("want unknown keys error, got %v", err)
	}
}

func TestLoadRejectsLoosePerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions only")
	}
	p := Paths{Dir: t.TempDir()}
	c, s := validConnect(t)
	if err := Save(p, c, s); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p.Secrets(), 0o644)
	if _, _, err := Load(p); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("want perms error, got %v", err)
	}
}

func TestIfaceAddrs(t *testing.T) {
	c := Default()
	a4, err := c.IfaceAddr4()
	if err != nil || a4.String() != "10.9.0.2/24" {
		t.Fatalf("got %v %v", a4, err)
	}
	a6, ok, err := c.IfaceAddr6()
	if err != nil || !ok || a6.String() != "fd09:b4c0::2/64" {
		t.Fatalf("got %v %v %v", a6, ok, err)
	}
	c.Client.DNS = "10.9.0.1, fd09:b4c0::1"
	d, err := c.DNSServers()
	if err != nil || len(d) != 2 {
		t.Fatalf("got %v %v", d, err)
	}
}
