package doctor

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"backhaul/internal/config"
	"backhaul/internal/keys"
	"backhaul/internal/tlspin"
	"backhaul/internal/transport"
)

// An exit node that was set up again (new certificate) must be rejected by a
// client still holding the old pairing — with a TLS fingerprint failure.
func TestStalePairingFailsPinCheck(t *testing.T) {
	dir := t.TempDir()
	oldFP, err := tlspin.GenerateSelfSigned("127.0.0.1", filepath.Join(dir, "old.pem"), filepath.Join(dir, "old.key"))
	if err != nil {
		t.Fatal(err)
	}
	newCert, newKey := filepath.Join(dir, "new.pem"), filepath.Join(dir, "new.key")
	newFP, err := tlspin.GenerateSelfSigned("127.0.0.1", newCert, newKey)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(newCert, newKey)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { go ln.Close() }() // async: some Windows LSPs block Close during Accept
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()

	check := func(pin string) Result {
		c := config.Default()
		c.Transport.Endpoint = "127.0.0.1"
		c.Transport.Port = ln.Addr().(*net.TCPAddr).Port
		c.Transport.TLSSHA256 = pin
		d := &Doctor{Cfg: c, Paths: config.Paths{Dir: dir}}
		for _, r := range d.Preflight(context.Background()) {
			if r.Name == CheckTLSPin {
				return r
			}
		}
		t.Fatal("no TLS check ran (port " + strconv.Itoa(c.Transport.Port) + ")")
		return Result{}
	}
	if r := check(oldFP); r.Status != Fail {
		t.Fatalf("stale pairing accepted: %+v", r)
	}
	if r := check(newFP); r.Status != Pass {
		t.Fatalf("current pairing rejected: %+v", r)
	}
}

func TestRealityCamouflageAgainstRealXray(t *testing.T) {
	bin := os.Getenv("BACKHAUL_TEST_XRAY")
	if bin == "" {
		t.Skip("set BACKHAUL_TEST_XRAY (needs internet: REALITY relays probes to the real site)")
	}
	kp, _ := keys.NewRealityPair()
	uuid, _ := keys.NewUUID()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	dir := t.TempDir()
	srv, err := transport.NewReality(transport.RealityOptions{Binary: bin, Role: transport.RoleServer,
		ConfigPath: filepath.Join(dir, "xray.json"), ListenAddr: "127.0.0.1", Port: port, PrivateKey: kp.Private,
		UUID: uuid, ShortID: "a1b2c3d4", ServerName: "www.amazon.com", Target: "www.amazon.com:443",
		ReadyTimeout: 15 * time.Second, BackoffMin: time.Second, BackoffMax: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	c := config.Default()
	c.Transport.Kind = config.TransportReality
	d := &Doctor{Cfg: c, Paths: config.Paths{Dir: dir}}
	if r := d.realityCamouflage(ctx, "127.0.0.1:"+strconv.Itoa(port)); r.Status != Pass {
		t.Fatalf("real REALITY exit node not recognised: %+v", r)
	}
	// An impostor with its own certificate must fail.
	cert, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	tlspin.GenerateSelfSigned("www.amazon.com", cert, key)
	pair, _ := tls.LoadX509KeyPair(cert, key)
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	defer func() { go ln.Close() }()
	go func() {
		for {
			cc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { cc.(*tls.Conn).Handshake(); cc.Close() }()
		}
	}()
	if r := d.realityCamouflage(ctx, ln.Addr().String()); r.Status != Fail {
		t.Fatalf("self-signed impostor accepted: %+v", r)
	}
}
