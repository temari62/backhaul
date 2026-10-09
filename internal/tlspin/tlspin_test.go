package tlspin

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tlsEcho starts a TLS echo server using a freshly generated self-signed cert.
func tlsEcho(t *testing.T) (addr, fingerprint string) {
	t.Helper()
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	fp, err := GenerateSelfSigned("exit.example", cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if ffp, _ := FileFingerprint(cert); ffp != fp {
		t.Fatalf("file fingerprint %s != %s", ffp, fp)
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { go ln.Close() }) // async: some Windows LSPs block Close during Accept
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String(), fp
}

func TestFingerprintFormat(t *testing.T) {
	fp := Fingerprint([]byte("x"))
	if len(fp) != 95 || strings.ToUpper(fp) != fp {
		t.Fatalf("bad format %q", fp)
	}
	if Normalize(strings.ToLower(strings.ReplaceAll(fp, ":", ""))) != fp {
		t.Fatal("normalize failed")
	}
}

func TestPinAcceptsMatchAndRejectsMismatch(t *testing.T) {
	addr, fp := tlsEcho(t)
	d := tls.Dialer{Config: Config("exit.example", strings.ToLower(fp))}
	c, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("matching pin rejected: %v", err)
	}
	c.Close()

	wrong := strings.TrimSuffix(strings.Repeat("00:", 32), ":")
	d = tls.Dialer{Config: Config("exit.example", wrong)}
	if _, err := d.DialContext(context.Background(), "tcp", addr); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("wrong pin accepted: %v", err)
	}
	got, err := Probe(context.Background(), addr, "exit.example")
	if err != nil || got != fp {
		t.Fatalf("probe got %s %v", got, err)
	}
}

func TestProxyPinsAndForwards(t *testing.T) {
	addr, fp := tlsEcho(t)
	p, err := NewProxy(func() string { return addr }, "exit.example", fp, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Serve(ctx)
	c, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo through proxy: %q %v", buf, err)
	}

	// Wrong pin: the proxy must refuse to forward and report ErrMismatch.
	bad, _ := NewProxy(func() string { return addr }, "exit.example", strings.TrimSuffix(strings.Repeat("11:", 32), ":"), 5*time.Second)
	go bad.Serve(ctx)
	c2, _ := net.Dial("tcp", bad.Addr())
	c2.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected closed connection")
	}
	c2.Close()
	if !errors.Is(bad.LastError(), ErrMismatch) {
		t.Fatalf("LastError = %v", bad.LastError())
	}
}

func TestProxyDownReflectsUpstream(t *testing.T) {
	addr, fp := tlsEcho(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, _ := NewProxy(func() string { return addr }, "exit.example", fp, 2*time.Second)
	go p.Serve(ctx)
	if p.Down() {
		t.Fatal("fresh proxy must not report down")
	}
	c, _ := net.Dial("tcp", p.Addr())
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("x"))
	io.ReadFull(c, make([]byte, 1))
	if p.Down() {
		t.Fatal("down while an upstream connection is open")
	}
	c.Close()

	// Unreachable exit node: refused dial, nothing open → down.
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	q, _ := NewProxy(func() string { return deadAddr }, "exit.example", fp, time.Second)
	go q.Serve(ctx)
	c2, _ := net.Dial("tcp", q.Addr())
	c2.SetDeadline(time.Now().Add(5 * time.Second))
	c2.Read(make([]byte, 1)) // proxy closes us after the failed dial
	c2.Close()
	deadline := time.Now().Add(3 * time.Second)
	for !q.Down() {
		if time.Now().After(deadline) {
			t.Fatal("proxy with an unreachable exit node not reported down")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
