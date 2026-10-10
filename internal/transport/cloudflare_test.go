package transport

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"

	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"backhaul/internal/tlspin"
)

// testCA issues a leaf certificate for host signed by a fresh CA, standing in
// for Cloudflare's publicly trusted edge certificate.
func testCA(t *testing.T, host string) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Edge CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

// TestCloudflareStyleFrontingEndToEnd: client → pinned-less TLS proxy (CA
// verification) → fake Cloudflare edge (routes by Host, re-originates HTTPS
// to the origin accepting its self-signed cert, like SSL mode "Full") →
// wstunnel server on the exit node → UDP echo, and back.
func TestCloudflareStyleFrontingEndToEnd(t *testing.T) {
	bin := wstunnelBinary(t)
	const host = "vpn.example.test"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	echo, _ := net.ListenPacket("udp", "127.0.0.1:0")
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

	// Origin: the exit node's wstunnel server with its self-signed cert.
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if _, err := tlspin.GenerateSelfSigned(host, cert, key); err != nil {
		t.Fatal(err)
	}
	originPort := freePort(t, "tcp")
	common := WstunnelOptions{Binary: bin, PathPrefix: "secretprefix", ReadyTimeout: 15 * time.Second,
		BackoffMin: 200 * time.Millisecond, BackoffMax: 2 * time.Second}
	so := common
	so.Role, so.ListenAddr, so.Port, so.CertFile, so.KeyFile, so.RestrictTo = RoleServer, "127.0.0.1", originPort, cert, key, echo.LocalAddr().String()
	srv := NewWstunnel(so)
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	// Fake Cloudflare edge.
	pool, edgeCert := testCA(t, host)
	originAddr := "127.0.0.1:" + strconv.Itoa(originPort)
	var wrongHost, edgeReqs, edgeUpgrades atomic.Int32
	edgeLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{edgeCert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { go edgeLn.Close() }()
	go func() {
		for {
			cc, err := edgeLn.Accept()
			if err != nil {
				return
			}
			go edgeRelay(cc, originAddr, host, &wrongHost, &edgeReqs, &edgeUpgrades)
		}
	}()

	// Client: verify the edge's certificate for host (no pin), send Host.
	proxy, err := tlspin.NewProxyWithConfig(func() string { return edgeLn.Addr().String() },
		tlspin.VerifiedConfig(host, pool), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	go proxy.Serve(ctx)
	defer proxy.Close()
	local := "127.0.0.1:" + strconv.Itoa(freePort(t, "udp"))
	co := common
	co.Role, co.ServerURL, co.LocalUDP, co.RemoteUDP, co.HostHeader = RoleClient, "ws://"+proxy.Addr(), local, echo.LocalAddr().String(), host
	cli := NewWstunnel(co)
	if err := cli.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer cli.Stop()

	c, _ := net.Dial("udp", local)
	defer func() { go c.Close() }()
	echoed := make(chan string, 8)
	go func() { // reads in a goroutine: socket deadlines don't fire on some Windows LSP hosts
		buf := make([]byte, 64)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			echoed <- string(buf[:n])
		}
	}()
	deadline := time.After(20 * time.Second)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		c.Write([]byte("wg-handshake"))
		select {
		case got := <-echoed:
			if got != "wg-handshake" || wrongHost.Load() != 0 {
				t.Fatalf("got %q, wrong-host requests %d", got, wrongHost.Load())
			}
			return
		case <-tick.C:
		case <-deadline:
			t.Fatalf("no echo through the Cloudflare-style edge (edge requests %d, upgrades %d, client %+v, proxy err %v, wrong-host %d)",
				edgeReqs.Load(), edgeUpgrades.Load(), cli.Status(), proxy.LastError(), wrongHost.Load())
		}
	}
}

// The client must refuse an edge whose certificate isn't valid for the host
// (no silent fallback to "accept anything" when there is no pin).
func TestVerifiedProxyRejectsWrongCertificate(t *testing.T) {
	pool, _ := testCA(t, "vpn.example.test")
	_, other := testCA(t, "evil.example.test")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{other}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { go ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	d := tls.Dialer{Config: tlspin.VerifiedConfig("vpn.example.test", pool)}
	if c, err := d.Dial("tcp", ln.Addr().String()); err == nil {
		c.Close()
		t.Fatal("certificate for another host/CA was accepted")
	}
}

// edgeRelay is a minimal CDN edge: it terminates TLS, routes by Host, opens
// HTTPS to the origin accepting its self-signed certificate (Cloudflare SSL
// mode "Full"), forwards the request, then relays bytes both ways — which is
// what a CDN does for a WebSocket after the upgrade.
func edgeRelay(cc net.Conn, origin, host string, wrongHost, reqs, upgrades *atomic.Int32) {
	defer cc.Close()
	br := bufio.NewReader(cc)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	reqs.Add(1)
	if req.Header.Get("Upgrade") != "" {
		upgrades.Add(1)
	}
	if req.Host != host {
		wrongHost.Add(1)
		io.WriteString(cc, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return
	}
	oc, err := tls.Dial("tcp", origin, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		io.WriteString(cc, "HTTP/1.1 522 Origin Unreachable\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer oc.Close()
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	if err := req.Write(oc); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(oc, br); done <- struct{}{} }() // includes anything already buffered
	go func() { io.Copy(cc, oc); done <- struct{}{} }()
	<-done
}
