// Package tlspin generates the self-signed wstunnel certificate, computes its
// SHA-256 fingerprint, and dials TLS with that fingerprint pinned.
package tlspin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CertValidity is how long the generated self-signed cert is valid.
// Pinning (not expiry) is what protects us, so make it long-lived.
const CertValidity = 10 * 365 * 24 * time.Hour

// Fingerprint formats SHA-256(der) as "AB:CD:...".
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// Normalize uppercases a fingerprint and accepts forms with or without colons.
func Normalize(fp string) string {
	fp = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(fp), ":", ""))
	if len(fp) != 64 {
		return fp
	}
	parts := make([]string, 32)
	for i := range parts {
		parts[i] = fp[2*i : 2*i+2]
	}
	return strings.Join(parts, ":")
}

// GenerateSelfSigned writes an ECDSA P-256 cert/key for hostname to certPath
// and keyPath (key 0600) and returns the cert fingerprint.
func GenerateSelfSigned(hostname, certPath, keyPath string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", err
	}
	if hostname == "" {
		hostname = "localhost"
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostname},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(CertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{hostname}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", err
	}
	return Fingerprint(der), nil
}

// FileFingerprint returns the fingerprint of the first cert in a PEM file.
func FileFingerprint(certPath string) (string, error) {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return "", fmt.Errorf("%s: no PEM certificate", certPath)
	}
	return Fingerprint(blk.Bytes), nil
}

// ErrMismatch means the server presented a certificate we did not pin.
var ErrMismatch = errors.New("TLS fingerprint mismatch — possible MITM or the exit node's cert changed")

// Config returns a tls.Config that accepts exactly the pinned leaf cert.
// Chain/hostname verification is replaced by the pin since the cert is self-signed.
func Config(serverName, pinned string) *tls.Config {
	want := Normalize(pinned)
	return &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by VerifyPeerCertificate below
		NextProtos:         []string{"http/1.1"},
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return ErrMismatch
			}
			if got := Fingerprint(raw[0]); got != want {
				return fmt.Errorf("%w (got %s, pinned %s)", ErrMismatch, got, want)
			}
			return nil
		},
	}
}

// Probe connects to addr and returns the presented leaf fingerprint without
// enforcing a pin (used by doctor to report what the server sends).
func Probe(ctx context.Context, addr, serverName string) (string, error) {
	d := tls.Dialer{Config: &tls.Config{ServerName: serverName, InsecureSkipVerify: true}}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	st := c.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return "", errors.New("no peer certificate")
	}
	return Fingerprint(st.PeerCertificates[0].Raw), nil
}
