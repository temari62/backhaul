// Package keys generates WireGuard keypairs and preshared keys using wgctrl's
// audited Curve25519 helpers.
package keys

import (
	"encoding/hex"
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Pair is a WireGuard keypair in base64 form.
type Pair struct {
	Private string
	Public  string
}

// NewPair generates a fresh WireGuard keypair.
func NewPair() (Pair, error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Pair{}, fmt.Errorf("generate private key: %w", err)
	}
	return Pair{Private: k.String(), Public: k.PublicKey().String()}, nil
}

// NewPresharedKey generates a random 32-byte preshared key (base64).
func NewPresharedKey() (string, error) {
	k, err := wgtypes.GenerateKey()
	if err != nil {
		return "", fmt.Errorf("generate preshared key: %w", err)
	}
	return k.String(), nil
}

// PublicFromPrivate derives the public key from a base64 private key.
func PublicFromPrivate(priv string) (string, error) {
	k, err := wgtypes.ParseKey(priv)
	if err != nil {
		return "", err
	}
	return k.PublicKey().String(), nil
}

// Hex converts a base64 key into the lowercase hex form used by the
// WireGuard UAPI protocol.
func Hex(b64 string) (string, error) {
	k, err := wgtypes.ParseKey(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(k[:]), nil
}

// Redact shortens a key for logs: public keys are fine to show partially;
// call this for anything that might be secret too.
func Redact(k string) string {
	if len(k) < 8 {
		return "[REDACTED]"
	}
	return k[:4] + "…[REDACTED]"
}
