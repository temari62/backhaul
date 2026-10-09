package keys

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// RealityPair is an X25519 key pair in Xray's encoding (unpadded base64url).
type RealityPair struct {
	Private string // exit node only (secrets.toml)
	Public  string // goes to the client in the pairing code
}

// NewRealityPair generates the exit node's REALITY key pair.
func NewRealityPair() (RealityPair, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return RealityPair{}, err
	}
	enc := base64.RawURLEncoding
	return RealityPair{Private: enc.EncodeToString(k.Bytes()), Public: enc.EncodeToString(k.PublicKey().Bytes())}, nil
}

// RealityPublicFromPrivate derives the public key (as `xray x25519 -i` does).
func RealityPublicFromPrivate(priv string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(priv)
	if err != nil {
		return "", err
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// NewUUID returns a random RFC 4122 version-4 UUID (the VLESS user id).
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// NewShortID returns a random REALITY short id (8 hex chars).
func NewShortID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
