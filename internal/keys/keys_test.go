package keys

import (
	"encoding/base64"
	"testing"
)

func TestNewPair(t *testing.T) {
	a, err := NewPair()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewPair()
	if a.Private == b.Private || a.Public == b.Public {
		t.Fatal("keys not random")
	}
	pub, err := PublicFromPrivate(a.Private)
	if err != nil || pub != a.Public {
		t.Fatalf("derived %q want %q (%v)", pub, a.Public, err)
	}
	raw, _ := base64.StdEncoding.DecodeString(a.Private)
	if len(raw) != 32 || raw[0]&7 != 0 || raw[31]&0x80 != 0 || raw[31]&0x40 == 0 {
		t.Fatal("private key not clamped Curve25519 scalar")
	}
}

func TestPSKAndHex(t *testing.T) {
	psk, err := NewPresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	h, err := Hex(psk)
	if err != nil || len(h) != 64 {
		t.Fatalf("hex %q %v", h, err)
	}
	if _, err := Hex("garbage"); err == nil {
		t.Fatal("expected error")
	}
	if Redact(psk) == psk {
		t.Fatal("redact returned the key")
	}
}
