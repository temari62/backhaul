package keys

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestRealityKeysAndIDs(t *testing.T) {
	p, err := NewRealityPair()
	if err != nil || len(p.Private) != 43 || len(p.Public) != 43 {
		t.Fatalf("%+v %v", p, err)
	}
	if pub, _ := RealityPublicFromPrivate(p.Private); pub != p.Public {
		t.Fatal("public key derivation mismatch")
	}
	u, _ := NewUUID()
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(u) {
		t.Fatalf("bad uuid %s", u)
	}
	if s, _ := NewShortID(); !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(s) {
		t.Fatalf("bad short id %s", s)
	}
}

// Cross-check our key encoding against Xray itself.
func TestRealityKeysMatchXray(t *testing.T) {
	bin := os.Getenv("BACKHAUL_TEST_XRAY")
	if bin == "" {
		t.Skip("set BACKHAUL_TEST_XRAY to an xray binary")
	}
	p, _ := NewRealityPair()
	out, err := exec.Command(bin, "x25519", "-i", p.Private).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(string(out), p.Public) {
		t.Fatalf("xray derives a different public key:\n%s\nours: %s", out, p.Public)
	}
}
