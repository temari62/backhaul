package pairing

import (
	"bytes"
	"strings"
	"testing"

	"rsc.io/qr"
)

func TestRealBlobFitsInQR(t *testing.T) {
	b := blob(t)
	b.Endpoint = strings.Repeat("x", 60) + ".duckdns.org" // generous hostname
	s, err := Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := WriteQR(&out, s); err != nil {
		t.Fatalf("blob of %d bytes: %v", len(s), err)
	}
	code, _ := qr.Encode(s, qr.L)
	rows := strings.Count(out.String(), "\n")
	if want := (code.Size + 2*qrQuiet + 1) / 2; rows != want {
		t.Fatalf("rows %d want %d", rows, want)
	}
	t.Logf("blob %d bytes → QR %d modules (%d terminal columns)", len(s), code.Size, code.Size+2*qrQuiet)
}
