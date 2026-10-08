package pairing

import (
	"fmt"
	"io"
	"strings"

	"rsc.io/qr"
)

// qrQuiet is the white border (in modules) scanners need around the code.
const qrQuiet = 2

// WriteQR renders s as a terminal QR code: two modules per character row
// using half blocks, drawn black-on-white with explicit ANSI colours so it
// scans on both dark and light terminal themes.
func WriteQR(w io.Writer, s string) error {
	code, err := qr.Encode(s, qr.L)
	if err != nil {
		return fmt.Errorf("pairing blob too large for a QR code: %w", err)
	}
	black := func(x, y int) bool {
		return x >= 0 && y >= 0 && x < code.Size && y < code.Size && code.Black(x, y)
	}
	const on, off = "\x1b[30;47m", "\x1b[0m" // black fg on white bg
	var b strings.Builder
	for y := -qrQuiet; y < code.Size+qrQuiet; y += 2 {
		b.WriteString(on)
		for x := -qrQuiet; x < code.Size+qrQuiet; x++ {
			switch top, bot := black(x, y), black(x, y+1); {
			case top && bot:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bot:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString(off + "\n")
	}
	_, err = io.WriteString(w, b.String())
	return err
}
