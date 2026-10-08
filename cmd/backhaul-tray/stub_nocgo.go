//go:build darwin && !cgo

// The macOS tray backend uses Cocoa via cgo; this stub keeps cgo-less
// cross-builds (CGO_ENABLED=0 GOOS=darwin) of ./... working.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "backhaul-tray for macOS must be built on a Mac with CGO_ENABLED=1 (go build ./cmd/backhaul-tray)")
	os.Exit(1)
}
