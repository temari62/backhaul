//go:build !linux || !cgo || !gtk

// The Linux app needs WebKitGTK via cgo, behind the "gtk" build tag so that a
// plain `go build ./...` needs no GTK headers. This stub keeps `go build
// ./...` and `go vet ./...` working everywhere else, and says what happened
// if such a build is run by mistake.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "backhaul-app: this binary was built without the GUI; build it with build-app-linux.sh (Linux, cgo, -tags gtk)")
	os.Exit(1)
}
