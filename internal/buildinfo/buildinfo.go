// Package buildinfo carries values stamped into the binary at build time.
package buildinfo

// Version is the application version, e.g. "0.4.0". It is set at build time
// with -ldflags "-X backhaul/internal/buildinfo.Version=<v>" (see build-app.ps1
// and build-installer.ps1, which read the repo-root VERSION file). Unstamped
// builds (go build, go test, go run) report "dev".
var Version = "dev"

// IsDev reports whether this is an unstamped development build.
func IsDev() bool { return Version == "dev" || Version == "" }
