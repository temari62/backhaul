// Command gen prepares the Windows app's embedded assets: it downloads the
// pinned wstunnel and Wintun releases (verifying their SHA-256) into
// cmd/backhaul-app/bundle, and draws the app icon into cmd/backhaul-app/winres.
//
//	go run ./cmd/backhaul-app/gen
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"backhaul/internal/config"
	"backhaul/internal/fetch"
	"backhaul/internal/logo"
	"backhaul/internal/transport"
	"backhaul/internal/wg"
)

func main() {
	dir := flag.String("dir", "cmd/backhaul-app", "app directory")
	arch := flag.String("arch", "amd64", "windows architecture to bundle")
	iconOnly := flag.Bool("icon-only", false, "only (re)draw the icon; skip the component downloads")
	size := flag.Int("size", 0, "with -icon-only and -out: render a single PNG at this pixel size")
	out := flag.String("out", "", "with -icon-only and -size: write the single PNG here (e.g. a .icns master)")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if *iconOnly {
		if *out != "" && *size > 0 {
			must(os.WriteFile(*out, drawIcon(*size), 0o644))
			log.Printf("icon %dpx written to %s", *size, *out)
			return
		}
		drawIcons(*dir)
		return
	}

	bundle := filepath.Join(*dir, "bundle")
	must(os.MkdirAll(bundle, 0o755))

	// wstunnel
	v := config.DefaultWstunnelVersion
	plat := "windows_" + *arch
	sum := transport.PinnedWstunnelSHA256(v, plat)
	if sum == "" {
		log.Fatalf("no pinned wstunnel checksum for %s %s", v, plat)
	}
	url := fmt.Sprintf("https://github.com/erebe/wstunnel/releases/download/v%s/wstunnel_%s_%s.tar.gz", v, v, plat)
	log.Printf("wstunnel %s (%s)", v, plat)
	archive, err := fetch.Verified(ctx, url, sum)
	must(err)
	exe, err := fetch.FromTarGz(archive, "wstunnel.exe")
	must(err)
	must(os.WriteFile(filepath.Join(bundle, "wstunnel.exe"), exe, 0o644))

	// wintun
	wintunArch := map[string]string{"amd64": "amd64", "arm64": "arm64", "386": "x86"}[*arch]
	log.Printf("wintun (%s)", wintunArch)
	zip, err := fetch.Verified(ctx, wg.WintunURL, wg.WintunSHA256)
	must(err)
	dll, err := fetch.FromZip(zip, "wintun/bin/"+wintunArch+"/wintun.dll")
	must(err)
	must(os.WriteFile(filepath.Join(bundle, "wintun.dll"), dll, 0o644))

	// xray (REALITY transport)
	xurl, xsum, err := transport.XrayRelease(config.DefaultXrayVersion, plat)
	must(err)
	log.Printf("xray %s (%s)", config.DefaultXrayVersion, plat)
	xzip, err := fetch.Verified(ctx, xurl, xsum)
	must(err)
	xexe, err := fetch.FromZip(xzip, "xray.exe")
	must(err)
	must(os.WriteFile(filepath.Join(bundle, "xray.exe"), xexe, 0o644))

	// vcruntime140.dll: wstunnel (an MSVC build) needs it, and Windows doesn't
	// ship it — only the Visual C++ Redistributable does. Microsoft allows
	// app-local copies; take the build machine's (x64 Windows, current VC++).
	sysDir := os.Getenv("SystemRoot")
	if *arch != "amd64" || sysDir == "" {
		log.Fatalf("vcruntime140.dll: build the bundle on 64-bit Windows for -arch amd64")
	}
	vc, err := os.ReadFile(filepath.Join(sysDir, "System32", "vcruntime140.dll"))
	if err != nil {
		log.Fatalf("vcruntime140.dll: %v (install the Visual C++ Redistributable x64 on the build machine)", err)
	}
	must(os.WriteFile(filepath.Join(bundle, "vcruntime140.dll"), vc, 0o644))

	// icon
	drawIcons(*dir)
	log.Printf("assets ready in %s", bundle)
}

// drawIcons writes the app icon PNGs that go-winres embeds into the exe.
func drawIcons(appDir string) {
	res := filepath.Join(appDir, "winres")
	must(os.MkdirAll(res, 0o755))
	must(os.WriteFile(filepath.Join(res, "icon.png"), drawIcon(256), 0o644))
	must(os.WriteFile(filepath.Join(res, "icon16.png"), drawIcon(16), 0o644))
	log.Printf("icon drawn in %s", res)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// drawIcon renders the logo (internal/logo, shared with the tray icons).
func drawIcon(size int) []byte { return logo.PNG(size) }
