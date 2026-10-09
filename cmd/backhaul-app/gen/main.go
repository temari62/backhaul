// Command gen prepares the Windows app's embedded assets: it downloads the
// pinned wstunnel and Wintun releases (verifying their SHA-256) into
// cmd/backhaul-app/bundle, and draws the app icon into cmd/backhaul-app/winres.
//
//	go run ./cmd/backhaul-app/gen
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"path/filepath"
	"time"

	"backhaul/internal/config"
	"backhaul/internal/fetch"
	"backhaul/internal/transport"
	"backhaul/internal/wg"
)

func main() {
	dir := flag.String("dir", "cmd/backhaul-app", "app directory")
	arch := flag.String("arch", "amd64", "windows architecture to bundle")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

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

	// icon
	res := filepath.Join(*dir, "winres")
	must(os.MkdirAll(res, 0o755))
	must(os.WriteFile(filepath.Join(res, "icon.png"), drawIcon(256), 0o644))
	must(os.WriteFile(filepath.Join(res, "icon16.png"), drawIcon(16), 0o644))
	log.Printf("assets ready in %s and %s", bundle, res)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// drawIcon renders the logo: an indigo→cyan rounded square with two white
// "tunnel" arcs and a dot, anti-aliased by 4x4 supersampling.
func drawIcon(size int) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	s := float64(size)
	a := color.NRGBA{0x4f, 0x46, 0xe5, 0xff}
	b := color.NRGBA{0x06, 0xb6, 0xd4, 0xff}
	radius := s * 0.22
	cx, cy := s/2, s*0.70
	inside := func(x, y float64) (bg, fg bool) {
		// rounded square
		dx := math.Max(math.Max(radius-x, x-(s-radius)), 0)
		dy := math.Max(math.Max(radius-y, y-(s-radius)), 0)
		if dx*dx+dy*dy > radius*radius {
			return false, false
		}
		d := math.Hypot(x-cx, y-cy)
		stroke := s * 0.075
		above := y <= cy
		arc := func(r float64) bool { return above && math.Abs(d-r) <= stroke/2 }
		return true, arc(s*0.34) || arc(s*0.19) || d <= s*0.055
	}
	const ss = 4
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var nbg, nfg int
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					bg, fg := inside(float64(px)+(float64(sx)+.5)/ss, float64(py)+(float64(sy)+.5)/ss)
					if bg {
						nbg++
					}
					if fg {
						nfg++
					}
				}
			}
			if nbg == 0 {
				continue
			}
			t := (float64(px) + float64(py)) / (2 * s)
			mix := func(u, v uint8) float64 { return float64(u) + (float64(v)-float64(u))*t }
			f := float64(nfg) / float64(nbg)
			r := mix(a.R, b.R)*(1-f) + 255*f
			g := mix(a.G, b.G)*(1-f) + 255*f
			bl := mix(a.B, b.B)*(1-f) + 255*f
			img.SetNRGBA(px, py, color.NRGBA{uint8(r), uint8(g), uint8(bl), uint8(255 * nbg / (ss * ss))})
		}
	}
	var buf bytes.Buffer
	must(png.Encode(&buf, img))
	return buf.Bytes()
}
