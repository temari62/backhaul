// Package logo draws the Backhaul icon — the one picture behind the Windows
// exe icon, the macOS .icns, the Linux launcher icon and the tray icons — so
// they never drift apart. It is rendered, not embedded: a few lines of
// geometry at any size beats a set of PNGs.
package logo

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

var (
	indigo = color.NRGBA{0x4f, 0x46, 0xe5, 0xff}
	cyan   = color.NRGBA{0x06, 0xb6, 0xd4, 0xff}
	white  = color.NRGBA{0xff, 0xff, 0xff, 0xff}
)

// PNG renders the logo at size×size pixels: an indigo→cyan rounded square
// with two white "nodes" (the two paired machines) joined by a link, the
// lower-left node drawn as a ring (your home exit node) and the upper-right
// one solid (this PC).
func PNG(size int) []byte { return encode(Draw(size, nil)) }

// BadgePNG is PNG with a status dot of colour c in the lower-right corner,
// ringed in white so it reads over the gradient — the tray icons.
func BadgePNG(size int, c color.NRGBA) []byte { return encode(Draw(size, &c)) }

// Draw renders the logo, with a status badge if badge is not nil.
// Anti-aliased by 4x4 supersampling.
func Draw(size int, badge *color.NRGBA) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	s := float64(size)
	radius := s * 0.22

	// Two nodes on a diagonal, joined by a link (traffic going out and up).
	ax, ay := s*0.32, s*0.68 // home exit node (lower-left)
	bx, by := s*0.68, s*0.32 // this PC (upper-right)
	node := s * 0.145        // node radius
	link := s * 0.052        // half-thickness of the connecting bar
	// A ring is only legible when its wall is at least ~1px; below that the
	// small icon draws the home node solid too, so it never turns into a blob.
	ringWall := s * 0.052
	ring := ringWall >= 1.1

	// The badge sits in the corner clear of both nodes and the link, and is
	// allowed to overhang the square: it is composited over transparency.
	cx, cy := s*0.76, s*0.76
	badgeR := s * 0.19
	badgeRing := math.Max(s*0.045, 1)

	inside := func(x, y float64) (bg, fg bool) {
		// rounded square
		dx := math.Max(math.Max(radius-x, x-(s-radius)), 0)
		dy := math.Max(math.Max(radius-y, y-(s-radius)), 0)
		if dx*dx+dy*dy > radius*radius {
			return false, false
		}
		bg = true
		// Link first, so it reads as joining the nodes, not crossing them.
		if distToSegment(x, y, ax, ay, bx, by) <= link {
			return bg, true
		}
		if da := math.Hypot(x-ax, y-ay); da <= node {
			if ring {
				return bg, da >= node-ringWall // hollow home node
			}
			return bg, true
		}
		if math.Hypot(x-bx, y-by) <= node {
			return bg, true // solid "this PC" node
		}
		return bg, false
	}
	const ss = 4
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var nbg, nfg, nRing, nDot int
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x, y := float64(px)+(float64(sx)+.5)/ss, float64(py)+(float64(sy)+.5)/ss
					bg, fg := inside(x, y)
					if bg {
						nbg++
					}
					if fg {
						nfg++
					}
					if badge != nil {
						if d := math.Hypot(x-cx, y-cy); d <= badgeR {
							nDot++
						} else if d <= badgeR+badgeRing {
							nRing++
						}
					}
				}
			}
			var p color.NRGBA
			if nbg > 0 {
				t := (float64(px) + float64(py)) / (2 * s)
				mix := func(u, v uint8) float64 { return float64(u) + (float64(v)-float64(u))*t }
				f := float64(nfg) / float64(nbg)
				p = color.NRGBA{
					uint8(mix(indigo.R, cyan.R)*(1-f) + 255*f),
					uint8(mix(indigo.G, cyan.G)*(1-f) + 255*f),
					uint8(mix(indigo.B, cyan.B)*(1-f) + 255*f),
					uint8(255 * nbg / (ss * ss)),
				}
			}
			if nRing > 0 {
				p = over(p, white, float64(nRing)/(ss*ss))
			}
			if nDot > 0 {
				p = over(p, *badge, float64(nDot)/(ss*ss))
			}
			if p.A > 0 {
				img.SetNRGBA(px, py, p)
			}
		}
	}
	return img
}

// over composites src with the given coverage over dst (both non-premultiplied).
func over(dst, src color.NRGBA, cov float64) color.NRGBA {
	sa := float64(src.A) / 255 * cov
	da := float64(dst.A) / 255
	oa := sa + da*(1-sa)
	if oa == 0 {
		return color.NRGBA{}
	}
	ch := func(s, d uint8) uint8 {
		return uint8(math.Round((float64(s)*sa + float64(d)*da*(1-sa)) / oa))
	}
	return color.NRGBA{ch(src.R, dst.R), ch(src.G, dst.G), ch(src.B, dst.B), uint8(math.Round(oa * 255))}
}

func encode(img *image.NRGBA) []byte {
	var buf bytes.Buffer
	_ = png.Encode(&buf, img) // an NRGBA in memory cannot fail to encode
	return buf.Bytes()
}

// distToSegment returns the distance from (px,py) to the segment (ax,ay)-(bx,by).
func distToSegment(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	l2 := dx*dx + dy*dy
	if l2 == 0 {
		return math.Hypot(px-ax, py-ay)
	}
	t := ((px-ax)*dx + (py-ay)*dy) / l2
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(ax+t*dx), py-(ay+t*dy))
}
