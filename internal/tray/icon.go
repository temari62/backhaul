package tray

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"runtime"
)

// iconSize is the generated icon edge in pixels; trays downscale as needed.
const iconSize = 64

var phaseColors = map[Phase]color.NRGBA{
	Down:     {0x8a, 0x8f, 0x98, 0xff},
	Starting: {0xf0, 0xa2, 0x02, 0xff},
	Up:       {0x2e, 0xb8, 0x5c, 0xff},
	Failed:   {0xe0, 0x3e, 0x3e, 0xff},
}

// DotPNG draws an anti-aliased filled circle in the phase colour.
func DotPNG(p Phase) []byte {
	c := phaseColors[p]
	img := image.NewNRGBA(image.Rect(0, 0, iconSize, iconSize))
	r := float64(iconSize)/2 - 4
	cx := float64(iconSize) / 2
	for y := 0; y < iconSize; y++ {
		for x := 0; x < iconSize; x++ {
			// 4x4 supersampling for a smooth edge.
			hits := 0
			for sy := 0; sy < 4; sy++ {
				for sx := 0; sx < 4; sx++ {
					dx := float64(x) + (float64(sx)+0.5)/4 - cx
					dy := float64(y) + (float64(sy)+0.5)/4 - cx
					if dx*dx+dy*dy <= r*r {
						hits++
					}
				}
			}
			if hits > 0 {
				img.SetNRGBA(x, y, color.NRGBA{c.R, c.G, c.B, uint8(int(c.A) * hits / 16)})
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// ICO wraps a PNG in a single-image .ico container (PNG-in-ICO is supported
// since Windows Vista), which is what the Windows tray expects.
func ICO(pngData []byte) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, struct{ Reserved, Type, Count uint16 }{0, 1, 1})
	binary.Write(&b, binary.LittleEndian, struct {
		W, H, Colors, Reserved uint8
		Planes, BPP            uint16
		Size, Offset           uint32
	}{iconSize, iconSize, 0, 0, 1, 32, uint32(len(pngData)), 6 + 16})
	b.Write(pngData)
	return b.Bytes()
}

// Icon returns the platform-appropriate icon bytes for a phase.
func Icon(p Phase) []byte {
	if runtime.GOOS == "windows" {
		return ICO(DotPNG(p))
	}
	return DotPNG(p)
}
