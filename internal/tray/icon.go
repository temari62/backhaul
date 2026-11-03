package tray

import (
	"bytes"
	"encoding/binary"
	"image/color"
	"runtime"

	"backhaul/internal/logo"
)

// iconSize is the generated icon edge in pixels; trays downscale as needed.
const iconSize = 64

var phaseColors = map[Phase]color.NRGBA{
	Down:     {0x8a, 0x8f, 0x98, 0xff},
	Starting: {0xf0, 0xa2, 0x02, 0xff},
	Up:       {0x2e, 0xb8, 0x5c, 0xff},
	Failed:   {0xe0, 0x3e, 0x3e, 0xff},
}

// PNG draws the app logo with a status dot in the phase colour, so the tray
// shows the same icon as the app, the launcher and the exe.
func PNG(p Phase) []byte { return logo.BadgePNG(iconSize, phaseColors[p]) }

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
		return ICO(PNG(p))
	}
	return PNG(p)
}
