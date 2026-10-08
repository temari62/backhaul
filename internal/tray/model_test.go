package tray

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"strings"
	"testing"
	"time"

	"backhaul/internal/state"
)

func TestCompute(t *testing.T) {
	now := time.Now()
	fresh := func(healthy bool, reconnects int) *state.Runtime {
		return &state.Runtime{Mode: "connect", Endpoint: "home.example", Updated: now, Healthy: healthy,
			Reconnects: reconnects, LastHandshake: now.Add(-5 * time.Second), KillSwitch: true}
	}
	base := Inputs{StaleAfter: 30 * time.Second, LaunchWait: time.Minute, Now: now}
	cases := []struct {
		name  string
		mod   func(*Inputs)
		phase Phase
		conn  bool
		disc  bool
		text  string
	}{
		{"down", func(*Inputs) {}, Down, true, false, "Disconnected"},
		{"up", func(i *Inputs) { i.Runtime, i.Alive = fresh(true, 0), true }, Up, false, true, "home.example"},
		{"handshaking", func(i *Inputs) { i.Runtime, i.Alive = fresh(false, 0), true }, Starting, false, true, "Connecting"},
		{"reconnecting", func(i *Inputs) { i.Runtime, i.Alive = fresh(false, 2), true }, Starting, false, true, "Reconnecting… (2)"},
		{"dead pid", func(i *Inputs) { i.Runtime, i.Alive = fresh(true, 0), false }, Down, true, false, "Disconnected"},
		{"stale", func(i *Inputs) {
			i.Runtime, i.Alive = fresh(true, 0), true
			i.Runtime.Updated = now.Add(-time.Hour)
		}, Down, true, false, "Disconnected"},
		{"launching", func(i *Inputs) { i.LaunchedAt = now.Add(-10 * time.Second) }, Starting, false, false, "Starting"},
		{"launch failed", func(i *Inputs) { i.LaunchedAt = now.Add(-2 * time.Minute) }, Failed, true, false, "failed"},
	}
	for _, c := range cases {
		in := base
		c.mod(&in)
		v := Compute(in)
		if v.Phase != c.phase || v.CanConnect != c.conn || v.CanDisconnect != c.disc || !strings.Contains(v.Status, c.text) {
			t.Errorf("%s: got %+v", c.name, v)
		}
	}
}

func TestIcons(t *testing.T) {
	for p := range phaseColors {
		img, err := png.Decode(bytes.NewReader(DotPNG(p)))
		if err != nil || img.Bounds().Dx() != iconSize {
			t.Fatalf("phase %d: %v", p, err)
		}
		_, _, _, a := img.At(0, 0).RGBA()
		_, _, _, ac := img.At(iconSize/2, iconSize/2).RGBA()
		if a != 0 || ac == 0 {
			t.Fatalf("phase %d: corner should be transparent, centre opaque", p)
		}
	}
	ico := ICO(DotPNG(Up))
	if binary.LittleEndian.Uint16(ico[2:]) != 1 || binary.LittleEndian.Uint32(ico[18:]) != 22 || !bytes.Equal(ico[22:26], []byte("\x89PNG")) {
		t.Fatal("bad ICO container")
	}
}

func TestShellLine(t *testing.T) {
	got := shellLine("/opt/back haul/backhaul", []string{"connect", "--config-dir", "/home/o'neil/.config/backhaul"}, "/tmp/l og")
	want := `'/opt/back haul/backhaul' 'connect' '--config-dir' '/home/o'\''neil/.config/backhaul' >> '/tmp/l og' 2>&1`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
