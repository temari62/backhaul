package update

import "testing"

func TestNewer(t *testing.T) {
	cases := []struct {
		cur, cand string
		want      bool
	}{
		{"0.4.0", "0.5.0", true},
		{"0.4.0", "0.4.1", true},
		{"0.4.0", "1.0.0", true},
		{"0.4.0", "0.4.0", false},
		{"0.5.0", "0.4.0", false},
		{"1.0.0", "0.9.9", false},
		{"v0.4.0", "v0.4.1", true},   // leading "v" tolerated
		{"0.4", "0.4.1", true},       // missing patch = .0
		{"0.4.0", "0.4", false},      // 0.4 == 0.4.0
		{"dev", "0.4.0", true},       // a real release beats a dev build
		{"0.4.0", "dev", false},      // dev never updates over a release
		{"0.4.0", "0.4.1-rc1", true}, // suffix ignored, patch wins
		{"0.4.0", "0.4.0-rc1", false},
	}
	for _, c := range cases {
		if got := Newer(c.cur, c.cand); got != c.want {
			t.Errorf("Newer(%q,%q)=%v want %v", c.cur, c.cand, got, c.want)
		}
	}
}

func TestInstallerName(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"0.5.0", "Backhaul-Setup-0.5.0.exe"},
		{"v0.5.0", "Backhaul-Setup-0.5.0.exe"},
		{" 1.2.3 ", "Backhaul-Setup-1.2.3.exe"},
	} {
		if got := InstallerName(c.in); got != c.want {
			t.Errorf("InstallerName(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestReleaseAsset(t *testing.T) {
	r := Release{Assets: []Asset{{Name: "checksums.txt"}, {Name: "Backhaul-Setup-0.5.0.exe"}}}
	if a := r.asset("CHECKSUMS.TXT"); a == nil { // case-insensitive
		t.Fatal("expected checksums.txt match")
	}
	if a := r.asset("missing"); a != nil {
		t.Fatal("expected nil for missing asset")
	}
}
