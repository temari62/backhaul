package osutil

import (
	"os"
	"runtime"
	"testing"
)

// A systemd system service has no $HOME; the home directory must still be
// found (from the user database).
func TestUserHomeWithoutHOME(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses USERPROFILE")
	}
	want, err := UserHome()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", "")
	os.Unsetenv("HOME")
	got, err := UserHome()
	if err != nil || got == "" {
		t.Fatalf("without $HOME: %q, %v", got, err)
	}
	if got != want {
		t.Logf("home from the user database: %s ($HOME was %s)", got, want)
	}
}
