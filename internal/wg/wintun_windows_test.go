//go:build windows

package wg

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// The single-file app keeps wintun.dll outside the exe's folder and relies on
// Windows reusing an already-loaded module when wireguard-go later loads
// "wintun.dll" by name with application-dir/system32-only search flags.
func TestPreloadedDLLIsFoundByName(t *testing.T) {
	src := os.Getenv("BACKHAUL_TEST_WINTUN")
	if src == "" {
		t.Skip("set BACKHAUL_TEST_WINTUN to a wintun.dll")
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	// Not t.TempDir(): a loaded DLL cannot be deleted by the test cleanup.
	dir, err := os.MkdirTemp("", "wintun-preload")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "wintun.dll")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	// Exactly the flags golang.zx2c4.com/wintun uses.
	const flags = windows.LOAD_LIBRARY_SEARCH_APPLICATION_DIR | windows.LOAD_LIBRARY_SEARCH_SYSTEM32
	if _, err := windows.LoadLibraryEx("wintun.dll", 0, flags); err == nil {
		t.Skip("wintun.dll is already resolvable on this machine; cannot prove the preload")
	}
	if err := preloadWintun(p); err != nil {
		t.Fatal(err)
	}
	h, err := windows.LoadLibraryEx("wintun.dll", 0, flags)
	if err != nil {
		t.Fatalf("by-name load after preload failed: %v", err)
	}
	if _, err := windows.GetProcAddress(h, "WintunCreateAdapter"); err != nil {
		t.Fatalf("resolved module is not wintun: %v", err)
	}
}
