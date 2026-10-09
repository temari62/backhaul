//go:build windows

package wg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"golang.org/x/sys/windows"

	"backhaul/internal/fetch"
)

// WintunPath is where backhaul keeps wintun.dll:
// %LOCALAPPDATA%\Backhaul\bin\wintun.dll (so nothing litters the exe's folder).
func WintunPath() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		var err error
		if base, err = os.UserCacheDir(); err != nil {
			return "", err
		}
	}
	return filepath.Join(base, "Backhaul", "bin", "wintun.dll"), nil
}

// legacyWintunPath is next to the exe, where wireguard-go looks by default.
func legacyWintunPath() string {
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(self), "wintun.dll")
}

var (
	preloadOnce sync.Once
	preloadErr  error
)

// preloadWintun loads wintun.dll by full path. wireguard-go later loads
// "wintun.dll" by name, and Windows returns an already-loaded module with
// that base name regardless of search path.
func preloadWintun(path string) error {
	preloadOnce.Do(func() {
		_, preloadErr = windows.LoadLibraryEx(path, 0, windows.LOAD_WITH_ALTERED_SEARCH_PATH)
		if preloadErr != nil {
			preloadErr = fmt.Errorf("load %s: %w", path, preloadErr)
		}
	})
	return preloadErr
}

// InstallWintun writes dll (e.g. one embedded in the app) to WintunPath if
// it isn't already there with identical content.
func InstallWintun(dll []byte) error {
	dst, err := WintunPath()
	if err != nil {
		return err
	}
	if cur, err := os.ReadFile(dst); err == nil && bytes.Equal(sha(cur), sha(dll)) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, dll, 0o644)
}

func sha(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

// EnsureWintun makes wintun.dll available to the embedded engine: use one
// next to the exe if present, else WintunPath (downloading the signed,
// checksum-pinned release if missing), and preload it.
func EnsureWintun(ctx context.Context) error {
	if p := legacyWintunPath(); p != "" {
		if _, err := os.Stat(p); err == nil {
			return nil // wireguard-go finds it next to the exe itself
		}
	}
	dst, err := WintunPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(dst); err != nil {
		arch := map[string]string{"amd64": "amd64", "arm64": "arm64", "386": "x86", "arm": "arm"}[runtime.GOARCH]
		slog.Info("downloading Wintun driver", "url", WintunURL)
		zip, err := fetch.Verified(ctx, WintunURL, WintunSHA256)
		if err != nil {
			return fmt.Errorf("download wintun: %w", err)
		}
		dll, err := fetch.FromZip(zip, "wintun/bin/"+arch+"/wintun.dll")
		if err != nil {
			return err
		}
		if err := InstallWintun(dll); err != nil {
			return fmt.Errorf("write %s: %w", dst, err)
		}
		slog.Info("installed wintun.dll", "path", dst)
	}
	return preloadWintun(dst)
}

// WintunInstalled reports where wintun.dll is available (next to the exe or
// in WintunPath).
func WintunInstalled() (string, bool) {
	if p := legacyWintunPath(); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	p, err := WintunPath()
	if err != nil {
		return "", false
	}
	_, err = os.Stat(p)
	return p, err == nil
}
