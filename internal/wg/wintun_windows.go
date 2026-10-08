//go:build windows

package wg

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"backhaul/internal/fetch"
)

const (
	wintunURL    = "https://www.wintun.net/builds/wintun-0.14.1.zip"
	wintunSHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
)

// WintunPath is where wireguard-go looks for wintun.dll (next to the exe).
func WintunPath() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(self), "wintun.dll"), nil
}

// EnsureWintun downloads the signed Wintun driver DLL (checksum-pinned) next
// to backhaul.exe if it is missing. Required by the embedded engine.
func EnsureWintun(ctx context.Context) error {
	dst, err := WintunPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	arch := map[string]string{"amd64": "amd64", "arm64": "arm64", "386": "x86", "arm": "arm"}[runtime.GOARCH]
	slog.Info("downloading Wintun driver", "url", wintunURL)
	zip, err := fetch.Verified(ctx, wintunURL, wintunSHA256)
	if err != nil {
		return fmt.Errorf("download wintun: %w", err)
	}
	dll, err := fetch.FromZip(zip, "wintun/bin/"+arch+"/wintun.dll")
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, dll, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	slog.Info("installed wintun.dll", "path", dst)
	return nil
}
