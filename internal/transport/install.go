package transport

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"backhaul/internal/config"
	"backhaul/internal/fetch"
)

// wstunnelSHA256 pins release archive checksums per version and platform
// (taken from the GitHub release asset digests).
var wstunnelSHA256 = map[string]map[string]string{
	"10.7.1": {
		"linux_amd64":   "fa842ed53fbb14b1c69cd98829f9895d7f8a6b0d562c57c1175851a52cea9ea2",
		"linux_arm64":   "99f9506d01d1b4073254609600ec5056dab8dc58aec75c32f6eb0508335a8fd2",
		"darwin_amd64":  "ac234c60d461532d81fb60e610787bbc2ce48bcd095f57eb8f86d1a3914e344c",
		"darwin_arm64":  "2c1f427fd651a74c8844a0ed352c13d667da7e08056b790549917d6952ec69ac",
		"windows_amd64": "deb3c8b8d9fecf5428f7e0caabbc13aeb3b1edbfba49e1724a7a065c027bd0f2",
		"windows_arm64": "1d642b29aba0e05c5564adf1dfe2e4494cd10b62331490471bdf6d6548085c96",
	},
}

func exeName() string {
	if runtime.GOOS == "windows" {
		return "wstunnel.exe"
	}
	return "wstunnel"
}

// FindWstunnel locates the wstunnel binary without downloading:
// config path → next to backhaul → <config>/bin → $PATH.
func FindWstunnel(cfg *config.Config, binDir string) (string, bool) {
	if p := cfg.Transport.WstunnelPath; p != "" {
		_, err := os.Stat(p)
		return p, err == nil
	}
	cands := []string{}
	if self, err := os.Executable(); err == nil {
		cands = append(cands, filepath.Join(filepath.Dir(self), exeName()))
	}
	cands = append(cands, filepath.Join(binDir, cfg.Transport.WstunnelVersion, exeName()))
	for _, c := range cands {
		if _, err := os.Stat(c); err == nil {
			return c, true
		}
	}
	if p, err := exec.LookPath("wstunnel"); err == nil {
		return p, true
	}
	return "", false
}

// EnsureWstunnel returns a usable wstunnel path, downloading the pinned
// release into binDir (checksum-verified) if none is installed.
func EnsureWstunnel(ctx context.Context, cfg *config.Config, binDir string) (string, error) {
	if p, ok := FindWstunnel(cfg, binDir); ok {
		return p, nil
	}
	if cfg.Transport.WstunnelPath != "" {
		return "", fmt.Errorf("transport.wstunnel_path %q does not exist", cfg.Transport.WstunnelPath)
	}
	v := cfg.Transport.WstunnelVersion
	plat := runtime.GOOS + "_" + runtime.GOARCH
	asset := fmt.Sprintf("wstunnel_%s_%s.tar.gz", v, plat)
	base := fmt.Sprintf("https://github.com/erebe/wstunnel/releases/download/v%s/", v)

	sum := wstunnelSHA256[v][plat]
	if sum == "" {
		// Unpinned version: fall back to the release's checksums.txt (same
		// origin, so weaker than a pin). TODO(spec): pin more versions.
		slog.Warn("no pinned checksum for this wstunnel version; using release checksums.txt", "version", v, "platform", plat)
		list, err := fetch.Get(ctx, base+"checksums.txt")
		if err != nil {
			return "", fmt.Errorf("fetch wstunnel checksums: %w", err)
		}
		if sum = fetch.ChecksumFromList(string(list), asset); sum == "" {
			return "", fmt.Errorf("no wstunnel release for %s (asset %s)", plat, asset)
		}
	}
	slog.Info("downloading wstunnel", "version", v, "platform", plat)
	archive, err := fetch.Verified(ctx, base+asset, sum)
	if err != nil {
		return "", fmt.Errorf("download wstunnel: %w", err)
	}
	bin, err := fetch.FromTarGz(archive, exeName())
	if err != nil {
		return "", err
	}
	dir := filepath.Join(binDir, v)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, exeName())
	if err := os.WriteFile(dst+".tmp", bin, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(dst+".tmp", dst); err != nil {
		return "", err
	}
	slog.Info("installed wstunnel", "path", dst)
	return dst, nil
}
