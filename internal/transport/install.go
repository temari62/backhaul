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

// PinnedWstunnelSHA256 returns the pinned archive checksum for a wstunnel
// version and "<goos>_<goarch>" platform ("" if not pinned).
func PinnedWstunnelSHA256(version, platform string) string {
	return wstunnelSHA256[version][platform]
}

// xrayAssets maps platform → release asset, and xraySHA256 pins the archive
// checksums per version (from the GitHub release asset digests).
var (
	xrayAssets = map[string]string{
		"windows_amd64": "Xray-windows-64.zip",
		"linux_amd64":   "Xray-linux-64.zip",
		"linux_arm64":   "Xray-linux-arm64-v8a.zip",
		"darwin_amd64":  "Xray-macos-64.zip",
		"darwin_arm64":  "Xray-macos-arm64-v8a.zip",
	}
	xraySHA256 = map[string]map[string]string{
		"26.3.27": {
			"windows_amd64": "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad",
			"linux_amd64":   "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
			"linux_arm64":   "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
			"darwin_amd64":  "f5b0471d3459eff1b82e48af0aeac186abcc3298210070afbbbd8437a4e8b203",
			"darwin_arm64":  "2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf",
		},
	}
)

func xrayExe() string {
	if runtime.GOOS == "windows" {
		return "xray.exe"
	}
	return "xray"
}

// XrayRelease returns the download URL and pinned checksum for a platform.
func XrayRelease(version, platform string) (url, sha string, err error) {
	asset, ok := xrayAssets[platform]
	if !ok {
		return "", "", fmt.Errorf("no Xray build for %s", platform)
	}
	sha = xraySHA256[version][platform]
	if sha == "" {
		return "", "", fmt.Errorf("no pinned checksum for Xray %s %s", version, platform)
	}
	return fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/download/v%s/%s", version, asset), sha, nil
}

// EnsureXray returns a usable xray path: transport.xray_path, next to
// backhaul, <config>/bin/xray-<version>/, $PATH — or downloads the pinned
// release (checksum-verified).
func EnsureXray(ctx context.Context, cfg *config.Config, binDir string) (string, error) {
	if p := cfg.Transport.XrayPath; p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("transport.xray_path %q does not exist", p)
		}
		return p, nil
	}
	v := cfg.Transport.XrayVersion
	dir := filepath.Join(binDir, "xray-"+v)
	var cands []string
	if self, err := os.Executable(); err == nil {
		cands = append(cands, filepath.Join(filepath.Dir(self), xrayExe()))
	}
	cands = append(cands, filepath.Join(dir, xrayExe()))
	for _, c := range cands {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	if p, err := exec.LookPath("xray"); err == nil {
		return p, nil
	}
	url, sha, err := XrayRelease(v, runtime.GOOS+"_"+runtime.GOARCH)
	if err != nil {
		return "", err
	}
	slog.Info("downloading xray", "version", v)
	archive, err := fetch.Verified(ctx, url, sha)
	if err != nil {
		return "", fmt.Errorf("download xray: %w", err)
	}
	bin, err := fetch.FromZip(archive, xrayExe())
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, xrayExe())
	if err := os.WriteFile(dst+".tmp", bin, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(dst+".tmp", dst); err != nil {
		return "", err
	}
	slog.Info("installed xray", "path", dst)
	return dst, nil
}

// cloudflared (Cloudflare Tunnel exit node). Checksums verified against the
// downloads and GitHub's recorded digests; the Windows build is signed by
// Cloudflare, Inc.
var cloudflaredAssets = map[string]string{
	"windows_amd64": "cloudflared-windows-amd64.exe",
	"linux_amd64":   "cloudflared-linux-amd64",
	"linux_arm64":   "cloudflared-linux-arm64",
}

var cloudflaredSHA256 = map[string]map[string]string{
	"2026.9.3": {
		"windows_amd64": "f096265ec2fcbe9bb6e2d64268db167ced3fcbb83d894bdb9e2fcdb26f2ea7e2",
		"linux_amd64":   "77e26d8d900e0b8469f416239d14b5f296525fdf79fee6f511ef55609e3fbac2",
		"linux_arm64":   "aaeb2d7d0da3614634c7e03ab13487a1522c2e79165ed2929cfe23d5e95b326d",
	},
}

// CloudflaredRelease returns the download URL and pinned SHA-256 for platform.
func CloudflaredRelease(version, platform string) (url, sha string, err error) {
	asset, ok := cloudflaredAssets[platform]
	if !ok {
		return "", "", fmt.Errorf("Cloudflare Tunnel mode isn't available on %s yet (Windows and Linux are)", platform)
	}
	if sha = cloudflaredSHA256[version][platform]; sha == "" {
		return "", "", fmt.Errorf("no pinned checksum for cloudflared %s %s", version, platform)
	}
	return fmt.Sprintf("https://github.com/cloudflare/cloudflared/releases/download/%s/%s", version, asset), sha, nil
}

func cloudflaredExe() string {
	if runtime.GOOS == "windows" {
		return "cloudflared.exe"
	}
	return "cloudflared"
}

// EnsureCloudflared returns a usable cloudflared: the configured path, or
// <config>/bin/cloudflared-<version>/, downloading the pinned release
// (checksum-verified) the first time.
func EnsureCloudflared(ctx context.Context, cfg *config.Config, binDir string) (string, error) {
	if p := cfg.Reachability.CFTunnel.CloudflaredPath; p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("reachability.cloudflare_tunnel.cloudflared_path %q does not exist", p)
		}
		return p, nil
	}
	v := config.DefaultCloudflaredVersion
	dir := filepath.Join(binDir, "cloudflared-"+v)
	dst := filepath.Join(dir, cloudflaredExe())
	if _, err := os.Stat(dst); err == nil {
		return dst, nil
	}
	url, sha, err := CloudflaredRelease(v, runtime.GOOS+"_"+runtime.GOARCH)
	if err != nil {
		return "", err
	}
	slog.Info("downloading cloudflared (Cloudflare Tunnel)", "version", v)
	bin, err := fetch.Verified(ctx, url, sha)
	if err != nil {
		return "", fmt.Errorf("download cloudflared: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(dst+".tmp", bin, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(dst+".tmp", dst); err != nil {
		return "", err
	}
	slog.Info("installed cloudflared", "path", dst)
	return dst, nil
}
