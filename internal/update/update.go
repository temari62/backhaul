// Package update checks GitHub Releases for a newer Backhaul and, on Windows,
// applies the update by downloading the signed-by-checksum installer and
// running it silently.
//
// It never downloads anything whose SHA-256 is not listed in the release's
// checksums.txt, so a tampered CDN or mirror can't feed a different binary.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"backhaul/internal/buildinfo"
	"backhaul/internal/fetch"
)

// Repo is the GitHub "owner/name" whose releases are offered as updates.
const Repo = "temari62/backhaul"

// checksumsAsset is the release asset listing "sha256  filename" lines.
const checksumsAsset = "checksums.txt"

// maxInstaller caps the installer download (the all-in-one app is ~60 MB).
const maxInstaller = 256 << 20

// Release is the subset of a GitHub release we use.
type Release struct {
	Tag     string  // e.g. "v0.5.0"
	Name    string  // release title
	Notes   string  // release body (markdown)
	Assets  []Asset // downloadable files
	Version string  // Tag without a leading "v"
}

// Asset is one downloadable file in a release.
type Asset struct {
	Name string
	URL  string
	Size int64
}

type ghRelease struct {
	TagName    string `json:"tag_name"`
	Name       string `json:"name"`
	Body       string `json:"body"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

// Latest fetches the repository's latest (non-draft, non-prerelease) release.
func Latest(ctx context.Context) (Release, error) {
	url := "https://api.github.com/repos/" + Repo + "/releases/latest"
	b, err := fetch.Get(ctx, url)
	if err != nil {
		return Release{}, fmt.Errorf("checking for updates: %w", err)
	}
	var g ghRelease
	if err := json.Unmarshal(b, &g); err != nil {
		return Release{}, fmt.Errorf("parsing release feed: %w", err)
	}
	rel := Release{Tag: g.TagName, Name: g.Name, Notes: g.Body, Version: normalize(g.TagName)}
	for _, a := range g.Assets {
		rel.Assets = append(rel.Assets, Asset{Name: a.Name, URL: a.URL, Size: a.Size})
	}
	return rel, nil
}

// Status is the result of a check.
type Status struct {
	Current   string `json:"current"`   // the running version
	Latest    string `json:"latest"`    // the newest released version
	Available bool   `json:"available"` // Latest is newer than Current
	Notes     string `json:"notes"`     // release notes for Latest
}

// Check reports whether a newer release than the running build exists. A dev
// build (unstamped) never reports an update, so developers aren't nagged.
func Check(ctx context.Context) (Status, error) {
	cur := buildinfo.Version
	rel, err := Latest(ctx)
	if err != nil {
		return Status{Current: cur}, err
	}
	st := Status{Current: cur, Latest: rel.Version, Notes: rel.Notes}
	if !buildinfo.IsDev() {
		st.Available = Newer(cur, rel.Version)
	}
	return st, nil
}

// asset returns the release asset whose name matches want, or nil.
func (r Release) asset(want string) *Asset {
	for i := range r.Assets {
		if strings.EqualFold(r.Assets[i].Name, want) {
			return &r.Assets[i]
		}
	}
	return nil
}

// InstallerName is the Windows installer asset name for a version, matching
// what build-installer.ps1 produces.
func InstallerName(version string) string {
	return "Backhaul-Setup-" + normalize(version) + ".exe"
}

// Download fetches rel's Windows installer into dir, verifying its SHA-256
// against the release's checksums.txt. It returns the saved file's path.
func Download(ctx context.Context, rel Release, dir string) (string, error) {
	name := InstallerName(rel.Version)
	a := rel.asset(name)
	if a == nil {
		return "", fmt.Errorf("release %s has no installer %q", rel.Tag, name)
	}
	ck := rel.asset(checksumsAsset)
	if ck == nil {
		return "", fmt.Errorf("release %s has no %s", rel.Tag, checksumsAsset)
	}
	list, err := fetch.Get(ctx, ck.URL)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", checksumsAsset, err)
	}
	want := fetch.ChecksumFromList(string(list), name)
	if want == "" {
		return "", fmt.Errorf("%s does not list %q", checksumsAsset, name)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, name)
	if err := downloadVerified(ctx, a.URL, want, dst); err != nil {
		return "", err
	}
	return dst, nil
}

// downloadVerified streams url to path and checks its SHA-256 against want,
// removing the file if the checksum does not match.
func downloadVerified(ctx context.Context, url, want, path string) (err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		cerr := f.Close()
		if err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(path)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxInstaller+1))
	if err != nil {
		return err
	}
	if n > maxInstaller {
		return fmt.Errorf("installer larger than %d bytes", maxInstaller)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, want) {
		err = fmt.Errorf("checksum mismatch: got %s, want %s", got, want)
		return err
	}
	return nil
}

// Newer reports whether candidate is a strictly higher version than current.
// Both are compared as dot-separated integers (a simple semver core, ignoring
// any pre-release/build suffix). An unparseable current is treated as oldest,
// so a real release always wins over "dev".
func Newer(current, candidate string) bool {
	return compare(current, candidate) < 0
}

// compare returns -1, 0, or 1 comparing two versions by numeric components.
func compare(a, b string) int {
	pa, pb := parts(a), parts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

// parts splits "1.2.3" into [1 2 3], stopping at the first non-numeric
// component (e.g. a "-rc1" suffix). An unparseable version yields nil, which
// compare treats as lowest.
func parts(v string) []int {
	v = normalize(v)
	if v == "" || v == "dev" {
		return nil
	}
	var out []int
	for _, f := range strings.Split(v, ".") {
		if i := strings.IndexFunc(f, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
			f = f[:i]
		}
		n, err := strconv.Atoi(f)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

// normalize strips a leading "v" and surrounding space from a tag.
func normalize(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}
