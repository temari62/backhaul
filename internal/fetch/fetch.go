// Package fetch downloads release artifacts and refuses anything whose
// SHA-256 does not match the expected value.
package fetch

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

// MaxSize caps downloads (wstunnel/wintun archives are a few MB).
const MaxSize = 64 << 20

// Timeout bounds one download.
const Timeout = 5 * time.Minute

// Verified downloads url and checks it against wantSHA256 (hex).
func Verified(ctx context.Context, url, wantSHA256 string) ([]byte, error) {
	if wantSHA256 == "" {
		return nil, fmt.Errorf("refusing to download %s without a pinned checksum", url)
	}
	b, err := Get(ctx, url)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, wantSHA256) {
		return nil, fmt.Errorf("checksum mismatch for %s: got %s, want %s", url, got, wantSHA256)
	}
	return b, nil
}

// Get downloads url (size-capped).
func Get(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxSize {
		return nil, fmt.Errorf("GET %s: response too large", url)
	}
	return b, nil
}

// ChecksumFromList finds name in a goreleaser-style "sha256  filename" list.
func ChecksumFromList(list, name string) string {
	for _, line := range strings.Split(list, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return f[0]
		}
	}
	return ""
}

// FromTarGz returns the first regular file in a .tar.gz whose base name is name.
func FromTarGz(archive []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s not found in archive", name)
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && path.Base(h.Name) == name {
			return io.ReadAll(io.LimitReader(tr, MaxSize))
		}
	}
}

// FromZip returns the file at exactly member (forward-slash path) in a zip.
func FromZip(archive []byte, member string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if f.Name == member {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, MaxSize))
		}
	}
	return nil, fmt.Errorf("%s not found in archive", member)
}
