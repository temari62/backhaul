// Package ddns keeps the exit node's hostname pointed at its current home IP
// (§3 mode A). Providers are pluggable; DuckDNS and Cloudflare ship in v1.
package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Updater pushes the current public IP to a DNS provider.
type Updater interface {
	Name() string
	Update(ctx context.Context) (string, error)
}

// Options configure an updater. Token is secret: never log it.
type Options struct {
	Provider   string
	Domain     string
	Token      string
	ZoneID     string
	IPCheckURL string
	Client     *http.Client
}

// New returns the updater for opts.Provider.
func New(o Options) (Updater, error) {
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 30 * time.Second}
	}
	switch o.Provider {
	case "duckdns":
		return &DuckDNS{o: o, BaseURL: "https://www.duckdns.org/update"}, nil
	case "cloudflare":
		return &Cloudflare{o: o, BaseURL: "https://api.cloudflare.com/client/v4"}, nil
	default:
		return nil, fmt.Errorf("unknown ddns provider %q", o.Provider)
	}
}

// Run updates immediately and then every interval until ctx is done.
func Run(ctx context.Context, u Updater, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	last := ""
	for {
		ip, err := u.Update(ctx)
		switch {
		case err != nil:
			slog.Warn("ddns update failed", "provider", u.Name(), "err", err)
		case ip != last:
			slog.Info("ddns updated", "provider", u.Name(), "ip", ip)
			last = ip
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// DuckDNS updates <sub>.duckdns.org; DuckDNS detects the caller's IP itself.
type DuckDNS struct {
	o       Options
	BaseURL string
}

func (d *DuckDNS) Name() string { return "duckdns" }

func (d *DuckDNS) Update(ctx context.Context) (string, error) {
	sub := strings.TrimSuffix(d.o.Domain, ".duckdns.org")
	q := url.Values{"domains": {sub}, "token": {d.o.Token}, "ip": {""}, "verbose": {"true"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.BaseURL+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	resp, err := d.o.Client.Do(req)
	if err != nil {
		return "", redact(err, d.o.Token)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) == 0 || lines[0] != "OK" {
		return "", fmt.Errorf("duckdns rejected the update (%s) — check domain and token", strings.TrimSpace(lines[0]))
	}
	if len(lines) > 1 {
		return strings.TrimSpace(lines[1]), nil
	}
	return "", nil
}

// Cloudflare updates (or creates) an A record via the v4 API with a scoped token.
type Cloudflare struct {
	o       Options
	BaseURL string
}

func (c *Cloudflare) Name() string { return "cloudflare" }

type cfResp struct {
	Success bool              `json:"success"`
	Errors  []json.RawMessage `json:"errors"`
	Result  json.RawMessage   `json:"result"`
}

func (c *Cloudflare) call(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.o.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.o.Client.Do(req)
	if err != nil {
		return redact(err, c.o.Token)
	}
	defer resp.Body.Close()
	var r cfResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return fmt.Errorf("cloudflare: %s: %w", resp.Status, err)
	}
	if !r.Success {
		return fmt.Errorf("cloudflare: %s: %s", resp.Status, joinRaw(r.Errors))
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

func (c *Cloudflare) Update(ctx context.Context) (string, error) {
	ip, err := PublicIP(ctx, c.o.Client, c.o.IPCheckURL)
	if err != nil {
		return "", err
	}
	var recs []struct {
		ID      string `json:"id"`
		Content string `json:"content"`
	}
	zone := url.PathEscape(c.o.ZoneID)
	if err := c.call(ctx, http.MethodGet, "/zones/"+zone+"/dns_records?type=A&name="+url.QueryEscape(c.o.Domain), nil, &recs); err != nil {
		return "", err
	}
	rec := map[string]any{"type": "A", "name": c.o.Domain, "content": ip, "ttl": 60, "proxied": false}
	if len(recs) == 0 {
		return ip, c.call(ctx, http.MethodPost, "/zones/"+zone+"/dns_records", rec, nil)
	}
	if recs[0].Content == ip {
		return ip, nil
	}
	return ip, c.call(ctx, http.MethodPatch, "/zones/"+zone+"/dns_records/"+url.PathEscape(recs[0].ID), rec, nil)
}

// PublicIP asks an IP-echo service for this machine's public address.
func PublicIP(ctx context.Context, client *http.Client, checkURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", checkURL, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(b))
	if ip == "" {
		return "", errors.New("empty response from IP check service")
	}
	return ip, nil
}

func redact(err error, secret string) error {
	if secret == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), secret, "[REDACTED]"))
}

func joinRaw(rs []json.RawMessage) string {
	s := make([]string, len(rs))
	for i, r := range rs {
		s[i] = string(r)
	}
	return strings.Join(s, "; ")
}
