package ddns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CloudflareAPI is the API base URL (overridden in tests).
var CloudflareAPI = "https://api.cloudflare.com/client/v4"

// CloudflareZone finds the zone that contains hostname (e.g. "example.com"
// for "vpn.example.com") using a scoped API token.
func CloudflareZone(ctx context.Context, client *http.Client, token, hostname string) (id, name string, err error) {
	c := &Cloudflare{o: Options{Token: token, Client: orDefault(client)}, BaseURL: CloudflareAPI}
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(hostname), "."), ".")
	for i := 0; i+2 <= len(labels); i++ { // longest candidate first: a.b.example.com, b.example.com, example.com
		candidate := strings.Join(labels[i:], ".")
		var zones []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		if err := c.call(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(candidate), nil, &zones); err != nil {
			return "", "", err
		}
		if len(zones) > 0 {
			if zones[0].Status != "" && zones[0].Status != "active" {
				return zones[0].ID, zones[0].Name, fmt.Errorf("the Cloudflare zone %s is %q, not active yet — finish moving the domain's nameservers to Cloudflare (at your registrar), then try again", zones[0].Name, zones[0].Status)
			}
			return zones[0].ID, zones[0].Name, nil
		}
	}
	return "", "", fmt.Errorf("no Cloudflare zone found for %s — add the domain to your Cloudflare account, and make sure the API token can read it", hostname)
}

// CloudflareEnsureSSL makes sure Cloudflare will talk HTTPS to the exit node
// while accepting its self-signed certificate (SSL mode "full"). "flexible"
// or "off" would send plain HTTP to port 443 and break the tunnel; "strict"
// would reject the self-signed certificate. It returns the previous mode.
func CloudflareEnsureSSL(ctx context.Context, client *http.Client, token, zoneID string) (prev string, changed bool, err error) {
	c := &Cloudflare{o: Options{Token: token, Client: orDefault(client)}, BaseURL: CloudflareAPI}
	var cur struct {
		Value string `json:"value"`
	}
	path := "/zones/" + url.PathEscape(zoneID) + "/settings/ssl"
	if err := c.call(ctx, http.MethodGet, path, nil, &cur); err != nil {
		return "", false, err
	}
	if cur.Value == "full" {
		return cur.Value, false, nil
	}
	if err := c.call(ctx, http.MethodPatch, path, map[string]string{"value": "full"}, nil); err != nil {
		return cur.Value, false, fmt.Errorf("set SSL/TLS mode to Full (the token needs Zone Settings: Edit, or set it yourself in the Cloudflare dashboard): %w", err)
	}
	return cur.Value, true, nil
}

// CloudflareUpsertRecord points hostname at ip through Cloudflare (proxied).
func CloudflareUpsertRecord(ctx context.Context, client *http.Client, token, zoneID, hostname, ip string) error {
	if ip == "" {
		return errors.New("no public IP to point the record at")
	}
	c := &Cloudflare{o: Options{Token: token, ZoneID: zoneID, Domain: hostname, Proxied: true, Client: orDefault(client)}, BaseURL: CloudflareAPI}
	return c.Upsert(ctx, ip)
}

func orDefault(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 30 * time.Second}
}
