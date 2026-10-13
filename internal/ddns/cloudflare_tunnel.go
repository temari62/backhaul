package ddns

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Cloudflare Tunnel: the exit node keeps an outgoing connection to
// Cloudflare (cloudflared), and Cloudflare sends the client's traffic down
// it — so no router port forward is needed. These calls create the tunnel,
// route the hostname to the local wstunnel server, and point DNS at it.
// The API token needs Account · Cloudflare Tunnel · Edit on top of the
// permissions the plain Cloudflare mode uses.

func (c *Cloudflare) tunnelPath(accountID string, rest ...string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/cfd_tunnel"
	for _, r := range rest {
		p += "/" + url.PathEscape(r)
	}
	return p
}

func newCF(client *http.Client, token string) *Cloudflare {
	return &Cloudflare{o: Options{Token: token, Client: orDefault(client)}, BaseURL: CloudflareAPI}
}

// TunnelName is the name Backhaul gives the tunnel for hostname.
func TunnelName(hostname string) string { return "backhaul-" + strings.ToLower(hostname) }

// CloudflareEnsureTunnel returns the ID of the tunnel called name, creating
// it (configured from Cloudflare's side) if it doesn't exist yet.
func CloudflareEnsureTunnel(ctx context.Context, client *http.Client, token, accountID, name string) (string, error) {
	c := newCF(client, token)
	var found []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	q := "?is_deleted=false&name=" + url.QueryEscape(name)
	if err := c.call(ctx, http.MethodGet, c.tunnelPath(accountID)+q, nil, &found); err != nil {
		return "", tunnelPermission(err)
	}
	for _, t := range found {
		if t.Name == name && t.ID != "" {
			return t.ID, nil
		}
	}
	var created struct {
		ID string `json:"id"`
	}
	body := map[string]any{"name": name, "config_src": "cloudflare"}
	if err := c.call(ctx, http.MethodPost, c.tunnelPath(accountID), body, &created); err != nil {
		return "", tunnelPermission(err)
	}
	if created.ID == "" {
		return "", fmt.Errorf("cloudflare: the new tunnel has no ID")
	}
	return created.ID, nil
}

// CloudflareTunnelToken returns the token cloudflared runs the tunnel with.
func CloudflareTunnelToken(ctx context.Context, client *http.Client, token, accountID, tunnelID string) (string, error) {
	c := newCF(client, token)
	var t string
	if err := c.call(ctx, http.MethodGet, c.tunnelPath(accountID, tunnelID, "token"), nil, &t); err != nil {
		return "", tunnelPermission(err)
	}
	if t == "" {
		return "", fmt.Errorf("cloudflare: empty tunnel token")
	}
	return t, nil
}

// CloudflareTunnelRoute sends hostname's traffic down the tunnel to service
// (the local wstunnel server). Its certificate is the exit node's own
// self-signed one, which cloudflared is told to accept.
func CloudflareTunnelRoute(ctx context.Context, client *http.Client, token, accountID, tunnelID, hostname, service string) error {
	c := newCF(client, token)
	cfg := map[string]any{"config": map[string]any{"ingress": []map[string]any{
		{"hostname": hostname, "service": service, "originRequest": map[string]any{"noTLSVerify": true}},
		{"service": "http_status:404"},
	}}}
	return tunnelPermission(c.call(ctx, http.MethodPut, c.tunnelPath(accountID, tunnelID, "configurations"), cfg, nil))
}

// CloudflarePointToTunnel makes hostname a proxied CNAME to the tunnel,
// replacing any A/AAAA/CNAME record it had (e.g. from the router-based
// Cloudflare mode).
func CloudflarePointToTunnel(ctx context.Context, client *http.Client, token, zoneID, hostname, tunnelID string) error {
	c := newCF(client, token)
	zone := "/zones/" + url.PathEscape(zoneID) + "/dns_records"
	target := tunnelID + ".cfargotunnel.com"
	var recs []struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Content string `json:"content"`
		Proxied bool   `json:"proxied"`
	}
	if err := c.call(ctx, http.MethodGet, zone+"?name="+url.QueryEscape(hostname), nil, &recs); err != nil {
		return err
	}
	have := false
	for _, r := range recs {
		switch {
		case r.Type == "CNAME" && strings.EqualFold(r.Content, target) && r.Proxied && !have:
			have = true
		case r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME":
			if err := c.call(ctx, http.MethodDelete, zone+"/"+url.PathEscape(r.ID), nil, nil); err != nil {
				return err
			}
		}
	}
	if have {
		return nil
	}
	rec := map[string]any{"type": "CNAME", "name": hostname, "content": target, "proxied": true, "ttl": 1}
	return c.call(ctx, http.MethodPost, zone, rec, nil)
}

// tunnelPermission explains the usual cause of a refused tunnel call.
func tunnelPermission(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	if strings.Contains(s, "403") || strings.Contains(s, "10000") || strings.Contains(strings.ToLower(s), "authentication") {
		return fmt.Errorf("%w — the API token needs the permission Account · Cloudflare Tunnel · Edit (edit the token in Cloudflare → My Profile → API Tokens)", err)
	}
	return err
}
