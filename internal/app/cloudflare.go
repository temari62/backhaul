package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"backhaul/internal/ddns"
)

// CloudflareResult describes what PrepareCloudflare set up.
type CloudflareResult struct {
	ZoneID, ZoneName string
	PublicIP         string
	PrevSSL          string
	SSLChanged       bool
}

// PrepareCloudflare readies a Cloudflare zone for the exit node: finds the
// zone holding hostname, makes sure its SSL/TLS mode is "Full" (HTTPS to the
// exit node with its self-signed certificate), and points hostname at this
// PC's public IP through Cloudflare (proxied). The exit node's DDNS updater
// keeps that record current afterwards.
func PrepareCloudflare(ctx context.Context, token, hostname, ipCheckURL string) (*CloudflareResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 20 * time.Second}
	id, name, err := ddns.CloudflareZone(ctx, client, token, hostname)
	if err != nil {
		return nil, err
	}
	res := &CloudflareResult{ZoneID: id, ZoneName: name}
	if res.PrevSSL, res.SSLChanged, err = ddns.CloudflareEnsureSSL(ctx, client, token, id); err != nil {
		return nil, err
	}
	if res.SSLChanged {
		slog.Warn("changed the Cloudflare SSL/TLS mode so it can reach the exit node", "zone", name, "from", res.PrevSSL, "to", "full")
	}
	if res.PublicIP, err = ddns.PublicIP(ctx, client, ipCheckURL); err != nil {
		return nil, err
	}
	if err := ddns.CloudflareUpsertRecord(ctx, client, token, id, hostname, res.PublicIP); err != nil {
		return nil, err
	}
	slog.Info("Cloudflare record ready", "hostname", hostname, "points_to", res.PublicIP, "proxied", true)
	return res, nil
}

// TunnelResult describes what PrepareCloudflareTunnel set up.
type TunnelResult struct {
	ZoneID, ZoneName, AccountID string
	TunnelID, TunnelToken       string
}

// PrepareCloudflareTunnel readies Cloudflare Tunnel mode: finds the zone
// and its account, creates (or reuses) the tunnel "backhaul-<hostname>",
// routes hostname through it to the exit node's local wstunnel server on
// 127.0.0.1:localPort, points hostname's DNS at the tunnel (proxied CNAME),
// and fetches the token cloudflared runs it with.
func PrepareCloudflareTunnel(ctx context.Context, token, hostname string, localPort int) (*TunnelResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 20 * time.Second}
	var r TunnelResult
	var err error
	if r.ZoneID, r.ZoneName, r.AccountID, err = ddns.CloudflareZoneAccount(ctx, client, token, hostname); err != nil {
		return nil, err
	}
	if r.AccountID == "" {
		return nil, errors.New("cloudflare: could not tell which account owns the zone")
	}
	if r.TunnelID, err = ddns.CloudflareEnsureTunnel(ctx, client, token, r.AccountID, ddns.TunnelName(hostname)); err != nil {
		return nil, err
	}
	service := "https://127.0.0.1:" + strconv.Itoa(localPort)
	if err := ddns.CloudflareTunnelRoute(ctx, client, token, r.AccountID, r.TunnelID, hostname, service); err != nil {
		return nil, err
	}
	if err := ddns.CloudflarePointToTunnel(ctx, client, token, r.ZoneID, hostname, r.TunnelID); err != nil {
		return nil, err
	}
	if r.TunnelToken, err = ddns.CloudflareTunnelToken(ctx, client, token, r.AccountID, r.TunnelID); err != nil {
		return nil, err
	}
	slog.Info("Cloudflare Tunnel ready", "hostname", hostname, "tunnel", ddns.TunnelName(hostname))
	return &r, nil
}
