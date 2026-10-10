package app

import (
	"context"
	"log/slog"
	"net/http"
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
