package gui

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"backhaul/internal/config"
	"backhaul/internal/ddns"
)

func TestSetupServeCloudflareEndToEnd(t *testing.T) {
	var record map[string]any
	ssl := "flexible"
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok := func(v any) { b, _ := json.Marshal(map[string]any{"success": true, "result": v}); w.Write(b) }
		switch {
		case r.URL.Path == "/zones" && r.URL.Query().Get("name") == "mydomain.com":
			ok([]map[string]string{{"id": "z9", "name": "mydomain.com", "status": "active"}})
		case r.URL.Path == "/zones":
			ok([]any{})
		case r.URL.Path == "/zones/z9/settings/ssl" && r.Method == http.MethodGet:
			ok(map[string]string{"value": ssl})
		case r.URL.Path == "/zones/z9/settings/ssl":
			ssl = "full"
			ok(map[string]string{"value": ssl})
		case r.URL.Path == "/zones/z9/dns_records" && r.Method == http.MethodGet:
			ok([]any{})
		case r.URL.Path == "/zones/z9/dns_records" && r.Method == http.MethodPost:
			json.NewDecoder(r.Body).Decode(&record)
			ok(record)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
		}
	}))
	defer func() { go api.Close() }()
	ip := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "50.46.184.113") }))
	defer func() { go ip.Close() }()
	old := ddns.CloudflareAPI
	ddns.CloudflareAPI = api.URL
	defer func() { ddns.CloudflareAPI = old }()

	b := &Backend{Base: t.TempDir(), IPCheckURL: ip.URL}
	if _, err := b.SetupServe("vpn.mydomain.com", 443, config.TransportCloudflare, ""); err == nil {
		t.Fatal("missing token must be rejected")
	}
	if _, err := b.SetupServe("50.46.184.113", 443, config.TransportCloudflare, "cf-secret-token-123"); err == nil {
		t.Fatal("an IP instead of a hostname must be rejected")
	}
	p, err := b.SetupServe("https://vpn.mydomain.com/", 443, config.TransportCloudflare, "cf-secret-token-123")
	if err != nil {
		t.Fatal(err)
	}
	if ssl != "full" || record["proxied"] != true || record["content"] != "50.46.184.113" || record["name"] != "vpn.mydomain.com" {
		t.Fatalf("Cloudflare not prepared: ssl=%s record=%v", ssl, record)
	}
	srv, sec, err := config.Load(config.Paths{Dir: b.ProfileDir(RoleServe)})
	if err != nil {
		t.Fatal(err)
	}
	if srv.Transport.Kind != config.TransportCloudflare || srv.DDNS.Provider != "cloudflare" || !srv.DDNS.Proxied ||
		srv.DDNS.ZoneID != "z9" || sec.DDNSToken != "cf-secret-token-123" {
		t.Fatalf("exit node config: %+v / ddns %+v", srv.Transport, srv.DDNS)
	}
	if err := b.ImportPairing(p.Code); err != nil {
		t.Fatal(err)
	}
	cli, csec, err := config.Load(config.Paths{Dir: b.ProfileDir(RoleConnect)})
	if err != nil {
		t.Fatal(err)
	}
	if cli.Transport.Kind != config.TransportCloudflare || cli.Transport.Endpoint != "vpn.mydomain.com" || cli.Transport.Port != 443 {
		t.Fatalf("client config: %+v", cli.Transport)
	}
	raw, _ := base64.StdEncoding.DecodeString(p.Code)
	if csec.DDNSToken != "" || len(raw) == 0 || strings.Contains(string(raw), "cf-secret-token-123") {
		t.Fatal("the Cloudflare token must never reach the client")
	}
	// The pairing ID shown on both PCs must match, so users can tell they
	// picked the right exit node.
	v := b.State()
	if v.Serve.PairingID == "" || len(v.Nodes) != 1 || v.Nodes[0].PairingID != v.Serve.PairingID || v.Nodes[0].Port != 443 {
		t.Fatalf("pairing ID/port differ: exit node %q, client %+v", v.Serve.PairingID, v.Nodes)
	}
}
