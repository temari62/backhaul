package gui

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"backhaul/internal/config"
	"backhaul/internal/ddns"
)

// fakeCloudflare models the parts of the Cloudflare API that Cloudflare
// Tunnel setup uses, with state, so re-running setup can be checked too.
type fakeCloudflare struct {
	t        *testing.T
	mu       sync.Mutex
	tunnels  map[string]string // name → id
	creates  int
	ingress  []map[string]any
	records  map[string]map[string]any // id → record
	nextID   int
	deletes  int
	tokenHit int
}

func (f *fakeCloudflare) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ok := func(v any) { b, _ := json.Marshal(map[string]any{"success": true, "result": v}); w.Write(b) }
	p := r.URL.Path
	switch {
	case p == "/zones" && r.URL.Query().Get("name") == "mydomain.com":
		ok([]map[string]any{{"id": "z9", "name": "mydomain.com", "status": "active", "account": map[string]string{"id": "acc1"}}})
	case p == "/zones":
		ok([]any{})
	case p == "/accounts/acc1/cfd_tunnel" && r.Method == http.MethodGet:
		var out []map[string]string
		if id, found := f.tunnels[r.URL.Query().Get("name")]; found {
			out = append(out, map[string]string{"id": id, "name": r.URL.Query().Get("name")})
		}
		ok(out)
	case p == "/accounts/acc1/cfd_tunnel" && r.Method == http.MethodPost:
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["config_src"] != "cloudflare" {
			f.t.Errorf("tunnel must be configured from Cloudflare's side: %v", body)
		}
		f.creates++
		f.tunnels[body["name"]] = "tun-1"
		ok(map[string]string{"id": "tun-1", "name": body["name"]})
	case p == "/accounts/acc1/cfd_tunnel/tun-1/configurations" && r.Method == http.MethodPut:
		var body struct {
			Config struct {
				Ingress []map[string]any `json:"ingress"`
			} `json:"config"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		f.ingress = body.Config.Ingress
		ok(map[string]any{})
	case p == "/accounts/acc1/cfd_tunnel/tun-1/token":
		f.tokenHit++
		ok("tunnel-token-xyz")
	case p == "/zones/z9/dns_records" && r.Method == http.MethodGet:
		var out []map[string]any
		for _, rec := range f.records {
			if rec["name"] == r.URL.Query().Get("name") {
				out = append(out, rec)
			}
		}
		ok(out)
	case p == "/zones/z9/dns_records" && r.Method == http.MethodPost:
		var rec map[string]any
		json.NewDecoder(r.Body).Decode(&rec)
		f.nextID++
		id := "r" + string(rune('0'+f.nextID))
		rec["id"] = id
		f.records[id] = rec
		ok(rec)
	case strings.HasPrefix(p, "/zones/z9/dns_records/") && r.Method == http.MethodDelete:
		delete(f.records, strings.TrimPrefix(p, "/zones/z9/dns_records/"))
		f.deletes++
		ok(map[string]string{})
	default:
		f.t.Errorf("unexpected %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"success":false,"errors":[{"message":"not found"}]}`))
	}
}

func TestSetupServeCloudflareTunnel(t *testing.T) {
	f := &fakeCloudflare{t: t, tunnels: map[string]string{}, records: map[string]map[string]any{
		// The hostname was used with the router-based Cloudflare mode before.
		"old": {"id": "old", "type": "A", "name": "home.mydomain.com", "content": "50.46.184.113", "proxied": true},
	}}
	api := httptest.NewServer(f)
	defer func() { go api.Close() }()
	old := ddns.CloudflareAPI
	ddns.CloudflareAPI = api.URL
	defer func() { ddns.CloudflareAPI = old }()

	b := &Backend{Base: t.TempDir()}
	p, err := b.SetupServe("home.mydomain.com", 8443, TransportCFTunnel, "cf-secret-token-123")
	if err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	if f.creates != 1 || len(f.ingress) != 2 || f.ingress[0]["hostname"] != "home.mydomain.com" ||
		f.ingress[0]["service"] != "https://127.0.0.1:47443" || f.ingress[1]["service"] != "http_status:404" {
		t.Fatalf("tunnel route: creates=%d ingress=%v", f.creates, f.ingress)
	}
	if or, _ := f.ingress[0]["originRequest"].(map[string]any); or["noTLSVerify"] != true {
		t.Fatalf("cloudflared must accept the exit node's self-signed certificate: %v", f.ingress[0])
	}
	if len(f.records) != 1 {
		t.Fatalf("records: %v", f.records)
	}
	for _, rec := range f.records {
		if rec["type"] != "CNAME" || rec["content"] != "tun-1.cfargotunnel.com" || rec["proxied"] != true {
			t.Fatalf("DNS must be a proxied CNAME to the tunnel: %v", rec)
		}
	}
	f.mu.Unlock()

	srv, ssec, err := config.Load(config.Paths{Dir: b.ProfileDir(RoleServe)})
	if err != nil {
		t.Fatal(err)
	}
	if srv.Reachability.Mode != config.ReachCFTunnel || srv.Reachability.CFTunnel.TunnelID != "tun-1" ||
		srv.DDNS.Provider != "" || ssec.CFTunnelToken != "tunnel-token-xyz" || srv.Transport.Port != 443 {
		t.Fatalf("exit node config: reach %+v ddns %+v port %d token %q", srv.Reachability, srv.DDNS, srv.Transport.Port, ssec.CFTunnelToken)
	}
	if v := b.State(); v.Serve.Transport != TransportCFTunnel {
		t.Fatalf("Share tab should say Cloudflare Tunnel, got %q", v.Serve.Transport)
	}

	// The client gets an ordinary Cloudflare exit node, and no secrets.
	raw, _ := base64.StdEncoding.DecodeString(p.Code)
	for _, secret := range []string{"cf-secret-token-123", "tunnel-token-xyz"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("pairing code contains %q", secret)
		}
	}
	if err := b.ImportPairing(p.Code); err != nil {
		t.Fatal(err)
	}
	cli, _, err := config.Load(config.Paths{Dir: b.ProfileDir(RoleConnect)})
	if err != nil {
		t.Fatal(err)
	}
	if cli.Transport.Kind != config.TransportCloudflare || cli.Transport.Port != 443 || cli.Reachability.Mode != config.ReachPortForward {
		t.Fatalf("client config: %+v / %+v", cli.Transport, cli.Reachability)
	}

	// Setting up again reuses the tunnel and the record.
	if err := b.Reset(RoleServe); err != nil {
		t.Fatal(err)
	}
	if _, err := b.SetupServe("home.mydomain.com", 443, TransportCFTunnel, "cf-secret-token-123"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.creates != 1 || len(f.records) != 1 {
		t.Fatalf("re-setup made duplicates: creates=%d records=%v", f.creates, f.records)
	}
}

// A token without the tunnel permission gets a clear explanation.
func TestCloudflareTunnelPermissionHint(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/zones" {
			w.Write([]byte(`{"success":true,"result":[{"id":"z9","name":"mydomain.com","status":"active","account":{"id":"acc1"}}]}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
	}))
	defer func() { go api.Close() }()
	old := ddns.CloudflareAPI
	ddns.CloudflareAPI = api.URL
	defer func() { ddns.CloudflareAPI = old }()

	b := &Backend{Base: t.TempDir()}
	_, err := b.SetupServe("home.mydomain.com", 443, TransportCFTunnel, "tok")
	if err == nil || !strings.Contains(err.Error(), "Account · Cloudflare Tunnel · Edit") {
		t.Fatalf("want the permission hint, got %v", err)
	}
}
