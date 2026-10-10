package ddns

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeCF is a minimal Cloudflare API: one zone, its SSL setting, A records.
type fakeCF struct {
	mu         sync.Mutex
	zoneName   string
	zoneStatus string
	ssl        string
	records    []map[string]any
	calls      []string
}

func (f *fakeCF) serve(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(403)
			io.WriteString(w, `{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}`)
			return
		}
		ok := func(v any) {
			b, _ := json.Marshal(map[string]any{"success": true, "result": v})
			w.Write(b)
		}
		switch {
		case r.URL.Path == "/zones":
			if r.URL.Query().Get("name") == f.zoneName {
				ok([]map[string]string{{"id": "z1", "name": f.zoneName, "status": f.zoneStatus}})
			} else {
				ok([]any{})
			}
		case r.URL.Path == "/zones/z1/settings/ssl" && r.Method == http.MethodGet:
			ok(map[string]string{"value": f.ssl})
		case r.URL.Path == "/zones/z1/settings/ssl" && r.Method == http.MethodPatch:
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			f.ssl = body["value"]
			ok(map[string]string{"value": f.ssl})
		case r.URL.Path == "/zones/z1/dns_records" && r.Method == http.MethodGet:
			ok(f.records)
		case r.URL.Path == "/zones/z1/dns_records" && r.Method == http.MethodPost:
			var rec map[string]any
			json.NewDecoder(r.Body).Decode(&rec)
			rec["id"] = "r1"
			f.records = append(f.records, rec)
			ok(rec)
		case strings.HasPrefix(r.URL.Path, "/zones/z1/dns_records/") && r.Method == http.MethodPatch:
			var rec map[string]any
			json.NewDecoder(r.Body).Decode(&rec)
			rec["id"] = "r1"
			f.records[0] = rec
			ok(rec)
		default:
			t.Errorf("unexpected call %s %s", r.Method, r.URL)
			w.WriteHeader(404)
		}
	}))
}

func withFakeCF(t *testing.T, f *fakeCF) {
	srv := f.serve(t)
	old := CloudflareAPI
	CloudflareAPI = srv.URL
	t.Cleanup(func() { CloudflareAPI = old; go srv.Close() })
}

func TestCloudflareZoneFromSubdomain(t *testing.T) {
	f := &fakeCF{zoneName: "example.com", zoneStatus: "active"}
	withFakeCF(t, f)
	id, name, err := CloudflareZone(context.Background(), nil, "tok", "vpn.home.example.com")
	if err != nil || id != "z1" || name != "example.com" {
		t.Fatalf("got %q %q %v", id, name, err)
	}
	if _, _, err := CloudflareZone(context.Background(), nil, "tok", "vpn.other.org"); err == nil {
		t.Fatal("unknown domain must fail with guidance")
	}
	if _, _, err := CloudflareZone(context.Background(), nil, "wrong", "vpn.example.com"); err == nil {
		t.Fatal("bad token must fail")
	}
}

func TestCloudflareZoneNotYetActive(t *testing.T) {
	f := &fakeCF{zoneName: "example.com", zoneStatus: "pending"}
	withFakeCF(t, f)
	_, _, err := CloudflareZone(context.Background(), nil, "tok", "vpn.example.com")
	if err == nil || !strings.Contains(err.Error(), "nameservers") {
		t.Fatalf("pending zone must explain the nameserver step, got %v", err)
	}
}

func TestCloudflareEnsureSSL(t *testing.T) {
	for start, wantChanged := range map[string]bool{"flexible": true, "off": true, "strict": true, "full": false} {
		f := &fakeCF{zoneName: "example.com", zoneStatus: "active", ssl: start}
		withFakeCF(t, f)
		prev, changed, err := CloudflareEnsureSSL(context.Background(), nil, "tok", "z1")
		if err != nil || prev != start || changed != wantChanged || f.ssl != "full" {
			t.Errorf("%s: prev=%q changed=%v now=%q err=%v", start, prev, changed, f.ssl, err)
		}
	}
}

func TestCloudflareUpsertProxiedRecord(t *testing.T) {
	f := &fakeCF{zoneName: "example.com", zoneStatus: "active"}
	withFakeCF(t, f)
	if err := CloudflareUpsertRecord(context.Background(), nil, "tok", "z1", "vpn.example.com", "50.46.184.113"); err != nil {
		t.Fatal(err)
	}
	r := f.records[0]
	if r["proxied"] != true || r["content"] != "50.46.184.113" || r["ttl"] != float64(1) {
		t.Fatalf("record not proxied/auto-TTL: %v", r)
	}
	// An existing grey-cloud record with the same IP must still be switched to proxied.
	f.records[0]["proxied"] = false
	if err := CloudflareUpsertRecord(context.Background(), nil, "tok", "z1", "vpn.example.com", "50.46.184.113"); err != nil {
		t.Fatal(err)
	}
	if f.records[0]["proxied"] != true || !strings.HasPrefix(f.calls[len(f.calls)-1], "PATCH") {
		t.Fatalf("unproxied record not fixed: %v (calls %v)", f.records[0], f.calls)
	}
}
