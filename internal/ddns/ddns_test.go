package ddns

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDuckDNS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("domains") != "myhome" || r.URL.Query().Get("token") != "tok" {
			io.WriteString(w, "KO")
			return
		}
		io.WriteString(w, "OK\n198.51.100.4\n\nUPDATED")
	}))
	defer func() { go srv.Close() }()
	u, _ := New(Options{Provider: "duckdns", Domain: "myhome.duckdns.org", Token: "tok"})
	u.(*DuckDNS).BaseURL = srv.URL
	ip, err := u.Update(context.Background())
	if err != nil || ip != "198.51.100.4" {
		t.Fatalf("ip=%q err=%v", ip, err)
	}
	u.(*DuckDNS).o.Token = "wrong"
	if _, err := u.Update(context.Background()); err == nil || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("expected rejection without token in message, got %v", err)
	}
}

func TestCloudflareCreatesThenPatches(t *testing.T) {
	var records []map[string]any
	var calls []string
	ipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "198.51.100.9\n") }))
	defer func() { go ipSrv.Close() }()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method)
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(403)
			io.WriteString(w, `{"success":false,"errors":[{"message":"auth"}]}`)
			return
		}
		switch r.Method {
		case http.MethodGet:
			b, _ := json.Marshal(map[string]any{"success": true, "result": records})
			w.Write(b)
		case http.MethodPost:
			var rec map[string]any
			json.NewDecoder(r.Body).Decode(&rec)
			rec["id"] = "r1"
			records = append(records, rec)
			io.WriteString(w, `{"success":true,"result":{}}`)
		case http.MethodPatch:
			if !strings.HasSuffix(r.URL.Path, "/dns_records/r1") {
				t.Errorf("patch path %s", r.URL.Path)
			}
			io.WriteString(w, `{"success":true,"result":{}}`)
		}
	}))
	defer func() { go api.Close() }()
	u, _ := New(Options{Provider: "cloudflare", Domain: "home.example.com", Token: "tok", ZoneID: "z", IPCheckURL: ipSrv.URL})
	u.(*Cloudflare).BaseURL = api.URL
	if ip, err := u.Update(context.Background()); err != nil || ip != "198.51.100.9" {
		t.Fatalf("create: %q %v", ip, err)
	}
	records[0]["content"] = "203.0.113.1" // home IP changed
	if _, err := u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, ",") != "GET,POST,GET,PATCH" {
		t.Fatalf("calls %v", calls)
	}
}
