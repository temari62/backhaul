package upnp

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBehindCarrierNAT(t *testing.T) {
	for ip, want := range map[string]bool{
		"100.64.1.2": true, "100.127.255.1": true, "10.0.0.5": true, "192.168.1.1": true, "172.16.0.1": true,
		"50.46.184.113": false, "8.8.8.8": false, "100.128.0.1": false, "garbage": false,
	} {
		if got := BehindCarrierNAT(ip); got != want {
			t.Errorf("%s: got %v want %v", ip, got, want)
		}
	}
}

type fakeGW struct {
	permanentOnly bool
	adds, deletes int
	lastLease     uint32
	lastClient    string
}

func (f *fakeGW) AddPortMappingCtx(_ context.Context, _ string, _ uint16, _ string, _ uint16, client string, _ bool, _ string, lease uint32) error {
	if f.permanentOnly && lease != 0 {
		return errors.New("725 OnlyPermanentLeasesSupported")
	}
	f.adds++
	f.lastLease, f.lastClient = lease, client
	return nil
}
func (f *fakeGW) DeletePortMappingCtx(context.Context, string, uint16, string) error {
	f.deletes++
	return nil
}
func (f *fakeGW) GetExternalIPAddressCtx(context.Context) (string, error) {
	return "50.46.184.113", nil
}

func TestMappingFallsBackToPermanentAndCleansUp(t *testing.T) {
	gw := &fakeGW{permanentOnly: true}
	m := &Mapping{gw: gw, port: 443, lanIP: "192.168.1.20", lease: 3600}
	if err := m.add(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gw.lastLease != 0 || gw.lastClient != "192.168.1.20" || m.lease != 0 {
		t.Fatalf("expected permanent mapping to the LAN IP, got lease %d client %s", gw.lastLease, gw.lastClient)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.KeepAlive(ctx) // returns at once and removes the mapping
	if gw.deletes != 1 {
		t.Fatalf("mapping not removed on stop (deletes=%d)", gw.deletes)
	}
}

// On a network without a UPnP router (like a datacenter host), Open must
// give up by its deadline instead of hanging serve's startup.
func TestOpenReturnsByDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	m, err := Open(ctx, 443, "192.0.2.10")
	if took := time.Since(start); took > 4*time.Second {
		t.Fatalf("Open took %s", took)
	}
	if err == nil {
		m.KeepAlive(ctx) // a real router answered: clean up after ourselves
		t.Skip("a UPnP router is present on this network")
	}
	t.Logf("as expected without a router: %v", err)
}
