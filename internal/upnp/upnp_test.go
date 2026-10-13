package upnp

import (
	"context"
	"errors"
	"fmt"
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
	conflict      bool   // answer UPnP 718
	holder        string // who holds the port
}

func (f *fakeGW) AddPortMappingCtx(_ context.Context, _ string, _ uint16, _ string, _ uint16, client string, _ bool, _ string, lease uint32) error {
	if f.conflict {
		return errors.New("SOAP fault: UPnPError 718 ConflictInMappingEntry")
	}
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

func (f *fakeGW) GetSpecificPortMappingEntryCtx(context.Context, string, uint16, string) (uint16, string, bool, string, uint32, error) {
	if f.holder == "" {
		return 0, "", false, "", 0, errors.New("714 NoSuchEntryInArray")
	}
	return 443, f.holder, true, "Backhaul exit node", 0, nil
}

// A port already forwarded elsewhere (UPnP 718) is reported with its holder.
func TestConflictNamesTheOtherDevice(t *testing.T) {
	gw := &fakeGW{conflict: true, holder: "192.168.88.13"}
	m := &Mapping{gw: gw, port: 443, lanIP: "192.168.88.45", lease: 3600}
	err := m.add(context.Background())
	if err == nil || !isConflict(err) {
		t.Fatalf("want a conflict, got %v", err)
	}
	_, holder, _, desc, _, _ := gw.GetSpecificPortMappingEntryCtx(context.Background(), "", 443, "TCP")
	ce := &ConflictError{Port: 443, Holder: holder, Desc: desc}
	if got := ce.Error(); got != "port 443 is already forwarded to 192.168.88.13 (Backhaul exit node)" {
		t.Fatal(got)
	}
	var target *ConflictError
	if !errors.As(fmt.Errorf("router refused the port forward: %w", ce), &target) || target.Holder != "192.168.88.13" {
		t.Fatal("ConflictError not reachable with errors.As")
	}
}
