package gui

import (
	"os"
	"path/filepath"
	"testing"

	"backhaul/internal/app"
	"backhaul/internal/config"
)

// exitNodeCode sets up a throwaway exit node and returns its pairing code.
func exitNodeCode(t *testing.T, endpoint string) string {
	t.Helper()
	res, err := app.SetupExitNode(config.Paths{Dir: t.TempDir()}, app.ExitNodeOptions{
		Endpoint: endpoint, Port: 443, Subnet: "10.9.0.0/24", ReachMode: config.ReachPortForward})
	if err != nil {
		t.Fatal(err)
	}
	return res.Blob
}

func TestNodeList(t *testing.T) {
	b := &Backend{Base: t.TempDir()}
	if len(b.Nodes()) != 0 || b.State().Connect.Configured {
		t.Fatal("fresh install should have no exit nodes")
	}
	home, office := exitNodeCode(t, "198.51.100.1"), exitNodeCode(t, "198.51.100.2")
	n1, err := b.AddNode(home, "Home")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.AddNode(office, ""); err != nil {
		t.Fatal(err)
	}
	ns := b.Nodes()
	if len(ns) != 2 || ns[0].Name != "Home" || ns[1].Name != "198.51.100.2" || !ns[1].Selected {
		t.Fatalf("list = %+v", ns)
	}
	if v := b.State(); !v.Connect.Configured || v.Connect.Endpoint != "198.51.100.2" {
		t.Fatalf("Connect should use the newest node: %+v", v.Connect)
	}
	if err := b.SelectNode(n1.ID); err != nil {
		t.Fatal(err)
	}
	if b.State().Connect.Endpoint != "198.51.100.1" {
		t.Fatal("selection not used")
	}
	// Re-pairing the same exit node updates it rather than adding a copy.
	if _, err := b.AddNode(home, ""); err != nil || len(b.Nodes()) != 2 {
		t.Fatalf("re-pair made a duplicate: %v %+v", err, b.Nodes())
	}
	if b.Nodes()[0].Name != "Home" {
		t.Fatal("re-pair lost the name")
	}
	if err := b.RenameNode(n1.ID, "Parents"); err != nil || b.Nodes()[0].Name != "Parents" {
		t.Fatal("rename failed")
	}
	if err := b.SetKillSwitch(false); err != nil {
		t.Fatal(err)
	}
	for _, id := range b.nodeIDs() {
		c, _, _ := config.Load(config.Paths{Dir: b.nodeDir(id)})
		if c.Client.KillSwitch {
			t.Fatal("kill-switch choice not applied to every node")
		}
	}
	if err := b.RemoveNode(n1.ID); err != nil {
		t.Fatal(err)
	}
	if ns := b.Nodes(); len(ns) != 1 || !ns[0].Selected || b.State().Connect.Endpoint != "198.51.100.2" {
		t.Fatalf("after remove: %+v", ns)
	}
	for _, bad := range []string{"../x", "", "ZZ"} {
		if b.SelectNode(bad) == nil || b.RemoveNode(bad) == nil {
			t.Fatalf("accepted bad id %q", bad)
		}
	}
}

// The single client profile of earlier versions joins the list.
func TestMigratesOldClientProfile(t *testing.T) {
	base := t.TempDir()
	cfg, sec, err := app.ImportBlob(exitNodeCode(t, "198.51.100.9"))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Save(config.Paths{Dir: filepath.Join(base, RoleConnect)}, cfg, sec); err != nil {
		t.Fatal(err)
	}
	b := &Backend{Base: base}
	ns := b.Nodes()
	if len(ns) != 1 || ns[0].Endpoint != "198.51.100.9" || !ns[0].Selected {
		t.Fatalf("not migrated: %+v", ns)
	}
	if _, err := os.Stat(filepath.Join(base, RoleConnect)); !os.IsNotExist(err) {
		t.Fatal("old profile dir still there")
	}
}
