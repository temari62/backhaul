package gui

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"backhaul/internal/app"
	"backhaul/internal/config"
)

// Node is one saved exit node in the Connect list. Each is a complete client
// profile in <base>/nodes/<id>; the selected one is what Connect uses.
type Node struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Endpoint  string `json:"endpoint"`
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	PairingID string `json:"pairingId,omitempty"`
	Selected  bool   `json:"selected"`
	ConfigErr string `json:"configError,omitempty"`
	added     int64  // sort key: creation time
}

const legacyNodeID = "cli" // a client profile made by the CLI in the base dir

func (b *Backend) nodesDir() string { return filepath.Join(b.Base, "nodes") }

func (b *Backend) nodeDir(id string) string {
	if id == legacyNodeID {
		return b.Base
	}
	return filepath.Join(b.nodesDir(), id)
}

func validNodeID(id string) bool {
	if id == legacyNodeID {
		return true
	}
	if id == "" || len(id) > 32 {
		return false
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// migrateNodes moves the single client profile of earlier versions
// (<base>/connect) into the list, once.
func (b *Backend) migrateNodes() {
	b.migrateOnce.Do(func() {
		old := filepath.Join(b.Base, RoleConnect)
		if _, err := os.Stat(filepath.Join(old, "config.toml")); err != nil {
			return
		}
		id := newNodeID()
		if err := os.MkdirAll(b.nodesDir(), 0o700); err != nil {
			return
		}
		if err := os.Rename(old, b.nodeDir(id)); err != nil {
			slog.Warn("could not move the saved exit node into the list", "err", err)
			return
		}
		_ = b.writeSelected(id)
	})
}

func newNodeID() string {
	var r [6]byte
	_, _ = rand.Read(r[:])
	return hex.EncodeToString(r[:])
}

func (b *Backend) nodeIDs() []string {
	b.migrateNodes()
	var ids []string
	if mode, err := readMode(b.Base); err == nil && mode == RoleConnect {
		ids = append(ids, legacyNodeID)
	}
	ents, _ := os.ReadDir(b.nodesDir())
	for _, e := range ents {
		if e.IsDir() && validNodeID(e.Name()) {
			if _, err := os.Stat(filepath.Join(b.nodesDir(), e.Name(), "config.toml")); err == nil {
				ids = append(ids, e.Name())
			}
		}
	}
	return ids
}

func (b *Backend) writeSelected(id string) error {
	if err := os.MkdirAll(b.nodesDir(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(b.nodesDir(), "selected"), []byte(id), 0o600)
}

// selectedNode is the chosen node, or the first one, or "" if none exist.
func (b *Backend) selectedNode() string {
	ids := b.nodeIDs()
	raw, _ := os.ReadFile(filepath.Join(b.nodesDir(), "selected"))
	want := strings.TrimSpace(string(raw))
	for _, id := range ids {
		if id == want {
			return id
		}
	}
	if len(ids) > 0 {
		return ids[0]
	}
	return ""
}

// connectDir is the profile Connect uses: the selected node's.
func (b *Backend) connectDir() string {
	if id := b.selectedNode(); id != "" {
		return b.nodeDir(id)
	}
	return filepath.Join(b.nodesDir(), "none") // no config there: "not configured"
}

// Nodes lists the saved exit nodes, oldest first.
func (b *Backend) Nodes() []Node {
	sel := b.selectedNode()
	out := []Node{} // never null in JSON: the page reads .length
	for _, id := range b.nodeIDs() {
		dir := b.nodeDir(id)
		n := Node{ID: id, Selected: id == sel}
		if st, err := os.Stat(filepath.Join(dir, "config.toml")); err == nil {
			n.added = st.ModTime().UnixNano()
		}
		cfg, _, err := config.Load(config.Paths{Dir: dir})
		if err != nil {
			msg, _, _ := strings.Cut(err.Error(), "\n")
			n.ConfigErr = msg
		} else {
			n.Endpoint, n.Port, _ = cfg.RemoteHost()
			n.Transport = cfg.Transport.Kind
			n.PairingID = pairingID(cfg)
		}
		if raw, err := os.ReadFile(filepath.Join(dir, "name.txt")); err == nil {
			n.Name = strings.TrimSpace(string(raw))
		}
		if n.Name == "" {
			n.Name = n.Endpoint
		}
		if id != legacyNodeID {
			if st, err := os.Stat(filepath.Join(b.nodesDir(), id, "added")); err == nil {
				n.added = st.ModTime().UnixNano()
			}
		}
		out = append(out, n)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].added < out[j].added })
	return out
}

func pairingID(cfg *config.Config) string {
	if cfg.Transport.Kind == config.TransportReality && len(cfg.Transport.Reality.PublicKey) >= 11 {
		return cfg.Transport.Reality.PublicKey[:11]
	}
	if fp := cfg.Transport.TLSSHA256; len(fp) >= 11 {
		return fp[:11]
	}
	return ""
}

// AddNode saves a pairing code as a new exit node and selects it. If the
// code is for an exit node already in the list (same pairing ID), that entry
// is updated instead of duplicated.
func (b *Backend) AddNode(blob, name string) (Node, error) {
	if err := b.notRunning(RoleConnect); err != nil {
		return Node{}, err
	}
	cfg, sec, err := app.ImportBlob(blob)
	if err != nil {
		return Node{}, fmt.Errorf("that doesn't look like a valid pairing code: %w", err)
	}
	// New nodes keep the user's kill-switch choice.
	if cur, _, err := config.Load(config.Paths{Dir: b.connectDir()}); err == nil {
		cfg.Client.KillSwitch = cur.Client.KillSwitch
	}
	id := ""
	pid := pairingID(cfg)
	for _, n := range b.Nodes() {
		if pid != "" && n.PairingID == pid && n.Endpoint == cfg.Transport.Endpoint {
			id = n.ID // same exit node, re-paired: replace in place
		}
	}
	if id == "" {
		id = newNodeID()
	}
	p := config.Paths{Dir: b.nodeDir(id)}
	if err := config.Save(p, cfg, sec); err != nil {
		return Node{}, err
	}
	if id != legacyNodeID {
		if _, err := os.Stat(filepath.Join(p.Dir, "added")); err != nil {
			_ = os.WriteFile(filepath.Join(p.Dir, "added"), nil, 0o600)
		}
	}
	if name = strings.TrimSpace(name); name != "" {
		_ = os.WriteFile(filepath.Join(p.Dir, "name.txt"), []byte(name), 0o600)
	}
	if err := b.writeSelected(id); err != nil {
		return Node{}, err
	}
	slog.Info("exit node saved", "name", name, "endpoint", cfg.Transport.Endpoint)
	for _, n := range b.Nodes() {
		if n.ID == id {
			return n, nil
		}
	}
	return Node{ID: id}, nil
}

// SelectNode chooses the exit node Connect uses.
func (b *Backend) SelectNode(id string) error {
	if !validNodeID(id) {
		return errors.New("unknown exit node")
	}
	b.mu.Lock()
	running := b.running == RoleConnect
	b.mu.Unlock()
	if running && id != b.selectedNode() {
		return errors.New("disconnect first, then choose another exit node")
	}
	for _, n := range b.nodeIDs() {
		if n == id {
			return b.writeSelected(id)
		}
	}
	return errors.New("unknown exit node")
}

// RenameNode sets a node's display name.
func (b *Backend) RenameNode(id, name string) error {
	if !validNodeID(id) {
		return errors.New("unknown exit node")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("enter a name")
	}
	return os.WriteFile(filepath.Join(b.nodeDir(id), "name.txt"), []byte(name), 0o600)
}

// RemoveNode forgets an exit node.
func (b *Backend) RemoveNode(id string) error {
	if !validNodeID(id) {
		return errors.New("unknown exit node")
	}
	b.mu.Lock()
	running := b.running == RoleConnect
	b.mu.Unlock()
	if running && id == b.selectedNode() {
		return errors.New("disconnect first")
	}
	if id == legacyNodeID {
		for _, f := range []string{"config.toml", "secrets.toml", "name.txt"} {
			os.Remove(filepath.Join(b.Base, f))
		}
		return nil
	}
	return os.RemoveAll(b.nodeDir(id))
}

// ProfileDirs lists every profile directory (for crash recovery at start).
func (b *Backend) ProfileDirs() []string {
	dirs := []string{b.ProfileDir(RoleServe)}
	for _, id := range b.nodeIDs() {
		dirs = append(dirs, b.nodeDir(id))
	}
	return dirs
}
