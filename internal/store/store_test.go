package store

import (
	"errors"
	"path/filepath"
	"testing"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustCreate(t *testing.T, s *Store, node, name string) *Interface {
	t.Helper()
	i := &Interface{Node: node, Name: name, PrivateKey: "k", Address: "10.0.0.1/24", ListenPort: 51820, Enabled: true}
	if err := s.CreateInterface(i); err != nil {
		t.Fatal(err)
	}
	return i
}

func TestInterfaceCRUD(t *testing.T) {
	s := open(t)
	mustCreate(t, s, "", "wg0")

	got, err := s.GetInterface("", "wg0")
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != "10.0.0.1/24" || got.ListenPort != 51820 || got.ConfigVersion != 1 || !got.Enabled {
		t.Errorf("unexpected interface: %+v", got)
	}
	if _, err := s.GetInterface("", "wg9"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}

	list, err := s.ListInterfaces("")
	if err != nil || len(list) != 1 {
		t.Errorf("ListInterfaces = %v, %v", list, err)
	}

	if err := s.DeleteInterface("", "wg0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetInterface("", "wg0"); !errors.Is(err, ErrNotFound) {
		t.Error("interface should be gone")
	}
}

func TestSameNameOnDifferentNodes(t *testing.T) {
	s := open(t)
	mustCreate(t, s, "n1", "wg0")
	mustCreate(t, s, "n2", "wg0")

	for _, node := range []string{"n1", "n2"} {
		ifc, err := s.GetInterface(node, "wg0")
		if err != nil || ifc.Node != node {
			t.Errorf("GetInterface(%s) = %+v, %v", node, ifc, err)
		}
	}
	all, _ := s.ListInterfaces("")
	if len(all) != 2 {
		t.Errorf("ListInterfaces('') = %d rows, want 2 (all nodes)", len(all))
	}
	if err := s.DeleteInterface("n1", "wg0"); err != nil {
		t.Fatal(err)
	}
	one, _ := s.ListInterfaces("n2")
	if len(one) != 1 {
		t.Error("n2 interface should remain")
	}
}

func TestPeerLifecycleAndCascade(t *testing.T) {
	s := open(t)
	mustCreate(t, s, "", "wg0")
	p := &Peer{Interface: "wg0", Name: "laptop", PublicKey: "pub1", AllowedIPs: "10.0.0.2/32"}
	if err := s.AddPeer(p); err != nil {
		t.Fatal(err)
	}
	if p.ID == 0 {
		t.Error("AddPeer should set ID")
	}

	got, err := s.GetPeer("", "wg0", "laptop")
	if err != nil || got.AllowedIPs != "10.0.0.2/32" {
		t.Fatalf("GetPeer = %+v, %v", got, err)
	}
	if _, err := s.GetPeer("", "wg0", "pub1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPeer("", "wg0", "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPeer("", "wg0", "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}

	if err := s.DeleteInterface("", "wg0"); err != nil {
		t.Fatal(err)
	}
	if peers, _ := s.ListPeers("", "wg0"); len(peers) != 0 {
		t.Errorf("peers should cascade-delete, got %d", len(peers))
	}
}

func TestPeerMutationBumpsVersion(t *testing.T) {
	s := open(t)
	mustCreate(t, s, "", "wg0")
	version := func() int64 {
		i, err := s.GetInterface("", "wg0")
		if err != nil {
			t.Fatal(err)
		}
		return i.ConfigVersion
	}
	v0 := version()
	if err := s.AddPeer(&Peer{Interface: "wg0", Name: "a", PublicKey: "pubA", AllowedIPs: "10.0.0.2/32"}); err != nil {
		t.Fatal(err)
	}
	if v := version(); v != v0+1 {
		t.Errorf("version after add = %d, want %d", v, v0+1)
	}
	if _, err := s.DeletePeer("", "wg0", "a"); err != nil {
		t.Fatal(err)
	}
	if v := version(); v != v0+2 {
		t.Errorf("version after delete = %d, want %d", v, v0+2)
	}
	if err := s.SetEnabled("", "wg0", false); err != nil {
		t.Fatal(err)
	}
	ifc, _ := s.GetInterface("", "wg0")
	if ifc.Enabled || ifc.ConfigVersion != v0+3 {
		t.Errorf("SetEnabled: enabled=%v version=%d", ifc.Enabled, ifc.ConfigVersion)
	}
}

func TestNodeRegistry(t *testing.T) {
	s := open(t)
	if err := s.EnsureNode("n1", "AA:BB"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureNode("n1", "CC:DD"); err != nil { // upsert fingerprint
		t.Fatal(err)
	}
	if err := s.EnsureNode("n2", "EE:FF"); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchNode("n1", "2026-08-27T10:00:00Z"); err != nil {
		t.Fatal(err)
	}
	nodes, err := s.ListNodes()
	if err != nil || len(nodes) != 2 {
		t.Fatalf("ListNodes = %v, %v", nodes, err)
	}
	for _, n := range nodes {
		if n.Name == "n1" && (n.Fingerprint != "CC:DD" || n.LastSeen != "2026-08-27T10:00:00Z") {
			t.Errorf("n1 = %+v", n)
		}
	}
}

func TestConfigVersionPerNode(t *testing.T) {
	s := open(t)
	if v, err := s.ConfigVersion("n1"); err != nil || v != 0 {
		t.Fatalf("empty node version = %d, %v", v, err)
	}
	mustCreate(t, s, "n1", "wg0")
	if v, _ := s.ConfigVersion("n1"); v != 1 {
		t.Errorf("n1 version = %d, want 1", v)
	}
	if v, _ := s.ConfigVersion("n2"); v != 0 {
		t.Errorf("n2 version = %d, want 0", v)
	}
}
