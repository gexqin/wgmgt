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

func TestInterfaceCRUD(t *testing.T) {
	s := open(t)
	i := &Interface{Name: "wg0", PrivateKey: "k", Address: "10.0.0.1/24", ListenPort: 51820}
	if err := s.CreateInterface(i); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetInterface("wg0")
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != "10.0.0.1/24" || got.ListenPort != 51820 || got.ConfigVersion != 1 {
		t.Errorf("unexpected interface: %+v", got)
	}

	if _, err := s.GetInterface("wg9"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}

	list, err := s.ListInterfaces()
	if err != nil || len(list) != 1 {
		t.Errorf("ListInterfaces = %v, %v", list, err)
	}

	if err := s.DeleteInterface("wg0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetInterface("wg0"); !errors.Is(err, ErrNotFound) {
		t.Error("interface should be gone")
	}
}

func TestPeerLifecycleAndCascade(t *testing.T) {
	s := open(t)
	if err := s.CreateInterface(&Interface{Name: "wg0", PrivateKey: "k", Address: "10.0.0.1/24"}); err != nil {
		t.Fatal(err)
	}
	p := &Peer{Interface: "wg0", Name: "laptop", PublicKey: "pub1", AllowedIPs: "10.0.0.2/32"}
	if err := s.AddPeer(p); err != nil {
		t.Fatal(err)
	}
	if p.ID == 0 {
		t.Error("AddPeer should set ID")
	}

	got, err := s.GetPeer("wg0", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if got.AllowedIPs != "10.0.0.2/32" {
		t.Errorf("unexpected peer: %+v", got)
	}

	// Lookup by ID string and by public key too.
	if _, err := s.GetPeer("wg0", "pub1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPeer("wg0", "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPeer("wg0", "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}

	// Deleting the interface must cascade to peers.
	if err := s.DeleteInterface("wg0"); err != nil {
		t.Fatal(err)
	}
	if peers, _ := s.ListPeers("wg0"); len(peers) != 0 {
		t.Errorf("peers should cascade-delete, got %d", len(peers))
	}
}

func TestPeerMutationBumpsVersion(t *testing.T) {
	s := open(t)
	if err := s.CreateInterface(&Interface{Name: "wg0", PrivateKey: "k", Address: "10.0.0.1/24"}); err != nil {
		t.Fatal(err)
	}
	before := func() int64 {
		i, err := s.GetInterface("wg0")
		if err != nil {
			t.Fatal(err)
		}
		return i.ConfigVersion
	}
	v0 := before()
	if err := s.AddPeer(&Peer{Interface: "wg0", Name: "a", PublicKey: "pubA", AllowedIPs: "10.0.0.2/32"}); err != nil {
		t.Fatal(err)
	}
	if v := before(); v != v0+1 {
		t.Errorf("version after add = %d, want %d", v, v0+1)
	}
	if _, err := s.DeletePeer("wg0", "a"); err != nil {
		t.Fatal(err)
	}
	if v := before(); v != v0+2 {
		t.Errorf("version after delete = %d, want %d", v, v0+2)
	}
}

func TestBumpUnknownInterface(t *testing.T) {
	s := open(t)
	if err := s.bump("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}
