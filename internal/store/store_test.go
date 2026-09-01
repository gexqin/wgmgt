package store

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func TestDeleteNodeCascadesAndAllowsReuse(t *testing.T) {
	s := open(t)
	if err := s.EnsureNodePending("n1"); err != nil {
		t.Fatal(err)
	}
	mustCreate(t, s, "n1", "wg0")
	if err := s.AddPeer(&Peer{Node: "n1", Interface: "wg0", Name: "laptop", PublicKey: "pub1", AllowedIPs: "10.0.0.2/32"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateEnrollToken("n1", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureNode("n2", "fp"); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteNode("n1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetNode("n1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetNode = %v, want ErrNotFound", err)
	}
	if ifcs, err := s.ListInterfaces("n1"); err != nil || len(ifcs) != 0 {
		t.Errorf("interfaces after delete = %v, %v", ifcs, err)
	}
	if peers, err := s.ListPeers("n1", "wg0"); err != nil || len(peers) != 0 {
		t.Errorf("peers after delete = %v, %v", peers, err)
	}
	if toks, err := s.ListEnrollTokens("n1"); err != nil || len(toks) != 0 {
		t.Errorf("tokens after delete = %v, %v", toks, err)
	}
	if nodes, _ := s.ListNodes(); len(nodes) != 1 || nodes[0].Name != "n2" {
		t.Errorf("siblings must survive, nodes = %v", nodes)
	}

	// The name is free again: a fresh node can take it.
	if err := s.EnsureNodePending("n1"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.GetNode("n1"); err != nil || n.Fingerprint != "" {
		t.Errorf("recreated node = %+v, %v", n, err)
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

func TestChangeHookFires(t *testing.T) {
	// The hook is the controller's long-poll wake path: every mutation that
	// can change a node's config version must fire it with the right node.
	s := open(t)
	mustCreate(t, s, "n1", "wg0")

	var got []string
	s.OnChange = func(node string) { got = append(got, node) }

	s.CreateInterface(&Interface{Node: "n2", Name: "wg0", PrivateKey: "k", Address: "10.0.0.2/24"})
	s.SetEnabled("n1", "wg0", false)
	s.UpdateServerEndpoint("n1", "wg0", "vpn.example.com:51820")
	s.AddPeer(&Peer{Node: "n1", Interface: "wg0", Name: "p", PublicKey: "pub1", AllowedIPs: "10.0.0.3/32"})
	s.DeletePeer("n1", "wg0", "pub1")
	s.DeleteInterface("n2", "wg0")

	want := []string{"n2", "n1", "n1", "n1", "n1", "n2"}
	if len(got) != len(want) {
		t.Fatalf("hook fired %d times (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("hook call %d = %q, want %q", i, got[i], want[i])
		}
	}

	// Registry writes are not config changes — must not fire.
	got = nil
	s.EnsureNode("n3", "fp")
	s.TouchNode("n3", "now")
	if len(got) != 0 {
		t.Errorf("registry writes must not fire the hook: %v", got)
	}

	// Nil hook (CLI/local mode) must be safe.
	s.OnChange = nil
	if err := s.SetEnabled("n1", "wg0", true); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollTokenLifecycle(t *testing.T) {
	s := open(t)
	token, err := s.CreateEnrollToken("router1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 48 { // 24 bytes hex
		t.Fatalf("token len = %d, want 48", len(token))
	}

	node, err := s.RedeemEnrollToken(token)
	if err != nil || node != "router1" {
		t.Fatalf("redeem = %q, %v", node, err)
	}
	if _, err := s.RedeemEnrollToken(token); !errors.Is(err, ErrNotFound) {
		t.Error("double redeem must fail")
	}
	if _, err := s.RedeemEnrollToken("bogus"); !errors.Is(err, ErrNotFound) {
		t.Error("unknown token must fail identically")
	}

	toks, err := s.ListEnrollTokens("")
	if err != nil || len(toks) != 0 {
		t.Errorf("used token still listed: %v, %v", toks, err)
	}

	// Expired tokens cannot be redeemed and are lazily deleted.
	expired, err := s.CreateEnrollToken("router2", -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemEnrollToken(expired); !errors.Is(err, ErrNotFound) {
		t.Error("expired token redeemed")
	}
	fresh, _ := s.CreateEnrollToken("router3", time.Hour) // triggers lazy cleanup
	if _, err := s.RedeemEnrollToken(expired); !errors.Is(err, ErrNotFound) {
		t.Error("expired token redeemed after cleanup")
	}
	if _, err := s.RedeemEnrollToken(fresh); err != nil {
		t.Fatal(err)
	}

	// Revocation removes outstanding tokens only.
	t1, _ := s.CreateEnrollToken("router1", time.Hour)
	t2, _ := s.CreateEnrollToken("other", time.Hour)
	if err := s.DeleteEnrollTokens("router1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemEnrollToken(t1); !errors.Is(err, ErrNotFound) {
		t.Error("revoked token redeemed")
	}
	if _, err := s.RedeemEnrollToken(t2); err != nil {
		t.Error("revocation must not touch other nodes' tokens")
	}
}

func TestEnrollTokenConcurrentRedeem(t *testing.T) {
	s := open(t)
	token, err := s.CreateEnrollToken("n1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.RedeemEnrollToken(token); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Errorf("exactly one redeem must succeed, got %d", ok.Load())
	}
}

func TestValidNodeName(t *testing.T) {
	for _, ok := range []string{"a", "router1", "node-2", "a.b_c", "AbC123"} {
		if !ValidNodeName(ok) {
			t.Errorf("ValidNodeName(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "-a", "a/b", "a b", ".", "a:b", string(make([]byte, 65))} {
		if ValidNodeName(bad) {
			t.Errorf("ValidNodeName(%q) = true", bad)
		}
	}
}

func TestEnsureNodePendingKeepsFingerprint(t *testing.T) {
	s := open(t)
	if err := s.EnsureNode("n1", "AA:BB"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureNodePending("n1"); err != nil {
		t.Fatal(err)
	}
	n, err := s.GetNode("n1")
	if err != nil {
		t.Fatal(err)
	}
	if n.Fingerprint != "AA:BB" {
		t.Errorf("fingerprint = %q, want AA:BB (pending must not clobber)", n.Fingerprint)
	}
	if err := s.EnsureNodePending("n2"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.GetNode("n2"); err != nil || n.Fingerprint != "" {
		t.Errorf("new pending node = %+v, %v", n, err)
	}
}
