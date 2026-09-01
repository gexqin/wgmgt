package web

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/gexqin/wgmgt/internal/app"
	"github.com/gexqin/wgmgt/internal/control"
	"github.com/gexqin/wgmgt/internal/store"
)

func newTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateInterface(&store.Interface{
		Name: "wgt0", PrivateKey: key.String(), Address: "10.99.0.1/24", ListenPort: 51899,
	}); err != nil {
		t.Fatal(err)
	}
	srv, err := New(&app.App{Store: st, ConfDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, "/t/" + srv.Token()
}

func get(t *testing.T, ts *httptest.Server, path string) (int, string) {
	t.Helper()
	resp, err := ts.Client().Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestWrongTokenIs404(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, p := range []string{"/", "/t/wrongtoken/", "/t/wrongtoken/iface/wgt0"} {
		if code, _ := get(t, ts, p); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, code)
		}
	}
}

func TestDashboardRendersInterface(t *testing.T) {
	ts, prefix := newTestServer(t)
	code, body := get(t, ts, prefix+"/")
	if code != http.StatusOK {
		t.Fatalf("dashboard = %d", code)
	}
	for _, want := range []string{"wgt0", "10.99.0.1/24", "DOWN", "Interfaces"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
}

func TestIfacePageAndStaticAssets(t *testing.T) {
	ts, prefix := newTestServer(t)
	code, body := get(t, ts, prefix+"/iface/wgt0")
	if code != http.StatusOK || !strings.Contains(body, "Add peer") {
		t.Fatalf("iface page = %d", code)
	}
	if code, _ := get(t, ts, prefix+"/static/wgmgt.css"); code != http.StatusOK {
		t.Error("css not served")
	}
	if code, _ := get(t, ts, prefix+"/static/htmx.min.js"); code != http.StatusOK {
		t.Error("htmx not served")
	}
	if code, _ := get(t, ts, prefix+"/iface/nope"); code != http.StatusNotFound {
		t.Error("unknown iface should 404")
	}
}

// noRedirect returns a client that reports redirect responses instead of
// following them, so we can assert the 303 semantics.
func noRedirect(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func TestPeerAddAndRemoveFlow(t *testing.T) {
	ts, prefix := newTestServer(t)
	client := noRedirect(t)

	// Add a peer via the form (auto allowed IP expected: 10.99.0.2/32).
	resp, err := client.PostForm(ts.URL+prefix+"/iface/wgt0/peers", url.Values{
		"name":            {"laptop"},
		"server_endpoint": {"vpn.example.com:51899"},
		"allowed_ips":     {""},
		"keepalive":       {"25"},
		"preshared_key":   {"1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("peer add = %d, want 303", resp.StatusCode)
	}

	code, body := get(t, ts, prefix+"/iface/wgt0")
	if code != http.StatusOK || !strings.Contains(body, "laptop") || !strings.Contains(body, "10.99.0.2/32") {
		t.Fatalf("peer not visible after add (code %d)", code)
	}

	// Client conf page renders.
	code, body = get(t, ts, prefix+"/iface/wgt0/peers/laptop/conf")
	if code != http.StatusOK || !strings.Contains(body, "vpn.example.com:51899") || !strings.Contains(body, "[Peer]") {
		t.Fatalf("client conf page = %d", code)
	}

	// Remove it.
	resp, err = client.PostForm(ts.URL+prefix+"/iface/wgt0/peers/laptop/rm", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("peer rm = %d, want 303", resp.StatusCode)
	}
	_, body = get(t, ts, prefix+"/iface/wgt0")
	if strings.Contains(body, "10.99.0.2/32") {
		t.Error("peer still visible after remove")
	}
}

func TestIfaceCreateRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.EnsureNode("n1", "fp"); err != nil {
		t.Fatal(err)
	}
	srv, err := NewController(&app.App{Store: st, ConfDir: dir}, control.NewReports(), ControllerOpts{
		APIURL:        "https://ctrl:8443",
		CAFingerprint: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	cts := httptest.NewServer(srv.Handler())
	defer cts.Close()
	cprefix := "/t/" + srv.Token()

	for _, evil := range []string{"../../tmp/pwned", "a/b", "way.too.long.interface.name"} {
		resp, err := noRedirect(t).PostForm(cts.URL+cprefix+"/node/n1/ifaces", url.Values{
			"name": {evil}, "address": {"10.0.0.1/24"},
		})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("name %q = %d, want 400", evil, resp.StatusCode)
		}
	}
}

func TestPeerAddRequiresName(t *testing.T) {
	ts, prefix := newTestServer(t)
	resp, err := ts.Client().PostForm(ts.URL+prefix+"/iface/wgt0/peers", url.Values{"name": {""}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("nameless add = %d, want 400", resp.StatusCode)
	}
}

func TestConfGeneratedOnPeerAdd(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key, _ := wgtypes.GeneratePrivateKey()
	st.CreateInterface(&store.Interface{Name: "wgt0", PrivateKey: key.String(), Address: "10.99.0.1/24"})
	srv, err := New(&app.App{Store: st, ConfDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	prefix := "/t/" + srv.Token()

	resp, err := ts.Client().PostForm(ts.URL+prefix+"/iface/wgt0/peers", url.Values{"name": {"p1"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	confBytes, err := os.ReadFile(filepath.Join(dir, "wgt0.conf"))
	if err != nil {
		t.Fatalf("conf not written: %v", err)
	}
	conf := string(confBytes)
	if !strings.Contains(conf, "[Peer]") {
		t.Errorf("conf missing peer:\n%s", conf)
	}
}

// newControllerServer builds a controller-mode test server.
func newControllerServer(t *testing.T) (*httptest.Server, string, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv, err := NewController(&app.App{Store: st, ConfDir: dir}, control.NewReports(), ControllerOpts{
		APIURL:        "https://ctrl:8443",
		CAFingerprint: strings.Repeat("ab", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, "/t/" + srv.Token(), st
}

func TestNodeAddShowsJoinCommand(t *testing.T) {
	ts, prefix, st := newControllerServer(t)

	resp, err := noRedirect(t).PostForm(ts.URL+prefix+"/nodes", url.Values{"name": {"router9"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("node add = %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")

	code, body := get(t, ts, loc)
	if code != http.StatusOK || !strings.Contains(body, "--token") ||
		!strings.Contains(body, "--ca-hash sha256:") || !strings.Contains(body, "wgmgt agent") {
		t.Fatalf("join page = %d, body missing command:\n%s", code, body)
	}

	// The page is one-time: a second GET must 404.
	if code, _ := get(t, ts, loc); code != http.StatusNotFound {
		t.Errorf("second view = %d, want 404", code)
	}

	// The pending node appears on the dashboard.
	if code, body := get(t, ts, prefix+"/"); code != http.StatusOK || !strings.Contains(body, "router9") {
		t.Errorf("node not on dashboard (code %d)", code)
	}

	// A redeemable token really exists for the node.
	toks, err := st.ListEnrollTokens("")
	if err != nil || len(toks) != 1 || toks[0].Node != "router9" {
		t.Errorf("outstanding tokens = %v, %v", toks, err)
	}
}

func TestNodeAddValidatesName(t *testing.T) {
	ts, prefix, _ := newControllerServer(t)
	for _, bad := range []string{"", "a/b", "lead ing", "-x"} {
		resp, err := noRedirect(t).PostForm(ts.URL+prefix+"/nodes", url.Values{"name": {bad}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("name %q = %d, want 400", bad, resp.StatusCode)
		}
	}
}

func TestNodeTokenRemintRevokesOld(t *testing.T) {
	ts, prefix, st := newControllerServer(t)
	if err := st.EnsureNodePending("n1"); err != nil {
		t.Fatal(err)
	}
	first, err := st.CreateEnrollToken("n1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := noRedirect(t).PostForm(ts.URL+prefix+"/node/n1/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("re-mint = %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if code, body := get(t, ts, loc); code != http.StatusOK || !strings.Contains(body, "--token") {
		t.Fatalf("join page after re-mint = %d", code)
	}

	// The old token was revoked; exactly one new one is outstanding.
	if _, err := st.RedeemEnrollToken(first); !errors.Is(err, store.ErrNotFound) {
		t.Error("old token must be revoked by re-mint")
	}
	toks, err := st.ListEnrollTokens("n1")
	if err != nil || len(toks) != 1 {
		t.Errorf("outstanding tokens after re-mint = %v, %v", toks, err)
	}
}

func TestQuickAddPeerOnNodePage(t *testing.T) {
	ts, prefix, st := newControllerServer(t)
	st.EnsureNode("n1", "fp")
	key, _ := wgtypes.GeneratePrivateKey()
	if err := st.CreateInterface(&store.Interface{Node: "n1", Name: "wg0", PrivateKey: key.String(), Address: "10.7.0.1/24", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	// The node page renders the quick-add form with the interface select.
	code, body := get(t, ts, prefix+"/node/n1")
	if code != http.StatusOK || !strings.Contains(body, `name="iface"`) || !strings.Contains(body, "Quick add peer") {
		t.Fatalf("node page missing quick-add (code %d)", code)
	}

	resp, err := noRedirect(t).PostForm(ts.URL+prefix+"/node/n1/peers", url.Values{
		"iface": {"wg0"}, "name": {"laptop"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("quick add = %d, want 303", resp.StatusCode)
	}
	peers, err := st.ListPeers("n1", "wg0")
	if err != nil || len(peers) != 1 || peers[0].Name != "laptop" {
		t.Fatalf("peers after quick add = %v, %v", peers, err)
	}
	if peers[0].AllowedIPs != "10.7.0.2/32" {
		t.Errorf("auto allowed IP = %q, want 10.7.0.2/32", peers[0].AllowedIPs)
	}

	// Unknown interface is a 404, missing choice a 400.
	resp, err = noRedirect(t).PostForm(ts.URL+prefix+"/node/n1/peers", url.Values{"iface": {"nope"}, "name": {"x"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown iface = %d, want 404", resp.StatusCode)
	}
	resp, err = noRedirect(t).PostForm(ts.URL+prefix+"/node/n1/peers", url.Values{"name": {"x"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing iface = %d, want 400", resp.StatusCode)
	}
}
