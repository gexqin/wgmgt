package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/gexqin/wgmgt/internal/app"
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
		"name":             {"laptop"},
		"server_endpoint":  {"vpn.example.com:51899"},
		"allowed_ips":      {""},
		"keepalive":        {"25"},
		"preshared_key":    {"1"},
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
