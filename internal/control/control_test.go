package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gexqin/wgmgt/internal/certs"
	"github.com/gexqin/wgmgt/internal/store"
)

type pki struct {
	ca        *certs.CA
	server    tls.Certificate
	pool      *x509.CertPool
	agentCert tls.Certificate
	agentFP   string // fingerprint of the agent certificate
}

func newPKI(t *testing.T, agentName string) pki {
	t.Helper()
	ca, err := certs.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	srvPEM, srvKey, err := ca.NewServerCert([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	srvTLS, err := tls.X509KeyPair(srvPEM, srvKey)
	if err != nil {
		t.Fatal(err)
	}
	agPEM, agKey, err := ca.NewAgentCert(agentName)
	if err != nil {
		t.Fatal(err)
	}
	agTLS, err := tls.X509KeyPair(agPEM, agKey)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := certs.Fingerprint(agPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pki{ca: ca, server: srvTLS, pool: pool, agentCert: agTLS, agentFP: fp}
}

func newAPIServer(t *testing.T, st *store.Store, p pki, reports *Reports, hold time.Duration) (*httptest.Server, *API) {
	t.Helper()
	api := NewAPI(st, reports, hold)
	// The controller wires the store hook to the API (see cli/server.go);
	// mirror it so long-poll tests exercise the real wake path.
	st.OnChange = api.Notify
	srv := httptest.NewUnstartedServer(api.Handler())
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{p.server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.pool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, api
}

func clientFor(t *testing.T, p pki) *http.Client {
	t.Helper()
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{p.agentCert},
		RootCAs:      p.pool,
		MinVersion:   tls.VersionTLS12,
	}}}
}

func poll(t *testing.T, c *http.Client, url string, since int64) (int, pollResp) {
	t.Helper()
	body, _ := json.Marshal(PollRequest{Since: since, Status: StatusReport{Interfaces: []IfaceReport{
		{Name: "wg0", Up: true, Peers: []PeerReport{{PublicKey: "k", Rx: 42}}},
	}}})
	resp, err := c.Post(url+"/api/poll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out pollResp
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

type pollResp struct {
	Version    int64             `json:"version"`
	Interfaces *[]AgentInterface `json:"interfaces"`
}

// pollAsync starts a poll on a goroutine and returns its result channel —
// the shape long-poll assertions need (nothing arrives until the wake).
func pollAsync(t *testing.T, c *http.Client, url string, since int64) <-chan pollResult {
	t.Helper()
	body, _ := json.Marshal(PollRequest{Since: since, Status: StatusReport{}})
	ch := make(chan pollResult, 1)
	go func() {
		resp, err := c.Post(url+"/api/poll", "application/json", bytes.NewReader(body))
		if err != nil {
			ch <- pollResult{err: err}
			return
		}
		defer resp.Body.Close()
		var out pollResp
		json.NewDecoder(resp.Body).Decode(&out)
		ch <- pollResult{code: resp.StatusCode, resp: out}
	}()
	return ch
}

type pollResult struct {
	err  error
	code int
	resp pollResp
}

func TestPollPushesConfigAndRecordsReport(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.CreateInterface(&store.Interface{Node: "n1", Name: "wg0", PrivateKey: "k", Address: "10.5.0.1/24", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddPeer(&store.Peer{Node: "n1", Interface: "wg0", Name: "p1", PublicKey: "pub", AllowedIPs: "10.5.0.2/32", ClientPrivateKey: "SECRET-CLIENT-KEY"}); err != nil {
		t.Fatal(err)
	}

	p := newPKI(t, "n1")
	if err := st.EnsureNode("n1", p.agentFP); err != nil {
		t.Fatal(err)
	}
	reports := NewReports()
	ts, _ := newAPIServer(t, st, p, reports, 0)
	c := clientFor(t, p)

	code, resp := poll(t, c, ts.URL, 0)
	if code != http.StatusOK || resp.Interfaces == nil || len(*resp.Interfaces) != 1 {
		t.Fatalf("poll = %d %+v", code, resp)
	}
	ifc := (*resp.Interfaces)[0]
	if ifc.Name != "wg0" || !ifc.Enabled || len(ifc.Peers) != 1 {
		t.Fatalf("interface payload wrong: %+v", ifc)
	}
	// The peer's client private key must NEVER travel to the agent.
	if ifc.Peers[0].ClientPrivateKey != "" {
		t.Errorf("client private key leaked to agent: %q", ifc.Peers[0].ClientPrivateKey)
	}

	// Report recorded with live data from the request body.
	entry := reports.Get("n1")
	if entry.When.IsZero() || len(entry.Report.Interfaces) != 1 || entry.Report.Interfaces[0].Peers[0].Rx != 42 {
		t.Errorf("report not recorded: %+v", entry)
	}

	// Up-to-date poll omits the config.
	code, resp = poll(t, c, ts.URL, resp.Version)
	if code != http.StatusOK || resp.Interfaces != nil {
		t.Errorf("fresh poll should omit interfaces: %d %+v", code, resp)
	}

	// A change bumps the version and re-pushes.
	if err := st.SetEnabled("n1", "wg0", false); err != nil {
		t.Fatal(err)
	}
	_, resp2 := poll(t, c, ts.URL, 0)
	if resp2.Interfaces == nil || (*resp2.Interfaces)[0].Enabled {
		t.Errorf("disabled interface should push Enabled=false: %+v", resp2)
	}

	// last_seen updated.
	nodes, _ := st.ListNodes()
	if nodes[0].LastSeen == "" {
		t.Error("last_seen not recorded")
	}
}

func TestPollRejectsServerCN(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	p := newPKI(t, "wgmgt-server") // forbidden CN
	ts, _ := newAPIServer(t, st, p, NewReports(), 0)
	c := clientFor(t, p)
	code, _ := poll(t, c, ts.URL, 0)
	if code != http.StatusUnauthorized {
		t.Errorf("server-CN cert should be rejected, got %d", code)
	}
}

func TestPollEnforcesFingerprint(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "db"))
	defer st.Close()

	p := newPKI(t, "n1")
	ts, _ := newAPIServer(t, st, p, NewReports(), 0)
	c := clientFor(t, p)

	// Not enrolled at all.
	if code, _ := poll(t, c, ts.URL, 0); code != http.StatusForbidden {
		t.Errorf("unenrolled node = %d, want 403", code)
	}

	// Enrolled with a different (superseded) fingerprint — the revocation
	// path: re-enroll replaces the fingerprint, old cert stops working.
	if err := st.EnsureNode("n1", "superseded-fingerprint"); err != nil {
		t.Fatal(err)
	}
	if code, _ := poll(t, c, ts.URL, 0); code != http.StatusForbidden {
		t.Errorf("superseded cert = %d, want 403", code)
	}

	// Enrolled with the real fingerprint — allowed.
	if err := st.EnsureNode("n1", p.agentFP); err != nil {
		t.Fatal(err)
	}
	if code, _ := poll(t, c, ts.URL, 0); code != http.StatusOK {
		t.Errorf("matching cert = %d, want 200", code)
	}
}

func TestPollWithoutClientCertRejected(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "db"))
	defer st.Close()
	p := newPKI(t, "n1")
	ts, _ := newAPIServer(t, st, p, NewReports(), 0)
	// Plain client: TLS handshake itself fails (client cert required).
	c := &http.Client{}
	if _, err := c.Post(ts.URL+"/api/poll", "application/json", bytes.NewReader([]byte(`{}`))); err == nil {
		t.Error("handshake without client cert should fail")
	}
}

func TestPollVerifiesTimeIntervalSanity(t *testing.T) {
	// sanity guard for the report cache timestamp used by the UI.
	r := NewReports()
	r.Update("x", StatusReport{})
	if r.Get("x").When.After(time.Now().Add(time.Minute)) {
		t.Error("report timestamps must be sane")
	}
}

// newLongPollFixture builds a one-interface store + enrolled node + holding
// API server; the shared setup of the long-poll tests.
func newLongPollFixture(t *testing.T, hold time.Duration) (*store.Store, *http.Client, string, *API) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.CreateInterface(&store.Interface{Node: "n1", Name: "wg0", PrivateKey: "k", Address: "10.5.0.1/24", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	p := newPKI(t, "n1")
	if err := st.EnsureNode("n1", p.agentFP); err != nil {
		t.Fatal(err)
	}
	ts, api := newAPIServer(t, st, p, NewReports(), hold)
	return st, clientFor(t, p), ts.URL, api
}

func TestLongPollWaitsForChange(t *testing.T) {
	st, c, url, _ := newLongPollFixture(t, 5*time.Second)

	_, cur := poll(t, c, url, 0) // fetch current version
	ch := pollAsync(t, c, url, cur.Version)

	select {
	case r := <-ch:
		t.Fatalf("current-version poll must be held, got %+v", r)
	case <-time.After(150 * time.Millisecond):
	}

	// Any mutation wakes the held poll within milliseconds.
	if err := st.SetEnabled("n1", "wg0", false); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-ch:
		if r.err != nil || r.code != http.StatusOK {
			t.Fatalf("woken poll: %v %+v", r.err, r)
		}
		if r.resp.Version == cur.Version || r.resp.Interfaces == nil {
			t.Errorf("woken poll should push the new config: %+v", r.resp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("poll was not woken by the config change")
	}
}

func TestLongPollHoldExpiry(t *testing.T) {
	_, c, url, _ := newLongPollFixture(t, 100*time.Millisecond)

	_, cur := poll(t, c, url, 0)
	ch := pollAsync(t, c, url, cur.Version)
	select {
	case r := <-ch:
		if r.err != nil || r.code != http.StatusOK {
			t.Fatalf("expired poll: %v %+v", r.err, r)
		}
		// Hold expiry answers "no change" so the agent re-polls immediately.
		if r.resp.Version != cur.Version || r.resp.Interfaces != nil {
			t.Errorf("expired poll should return current version, no config: %+v", r.resp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("poll did not return after hold expiry")
	}
}

func TestLongPollWakesOnVersionDrop(t *testing.T) {
	st, c, url, _ := newLongPollFixture(t, 5*time.Second)

	// A second interface at v1; wg0 has been bumped to v3 by peer churn.
	st.SetEnabled("n1", "wg0", false)
	st.SetEnabled("n1", "wg0", true)
	if err := st.CreateInterface(&store.Interface{Node: "n1", Name: "wg1", PrivateKey: "k", Address: "10.6.0.1/24", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	v, _ := st.ConfigVersion("n1")
	if v != 3 {
		t.Fatalf("setup: version = %d, want 3", v)
	}

	ch := pollAsync(t, c, url, 3)
	select {
	case r := <-ch:
		t.Fatalf("poll must be held at the current version, got %+v", r)
	case <-time.After(150 * time.Millisecond):
	}

	// Deleting the top-version interface DROPS the node's MAX version; the
	// poll must still wake and push (version "different", not "greater").
	if err := st.DeleteInterface("n1", "wg0"); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-ch:
		if r.err != nil || r.resp.Version != 1 || r.resp.Interfaces == nil {
			t.Fatalf("dropped-version poll: %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("poll was not woken by the version drop")
	}
}

func TestLongPollClientCancel(t *testing.T) {
	_, c, url, _ := newLongPollFixture(t, 5*time.Second)

	_, cur := poll(t, c, url, 0)
	ctx, cancel := context.WithCancel(context.Background())
	body, _ := json.Marshal(PollRequest{Since: cur.Version, Status: StatusReport{}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/api/poll", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		resp, err := c.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		done <- err
	}()
	time.Sleep(100 * time.Millisecond) // let the request reach the hold loop
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("cancelled poll should report an error to the client")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled poll did not return")
	}
}

func TestShutdownWakeAll(t *testing.T) {
	_, c, url, api := newLongPollFixture(t, 30*time.Second)

	_, cur := poll(t, c, url, 0)
	ch := pollAsync(t, c, url, cur.Version)
	select {
	case r := <-ch:
		t.Fatalf("poll must be held, got %+v", r)
	case <-time.After(150 * time.Millisecond):
	}

	api.WakeAll() // graceful shutdown: answer now, agents reconnect elsewhere
	select {
	case r := <-ch:
		if r.err != nil || r.code != http.StatusOK || r.resp.Interfaces != nil {
			t.Fatalf("wake-all should answer no-change: %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WakeAll did not release the held poll")
	}
}
