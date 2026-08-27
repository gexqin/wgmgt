package control

import (
	"bytes"
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
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pki{ca: ca, server: srvTLS, pool: pool, agentCert: agTLS}
}

func newAPIServer(t *testing.T, st *store.Store, p pki, reports *Reports) *httptest.Server {
	t.Helper()
	api := NewAPI(st, reports)
	srv := httptest.NewUnstartedServer(api.Handler())
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{p.server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.pool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
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

func TestPollPushesConfigAndRecordsReport(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.EnsureNode("n1", "fp"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateInterface(&store.Interface{Node: "n1", Name: "wg0", PrivateKey: "k", Address: "10.5.0.1/24", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddPeer(&store.Peer{Node: "n1", Interface: "wg0", Name: "p1", PublicKey: "pub", AllowedIPs: "10.5.0.2/32"}); err != nil {
		t.Fatal(err)
	}

	p := newPKI(t, "n1")
	reports := NewReports()
	ts := newAPIServer(t, st, p, reports)
	c := clientFor(t, p)

	code, resp := poll(t, c, ts.URL, 0)
	if code != http.StatusOK || resp.Interfaces == nil || len(*resp.Interfaces) != 1 {
		t.Fatalf("poll = %d %+v", code, resp)
	}
	ifc := (*resp.Interfaces)[0]
	if ifc.Name != "wg0" || !ifc.Enabled || len(ifc.Peers) != 1 || ifc.Peers[0].ClientPrivateKey != "" {
		t.Errorf("interface payload wrong: %+v", ifc)
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
	ts := newAPIServer(t, st, p, NewReports())
	c := clientFor(t, p)
	code, _ := poll(t, c, ts.URL, 0)
	if code != http.StatusUnauthorized {
		t.Errorf("server-CN cert should be rejected, got %d", code)
	}
}

func TestPollWithoutClientCertRejected(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "db"))
	defer st.Close()
	p := newPKI(t, "n1")
	ts := newAPIServer(t, st, p, NewReports())
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
