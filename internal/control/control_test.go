package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	api, err := NewAPI(st, p.ca, reports, hold)
	if err != nil {
		t.Fatal(err)
	}
	// The controller wires the store hook to the API (see cli/server.go);
	// mirror it so long-poll tests exercise the real wake path.
	st.OnChange = api.Notify
	// Mirror API.Server's TLS setup: optional client certs (enrollment has
	// none yet) and the CA appended to the presented chain for --ca-hash
	// pinning.
	presented := p.server
	presented.Certificate = append(append([][]byte{}, p.server.Certificate...), p.ca.Cert.Raw)
	srv := httptest.NewUnstartedServer(api.Handler())
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{presented},
		ClientAuth:   tls.VerifyClientCertIfGiven,
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
	if err := st.CreateInterface(&store.Interface{Client: "n1", Name: "wg0", PrivateKey: "k", Address: "10.5.0.1/24", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddPeer(&store.Peer{Client: "n1", Interface: "wg0", Name: "p1", PublicKey: "pub", AllowedIPs: "10.5.0.2/32", ClientPrivateKey: "SECRET-CLIENT-KEY"}); err != nil {
		t.Fatal(err)
	}

	p := newPKI(t, "n1")
	if err := st.EnsureClient("n1", p.agentFP); err != nil {
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
	clients, _ := st.ListClients()
	if clients[0].LastSeen == "" {
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
		t.Errorf("unenrolled client = %d, want 403", code)
	}

	// Enrolled with a different (superseded) fingerprint — the revocation
	// path: re-enroll replaces the fingerprint, old cert stops working.
	if err := st.EnsureClient("n1", "superseded-fingerprint"); err != nil {
		t.Fatal(err)
	}
	if code, _ := poll(t, c, ts.URL, 0); code != http.StatusForbidden {
		t.Errorf("superseded cert = %d, want 403", code)
	}

	// Enrolled with the real fingerprint — allowed.
	if err := st.EnsureClient("n1", p.agentFP); err != nil {
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
	// TLS layer no longer demands a client cert (enrollment needs it open),
	// so the rejection comes from the handler as a 401.
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    p.pool,
		MinVersion: tls.VersionTLS12,
	}}}
	resp, err := c.Post(ts.URL+"/api/poll", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("poll without client cert = %d, want 401", resp.StatusCode)
	}
}

// enrollPost posts an enrollment request with a certificate-less client
// (the bootstrapping agent's situation).
func enrollPost(t *testing.T, c *http.Client, url, token, pubPEM string) (int, EnrollResponse) {
	t.Helper()
	body, _ := json.Marshal(EnrollRequest{Token: token, PublicKey: pubPEM})
	resp, err := c.Post(url+"/api/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out EnrollResponse
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func plainClient(p pki) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    p.pool,
		MinVersion: tls.VersionTLS12,
	}}}
}

func agentPubPEM(t *testing.T) (pubPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return pubPEM, keyPEM
}

func TestEnrollIssuesCertForPublicKey(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.EnsureClientPending("client7"); err != nil {
		t.Fatal(err)
	}
	token, err := st.CreateEnrollToken("client7", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	p := newPKI(t, "unused")
	ts, _ := newAPIServer(t, st, p, NewReports(), 0)

	pubPEM, keyPEM := agentPubPEM(t)
	code, resp := enrollPost(t, plainClient(p), ts.URL, token, pubPEM)
	if code != http.StatusOK {
		t.Fatalf("enroll = %d %+v", code, resp)
	}
	if resp.Client != "client7" || resp.CA == "" || resp.Cert == "" {
		t.Fatalf("enroll response incomplete: %+v", resp)
	}

	// The issued certificate is signed by the CA for OUR public key.
	block, _ := pem.Decode([]byte(resp.Cert))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "client7" {
		t.Errorf("cert CN = %q", cert.Subject.CommonName)
	}
	if err := cert.CheckSignatureFrom(p.ca.Cert); err != nil {
		t.Errorf("cert not signed by controller CA: %v", err)
	}
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Error("cert key differs from the submitted public key")
	}

	// End-to-end: the enrolled material can poll over mTLS immediately.
	pair, err := tls.X509KeyPair([]byte(resp.Cert), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(p.ca.Cert)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{pair},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}}}
	if code, _ := poll(t, c, ts.URL, 0); code != http.StatusOK {
		t.Errorf("post-enroll poll = %d, want 200", code)
	}
}

func TestEnrollTokenSingleUse(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "db"))
	defer st.Close()
	token, err := st.CreateEnrollToken("n1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p := newPKI(t, "unused")
	ts, _ := newAPIServer(t, st, p, NewReports(), 0)
	c := plainClient(p)
	pubPEM, _ := agentPubPEM(t)

	if code, _ := enrollPost(t, c, ts.URL, token, pubPEM); code != http.StatusOK {
		t.Fatalf("first enroll = %d", code)
	}
	if code, _ := enrollPost(t, c, ts.URL, token, pubPEM); code != http.StatusForbidden {
		t.Errorf("token reuse = %d, want 403", code)
	}
}

func TestEnrollWrongToken(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "db"))
	defer st.Close()
	p := newPKI(t, "unused")
	ts, _ := newAPIServer(t, st, p, NewReports(), 0)
	pubPEM, _ := agentPubPEM(t)
	if code, _ := enrollPost(t, plainClient(p), ts.URL, "bogus", pubPEM); code != http.StatusForbidden {
		t.Errorf("wrong token = %d, want 403", code)
	}
}

func TestEnrollBadPublicKey(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "db"))
	defer st.Close()
	token, _ := st.CreateEnrollToken("n1", time.Hour)
	p := newPKI(t, "unused")
	ts, _ := newAPIServer(t, st, p, NewReports(), 0)
	// Malformed body does not waste the token...
	if code, _ := enrollPost(t, plainClient(p), ts.URL, token, "not pem"); code != http.StatusBadRequest {
		t.Errorf("garbage public key = %d, want 400", code)
	}
	// ...but a well-formed PEM with a rejected key burns it (fail-closed).
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	rsaPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if code, _ := enrollPost(t, plainClient(p), ts.URL, token, rsaPEM); code != http.StatusBadRequest {
		t.Errorf("RSA public key = %d, want 400", code)
	}
	if code, _ := enrollPost(t, plainClient(p), ts.URL, token, rsaPEM); code != http.StatusForbidden {
		t.Errorf("token should be burned after the failed issue, got %d", code)
	}
}

func TestEnrollWithoutToken(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "db"))
	defer st.Close()
	p := newPKI(t, "unused")
	ts, _ := newAPIServer(t, st, p, NewReports(), 0)
	pubPEM, _ := agentPubPEM(t)
	if code, _ := enrollPost(t, plainClient(p), ts.URL, "", pubPEM); code != http.StatusForbidden {
		t.Errorf("missing token = %d, want 403", code)
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

// newLongPollFixture builds a one-interface store + enrolled client + holding
// API server; the shared setup of the long-poll tests.
func newLongPollFixture(t *testing.T, hold time.Duration) (*store.Store, *http.Client, string, *API) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.CreateInterface(&store.Interface{Client: "n1", Name: "wg0", PrivateKey: "k", Address: "10.5.0.1/24", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	p := newPKI(t, "n1")
	if err := st.EnsureClient("n1", p.agentFP); err != nil {
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
	if err := st.CreateInterface(&store.Interface{Client: "n1", Name: "wg1", PrivateKey: "k", Address: "10.6.0.1/24", Enabled: true}); err != nil {
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

	// Deleting the top-version interface DROPS the client's MAX version; the
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
