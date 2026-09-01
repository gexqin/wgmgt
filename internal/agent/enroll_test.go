package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gexqin/wgmgt/internal/certs"
	"github.com/gexqin/wgmgt/internal/control"
	"github.com/gexqin/wgmgt/internal/store"
)

// newTLSServer mirrors control.API.Server's TLS setup.
func newTLSServer(t *testing.T, h http.Handler, cert tls.Certificate, caPool *x509.CertPool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// startController runs a real control API server the way cli/server.go
// does: CA in the presented chain, client certs optional. withRoot=false
// simulates an old controller that serves only its leaf certificate.
func startController(t *testing.T, withRoot bool) (*store.Store, *certs.CA, string) {
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
	if withRoot {
		srvTLS.Certificate = append(srvTLS.Certificate, ca.Cert.Raw)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	api, err := control.NewAPI(st, ca, control.NewReports(), 0)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	srv := newTLSServer(t, api.Handler(), srvTLS, pool)
	return st, ca, srv.URL
}

func TestEnrollSuccess(t *testing.T) {
	st, ca, url := startController(t, true)
	if err := st.EnsureClientPending("client7"); err != nil {
		t.Fatal(err)
	}
	token, err := st.CreateEnrollToken("client7", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	confDir := filepath.Join(t.TempDir(), "agent")
	caPEM, certPEM, keyPEM, err := Enroll(context.Background(), url, token, "sha256:"+ca.CAFingerprint(), confDir)
	if err != nil {
		t.Fatal(err)
	}

	// Material persisted with tight modes for the key.
	for name, mode := range map[string]os.FileMode{
		"ca.pem": 0o644, "agent.pem": 0o644, "agent.key": 0o600,
	} {
		fi, err := os.Stat(filepath.Join(confDir, name))
		if err != nil {
			t.Fatalf("%s not persisted: %v", name, err)
		}
		if fi.Mode().Perm() != mode {
			t.Errorf("%s mode = %v, want %v", name, fi.Mode().Perm(), mode)
		}
	}
	if gca, gcert, gkey, ok := LoadMaterial(confDir); !ok || string(gca) != string(caPEM) || string(gcert) != string(certPEM) || string(gkey) != string(keyPEM) {
		t.Error("LoadMaterial must round-trip the persisted material")
	}

	// The returned material feeds the normal agent unchanged.
	if _, err := New(url, caPEM, certPEM, keyPEM, time.Second, 0, confDir); err != nil {
		t.Errorf("agent.New with enrolled material: %v", err)
	}
}

func TestEnrollWrongPin(t *testing.T) {
	st, _, url := startController(t, true)
	token, err := st.CreateEnrollToken("n1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	badPin := strings.Repeat("ab", 32)
	_, _, _, err = Enroll(context.Background(), url, token, badPin, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "does not match --ca-hash") {
		t.Fatalf("wrong pin error = %v", err)
	}
}

func TestEnrollServerWithoutRoot(t *testing.T) {
	st, _, url := startController(t, false)
	token, err := st.CreateEnrollToken("n1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_ = st
	// Any pin fails against a leaf-only chain, and the error must say so.
	_, _, _, err = Enroll(context.Background(), url, token, strings.Repeat("11", 32), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "does not match --ca-hash") {
		t.Fatalf("leaf-only chain error = %v", err)
	}
}

func TestEnrollBadHashFormat(t *testing.T) {
	if _, _, _, err := Enroll(context.Background(), "https://x", "tok", "tooshort", t.TempDir()); err == nil {
		t.Error("short hash must be rejected")
	}
	if _, _, _, err := Enroll(context.Background(), "https://x", "tok", "zz"+strings.Repeat("a", 62), t.TempDir()); err == nil {
		t.Error("non-hex hash must be rejected")
	}
}

func TestLoadMaterialIncomplete(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, ok := LoadMaterial(dir); ok {
		t.Error("empty dir must not load")
	}
	os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "agent.pem"), []byte("x"), 0o644)
	// agent.key missing.
	if _, _, _, ok := LoadMaterial(dir); ok {
		t.Error("missing key must not load")
	}
}
