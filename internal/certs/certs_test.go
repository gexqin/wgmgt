package certs

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCAIssueAndVerify(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}

	srvPEM, _, err := ca.NewServerCert([]string{"10.0.0.1", "ctrl.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	srv := parse(t, srvPEM)
	if err := srv.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("server cert not signed by CA: %v", err)
	}
	if srv.Subject.CommonName != "wgmgt-server" {
		t.Errorf("server CN = %q", srv.Subject.CommonName)
	}
	var hasIP, hasDNS bool
	for _, ip := range srv.IPAddresses {
		if ip.String() == "10.0.0.1" {
			hasIP = true
		}
	}
	for _, d := range srv.DNSNames {
		if d == "ctrl.example.com" || d == "localhost" {
			hasDNS = true
		}
	}
	if !hasIP || !hasDNS {
		t.Errorf("SANs missing: ips=%v dns=%v", srv.IPAddresses, srv.DNSNames)
	}

	agentPEM, _, err := ca.NewAgentCert("node1")
	if err != nil {
		t.Fatal(err)
	}
	agent := parse(t, agentPEM)
	if agent.Subject.CommonName != "node1" {
		t.Errorf("agent CN = %q, want node1", agent.Subject.CommonName)
	}
	if err := agent.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("agent cert not signed by CA: %v", err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Cert.Equal(ca.Cert) {
		t.Error("loaded CA cert differs")
	}

	// LoadOrNewCA must not regenerate an existing CA.
	again, err := LoadOrNewCA(dir)
	if err != nil || !again.Cert.Equal(ca.Cert) {
		t.Errorf("LoadOrNewCA regenerated: %v", err)
	}
}

func TestLoadOrNewCARefusesToRegenerateWithoutKey(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Save(dir); err != nil {
		t.Fatal(err)
	}
	// ca.key lost: regenerating would invalidate every issued cert — must
	// be a hard error, not a silent new CA.
	os.Remove(filepath.Join(dir, "ca.key"))
	again, err := LoadOrNewCA(dir)
	if err == nil {
		t.Fatalf("expected hard error, got CA %v", again.Cert.Subject)
	}
	if again != nil {
		t.Error("no CA should be returned on error")
	}
}

func TestEnsureServerCerts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	cert, pool, err := EnsureServerCerts(dir, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 || pool == nil {
		t.Fatal("no cert or pool returned")
	}
	// Second call must load the same pair without error.
	if _, _, err := EnsureServerCerts(dir, []string{"127.0.0.1"}); err != nil {
		t.Errorf("second EnsureServerCerts: %v", err)
	}
}

func TestFingerprint(t *testing.T) {
	ca, _ := NewCA()
	agentPEM, _, err := ca.NewAgentCert("n1")
	if err != nil {
		t.Fatal(err)
	}
	fp, err := Fingerprint(agentPEM)
	if err != nil || len(fp) != 64 { // hex sha256
		t.Errorf("fingerprint = %q, %v", fp, err)
	}
}

func parse(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
