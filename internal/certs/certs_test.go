package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
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

func TestNewAgentCertFromKey(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	certPEM, err := ca.NewAgentCertFromKey("node7", pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	cert := parse(t, certPEM)
	if cert.Subject.CommonName != "node7" {
		t.Errorf("CN = %q, want node7", cert.Subject.CommonName)
	}
	if err := cert.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("cert not signed by CA: %v", err)
	}
	got := cert.PublicKey.(*ecdsa.PublicKey)
	if got.X.Cmp(key.PublicKey.X) != 0 || got.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Error("cert public key differs from the submitted key")
	}
	// The issued pair must be usable as a TLS client certificate.
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mustMarshalECKey(t, key)})
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Errorf("X509KeyPair: %v", err)
	}
}

func TestNewAgentCertFromKeyRejectsBadInput(t *testing.T) {
	ca, _ := NewCA()
	if _, err := ca.NewAgentCertFromKey("n", []byte("not pem")); err == nil {
		t.Error("garbage PEM accepted")
	}

	// RSA keys are rejected.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if _, err := ca.NewAgentCertFromKey("n", rsaPEM); err == nil {
		t.Error("RSA key accepted")
	}

	// Wrong curve is rejected.
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ = x509.MarshalPKIXPublicKey(&p384.PublicKey)
	p384PEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if _, err := ca.NewAgentCertFromKey("n", p384PEM); err == nil {
		t.Error("P-384 key accepted")
	}
}

func TestCAHelpers(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	fp := ca.CAFingerprint()
	if len(fp) != 64 {
		t.Errorf("CAFingerprint len = %d, want 64", len(fp))
	}
	if fp != ca.CAFingerprint() {
		t.Error("CAFingerprint not stable")
	}
	if got, err := Fingerprint(ca.CAPEM()); err != nil || got != fp {
		t.Errorf("CAPEM fingerprint = %q (%v), want %q", got, err, fp)
	}
}

func mustMarshalECKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
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
