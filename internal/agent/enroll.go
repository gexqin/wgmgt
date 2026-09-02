// Token bootstrap enrollment: the client side of POST /api/enroll.
package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gexqin/wgmgt/internal/control"
	"github.com/gexqin/wgmgt/internal/fileutil"
)

// Filenames of the persisted enrollment material inside confDir. The conf
// scanner only picks up *.conf files, so the PEMs can live alongside them.
const (
	materialCA   = "ca.pem"
	materialCert = "agent.pem"
	materialKey  = "agent.key"
)

// LoadMaterial returns the persisted mTLS material from dir (ok=false when
// any file is missing or the key/certificate/CA relationship is invalid) —
// the skip-enrollment path on restarts.
func LoadMaterial(dir string) (caPEM, certPEM, keyPEM []byte, ok bool) {
	var err error
	if caPEM, err = os.ReadFile(filepath.Join(dir, materialCA)); err != nil {
		return nil, nil, nil, false
	}
	if certPEM, err = os.ReadFile(filepath.Join(dir, materialCert)); err != nil {
		return nil, nil, nil, false
	}
	if keyPEM, err = os.ReadFile(filepath.Join(dir, materialKey)); err != nil {
		return nil, nil, nil, false
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, nil, nil, false
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || !ca.IsCA {
		return nil, nil, nil, false
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, nil, nil, false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, nil, false
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, nil, nil, false
	}
	return caPEM, certPEM, keyPEM, true
}

// Enroll exchanges a one-time token for a certificate. The agent generates
// its ECDSA P-256 keypair locally and sends only the public key; the server
// is authenticated by pinning caHash (hex SHA-256 of the controller's root
// CA, "sha256:<hex>" or bare hex) against the presented chain. The mTLS
// material is persisted under confDir (dir 0700; key 0600) so restarts can
// skip enrollment.
func Enroll(ctx context.Context, serverURL, token, caHash, confDir string) (caPEM, certPEM, keyPEM []byte, err error) {
	pin, err := parseCAHash(caHash)
	if err != nil {
		return nil, nil, nil, err
	}
	host := ""
	if u, err := url.Parse(serverURL); err == nil {
		host = u.Hostname()
	}

	// The private key never leaves this client: only its public half travels.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Unlike the poll client there is no long-polling here, so a hard
	// timeout is correct.
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// InsecureSkipVerify alone would accept any server; the
				// callback below restores trust by pinning the root CA.
				InsecureSkipVerify: true, // #nosec G402 -- VerifyConnection below performs pinned CA, chain, and hostname verification.
				MinVersion:         tls.VersionTLS12,
				VerifyConnection:   verifyPinnedCA(pin, host),
			},
		},
	}

	body, _ := json.Marshal(control.EnrollRequest{Token: token, PublicKey: string(pubPEM)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(serverURL, "/")+"/api/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet := make([]byte, 256)
		n, _ := resp.Body.Read(snippet)
		return nil, nil, nil, fmt.Errorf("server answered %s: %s",
			resp.Status, strings.TrimSpace(string(snippet[:n])))
	}

	var out control.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, nil, nil, fmt.Errorf("enroll response: %w", err)
	}
	caPEM, certPEM = []byte(out.CA), []byte(out.Cert)

	// Defense against a pinned-but-hostile endpoint swapping material: the
	// pair must be consistent and the certificate must be signed by the CA
	// that came back with it.
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, nil, nil, errors.New("enroll response: CA is not valid PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("enroll response CA: %v", err)
	}
	if sum := sha256.Sum256(caCert.Raw); !bytes.Equal(sum[:], pin) {
		return nil, nil, nil, errors.New("enroll response CA does not match --ca-hash")
	}
	if !caCert.IsCA {
		return nil, nil, nil, errors.New("enroll response CA is not a certificate authority")
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, nil, errors.New("enroll response: certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("enroll response certificate: %v", err)
	}
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		return nil, nil, nil, fmt.Errorf("enroll response certificate is not signed by the returned CA: %v", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return nil, nil, nil, fmt.Errorf("issued certificate does not match our key: %v", err)
	}

	if err := os.MkdirAll(confDir, 0o700); err != nil {
		return nil, nil, nil, err
	}
	if err := os.Chmod(confDir, 0o700); err != nil {
		return nil, nil, nil, fmt.Errorf("secure conf directory: %w", err)
	}
	if err := fileutil.WriteAtomic(filepath.Join(confDir, materialCA), caPEM, 0o644); err != nil {
		return nil, nil, nil, err
	}
	if err := fileutil.WriteAtomic(filepath.Join(confDir, materialCert), certPEM, 0o644); err != nil {
		return nil, nil, nil, err
	}
	if err := fileutil.WriteAtomic(filepath.Join(confDir, materialKey), keyPEM, 0o600); err != nil {
		return nil, nil, nil, err
	}
	return caPEM, certPEM, keyPEM, nil
}

// parseCAHash accepts "sha256:<hex>" or bare hex and requires a full
// SHA-256 (32 bytes).
func parseCAHash(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "sha256:")
	pin, err := hex.DecodeString(s)
	if err != nil || len(pin) != 32 {
		return nil, fmt.Errorf("--ca-hash must be a hex SHA-256 fingerprint (sha256:<hex> or bare hex)")
	}
	return pin, nil
}

// verifyPinnedCA builds the TLS verification callback: some presented
// certificate must hash to the pin, and the leaf must verify (signature and
// hostname) against that pinned root. VerifyConnection also runs for resumed
// TLS sessions, unlike VerifyPeerCertificate.
func verifyPinnedCA(pin []byte, host string) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("server presented no certificate")
		}
		certs := state.PeerCertificates
		var root *x509.Certificate
		for _, c := range certs {
			if sum := sha256.Sum256(c.Raw); bytes.Equal(sum[:], pin) {
				root = c
				break
			}
		}
		if root == nil {
			last := certs[len(certs)-1]
			sum := sha256.Sum256(last.Raw)
			return fmt.Errorf("server CA does not match --ca-hash (got %x…, want %x…): is the controller address or the hash stale?",
				sum[:8], pin[:8])
		}
		if !root.IsCA {
			return errors.New("pinned certificate is not a CA")
		}
		pool := x509.NewCertPool()
		pool.AddCert(root)
		intermediates := x509.NewCertPool()
		for _, cert := range certs[1:] {
			if !cert.Equal(root) {
				intermediates.AddCert(cert)
			}
		}
		if _, err := certs[0].Verify(x509.VerifyOptions{
			Roots:         pool,
			Intermediates: intermediates,
			DNSName:       host,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return fmt.Errorf("server certificate does not verify against the pinned CA: %v", err)
		}
		return nil
	}
}
