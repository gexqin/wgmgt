// Package certs manages the controller's internal PKI: a self-signed CA,
// the server's TLS certificate, and per-agent client certificates. mTLS is
// the only authentication mechanism — an agent's certificate CN is its
// node name.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CA is the wgmgt certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA generates a fresh CA (10-year validity).
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "wgmgt-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// LoadCA reads ca.pem/ca.key from dir.
func LoadCA(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, err
	}
	return parseCA(certPEM, keyPEM)
}

// Save writes ca.pem/ca.key into dir (0600).
func (ca *CA) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), pemCert(ca.Cert, "CERTIFICATE"), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "ca.key"), pemKey(ca.Key), 0o600)
}

// LoadOrNewCA returns the CA in dir, creating it on first run. A ca.pem
// without its key is a hard error, not a first run: silently regenerating
// would invalidate every issued agent certificate (split brain).
func LoadOrNewCA(dir string) (*CA, error) {
	ca, err := LoadCA(dir)
	if err == nil {
		return ca, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, statErr := os.Stat(filepath.Join(dir, "ca.pem")); statErr == nil {
		return nil, fmt.Errorf("ca.pem exists but its key is unreadable (%v) — refusing to regenerate the CA, which would invalidate all agent certificates; restore ca.key or move the whole PKI directory away", err)
	}
	ca, err = NewCA()
	if err != nil {
		return nil, err
	}
	return ca, ca.Save(dir)
}

// NewServerCert issues the controller's TLS certificate with the given
// hosts as DNS/IP SANs plus localhost.
func (ca *CA) NewServerCert(hosts []string) (certPEM, keyPEM []byte, err error) {
	return ca.issue("wgmgt-server", hosts, x509.ExtKeyUsageServerAuth)
}

// NewAgentCert issues a client certificate; CN is the node name.
func (ca *CA) NewAgentCert(name string) (certPEM, keyPEM []byte, err error) {
	return ca.issue(name, nil, x509.ExtKeyUsageClientAuth)
}

func (ca *CA) issue(cn string, hosts []string, eku x509.ExtKeyUsage) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	if eku == x509.ExtKeyUsageServerAuth {
		tmpl.DNSNames = append(tmpl.DNSNames, "localhost")
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return pemCert(cert, "CERTIFICATE"), pemKey(key), nil
}

// Fingerprint returns the hex SHA-256 fingerprint of a PEM certificate.
func Fingerprint(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", sum), nil
}

// EnsureServerCerts makes sure dir contains ca.pem/ca.key and
// server.pem/server.key valid for hosts, creating what is missing.
// Returns the TLS server certificate.
func EnsureServerCerts(dir string, hosts []string) (tls.Certificate, *x509.CertPool, error) {
	ca, err := LoadOrNewCA(dir)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPath := filepath.Join(dir, "server.pem")
	keyPath := filepath.Join(dir, "server.key")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return tls.Certificate{}, nil, err
		}
		certPEM, keyPEM, err := ca.NewServerCert(hosts)
		if err != nil {
			return tls.Certificate{}, nil, err
		}
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return tls.Certificate{}, nil, err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return tls.Certificate{}, nil, err
		}
		cert, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return tls.Certificate{}, nil, err
		}
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return cert, pool, nil
}

// --- helpers ---

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 120)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return big.NewInt(1)
	}
	return n
}

func pemCert(cert *x509.Certificate, typ string) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: cert.Raw})
}

func pemKey(key *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("ca.pem: no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("ca.key: no PEM block")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}
