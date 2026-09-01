// Package control implements the wgmgt controller's agent-facing API and
// state. Protocol (per plan decision #13): JSON over TLS with mutual
// certificate authentication; agents connect outbound via HTTP long-polling
// (a poll whose version is current is held until the config changes or the
// hold expires, so changes reach agents in milliseconds); the agent
// certificate CN is the node name.
package control

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gexqin/wgmgt/internal/store"
)

// PollRequest is the agent's periodic request body.
type PollRequest struct {
	Since int64 `json:"since"` // config version the agent already has
	// Status is the agent's live report; it rides along so the controller
	// needs no separate reporting endpoint.
	Status StatusReport `json:"status"`
}

// AgentConfig is the response when the agent's version is stale.
type AgentConfig struct {
	Version    int64            `json:"version"`
	Interfaces []AgentInterface `json:"interfaces"`
}

// AgentInterface is one interface of the node's desired state.
type AgentInterface struct {
	Name       string       `json:"name"`
	PrivateKey string       `json:"private_key"`
	ListenPort int          `json:"listen_port"`
	Address    string       `json:"address"`
	MTU        int          `json:"mtu"`
	Enabled    bool         `json:"enabled"`
	PostUp     string       `json:"post_up"`
	PostDown   string       `json:"post_down"`
	Peers      []store.Peer `json:"peers"`
}

// StatusReport is the agent's live view of its managed devices.
type StatusReport struct {
	// Quarantined means the agent rolled its config back after losing
	// contact with the controller and is waiting for a newer version.
	Quarantined bool          `json:"quarantined"`
	Interfaces  []IfaceReport `json:"interfaces"`
}

// IfaceReport is one interface's live state.
type IfaceReport struct {
	Name  string       `json:"name"`
	Up    bool         `json:"up"`
	Peers []PeerReport `json:"peers"`
}

// PeerReport is one peer's live counters.
type PeerReport struct {
	PublicKey string    `json:"public_key"`
	Handshake time.Time `json:"handshake"`
	Rx        int64     `json:"rx"`
	Tx        int64     `json:"tx"`
	Endpoint  string    `json:"endpoint"`
}

// Reports caches the last status report per node for the web UI.
type Reports struct {
	mu     sync.RWMutex
	latest map[string]ReportEntry
}

// ReportEntry is a report plus its arrival time.
type ReportEntry struct {
	When   time.Time
	Report StatusReport
}

func NewReports() *Reports {
	return &Reports{latest: map[string]ReportEntry{}}
}

func (rp *Reports) Update(node string, r StatusReport) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.latest[node] = ReportEntry{When: time.Now(), Report: r}
}

// Get returns the latest report of a node (zero When if none yet).
func (rp *Reports) Get(node string) ReportEntry {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.latest[node]
}

// Notifier wakes hanging long-polls. Wake closes the node's current
// generation channel; WakeCh lazily recreates it for the next waiter. The
// capture-order rule that makes this race-free: a handler must grab WakeCh
// BEFORE reading the config version — a change after the capture closes the
// channel (wakes us), a change before the read shows up as version != since.
type Notifier struct {
	mu  sync.Mutex
	gen map[string]chan struct{}
}

func NewNotifier() *Notifier { return &Notifier{gen: map[string]chan struct{}{}} }

// Wake releases all current waiters of a node.
func (n *Notifier) Wake(node string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ch, ok := n.gen[node]; ok {
		close(ch)
		delete(n.gen, node)
	}
}

// WakeCh returns the node's current generation channel (created on demand).
func (n *Notifier) WakeCh(node string) <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ch, ok := n.gen[node]; ok {
		return ch
	}
	ch := make(chan struct{})
	n.gen[node] = ch
	return ch
}

// EnrollRequest is the bootstrap request body — the one-time token plus
// the agent's own public key (PEM "PUBLIC KEY", PKIX). The private key
// never travels; the certificate is signed for this key.
type EnrollRequest struct {
	Token     string `json:"token"`
	PublicKey string `json:"public_key"`
}

// EnrollResponse is the bootstrap response: the issued certificate, the CA
// the agent must use for subsequent mTLS polls, and the confirmed node name.
type EnrollResponse struct {
	Node string `json:"node"`
	CA   string `json:"ca"`   // CA certificate PEM
	Cert string `json:"cert"` // agent certificate PEM
}

// CertIssuer signs agent certificates during token enrollment. It is
// satisfied by *certs.CA; the interface keeps this package decoupled from
// the PKI implementation.
type CertIssuer interface {
	NewAgentCertFromKey(name string, pubPEM []byte) ([]byte, error)
	CAPEM() []byte
}

// API is the agent-facing HTTP API behind mTLS.
type API struct {
	store    *store.Store
	issuer   CertIssuer
	caCert   *x509.Certificate // parsed issuer.CAPEM(); pinned by agents via --ca-hash
	reports  *Reports
	hold     time.Duration
	notifier *Notifier
	shutdown atomic.Bool
}

// NewAPI builds the API. issuer signs certificates for token enrollment
// (nil disables /api/enroll); hold is the maximum time a current-version
// poll is held waiting for changes (<= 0 answers immediately).
func NewAPI(st *store.Store, issuer CertIssuer, reports *Reports, hold time.Duration) (*API, error) {
	a := &API{store: st, issuer: issuer, reports: reports, hold: hold, notifier: NewNotifier()}
	if issuer != nil {
		block, _ := pem.Decode(issuer.CAPEM())
		if block == nil {
			return nil, errors.New("issuer CA PEM does not decode")
		}
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("issuer CA PEM: %v", err)
		}
		a.caCert = caCert
	}
	return a, nil
}

// Notify wakes a node's hanging polls; the controller wires the store's
// OnChange hook to it so every mutation path releases waiting agents.
func (a *API) Notify(node string) { a.notifier.Wake(node) }

// WakeAll releases every hanging poll (graceful shutdown): handlers answer
// immediately with the current version — agents reconnect to the new process
// instead of waiting out the hold or eating a broken connection.
func (a *API) WakeAll() {
	a.shutdown.Store(true)
	nodes, err := a.store.ListNodes()
	if err != nil {
		return
	}
	for _, n := range nodes {
		a.notifier.Wake(n.Name)
	}
}

// Handler returns the API mux (mount behind mTLS verification).
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/poll", a.handlePoll)
	mux.HandleFunc("POST /api/enroll", a.handleEnroll)
	return mux
}

// Server builds the HTTP server for the agent API. Client certificates are
// verified when presented but not required at the TLS layer: the
// bootstrapping enrollment path (/api/enroll) authenticates by one-time
// token and has no certificate yet. Every other route (handlePoll) rejects
// certificate-less requests itself.
func (a *API) Server(addr string, cert tls.Certificate, caPool *x509.CertPool) *http.Server {
	// Serve the CA alongside the leaf so bootstrapping agents can pin the
	// root via --ca-hash against the presented chain.
	presented := cert
	if a.caCert != nil {
		presented.Certificate = append(append([][]byte{}, cert.Certificate...), a.caCert.Raw)
	}
	return &http.Server{
		Addr:    addr,
		Handler: a.Handler(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{presented},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    caPool,
			MinVersion:   tls.VersionTLS12,
		},
		// Deliberately no ReadTimeout/WriteTimeout: they would kill held
		// long-poll responses. Header and idle times are still bounded.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// handleEnroll exchanges a one-time token for a certificate signed for the
// requester's public key. Token auth only — the bootstrapping agent has no
// client certificate yet. The token is burned BEFORE signing (fail-closed:
// a failed request can never mint a second certificate) but AFTER cheap
// public-key shape checks, so malformed requests do not waste tokens.
func (a *API) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if a.issuer == nil {
		http.Error(w, "enrollment disabled", http.StatusServiceUnavailable)
		return
	}
	var req EnrollRequest
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Token == "" {
		http.Error(w, "missing token", http.StatusForbidden)
		return
	}
	if block, _ := pem.Decode([]byte(req.PublicKey)); block == nil {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}
	node, err := a.store.RedeemEnrollToken(req.Token)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "invalid, expired, or already-used enrollment token", http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	certPEM, err := a.issuer.NewAgentCertFromKey(node, []byte(req.PublicKey))
	if err != nil {
		// The token is already burned; the node needs a fresh one.
		http.Error(w, "invalid public key ("+err.Error()+") — token consumed, mint a new one", http.StatusBadRequest)
		return
	}
	fp, err := fingerprintPEM(certPEM)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := a.store.EnsureNode(node, fp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(EnrollResponse{Node: node, CA: string(a.issuer.CAPEM()), Cert: string(certPEM)}); err != nil {
		log.Printf("enroll response: %v", err)
	}
}

// handlePoll authenticates the agent by certificate CN plus fingerprint,
// records its report, and returns the desired config when the agent's
// version is stale. The fingerprint check is the revocation mechanism:
// re-running `wgmgt server enroll <node>` issues a new certificate and
// supersedes the old one immediately.
func (a *API) handlePoll(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	peerCert := r.TLS.PeerCertificates[0]
	node := peerCert.Subject.CommonName
	if node == "" || node == "wgmgt-ca" || node == "wgmgt-server" {
		http.Error(w, "invalid node certificate", http.StatusUnauthorized)
		return
	}
	n, err := a.store.GetNode(node)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "node not enrolled", http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if fp := certFingerprint(peerCert); n.Fingerprint != "" && n.Fingerprint != fp {
		http.Error(w, "certificate superseded (re-enroll the node)", http.StatusForbidden)
		return
	}

	var req PollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	a.reports.Update(node, req.Status)
	a.store.TouchNode(node, time.Now().UTC().Format(time.RFC3339))

	// Capture the wake channel BEFORE reading the version (see Notifier):
	// changes racing this request are caught either by the channel close or
	// by the version comparison, never by neither.
	ch := a.notifier.WakeCh(node)
	version, err := a.store.ConfigVersion(node)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	timer := time.NewTimer(a.hold)
	defer timer.Stop()
	timedOut := false
	for version == req.Since && a.hold > 0 && !timedOut {
		select {
		case <-ch: // config changed (or shutdown wake) — re-read and re-check
			if a.shutdown.Load() {
				timedOut = true // answer now so agents move to the new process
				continue
			}
			ch = a.notifier.WakeCh(node)
			if version, err = a.store.ConfigVersion(node); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		case <-timer.C: // hold expired: answer with the current version
			timedOut = true
		case <-r.Context().Done(): // client went away — release the goroutine
			return
		}
	}

	resp := struct {
		Version    int64             `json:"version"`
		Interfaces *[]AgentInterface `json:"interfaces,omitempty"`
	}{Version: version}

	// "Different", not "greater": deleting the top-version interface lowers
	// the node's MAX version, and that delete must reach the agent too.
	if version != req.Since {
		cfg, err := a.configFor(node)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp.Interfaces = &cfg
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("poll response: %v", err)
	}
}

// certFingerprint mirrors certs.Fingerprint without an import cycle.
func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", sum)
}

// fingerprintPEM is the PEM variant of certFingerprint.
func fingerprintPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return certFingerprint(cert), nil
}

func (a *API) configFor(node string) ([]AgentInterface, error) {
	ifaces, err := a.store.ListInterfaces(node)
	if err != nil {
		return nil, err
	}
	// Every interface (enabled or not) is pushed; agents leave disabled
	// ones down so the config travels with the node.
	peers, err := a.store.ListPeers(node, "")
	if err != nil {
		return nil, err
	}
	// Agents never need peers' client private keys — strip them so one
	// compromised node cannot harvest its peers' client identities.
	byIface := map[string][]store.Peer{}
	for _, p := range peers {
		p.ClientPrivateKey = ""
		byIface[p.Interface] = append(byIface[p.Interface], p)
	}
	out := make([]AgentInterface, 0, len(ifaces))
	for _, ifc := range ifaces {
		ps := byIface[ifc.Name]
		if ps == nil {
			ps = []store.Peer{}
		}
		out = append(out, AgentInterface{
			Name: ifc.Name, PrivateKey: ifc.PrivateKey, ListenPort: ifc.ListenPort,
			Address: ifc.Address, MTU: ifc.MTU, Enabled: ifc.Enabled,
			PostUp: ifc.PostUp, PostDown: ifc.PostDown, Peers: ps,
		})
	}
	return out, nil
}
