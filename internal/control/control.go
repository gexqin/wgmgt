// Package control implements the wgmgt controller's agent-facing API and
// state. Protocol (per plan decision #13): JSON over TLS with mutual
// certificate authentication; agents connect outbound and pull their
// configuration on an interval; the agent certificate CN is the node name.
package control

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"sync"
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
	Interfaces []IfaceReport `json:"interfaces"`
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

// API is the agent-facing HTTP API behind mTLS.
type API struct {
	store   *store.Store
	reports *Reports
}

func NewAPI(st *store.Store, reports *Reports) *API {
	return &API{store: st, reports: reports}
}

// Handler returns the API mux (mount behind mTLS verification).
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/poll", a.handlePoll)
	return mux
}

// Server builds the mTLS HTTP server.
func (a *API) Server(addr string, cert tls.Certificate, caPool *x509.CertPool) *http.Server {
	return &http.Server{
		Addr:    addr,
		Handler: a.Handler(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caPool,
			MinVersion:   tls.VersionTLS12,
		},
	}
}

// handlePoll authenticates the agent by certificate CN, records its report,
// and returns the desired config when the agent's version is stale.
func (a *API) handlePoll(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	node := r.TLS.PeerCertificates[0].Subject.CommonName
	if node == "" || node == "wgmgt-ca" || node == "wgmgt-server" {
		http.Error(w, "invalid node certificate", http.StatusUnauthorized)
		return
	}

	var req PollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	a.reports.Update(node, req.Status)
	a.store.TouchNode(node, time.Now().UTC().Format(time.RFC3339))

	version, err := a.store.ConfigVersion(node)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := struct {
		Version    int64             `json:"version"`
		Interfaces *[]AgentInterface `json:"interfaces,omitempty"`
	}{Version: version}

	if version > req.Since {
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
	byIface := map[string][]store.Peer{}
	for _, p := range peers {
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
