// Package agent implements the wgmgt agent: a stateless pull loop that
// fetches its node's desired config from the controller over mTLS, applies
// it via netlink, and reports live status back with each poll. The agent's
// only local state is its certificate and the generated conf files.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gexqin/wgmgt/internal/confgen"
	"github.com/gexqin/wgmgt/internal/control"
	"github.com/gexqin/wgmgt/internal/store"
	"github.com/gexqin/wgmgt/internal/wgctl"
)

// Agent polls the controller and applies config.
type Agent struct {
	serverURL  string
	client     *http.Client
	interval   time.Duration
	confDir    string
	appliedVer int64
}

// New builds an agent. caPEM/certPEM/keyPEM are the mTLS material issued
// by `wgmgt server enroll`.
func New(serverURL string, caPEM, certPEM, keyPEM []byte, interval time.Duration, confDir string) (*Agent, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid CA PEM")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("agent certificate: %w", err)
	}
	return &Agent{
		serverURL: strings.TrimSuffix(serverURL, "/"),
		client: &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
				MinVersion:   tls.VersionTLS12,
			}},
		},
		interval: interval,
		confDir:  confDir,
	}, nil
}

// Run polls until the context is cancelled. The first poll happens
// immediately (appliedVer 0 forces a full config fetch).
func (a *Agent) Run(ctx context.Context) error {
	t := time.NewTicker(a.interval)
	defer t.Stop()
	for {
		if err := a.PollOnce(ctx); err != nil {
			log.Printf("agent: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// PollOnce fetches new config (if any), applies it, and reports status.
func (a *Agent) PollOnce(ctx context.Context) error {
	body, _ := json.Marshal(control.PollRequest{Since: a.appliedVer, Status: a.collectStatus()})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.serverURL+"/api/poll", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("poll: %s", resp.Status)
	}
	var cfg struct {
		Version    int64                     `json:"version"`
		Interfaces *[]control.AgentInterface `json:"interfaces"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return err
	}
	if cfg.Interfaces != nil && *cfg.Interfaces != nil {
		if err := a.Apply(*cfg.Interfaces); err != nil {
			return fmt.Errorf("apply v%d: %w", cfg.Version, err)
		}
		a.appliedVer = cfg.Version
		log.Printf("agent: applied config v%d (%d interfaces)", cfg.Version, len(*cfg.Interfaces))
	} else {
		a.appliedVer = cfg.Version
	}
	return nil
}

// Apply converges the node to the desired state: enabled interfaces up
// with the right peers, disabled interfaces down, conf files written.
func (a *Agent) Apply(cfg []control.AgentInterface) error {
	if err := os.MkdirAll(a.confDir, 0o700); err != nil {
		return err
	}
	for _, ci := range cfg {
		ifc := &store.Interface{
			Name: ci.Name, PrivateKey: ci.PrivateKey, ListenPort: ci.ListenPort,
			Address: ci.Address, MTU: ci.MTU, PostUp: ci.PostUp, PostDown: ci.PostDown,
		}
		path := filepath.Join(a.confDir, ci.Name+".conf")
		if ci.Enabled {
			// Conf first (also marks the interface as managed), then netlink.
			if err := os.WriteFile(path, []byte(confgen.Interface(ifc, ci.Peers)), 0o600); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
			if !wgctl.Exists(ci.Name) {
				if err := wgctl.Up(ifc, ci.Peers); err != nil {
					return fmt.Errorf("up %s: %w", ci.Name, err)
				}
			} else if err := wgctl.ApplyPeers(ifc, ci.Peers); err != nil {
				return fmt.Errorf("apply peers %s: %w", ci.Name, err)
			}
		} else {
			os.Remove(path)
			if wgctl.Exists(ci.Name) {
				if err := wgctl.Down(ifc); err != nil {
					return fmt.Errorf("down %s: %w", ci.Name, err)
				}
			}
		}
	}
	return nil
}

// collectStatus reports every managed interface (the conf files mark the
// managed set, surviving agent restarts) with live peer counters.
func (a *Agent) collectStatus() control.StatusReport {
	rep := control.StatusReport{Interfaces: []control.IfaceReport{}}
	entries, err := os.ReadDir(a.confDir)
	if err != nil {
		return rep
	}
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".conf")
		if name == e.Name() {
			continue
		}
		ir := control.IfaceReport{Name: name, Peers: []control.PeerReport{}}
		if wgctl.Exists(name) {
			ir.Up = true
			if live, err := wgctl.DeviceStatus(name); err == nil {
				for pub, st := range live {
					ir.Peers = append(ir.Peers, control.PeerReport{
						PublicKey: pub, Handshake: st.LastHandshake,
						Rx: st.Rx, Tx: st.Tx, Endpoint: st.Endpoint,
					})
				}
			}
		}
		rep.Interfaces = append(rep.Interfaces, ir)
	}
	return rep
}
