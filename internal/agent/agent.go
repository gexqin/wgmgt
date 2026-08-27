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
	"strconv"
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

	// Dead-man switch: after applying a config, the agent must reach the
	// controller again within verifyTimeout. If it cannot (a full-tunnel
	// route locked the node out, say), it tears its WireGuard down and
	// refuses to re-apply that config version (quarantine) — the operator
	// fixes the config, the version bumps, and the agent tries again.
	verifyTimeout  time.Duration
	verifying      bool
	pendingSince   time.Time
	quarantinedVer int64
	sigs           map[string]ifaceSig // routing signatures of applied interfaces
}

// New builds an agent. caPEM/certPEM/keyPEM are the mTLS material issued
// by `wgmgt server enroll`. verifyTimeout enables the dead-man switch
// (0 disables it).
func New(serverURL string, caPEM, certPEM, keyPEM []byte, interval, verifyTimeout time.Duration, confDir string) (*Agent, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid CA PEM")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("agent certificate: %w", err)
	}
	a := &Agent{
		serverURL: strings.TrimSuffix(serverURL, "/"),
		client: &http.Client{
			// A hard request timeout matters: a locked-out node's polls hang
			// on TCP connects that never complete, and the watchdog must
			// still get scheduled — the Run loop only ticks between polls.
			Timeout: 10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
				MinVersion:   tls.VersionTLS12,
			}},
		},
		interval:      interval,
		verifyTimeout: verifyTimeout,
		confDir:       confDir,
	}
	a.loadQuarantine()
	return a, nil
}

// Run polls until the context is cancelled. The first poll happens
// immediately (appliedVer 0 forces a full config fetch). The watchdog runs
// on a short side ticker so a locked-out node still fires on time even
// with a long poll interval.
func (a *Agent) Run(ctx context.Context) error {
	poll := time.NewTicker(a.interval)
	defer poll.Stop()
	watch := time.NewTicker(5 * time.Second)
	defer watch.Stop()
	for {
		if err := a.PollOnce(ctx); err != nil {
			log.Printf("agent: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-watch.C:
			a.checkWatchdog()
		case <-poll.C:
		}
	}
}

// checkWatchdog rolls back an unverified config.
func (a *Agent) checkWatchdog() {
	if a.verifyTimeout <= 0 || !a.verifying {
		return
	}
	if time.Since(a.pendingSince) <= a.verifyTimeout {
		return
	}
	log.Printf("agent: controller unreachable for %s after applying config v%d — rolling back WireGuard (quarantined until a newer version)",
		a.verifyTimeout, a.appliedVer)
	a.teardown()
	a.quarantinedVer = a.appliedVer
	a.saveQuarantine(a.quarantinedVer)
	a.verifying = false
}

// Quarantine survives restarts (a locked-out-then-rebooted node must not
// reapply the same broken config), so it lives in the conf dir.
func (a *Agent) quarantinePath() string { return filepath.Join(a.confDir, ".quarantine") }

func (a *Agent) saveQuarantine(version int64) {
	os.MkdirAll(a.confDir, 0o700)
	os.WriteFile(a.quarantinePath(), []byte(strconv.FormatInt(version, 10)), 0o600)
}

func (a *Agent) loadQuarantine() {
	b, err := os.ReadFile(a.quarantinePath())
	if err != nil {
		return
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && v > 0 {
		a.quarantinedVer = v
		log.Printf("agent: resuming quarantine at config v%d", v)
	}
}

func (a *Agent) clearQuarantine() {
	a.quarantinedVer = 0
	os.Remove(a.quarantinePath())
}

// teardown stops every managed interface (conf files stay as the record
// of the managed set; devices come back when a good config arrives).
func (a *Agent) teardown() {
	entries, err := os.ReadDir(a.confDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".conf")
		if name == e.Name() {
			continue
		}
		if err := wgctl.Down(&store.Interface{Name: name}); err != nil {
			log.Printf("agent: rollback %s: %v", name, err)
		}
	}
}

// PollOnce fetches new config (if any), applies it, and reports status.
// A successful poll also confirms the previously applied config (contact
// with the controller proves the node is not locked out).
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
		if a.quarantinedVer > 0 && cfg.Version <= a.quarantinedVer {
			// The config that locked us out is still current; stay down.
			a.appliedVer = cfg.Version
		} else if err := a.Apply(*cfg.Interfaces); err != nil {
			return fmt.Errorf("apply v%d: %w", cfg.Version, err)
		} else {
			a.appliedVer = cfg.Version
			a.clearQuarantine()
			if a.verifyTimeout > 0 {
				// New config pending verification by the NEXT poll.
				a.verifying = true
				a.pendingSince = time.Now()
			}
			log.Printf("agent: applied config v%d (%d interfaces)", cfg.Version, len(*cfg.Interfaces))
		}
	} else {
		a.appliedVer = cfg.Version
		// Reaching the controller proves the applied config is safe.
		a.verifying = false
	}
	return nil
}

// ifaceSig captures everything about an interface that cannot be changed
// by a hot peer update: address, port, MTU, and whether policy routing
// (a default route) is engaged. A signature change requires a rebuild.
type ifaceSig struct {
	addr   string
	port   int
	mtu    int
	policy bool
}

func sigOf(ci control.AgentInterface) ifaceSig {
	v4, v6 := wgctl.DefaultRouteFamilies(ci.Peers)
	return ifaceSig{addr: ci.Address, port: ci.ListenPort, mtu: ci.MTU, policy: v4 || v6}
}

// Apply converges the node to the desired state: enabled interfaces up
// with the right peers, disabled interfaces down, conf files written.
// Peer-only changes hot-apply; routing-signature changes (address, port,
// MTU, default-route on/off) rebuild the device.
func (a *Agent) Apply(cfg []control.AgentInterface) error {
	if err := os.MkdirAll(a.confDir, 0o700); err != nil {
		return err
	}
	if a.sigs == nil {
		a.sigs = map[string]ifaceSig{}
	}
	for _, ci := range cfg {
		// Defense in depth: the controller validates names too, but the
		// conf-file writes below turn names into paths, so an agent never
		// trusts a name it did not verify itself.
		if !store.ValidIfaceName(ci.Name) {
			return fmt.Errorf("invalid interface name %q from controller", ci.Name)
		}
		ifc := &store.Interface{
			Name: ci.Name, PrivateKey: ci.PrivateKey, ListenPort: ci.ListenPort,
			Address: ci.Address, MTU: ci.MTU, PostUp: ci.PostUp, PostDown: ci.PostDown,
		}
		path := filepath.Join(a.confDir, ci.Name+".conf")
		if !ci.Enabled {
			os.Remove(path)
			delete(a.sigs, ci.Name)
			if wgctl.Exists(ci.Name) {
				if err := wgctl.Down(ifc); err != nil {
					return fmt.Errorf("down %s: %w", ci.Name, err)
				}
			}
			continue
		}
		// Conf first (also marks the interface as managed), then netlink.
		if err := os.WriteFile(path, []byte(confgen.Interface(ifc, ci.Peers)), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		sig := sigOf(ci)
		prev, known := a.sigs[ci.Name]
		// An unknown signature (agent restart with the device up) rebuilds
		// once — otherwise routing changes would never reach a device that
		// outlived the agent process.
		if !wgctl.Exists(ci.Name) || !known || prev != sig {
			if wgctl.Exists(ci.Name) {
				if err := wgctl.Down(ifc); err != nil {
					return fmt.Errorf("rebuild down %s: %w", ci.Name, err)
				}
			}
			if err := wgctl.Up(ifc, ci.Peers); err != nil {
				return fmt.Errorf("up %s: %w", ci.Name, err)
			}
			a.sigs[ci.Name] = sig
		} else if err := wgctl.ApplyPeers(ifc, ci.Peers); err != nil {
			return fmt.Errorf("apply peers %s: %w", ci.Name, err)
		}
	}
	return nil
}

// collectStatus reports every managed interface (the conf files mark the
// managed set, surviving agent restarts) with live peer counters.
func (a *Agent) collectStatus() control.StatusReport {
	rep := control.StatusReport{Quarantined: a.quarantinedVer > 0, Interfaces: []control.IfaceReport{}}
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
