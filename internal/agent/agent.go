// Package agent implements the wgmgt agent: a stateless pull loop that
// fetches its client's desired config from the controller over mTLS, applies
// it via netlink, and reports live status back with each poll. The agent's
// only local state is its certificate and the generated conf files.
package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gexqin/wgmgt/internal/confgen"
	"github.com/gexqin/wgmgt/internal/control"
	"github.com/gexqin/wgmgt/internal/fileutil"
	"github.com/gexqin/wgmgt/internal/store"
	"github.com/gexqin/wgmgt/internal/wgctl"
)

// ErrRevoked means the controller explicitly rejected this agent's identity.
// It is not retried: the managed tunnels are removed before Run returns.
var ErrRevoked = errors.New("agent enrollment revoked")

// Agent polls the controller and applies config.
type Agent struct {
	serverURL  string
	client     *http.Client
	interval   time.Duration // backoff after a failed poll
	confDir    string
	appliedVer int64

	// Dead-man switch: after applying a config, the agent must reach the
	// controller again within verifyTimeout. If it cannot (a full-tunnel
	// route locked the client out, say), it tears its WireGuard down and
	// refuses to re-apply that config version (quarantine) — the operator
	// fixes the config, the version bumps, and the agent tries again.
	verifyTimeout  time.Duration
	verifying      bool
	pendingSince   time.Time
	quarantinedVer int64
	gotConfig      bool                // last poll delivered a config (Run pacing)
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
			// No blanket Timeout: it would abort held long-poll responses.
			// Instead the phases are bounded individually — dial/handshake
			// timeouts keep a black-holed (locked-out) client failing in ~10s
			// so the Run loop keeps scheduling the watchdog, and the header
			// timeout bounds a silent controller for everyone else. The
			// server's --poll-hold must stay below it.
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 60 * time.Second,
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					RootCAs:      pool,
					MinVersion:   tls.VersionTLS12,
				},
			},
		},
		interval:      interval,
		appliedVer:    -1,
		verifyTimeout: verifyTimeout,
		confDir:       confDir,
	}
	a.loadQuarantine()
	return a, nil
}

// Run polls until the context is cancelled. The first poll happens
// immediately (appliedVer -1 forces a full config fetch, including an empty
// desired state at controller revision 0). Each successful
// long-poll blocks for the server's hold time, so the request itself is the
// sleep — the agent reconnects instantly, and config changes reach it in
// milliseconds. The watchdog runs on a short side ticker so a locked-out
// client still fires on time even while polls fail or back off.
func (a *Agent) Run(ctx context.Context) error {
	watch := time.NewTicker(5 * time.Second)
	defer watch.Stop()
	for {
		start := time.Now()
		err := a.PollOnce(ctx)
		switch {
		case errors.Is(err, ErrRevoked):
			a.teardown(true)
			return err
		case err != nil:
			log.Printf("agent: %v", err)
			select {
			case <-ctx.Done():
				return nil
			case <-watch.C:
				a.checkWatchdog()
			case <-time.After(a.interval): // retry backoff
			}
		case a.gotConfig || time.Since(start) >= fastGap:
			// A pushed config (or a full-length hold) means the server is
			// long-polling: re-poll immediately, the next request hangs.
			// Drain a pending watchdog tick so rapid config changes cannot
			// starve it (it also runs inside the blocking poll's downtime).
			select {
			case <-watch.C:
				a.checkWatchdog()
			default:
			}
			select {
			case <-ctx.Done():
				return nil
			default:
			}
		default:
			// Fast "no change" answer: the server is not holding (hold=0 or
			// an old controller) — pace by the backoff interval to avoid a
			// hot loop, like the old interval-polling agent did.
			select {
			case <-ctx.Done():
				return nil
			case <-watch.C:
				a.checkWatchdog()
			case <-time.After(a.interval):
			}
		}
	}
}

// fastGap is the minimum round-trip that counts as "the server held the
// poll". Responses faster than this with no config mean no long-polling.
const fastGap = 5 * time.Second

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
	a.teardown(false)
	a.quarantinedVer = a.appliedVer
	a.saveQuarantine(a.quarantinedVer)
	a.verifying = false
}

// Quarantine survives restarts (a locked-out-then-rebooted client must not
// reapply the same broken config), so it lives in the conf dir.
func (a *Agent) quarantinePath() string { return filepath.Join(a.confDir, ".quarantine") }

func (a *Agent) saveQuarantine(version int64) {
	if err := os.MkdirAll(a.confDir, 0o700); err != nil {
		log.Printf("agent: save quarantine: %v", err)
		return
	}
	if err := fileutil.WriteAtomic(a.quarantinePath(), []byte(strconv.FormatInt(version, 10)), 0o600); err != nil {
		log.Printf("agent: save quarantine: %v", err)
	}
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
	if err := os.Remove(a.quarantinePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("agent: clear quarantine: %v", err)
	}
}

// teardown stops every managed interface. Revocation also removes generated
// conf files so a restarted process cannot treat stale desired state as live.
func (a *Agent) teardown(removeConfs bool) {
	entries, err := os.ReadDir(a.confDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".conf")
		if name == e.Name() {
			continue
		}
		ifc, err := ManagedInterfaceFromConf(filepath.Join(a.confDir, e.Name()), name)
		if err != nil {
			log.Printf("agent: rollback %s: %v", name, err)
			if removeConfs {
				if removeErr := os.Remove(filepath.Join(a.confDir, e.Name())); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
					log.Printf("agent: remove revoked config %s: %v", name, removeErr)
				}
			}
			continue
		}
		if wgctl.Exists(name) {
			if err := wgctl.Down(ifc); err != nil {
				log.Printf("agent: rollback %s: %v", name, err)
				continue
			}
		}
		if removeConfs {
			if err := os.Remove(filepath.Join(a.confDir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				log.Printf("agent: remove revoked config %s: %v", name, err)
			}
		}
		delete(a.sigs, name)
	}
	if removeConfs {
		a.clearQuarantine()
	}
}

// ManagedInterfaceFromConf reads the ownership key from a WGMGT-generated
// conf file. Destructive recovery paths use it to prove a device is ours.
func ManagedInterfaceFromConf(confPath, name string) (*store.Interface, error) {
	f, err := os.Open(confPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok && strings.TrimSpace(key) == "PrivateKey" {
			privateKey := strings.TrimSpace(value)
			if privateKey == "" {
				break
			}
			return &store.Interface{Name: name, PrivateKey: privateKey}, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("generated config has no interface private key")
}

// PollOnce fetches new config (if any), applies it, and reports status.
// A successful poll also confirms the previously applied config (contact
// with the controller proves the client is not locked out).
func (a *Agent) PollOnce(ctx context.Context) error {
	a.gotConfig = false
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
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w: poll answered %s", ErrRevoked, resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("poll: %s", resp.Status)
	}
	var cfg struct {
		Version    int64                     `json:"version"`
		Interfaces *[]control.AgentInterface `json:"interfaces"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&cfg); err != nil {
		return err
	}
	if cfg.Interfaces != nil && *cfg.Interfaces != nil {
		a.gotConfig = true
		if a.quarantinedVer > 0 && cfg.Version == a.quarantinedVer {
			// The config that locked us out is still current; stay down.
			// Exactly equal, not <=: a controller reset may restart revisions,
			// and a freshly enrolled client must be allowed to recover.
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
// by a hot peer update: address, port, MTU, routing table/mark, and whether
// policy routing (a default route) is engaged. A change requires a rebuild.
type ifaceSig struct {
	addr, table, fwmark string
	port, mtu           int
	policy              bool
}

func sigOf(ci control.AgentInterface) ifaceSig {
	v4, v6 := wgctl.DefaultRouteFamilies(ci.Peers)
	return ifaceSig{addr: ci.Address, port: ci.ListenPort, mtu: ci.MTU, table: ci.RouteTable, fwmark: ci.Fwmark, policy: v4 || v6}
}

// Apply converges the client to the desired state: enabled interfaces up
// with the right peers, disabled interfaces down, conf files written.
// Peer-only changes hot-apply; routing-signature changes (address, port,
// MTU, default-route on/off) rebuild the device.
func (a *Agent) Apply(cfg []control.AgentInterface) error {
	if err := os.MkdirAll(a.confDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(a.confDir, 0o700); err != nil {
		return fmt.Errorf("secure conf directory: %w", err)
	}
	if a.sigs == nil {
		a.sigs = map[string]ifaceSig{}
	}
	desired := make(map[string]bool, len(cfg))
	for _, ci := range cfg {
		// Defense in depth: the controller validates names too, but the
		// conf-file writes below turn names into paths, so an agent never
		// trusts a name it did not verify itself.
		if !store.ValidIfaceName(ci.Name) {
			return fmt.Errorf("invalid interface name %q from controller", ci.Name)
		}
		desired[ci.Name] = true
		ifc := &store.Interface{
			Name: ci.Name, PrivateKey: ci.PrivateKey, ListenPort: ci.ListenPort,
			Address: ci.Address, MTU: ci.MTU, DNS: ci.DNS, RouteTable: ci.RouteTable,
			Fwmark: ci.Fwmark, PostUp: ci.PostUp, PostDown: ci.PostDown,
		}
		path := filepath.Join(a.confDir, ci.Name+".conf")
		downIfc := ifc
		if wgctl.Exists(ci.Name) {
			if old, err := ManagedInterfaceFromConf(path, ci.Name); err == nil {
				old.PostDown = ifc.PostDown
				downIfc = old
			}
		}
		if !ci.Enabled {
			if wgctl.Exists(ci.Name) {
				if err := wgctl.Down(downIfc); err != nil {
					return fmt.Errorf("down %s: %w", ci.Name, err)
				}
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove disabled config %s: %w", ci.Name, err)
			}
			delete(a.sigs, ci.Name)
			continue
		}
		// Conf first (also marks the interface as managed), then netlink.
		if err := fileutil.WriteAtomic(path, []byte(confgen.Interface(ifc, ci.Peers)), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		sig := sigOf(ci)
		prev, known := a.sigs[ci.Name]
		// An unknown signature (agent restart with the device up) rebuilds
		// once — otherwise routing changes would never reach a device that
		// outlived the agent process.
		if !wgctl.Exists(ci.Name) || !known || prev != sig {
			if wgctl.Exists(ci.Name) {
				if err := wgctl.Down(downIfc); err != nil {
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
	return a.removeAbsent(desired)
}

func (a *Agent) removeAbsent(desired map[string]bool) error {
	entries, err := os.ReadDir(a.confDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".conf")
		if name == e.Name() || desired[name] {
			continue
		}
		if !store.ValidIfaceName(name) {
			return fmt.Errorf("refusing to remove invalid managed interface name %q", name)
		}
		path := filepath.Join(a.confDir, e.Name())
		ifc, err := ManagedInterfaceFromConf(path, name)
		if err != nil {
			return fmt.Errorf("read stale config %s: %w", name, err)
		}
		if wgctl.Exists(name) {
			if err := wgctl.Down(ifc); err != nil {
				return fmt.Errorf("remove stale interface %s: %w", name, err)
			}
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale config %s: %w", name, err)
		}
		delete(a.sigs, name)
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
