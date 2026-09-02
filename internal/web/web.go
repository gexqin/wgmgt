// Package web serves the embedded WGMGT web UI: dashboard, interface and
// peer management, live status. Every route lives under /t/<token>/, so
// only whoever sees the startup URL can reach the UI — that covers both
// random scanners and browser-side CSRF/DNS-rebinding against localhost.
//
// Two modes: local (single host, drives netlink directly) and controller
// (wgmgt server; interfaces belong to clients, live status comes from agent
// reports, up/down toggles the client's desired state).
package web

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/gexqin/wgmgt/internal/app"
	"github.com/gexqin/wgmgt/internal/confgen"
	"github.com/gexqin/wgmgt/internal/control"
	"github.com/gexqin/wgmgt/internal/humanize"
	"github.com/gexqin/wgmgt/internal/store"
	"github.com/gexqin/wgmgt/internal/wgctl"
)

//go:embed templates static
var files embed.FS

// Server is the web UI. Construct with New (local) or NewController.
type Server struct {
	app        *app.App
	token      string
	prefix     string // "/t/<token>"
	controller bool
	reports    *control.Reports
	apiURL     string // advertised agent API URL (join commands)
	caHash     string // controller CA fingerprint (join commands)
	// Pending join commands, served exactly once by handleEnrollShow.
	enrollMu   sync.Mutex
	enrollPend map[string]enrollView
	pages      map[string]*template.Template
	partial    *template.Template
	mux        *http.ServeMux
}

// ControllerOpts carries controller wiring the console needs to render
// agent join commands.
type ControllerOpts struct {
	APIURL        string // e.g. "https://ctrl.example.com:8443"
	CAFingerprint string // hex sha256 of the controller CA
}

// New builds a local-mode Server with a fresh random token.
func New(a *app.App) (*Server, error) { return newServer(a, false, nil, ControllerOpts{}) }

// NewController builds a controller-mode Server fed by agent reports.
func NewController(a *app.App, reports *control.Reports, opts ControllerOpts) (*Server, error) {
	return newServer(a, true, reports, opts)
}

func newServer(a *app.App, controller bool, reports *control.Reports, opts ControllerOpts) (*Server, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	s := &Server{
		app:        a,
		token:      hex.EncodeToString(buf),
		prefix:     "/t/" + hex.EncodeToString(buf),
		controller: controller,
		reports:    reports,
		apiURL:     opts.APIURL,
		caHash:     opts.CAFingerprint,
		enrollPend: map[string]enrollView{},
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

// Token returns the auth token embedded in every URL.
func (s *Server) Token() string { return s.token }

// URL returns the entry URL for the given host:port.
func (s *Server) URL(host string) string { return "http://" + host + s.prefix + "/" }

// url builds an absolute in-app path from path elements.
func (s *Server) url(elem ...string) string {
	joined := path.Join(append([]string{s.prefix}, elem...)...)
	if joined == s.prefix {
		return s.prefix + "/"
	}
	return joined
}

// ifaceURL builds the URL of an interface page (and sub-paths) in either mode.
func (s *Server) ifaceURL(ifc store.Interface, rest ...string) string {
	if s.controller {
		return s.url(append([]string{"client", ifc.Client, "iface", ifc.Name}, rest...)...)
	}
	return s.url(append([]string{"iface", ifc.Name}, rest...)...)
}

// Handler wraps the mux with the token check.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		}
		p := r.URL.Path
		if p == s.prefix {
			http.Redirect(w, r, s.prefix+"/", http.StatusTemporaryRedirect)
			return
		}
		if !strings.HasPrefix(p, s.prefix+"/") {
			http.NotFound(w, r)
			return
		}
		r.URL.Path = "/" + strings.TrimPrefix(p, s.prefix+"/")
		s.mux.ServeHTTP(w, r)
	})
}

// HTTPServer returns a bounded web server. The token check happens after HTTP
// parsing, so header/read timeouts are required even for unauthenticated peers.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

func (s *Server) routes() {
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET /static/", s.handleStatic)
	if s.controller {
		s.mux.HandleFunc("GET /{$}", s.handleDashboard)
		s.mux.HandleFunc("POST /clients", s.handleClientAdd)
		s.mux.HandleFunc("GET /enroll/{id}", s.handleEnrollShow)
		s.mux.HandleFunc("GET /client/{client}", s.handleClient)
		s.mux.HandleFunc("POST /client/{client}/token", s.handleClientToken)
		s.mux.HandleFunc("POST /client/{client}/rm", s.handleClientRm)
		s.mux.HandleFunc("POST /client/{client}/peers", s.handlePeerQuickAdd)
		s.mux.HandleFunc("POST /client/{client}/ifaces", s.handleIfaceCreate)
		s.mux.HandleFunc("GET /client/{client}/iface/{name}", s.handleIface)
		s.mux.HandleFunc("GET /client/{client}/iface/{name}/peers-table", s.handlePeersTable)
		s.mux.HandleFunc("GET /client/{client}/iface/{name}/peers/{ref}/conf", s.handlePeerConf)
		s.mux.HandleFunc("POST /client/{client}/iface/{name}/up", s.handleUp)
		s.mux.HandleFunc("POST /client/{client}/iface/{name}/down", s.handleDown)
		s.mux.HandleFunc("POST /client/{client}/iface/{name}/peers", s.handlePeerAdd)
		s.mux.HandleFunc("POST /client/{client}/iface/{name}/peers/{ref}/rm", s.handlePeerRm)
		return
	}
	s.mux.HandleFunc("GET /{$}", s.handleDashboard)
	s.mux.HandleFunc("GET /iface/{name}", s.handleIface)
	s.mux.HandleFunc("GET /iface/{name}/peers-table", s.handlePeersTable)
	s.mux.HandleFunc("GET /iface/{name}/peers/{ref}/conf", s.handlePeerConf)
	s.mux.HandleFunc("POST /iface/{name}/up", s.handleUp)
	s.mux.HandleFunc("POST /iface/{name}/down", s.handleDown)
	s.mux.HandleFunc("POST /iface/{name}/peers", s.handlePeerAdd)
	s.mux.HandleFunc("POST /iface/{name}/peers/{ref}/rm", s.handlePeerRm)
}

func (s *Server) parseTemplates() error {
	funcs := template.FuncMap{
		"u": s.url,
		"iu": func(ifc store.Interface, rest ...string) string {
			return s.ifaceURL(ifc, rest...)
		},
		"orDash": func(v string) string {
			if v == "" {
				return "–"
			}
			return v
		},
		"pubkey": func(priv string) string {
			k, err := wgtypes.ParseKey(priv)
			if err != nil {
				return "–"
			}
			return k.PublicKey().String()
		},
	}
	base, err := template.New("base").Funcs(funcs).ParseFS(files, "templates/base.html")
	if err != nil {
		return err
	}
	s.pages = map[string]*template.Template{}
	pages := []string{"dashboard.html", "iface.html", "peerconf.html", "error.html", "client.html", "enroll.html"}
	for _, page := range pages {
		t, err := template.Must(base.Clone()).ParseFS(files, "templates/"+page, "templates/peers.html")
		if err != nil {
			return fmt.Errorf("parse %s: %w", page, err)
		}
		s.pages[page] = t
	}
	s.partial = template.Must(template.New("peers").Funcs(funcs).ParseFS(files, "templates/peers.html"))
	return nil
}

// --- views ---

type peerView struct {
	Peer store.Peer
	Live *wgctl.PeerStatus
	Ago  string
	Rx   string
	Tx   string
}

type ifaceView struct {
	Iface store.Interface
	Up    bool
	Peers []peerView
	Rx    string // live totals
	Tx    string
}

type cardView struct {
	Name    string
	Address string
	Port    int
	Up      bool
	Peers   int
}

type clientCard struct {
	Name        string
	LastSeen    string // humanized, "" if never
	Online      bool
	Quarantined bool
	Interfaces  int
}

// liveStatus resolves the live state of an interface in either mode.
func (s *Server) liveStatus(ifc *store.Interface) (bool, map[string]wgctl.PeerStatus) {
	if s.controller {
		rep := s.reports.Get(ifc.Client)
		for _, ir := range rep.Report.Interfaces {
			if ir.Name != ifc.Name {
				continue
			}
			live := make(map[string]wgctl.PeerStatus, len(ir.Peers))
			for _, pr := range ir.Peers {
				live[pr.PublicKey] = wgctl.PeerStatus{
					LastHandshake: pr.Handshake, Rx: pr.Rx, Tx: pr.Tx, Endpoint: pr.Endpoint,
				}
			}
			return ir.Up, live
		}
		return false, nil
	}
	if !wgctl.Exists(ifc.Name) {
		return false, nil
	}
	live, err := wgctl.DeviceStatus(ifc.Name)
	if err != nil {
		log.Printf("device status %q: %v", ifc.Name, err)
		return true, nil
	}
	return true, live
}

func (s *Server) viewOf(client, name string) (ifaceView, error) {
	ifc, err := s.app.Store.GetInterface(client, name)
	if err != nil {
		return ifaceView{}, err
	}
	peers, err := s.app.Store.ListPeers(ifc.Client, ifc.Name)
	if err != nil {
		return ifaceView{}, err
	}
	up, live := s.liveStatus(ifc)
	v := ifaceView{Iface: *ifc, Up: up, Peers: []peerView{}}
	var rx, tx int64
	for _, p := range peers {
		pv := peerView{Peer: p}
		if st, ok := live[p.PublicKey]; ok {
			pv.Live = &st
			pv.Ago = humanize.Duration(humanize.Since(st.LastHandshake))
			pv.Rx = humanize.Bytes(st.Rx)
			pv.Tx = humanize.Bytes(st.Tx)
			rx += st.Rx
			tx += st.Tx
		}
		v.Peers = append(v.Peers, pv)
	}
	v.Rx = humanize.Bytes(rx)
	v.Tx = humanize.Bytes(tx)
	return v, nil
}

// --- handlers ---

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if s.controller {
		clients, err := s.app.Store.ListClients()
		if err != nil {
			s.serverError(w, err)
			return
		}
		ifaces, err := s.app.Store.ListInterfaces("") // "" = all clients
		if err != nil {
			s.serverError(w, err)
			return
		}
		counts := map[string]int{}
		for _, ifc := range ifaces {
			counts[ifc.Client]++
		}
		cards := make([]clientCard, 0, len(clients))
		for _, n := range clients {
			c := clientCard{Name: n.Name, Interfaces: counts[n.Name]}
			if entry := s.reports.Get(n.Name); !entry.When.IsZero() {
				age := time.Since(entry.When)
				c.LastSeen = humanize.Duration(age)
				c.Online = age < 2*time.Minute
				c.Quarantined = entry.Report.Quarantined
			}
			cards = append(cards, c)
		}
		s.render(w, http.StatusOK, "dashboard.html", struct {
			Controller bool
			Clients    []clientCard
		}{true, cards})
		return
	}
	ifaces, err := s.app.Store.ListInterfaces("")
	if err != nil {
		s.serverError(w, err)
		return
	}
	cards := make([]cardView, 0, len(ifaces))
	for _, ifc := range ifaces {
		peers, _ := s.app.Store.ListPeers("", ifc.Name)
		cards = append(cards, cardView{ifc.Name, ifc.Address, ifc.ListenPort, wgctl.Exists(ifc.Name), len(peers)})
	}
	s.render(w, http.StatusOK, "dashboard.html", struct {
		Controller bool
		Cards      []cardView
	}{false, cards})
}

// enrollTokenTTL is how long a minted enrollment token stays redeemable.
const enrollTokenTTL = 24 * time.Hour

// enrollView is a freshly minted join command, shown exactly once.
type enrollView struct {
	Client  string
	Token   string
	Command string
	Expires time.Time
}

// handleClientAdd is controller-only: the "Add client" form mints a one-time
// enrollment token and redirects to a page showing the join command.
func (s *Server) handleClientAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.badRequest(w, "bad form")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		s.badRequest(w, "client name is required")
		return
	}
	// Client names become URL paths and certificate CNs — keep them strict.
	if !store.ValidClientName(name) {
		s.badRequest(w, "invalid client name (max 64 chars, starts with [a-zA-Z0-9], then [a-zA-Z0-9_.-])")
		return
	}
	if err := s.app.Store.EnsureClientPending(name); err != nil {
		s.serverError(w, err)
		return
	}
	s.mintEnrollToken(w, r, name)
}

// handleClientToken re-mints an existing client's enrollment token: the old
// outstanding token (if any) is revoked, so each client has at most one live
// token. Re-minting for an enrolled client is the re-enrollment path — the
// new certificate supersedes the old one via the fingerprint check.
func (s *Server) handleClientToken(w http.ResponseWriter, r *http.Request) {
	client := r.PathValue("client")
	if _, err := s.app.Store.GetClient(client); err != nil {
		s.notFoundOrError(w, err)
		return
	}
	if err := s.app.Store.DeleteEnrollTokens(client); err != nil {
		s.serverError(w, err)
		return
	}
	s.mintEnrollToken(w, r, client)
}

// handleClientRm is controller-only: deletes the client and everything it owns
// (interfaces, peers, tokens). An enrolled agent fails auth on its next
// poll and its dead-man switch rolls WireGuard back — no agent-side action
// needed.
func (s *Server) handleClientRm(w http.ResponseWriter, r *http.Request) {
	client := r.PathValue("client")
	if _, err := s.app.Store.GetClient(client); err != nil {
		s.notFoundOrError(w, err)
		return
	}
	if err := s.app.Store.DeleteClient(client); err != nil {
		s.serverError(w, err)
		return
	}
	if s.reports != nil {
		s.reports.Delete(client)
	}
	http.Redirect(w, r, s.url(), http.StatusSeeOther)
}

// mintEnrollToken creates a one-time token for client and redirects to the
// page that shows the join command exactly once.
func (s *Server) mintEnrollToken(w http.ResponseWriter, r *http.Request, client string) {
	registered, err := s.app.Store.GetClient(client)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	token, err := s.app.Store.CreateEnrollToken(client, enrollTokenTTL)
	if err != nil {
		s.serverError(w, err)
		return
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		s.serverError(w, err)
		return
	}
	force := ""
	if registered.Fingerprint != "" {
		force = " --force-enroll"
	}
	view := enrollView{
		Client:  client,
		Token:   token,
		Command: fmt.Sprintf("sudo wgmgt agent --server %s --token %s --ca-hash sha256:%s%s", s.apiURL, token, s.caHash, force),
		Expires: time.Now().Add(enrollTokenTTL),
	}
	key := hex.EncodeToString(id)
	s.enrollMu.Lock()
	for oldKey, old := range s.enrollPend {
		if time.Now().After(old.Expires) {
			delete(s.enrollPend, oldKey)
		}
	}
	s.enrollPend[key] = view
	s.enrollMu.Unlock()
	http.Redirect(w, r, s.url("enroll", key), http.StatusSeeOther)
}

// handleEnrollShow serves the join command once; a second GET 404s (the
// token is one-time anyway, but the command contains it verbatim).
func (s *Server) handleEnrollShow(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("id")
	s.enrollMu.Lock()
	view, ok := s.enrollPend[key]
	delete(s.enrollPend, key)
	s.enrollMu.Unlock()
	if !ok {
		s.render(w, http.StatusNotFound, "error.html", errorView{Code: 404, Message: "join command already viewed or expired — mint a new token"})
		return
	}
	if time.Now().After(view.Expires) {
		s.render(w, http.StatusNotFound, "error.html", errorView{Code: 404, Message: "join command expired — mint a new token"})
		return
	}
	s.render(w, http.StatusOK, "enroll.html", view)
}

func (s *Server) handleClient(w http.ResponseWriter, r *http.Request) {
	client := r.PathValue("client")
	if _, err := s.app.Store.GetClient(client); err != nil {
		s.notFoundOrError(w, err)
		return
	}
	ifaces, err := s.app.Store.ListInterfaces(client)
	if err != nil {
		s.serverError(w, err)
		return
	}
	type clientIface struct {
		store.Interface
		ReportedUp bool
		PeerCount  int
	}
	list := make([]clientIface, 0, len(ifaces))
	for _, ifc := range ifaces {
		peers, _ := s.app.Store.ListPeers(client, ifc.Name)
		up, _ := s.liveStatus(&ifc)
		list = append(list, clientIface{Interface: ifc, ReportedUp: up, PeerCount: len(peers)})
	}
	// Enrollment state for the token section: enrolled (fingerprint set) or
	// still pending, plus the outstanding token's expiry if one exists.
	enrolled := false
	var tokenExpiry string
	if n, err := s.app.Store.GetClient(client); err == nil {
		enrolled = n.Fingerprint != ""
	}
	if toks, err := s.app.Store.ListEnrollTokens(client); err == nil && len(toks) > 0 {
		tokenExpiry = toks[0].ExpiresAt
	}
	s.render(w, http.StatusOK, "client.html", struct {
		Client      string
		Interfaces  []clientIface
		Enrolled    bool
		TokenExpiry string
	}{client, list, enrolled, tokenExpiry})
}

// handlePeerQuickAdd is controller-only: the client page's quick-add form.
// It resolves the chosen interface from the form and forwards to the
// regular peer-add handler.
func (s *Server) handlePeerQuickAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.badRequest(w, "bad form")
		return
	}
	iface := strings.TrimSpace(r.PostFormValue("iface"))
	if iface == "" {
		s.badRequest(w, "choose an interface")
		return
	}
	r.SetPathValue("name", iface)
	s.handlePeerAdd(w, r)
}

// handleIfaceCreate is controller-only: the wizard form for adding an
// interface to a client.
func (s *Server) handleIfaceCreate(w http.ResponseWriter, r *http.Request) {
	client := r.PathValue("client")
	if _, err := s.app.Store.GetClient(client); err != nil {
		s.notFoundOrError(w, err)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.badRequest(w, "bad form")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		s.badRequest(w, "interface name is required")
		return
	}
	// Interface names become conf file names on agents — strict validation
	// is a path-traversal guard, not cosmetics.
	if !store.ValidIfaceName(name) {
		s.badRequest(w, "invalid interface name (max 15 chars, [a-zA-Z0-9_-])")
		return
	}
	address := strings.TrimSpace(r.PostFormValue("address"))
	if _, err := netip.ParsePrefix(address); err != nil {
		s.badRequest(w, fmt.Sprintf("invalid address %q", address))
		return
	}
	portValue := strings.TrimSpace(r.PostFormValue("port"))
	port := 51820
	if portValue != "" {
		var err error
		port, err = strconv.Atoi(portValue)
		if err != nil || port < 0 || port > 65535 {
			s.badRequest(w, "listen port must be between 0 and 65535")
			return
		}
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		s.serverError(w, err)
		return
	}
	mtu := 0
	if value := strings.TrimSpace(r.PostFormValue("mtu")); value != "" {
		mtu, err = strconv.Atoi(value)
		if err != nil || mtu < 576 || mtu > 65535 {
			s.badRequest(w, "MTU must be between 576 and 65535, or empty for automatic")
			return
		}
	}
	ifc := &store.Interface{
		Client: client, Name: name, PrivateKey: key.String(),
		Address: address, ListenPort: port, MTU: mtu, Enabled: true,
	}
	if err := s.app.Store.CreateInterface(ifc); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, s.ifaceURL(*ifc), http.StatusSeeOther)
}

func (s *Server) handleIface(w http.ResponseWriter, r *http.Request) {
	v, err := s.viewOf(r.PathValue("client"), r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		s.render(w, http.StatusNotFound, "error.html", errorView{Code: 404, Message: "no such interface"})
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, http.StatusOK, "iface.html", v)
}

// handlePeersTable returns just the peer rows, polled by htmx every 5s.
func (s *Server) handlePeersTable(w http.ResponseWriter, r *http.Request) {
	v, err := s.viewOf(r.PathValue("client"), r.PathValue("name"))
	if err != nil {
		s.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.partial.ExecuteTemplate(w, "peers", v); err != nil {
		log.Printf("peers partial: %v", err)
	}
}

func (s *Server) handleUp(w http.ResponseWriter, r *http.Request) {
	s.handleUpDown(w, r, true)
}

func (s *Server) handleDown(w http.ResponseWriter, r *http.Request) {
	s.handleUpDown(w, r, false)
}

func (s *Server) handleUpDown(w http.ResponseWriter, r *http.Request, up bool) {
	client, name := r.PathValue("client"), r.PathValue("name")
	ifc, err := s.app.Store.GetInterface(client, name)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	if s.controller {
		// Remote clients: toggle desired state; the agent converges on poll.
		if err := s.app.Store.SetEnabled(ifc.Client, ifc.Name, up); err != nil {
			s.serverError(w, err)
			return
		}
		http.Redirect(w, r, s.ifaceURL(*ifc), http.StatusSeeOther)
		return
	}
	peers, err := s.app.Store.ListPeers("", name)
	if err != nil {
		s.serverError(w, err)
		return
	}
	if up {
		err = wgctl.Up(ifc, peers)
	} else {
		err = wgctl.Down(ifc)
	}
	if err != nil {
		s.serverError(w, fmt.Errorf("%s: %w", map[bool]string{true: "up", false: "down"}[up], err))
		return
	}
	http.Redirect(w, r, s.ifaceURL(*ifc), http.StatusSeeOther)
}

func (s *Server) handlePeerAdd(w http.ResponseWriter, r *http.Request) {
	client, name := r.PathValue("client"), r.PathValue("name")
	ifc, err := s.app.Store.GetInterface(client, name)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.badRequest(w, "bad form")
		return
	}
	peerName := strings.TrimSpace(r.PostFormValue("name"))
	if !store.ValidPeerName(peerName) {
		s.badRequest(w, "invalid peer name (max 64 chars, starts with [a-zA-Z0-9], then [a-zA-Z0-9_.-])")
		return
	}

	allowed := strings.TrimSpace(r.PostFormValue("allowed_ips"))
	if allowed == "" {
		if allowed, err = s.app.NextFreeIP(ifc); err != nil {
			s.badRequest(w, err.Error())
			return
		}
	}
	for _, cidr := range strings.Split(allowed, ",") {
		if _, err := netip.ParsePrefix(strings.TrimSpace(cidr)); err != nil {
			s.badRequest(w, fmt.Sprintf("invalid allowed IP %q", cidr))
			return
		}
	}

	// Optional import of a peer that manages its own keys.
	importedPub := strings.TrimSpace(r.PostFormValue("public_key"))
	var clientKey wgtypes.Key
	if importedPub != "" {
		if _, err := wgtypes.ParseKey(importedPub); err != nil {
			s.badRequest(w, "invalid public key")
			return
		}
	} else if clientKey, err = wgtypes.GeneratePrivateKey(); err != nil {
		s.serverError(w, err)
		return
	}
	endpoint := strings.TrimSpace(r.PostFormValue("endpoint"))
	if err := validateEndpoint(endpoint); err != nil {
		s.badRequest(w, "invalid peer endpoint: "+err.Error())
		return
	}
	serverEndpoint := strings.TrimSpace(r.PostFormValue("server_endpoint"))
	if err := validateEndpoint(serverEndpoint); err != nil {
		s.badRequest(w, "invalid server endpoint: "+err.Error())
		return
	}
	p := &store.Peer{
		Client:     ifc.Client,
		Interface:  ifc.Name,
		Name:       peerName,
		AllowedIPs: allowed,
		Endpoint:   endpoint,
	}
	if importedPub != "" {
		p.PublicKey = importedPub
	} else {
		p.PublicKey = clientKey.PublicKey().String()
		p.ClientPrivateKey = clientKey.String()
	}
	if value := strings.TrimSpace(r.PostFormValue("keepalive")); value != "" {
		ka, err := strconv.Atoi(value)
		if err != nil || ka < 0 || ka > 65535 {
			s.badRequest(w, "keepalive must be between 0 and 65535 seconds")
			return
		}
		p.Keepalive = ka
	}
	if r.PostFormValue("preshared_key") != "" {
		psk, err := wgtypes.GenerateKey()
		if err != nil {
			s.serverError(w, err)
			return
		}
		p.PresharedKey = psk.String()
	}
	if serverEndpoint != "" && serverEndpoint != ifc.ServerEndpoint {
		if err := s.app.Store.UpdateServerEndpoint(ifc.Client, ifc.Name, serverEndpoint); err != nil {
			s.serverError(w, err)
			return
		}
	}
	if err := s.app.Store.AddPeer(p); err != nil {
		s.serverError(w, err)
		return
	}
	if !s.controller {
		if err := s.app.SyncConf(name); err != nil {
			s.serverError(w, err)
			return
		}
	}
	http.Redirect(w, r, s.ifaceURL(*ifc), http.StatusSeeOther)
}

func (s *Server) handlePeerRm(w http.ResponseWriter, r *http.Request) {
	client, name, ref := r.PathValue("client"), r.PathValue("name"), r.PathValue("ref")
	if _, err := s.app.Store.DeletePeer(client, name, ref); err != nil {
		s.notFoundOrError(w, err)
		return
	}
	if !s.controller {
		if err := s.app.SyncConf(name); err != nil {
			s.serverError(w, err)
			return
		}
	}
	ifc, err := s.app.Store.GetInterface(client, name)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	http.Redirect(w, r, s.ifaceURL(*ifc), http.StatusSeeOther)
}

func (s *Server) handlePeerConf(w http.ResponseWriter, r *http.Request) {
	client, name, ref := r.PathValue("client"), r.PathValue("name"), r.PathValue("ref")
	ifc, err := s.app.Store.GetInterface(client, name)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	p, err := s.app.Store.GetPeer(client, name, ref)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	if p.ClientPrivateKey == "" {
		s.badRequest(w, "peer was imported with its own keys; its client conf is not stored")
		return
	}
	serverEndpoint := ifc.ServerEndpoint
	if serverEndpoint == "" {
		serverEndpoint = fmt.Sprintf("<server-public-ip>:%d", ifc.ListenPort)
	}
	conf, err := confgen.Client(ifc, p, serverEndpoint)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, http.StatusOK, "peerconf.html", struct {
		Iface    store.Interface
		PeerName string
		Conf     string
	}{*ifc, p.Name, conf})
}

func validateEndpoint(value string) error {
	if value == "" {
		return nil
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil || strings.TrimSpace(host) == "" {
		return fmt.Errorf("must be host:port (IPv6 addresses need brackets)")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		s.serverError(w, err)
		return
	}
	http.StripPrefix("/static/", http.FileServer(http.FS(sub))).ServeHTTP(w, r)
}

// --- rendering helpers ---

type errorView struct {
	Code    int
	Message string
}

func (s *Server) render(w http.ResponseWriter, status int, page string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.pages[page].ExecuteTemplate(w, "base", data); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}

func (s *Server) serverError(w http.ResponseWriter, err error) {
	log.Printf("web: %v", err)
	s.render(w, http.StatusInternalServerError, "error.html", errorView{Code: 500, Message: err.Error()})
}

func (s *Server) notFoundOrError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		s.render(w, http.StatusNotFound, "error.html", errorView{Code: 404, Message: "not found"})
		return
	}
	s.serverError(w, err)
}

func (s *Server) badRequest(w http.ResponseWriter, msg string) {
	s.render(w, http.StatusBadRequest, "error.html", errorView{Code: 400, Message: msg})
}
