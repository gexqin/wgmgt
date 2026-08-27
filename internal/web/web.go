// Package web serves the embedded WGMGT web UI: dashboard, interface and
// peer management, live status. Every route lives under /t/<token>/, so
// only whoever sees the startup URL can reach the UI — that covers both
// random scanners and browser-side CSRF/DNS-rebinding against localhost.
//
// Two modes: local (single host, drives netlink directly) and controller
// (wgmgt server; interfaces belong to nodes, live status comes from agent
// reports, up/down toggles the node's desired state).
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
	"net/http"
	"net/netip"
	"path"
	"strconv"
	"strings"
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
	pages      map[string]*template.Template
	partial    *template.Template
	mux        *http.ServeMux
}

// New builds a local-mode Server with a fresh random token.
func New(a *app.App) (*Server, error) { return newServer(a, false, nil) }

// NewController builds a controller-mode Server fed by agent reports.
func NewController(a *app.App, reports *control.Reports) (*Server, error) {
	return newServer(a, true, reports)
}

func newServer(a *app.App, controller bool, reports *control.Reports) (*Server, error) {
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
		return s.url(append([]string{"node", ifc.Node, "iface", ifc.Name}, rest...)...)
	}
	return s.url(append([]string{"iface", ifc.Name}, rest...)...)
}

// Handler wraps the mux with the token check.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func (s *Server) routes() {
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET /static/", s.handleStatic)
	if s.controller {
		s.mux.HandleFunc("GET /{$}", s.handleDashboard)
		s.mux.HandleFunc("GET /node/{node}", s.handleNode)
		s.mux.HandleFunc("POST /node/{node}/ifaces", s.handleIfaceCreate)
		s.mux.HandleFunc("GET /node/{node}/iface/{name}", s.handleIface)
		s.mux.HandleFunc("GET /node/{node}/iface/{name}/peers-table", s.handlePeersTable)
		s.mux.HandleFunc("GET /node/{node}/iface/{name}/peers/{ref}/conf", s.handlePeerConf)
		s.mux.HandleFunc("POST /node/{node}/iface/{name}/up", s.handleUp)
		s.mux.HandleFunc("POST /node/{node}/iface/{name}/down", s.handleDown)
		s.mux.HandleFunc("POST /node/{node}/iface/{name}/peers", s.handlePeerAdd)
		s.mux.HandleFunc("POST /node/{node}/iface/{name}/peers/{ref}/rm", s.handlePeerRm)
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
	pages := []string{"dashboard.html", "iface.html", "peerconf.html", "error.html", "node.html"}
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

type nodeCard struct {
	Name       string
	LastSeen   string // humanized, "" if never
	Online     bool
	Interfaces int
}

// liveStatus resolves the live state of an interface in either mode.
func (s *Server) liveStatus(ifc *store.Interface) (bool, map[string]wgctl.PeerStatus) {
	if s.controller {
		rep := s.reports.Get(ifc.Node)
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
		log.Printf("device status %s: %v", ifc.Name, err)
		return true, nil
	}
	return true, live
}

func (s *Server) viewOf(node, name string) (ifaceView, error) {
	ifc, err := s.app.Store.GetInterface(node, name)
	if err != nil {
		return ifaceView{}, err
	}
	peers, err := s.app.Store.ListPeers(ifc.Node, ifc.Name)
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
		nodes, err := s.app.Store.ListNodes()
		if err != nil {
			s.serverError(w, err)
			return
		}
		ifaces, _ := s.app.Store.ListInterfaces("*")
		counts := map[string]int{}
		for _, ifc := range ifaces {
			counts[ifc.Node]++
		}
		cards := make([]nodeCard, 0, len(nodes))
		for _, n := range nodes {
			c := nodeCard{Name: n.Name, Interfaces: counts[n.Name]}
			if entry := s.reports.Get(n.Name); !entry.When.IsZero() {
				age := time.Since(entry.When)
				c.LastSeen = humanize.Duration(age)
				c.Online = age < 2*time.Minute
			}
			cards = append(cards, c)
		}
		s.render(w, http.StatusOK, "dashboard.html", struct {
			Controller bool
			Nodes      []nodeCard
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

func (s *Server) handleNode(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	ifaces, err := s.app.Store.ListInterfaces(node)
	if err != nil {
		s.serverError(w, err)
		return
	}
	type nodeIface struct {
		store.Interface
		ReportedUp bool
		PeerCount  int
	}
	list := make([]nodeIface, 0, len(ifaces))
	for _, ifc := range ifaces {
		peers, _ := s.app.Store.ListPeers(node, ifc.Name)
		up, _ := s.liveStatus(&ifc)
		list = append(list, nodeIface{Interface: ifc, ReportedUp: up, PeerCount: len(peers)})
	}
	s.render(w, http.StatusOK, "node.html", struct {
		Node       string
		Interfaces []nodeIface
	}{node, list})
}

// handleIfaceCreate is controller-only: the wizard form for adding an
// interface to a node.
func (s *Server) handleIfaceCreate(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	if err := r.ParseForm(); err != nil {
		s.badRequest(w, "bad form")
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		s.badRequest(w, "interface name is required")
		return
	}
	address := strings.TrimSpace(r.PostFormValue("address"))
	if _, err := netip.ParsePrefix(address); err != nil {
		s.badRequest(w, fmt.Sprintf("invalid address %q", address))
		return
	}
	port, _ := strconv.Atoi(r.PostFormValue("port"))
	if port == 0 {
		port = 51820
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		s.serverError(w, err)
		return
	}
	mtu, _ := strconv.Atoi(r.PostFormValue("mtu"))
	ifc := &store.Interface{
		Node: node, Name: name, PrivateKey: key.String(),
		Address: address, ListenPort: port, MTU: mtu, Enabled: true,
	}
	if err := s.app.Store.CreateInterface(ifc); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, s.ifaceURL(*ifc), http.StatusSeeOther)
}

func (s *Server) handleIface(w http.ResponseWriter, r *http.Request) {
	v, err := s.viewOf(r.PathValue("node"), r.PathValue("name"))
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
	v, err := s.viewOf(r.PathValue("node"), r.PathValue("name"))
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
	node, name := r.PathValue("node"), r.PathValue("name")
	ifc, err := s.app.Store.GetInterface(node, name)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	if s.controller {
		// Remote nodes: toggle desired state; the agent converges on poll.
		if err := s.app.Store.SetEnabled(ifc.Node, ifc.Name, up); err != nil {
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
	node, name := r.PathValue("node"), r.PathValue("name")
	ifc, err := s.app.Store.GetInterface(node, name)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.badRequest(w, "bad form")
		return
	}
	peerName := strings.TrimSpace(r.PostFormValue("name"))
	if peerName == "" {
		s.badRequest(w, "peer name is required")
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
	p := &store.Peer{
		Node:       ifc.Node,
		Interface:  ifc.Name,
		Name:       peerName,
		AllowedIPs: allowed,
		Endpoint:   strings.TrimSpace(r.PostFormValue("endpoint")),
	}
	if importedPub != "" {
		p.PublicKey = importedPub
	} else {
		p.PublicKey = clientKey.PublicKey().String()
		p.ClientPrivateKey = clientKey.String()
	}
	if ka, _ := strconv.Atoi(r.PostFormValue("keepalive")); ka > 0 {
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
	if se := strings.TrimSpace(r.PostFormValue("server_endpoint")); se != "" && se != ifc.ServerEndpoint {
		if err := s.app.Store.UpdateServerEndpoint(ifc.Node, ifc.Name, se); err != nil {
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
	node, name, ref := r.PathValue("node"), r.PathValue("name"), r.PathValue("ref")
	if _, err := s.app.Store.DeletePeer(node, name, ref); err != nil {
		s.notFoundOrError(w, err)
		return
	}
	if !s.controller {
		if err := s.app.SyncConf(name); err != nil {
			s.serverError(w, err)
			return
		}
	}
	ifc, err := s.app.Store.GetInterface(node, name)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	http.Redirect(w, r, s.ifaceURL(*ifc), http.StatusSeeOther)
}

func (s *Server) handlePeerConf(w http.ResponseWriter, r *http.Request) {
	node, name, ref := r.PathValue("node"), r.PathValue("name"), r.PathValue("ref")
	ifc, err := s.app.Store.GetInterface(node, name)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	p, err := s.app.Store.GetPeer(node, name, ref)
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
	s.render(w, http.StatusOK, "peerconf.html", struct{ IfaceName, PeerName, Conf string }{name, p.Name, conf})
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
