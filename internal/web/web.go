// Package web serves the embedded WGMGT web UI: dashboard, interface and
// peer management, live status. Every route lives under /t/<token>/, so
// only whoever sees the startup URL can reach the UI — that covers both
// random scanners and browser-side CSRF/DNS-rebinding against localhost.
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

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/gexqin/wgmgt/internal/app"
	"github.com/gexqin/wgmgt/internal/confgen"
	"github.com/gexqin/wgmgt/internal/humanize"
	"github.com/gexqin/wgmgt/internal/store"
	"github.com/gexqin/wgmgt/internal/wgctl"
)

//go:embed templates static
var files embed.FS

// Server is the web UI. Construct with New.
type Server struct {
	app    *app.App
	token  string
	prefix string // "/t/<token>"
	pages  map[string]*template.Template
	partial *template.Template
	mux    *http.ServeMux
}

// New builds a Server with a fresh random token.
func New(a *app.App) (*Server, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	s := &Server{
		app:    a,
		token:  hex.EncodeToString(buf),
		prefix: "/t/" + hex.EncodeToString(buf),
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
	s.mux.HandleFunc("GET /{$}", s.handleDashboard)
	s.mux.HandleFunc("GET /static/", s.handleStatic)
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
		"u":     s.url,
		"orDash": func(v string) string { if v == "" { return "–" }; return v },
	}
	base, err := template.New("base").Funcs(funcs).ParseFS(files, "templates/base.html")
	if err != nil {
		return err
	}
	s.pages = map[string]*template.Template{}
	for _, page := range []string{"dashboard.html", "iface.html", "peerconf.html", "error.html"} {
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

func (s *Server) viewOf(name string) (ifaceView, error) {
	ifc, err := s.app.Store.GetInterface(name)
	if err != nil {
		return ifaceView{}, err
	}
	peers, err := s.app.Store.ListPeers(name)
	if err != nil {
		return ifaceView{}, err
	}
	v := ifaceView{Iface: *ifc, Up: wgctl.Exists(name), Peers: []peerView{}}
	var live map[string]wgctl.PeerStatus
	if v.Up {
		if live, err = wgctl.DeviceStatus(name); err != nil {
			return ifaceView{}, err
		}
	}
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
	ifaces, err := s.app.Store.ListInterfaces()
	if err != nil {
		s.serverError(w, err)
		return
	}
	cards := make([]cardView, 0, len(ifaces))
	for _, ifc := range ifaces {
		peers, _ := s.app.Store.ListPeers(ifc.Name)
		cards = append(cards, cardView{ifc.Name, ifc.Address, ifc.ListenPort, wgctl.Exists(ifc.Name), len(peers)})
	}
	s.render(w, http.StatusOK, "dashboard.html", struct{ Cards []cardView }{cards})
}

func (s *Server) handleIface(w http.ResponseWriter, r *http.Request) {
	v, err := s.viewOf(r.PathValue("name"))
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
	v, err := s.viewOf(r.PathValue("name"))
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
	name := r.PathValue("name")
	ifc, err := s.app.Store.GetInterface(name)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	peers, err := s.app.Store.ListPeers(name)
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
	http.Redirect(w, r, s.url("iface", name), http.StatusSeeOther)
}

func (s *Server) handlePeerAdd(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ifc, err := s.app.Store.GetInterface(name)
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

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		s.serverError(w, err)
		return
	}
	p := &store.Peer{
		Interface:        name,
		Name:             peerName,
		PublicKey:        key.PublicKey().String(),
		ClientPrivateKey: key.String(),
		AllowedIPs:       allowed,
		Endpoint:         strings.TrimSpace(r.PostFormValue("endpoint")),
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
		if err := s.app.Store.UpdateServerEndpoint(name, se); err != nil {
			s.serverError(w, err)
			return
		}
	}
	if err := s.app.Store.AddPeer(p); err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.app.SyncConf(name); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, s.url("iface", name), http.StatusSeeOther)
}

func (s *Server) handlePeerRm(w http.ResponseWriter, r *http.Request) {
	name, ref := r.PathValue("name"), r.PathValue("ref")
	if _, err := s.app.Store.DeletePeer(name, ref); err != nil {
		s.notFoundOrError(w, err)
		return
	}
	if err := s.app.SyncConf(name); err != nil {
		s.serverError(w, err)
		return
	}
	http.Redirect(w, r, s.url("iface", name), http.StatusSeeOther)
}

func (s *Server) handlePeerConf(w http.ResponseWriter, r *http.Request) {
	name, ref := r.PathValue("name"), r.PathValue("ref")
	ifc, err := s.app.Store.GetInterface(name)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	p, err := s.app.Store.GetPeer(name, ref)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	if p.ClientPrivateKey == "" {
		s.badRequest(w, "peer was imported with --public-key; its client conf is not stored")
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
