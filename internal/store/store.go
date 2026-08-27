// Package store persists WGMGT state in SQLite.
//
// SQLite is the single source of truth; wg-quick-compatible conf files are
// generated artifacts derived from it (see internal/confgen).
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"

	_ "modernc.org/sqlite" // pure-Go driver, keeps cross-compilation CGO-free
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the database at path and runs
// migrations. The file is tightened to 0600 because it holds private keys.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// modernc.org/sqlite is not safe for concurrent writers; one connection
	// serializes access and sidesteps SQLITE_BUSY entirely.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	os.Chmod(path, 0o600) // best effort; may be read-only mounts
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func migrate(db *sql.DB) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS interfaces (
  name           TEXT PRIMARY KEY,
  private_key    TEXT NOT NULL,
  listen_port    INTEGER NOT NULL DEFAULT 0,
  address        TEXT NOT NULL,
  mtu            INTEGER NOT NULL DEFAULT 0,
  dns            TEXT NOT NULL DEFAULT '',
  route_table    TEXT NOT NULL DEFAULT '',
  fwmark         TEXT NOT NULL DEFAULT '',
  server_endpoint TEXT NOT NULL DEFAULT '',
  post_up        TEXT NOT NULL DEFAULT '',
  post_down      TEXT NOT NULL DEFAULT '',
  config_version INTEGER NOT NULL DEFAULT 1,
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS peers (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  interface         TEXT NOT NULL REFERENCES interfaces(name) ON DELETE CASCADE,
  name              TEXT NOT NULL,
  public_key        TEXT NOT NULL UNIQUE,
  client_private_key TEXT NOT NULL DEFAULT '',
  preshared_key     TEXT NOT NULL DEFAULT '',
  allowed_ips       TEXT NOT NULL,
  endpoint          TEXT NOT NULL DEFAULT '',
  keepalive         INTEGER NOT NULL DEFAULT 0,
  created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_peers_interface ON peers(interface);
`
	_, err := db.Exec(ddl)
	return err
}

// Interface is a managed WireGuard interface.
type Interface struct {
	Name           string
	PrivateKey     string // base64, server side
	ListenPort     int
	Address        string // CIDR, e.g. 10.0.0.1/24
	MTU            int    // 0 = kernel default
	DNS            string
	RouteTable     string
	Fwmark         string
	ServerEndpoint string // public endpoint advertised in client confs
	PostUp         string
	PostDown       string
	ConfigVersion  int64
}

// Peer is a managed peer of an interface. ClientPrivateKey is kept so
// client confs can be re-printed later; the tradeoff is documented in
// USAGE.md (DB is 0600 and already holds the server private key).
type Peer struct {
	ID              int64
	Interface       string
	Name            string
	PublicKey       string // base64, peer side
	ClientPrivateKey string
	PresharedKey    string
	AllowedIPs      string // comma-separated CIDRs
	Endpoint        string // peer's endpoint as seen from this host
	Keepalive       int    // seconds, 0 = off
}

// CreateInterface inserts a new interface.
func (s *Store) CreateInterface(i *Interface) error {
	_, err := s.db.Exec(`INSERT INTO interfaces
		(name, private_key, listen_port, address, mtu, dns, route_table, fwmark, server_endpoint, post_up, post_down)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		i.Name, i.PrivateKey, i.ListenPort, i.Address, i.MTU, i.DNS, i.RouteTable, i.Fwmark, i.ServerEndpoint, i.PostUp, i.PostDown)
	return err
}

// GetInterface returns the interface with the given name.
func (s *Store) GetInterface(name string) (*Interface, error) {
	row := s.db.QueryRow(`SELECT name, private_key, listen_port, address, mtu, dns, route_table, fwmark, server_endpoint, post_up, post_down, config_version
		FROM interfaces WHERE name = ?`, name)
	var i Interface
	err := row.Scan(&i.Name, &i.PrivateKey, &i.ListenPort, &i.Address, &i.MTU, &i.DNS, &i.RouteTable, &i.Fwmark, &i.ServerEndpoint, &i.PostUp, &i.PostDown, &i.ConfigVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: interface %q", ErrNotFound, name)
	}
	return &i, err
}

// ListInterfaces returns all interfaces.
func (s *Store) ListInterfaces() ([]Interface, error) {
	rows, err := s.db.Query(`SELECT name, private_key, listen_port, address, mtu, dns, route_table, fwmark, server_endpoint, post_up, post_down, config_version
		FROM interfaces ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Interface
	for rows.Next() {
		var i Interface
		if err := rows.Scan(&i.Name, &i.PrivateKey, &i.ListenPort, &i.Address, &i.MTU, &i.DNS, &i.RouteTable, &i.Fwmark, &i.ServerEndpoint, &i.PostUp, &i.PostDown, &i.ConfigVersion); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// DeleteInterface removes an interface (and its peers, via cascade).
func (s *Store) DeleteInterface(name string) error {
	res, err := s.db.Exec("DELETE FROM interfaces WHERE name = ?", name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: interface %q", ErrNotFound, name)
	}
	return nil
}

// UpdateServerEndpoint sets the public endpoint advertised in client confs.
func (s *Store) UpdateServerEndpoint(name, endpoint string) error {
	_, err := s.db.Exec("UPDATE interfaces SET server_endpoint = ?, config_version = config_version + 1 WHERE name = ?", endpoint, name)
	return err
}

// AddPeer inserts a peer for the given interface.
func (s *Store) AddPeer(p *Peer) error {
	res, err := s.db.Exec(`INSERT INTO peers
		(interface, name, public_key, client_private_key, preshared_key, allowed_ips, endpoint, keepalive)
		VALUES (?,?,?,?,?,?,?,?)`,
		p.Interface, p.Name, p.PublicKey, p.ClientPrivateKey, p.PresharedKey, p.AllowedIPs, p.Endpoint, p.Keepalive)
	if err != nil {
		return err
	}
	p.ID, _ = res.LastInsertId()
	return s.bump(p.Interface)
}

// UpdatePeer replaces the mutable fields of a peer.
func (s *Store) UpdatePeer(p *Peer) error {
	_, err := s.db.Exec(`UPDATE peers SET name = ?, allowed_ips = ?, endpoint = ?, keepalive = ? WHERE id = ?`,
		p.Name, p.AllowedIPs, p.Endpoint, p.Keepalive, p.ID)
	if err != nil {
		return err
	}
	return s.bump(p.Interface)
}

// ListPeers returns the peers of an interface (all interfaces if name is empty).
func (s *Store) ListPeers(iface string) ([]Peer, error) {
	q := `SELECT id, interface, name, public_key, client_private_key, preshared_key, allowed_ips, endpoint, keepalive FROM peers`
	var (
		rows *sql.Rows
		err  error
	)
	if iface == "" {
		rows, err = s.db.Query(q + " ORDER BY id")
	} else {
		rows, err = s.db.Query(q+" WHERE interface = ? ORDER BY id", iface)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Peer
	for rows.Next() {
		var p Peer
		if err := rows.Scan(&p.ID, &p.Interface, &p.Name, &p.PublicKey, &p.ClientPrivateKey, &p.PresharedKey, &p.AllowedIPs, &p.Endpoint, &p.Keepalive); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPeer returns a peer of iface by name, public key, or numeric ID.
func (s *Store) GetPeer(iface, ref string) (*Peer, error) {
	peers, err := s.ListPeers(iface)
	if err != nil {
		return nil, err
	}
	for _, p := range peers {
		if p.Name == ref || p.PublicKey == ref || fmt.Sprint(p.ID) == ref {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("%w: peer %q on %q", ErrNotFound, ref, iface)
}

// DeletePeer removes a peer of iface by name, public key, or numeric ID.
func (s *Store) DeletePeer(iface, ref string) (*Peer, error) {
	p, err := s.GetPeer(iface, ref)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec("DELETE FROM peers WHERE id = ?", p.ID); err != nil {
		return nil, err
	}
	return p, s.bump(iface)
}

// bump increments the config version of an interface after any change,
// so agents can detect updates (M3) and conf regeneration can be ordered.
func (s *Store) bump(iface string) error {
	res, err := s.db.Exec("UPDATE interfaces SET config_version = config_version + 1 WHERE name = ?", iface)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: interface %q", ErrNotFound, iface)
	}
	return nil
}
