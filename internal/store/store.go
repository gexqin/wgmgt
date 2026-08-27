// Package store persists WGMGT state in SQLite.
//
// SQLite is the single source of truth; wg-quick-compatible conf files are
// generated artifacts derived from it (see internal/confgen). The controller
// (wgmgt server) additionally records which node owns each interface.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"regexp"

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
  name           TEXT NOT NULL,
  node           TEXT NOT NULL DEFAULT '',
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
  enabled        INTEGER NOT NULL DEFAULT 1,
  config_version INTEGER NOT NULL DEFAULT 1,
  created_at     TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (node, name)
);
CREATE TABLE IF NOT EXISTS peers (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  interface         TEXT NOT NULL,
  node              TEXT NOT NULL DEFAULT '',
  name              TEXT NOT NULL,
  public_key        TEXT NOT NULL UNIQUE,
  client_private_key TEXT NOT NULL DEFAULT '',
  preshared_key     TEXT NOT NULL DEFAULT '',
  allowed_ips       TEXT NOT NULL,
  endpoint          TEXT NOT NULL DEFAULT '',
  keepalive         INTEGER NOT NULL DEFAULT 0,
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (node, interface) REFERENCES interfaces(node, name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_peers_interface ON peers(node, interface);
CREATE TABLE IF NOT EXISTS nodes (
  name        TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen   TEXT NOT NULL DEFAULT ''
);
`
	if _, err := db.Exec(ddl); err != nil {
		return err
	}
	// Upgrade older single-host databases: (node, name) became the key.
	// Recreate is only possible if empty; otherwise report the mismatch.
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM interfaces").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		var hasNode sql.NullString
		if err := db.QueryRow("SELECT node FROM interfaces LIMIT 1").Scan(&hasNode); err != nil {
			return fmt.Errorf("legacy database detected (interfaces table without node column); delete the db or migrate manually: %w", err)
		}
	}
	return nil
}

// Node is a managed machine known to the controller.
type Node struct {
	Name        string
	Fingerprint string
	LastSeen    string
}

// Interface is a managed WireGuard interface.
type Interface struct {
	Node           string `json:"node"`
	Name           string `json:"name"`
	PrivateKey     string `json:"private_key"`
	ListenPort     int    `json:"listen_port"`
	Address        string `json:"address"`
	MTU            int    `json:"mtu"`
	DNS            string `json:"dns"`
	RouteTable     string `json:"route_table"`
	Fwmark         string `json:"fwmark"`
	ServerEndpoint string `json:"server_endpoint"`
	PostUp         string `json:"post_up"`
	PostDown       string `json:"post_down"`
	Enabled        bool   `json:"enabled"`
	ConfigVersion  int64  `json:"config_version"`
}

// Peer is a managed peer of an interface. ClientPrivateKey is kept so
// client confs can be re-printed later; the tradeoff is documented in
// USAGE.md (DB is 0600 and already holds the server private key).
type Peer struct {
	ID               int64  `json:"id"`
	Node             string `json:"node"`
	Interface        string `json:"interface"`
	Name             string `json:"name"`
	PublicKey        string `json:"public_key"`
	ClientPrivateKey string `json:"client_private_key,omitempty"`
	PresharedKey     string `json:"preshared_key,omitempty"`
	AllowedIPs       string `json:"allowed_ips"`
	Endpoint         string `json:"endpoint"`
	Keepalive        int    `json:"keepalive"`
}

const ifaceCols = `node, name, private_key, listen_port, address, mtu, dns, route_table, fwmark, server_endpoint, post_up, post_down, enabled, config_version`
const peerCols = `id, node, interface, name, public_key, client_private_key, preshared_key, allowed_ips, endpoint, keepalive`

// CreateInterface inserts a new interface.
func (s *Store) CreateInterface(i *Interface) error {
	if i.ConfigVersion == 0 {
		i.ConfigVersion = 1
	}
	_, err := s.db.Exec(`INSERT INTO interfaces
		(`+ifaceCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		i.Node, i.Name, i.PrivateKey, i.ListenPort, i.Address, i.MTU, i.DNS, i.RouteTable, i.Fwmark, i.ServerEndpoint, i.PostUp, i.PostDown, i.Enabled, i.ConfigVersion)
	return err
}

func scanIface(row interface{ Scan(...any) error }) (*Interface, error) {
	var i Interface
	err := row.Scan(&i.Node, &i.Name, &i.PrivateKey, &i.ListenPort, &i.Address, &i.MTU, &i.DNS, &i.RouteTable, &i.Fwmark, &i.ServerEndpoint, &i.PostUp, &i.PostDown, &i.Enabled, &i.ConfigVersion)
	return &i, err
}

// GetInterface returns the interface with the given name. In a multi-node
// database pass the node; with a single-host database node is "".
func (s *Store) GetInterface(node, name string) (*Interface, error) {
	i, err := scanIface(s.db.QueryRow(`SELECT `+ifaceCols+` FROM interfaces WHERE node = ? AND name = ?`, node, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: interface %q", ErrNotFound, name)
	}
	return i, err
}

// ListInterfaces returns all interfaces (optionally of one node).
func (s *Store) ListInterfaces(node string) ([]Interface, error) {
	rows, err := s.db.Query(`SELECT `+ifaceCols+` FROM interfaces`+
		whereNode(node)+" ORDER BY node, name", nodeArgs(node)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Interface
	for rows.Next() {
		i, err := scanIface(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *i)
	}
	return out, rows.Err()
}

// DeleteInterface removes an interface (and its peers, via cascade).
func (s *Store) DeleteInterface(node, name string) error {
	res, err := s.db.Exec("DELETE FROM interfaces WHERE node = ? AND name = ?", node, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: interface %q", ErrNotFound, name)
	}
	return nil
}

// SetEnabled toggles an interface and bumps its config version so agents
// pick the change up on their next poll.
func (s *Store) SetEnabled(node, name string, enabled bool) error {
	return s.bumpIf("UPDATE interfaces SET enabled = ?, config_version = config_version + 1 WHERE node = ? AND name = ?", enabled, node, name)
}

// UpdateServerEndpoint sets the public endpoint advertised in client confs.
func (s *Store) UpdateServerEndpoint(node, name, endpoint string) error {
	_, err := s.db.Exec("UPDATE interfaces SET server_endpoint = ?, config_version = config_version + 1 WHERE node = ? AND name = ?", endpoint, node, name)
	return err
}

// AddPeer inserts a peer for the given interface.
func (s *Store) AddPeer(p *Peer) error {
	res, err := s.db.Exec(`INSERT INTO peers
		(node, interface, name, public_key, client_private_key, preshared_key, allowed_ips, endpoint, keepalive)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		p.Node, p.Interface, p.Name, p.PublicKey, p.ClientPrivateKey, p.PresharedKey, p.AllowedIPs, p.Endpoint, p.Keepalive)
	if err != nil {
		return err
	}
	p.ID, _ = res.LastInsertId()
	return s.bump(p.Node, p.Interface)
}

// ListPeers returns the peers of an interface (of all interfaces if name is empty).
func (s *Store) ListPeers(node, iface string) ([]Peer, error) {
	q := `SELECT ` + peerCols + ` FROM peers WHERE 1=1`
	var args []any
	if node != "*" {
		q += ` AND node = ?`
		args = append(args, node)
	}
	if iface != "" {
		q += ` AND interface = ?`
		args = append(args, iface)
	}
	rows, err := s.db.Query(q+" ORDER BY id", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Peer
	for rows.Next() {
		var p Peer
		if err := rows.Scan(&p.ID, &p.Node, &p.Interface, &p.Name, &p.PublicKey, &p.ClientPrivateKey, &p.PresharedKey, &p.AllowedIPs, &p.Endpoint, &p.Keepalive); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPeer returns a peer of iface by name, public key, or numeric ID.
func (s *Store) GetPeer(node, iface, ref string) (*Peer, error) {
	peers, err := s.ListPeers(node, iface)
	if err != nil {
		return nil, err
	}
	for _, p := range peers {
		if p.Name == ref || p.PublicKey == ref || fmt.Sprint(p.ID) == ref {
			p := p
			return &p, nil
		}
	}
	return nil, fmt.Errorf("%w: peer %q", ErrNotFound, ref)
}

// DeletePeer removes a peer of iface by name, public key, or numeric ID.
func (s *Store) DeletePeer(node, iface, ref string) (*Peer, error) {
	p, err := s.GetPeer(node, iface, ref)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec("DELETE FROM peers WHERE id = ?", p.ID); err != nil {
		return nil, err
	}
	return p, s.bump(node, iface)
}

// ConfigVersion returns the max config version of a node's interfaces
// (0 when the node has none) — the number agents poll with.
func (s *Store) ConfigVersion(node string) (int64, error) {
	var v sql.NullInt64
	err := s.db.QueryRow("SELECT MAX(config_version) FROM interfaces WHERE node = ?", node).Scan(&v)
	return v.Int64, err
}

// --- node registry ---

// EnsureNode registers a node (or refreshes its certificate fingerprint).
func (s *Store) EnsureNode(name, fingerprint string) error {
	_, err := s.db.Exec(`INSERT INTO nodes (name, fingerprint) VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET fingerprint = excluded.fingerprint`, name, fingerprint)
	return err
}

// TouchNode records the last time a node polled.
func (s *Store) TouchNode(name, when string) error {
	_, err := s.db.Exec("UPDATE nodes SET last_seen = ? WHERE name = ?", when, name)
	return err
}

// ListNodes returns all registered nodes.
func (s *Store) ListNodes() ([]Node, error) {
	rows, err := s.db.Query("SELECT name, fingerprint, last_seen FROM nodes ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.Name, &n.Fingerprint, &n.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// GetNode returns a registered node by name.
func (s *Store) GetNode(name string) (*Node, error) {
	var n Node
	err := s.db.QueryRow("SELECT name, fingerprint, last_seen FROM nodes WHERE name = ?", name).
		Scan(&n.Name, &n.Fingerprint, &n.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: node %q", ErrNotFound, name)
	}
	return &n, err
}

// ValidIfaceName reports whether name is a safe Linux interface name.
// It doubles as a path-safety guard: interface names become conf file
// names on agents, so this must stay strict.
var ifaceNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

func ValidIfaceName(name string) bool { return ifaceNameRe.MatchString(name) }

// --- internals ---

func whereNode(node string) string {
	if node == "" {
		return ""
	}
	return " WHERE node = ?"
}

func nodeArgs(node string) []any {
	if node == "" {
		return nil
	}
	return []any{node}
}

// bump increments the config version of an interface after any change,
// so agents detect updates and conf regeneration can be ordered.
func (s *Store) bump(node, iface string) error {
	return s.bumpIf("UPDATE interfaces SET config_version = config_version + 1 WHERE node = ? AND name = ?", node, iface)
}

func (s *Store) bumpIf(q string, args ...any) error {
	res, err := s.db.Exec(q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
