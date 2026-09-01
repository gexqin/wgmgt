// Package store persists WGMGT state in SQLite.
//
// SQLite is the single source of truth; wg-quick-compatible conf files are
// generated artifacts derived from it (see internal/confgen). The controller
// (wgmgt server) additionally records which node owns each interface.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, keeps cross-compilation CGO-free
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB

	// OnChange, when set, is invoked with the node after any mutation that
	// can change a node's config version. The controller wires it to wake
	// hanging long-polls; it is nil in CLI/local mode.
	OnChange func(node string)
}

// changed fires the OnChange hook (a no-op when unset).
func (s *Store) changed(node string) {
	if s.OnChange != nil {
		s.OnChange(node)
	}
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
CREATE TABLE IF NOT EXISTS enroll_tokens (
  token_hash TEXT PRIMARY KEY,   -- hex sha256 of the plaintext token
  node       TEXT NOT NULL,
  created_at TEXT NOT NULL,      -- all three time columns are written from Go
  expires_at TEXT NOT NULL,      -- as RFC3339 UTC; datetime('now') defaults
  used_at    TEXT NOT NULL DEFAULT '' -- elsewhere do not sort with them
);
CREATE INDEX IF NOT EXISTS idx_enroll_tokens_node ON enroll_tokens(node);
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
	if err != nil {
		return err
	}
	s.changed(i.Node)
	return nil
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
	// Deleting the top-version interface lowers the node's MAX version —
	// still a config change agents must see.
	s.changed(node)
	return nil
}

// SetEnabled toggles an interface and bumps its config version so agents
// pick the change up on their next poll.
func (s *Store) SetEnabled(node, name string, enabled bool) error {
	if err := s.bumpIf("UPDATE interfaces SET enabled = ?, config_version = config_version + 1 WHERE node = ? AND name = ?", enabled, node, name); err != nil {
		return err
	}
	s.changed(node)
	return nil
}

// UpdateServerEndpoint sets the public endpoint advertised in client confs.
func (s *Store) UpdateServerEndpoint(node, name, endpoint string) error {
	_, err := s.db.Exec("UPDATE interfaces SET server_endpoint = ?, config_version = config_version + 1 WHERE node = ? AND name = ?", endpoint, node, name)
	if err != nil {
		return err
	}
	s.changed(node)
	return nil
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
	if err := s.bump(p.Node, p.Interface); err != nil {
		return err
	}
	s.changed(p.Node)
	return nil
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
	if err := s.bump(node, iface); err != nil {
		return nil, err
	}
	s.changed(node)
	return p, nil
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

// DeleteNode removes a node and everything it owns: interfaces (peers go
// with them via cascade), enrollment tokens, and the registry row. An
// enrolled agent discovers this on its next poll (auth fails, node unknown)
// and rolls itself back via its verify-timeout dead-man switch.
func (s *Store) DeleteNode(name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		"DELETE FROM interfaces WHERE node = ?", // peers cascade
		"DELETE FROM enroll_tokens WHERE node = ?",
		"DELETE FROM nodes WHERE name = ?",
	} {
		if _, err := tx.Exec(q, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ValidIfaceName reports whether name is a safe Linux interface name.
// It doubles as a path-safety guard: interface names become conf file
// names on agents, so this must stay strict.
var ifaceNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

func ValidIfaceName(name string) bool { return ifaceNameRe.MatchString(name) }

// ValidNodeName reports whether name is a safe node name: it ends up in
// URLs and certificate CNs, so it must stay conservative.
var nodeNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func ValidNodeName(name string) bool { return nodeNameRe.MatchString(name) }

// EnsureNodePending registers a node row without touching an existing
// fingerprint (unlike EnsureNode, which overwrites it) — used when minting
// an enrollment token so the dashboard can show the pending node.
func (s *Store) EnsureNodePending(name string) error {
	_, err := s.db.Exec("INSERT INTO nodes (name, fingerprint) VALUES (?, '') ON CONFLICT(name) DO NOTHING", name)
	return err
}

// --- enrollment tokens ---

// EnrollToken is a one-time bootstrap token record. Only the hash is
// stored; the plaintext exists solely at creation time.
type EnrollToken struct {
	Node      string
	CreatedAt string
	ExpiresAt string
	Used      bool
}

// CreateEnrollToken mints a one-time token for node, valid for ttl, and
// piggybacks deletion of long-expired rows. Returns the plaintext token.
func (s *Store) CreateEnrollToken(node string, ttl time.Duration) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO enroll_tokens (token_hash, node, created_at, expires_at) VALUES (?,?,?,?)`,
		fmt.Sprintf("%x", sum), node, now.Format(time.RFC3339), now.Add(ttl).Format(time.RFC3339))
	if err != nil {
		return "", err
	}
	// Lazy cleanup of tokens that expired unused more than a day ago.
	s.db.Exec("DELETE FROM enroll_tokens WHERE expires_at < ?", now.Add(-24*time.Hour).Format(time.RFC3339))
	return token, nil
}

// RedeemEnrollToken atomically burns a token and returns its node.
// ErrNotFound covers unknown, expired, and already-used — deliberately
// indistinguishable to callers.
func (s *Store) RedeemEnrollToken(token string) (string, error) {
	sum := sha256.Sum256([]byte(token))
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec("UPDATE enroll_tokens SET used_at = ? WHERE token_hash = ? AND used_at = '' AND expires_at > ?",
		now, fmt.Sprintf("%x", sum), now)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", fmt.Errorf("%w: enroll token", ErrNotFound)
	}
	var node string
	if err := s.db.QueryRow("SELECT node FROM enroll_tokens WHERE token_hash = ?", fmt.Sprintf("%x", sum)).Scan(&node); err != nil {
		return "", err
	}
	return node, nil
}

// ListEnrollTokens returns outstanding (unused, unexpired) tokens,
// optionally limited to one node ("" = all nodes).
func (s *Store) ListEnrollTokens(node string) ([]EnrollToken, error) {
	q := "SELECT node, created_at, expires_at FROM enroll_tokens WHERE used_at = '' AND expires_at > ?"
	args := []any{time.Now().UTC().Format(time.RFC3339)}
	if node != "" {
		q += " AND node = ?"
		args = append(args, node)
	}
	q += " ORDER BY created_at"
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollToken
	for rows.Next() {
		var t EnrollToken
		if err := rows.Scan(&t.Node, &t.CreatedAt, &t.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteEnrollTokens revokes all outstanding tokens of a node.
func (s *Store) DeleteEnrollTokens(node string) error {
	_, err := s.db.Exec("DELETE FROM enroll_tokens WHERE node = ? AND used_at = ''", node)
	return err
}

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
