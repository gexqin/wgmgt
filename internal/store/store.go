// Package store persists WGMGT state in SQLite.
//
// SQLite is the single source of truth; wg-quick-compatible conf files are
// generated artifacts derived from it (see internal/confgen). The controller
// (wgmgt server) additionally records which client owns each interface.
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

// ErrLegacySchema is returned by Open for databases created before the
// node→client rename. They are not migrated; `wgmgt init` offers a full
// reset (wipe the db, regenerate everything).
var ErrLegacySchema = errors.New("legacy database (created before the node→client rename)")

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB

	// OnChange, when set, is invoked with the client after any mutation that
	// can change a client's config version. The controller wires it to wake
	// hanging long-polls; it is nil in CLI/local mode.
	OnChange func(client string)
}

// changed fires the OnChange hook (a no-op when unset).
func (s *Store) changed(client string) {
	if s.OnChange != nil {
		s.OnChange(client)
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
		_ = db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		if errors.Is(err, ErrLegacySchema) {
			return nil, fmt.Errorf("%w at %s: re-run `wgmgt init` and confirm the reset, or remove the file", err, path)
		}
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("secure database permissions: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func migrate(db *sql.DB) error {
	// Detect pre-rename databases BEFORE the DDL: CREATE INDEX on an old
	// peers table would fail with a confusing "no such column: client",
	// and every query afterwards would too. init offers a full reset.
	if legacy, err := isLegacySchema(db); err != nil {
		return err
	} else if legacy {
		return ErrLegacySchema
	}
	const ddl = `
CREATE TABLE IF NOT EXISTS interfaces (
  name           TEXT NOT NULL,
  client         TEXT NOT NULL DEFAULT '',
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
  PRIMARY KEY (client, name)
);
CREATE TABLE IF NOT EXISTS peers (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  interface         TEXT NOT NULL,
  client            TEXT NOT NULL DEFAULT '',
  name              TEXT NOT NULL,
  public_key        TEXT NOT NULL UNIQUE,
  client_private_key TEXT NOT NULL DEFAULT '',
  preshared_key     TEXT NOT NULL DEFAULT '',
  allowed_ips       TEXT NOT NULL,
  endpoint          TEXT NOT NULL DEFAULT '',
  keepalive         INTEGER NOT NULL DEFAULT 0,
  created_at        TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (client, interface) REFERENCES interfaces(client, name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_peers_interface ON peers(client, interface);
CREATE TABLE IF NOT EXISTS clients (
  name        TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS enroll_tokens (
  token_hash TEXT PRIMARY KEY,   -- hex sha256 of the plaintext token
  client     TEXT NOT NULL,
  created_at TEXT NOT NULL,      -- all three time columns are written from Go
  expires_at TEXT NOT NULL,      -- as RFC3339 UTC; datetime('now') defaults
  used_at    TEXT NOT NULL DEFAULT '' -- elsewhere do not sort with them
);
CREATE INDEX IF NOT EXISTS idx_enroll_tokens_client ON enroll_tokens(client);
CREATE TABLE IF NOT EXISTS config_revisions (
  client  TEXT PRIMARY KEY,
  version INTEGER NOT NULL DEFAULT 0
);
INSERT INTO config_revisions (client, version)
  SELECT client, MAX(config_version) FROM interfaces GROUP BY client
  ON CONFLICT(client) DO NOTHING;
CREATE TRIGGER IF NOT EXISTS interfaces_revision_insert
AFTER INSERT ON interfaces BEGIN
  INSERT INTO config_revisions (client, version) VALUES (NEW.client, 1)
    ON CONFLICT(client) DO UPDATE SET version = version + 1;
END;
CREATE TRIGGER IF NOT EXISTS interfaces_revision_update
AFTER UPDATE ON interfaces BEGIN
  INSERT INTO config_revisions (client, version) VALUES (NEW.client, 1)
    ON CONFLICT(client) DO UPDATE SET version = version + 1;
END;
CREATE TRIGGER IF NOT EXISTS interfaces_revision_delete
AFTER DELETE ON interfaces BEGIN
  INSERT INTO config_revisions (client, version) VALUES (OLD.client, 1)
    ON CONFLICT(client) DO UPDATE SET version = version + 1;
END;
`
	_, err := db.Exec(ddl)
	return err
}

// isLegacySchema reports whether db predates the node→client rename: an
// old "nodes" registry table, or an interfaces table still keyed by the
// "node" column.
func isLegacySchema(db *sql.DB) (bool, error) {
	for _, table := range []string{"nodes", "interfaces"} {
		var n int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table,
		).Scan(&n); err != nil {
			return false, err
		}
		if n == 0 {
			continue
		}
		if table == "nodes" {
			return true, nil // the registry is only called "nodes" pre-rename
		}
		var col int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM pragma_table_info('interfaces') WHERE name='client'`,
		).Scan(&col); err != nil {
			return false, err
		}
		if col == 0 {
			return true, nil
		}
	}
	return false, nil
}

// Client is a managed machine known to the controller.
type Client struct {
	Name        string
	Fingerprint string
	LastSeen    string
}

// Interface is a managed WireGuard interface.
type Interface struct {
	Client         string `json:"client"`
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
	Client           string `json:"client"`
	Interface        string `json:"interface"`
	Name             string `json:"name"`
	PublicKey        string `json:"public_key"`
	ClientPrivateKey string `json:"client_private_key,omitempty"`
	PresharedKey     string `json:"preshared_key,omitempty"`
	AllowedIPs       string `json:"allowed_ips"`
	Endpoint         string `json:"endpoint"`
	Keepalive        int    `json:"keepalive"`
}

const ifaceCols = `client, name, private_key, listen_port, address, mtu, dns, route_table, fwmark, server_endpoint, post_up, post_down, enabled, config_version`
const peerCols = `id, client, interface, name, public_key, client_private_key, preshared_key, allowed_ips, endpoint, keepalive`

// CreateInterface inserts a new interface.
func (s *Store) CreateInterface(i *Interface) error {
	if i.ConfigVersion == 0 {
		i.ConfigVersion = 1
	}
	_, err := s.db.Exec(`INSERT INTO interfaces
		(`+ifaceCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		i.Client, i.Name, i.PrivateKey, i.ListenPort, i.Address, i.MTU, i.DNS, i.RouteTable, i.Fwmark, i.ServerEndpoint, i.PostUp, i.PostDown, i.Enabled, i.ConfigVersion)
	if err != nil {
		return err
	}
	s.changed(i.Client)
	return nil
}

func scanIface(row interface{ Scan(...any) error }) (*Interface, error) {
	var i Interface
	err := row.Scan(&i.Client, &i.Name, &i.PrivateKey, &i.ListenPort, &i.Address, &i.MTU, &i.DNS, &i.RouteTable, &i.Fwmark, &i.ServerEndpoint, &i.PostUp, &i.PostDown, &i.Enabled, &i.ConfigVersion)
	return &i, err
}

// GetInterface returns the interface with the given name. In a multi-client
// database pass the client; with a single-host database client is "".
func (s *Store) GetInterface(client, name string) (*Interface, error) {
	i, err := scanIface(s.db.QueryRow(`SELECT `+ifaceCols+` FROM interfaces WHERE client = ? AND name = ?`, client, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: interface %q", ErrNotFound, name)
	}
	return i, err
}

// ListInterfaces returns all interfaces (optionally of one client).
func (s *Store) ListInterfaces(client string) ([]Interface, error) {
	rows, err := s.db.Query(`SELECT `+ifaceCols+` FROM interfaces`+
		whereClient(client)+" ORDER BY client, name", clientArgs(client)...)
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
func (s *Store) DeleteInterface(client, name string) error {
	res, err := s.db.Exec("DELETE FROM interfaces WHERE client = ? AND name = ?", client, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: interface %q", ErrNotFound, name)
	}
	// The deletion trigger advances the client-wide desired-state revision.
	s.changed(client)
	return nil
}

// SetEnabled toggles an interface and bumps its config version so agents
// pick the change up on their next poll.
func (s *Store) SetEnabled(client, name string, enabled bool) error {
	if err := s.bumpIf("UPDATE interfaces SET enabled = ?, config_version = config_version + 1 WHERE client = ? AND name = ?", enabled, client, name); err != nil {
		return err
	}
	s.changed(client)
	return nil
}

// UpdateServerEndpoint sets the public endpoint advertised in client confs.
func (s *Store) UpdateServerEndpoint(client, name, endpoint string) error {
	res, err := s.db.Exec("UPDATE interfaces SET server_endpoint = ?, config_version = config_version + 1 WHERE client = ? AND name = ?", endpoint, client, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: interface %q", ErrNotFound, name)
	}
	s.changed(client)
	return nil
}

// AddPeer inserts a peer for the given interface.
func (s *Store) AddPeer(p *Peer) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRow("SELECT COUNT(*) FROM peers WHERE client = ? AND interface = ? AND name = ?", p.Client, p.Interface, p.Name).Scan(&exists); err != nil {
		return err
	}
	if exists != 0 {
		return fmt.Errorf("peer name %q already exists on interface %q", p.Name, p.Interface)
	}
	res, err := tx.Exec(`INSERT INTO peers
		(client, interface, name, public_key, client_private_key, preshared_key, allowed_ips, endpoint, keepalive)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		p.Client, p.Interface, p.Name, p.PublicKey, p.ClientPrivateKey, p.PresharedKey, p.AllowedIPs, p.Endpoint, p.Keepalive)
	if err != nil {
		return err
	}
	p.ID, _ = res.LastInsertId()
	res, err = tx.Exec("UPDATE interfaces SET config_version = config_version + 1 WHERE client = ? AND name = ?", p.Client, p.Interface)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: interface %q", ErrNotFound, p.Interface)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.changed(p.Client)
	return nil
}

// ListPeers returns the peers of an interface (of all interfaces if name is empty).
func (s *Store) ListPeers(client, iface string) ([]Peer, error) {
	q := `SELECT ` + peerCols + ` FROM peers WHERE 1=1`
	var args []any
	if client != "*" {
		q += ` AND client = ?`
		args = append(args, client)
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
		if err := rows.Scan(&p.ID, &p.Client, &p.Interface, &p.Name, &p.PublicKey, &p.ClientPrivateKey, &p.PresharedKey, &p.AllowedIPs, &p.Endpoint, &p.Keepalive); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPeer returns a peer of iface by name, public key, or numeric ID.
func (s *Store) GetPeer(client, iface, ref string) (*Peer, error) {
	peers, err := s.ListPeers(client, iface)
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
func (s *Store) DeletePeer(client, iface, ref string) (*Peer, error) {
	p, err := s.GetPeer(client, iface, ref)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM peers WHERE id = ?", p.ID); err != nil {
		return nil, err
	}
	res, err := tx.Exec("UPDATE interfaces SET config_version = config_version + 1 WHERE client = ? AND name = ?", client, iface)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, fmt.Errorf("%w: interface %q", ErrNotFound, iface)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.changed(client)
	return p, nil
}

// ConfigVersion returns the client's monotonic desired-state revision. It is
// separate from per-interface config_version so changes to any interface,
// including deletion of the last one, always produce a distinct value.
func (s *Store) ConfigVersion(client string) (int64, error) {
	var v int64
	err := s.db.QueryRow("SELECT version FROM config_revisions WHERE client = ?", client).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

// --- client registry ---

// EnsureClient registers a client (or refreshes its certificate fingerprint).
func (s *Store) EnsureClient(name, fingerprint string) error {
	_, err := s.db.Exec(`INSERT INTO clients (name, fingerprint) VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET fingerprint = excluded.fingerprint`, name, fingerprint)
	return err
}

// TouchClient records the last time a client polled.
func (s *Store) TouchClient(name, when string) error {
	_, err := s.db.Exec("UPDATE clients SET last_seen = ? WHERE name = ?", when, name)
	return err
}

// ListClients returns all registered clients.
func (s *Store) ListClients() ([]Client, error) {
	rows, err := s.db.Query("SELECT name, fingerprint, last_seen FROM clients ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		var n Client
		if err := rows.Scan(&n.Name, &n.Fingerprint, &n.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// GetClient returns a registered client by name.
func (s *Store) GetClient(name string) (*Client, error) {
	var n Client
	err := s.db.QueryRow("SELECT name, fingerprint, last_seen FROM clients WHERE name = ?", name).
		Scan(&n.Name, &n.Fingerprint, &n.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: client %q", ErrNotFound, name)
	}
	return &n, err
}

// DeleteClient removes a client and everything it owns: interfaces (peers go
// with them via cascade), enrollment tokens, and the registry row. An
// enrolled agent discovers this on its next poll and immediately removes its
// managed devices and generated configurations.
func (s *Store) DeleteClient(name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		"DELETE FROM interfaces WHERE client = ?", // peers cascade
		"DELETE FROM enroll_tokens WHERE client = ?",
		"DELETE FROM clients WHERE name = ?",
		"DELETE FROM config_revisions WHERE client = ?",
	} {
		if _, err := tx.Exec(q, name); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.changed(name)
	return nil
}

// ValidIfaceName reports whether name is a safe Linux interface name.
// It doubles as a path-safety guard: interface names become conf file
// names on agents, so this must stay strict.
var ifaceNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

func ValidIfaceName(name string) bool { return ifaceNameRe.MatchString(name) }

// ValidClientName reports whether name is a safe client name: it ends up in
// URLs and certificate CNs, so it must stay conservative.
var clientNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func ValidClientName(name string) bool { return clientNameRe.MatchString(name) }

// ValidPeerName reports whether a peer label is safe as a URL path element
// and unambiguous within an interface.
func ValidPeerName(name string) bool { return clientNameRe.MatchString(name) }

// EnsureClientPending registers a client row without touching an existing
// fingerprint (unlike EnsureClient, which overwrites it) — used when minting
// an enrollment token so the dashboard can show the pending client.
func (s *Store) EnsureClientPending(name string) error {
	_, err := s.db.Exec("INSERT INTO clients (name, fingerprint) VALUES (?, '') ON CONFLICT(name) DO NOTHING", name)
	return err
}

// --- enrollment tokens ---

// EnrollToken is a one-time bootstrap token record. Only the hash is
// stored; the plaintext exists solely at creation time.
type EnrollToken struct {
	Client    string
	CreatedAt string
	ExpiresAt string
	Used      bool
}

// CreateEnrollToken mints a one-time token for client, valid for ttl, and
// piggybacks deletion of long-expired rows. Returns the plaintext token.
func (s *Store) CreateEnrollToken(client string, ttl time.Duration) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO enroll_tokens (token_hash, client, created_at, expires_at) VALUES (?,?,?,?)`,
		fmt.Sprintf("%x", sum), client, now.Format(time.RFC3339), now.Add(ttl).Format(time.RFC3339))
	if err != nil {
		return "", err
	}
	// Lazy cleanup of tokens that expired unused more than a day ago.
	_, _ = s.db.Exec("DELETE FROM enroll_tokens WHERE expires_at < ?", now.Add(-24*time.Hour).Format(time.RFC3339))
	return token, nil
}

// RedeemEnrollToken atomically burns a token and returns its client.
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
	var client string
	if err := s.db.QueryRow("SELECT client FROM enroll_tokens WHERE token_hash = ?", fmt.Sprintf("%x", sum)).Scan(&client); err != nil {
		return "", err
	}
	return client, nil
}

// ListEnrollTokens returns outstanding (unused, unexpired) tokens,
// optionally limited to one client ("" = all clients).
func (s *Store) ListEnrollTokens(client string) ([]EnrollToken, error) {
	q := "SELECT client, created_at, expires_at FROM enroll_tokens WHERE used_at = '' AND expires_at > ?"
	args := []any{time.Now().UTC().Format(time.RFC3339)}
	if client != "" {
		q += " AND client = ?"
		args = append(args, client)
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
		if err := rows.Scan(&t.Client, &t.CreatedAt, &t.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteEnrollTokens revokes all outstanding tokens of a client.
func (s *Store) DeleteEnrollTokens(client string) error {
	_, err := s.db.Exec("DELETE FROM enroll_tokens WHERE client = ? AND used_at = ''", client)
	return err
}

// --- internals ---

func whereClient(client string) string {
	if client == "" {
		return ""
	}
	return " WHERE client = ?"
}

func clientArgs(client string) []any {
	if client == "" {
		return nil
	}
	return []any{client}
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
