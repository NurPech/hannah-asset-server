package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ── Namespaces ────────────────────────────────────────────────────────────────

var namespaceNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func isValidNamespaceName(name string) bool {
	return namespaceNameRe.MatchString(name)
}

type Namespace struct {
	Name        string
	Parent      string // "" if root
	Description string
	CreatedAt   time.Time
}

// IsValidNamespace reports whether ns is a known, DB-registered namespace.
func (s *Store) IsValidNamespace(ns string) bool {
	var exists int
	err := s.db.QueryRow(`SELECT 1 FROM namespaces WHERE name=?`, ns).Scan(&exists)
	return err == nil
}

func (s *Store) ListNamespaceNames() ([]string, error) {
	rows, err := s.db.Query(`SELECT name FROM namespaces ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) ListNamespaces() ([]*Namespace, error) {
	rows, err := s.db.Query(`SELECT name,COALESCE(parent,''),description,created_at FROM namespaces ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Namespace
	for rows.Next() {
		n, err := scanNamespace(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) GetNamespace(name string) (*Namespace, error) {
	return scanNamespace(s.db.QueryRow(
		`SELECT name,COALESCE(parent,''),description,created_at FROM namespaces WHERE name=?`, name,
	))
}

func scanNamespace(row dbScanner) (*Namespace, error) {
	var n Namespace
	var createdAt string
	err := row.Scan(&n.Name, &n.Parent, &n.Description, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &n, nil
}

func (s *Store) CreateNamespace(n *Namespace) error {
	if !isValidNamespaceName(n.Name) {
		return fmt.Errorf("invalid namespace name %q", n.Name)
	}
	if n.Parent != "" && !s.IsValidNamespace(n.Parent) {
		return fmt.Errorf("unknown parent namespace %q", n.Parent)
	}
	_, err := s.db.Exec(
		`INSERT INTO namespaces(name,parent,description,created_at) VALUES(?,?,?,?)`,
		n.Name, nullStr(n.Parent), n.Description, now(),
	)
	return err
}

// UpdateNamespace changes description and/or parent. Reparenting is rejected if it would
// create a cycle (i.e. the new parent is name itself or one of its own descendants).
func (s *Store) UpdateNamespace(name, description, parent string) error {
	if parent != "" {
		if !s.IsValidNamespace(parent) {
			return fmt.Errorf("unknown parent namespace %q", parent)
		}
		chain, err := s.NamespaceChain(parent)
		if err != nil {
			return err
		}
		for _, ns := range chain {
			if ns == name {
				return fmt.Errorf("reparenting %q to %q would create a cycle", name, parent)
			}
		}
	}
	_, err := s.db.Exec(`UPDATE namespaces SET description=?,parent=? WHERE name=?`, description, nullStr(parent), name)
	return err
}

// DeleteNamespace fails if the namespace still has children or overrides (enforced by the
// namespaces.parent / asset_overrides.namespace foreign keys), or is still tagged on an asset.
func (s *Store) DeleteNamespace(name string) error {
	var inUse int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM assets WHERE namespace = ?`, name,
	).Scan(&inUse); err != nil {
		return err
	}
	if inUse > 0 {
		return fmt.Errorf("namespace %q is still used by %d asset(s)", name, inUse)
	}
	_, err := s.db.Exec(`DELETE FROM namespaces WHERE name=?`, name)
	return err
}

// NamespaceChain returns name followed by its ancestors up to the root.
func (s *Store) NamespaceChain(name string) ([]string, error) {
	chain := []string{name}
	seen := map[string]bool{name: true}
	current := name
	for i := 0; i < 32; i++ {
		ns, err := s.GetNamespace(current)
		if err != nil {
			return nil, err
		}
		if ns == nil || ns.Parent == "" || seen[ns.Parent] {
			break
		}
		chain = append(chain, ns.Parent)
		seen[ns.Parent] = true
		current = ns.Parent
	}
	return chain, nil
}

// ── Data types ────────────────────────────────────────────────────────────────

type User struct {
	ID           string
	Username     string
	PasswordHash string
	OIDCSub      string
	IsAdmin      bool
	IsActive     bool
	CreatedAt    time.Time
}

type Group struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
}

type Role struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
}

type Permission struct {
	Namespace string `json:"namespace"`
	Action    string `json:"action"`
}

type ServiceAccount struct {
	ID        string
	Name      string
	CreatedBy string
	IsActive  bool
	CreatedAt time.Time
}

type ServiceAccountToken struct {
	ID               string
	ServiceAccountID string
	Name             string
	TokenHash        string
	CreatedAt        time.Time
	ExpiresAt        *time.Time
	LastUsedAt       *time.Time
}

type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type OAuth2Config struct {
	IssuerURL    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Enabled      bool   `json:"enabled"`
}

// Asset lives in exactly one namespace. Child namespaces inherit it via chain
// resolution (see Store.ResolveAssetsForChain); a namespace "overrides" a key
// inherited from an ancestor simply by having its own row for that key.
type Asset struct {
	Namespace   string     `json:"namespace"`
	Key         string     `json:"key"`
	Filename    string     `json:"filename"`
	MimeType    string     `json:"mime_type"`
	SHA256      string     `json:"sha256"`
	Size        int64      `json:"size"`
	StoragePath string     `json:"-"`
	UploadedAt  time.Time  `json:"uploaded_at"`
	Meta        *AssetMeta `json:"meta,omitempty"`
}

// ── Store ─────────────────────────────────────────────────────────────────────

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// ── Helpers ───────────────────────────────────────────────────────────────────

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func generateToken() (plain, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	plain = hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(plain))
	hash = hex.EncodeToString(sum[:])
	return
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func (s *Store) expandWildcards(perms []Permission) []Permission {
	seen := map[string]bool{}
	var out []Permission
	for _, p := range perms {
		if p.Namespace == "*" {
			names, err := s.ListNamespaceNames()
			if err != nil {
				continue
			}
			for _, ns := range names {
				key := ns + ":" + p.Action
				if !seen[key] {
					out = append(out, Permission{Namespace: ns, Action: p.Action})
					seen[key] = true
				}
			}
		} else {
			key := p.Namespace + ":" + p.Action
			if !seen[key] {
				out = append(out, p)
				seen[key] = true
			}
		}
	}
	return out
}

func hasPermission(perms []Permission, ns, action string) bool {
	for _, p := range perms {
		if p.Action == action && (p.Namespace == ns || p.Namespace == "*") {
			return true
		}
	}
	return false
}

// ── Users ─────────────────────────────────────────────────────────────────────

func (s *Store) CreateUser(u *User) error {
	_, err := s.db.Exec(
		`INSERT INTO users(id,username,password_hash,oidc_sub,is_admin,is_active,created_at)
		 VALUES(?,?,?,?,?,?,?)`,
		u.ID, u.Username, nullStr(u.PasswordHash), nullStr(u.OIDCSub),
		boolInt(u.IsAdmin), boolInt(u.IsActive), now(),
	)
	return err
}

func (s *Store) UserCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) GetUserByID(id string) (*User, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT id,username,password_hash,oidc_sub,is_admin,is_active,created_at FROM users WHERE id=?`, id,
	))
}

func (s *Store) GetUserByUsername(username string) (*User, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT id,username,password_hash,oidc_sub,is_admin,is_active,created_at FROM users WHERE username=?`, username,
	))
}

func (s *Store) GetUserByOIDCSub(sub string) (*User, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT id,username,password_hash,oidc_sub,is_admin,is_active,created_at FROM users WHERE oidc_sub=?`, sub,
	))
}

func (s *Store) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(
		`SELECT id,username,password_hash,oidc_sub,is_admin,is_active,created_at FROM users ORDER BY created_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*User
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) UpdateUser(u *User) error {
	_, err := s.db.Exec(
		`UPDATE users SET username=?,password_hash=?,oidc_sub=?,is_admin=?,is_active=? WHERE id=?`,
		u.Username, nullStr(u.PasswordHash), nullStr(u.OIDCSub),
		boolInt(u.IsAdmin), boolInt(u.IsActive), u.ID,
	)
	return err
}

func (s *Store) DeleteUser(id string) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

type dbScanner interface {
	Scan(dest ...any) error
}

func (s *Store) scanUser(row dbScanner) (*User, error) {
	var u User
	var ph, sub sql.NullString
	var admin, active int
	var createdAt string
	err := row.Scan(&u.ID, &u.Username, &ph, &sub, &admin, &active, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.PasswordHash = ph.String
	u.OIDCSub = sub.String
	u.IsAdmin = admin == 1
	u.IsActive = active == 1
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &u, nil
}

// ── Groups ────────────────────────────────────────────────────────────────────

func (s *Store) CreateGroup(g *Group) error {
	_, err := s.db.Exec(
		`INSERT INTO groups(id,name,description,created_at) VALUES(?,?,?,?)`,
		g.ID, g.Name, g.Description, now(),
	)
	return err
}

func (s *Store) GetGroupByID(id string) (*Group, error) {
	var g Group
	var createdAt string
	err := s.db.QueryRow(
		`SELECT id,name,description,created_at FROM groups WHERE id=?`, id,
	).Scan(&g.ID, &g.Name, &g.Description, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	g.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &g, nil
}

func (s *Store) ListGroups() ([]*Group, error) {
	rows, err := s.db.Query(`SELECT id,name,description,created_at FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Group
	for rows.Next() {
		var g Group
		var createdAt string
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &createdAt); err != nil {
			return nil, err
		}
		g.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, &g)
	}
	return out, rows.Err()
}

func (s *Store) UpdateGroup(g *Group) error {
	_, err := s.db.Exec(`UPDATE groups SET name=?,description=? WHERE id=?`, g.Name, g.Description, g.ID)
	return err
}

func (s *Store) DeleteGroup(id string) error {
	_, err := s.db.Exec(`DELETE FROM groups WHERE id=?`, id)
	return err
}

func (s *Store) AddUserToGroup(userID, groupID string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO user_groups(user_id,group_id) VALUES(?,?)`, userID, groupID)
	return err
}

func (s *Store) RemoveUserFromGroup(userID, groupID string) error {
	_, err := s.db.Exec(`DELETE FROM user_groups WHERE user_id=? AND group_id=?`, userID, groupID)
	return err
}

func (s *Store) ListGroupMembers(groupID string) ([]*User, error) {
	rows, err := s.db.Query(
		`SELECT u.id,u.username,u.password_hash,u.oidc_sub,u.is_admin,u.is_active,u.created_at
		 FROM users u JOIN user_groups ug ON u.id=ug.user_id WHERE ug.group_id=? ORDER BY u.username`,
		groupID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) ListGroupRoles(groupID string) ([]*Role, error) {
	rows, err := s.db.Query(
		`SELECT r.id,r.name,r.description,r.created_at FROM roles r
		 JOIN group_roles gr ON r.id=gr.role_id WHERE gr.group_id=? ORDER BY r.name`,
		groupID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Role
	for rows.Next() {
		var r Role
		var createdAt string
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &createdAt); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (s *Store) ListUserGroups(userID string) ([]*Group, error) {
	rows, err := s.db.Query(
		`SELECT g.id,g.name,g.description,g.created_at FROM groups g
		 JOIN user_groups ug ON g.id=ug.group_id WHERE ug.user_id=? ORDER BY g.name`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Group
	for rows.Next() {
		var g Group
		var createdAt string
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &createdAt); err != nil {
			return nil, err
		}
		g.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, &g)
	}
	return out, rows.Err()
}

// SyncUserGroupsByName replaces the user's group memberships with groups matching the given names.
// Groups not found in the DB are silently skipped. Used for OAuth groups-claim sync.
func (s *Store) SyncUserGroupsByName(userID string, groupNames []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM user_groups WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, name := range groupNames {
		var id string
		if err := tx.QueryRow(`SELECT id FROM groups WHERE name=?`, name).Scan(&id); err != nil {
			continue // group not found — skip
		}
		tx.Exec(`INSERT OR IGNORE INTO user_groups(user_id,group_id) VALUES(?,?)`, userID, id)
	}
	return tx.Commit()
}

// ── Roles ─────────────────────────────────────────────────────────────────────

func (s *Store) CreateRole(r *Role) error {
	_, err := s.db.Exec(
		`INSERT INTO roles(id,name,description,created_at) VALUES(?,?,?,?)`,
		r.ID, r.Name, r.Description, now(),
	)
	return err
}

func (s *Store) GetRoleByID(id string) (*Role, error) {
	var r Role
	var createdAt string
	err := s.db.QueryRow(
		`SELECT id,name,description,created_at FROM roles WHERE id=?`, id,
	).Scan(&r.ID, &r.Name, &r.Description, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &r, nil
}

func (s *Store) ListRoles() ([]*Role, error) {
	rows, err := s.db.Query(`SELECT id,name,description,created_at FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Role
	for rows.Next() {
		var r Role
		var createdAt string
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &createdAt); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (s *Store) UpdateRole(r *Role) error {
	_, err := s.db.Exec(`UPDATE roles SET name=?,description=? WHERE id=?`, r.Name, r.Description, r.ID)
	return err
}

func (s *Store) DeleteRole(id string) error {
	_, err := s.db.Exec(`DELETE FROM roles WHERE id=?`, id)
	return err
}

func (s *Store) SetRolePermissions(roleID string, perms []Permission) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM role_permissions WHERE role_id=?`, roleID); err != nil {
		return err
	}
	for _, p := range perms {
		if _, err := tx.Exec(
			`INSERT INTO role_permissions(role_id,namespace,action) VALUES(?,?,?)`,
			roleID, p.Namespace, p.Action,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetRolePermissions(roleID string) ([]Permission, error) {
	rows, err := s.db.Query(`SELECT namespace,action FROM role_permissions WHERE role_id=?`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPermissions(rows)
}

func (s *Store) AssignRoleToUser(roleID, userID string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO user_roles(user_id,role_id) VALUES(?,?)`, userID, roleID)
	return err
}

func (s *Store) AssignRoleToGroup(roleID, groupID string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO group_roles(group_id,role_id) VALUES(?,?)`, groupID, roleID)
	return err
}

func (s *Store) RemoveRoleFromUser(roleID, userID string) error {
	_, err := s.db.Exec(`DELETE FROM user_roles WHERE user_id=? AND role_id=?`, userID, roleID)
	return err
}

func (s *Store) RemoveRoleFromGroup(roleID, groupID string) error {
	_, err := s.db.Exec(`DELETE FROM group_roles WHERE group_id=? AND role_id=?`, groupID, roleID)
	return err
}

func (s *Store) ResolveUserPermissions(userID string) ([]Permission, error) {
	const q = `
		SELECT DISTINCT rp.namespace, rp.action
		FROM role_permissions rp
		WHERE rp.role_id IN (
			SELECT role_id FROM user_roles WHERE user_id = ?
			UNION
			SELECT gr.role_id FROM group_roles gr
			JOIN user_groups ug ON gr.group_id = ug.group_id
			WHERE ug.user_id = ?
		)`
	rows, err := s.db.Query(q, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	perms, err := scanPermissions(rows)
	if err != nil {
		return nil, err
	}
	return s.expandWildcards(perms), nil
}

// ── Service Accounts ──────────────────────────────────────────────────────────

func (s *Store) CreateServiceAccount(sa *ServiceAccount) error {
	_, err := s.db.Exec(
		`INSERT INTO service_accounts(id,name,created_by,is_active,created_at) VALUES(?,?,?,?,?)`,
		sa.ID, sa.Name, nullStr(sa.CreatedBy), boolInt(sa.IsActive), now(),
	)
	return err
}

func (s *Store) GetServiceAccountByID(id string) (*ServiceAccount, error) {
	return s.scanServiceAccount(s.db.QueryRow(
		`SELECT id,name,COALESCE(created_by,''),is_active,created_at FROM service_accounts WHERE id=?`, id,
	))
}

func (s *Store) ListServiceAccounts() ([]*ServiceAccount, error) {
	rows, err := s.db.Query(
		`SELECT id,name,COALESCE(created_by,''),is_active,created_at FROM service_accounts ORDER BY name`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanServiceAccounts(rows)
}

func (s *Store) ListServiceAccountsByUser(userID string) ([]*ServiceAccount, error) {
	rows, err := s.db.Query(
		`SELECT id,name,COALESCE(created_by,''),is_active,created_at FROM service_accounts WHERE created_by=? ORDER BY name`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanServiceAccounts(rows)
}

func (s *Store) DeleteServiceAccount(id string) error {
	_, err := s.db.Exec(`DELETE FROM service_accounts WHERE id=?`, id)
	return err
}

func (s *Store) SetServiceAccountPermissions(saID string, perms []Permission) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM service_account_permissions WHERE service_account_id=?`, saID); err != nil {
		return err
	}
	for _, p := range perms {
		if _, err := tx.Exec(
			`INSERT INTO service_account_permissions(service_account_id,namespace,action) VALUES(?,?,?)`,
			saID, p.Namespace, p.Action,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetServiceAccountPermissions(saID string) ([]Permission, error) {
	rows, err := s.db.Query(
		`SELECT namespace,action FROM service_account_permissions WHERE service_account_id=?`, saID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	perms, err := scanPermissions(rows)
	if err != nil {
		return nil, err
	}
	return s.expandWildcards(perms), nil
}

func (s *Store) GetServiceAccountByTokenHash(hash string) (*ServiceAccount, error) {
	row := s.db.QueryRow(
		`SELECT sa.id,sa.name,COALESCE(sa.created_by,''),sa.is_active,sa.created_at
		 FROM service_accounts sa
		 JOIN service_account_tokens t ON t.service_account_id = sa.id
		 WHERE t.token_hash=? AND sa.is_active=1`,
		hash,
	)
	return s.scanServiceAccount(row)
}

func (s *Store) scanServiceAccount(row dbScanner) (*ServiceAccount, error) {
	var sa ServiceAccount
	var active int
	var createdAt string
	err := row.Scan(&sa.ID, &sa.Name, &sa.CreatedBy, &active, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sa.IsActive = active == 1
	sa.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	return &sa, nil
}

func (s *Store) scanServiceAccounts(rows *sql.Rows) ([]*ServiceAccount, error) {
	var out []*ServiceAccount
	for rows.Next() {
		sa, err := s.scanServiceAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sa)
	}
	return out, rows.Err()
}

// ── Service Account Tokens ────────────────────────────────────────────────────

func (s *Store) CreateServiceAccountToken(t *ServiceAccountToken) error {
	_, err := s.db.Exec(
		`INSERT INTO service_account_tokens(id,service_account_id,name,token_hash,created_at) VALUES(?,?,?,?,?)`,
		t.ID, t.ServiceAccountID, t.Name, t.TokenHash, now(),
	)
	return err
}

func (s *Store) ListTokensForServiceAccount(saID string) ([]*ServiceAccountToken, error) {
	rows, err := s.db.Query(
		`SELECT id,service_account_id,name,token_hash,created_at,expires_at,last_used_at
		 FROM service_account_tokens WHERE service_account_id=? ORDER BY created_at`,
		saID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ServiceAccountToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteToken(id string) error {
	_, err := s.db.Exec(`DELETE FROM service_account_tokens WHERE id=?`, id)
	return err
}

func (s *Store) TouchTokenLastUsed(tokenHash string) {
	s.db.Exec(
		`UPDATE service_account_tokens SET last_used_at=? WHERE token_hash=?`,
		now(), tokenHash,
	)
}

func scanToken(row dbScanner) (*ServiceAccountToken, error) {
	var t ServiceAccountToken
	var createdAt string
	var expiresAt, lastUsedAt sql.NullString
	err := row.Scan(&t.ID, &t.ServiceAccountID, &t.Name, &t.TokenHash, &createdAt, &expiresAt, &lastUsedAt)
	if err != nil {
		return nil, err
	}
	t.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if expiresAt.Valid {
		ts, _ := time.Parse(time.RFC3339, expiresAt.String)
		t.ExpiresAt = &ts
	}
	if lastUsedAt.Valid {
		ts, _ := time.Parse(time.RFC3339, lastUsedAt.String)
		t.LastUsedAt = &ts
	}
	return &t, nil
}

// ── Sessions ──────────────────────────────────────────────────────────────────

func (s *Store) CreateSession(sess *Session) error {
	_, err := s.db.Exec(
		`INSERT INTO sessions(id,user_id,created_at,expires_at) VALUES(?,?,?,?)`,
		sess.ID, sess.UserID, now(),
		sess.ExpiresAt.UTC().Format(time.RFC3339),
	)
	return err
}

func (s *Store) GetSessionByID(id string) (*Session, error) {
	var sess Session
	var createdAt, expiresAt string
	err := s.db.QueryRow(
		`SELECT id,user_id,created_at,expires_at FROM sessions WHERE id=?`, id,
	).Scan(&sess.ID, &sess.UserID, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sess.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	sess.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	return &sess, nil
}

func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id=?`, id)
	return err
}

func (s *Store) DeleteExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < datetime('now')`)
	return err
}

// ── OAuth2 Config ─────────────────────────────────────────────────────────────

func (s *Store) GetOAuth2Config() (*OAuth2Config, error) {
	var cfg OAuth2Config
	var enabled int
	err := s.db.QueryRow(
		`SELECT issuer_url,client_id,client_secret,enabled FROM oauth2_config WHERE id=1`,
	).Scan(&cfg.IssuerURL, &cfg.ClientID, &cfg.ClientSecret, &enabled)
	if err != nil {
		return nil, err
	}
	cfg.Enabled = enabled == 1
	return &cfg, nil
}

func (s *Store) SetOAuth2Config(cfg *OAuth2Config) error {
	_, err := s.db.Exec(
		`UPDATE oauth2_config SET issuer_url=?,client_id=?,client_secret=?,enabled=? WHERE id=1`,
		cfg.IssuerURL, cfg.ClientID, cfg.ClientSecret, boolInt(cfg.Enabled),
	)
	return err
}

// ── Assets ────────────────────────────────────────────────────────────────────

func (s *Store) GetAsset(namespace, key string) (*Asset, error) {
	return s.scanAsset(s.db.QueryRow(
		`SELECT namespace,key,filename,mime_type,sha256,size,storage_path,uploaded_at,meta
		 FROM assets WHERE namespace=? AND key=?`, namespace, key,
	))
}

func (s *Store) ListAssets() ([]*Asset, error) {
	rows, err := s.db.Query(
		`SELECT namespace,key,filename,mime_type,sha256,size,storage_path,uploaded_at,meta
		 FROM assets ORDER BY namespace, key`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanAssets(rows)
}

// ListAssetsByNamespace returns the assets stored directly in namespace (not
// resolved through inheritance — that's ResolveAssetsForChain).
func (s *Store) ListAssetsByNamespace(namespace string) ([]*Asset, error) {
	rows, err := s.db.Query(
		`SELECT namespace,key,filename,mime_type,sha256,size,storage_path,uploaded_at,meta
		 FROM assets WHERE namespace=? ORDER BY key`,
		namespace,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanAssets(rows)
}

// ResolveAssetsForChain resolves the visible assets for a namespace chain
// (the namespace itself plus its ancestors, most specific first, as returned
// by NamespaceChain): for each key, the entry from the most specific level
// wins, letting a namespace "override" what it inherited from an ancestor.
func (s *Store) ResolveAssetsForChain(chain []string) ([]*Asset, error) {
	if len(chain) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(chain)), ",")
	args := make([]any, len(chain))
	for i, ns := range chain {
		args[i] = ns
	}
	rows, err := s.db.Query(fmt.Sprintf(`
		SELECT namespace,key,filename,mime_type,sha256,size,storage_path,uploaded_at,meta
		FROM assets WHERE namespace IN (%s)
	`, placeholders), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	all, err := s.scanAssets(rows)
	if err != nil {
		return nil, err
	}

	rank := make(map[string]int, len(chain))
	for i, ns := range chain {
		rank[ns] = i
	}
	byKey := make(map[string]*Asset, len(all))
	for _, a := range all {
		if existing, ok := byKey[a.Key]; !ok || rank[a.Namespace] < rank[existing.Namespace] {
			byKey[a.Key] = a
		}
	}
	out := make([]*Asset, 0, len(byKey))
	for _, a := range byKey {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (s *Store) UpsertAsset(a *Asset) error {
	var metaVal sql.NullString
	if a.Meta != nil {
		b, err := json.Marshal(a.Meta)
		if err != nil {
			return err
		}
		metaVal = sql.NullString{String: string(b), Valid: true}
	}
	_, err := s.db.Exec(`
		INSERT INTO assets (namespace,key,filename,mime_type,sha256,size,storage_path,uploaded_at,meta)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(namespace,key) DO UPDATE SET
			filename     = excluded.filename,
			mime_type    = excluded.mime_type,
			sha256       = excluded.sha256,
			size         = excluded.size,
			storage_path = excluded.storage_path,
			uploaded_at  = excluded.uploaded_at,
			meta         = excluded.meta
	`, a.Namespace, a.Key, a.Filename, a.MimeType, a.SHA256, a.Size, a.StoragePath, a.UploadedAt.UTC().Format(time.RFC3339), metaVal)
	return err
}

func (s *Store) DeleteAsset(namespace, key string) error {
	_, err := s.db.Exec(`DELETE FROM assets WHERE namespace=? AND key=?`, namespace, key)
	return err
}

func (s *Store) scanAsset(row dbScanner) (*Asset, error) {
	var a Asset
	var uploadedAt string
	var metaJSON sql.NullString
	err := row.Scan(&a.Namespace, &a.Key, &a.Filename, &a.MimeType, &a.SHA256, &a.Size, &a.StoragePath, &uploadedAt, &metaJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.UploadedAt, _ = time.Parse(time.RFC3339, uploadedAt)
	if metaJSON.Valid {
		var meta AssetMeta
		if json.Unmarshal([]byte(metaJSON.String), &meta) == nil {
			a.Meta = &meta
		}
	}
	return &a, nil
}

func (s *Store) scanAssets(rows *sql.Rows) ([]*Asset, error) {
	var out []*Asset
	for rows.Next() {
		a, err := s.scanAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

func scanPermissions(rows *sql.Rows) ([]Permission, error) {
	var out []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.Namespace, &p.Action); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
