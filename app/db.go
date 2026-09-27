package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

func openDB(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)",
		path,
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}
	return db, nil
}

func currentSchemaVersion(db *sql.DB) (int, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`)
	if err != nil {
		return 0, err
	}
	var v int
	err = db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	return v, err
}

type migration struct {
	version int
	sql     string                 // set for plain SQL migrations
	fn      func(tx *sql.Tx) error // set for Go-code migrations; runs in the same tx as sql would
}

func applyMigration(db *sql.DB, m migration) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if m.fn != nil {
		if err := m.fn(tx); err != nil {
			return fmt.Errorf("migration %d: %w", m.version, err)
		}
	} else if _, err := tx.Exec(m.sql); err != nil {
		return fmt.Errorf("migration %d: %w", m.version, err)
	}
	if _, err := tx.Exec(
		`INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`,
		m.version, time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return err
	}
	return tx.Commit()
}

func runMigrations(db *sql.DB) error {
	current, err := currentSchemaVersion(db)
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		log.Printf("applying DB migration %d", m.version)
		if err := applyMigration(db, m); err != nil {
			return err
		}
	}
	return nil
}

var migrations = []migration{
	{version: 1, sql: migration1},
	{version: 2, sql: migration2},
	{version: 3, sql: migration3},
	{version: 4, sql: migration4},
	{version: 5, sql: migration5},
	{version: 6, fn: migrateUnifyAssetOwnership},
}

// Auth tables — identical structure to update-server, but with "namespace" instead of "channel"
const migration1 = `
CREATE TABLE users (
	id            TEXT PRIMARY KEY,
	username      TEXT NOT NULL UNIQUE,
	password_hash TEXT,
	oidc_sub      TEXT UNIQUE,
	is_admin      INTEGER NOT NULL DEFAULT 0,
	is_active     INTEGER NOT NULL DEFAULT 1,
	created_at    TEXT NOT NULL
);

CREATE TABLE groups (
	id          TEXT PRIMARY KEY,
	name        TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	created_at  TEXT NOT NULL
);

CREATE TABLE user_groups (
	user_id  TEXT NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
	group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
	PRIMARY KEY (user_id, group_id)
);

CREATE TABLE roles (
	id          TEXT PRIMARY KEY,
	name        TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	created_at  TEXT NOT NULL
);

CREATE TABLE role_permissions (
	role_id   TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
	namespace TEXT NOT NULL,
	action    TEXT NOT NULL,
	PRIMARY KEY (role_id, namespace, action)
);

CREATE TABLE user_roles (
	user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
	PRIMARY KEY (user_id, role_id)
);

CREATE TABLE group_roles (
	group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
	role_id  TEXT NOT NULL REFERENCES roles(id)  ON DELETE CASCADE,
	PRIMARY KEY (group_id, role_id)
);

CREATE TABLE service_accounts (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL UNIQUE,
	created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
	is_active  INTEGER NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL
);

CREATE TABLE service_account_permissions (
	service_account_id TEXT NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
	namespace          TEXT NOT NULL,
	action             TEXT NOT NULL,
	PRIMARY KEY (service_account_id, namespace, action)
);

CREATE TABLE service_account_tokens (
	id                 TEXT PRIMARY KEY,
	service_account_id TEXT NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
	name               TEXT NOT NULL,
	token_hash         TEXT NOT NULL UNIQUE,
	created_at         TEXT NOT NULL,
	expires_at         TEXT,
	last_used_at       TEXT
);

CREATE TABLE sessions (
	id         TEXT PRIMARY KEY,
	user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);

CREATE TABLE oauth2_config (
	id            INTEGER PRIMARY KEY CHECK (id = 1),
	issuer_url    TEXT NOT NULL DEFAULT '',
	client_id     TEXT NOT NULL DEFAULT '',
	client_secret TEXT NOT NULL DEFAULT '',
	redirect_url  TEXT NOT NULL DEFAULT '',
	enabled       INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO oauth2_config(id) VALUES (1);
`

const migration2 = `
CREATE TABLE assets (
	key         TEXT PRIMARY KEY,
	filename    TEXT NOT NULL,
	mime_type   TEXT NOT NULL,
	sha256      TEXT NOT NULL,
	size        INTEGER NOT NULL,
	namespaces  TEXT NOT NULL,
	uploaded_at TEXT NOT NULL
);
`

const migration3 = `ALTER TABLE assets ADD COLUMN meta TEXT`

const migration4 = `
CREATE TABLE namespaces (
	name        TEXT PRIMARY KEY,
	parent      TEXT REFERENCES namespaces(name),
	description TEXT NOT NULL DEFAULT '',
	created_at  TEXT NOT NULL
);

INSERT INTO namespaces(name, parent, description, created_at) VALUES ('core', NULL, '', strftime('%Y-%m-%dT%H:%M:%SZ','now'));
INSERT INTO namespaces(name, parent, description, created_at) VALUES ('satellite', NULL, '', strftime('%Y-%m-%dT%H:%M:%SZ','now'));

CREATE TABLE asset_overrides (
	namespace   TEXT NOT NULL REFERENCES namespaces(name),
	key         TEXT NOT NULL,
	filename    TEXT NOT NULL,
	mime_type   TEXT NOT NULL,
	sha256      TEXT NOT NULL,
	size        INTEGER NOT NULL,
	uploaded_at TEXT NOT NULL,
	meta        TEXT,
	PRIMARY KEY (namespace, key)
);
`

const migration5 = `
INSERT INTO namespaces(name, parent, description, created_at)
  VALUES ('shared', NULL, '', strftime('%Y-%m-%dT%H:%M:%SZ','now'));
UPDATE namespaces SET parent = 'shared' WHERE name IN ('core', 'satellite');
`

// migrateUnifyAssetOwnership merges the old assets (namespaces JSON array) and
// asset_overrides (namespace+key) tables into a single assets table keyed by
// (namespace, key). It never touches files on disk — storage_path keeps
// pointing at wherever the file already lives (flat for old base assets,
// overrides/<ns>/ for old overrides); only new uploads after this migration
// write to the new <namespace>/<key><ext> layout.
func migrateUnifyAssetOwnership(tx *sql.Tx) error {
	if _, err := tx.Exec(`
		CREATE TABLE assets_new (
			namespace    TEXT NOT NULL REFERENCES namespaces(name),
			key          TEXT NOT NULL,
			filename     TEXT NOT NULL,
			mime_type    TEXT NOT NULL,
			sha256       TEXT NOT NULL,
			size         INTEGER NOT NULL,
			storage_path TEXT NOT NULL,
			uploaded_at  TEXT NOT NULL,
			meta         TEXT,
			PRIMARY KEY (namespace, key)
		)
	`); err != nil {
		return err
	}

	parent, err := loadNamespaceParents(tx)
	if err != nil {
		return err
	}

	rows, err := tx.Query(`SELECT key,filename,mime_type,sha256,size,namespaces,uploaded_at,meta FROM assets`)
	if err != nil {
		return err
	}
	type oldAsset struct {
		key, filename, mimeType, sha256, uploadedAt string
		size                                        int64
		namespaces                                  []string
		meta                                        sql.NullString
	}
	var oldAssets []oldAsset
	for rows.Next() {
		var a oldAsset
		var nsJSON string
		if err := rows.Scan(&a.key, &a.filename, &a.mimeType, &a.sha256, &a.size, &nsJSON, &a.uploadedAt, &a.meta); err != nil {
			rows.Close()
			return err
		}
		if err := json.Unmarshal([]byte(nsJSON), &a.namespaces); err != nil {
			rows.Close()
			return fmt.Errorf("bad namespaces json for %q: %w", a.key, err)
		}
		oldAssets = append(oldAssets, a)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	for _, a := range oldAssets {
		targets, ok := resolveOwnership(a.namespaces, parent)
		if !ok {
			log.Printf("migration 6: %q: no common ancestor for %v, duplicating into each", a.key, a.namespaces)
		}
		for _, ns := range targets {
			if _, err := tx.Exec(`
				INSERT INTO assets_new(namespace,key,filename,mime_type,sha256,size,storage_path,uploaded_at,meta)
				VALUES (?,?,?,?,?,?,?,?,?)
				ON CONFLICT(namespace,key) DO NOTHING
			`, ns, a.key, a.filename, a.mimeType, a.sha256, a.size, a.filename, a.uploadedAt, a.meta); err != nil {
				return err
			}
		}
	}

	// asset_overrides win over an already-migrated base row with the same
	// (namespace,key) — matches the pre-migration runtime precedence, where
	// an override always shadowed the inherited/base asset.
	orows, err := tx.Query(`SELECT namespace,key,filename,mime_type,sha256,size,uploaded_at,meta FROM asset_overrides`)
	if err != nil {
		return err
	}
	for orows.Next() {
		var ns, key, filename, mimeType, sha256, uploadedAt string
		var size int64
		var meta sql.NullString
		if err := orows.Scan(&ns, &key, &filename, &mimeType, &sha256, &size, &uploadedAt, &meta); err != nil {
			orows.Close()
			return err
		}
		storagePath := "overrides/" + ns + "/" + filename
		if _, err := tx.Exec(`
			INSERT INTO assets_new(namespace,key,filename,mime_type,sha256,size,storage_path,uploaded_at,meta)
			VALUES (?,?,?,?,?,?,?,?,?)
			ON CONFLICT(namespace,key) DO UPDATE SET
				filename=excluded.filename, mime_type=excluded.mime_type, sha256=excluded.sha256,
				size=excluded.size, storage_path=excluded.storage_path,
				uploaded_at=excluded.uploaded_at, meta=excluded.meta
		`, ns, key, filename, mimeType, sha256, size, storagePath, uploadedAt, meta); err != nil {
			orows.Close()
			return err
		}
	}
	if err := orows.Err(); err != nil {
		return err
	}
	orows.Close()

	if _, err := tx.Exec(`DROP TABLE assets`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE asset_overrides`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE assets_new RENAME TO assets`); err != nil {
		return err
	}
	return nil
}

func loadNamespaceParents(tx *sql.Tx) (map[string]string, error) {
	rows, err := tx.Query(`SELECT name, COALESCE(parent,'') FROM namespaces`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, par string
		if err := rows.Scan(&name, &par); err != nil {
			return nil, err
		}
		out[name] = par
	}
	return out, rows.Err()
}

func namespaceChainFromMap(name string, parent map[string]string) []string {
	chain := []string{name}
	seen := map[string]bool{name: true}
	current := name
	for i := 0; i < 32; i++ {
		p, ok := parent[current]
		if !ok || p == "" || seen[p] {
			break
		}
		chain = append(chain, p)
		seen[p] = true
		current = p
	}
	return chain
}

// resolveOwnership picks the single namespace an asset tagged with the given
// namespaces should live in after unification: the closest common ancestor of
// all tagged namespaces (walking each namespace's chain from itself to root).
// If none exists (disjoint trees — shouldn't happen with today's data), it
// returns all of them with ok=false so the caller can duplicate + warn
// instead of silently losing data.
func resolveOwnership(namespaces []string, parent map[string]string) (targets []string, ok bool) {
	if len(namespaces) == 0 {
		return nil, false
	}
	if len(namespaces) == 1 {
		return namespaces, true
	}
	chains := make([][]string, len(namespaces))
	for i, ns := range namespaces {
		chains[i] = namespaceChainFromMap(ns, parent)
	}
	inAll := func(candidate string) bool {
		for _, c := range chains[1:] {
			found := false
			for _, x := range c {
				if x == candidate {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	for _, candidate := range chains[0] {
		if inAll(candidate) {
			return []string{candidate}, true
		}
	}
	return namespaces, false
}
