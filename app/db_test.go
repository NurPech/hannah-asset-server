package main

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// openTestDB applies every migration up to (but not including) version 6, so
// tests can seed pre-unification fixture data before running migration 6
// itself.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file::memory:?_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1) // keep all queries on the same in-memory DB
	t.Cleanup(func() { db.Close() })

	if _, err := db.Exec(`CREATE TABLE schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for _, m := range migrations {
		if m.version >= 6 {
			break
		}
		if err := applyMigration(db, m); err != nil {
			t.Fatalf("apply migration %d: %v", m.version, err)
		}
	}
	return db
}

func TestMigrateUnifyAssetOwnership(t *testing.T) {
	db := openTestDB(t)

	// Single-namespace asset: should land directly in that namespace, storage_path unchanged.
	if _, err := db.Exec(
		`INSERT INTO assets(key,filename,mime_type,sha256,size,namespaces,uploaded_at) VALUES(?,?,?,?,?,?,?)`,
		"only_core", "only_core.mp3", "audio/mpeg", "sha_core", 10, `["core"]`, "2026-01-01T00:00:00Z",
	); err != nil {
		t.Fatalf("seed only_core: %v", err)
	}

	// Multi-namespace asset (core+satellite): should land on the common ancestor 'shared'.
	if _, err := db.Exec(
		`INSERT INTO assets(key,filename,mime_type,sha256,size,namespaces,uploaded_at) VALUES(?,?,?,?,?,?,?)`,
		"both", "both.mp3", "audio/mpeg", "sha_both", 20, `["core","satellite"]`, "2026-01-01T00:00:00Z",
	); err != nil {
		t.Fatalf("seed both: %v", err)
	}

	// Base asset under satellite that also has an override for satellite — override must win.
	if _, err := db.Exec(
		`INSERT INTO assets(key,filename,mime_type,sha256,size,namespaces,uploaded_at) VALUES(?,?,?,?,?,?,?)`,
		"shadowed", "shadowed.mp3", "audio/mpeg", "sha_base", 30, `["satellite"]`, "2026-01-01T00:00:00Z",
	); err != nil {
		t.Fatalf("seed shadowed base: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO asset_overrides(namespace,key,filename,mime_type,sha256,size,uploaded_at) VALUES(?,?,?,?,?,?,?)`,
		"satellite", "shadowed", "shadowed_override.mp3", "audio/mpeg", "sha_override", 31, "2026-01-01T00:00:00Z",
	); err != nil {
		t.Fatalf("seed shadowed override: %v", err)
	}

	// Pure override under a child namespace, no base counterpart at all.
	if _, err := db.Exec(
		`INSERT INTO namespaces(name,parent,description,created_at) VALUES(?,?,?,?)`,
		"satellite-test", "satellite", "", "2026-01-01T00:00:00Z",
	); err != nil {
		t.Fatalf("seed satellite-test namespace: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO asset_overrides(namespace,key,filename,mime_type,sha256,size,uploaded_at) VALUES(?,?,?,?,?,?,?)`,
		"satellite-test", "test_only", "test_only.mp3", "audio/mpeg", "sha_test_only", 40, "2026-01-01T00:00:00Z",
	); err != nil {
		t.Fatalf("seed test_only override: %v", err)
	}

	m6 := migrations[5]
	if m6.version != 6 {
		t.Fatalf("expected migrations[5] to be version 6, got %d (migrations slice order changed?)", m6.version)
	}
	if err := applyMigration(db, m6); err != nil {
		t.Fatalf("apply migration 6: %v", err)
	}

	type row struct {
		namespace, key, storagePath, sha string
	}
	get := func(namespace, key string) *row {
		t.Helper()
		var r row
		err := db.QueryRow(
			`SELECT namespace,key,storage_path,sha256 FROM assets WHERE namespace=? AND key=?`, namespace, key,
		).Scan(&r.namespace, &r.key, &r.storagePath, &r.sha)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			t.Fatalf("query %s/%s: %v", namespace, key, err)
		}
		return &r
	}

	if r := get("core", "only_core"); r == nil || r.sha != "sha_core" || r.storagePath != "only_core.mp3" {
		t.Errorf("only_core: got %+v, want namespace=core sha=sha_core storage_path=only_core.mp3", r)
	}

	if r := get("shared", "both"); r == nil || r.sha != "sha_both" {
		t.Errorf("both: expected to land under shared with sha_both, got %+v", r)
	}
	if r := get("core", "both"); r != nil {
		t.Errorf("both: unexpectedly also present directly under core: %+v", r)
	}
	if r := get("satellite", "both"); r != nil {
		t.Errorf("both: unexpectedly also present directly under satellite: %+v", r)
	}

	if r := get("satellite", "shadowed"); r == nil || r.sha != "sha_override" || r.storagePath != "overrides/satellite/shadowed_override.mp3" {
		t.Errorf("shadowed: expected override to win over base, got %+v", r)
	}

	if r := get("satellite-test", "test_only"); r == nil || r.sha != "sha_test_only" {
		t.Errorf("test_only: expected override-only asset to survive migration, got %+v", r)
	}

	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='asset_overrides'`).Scan(&name)
	if err != sql.ErrNoRows {
		t.Errorf("expected asset_overrides table to be dropped, got err=%v name=%q", err, name)
	}
}

func TestResolveOwnershipNoCommonAncestor(t *testing.T) {
	parent := map[string]string{"a": "", "b": ""} // two unrelated roots
	targets, ok := resolveOwnership([]string{"a", "b"}, parent)
	if ok {
		t.Fatalf("expected ok=false for disjoint trees, got targets=%v", targets)
	}
	if len(targets) != 2 || targets[0] != "a" || targets[1] != "b" {
		t.Fatalf("expected fallback to duplicate into both original namespaces, got %v", targets)
	}
}

func TestResolveOwnershipSingleNamespace(t *testing.T) {
	targets, ok := resolveOwnership([]string{"core"}, map[string]string{"core": "shared"})
	if !ok || len(targets) != 1 || targets[0] != "core" {
		t.Fatalf("expected single namespace to map directly to itself, got targets=%v ok=%v", targets, ok)
	}
}
