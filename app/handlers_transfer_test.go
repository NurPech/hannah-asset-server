package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func newTransferTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "assets.db"))
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &App{store: NewStore(db), storagePath: dir, maxImportBytes: 1 << 20}
}

func withCtx(r *http.Request, ac *AuthContext) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), authContextKey, ac))
}

func (app *App) mustUpload(t *testing.T, ns, key, mime, body string) {
	t.Helper()
	if _, err := app.storeAsset(ns, key, mime, bytes.NewReader([]byte(body)), ""); err != nil {
		t.Fatalf("storeAsset %s/%s: %v", ns, key, err)
	}
}

func doImport(t *testing.T, app *App, ac *AuthContext, query string, bundle []byte) (int, importResult) {
	t.Helper()
	req := withCtx(httptest.NewRequest("POST", "/api/import"+query, bytes.NewReader(bundle)), ac)
	rec := httptest.NewRecorder()
	app.handleImport(rec, req)
	var res importResult
	json.Unmarshal(rec.Body.Bytes(), &res)
	return rec.Code, res
}

func TestExportImportRoundTrip(t *testing.T) {
	admin := &AuthContext{IsAdmin: true}

	src := newTransferTestApp(t)
	// "core" is seeded by the migrations.
	src.mustUpload(t, "core", "alert", "audio/mpeg", "mp3-bytes")
	src.mustUpload(t, "core", "logo", "image/png", "png-bytes")

	rec := httptest.NewRecorder()
	src.handleExport(rec, withCtx(httptest.NewRequest("GET", "/api/export?namespace=core", nil), admin))
	if rec.Code != http.StatusOK {
		t.Fatalf("export status %d: %s", rec.Code, rec.Body.String())
	}
	bundle := rec.Body.Bytes()

	// Import into a fresh server, into a differently named (auto-created) namespace.
	dst := newTransferTestApp(t)
	code, res := doImport(t, dst, admin, "?namespace=imported", bundle)
	if code != http.StatusOK || len(res.Imported) != 2 || len(res.Errors) != 0 || !res.Created {
		t.Fatalf("import: code=%d res=%+v", code, res)
	}
	a, err := dst.store.GetAsset("imported", "alert")
	if err != nil || a == nil || a.MimeType != "audio/mpeg" || a.Size != int64(len("mp3-bytes")) {
		t.Fatalf("imported asset wrong: %+v err=%v", a, err)
	}
	orig, _ := src.store.GetAsset("core", "alert")
	if a.SHA256 != orig.SHA256 {
		t.Fatalf("sha mismatch after import")
	}

	// Re-import: identical content is unchanged.
	_, res = doImport(t, dst, admin, "?namespace=imported", bundle)
	if len(res.Unchanged) != 2 || len(res.Imported) != 0 {
		t.Fatalf("re-import: %+v", res)
	}

	// Different content under the same key: conflict by default, replaced with overwrite=true.
	dst.mustUpload(t, "imported", "alert", "audio/mpeg", "local-change")
	_, res = doImport(t, dst, admin, "?namespace=imported", bundle)
	if len(res.Conflicts) != 1 || res.Conflicts[0] != "alert" {
		t.Fatalf("expected conflict: %+v", res)
	}
	_, res = doImport(t, dst, admin, "?namespace=imported&overwrite=true", bundle)
	if len(res.Imported) != 1 || res.Imported[0] != "alert" {
		t.Fatalf("expected overwrite: %+v", res)
	}
	if a, _ := dst.store.GetAsset("imported", "alert"); a.SHA256 != orig.SHA256 {
		t.Fatalf("overwrite did not restore content")
	}
}

func TestImportPermissions(t *testing.T) {
	src := newTransferTestApp(t)
	src.mustUpload(t, "core", "alert", "audio/mpeg", "x")
	rec := httptest.NewRecorder()
	src.handleExport(rec, withCtx(httptest.NewRequest("GET", "/api/export?namespace=core", nil), &AuthContext{IsAdmin: true}))
	bundle := rec.Body.Bytes()

	dst := newTransferTestApp(t)
	user := &AuthContext{Permissions: []Permission{{Namespace: "other", Action: "write"}}}

	// No write permission on the target namespace.
	if code, _ := doImport(t, dst, user, "?namespace=core", bundle); code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", code)
	}
	// Non-admins never create namespaces.
	dst.store.CreateNamespace(&Namespace{Name: "other"})
	user.Permissions = append(user.Permissions, Permission{Namespace: "missing", Action: "write"})
	if code, _ := doImport(t, dst, user, "?namespace=missing", bundle); code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", code)
	}
	// Export needs read.
	rec = httptest.NewRecorder()
	src.handleExport(rec, withCtx(httptest.NewRequest("GET", "/api/export?namespace=core", nil), &AuthContext{}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("export without read: expected 403, got %d", rec.Code)
	}
}

func TestImportRejectsGarbage(t *testing.T) {
	dst := newTransferTestApp(t)
	if code, _ := doImport(t, dst, &AuthContext{IsAdmin: true}, "?namespace=x", []byte("not a gzip")); code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", code)
	}
}
