package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var mimeToExt = map[string]string{
	"audio/mpeg":               ".mp3",
	"audio/wav":                ".wav",
	"audio/ogg":                ".ogg",
	"audio/flac":               ".flac",
	"audio/aac":                ".aac",
	"image/jpeg":               ".jpg",
	"image/png":                ".png",
	"image/gif":                ".gif",
	"image/webp":               ".webp",
	"video/mp4":                ".mp4",
	"video/webm":               ".webm",
	"application/octet-stream": ".bin",
}

func extForMime(mimeType string) string {
	mt, _, _ := mime.ParseMediaType(mimeType)
	if ext, ok := mimeToExt[mt]; ok {
		return ext
	}
	return ".bin"
}

func isValidKey(key string) bool {
	return key != "" && len(key) <= 255 && !strings.ContainsAny(key, "/\\.:") && key != ".."
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}

type manifestAsset struct {
	Namespace string     `json:"namespace"`
	SHA256    string     `json:"sha256"`
	Size      int64      `json:"size"`
	MIME      string     `json:"mime"`
	Meta      *AssetMeta `json:"meta,omitempty"`
}

// GET /manifest?namespace=<ns> — resolves the namespace chain (ns plus its
// ancestors), the most specific level wins per key.
func (app *App) handleManifest(w http.ResponseWriter, r *http.Request) {
	ctx := getAuthContext(r)
	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		writeError(w, http.StatusBadRequest, "namespace query param required")
		return
	}
	if !app.store.IsValidNamespace(ns) {
		writeError(w, http.StatusBadRequest, "unknown namespace")
		return
	}
	if !ctx.IsAdmin && !hasPermission(ctx.Permissions, ns, "read") {
		writeError(w, http.StatusForbidden, "Forbidden")
		return
	}

	chain, err := app.store.NamespaceChain(ns)
	if err != nil {
		log.Printf("manifest: chain %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	assets, err := app.store.ResolveAssetsForChain(chain)
	if err != nil {
		log.Printf("manifest: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	resp := struct {
		Version     int                      `json:"version"`
		GeneratedAt string                   `json:"generated_at"`
		Assets      map[string]manifestAsset `json:"assets"`
	}{
		Version:     1,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Assets:      make(map[string]manifestAsset),
	}
	for _, a := range assets {
		resp.Assets[a.Key] = manifestAsset{Namespace: a.Namespace, SHA256: a.SHA256, Size: a.Size, MIME: a.MimeType, Meta: a.Meta}
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /assets/{key}?namespace=<ns> — resolves the namespace chain, most specific wins.
func (app *App) handleDownload(w http.ResponseWriter, r *http.Request) {
	ctx := getAuthContext(r)
	key := r.PathValue("key")
	if !isValidKey(key) {
		http.Error(w, "invalid key", http.StatusBadRequest)
		return
	}

	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		http.Error(w, "namespace query param required", http.StatusBadRequest)
		return
	}
	if !app.store.IsValidNamespace(ns) {
		http.Error(w, "unknown namespace", http.StatusBadRequest)
		return
	}
	if !ctx.IsAdmin && !hasPermission(ctx.Permissions, ns, "read") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	chain, err := app.store.NamespaceChain(ns)
	if err != nil {
		log.Printf("download chain %q: %v", ns, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var asset *Asset
	for _, level := range chain {
		a, err := app.store.GetAsset(level, key)
		if err != nil {
			log.Printf("download get %q/%q: %v", level, key, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if a != nil {
			asset = a
			break
		}
	}
	if asset == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	filePath := filepath.Join(app.storagePath, asset.StoragePath)
	f, err := os.Open(filePath)
	if err != nil {
		log.Printf("download open %s: %v", filePath, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", asset.MimeType)
	io.Copy(w, f)
}

// PUT /namespaces/{ns}/assets/{key} — the single upload endpoint. Uploading to
// a child namespace a key that's also inherited from an ancestor simply
// overrides it there; no separate "override" concept exists anymore.
func (app *App) handleUpload(w http.ResponseWriter, r *http.Request) {
	ctx := getAuthContext(r)
	ns := r.PathValue("ns")
	key := r.PathValue("key")
	if !isValidKey(key) {
		writeError(w, http.StatusBadRequest, "invalid key")
		return
	}
	if !app.store.IsValidNamespace(ns) {
		writeError(w, http.StatusBadRequest, "unknown namespace")
		return
	}
	if !ctx.IsAdmin && !hasPermission(ctx.Permissions, ns, "write") {
		writeError(w, http.StatusForbidden, "Forbidden")
		return
	}

	mimeType := r.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	asset, err := app.storeAsset(ns, key, mimeType, r.Body, "")
	if err != nil {
		if errors.Is(err, errInvalidKey) {
			writeError(w, http.StatusBadRequest, "invalid key")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"namespace": ns,
		"key":       key,
		"sha256":    asset.SHA256,
		"size":      asset.Size,
	})
}

var (
	errInvalidKey       = errors.New("invalid key")
	errChecksumMismatch = errors.New("sha256 mismatch")
)

// storeAsset writes src to disk as (ns, key) and upserts the DB row. If wantSHA is non-empty
// the content must hash to it, otherwise nothing is stored and errChecksumMismatch is returned.
// The caller is responsible for authorization and for validating ns and key.
func (app *App) storeAsset(ns, key, mimeType string, src io.Reader, wantSHA string) (*Asset, error) {
	if mt, _, err := mime.ParseMediaType(mimeType); err == nil {
		mimeType = mt
	}

	nsDir := filepath.Join(app.storagePath, ns)
	if err := os.MkdirAll(nsDir, 0o755); err != nil {
		log.Printf("upload mkdir: %v", err)
		return nil, err
	}

	tmp, err := os.CreateTemp(nsDir, "upload-*")
	if err != nil {
		log.Printf("upload create temp: %v", err)
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), src)
	tmp.Close()
	if err != nil {
		log.Printf("upload read body: %v", err)
		return nil, err
	}
	checksum := fmt.Sprintf("%x", h.Sum(nil))
	if wantSHA != "" && !strings.EqualFold(wantSHA, checksum) {
		return nil, errChecksumMismatch
	}

	filename := key + extForMime(mimeType)
	destPath := filepath.Join(nsDir, filename)
	if !strings.HasPrefix(filepath.Clean(destPath), filepath.Clean(nsDir)) {
		return nil, errInvalidKey
	}

	old, err := app.store.GetAsset(ns, key)
	if err != nil {
		log.Printf("upload get old: %v", err)
		return nil, err
	}

	if err := os.Rename(tmpName, destPath); err != nil {
		log.Printf("upload rename: %v", err)
		return nil, err
	}

	if old != nil && old.StoragePath != filepath.ToSlash(filepath.Join(ns, filename)) {
		oldPath := filepath.Join(app.storagePath, old.StoragePath)
		if err := os.Remove(oldPath); err != nil && !os.IsNotExist(err) {
			log.Printf("upload remove old file %s: %v", oldPath, err)
		}
	}

	asset := &Asset{
		Namespace:   ns,
		Key:         key,
		Filename:    filename,
		MimeType:    mimeType,
		SHA256:      checksum,
		Size:        size,
		StoragePath: filepath.ToSlash(filepath.Join(ns, filename)),
		UploadedAt:  time.Now().UTC(),
		Meta:        extractMeta(mimeType, destPath),
	}
	if err := app.store.UpsertAsset(asset); err != nil {
		log.Printf("upload upsert: %v", err)
		return nil, err
	}
	return asset, nil
}

// DELETE /namespaces/{ns}/assets/{key}
func (app *App) handleDeleteAsset(w http.ResponseWriter, r *http.Request) {
	ctx := getAuthContext(r)
	ns := r.PathValue("ns")
	key := r.PathValue("key")
	if !isValidKey(key) {
		writeError(w, http.StatusBadRequest, "invalid key")
		return
	}
	if !ctx.IsAdmin && !hasPermission(ctx.Permissions, ns, "write") {
		writeError(w, http.StatusForbidden, "Forbidden")
		return
	}

	asset, err := app.store.GetAsset(ns, key)
	if err != nil {
		log.Printf("delete get %q/%q: %v", ns, key, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if asset == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	if err := app.store.DeleteAsset(ns, key); err != nil {
		log.Printf("delete db %q/%q: %v", ns, key, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	filePath := filepath.Join(app.storagePath, asset.StoragePath)
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		log.Printf("delete file %s: %v", filePath, err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// GET /namespaces/{ns}/assets — assets stored directly in ns (not resolved
// through inheritance — use /manifest for that).
func (app *App) handleListNamespaceAssets(w http.ResponseWriter, r *http.Request) {
	ctx := getAuthContext(r)
	ns := r.PathValue("ns")
	if !ctx.IsAdmin && !hasPermission(ctx.Permissions, ns, "read") {
		writeError(w, http.StatusForbidden, "Forbidden")
		return
	}
	assets, err := app.store.ListAssetsByNamespace(ns)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if assets == nil {
		assets = []*Asset{}
	}
	writeJSON(w, http.StatusOK, assets)
}

// GET /api/assets — list all assets across all namespaces (admin: all; user: only accessible namespaces)
func (app *App) handleListAssets(w http.ResponseWriter, r *http.Request) {
	ctx := getAuthContext(r)

	assets, err := app.store.ListAssets()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if !ctx.IsAdmin {
		var filtered []*Asset
		for _, a := range assets {
			if hasPermission(ctx.Permissions, a.Namespace, "read") {
				filtered = append(filtered, a)
			}
		}
		assets = filtered
	}

	if assets == nil {
		assets = []*Asset{}
	}
	writeJSON(w, http.StatusOK, assets)
}
