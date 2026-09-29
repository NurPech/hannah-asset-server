package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	bundleManifestName = "manifest.json"
	bundleFilePrefix   = "files/"
	bundleFormat       = 1
	maxManifestBytes   = 4 << 20
)

// bundleManifest is the first entry of an export bundle (tar.gz). Asset files follow as
// files/<key>. Only assets owned directly by the namespace are exported, not inherited ones.
type bundleManifest struct {
	Format     int           `json:"format"`
	Namespace  string        `json:"namespace"`
	ExportedAt time.Time     `json:"exported_at"`
	Assets     []bundleAsset `json:"assets"`
}

type bundleAsset struct {
	Key      string `json:"key"`
	MimeType string `json:"mime_type"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

// GET /api/export?namespace=<ns>[&keys=a,b,c] — streams a tar.gz bundle (read permission on ns).
func (app *App) handleExport(w http.ResponseWriter, r *http.Request) {
	ctx := getAuthContext(r)
	ns := r.URL.Query().Get("namespace")
	if ns == "" || !app.store.IsValidNamespace(ns) {
		writeError(w, http.StatusBadRequest, "unknown namespace")
		return
	}
	if !ctx.IsAdmin && !hasPermission(ctx.Permissions, ns, "read") {
		writeError(w, http.StatusForbidden, "Forbidden")
		return
	}

	var wanted map[string]bool
	if keys := r.URL.Query().Get("keys"); keys != "" {
		wanted = map[string]bool{}
		for _, k := range strings.Split(keys, ",") {
			wanted[strings.TrimSpace(k)] = true
		}
	}

	assets, err := app.store.ListAssetsByNamespace(ns)
	if err != nil {
		log.Printf("export list: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Stat everything up front so the manifest matches what will actually be written.
	manifest := bundleManifest{Format: bundleFormat, Namespace: ns, ExportedAt: time.Now().UTC(), Assets: []bundleAsset{}}
	paths := map[string]string{}
	for _, a := range assets {
		if wanted != nil && !wanted[a.Key] {
			continue
		}
		path := filepath.Join(app.storagePath, a.StoragePath)
		fi, err := os.Stat(path)
		if err != nil {
			log.Printf("export skip %s/%s: %v", ns, a.Key, err)
			continue
		}
		manifest.Assets = append(manifest.Assets, bundleAsset{Key: a.Key, MimeType: a.MimeType, SHA256: a.SHA256, Size: fi.Size()})
		paths[a.Key] = path
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="hannah-assets-%s-%s.tar.gz"`, ns, time.Now().UTC().Format("20060102")))

	gz, _ := gzip.NewWriterLevel(w, gzip.BestSpeed) // media is mostly compressed already
	tw := tar.NewWriter(gz)
	// Headers are already sent at this point; a failure can only truncate the stream.
	if err := writeTarEntry(tw, bundleManifestName, int64(len(manifestJSON)), strings.NewReader(string(manifestJSON))); err != nil {
		log.Printf("export %s: %v", ns, err)
		return
	}
	for _, ba := range manifest.Assets {
		f, err := os.Open(paths[ba.Key])
		if err != nil {
			log.Printf("export %s/%s: %v", ns, ba.Key, err)
			return
		}
		err = writeTarEntry(tw, bundleFilePrefix+ba.Key, ba.Size, f)
		f.Close()
		if err != nil {
			log.Printf("export %s/%s: %v", ns, ba.Key, err)
			return
		}
	}
	if err := tw.Close(); err != nil {
		log.Printf("export %s: %v", ns, err)
		return
	}
	if err := gz.Close(); err != nil {
		log.Printf("export %s: %v", ns, err)
	}
}

func writeTarEntry(tw *tar.Writer, name string, size int64, src io.Reader) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: size, ModTime: time.Now().UTC()}); err != nil {
		return err
	}
	_, err := io.Copy(tw, src)
	return err
}

type importError struct {
	Key   string `json:"key"`
	Error string `json:"error"`
}

type importResult struct {
	Namespace string        `json:"namespace"`
	Created   bool          `json:"namespace_created"`
	Imported  []string      `json:"imported"`
	Unchanged []string      `json:"unchanged"`
	Conflicts []string      `json:"conflicts"`
	Errors    []importError `json:"errors"`
}

// POST /api/import?namespace=<target>[&overwrite=true] — body is a tar.gz bundle from /api/export
// (write permission on the target). The target defaults to the namespace named in the bundle and
// is created if missing (admins only). Identical assets are skipped; assets whose key exists with
// different content are skipped as conflicts unless overwrite=true.
func (app *App) handleImport(w http.ResponseWriter, r *http.Request) {
	ctx := getAuthContext(r)
	overwrite, _ := strconv.ParseBool(r.URL.Query().Get("overwrite"))
	r.Body = http.MaxBytesReader(w, r.Body, app.maxImportBytes)

	gz, err := gzip.NewReader(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "not a gzip bundle")
		return
	}
	tr := tar.NewReader(gz)

	hdr, err := tr.Next()
	if err != nil || hdr.Name != bundleManifestName {
		writeError(w, http.StatusBadRequest, "bundle must start with "+bundleManifestName)
		return
	}
	var manifest bundleManifest
	if err := json.NewDecoder(io.LimitReader(tr, maxManifestBytes)).Decode(&manifest); err != nil {
		writeError(w, http.StatusBadRequest, "invalid manifest")
		return
	}
	if manifest.Format != bundleFormat {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported bundle format %d", manifest.Format))
		return
	}

	ns := r.URL.Query().Get("namespace")
	if ns == "" {
		ns = manifest.Namespace
	}
	if !isValidNamespaceName(ns) {
		writeError(w, http.StatusBadRequest, "invalid namespace")
		return
	}
	if !ctx.IsAdmin && !hasPermission(ctx.Permissions, ns, "write") {
		writeError(w, http.StatusForbidden, "Forbidden")
		return
	}
	res := importResult{Namespace: ns, Imported: []string{}, Unchanged: []string{}, Conflicts: []string{}, Errors: []importError{}}
	if !app.store.IsValidNamespace(ns) {
		if !ctx.IsAdmin {
			writeError(w, http.StatusBadRequest, "unknown namespace")
			return
		}
		if err := app.store.CreateNamespace(&Namespace{Name: ns, Description: "imported"}); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		res.Created = true
	}

	pending := make(map[string]bundleAsset, len(manifest.Assets))
	for _, ba := range manifest.Assets {
		if !isValidKey(ba.Key) {
			res.Errors = append(res.Errors, importError{ba.Key, "invalid key"})
			continue
		}
		pending[ba.Key] = ba
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			res.Errors = append(res.Errors, importError{"", "reading bundle: " + err.Error()})
			break
		}
		key, ok := strings.CutPrefix(hdr.Name, bundleFilePrefix)
		ba, listed := pending[key]
		if !ok || !listed {
			continue // not in the manifest: ignored
		}
		delete(pending, key)

		existing, err := app.store.GetAsset(ns, key)
		if err != nil {
			res.Errors = append(res.Errors, importError{key, "internal error"})
			continue
		}
		if existing != nil && strings.EqualFold(existing.SHA256, ba.SHA256) {
			res.Unchanged = append(res.Unchanged, key)
			continue
		}
		if existing != nil && !overwrite {
			res.Conflicts = append(res.Conflicts, key)
			continue
		}
		if hdr.Size != ba.Size {
			res.Errors = append(res.Errors, importError{key, "size does not match manifest"})
			continue
		}

		if _, err := app.storeAsset(ns, key, ba.MimeType, tr, ba.SHA256); err != nil {
			msg := "internal error"
			if errors.Is(err, errChecksumMismatch) {
				msg = "sha256 does not match manifest"
			}
			res.Errors = append(res.Errors, importError{key, msg})
			continue
		}
		res.Imported = append(res.Imported, key)
	}
	for key := range pending {
		res.Errors = append(res.Errors, importError{key, "listed in manifest but missing from bundle"})
	}

	writeJSON(w, http.StatusOK, res)
}
