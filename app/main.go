package main

import (
	_ "embed"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/crypto/bcrypt"
)

//go:embed ui.html
var uiHTML []byte

// ── App ───────────────────────────────────────────────────────────────────────

type App struct {
	store        *Store
	storagePath  string
	baseURL      string
	oidcProvider *oidc.Provider
	mu           sync.RWMutex
	secureCookie bool
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	port := envOr("PORT", "8080")
	storagePath := envOr("STORAGE_PATH", "/data")
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		log.Fatal("BASE_URL must be set (e.g. https://assets.hannah.local)")
	}
	dbPath := envOr("DB_PATH", filepath.Join(storagePath, "assets.db"))
	adminPassword := os.Getenv("ADMIN_PASSWORD")
	secureCookie := os.Getenv("INSECURE_COOKIE") != "true"

	if err := os.MkdirAll(storagePath, 0o755); err != nil {
		log.Fatalf("cannot create storage path: %v", err)
	}

	db, err := openDB(dbPath)
	if err != nil {
		log.Fatalf("cannot open database: %v", err)
	}
	defer db.Close()

	store := NewStore(db)

	if err := bootstrap(store, adminPassword); err != nil {
		log.Fatalf("bootstrap failed: %v", err)
	}

	app := &App{store: store, storagePath: storagePath, baseURL: baseURL, secureCookie: secureCookie}

	go func() {
		for range time.NewTicker(1 * time.Hour).C {
			if err := store.DeleteExpiredSessions(); err != nil {
				log.Printf("session cleanup: %v", err)
			}
		}
	}()

	mux := http.NewServeMux()
	app.registerRoutes(mux)

	log.Printf("hannah-asset-server listening on :%s (storage=%s)", port, storagePath)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

// ── Routes ────────────────────────────────────────────────────────────────────

func (app *App) registerRoutes(mux *http.ServeMux) {
	// UI (no auth)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(uiHTML)
	})
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /api/config", handlePublicConfig(app.store))

	// Auth
	mux.HandleFunc("POST /api/auth/login", app.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", app.handleLogout)
	mux.HandleFunc("GET /api/auth/oauth2/authorize", app.handleOAuth2Authorize)
	mux.HandleFunc("GET /api/auth/oauth2/callback", app.handleOAuth2Callback)

	// Helper: compose withAuth + guard
	auth := func(guard func(http.HandlerFunc) http.HandlerFunc, h http.HandlerFunc) http.HandlerFunc {
		return withAuth(app.store, guard(h))
	}

	// Assets — namespace is always required (chain resolution needs it); permission checks are inside handlers
	mux.HandleFunc("GET /manifest", auth(requireAuth, app.handleManifest))
	mux.HandleFunc("GET /assets/{key}", auth(requireAuth, app.handleDownload))
	mux.HandleFunc("GET /api/assets", auth(requireAuth, app.handleListAssets))

	mux.HandleFunc("PUT /namespaces/{ns}/assets/{key}", auth(requireAuth, app.handleUpload))
	mux.HandleFunc("DELETE /namespaces/{ns}/assets/{key}", auth(requireAuth, app.handleDeleteAsset))
	mux.HandleFunc("GET /namespaces/{ns}/assets", auth(requireAuth, app.handleListNamespaceAssets))

	// Namespaces (admin)
	mux.HandleFunc("GET /api/namespaces", auth(requireAuth, app.handleListNamespaces))
	mux.HandleFunc("POST /api/namespaces", auth(requireAdmin, app.handleCreateNamespace))
	mux.HandleFunc("PUT /api/namespaces/{name}", auth(requireAdmin, app.handleUpdateNamespace))
	mux.HandleFunc("DELETE /api/namespaces/{name}", auth(requireAdmin, app.handleDeleteNamespace))

	// Me
	mux.HandleFunc("GET /api/me", auth(requireAuth, app.handleMe))

	// Users (admin)
	mux.HandleFunc("GET /api/users", auth(requireAdmin, app.handleListUsers))
	mux.HandleFunc("POST /api/users", auth(requireAdmin, app.handleCreateUser))
	mux.HandleFunc("GET /api/users/{id}", withAuth(app.store, requireAdminOrSelf("id", app.handleGetUser)))
	mux.HandleFunc("PUT /api/users/{id}", auth(requireAdmin, app.handleUpdateUser))
	mux.HandleFunc("DELETE /api/users/{id}", auth(requireAdmin, app.handleDeleteUser))

	// Groups (admin)
	mux.HandleFunc("GET /api/groups", auth(requireAdmin, app.handleListGroups))
	mux.HandleFunc("POST /api/groups", auth(requireAdmin, app.handleCreateGroup))
	mux.HandleFunc("PUT /api/groups/{id}", auth(requireAdmin, app.handleUpdateGroup))
	mux.HandleFunc("DELETE /api/groups/{id}", auth(requireAdmin, app.handleDeleteGroup))
	mux.HandleFunc("GET /api/groups/{id}/members", auth(requireAdmin, app.handleListGroupMembers))
	mux.HandleFunc("POST /api/groups/{id}/members", auth(requireAdmin, app.handleAddGroupMember))
	mux.HandleFunc("DELETE /api/groups/{id}/members/{uid}", auth(requireAdmin, app.handleRemoveGroupMember))
	mux.HandleFunc("GET /api/groups/{id}/roles", auth(requireAdmin, app.handleListGroupRoles))
	mux.HandleFunc("POST /api/groups/{id}/roles", auth(requireAdmin, app.handleAddGroupRole))
	mux.HandleFunc("DELETE /api/groups/{id}/roles/{rid}", auth(requireAdmin, app.handleRemoveGroupRole))
	mux.HandleFunc("GET /api/users/{id}/groups", withAuth(app.store, requireAdminOrSelf("id", app.handleListUserGroups)))

	// Roles (admin)
	mux.HandleFunc("GET /api/roles", auth(requireAdmin, app.handleListRoles))
	mux.HandleFunc("POST /api/roles", auth(requireAdmin, app.handleCreateRole))
	mux.HandleFunc("PUT /api/roles/{id}", auth(requireAdmin, app.handleUpdateRole))
	mux.HandleFunc("DELETE /api/roles/{id}", auth(requireAdmin, app.handleDeleteRole))
	mux.HandleFunc("POST /api/roles/{id}/assignments", auth(requireAdmin, app.handleAssignRole))
	mux.HandleFunc("DELETE /api/roles/{id}/assignments/{target}", auth(requireAdmin, app.handleRemoveRoleAssignment))

	// Service accounts
	mux.HandleFunc("GET /api/service-accounts", auth(requireAuth, app.handleListServiceAccounts))
	mux.HandleFunc("POST /api/service-accounts", auth(requireAuth, app.handleCreateServiceAccount))
	mux.HandleFunc("GET /api/service-accounts/{id}", withAuth(app.store, requireAdminOrOwner(app.store, app.handleGetServiceAccount)))
	mux.HandleFunc("DELETE /api/service-accounts/{id}", withAuth(app.store, requireAdminOrOwner(app.store, app.handleDeleteServiceAccount)))
	mux.HandleFunc("POST /api/service-accounts/{id}/tokens", withAuth(app.store, requireAdminOrOwner(app.store, app.handleCreateToken)))
	mux.HandleFunc("DELETE /api/service-accounts/{id}/tokens/{tokenId}", withAuth(app.store, requireAdminOrOwner(app.store, app.handleRevokeToken)))
	mux.HandleFunc("GET /api/service-accounts/{id}/permissions", withAuth(app.store, requireAdminOrOwner(app.store, app.handleGetServiceAccountPermissions)))
	mux.HandleFunc("PUT /api/service-accounts/{id}/permissions", withAuth(app.store, requireAdminOrOwner(app.store, app.handleSetServiceAccountPermissions)))

	// OAuth2 config (admin)
	mux.HandleFunc("GET /api/oauth2/config", auth(requireAdmin, app.handleGetOAuth2Config))
	mux.HandleFunc("PUT /api/oauth2/config", auth(requireAdmin, app.handleSetOAuth2Config))
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

func bootstrap(store *Store, adminPassword string) error {
	count, err := store.UserCount()
	if err != nil {
		return err
	}
	if count == 0 && adminPassword != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), 12)
		if err != nil {
			return err
		}
		admin := &User{
			ID:           newID(),
			Username:     "admin",
			PasswordHash: string(hash),
			IsAdmin:      true,
			IsActive:     true,
		}
		if err := store.CreateUser(admin); err != nil {
			return err
		}
		log.Println("bootstrap: created admin user")
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
