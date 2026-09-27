package main

import (
	"context"
	"net/http"
	"strings"
	"time"
)

type contextKey int

const authContextKey contextKey = 0

type AuthContext struct {
	UserID           string
	Username         string
	IsAdmin          bool
	IsServiceAccount bool
	ServiceAccountID string
	ServiceName      string
	Permissions      []Permission
}

func getAuthContext(r *http.Request) *AuthContext {
	ctx, _ := r.Context().Value(authContextKey).(*AuthContext)
	return ctx
}

func withAuth(store *Store, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authCtx := resolveAuth(store, r); authCtx != nil {
			r = r.WithContext(context.WithValue(r.Context(), authContextKey, authCtx))
		}
		next(w, r)
	}
}

func resolveAuth(store *Store, r *http.Request) *AuthContext {
	// 1. Bearer token → service account
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		plain := strings.TrimPrefix(auth, "Bearer ")
		hash := sha256Hex(plain)
		sa, err := store.GetServiceAccountByTokenHash(hash)
		if err != nil || sa == nil {
			return nil
		}
		go store.TouchTokenLastUsed(hash)
		perms, _ := store.GetServiceAccountPermissions(sa.ID)
		return &AuthContext{
			IsServiceAccount: true,
			ServiceAccountID: sa.ID,
			ServiceName:      sa.Name,
			Permissions:      perms,
		}
	}

	// 2. Session cookie → user
	cookie, err := r.Cookie("hannah_session")
	if err != nil {
		return nil
	}
	hash := sha256Hex(cookie.Value)
	sess, err := store.GetSessionByID(hash)
	if err != nil || sess == nil {
		return nil
	}
	if time.Now().After(sess.ExpiresAt) {
		store.DeleteSession(hash)
		return nil
	}
	user, err := store.GetUserByID(sess.UserID)
	if err != nil || user == nil || !user.IsActive {
		return nil
	}
	perms, _ := store.ResolveUserPermissions(user.ID)
	return &AuthContext{
		UserID:      user.ID,
		Username:    user.Username,
		IsAdmin:     user.IsAdmin,
		Permissions: perms,
	}
}

// ── Guards ────────────────────────────────────────────────────────────────────

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if getAuthContext(r) == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := getAuthContext(r)
		if ctx == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !ctx.IsAdmin {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func requireAdminOrSelf(paramName string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := getAuthContext(r)
		if ctx == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		id := r.PathValue(paramName)
		if !ctx.IsAdmin && ctx.UserID != id {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func requireAdminOrOwner(store *Store, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := getAuthContext(r)
		if ctx == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if ctx.IsAdmin {
			next(w, r)
			return
		}
		saID := r.PathValue("id")
		sa, err := store.GetServiceAccountByID(saID)
		if err != nil || sa == nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		if sa.CreatedBy != ctx.UserID {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// requireNsPermission checks that the caller has the given action on the given namespace.
// Admins always pass. Namespace is read from the ?namespace= query param.
func requireNsPermission(store *Store, action string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := getAuthContext(r)
		if ctx == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if ctx.IsAdmin {
			next(w, r)
			return
		}
		ns := r.URL.Query().Get("namespace")
		if ns == "" || !store.IsValidNamespace(ns) {
			http.Error(w, "valid namespace required", http.StatusBadRequest)
			return
		}
		if !hasPermission(ctx.Permissions, ns, action) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
