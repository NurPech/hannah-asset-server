package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func (app *App) getOIDCProvider(ctx context.Context, redirectURL string) (*oidc.Provider, *oauth2.Config, error) {
	app.mu.RLock()
	p := app.oidcProvider
	app.mu.RUnlock()
	if p != nil {
		cfg, err := app.store.GetOAuth2Config()
		if err != nil {
			return nil, nil, err
		}
		return p, app.buildOAuth2Config(cfg, p, redirectURL), nil
	}
	cfg, err := app.store.GetOAuth2Config()
	if err != nil {
		return nil, nil, err
	}
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, nil, err
	}
	app.mu.Lock()
	app.oidcProvider = provider
	app.mu.Unlock()
	return provider, app.buildOAuth2Config(cfg, provider, redirectURL), nil
}

func (app *App) buildOAuth2Config(cfg *OAuth2Config, provider *oidc.Provider, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

// requestRedirectURL derives the OAuth2 callback URL from the incoming request instead of a
// statically configured scheme, since BASE_URL has no scheme (Traefik sits behind NetScaler,
// which terminates TLS and is trusted via forwardedHeaders.trustedIPs to set X-Forwarded-Proto).
func requestRedirectURL(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/api/auth/oauth2/callback"
}

func (app *App) handleOAuth2Authorize(w http.ResponseWriter, r *http.Request) {
	cfg, err := app.store.GetOAuth2Config()
	if err != nil || !cfg.Enabled {
		http.Error(w, "OAuth2 not configured", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	_, oauth2cfg, err := app.getOIDCProvider(ctx, requestRedirectURL(r))
	if err != nil {
		http.Error(w, "OAuth2 provider unavailable", http.StatusServiceUnavailable)
		return
	}
	b := make([]byte, 16)
	rand.Read(b)
	state := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth2_state",
		Value:    state,
		Path:     "/api/auth/oauth2",
		HttpOnly: true,
		Secure:   app.secureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
	http.Redirect(w, r, oauth2cfg.AuthCodeURL(state), http.StatusFound)
}

func (app *App) handleOAuth2Callback(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie("oauth2_state")
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "oauth2_state", Value: "", Path: "/api/auth/oauth2", MaxAge: -1})

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	provider, oauth2cfg, err := app.getOIDCProvider(ctx, requestRedirectURL(r))
	if err != nil {
		http.Error(w, "OAuth2 provider unavailable", http.StatusServiceUnavailable)
		return
	}

	token, err := oauth2cfg.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Token exchange failed", http.StatusBadRequest)
		return
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: oauth2cfg.ClientID})
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No ID token", http.StatusBadRequest)
		return
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "ID token verification failed", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Sub               string   `json:"sub"`
		PreferredUsername string   `json:"preferred_username"`
		Email             string   `json:"email"`
		Groups            []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
		return
	}

	user, err := app.store.GetUserByOIDCSub(claims.Sub)
	if err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		username := claims.PreferredUsername
		if username == "" {
			username = claims.Email
		}
		if username == "" {
			username = claims.Sub
		}
		user = &User{
			ID:       newID(),
			Username: username,
			OIDCSub:  claims.Sub,
			IsActive: true,
		}
		if err := app.store.CreateUser(user); err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}
	}
	if !user.IsActive {
		http.Error(w, "Account disabled", http.StatusForbidden)
		return
	}

	// Sync group memberships from IdP claim if present
	if len(claims.Groups) > 0 {
		app.store.SyncUserGroupsByName(user.ID, claims.Groups)
	}

	plain, hash, err := generateToken()
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	sess := &Session{
		ID:        hash,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := app.store.CreateSession(sess); err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "hannah_session",
		Value:    plain,
		Path:     "/",
		HttpOnly: true,
		Secure:   app.secureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func handlePublicConfig(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := store.GetOAuth2Config()
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"oauth2_enabled": cfg.Enabled,
		})
	}
}
