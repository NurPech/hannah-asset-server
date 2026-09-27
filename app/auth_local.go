package main

import (
	"encoding/json"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (app *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	user, err := app.store.GetUserByUsername(req.Username)
	if err != nil || user == nil || !user.IsActive || user.PasswordHash == "" {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"user_id":  user.ID,
		"username": user.Username,
		"is_admin": user.IsAdmin,
	})
}

func (app *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("hannah_session")
	if err == nil {
		app.store.DeleteSession(sha256Hex(cookie.Value))
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "hannah_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	w.WriteHeader(http.StatusNoContent)
}
