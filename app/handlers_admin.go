package main

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// ── JSON helpers ──────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ── /api/me ───────────────────────────────────────────────────────────────────

func (app *App) handleMe(w http.ResponseWriter, r *http.Request) {
	ctx := getAuthContext(r)
	if ctx.IsServiceAccount {
		writeJSON(w, http.StatusOK, map[string]any{
			"type":               "service_account",
			"service_account_id": ctx.ServiceAccountID,
			"permissions":        ctx.Permissions,
		})
		return
	}
	resp := map[string]any{
		"type":        "user",
		"user_id":     ctx.UserID,
		"username":    ctx.Username,
		"is_admin":    ctx.IsAdmin,
		"permissions": ctx.Permissions,
	}
	if u, _ := app.store.GetUserByID(ctx.UserID); u != nil {
		resp["has_password"] = u.PasswordHash != ""
	}
	writeJSON(w, http.StatusOK, resp)
}

// ── Users ─────────────────────────────────────────────────────────────────────

func (app *App) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := app.store.ListUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, usersToJSON(users))
}

func (app *App) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		IsAdmin  bool   `json:"is_admin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password required")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash error")
		return
	}
	u := &User{
		ID:           newID(),
		Username:     req.Username,
		PasswordHash: string(hash),
		IsAdmin:      req.IsAdmin,
		IsActive:     true,
	}
	if err := app.store.CreateUser(u); err != nil {
		writeError(w, http.StatusConflict, "username already exists")
		return
	}
	writeJSON(w, http.StatusCreated, userToJSON(u))
}

func (app *App) handleGetUser(w http.ResponseWriter, r *http.Request) {
	u, err := app.store.GetUserByID(r.PathValue("id"))
	if err != nil || u == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, userToJSON(u))
}

func (app *App) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	u, err := app.store.GetUserByID(r.PathValue("id"))
	if err != nil || u == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var req struct {
		Username *string `json:"username"`
		Password *string `json:"password"`
		IsAdmin  *bool   `json:"is_admin"`
		IsActive *bool   `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Username != nil {
		u.Username = *req.Username
	}
	if req.Password != nil && *req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), 12)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "hash error")
			return
		}
		u.PasswordHash = string(hash)
	}
	if req.IsAdmin != nil {
		u.IsAdmin = *req.IsAdmin
	}
	if req.IsActive != nil {
		u.IsActive = *req.IsActive
	}
	if err := app.store.UpdateUser(u); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, userToJSON(u))
}

func (app *App) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if ctx := getAuthContext(r); ctx.UserID == id {
		writeError(w, http.StatusBadRequest, "cannot delete yourself")
		return
	}
	if err := app.store.DeleteUser(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Groups ────────────────────────────────────────────────────────────────────

func (app *App) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := app.store.ListGroups()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, groupsToJSON(groups))
}

func (app *App) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	g := &Group{ID: newID(), Name: req.Name, Description: req.Description}
	if err := app.store.CreateGroup(g); err != nil {
		writeError(w, http.StatusConflict, "group name already exists")
		return
	}
	writeJSON(w, http.StatusCreated, groupToJSON(g))
}

func (app *App) handleUpdateGroup(w http.ResponseWriter, r *http.Request) {
	g, err := app.store.GetGroupByID(r.PathValue("id"))
	if err != nil || g == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Name != nil {
		g.Name = *req.Name
	}
	if req.Description != nil {
		g.Description = *req.Description
	}
	if err := app.store.UpdateGroup(g); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, groupToJSON(g))
}

func (app *App) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	if err := app.store.DeleteGroup(r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *App) handleListGroupMembers(w http.ResponseWriter, r *http.Request) {
	members, err := app.store.ListGroupMembers(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, usersToJSON(members))
}

func (app *App) handleAddGroupMember(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		writeError(w, http.StatusBadRequest, "user_id required")
		return
	}
	if err := app.store.AddUserToGroup(req.UserID, r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *App) handleRemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	if err := app.store.RemoveUserFromGroup(r.PathValue("uid"), r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *App) handleListGroupRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := app.store.ListGroupRoles(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, len(roles))
	for i, role := range roles {
		perms, _ := app.store.GetRolePermissions(role.ID)
		out[i] = roleToJSON(role, perms)
	}
	writeJSON(w, http.StatusOK, out)
}

func (app *App) handleAddGroupRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID string `json:"role_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RoleID == "" {
		writeError(w, http.StatusBadRequest, "role_id required")
		return
	}
	if err := app.store.AssignRoleToGroup(req.RoleID, r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *App) handleRemoveGroupRole(w http.ResponseWriter, r *http.Request) {
	if err := app.store.RemoveRoleFromGroup(r.PathValue("rid"), r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *App) handleListUserGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := app.store.ListUserGroups(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, groupsToJSON(groups))
}

// ── Roles ─────────────────────────────────────────────────────────────────────

func (app *App) handleListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := app.store.ListRoles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, len(roles))
	for i, role := range roles {
		perms, _ := app.store.GetRolePermissions(role.ID)
		out[i] = roleToJSON(role, perms)
	}
	writeJSON(w, http.StatusOK, out)
}

func (app *App) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string       `json:"name"`
		Description string       `json:"description"`
		Permissions []Permission `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	role := &Role{ID: newID(), Name: req.Name, Description: req.Description}
	if err := app.store.CreateRole(role); err != nil {
		writeError(w, http.StatusConflict, "role name already exists")
		return
	}
	if len(req.Permissions) > 0 {
		app.store.SetRolePermissions(role.ID, req.Permissions)
	}
	writeJSON(w, http.StatusCreated, roleToJSON(role, req.Permissions))
}

func (app *App) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	role, err := app.store.GetRoleByID(r.PathValue("id"))
	if err != nil || role == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var req struct {
		Name        *string      `json:"name"`
		Description *string      `json:"description"`
		Permissions []Permission `json:"permissions"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Name != nil {
		role.Name = *req.Name
	}
	if req.Description != nil {
		role.Description = *req.Description
	}
	app.store.UpdateRole(role)
	if req.Permissions != nil {
		app.store.SetRolePermissions(role.ID, req.Permissions)
	}
	perms, _ := app.store.GetRolePermissions(role.ID)
	writeJSON(w, http.StatusOK, roleToJSON(role, perms))
}

func (app *App) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	if err := app.store.DeleteRole(r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *App) handleAssignRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type     string `json:"type"`      // "user" or "group"
		TargetID string `json:"target_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TargetID == "" {
		writeError(w, http.StatusBadRequest, "type and target_id required")
		return
	}
	roleID := r.PathValue("id")
	var err error
	switch req.Type {
	case "user":
		err = app.store.AssignRoleToUser(roleID, req.TargetID)
	case "group":
		err = app.store.AssignRoleToGroup(roleID, req.TargetID)
	default:
		writeError(w, http.StatusBadRequest, "type must be 'user' or 'group'")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *App) handleRemoveRoleAssignment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type string `json:"type"` // "user" or "group"
	}
	json.NewDecoder(r.Body).Decode(&req)
	roleID := r.PathValue("id")
	targetID := r.PathValue("target")
	var err error
	switch req.Type {
	case "group":
		err = app.store.RemoveRoleFromGroup(roleID, targetID)
	default:
		err = app.store.RemoveRoleFromUser(roleID, targetID)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Namespaces ────────────────────────────────────────────────────────────────

func (app *App) handleListNamespaces(w http.ResponseWriter, r *http.Request) {
	namespaces, err := app.store.ListNamespaces()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, namespacesToJSON(namespaces))
}

func (app *App) handleCreateNamespace(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Parent      string `json:"parent"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	n := &Namespace{Name: req.Name, Parent: req.Parent, Description: req.Description}
	if err := app.store.CreateNamespace(n); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, namespaceToJSON(n))
}

func (app *App) handleUpdateNamespace(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	existing, err := app.store.GetNamespace(name)
	if err != nil || existing == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var req struct {
		Description *string `json:"description"`
		Parent      *string `json:"parent"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	description := existing.Description
	if req.Description != nil {
		description = *req.Description
	}
	parent := existing.Parent
	if req.Parent != nil {
		parent = *req.Parent
	}
	if err := app.store.UpdateNamespace(name, description, parent); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, _ := app.store.GetNamespace(name)
	writeJSON(w, http.StatusOK, namespaceToJSON(updated))
}

func (app *App) handleDeleteNamespace(w http.ResponseWriter, r *http.Request) {
	if err := app.store.DeleteNamespace(r.PathValue("name")); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Service Accounts ──────────────────────────────────────────────────────────

func (app *App) handleListServiceAccounts(w http.ResponseWriter, r *http.Request) {
	ctx := getAuthContext(r)
	var accounts []*ServiceAccount
	var err error
	if ctx.IsAdmin {
		accounts, err = app.store.ListServiceAccounts()
	} else {
		accounts, err = app.store.ListServiceAccountsByUser(ctx.UserID)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, len(accounts))
	for i, sa := range accounts {
		out[i] = saToJSON(sa)
	}
	writeJSON(w, http.StatusOK, out)
}

func (app *App) handleCreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	ctx := getAuthContext(r)
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	sa := &ServiceAccount{
		ID:        newID(),
		Name:      req.Name,
		CreatedBy: ctx.UserID,
		IsActive:  true,
	}
	if err := app.store.CreateServiceAccount(sa); err != nil {
		writeError(w, http.StatusConflict, "name already exists")
		return
	}
	writeJSON(w, http.StatusCreated, saToJSON(sa))
}

func (app *App) handleGetServiceAccount(w http.ResponseWriter, r *http.Request) {
	sa, err := app.store.GetServiceAccountByID(r.PathValue("id"))
	if err != nil || sa == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	perms, _ := app.store.GetServiceAccountPermissions(sa.ID)
	tokens, _ := app.store.ListTokensForServiceAccount(sa.ID)
	out := saToJSON(sa)
	out["permissions"] = perms
	out["tokens"] = tokensToJSON(tokens)
	writeJSON(w, http.StatusOK, out)
}

func (app *App) handleDeleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	if err := app.store.DeleteServiceAccount(r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *App) handleGetServiceAccountPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := app.store.GetServiceAccountPermissions(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, perms)
}

func (app *App) handleSetServiceAccountPermissions(w http.ResponseWriter, r *http.Request) {
	authCtx := getAuthContext(r)
	saID := r.PathValue("id")
	sa, err := app.store.GetServiceAccountByID(saID)
	if err != nil || sa == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var req struct {
		Permissions []Permission `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	var capped []Permission
	if authCtx.IsAdmin {
		capped = req.Permissions
	} else {
		creatorID := sa.CreatedBy
		if creatorID == "" {
			creatorID = authCtx.UserID
		}
		creatorPerms, _ := app.store.ResolveUserPermissions(creatorID)
		for _, p := range req.Permissions {
			if hasPermission(creatorPerms, p.Namespace, p.Action) {
				capped = append(capped, p)
			}
		}
	}
	if err := app.store.SetServiceAccountPermissions(saID, capped); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, capped)
}

func (app *App) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	saID := r.PathValue("id")
	sa, err := app.store.GetServiceAccountByID(saID)
	if err != nil || sa == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.Name == "" {
		req.Name = "token"
	}
	plain, hash, err := generateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	t := &ServiceAccountToken{
		ID:               newID(),
		ServiceAccountID: saID,
		Name:             req.Name,
		TokenHash:        hash,
	}
	if err := app.store.CreateServiceAccountToken(t); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":    t.ID,
		"name":  t.Name,
		"token": plain, // shown exactly once
	})
}

func (app *App) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if err := app.store.DeleteToken(r.PathValue("tokenId")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── OAuth2 Config ─────────────────────────────────────────────────────────────

func (app *App) handleGetOAuth2Config(w http.ResponseWriter, r *http.Request) {
	cfg, err := app.store.GetOAuth2Config()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (app *App) handleSetOAuth2Config(w http.ResponseWriter, r *http.Request) {
	var cfg OAuth2Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := app.store.SetOAuth2Config(&cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	app.mu.Lock()
	app.oidcProvider = nil
	app.mu.Unlock()
	writeJSON(w, http.StatusOK, cfg)
}

// ── JSON serialisation ────────────────────────────────────────────────────────

func userToJSON(u *User) map[string]any {
	return map[string]any{
		"id":           u.ID,
		"username":     u.Username,
		"is_admin":     u.IsAdmin,
		"is_active":    u.IsActive,
		"has_password": u.PasswordHash != "",
		"has_oidc":     u.OIDCSub != "",
		"created_at":   u.CreatedAt,
	}
}

func usersToJSON(users []*User) []map[string]any {
	out := make([]map[string]any, len(users))
	for i, u := range users {
		out[i] = userToJSON(u)
	}
	return out
}

func groupToJSON(g *Group) map[string]any {
	return map[string]any{
		"id":          g.ID,
		"name":        g.Name,
		"description": g.Description,
		"created_at":  g.CreatedAt,
	}
}

func groupsToJSON(groups []*Group) []map[string]any {
	out := make([]map[string]any, len(groups))
	for i, g := range groups {
		out[i] = groupToJSON(g)
	}
	return out
}

func roleToJSON(r *Role, perms []Permission) map[string]any {
	if perms == nil {
		perms = []Permission{}
	}
	return map[string]any{
		"id":          r.ID,
		"name":        r.Name,
		"description": r.Description,
		"permissions": perms,
		"created_at":  r.CreatedAt,
	}
}

func namespaceToJSON(n *Namespace) map[string]any {
	return map[string]any{
		"name":        n.Name,
		"parent":      n.Parent,
		"description": n.Description,
		"created_at":  n.CreatedAt,
	}
}

func namespacesToJSON(namespaces []*Namespace) []map[string]any {
	out := make([]map[string]any, len(namespaces))
	for i, n := range namespaces {
		out[i] = namespaceToJSON(n)
	}
	return out
}

func saToJSON(sa *ServiceAccount) map[string]any {
	return map[string]any{
		"id":         sa.ID,
		"name":       sa.Name,
		"created_by": sa.CreatedBy,
		"is_active":  sa.IsActive,
		"created_at": sa.CreatedAt,
	}
}

func tokensToJSON(tokens []*ServiceAccountToken) []map[string]any {
	out := make([]map[string]any, len(tokens))
	for i, t := range tokens {
		out[i] = map[string]any{
			"id":           t.ID,
			"name":         t.Name,
			"created_at":   t.CreatedAt,
			"expires_at":   t.ExpiresAt,
			"last_used_at": t.LastUsedAt,
		}
	}
	return out
}
