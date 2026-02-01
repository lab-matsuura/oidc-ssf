package handler

import (
	"context"
	"html/template"
	"net/http"
	"net/url"

	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres/sqlc"
	"golang.org/x/crypto/bcrypt"
)

// LoginHandler handles user login with DB authentication
type LoginHandler struct {
	queries   *sqlc.Queries
	templates *template.Template
}

// NewLoginHandler creates a new login handler with DB authentication
func NewLoginHandler(queries *sqlc.Queries, templates *template.Template) *LoginHandler {
	return &LoginHandler{
		queries:   queries,
		templates: templates,
	}
}

// ServeHTTP handles login requests
func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		h.showLoginForm(w, r, "")
		return
	}

	if r.Method == "POST" {
		h.processLogin(w, r)
	}
}

func (h *LoginHandler) showLoginForm(w http.ResponseWriter, r *http.Request, errorMsg string) {
	data := map[string]string{
		"RedirectURI":         r.URL.Query().Get("redirect_uri"),
		"ClientID":            r.URL.Query().Get("client_id"),
		"ResponseType":        r.URL.Query().Get("response_type"),
		"Scope":               r.URL.Query().Get("scope"),
		"State":               r.URL.Query().Get("state"),
		"Nonce":               r.URL.Query().Get("nonce"),
		"CodeChallenge":       r.URL.Query().Get("code_challenge"),
		"CodeChallengeMethod": r.URL.Query().Get("code_challenge_method"),
		"Error":               errorMsg,
	}

	// For POST requests with error, get values from form
	if r.Method == "POST" {
		data["RedirectURI"] = r.FormValue("redirect_uri")
		data["ClientID"] = r.FormValue("client_id")
		data["ResponseType"] = r.FormValue("response_type")
		data["Scope"] = r.FormValue("scope")
		data["State"] = r.FormValue("state")
		data["Nonce"] = r.FormValue("nonce")
		data["CodeChallenge"] = r.FormValue("code_challenge")
		data["CodeChallengeMethod"] = r.FormValue("code_challenge_method")
	}

	w.Header().Set("Content-Type", "text/html")
	if err := h.templates.ExecuteTemplate(w, "login.html", data); err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
	}
}

func (h *LoginHandler) processLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Validate credentials against DB
	if !h.validateCredentials(r.Context(), username, password) {
		h.showLoginForm(w, r, "Invalid username or password")
		return
	}

	// Redirect back to authorize endpoint with username and OIDC parameters
	values := url.Values{}
	values.Set("username", username)
	values.Set("redirect_uri", r.FormValue("redirect_uri"))
	values.Set("client_id", r.FormValue("client_id"))
	values.Set("response_type", r.FormValue("response_type"))
	values.Set("scope", r.FormValue("scope"))
	values.Set("state", r.FormValue("state"))

	// Preserve nonce for OIDC compliance
	if nonce := r.FormValue("nonce"); nonce != "" {
		values.Set("nonce", nonce)
	}

	// Preserve PKCE parameters
	if codeChallenge := r.FormValue("code_challenge"); codeChallenge != "" {
		values.Set("code_challenge", codeChallenge)
	}
	if codeChallengeMethod := r.FormValue("code_challenge_method"); codeChallengeMethod != "" {
		values.Set("code_challenge_method", codeChallengeMethod)
	}

	redirectURL := "/authorize?" + values.Encode()
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// validateCredentials checks if the provided username and password are valid against DB
func (h *LoginHandler) validateCredentials(ctx context.Context, username, password string) bool {
	// Get user from DB (only active users)
	user, err := h.queries.GetUserByUsername(ctx, username)
	if err != nil {
		// User not found or DB error - return false without revealing which
		return false
	}

	// Check if password hash exists
	if user.PasswordHash == nil {
		return false
	}

	// Verify password with bcrypt
	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
		return false
	}

	// Update last login time
	_ = h.queries.UpdateUserLastLogin(ctx, user.ID)

	return true
}
