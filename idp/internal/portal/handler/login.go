package handler

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/handler"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/portal"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres/sqlc"
	"github.com/lab-matsuura/oidc-ssf/pkg/ssf"
	"golang.org/x/crypto/bcrypt"
)

// LoginHandler handles unified login for both OIDC and portal
type LoginHandler struct {
	queries       *sqlc.Queries
	templates     *template.Template
	ssfAPIHandler *handler.SSFAPIHandler
	middleware    *portal.Middleware
}

// NewLoginHandler creates a new login handler
func NewLoginHandler(queries *sqlc.Queries, templates *template.Template, middleware *portal.Middleware) *LoginHandler {
	return &LoginHandler{
		queries:    queries,
		templates:  templates,
		middleware: middleware,
	}
}

// SetSSFAPIHandler sets the SSF API handler for Single Logout (SLO)
func (h *LoginHandler) SetSSFAPIHandler(ssfAPIHandler *handler.SSFAPIHandler) {
	h.ssfAPIHandler = ssfAPIHandler
}

// ShowLogin displays the login form or redirects if already logged in
func (h *LoginHandler) ShowLogin(w http.ResponseWriter, r *http.Request) {
	// Check if already logged in
	if user := h.getUserFromSession(r); user != nil && user.AccountStatus == "active" {
		// User is already authenticated
		if h.hasOIDCParams(r) {
			// OIDC flow - redirect to authorize with username
			h.redirectToAuthorize(w, r, user.Username)
			return
		}
		// Portal access - redirect to portal
		redirect := r.URL.Query().Get("redirect")
		if redirect == "" {
			redirect = "/portal"
		}
		http.Redirect(w, r, redirect, http.StatusSeeOther)
		return
	}

	// Show login form
	h.renderLoginForm(w, r, "")
}

// ProcessLogin handles the login form submission
func (h *LoginHandler) ProcessLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderLoginForm(w, r, "Invalid form data")
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Validate credentials
	user, err := h.queries.GetUserByUsername(r.Context(), username)
	if err != nil {
		h.renderLoginForm(w, r, "Invalid username or password")
		return
	}

	// Check if user is active
	if user.AccountStatus != "active" {
		h.renderLoginForm(w, r, "Account is disabled")
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
		h.renderLoginForm(w, r, "Invalid username or password")
		return
	}

	// Create server-side session
	userID := uuid.UUID(user.ID.Bytes)
	if err := h.middleware.CreateSession(r.Context(), w, r, userID); err != nil {
		log.Printf("Failed to create session: %v", err)
		h.renderLoginForm(w, r, "Failed to create session")
		return
	}

	// Update last login
	_ = h.queries.UpdateUserLastLogin(r.Context(), user.ID)

	// Redirect based on context
	if h.hasOIDCParams(r) {
		// OIDC flow - redirect to authorize
		h.redirectToAuthorize(w, r, username)
		return
	}

	// Portal access - redirect to portal or specified URL
	redirect := r.FormValue("redirect")
	if redirect == "" {
		redirect = "/portal"
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

// Logout handles logout with Single Logout (SLO)
func (h *LoginHandler) Logout(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromSession(r)

	if user != nil {
		userID := uuid.UUID(user.ID.Bytes)

		// Revoke ALL sessions for this user (server-side SLO)
		if err := h.middleware.RevokeUserSessions(r.Context(), userID); err != nil {
			log.Printf("Failed to revoke sessions: %v", err)
		}

		// Emit SSF session-revoked event for SLO
		if h.ssfAPIHandler != nil {
			userUUID := userID.String()
			eventData := map[string]any{
				"reason_admin": map[string]any{
					"en": "User initiated Single Logout from IdP",
				},
			}
			// Emit SSF event asynchronously (don't block logout)
			go func() {
				ctx := context.Background()
				result, err := h.ssfAPIHandler.EmitEventForSubject(ctx, ssf.EventTypeSessionRevoked, userUUID, eventData)
				if err != nil {
					log.Printf("SSF SLO: Failed to emit session-revoked event for user %s: %v", userUUID, err)
				} else {
					log.Printf("SSF SLO: Emitted session-revoked event for user %s (streams: %d, success: %d)",
						userUUID, result.StreamCount, result.SuccessCount)
				}
			}()
		}
	}

	// Clear session cookie
	portal.ClearSessionCookie(w)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// getUserFromSession retrieves user from server-side session
func (h *LoginHandler) getUserFromSession(r *http.Request) *sqlc.User {
	cookie, err := r.Cookie(portal.SessionCookie)
	if err != nil {
		return nil
	}

	sessionID, err := uuid.Parse(cookie.Value)
	if err != nil {
		return nil
	}

	pgSessionID := pgtype.UUID{Bytes: sessionID, Valid: true}

	// Look up session from DB (checks revoked_at and expires_at)
	session, err := h.queries.GetIDPSession(r.Context(), pgSessionID)
	if err != nil {
		return nil
	}

	// Get user from session
	user, err := h.queries.GetUserByIDIncludeInactive(r.Context(), session.UserID)
	if err != nil {
		return nil
	}

	return &user
}

// hasOIDCParams checks if the request has OIDC parameters
func (h *LoginHandler) hasOIDCParams(r *http.Request) bool {
	// Check query params (GET) or form values (POST)
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		clientID = r.FormValue("client_id")
	}
	return clientID != ""
}

// redirectToAuthorize redirects to the authorize endpoint with OIDC params
func (h *LoginHandler) redirectToAuthorize(w http.ResponseWriter, r *http.Request, username string) {
	values := url.Values{}
	values.Set("username", username)

	// Copy OIDC parameters from query or form
	params := []string{"redirect_uri", "client_id", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method"}
	for _, param := range params {
		val := r.URL.Query().Get(param)
		if val == "" {
			val = r.FormValue(param)
		}
		if val != "" {
			values.Set(param, val)
		}
	}

	redirectURL := "/authorize?" + values.Encode()
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// renderLoginForm renders the login form template
func (h *LoginHandler) renderLoginForm(w http.ResponseWriter, r *http.Request, errorMsg string) {
	// Collect data for template
	data := map[string]string{
		"Error":               errorMsg,
		"Redirect":            r.URL.Query().Get("redirect"),
		"RedirectURI":         h.getParam(r, "redirect_uri"),
		"ClientID":            h.getParam(r, "client_id"),
		"ResponseType":        h.getParam(r, "response_type"),
		"Scope":               h.getParam(r, "scope"),
		"State":               h.getParam(r, "state"),
		"Nonce":               h.getParam(r, "nonce"),
		"CodeChallenge":       h.getParam(r, "code_challenge"),
		"CodeChallengeMethod": h.getParam(r, "code_challenge_method"),
	}

	w.Header().Set("Content-Type", "text/html")
	if err := h.templates.ExecuteTemplate(w, "portal_login.html", data); err != nil {
		http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
	}
}

// getParam gets a parameter from query string or form values
func (h *LoginHandler) getParam(r *http.Request, name string) string {
	val := r.URL.Query().Get(name)
	if val == "" {
		val = r.FormValue(name)
	}
	return val
}
