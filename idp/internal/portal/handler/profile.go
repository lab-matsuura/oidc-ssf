package handler

import (
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/portal"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres/sqlc"
)

const sessionsPerPage = 10

// SessionView formats session data for template display
type SessionView struct {
	ID        string
	UserAgent string
	IPAddress string
	CreatedAt string
	ExpiresAt string
	RevokedAt string
	IsCurrent bool
	IsActive  bool
}

// Pagination holds pagination info for templates
type Pagination struct {
	CurrentPage int
	TotalPages  int
	HasPrev     bool
	HasNext     bool
	PrevPage    int
	NextPage    int
}

// ProfileHandler handles user profile
type ProfileHandler struct {
	queries   *sqlc.Queries
	templates *template.Template
}

// NewProfileHandler creates a new profile handler
func NewProfileHandler(queries *sqlc.Queries, templates *template.Template) *ProfileHandler {
	return &ProfileHandler{
		queries:   queries,
		templates: templates,
	}
}

// Show displays the user profile
func (h *ProfileHandler) Show(w http.ResponseWriter, r *http.Request) {
	user := portal.GetCurrentUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Get display name
	displayName := user.Username
	if user.DisplayName != nil && *user.DisplayName != "" {
		displayName = *user.DisplayName
	}

	// Format timestamps
	lastLogin := "Never"
	if user.LastLoginAt.Valid {
		lastLogin = user.LastLoginAt.Time.Format("2006-01-02 15:04:05")
	}

	createdAt := ""
	if user.CreatedAt.Valid {
		createdAt = user.CreatedAt.Time.Format("2006-01-02 15:04:05")
	}

	// Get page number from query param
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	// Get total session count for pagination
	totalCount, _ := h.queries.CountUserSessions(r.Context(), user.ID)
	totalPages := int((totalCount + sessionsPerPage - 1) / sessionsPerPage)
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	// Fetch login history with pagination
	offset := (page - 1) * sessionsPerPage
	sessions, _ := h.queries.ListUserSessions(r.Context(), sqlc.ListUserSessionsParams{
		UserID: user.ID,
		Limit:  sessionsPerPage,
		Offset: int32(offset),
	})

	// Get current session ID from cookie
	currentSessionID := ""
	if cookie, err := r.Cookie(portal.SessionCookie); err == nil {
		currentSessionID = cookie.Value
	}

	// Convert to view models
	var sessionViews []SessionView
	for _, s := range sessions {
		sessionID := uuid.UUID(s.ID.Bytes).String()
		view := SessionView{
			ID:        sessionID[:8] + "...",
			CreatedAt: s.CreatedAt.Time.Format("2006-01-02 15:04:05"),
			ExpiresAt: s.ExpiresAt.Time.Format("2006-01-02 15:04:05"),
			IsCurrent: sessionID == currentSessionID,
			IsActive:  !s.RevokedAt.Valid && s.ExpiresAt.Time.After(time.Now()),
		}
		if s.UserAgent != nil {
			view.UserAgent = *s.UserAgent
		}
		if s.IpAddress != nil {
			view.IPAddress = *s.IpAddress
		}
		if s.RevokedAt.Valid {
			view.RevokedAt = s.RevokedAt.Time.Format("2006-01-02 15:04:05")
		}
		sessionViews = append(sessionViews, view)
	}

	// Build pagination info
	pagination := Pagination{
		CurrentPage: page,
		TotalPages:  totalPages,
		HasPrev:     page > 1,
		HasNext:     page < totalPages,
		PrevPage:    page - 1,
		NextPage:    page + 1,
	}

	data := map[string]any{
		"Title":       "My Profile",
		"User":        user,
		"DisplayName": displayName,
		"LastLogin":   lastLogin,
		"CreatedAt":   createdAt,
		"IsAdmin":     portal.IsAdmin(r.Context()),
		"Success":     r.URL.Query().Get("success"),
		"Error":       r.URL.Query().Get("error"),
		"Sessions":    sessionViews,
		"Pagination":  pagination,
	}

	if err := h.templates.ExecuteTemplate(w, "portal_profile.html", data); err != nil {
		http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
	}
}

// UpdateDisplayName handles display name update
func (h *ProfileHandler) UpdateDisplayName(w http.ResponseWriter, r *http.Request) {
	user := portal.GetCurrentUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/portal/profile?error=Invalid+form+data", http.StatusSeeOther)
		return
	}

	displayName := r.FormValue("display_name")

	var displayNamePtr *string
	if displayName != "" {
		displayNamePtr = &displayName
	}

	if err := h.queries.UpdateUserDisplayName(r.Context(), sqlc.UpdateUserDisplayNameParams{
		ID:          user.ID,
		DisplayName: displayNamePtr,
	}); err != nil {
		http.Redirect(w, r, "/portal/profile?error=Failed+to+update+display+name", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/portal/profile?success=Display+name+updated", http.StatusSeeOther)
}
