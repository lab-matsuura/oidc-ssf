package handler

import (
	"html/template"
	"net/http"

	"github.com/lab-matsuura/oidc-ssf/idp/internal/portal"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres/sqlc"
)

// DashboardHandler handles the portal dashboard
type DashboardHandler struct {
	queries   *sqlc.Queries
	templates *template.Template
}

// NewDashboardHandler creates a new dashboard handler
func NewDashboardHandler(queries *sqlc.Queries, templates *template.Template) *DashboardHandler {
	return &DashboardHandler{
		queries:   queries,
		templates: templates,
	}
}

// Index displays the dashboard
func (h *DashboardHandler) Index(w http.ResponseWriter, r *http.Request) {
	user := portal.GetCurrentUser(r.Context())
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	isAdmin := portal.IsAdmin(r.Context())

	// Get display name
	displayName := user.Username
	if user.DisplayName != nil && *user.DisplayName != "" {
		displayName = *user.DisplayName
	}

	data := map[string]any{
		"Title":       "Dashboard",
		"User":        user,
		"DisplayName": displayName,
		"IsAdmin":     isAdmin,
	}

	// If admin, get statistics
	if isAdmin {
		userCount, _ := h.queries.CountUsers(r.Context())
		clientCount, _ := h.queries.CountClients(r.Context())
		streamCount, _ := h.queries.CountSSFStreams(r.Context())

		data["UserCount"] = userCount
		data["ClientCount"] = clientCount
		data["StreamCount"] = streamCount
	}

	if err := h.templates.ExecuteTemplate(w, "portal_dashboard.html", data); err != nil {
		http.Error(w, "Failed to render template: "+err.Error(), http.StatusInternalServerError)
	}
}
