package middleware

import (
	"net/http"
	"strings"

	"github.com/lab-matsuura/oidc-ssf/idp/internal/user"
)

// SetupRequired is a middleware that redirects to /setup if no owner exists
type SetupRequired struct {
	userService *user.Service
}

// NewSetupRequired creates a new setup required middleware
func NewSetupRequired(userService *user.Service) *SetupRequired {
	return &SetupRequired{
		userService: userService,
	}
}

// Middleware returns the HTTP middleware function
func (m *SetupRequired) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip middleware for setup page, static resources, and API endpoints
		path := r.URL.Path
		if path == "/setup" ||
			strings.HasPrefix(path, "/static/") ||
			strings.HasPrefix(path, "/.well-known/") ||
			path == "/token" ||
			path == "/authorize" ||
			path == "/userinfo" ||
			path == "/jwks" ||
			strings.HasPrefix(path, "/ssf/") {
			next.ServeHTTP(w, r)
			return
		}

		// Check if owner exists
		hasOwner, err := m.userService.HasOwner(r.Context())
		if err != nil {
			// On error, allow the request to proceed (fail open for OIDC endpoints)
			next.ServeHTTP(w, r)
			return
		}

		// If no owner, redirect to setup
		if !hasOwner {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}
