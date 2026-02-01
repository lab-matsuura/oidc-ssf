package handler

import (
	"net/http"

	"github.com/lab-matsuura/oidc-ssf/rp/internal/service"
)

func NewLogoutHandler(sessionService *service.SessionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Get current session
		session, isLoggedIn := sessionService.GetSessionFromRequest(r)

		if isLoggedIn && session != nil {
			// Delete the session from service
			_ = sessionService.DeleteSession(ctx, session.ID)
		}

		// Clear session cookie
		sessionService.ClearSessionCookie(w)

		// Redirect to home page
		http.Redirect(w, r, "/", http.StatusFound)
	}
}
