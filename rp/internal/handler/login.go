package handler

import (
	"log"
	"net/http"

	"github.com/lab-matsuura/oidc-ssf/rp/internal/config"
	"github.com/lab-matsuura/oidc-ssf/rp/internal/service"
)

func NewLoginHandler(cfg *config.Config, sessionService *service.SessionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate secure state for CSRF protection
		state := sessionService.CreateState()

		// Generate PKCE challenge
		pkceService := service.NewPKCEService()
		pkceChallenge, err := pkceService.GenerateChallenge()
		if err != nil {
			log.Printf("Failed to generate PKCE challenge: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Build authorization URL with PKCE
		authURL := cfg.GetAuthorizeURLWithPKCE(state, pkceChallenge.CodeChallenge, pkceChallenge.CodeChallengeMethod)

		// Store state and code_verifier in session/cookies for later validation
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    state,
			Path:     "/",
			MaxAge:   600, // 10 minutes
			HttpOnly: true,
			Secure:   cfg.SecureCookies,
			SameSite: http.SameSiteLaxMode,
		})

		http.SetCookie(w, &http.Cookie{
			Name:     "code_verifier",
			Value:    pkceChallenge.CodeVerifier,
			Path:     "/",
			MaxAge:   600, // 10 minutes
			HttpOnly: true,
			Secure:   cfg.SecureCookies,
			SameSite: http.SameSiteLaxMode,
		})

		// Redirect to OIDC Provider
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}
