package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/lab-matsuura/oidc-ssf/idp/internal/provider"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

func NewUserInfoHandler(p *provider.OIDCProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		// Validate the access token and get the access request
		_, ar, err := p.OAuth2.IntrospectToken(ctx, token, fosite.AccessToken, &openid.DefaultSession{}, "openid")
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract user info from the session
		session := ar.GetSession()
		userInfo := map[string]interface{}{
			"sub": session.GetSubject(),
		}

		// Try to get additional claims from the OpenID session
		if oidcSession, ok := session.(*openid.DefaultSession); ok && oidcSession.Claims != nil {
			// Add name, email, and role from extra claims if available
			if extra := oidcSession.Claims.Extra; extra != nil {
				if name, ok := extra["name"]; ok {
					userInfo["name"] = name
				}
				if email, ok := extra["email"]; ok {
					userInfo["email"] = email
				}
				if role, ok := extra["role"]; ok {
					userInfo["role"] = role
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(userInfo)
	}
}
