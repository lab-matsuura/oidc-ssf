package handler

import (
	"net/http"

	"github.com/lab-matsuura/oidc-ssf/idp/internal/provider"
)

func NewAuthorizeHandler(p *provider.OIDCProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Parse the authorization request (fosite handles PKCE parameters automatically)
		ar, err := p.OAuth2.NewAuthorizeRequest(ctx, r)
		if err != nil {
			p.OAuth2.WriteAuthorizeError(ctx, w, ar, err)
			return
		}

		// Check if user is authenticated (login handler validates credentials)
		username := r.FormValue("username")
		if username == "" {
			// Redirect to login with the original request parameters
			loginURL := "/login?" + r.URL.RawQuery
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		// Get nonce from the authorization request for OIDC compliance
		nonce := r.FormValue("nonce")
		if nonce == "" {
			// Also check the parsed form in case it was in POST body
			nonce = ar.GetRequestForm().Get("nonce")
		}

		// Grant requested scopes
		requestedScopes := ar.GetRequestedScopes()
		grantedScopes := []string{}
		for _, scope := range requestedScopes {
			ar.GrantScope(scope)
			grantedScopes = append(grantedScopes, scope)
		}

		// Create user session with client ID for audience binding
		clientID := ar.GetClient().GetID()
		session := p.CreateSession(ctx, username, clientID, nonce, grantedScopes)
		ar.SetSession(session)

		response, err := p.OAuth2.NewAuthorizeResponse(ctx, ar, session)
		if err != nil {
			p.OAuth2.WriteAuthorizeError(ctx, w, ar, err)
			return
		}

		// Write the authorization response (fosite handles PKCE automatically)
		p.OAuth2.WriteAuthorizeResponse(ctx, w, ar, response)
	}
}
