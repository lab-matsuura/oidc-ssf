package handler

import (
	"net/http"

	"github.com/lab-matsuura/oidc-ssf/idp/internal/provider"
	"github.com/ory/fosite/handler/openid"
)

func NewTokenHandler(p *provider.OIDCProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Create the token request (fosite handles PKCE verification automatically)
		accessRequest, err := p.OAuth2.NewAccessRequest(ctx, r, &openid.DefaultSession{})
		if err != nil {
			p.OAuth2.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		// Create the token response
		response, err := p.OAuth2.NewAccessResponse(ctx, accessRequest)
		if err != nil {
			p.OAuth2.WriteAccessError(ctx, w, accessRequest, err)
			return
		}

		// Write the token response
		p.OAuth2.WriteAccessResponse(ctx, w, accessRequest, response)
	}
}
