package handler

import (
	"encoding/json"
	"net/http"

	"github.com/lab-matsuura/oidc-ssf/idp/internal/provider"
)

type OpenIDConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	// SSF Transmitter Metadata
	SSFConfigurationEndpoint string `json:"ssf_configuration_endpoint,omitempty"`
}

func NewDiscoveryHandler(p *provider.OIDCProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issuer := p.IssuerURL

		config := OpenIDConfiguration{
			Issuer:                            issuer,
			AuthorizationEndpoint:             issuer + "/authorize",
			TokenEndpoint:                     issuer + "/token",
			UserinfoEndpoint:                  issuer + "/userinfo",
			JwksURI:                           issuer + "/jwks",
			ResponseTypesSupported:            []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"},
			SubjectTypesSupported:             []string{"public"},
			IDTokenSigningAlgValuesSupported:  []string{"RS256"},
			ScopesSupported:                   []string{"openid", "profile", "email"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
			ClaimsSupported:                   []string{"sub", "name", "email", "aud", "exp", "iat", "iss"},
			GrantTypesSupported:               []string{"authorization_code", "refresh_token", "client_credentials"},
			CodeChallengeMethodsSupported:     []string{"S256"},
			SSFConfigurationEndpoint:          issuer + "/.well-known/ssf-configuration",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(config)
	}
}
