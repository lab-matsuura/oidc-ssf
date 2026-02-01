package handler

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"

	"github.com/lab-matsuura/oidc-ssf/idp/internal/provider"
)

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func NewJWKSHandler(p *provider.OIDCProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pubKey := p.GetPublicKey()
		if pubKey == nil {
			http.Error(w, "Unable to get public key", http.StatusInternalServerError)
			return
		}

		jwks := JWKS{
			Keys: []JWK{
				{
					Kty: "RSA",
					Use: "sig",
					Alg: "RS256",
					Kid: p.KeyID,
					N:   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
					E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}
}
