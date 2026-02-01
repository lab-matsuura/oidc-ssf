package config

import (
	"net/url"
	"os"
)

type Config struct {
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	IssuerURL     string
	Scopes        []string
	SecureCookies bool // Set to true for HTTPS (production)
}

func NewConfig() *Config {
	return &Config{
		ClientID:      getEnvOrDefault("OIDC_CLIENT_ID", "test-client"),
		ClientSecret:  getEnvOrDefault("OIDC_CLIENT_SECRET", "test-secret"),
		RedirectURI:   getEnvOrDefault("OIDC_REDIRECT_URI", "http://localhost:8081/callback"),
		IssuerURL:     getEnvOrDefault("OIDC_ISSUER_URL", "http://localhost:8080"),
		Scopes:        []string{"openid", "profile", "email"},
		SecureCookies: getEnvBool("SECURE_COOKIES", false),
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value == "true" || value == "1" || value == "yes"
}

// GetAuthorizeURL builds the OIDC authorization URL
func (c *Config) GetAuthorizeURL(state string) string {
	params := url.Values{}
	params.Set("client_id", c.ClientID)
	params.Set("redirect_uri", c.RedirectURI)
	params.Set("response_type", "code")
	params.Set("scope", "openid profile email")
	params.Set("state", state)

	return c.IssuerURL + "/authorize?" + params.Encode()
}

// GetAuthorizeURLWithPKCE builds the OIDC authorization URL with PKCE parameters
func (c *Config) GetAuthorizeURLWithPKCE(state, codeChallenge, codeChallengeMethod string) string {
	params := url.Values{}
	params.Set("client_id", c.ClientID)
	params.Set("redirect_uri", c.RedirectURI)
	params.Set("response_type", "code")
	params.Set("scope", "openid profile email")
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", codeChallengeMethod)

	return c.IssuerURL + "/authorize?" + params.Encode()
}

// GetTokenURL returns the token endpoint URL
func (c *Config) GetTokenURL() string {
	return c.IssuerURL + "/token"
}

// GetUserInfoURL returns the userinfo endpoint URL
func (c *Config) GetUserInfoURL() string {
	return c.IssuerURL + "/userinfo"
}

// GetDiscoveryURL returns the OpenID Connect discovery URL
func (c *Config) GetDiscoveryURL() string {
	return c.IssuerURL + "/.well-known/openid-configuration"
}
