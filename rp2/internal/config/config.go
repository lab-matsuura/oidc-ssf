package config

import (
	"net/url"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	IssuerURL     string
	Scopes        []string
	SecureCookies bool // Set to true for HTTPS (production)

	// SSF Poll configuration
	SSFPollInterval time.Duration
	SSFPollMode     string // "short" or "long" (default: "short")
}

func NewConfig() *Config {
	pollInterval := getEnvInt("RP2_SSF_POLL_INTERVAL", 10)
	pollMode := getEnvOrDefault("RP2_SSF_POLL_MODE", "short") // "short" or "long"

	return &Config{
		ClientID:        getEnvOrDefault("RP2_OIDC_CLIENT_ID", "test-client-2"),
		ClientSecret:    getEnvOrDefault("RP2_OIDC_CLIENT_SECRET", "test-secret-2"),
		RedirectURI:     getEnvOrDefault("RP2_OIDC_REDIRECT_URI", "http://localhost:8082/callback"),
		IssuerURL:       getEnvOrDefault("OIDC_ISSUER_URL", "http://localhost:8080"),
		Scopes:          []string{"openid", "profile", "email"},
		SecureCookies:   getEnvBool("SECURE_COOKIES", false),
		SSFPollInterval: time.Duration(pollInterval) * time.Second,
		SSFPollMode:     pollMode,
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

func getEnvInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	if i, err := strconv.Atoi(value); err == nil {
		return i
	}
	return defaultValue
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

// GetSSFPollURL returns the SSF poll endpoint URL
func (c *Config) GetSSFPollURL() string {
	return c.IssuerURL + "/ssf/poll"
}
