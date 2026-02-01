package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/lab-matsuura/oidc-ssf/rp/internal/config"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

type OIDCService struct {
	config *config.Config
	client *http.Client
}

func NewOIDCService(cfg *config.Config) *OIDCService {
	return &OIDCService{
		config: cfg,
		client: &http.Client{},
	}
}

// ExchangeCodeForTokens exchanges authorization code for tokens
func (o *OIDCService) ExchangeCodeForTokens(code string) (*TokenResponse, error) {
	return o.ExchangeCodeForTokensWithPKCE(code, "")
}

// ExchangeCodeForTokensWithPKCE exchanges authorization code for tokens with optional PKCE
func (o *OIDCService) ExchangeCodeForTokensWithPKCE(code, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", o.config.ClientID)
	data.Set("client_secret", o.config.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", o.config.RedirectURI)

	// Add PKCE code_verifier if provided
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequest("POST", o.config.GetTokenURL(), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// GetUserInfo retrieves user information using access token
func (o *OIDCService) GetUserInfo(accessToken string) (*UserInfo, error) {
	req, err := http.NewRequest("GET", o.config.GetUserInfoURL(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read userinfo response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var userInfo UserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	return &userInfo, nil
}

// ValidateIDToken performs basic validation of ID token
// In production, you should verify the signature, issuer, audience, expiration, etc.
func (o *OIDCService) ValidateIDToken(idToken string) error {
	if idToken == "" {
		return fmt.Errorf("ID token is empty")
	}

	// Basic validation - check if it has 3 parts (header.payload.signature)
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid ID token format")
	}

	// In a real implementation, you would:
	// 1. Verify the signature using the JWKS endpoint
	// 2. Validate the issuer
	// 3. Validate the audience
	// 4. Check expiration time
	// 5. Validate other claims as needed

	return nil
}

// ParseIDTokenClaims extracts claims from ID token (without signature verification)
// This is for display purposes only - do not use for security decisions
func (o *OIDCService) ParseIDTokenClaims(idToken string) (map[string]interface{}, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid ID token format")
	}

	// Decode the payload (middle part)
	payload := parts[1]

	// Add padding if needed for base64 decoding
	for len(payload)%4 != 0 {
		payload += "="
	}

	// Note: This is a simplified approach. In production, use a proper JWT library
	// that handles base64url encoding correctly
	decodedBytes := make([]byte, len(payload))
	n, err := base64urlDecode(payload, decodedBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ID token payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decodedBytes[:n], &claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	return claims, nil
}

// Simple base64url decoder (for demo purposes)
func base64urlDecode(src string, dst []byte) (int, error) {
	// Replace base64url characters with base64 characters
	src = strings.ReplaceAll(src, "-", "+")
	src = strings.ReplaceAll(src, "_", "/")

	// Add padding
	for len(src)%4 != 0 {
		src += "="
	}

	decoded, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return 0, err
	}

	copy(dst, decoded)
	return len(decoded), nil
}
