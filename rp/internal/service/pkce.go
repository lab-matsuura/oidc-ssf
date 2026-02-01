package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	// Code verifier length (RFC 7636 recommends 43-128 characters)
	CodeVerifierLength = 64

	// Allowed characters for code verifier
	codeVerifierChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

// PKCEChallenge represents a PKCE challenge pair
type PKCEChallenge struct {
	CodeVerifier        string `json:"code_verifier"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// PKCEService handles PKCE code generation and validation
type PKCEService struct{}

// NewPKCEService creates a new PKCE service
func NewPKCEService() *PKCEService {
	return &PKCEService{}
}

// GenerateChallenge generates a new PKCE challenge pair
func (p *PKCEService) GenerateChallenge() (*PKCEChallenge, error) {
	// Generate cryptographically secure code verifier
	codeVerifier, err := p.generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}

	// Calculate code challenge using S256 method
	codeChallenge := p.calculateCodeChallenge(codeVerifier)

	return &PKCEChallenge{
		CodeVerifier:        codeVerifier,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
	}, nil
}

// ValidateCodeVerifier validates a code verifier against a code challenge
func (p *PKCEService) ValidateCodeVerifier(codeVerifier, expectedCodeChallenge string) bool {
	if codeVerifier == "" || expectedCodeChallenge == "" {
		return false
	}

	// Validate code verifier format
	if !p.isValidCodeVerifier(codeVerifier) {
		return false
	}

	// Calculate code challenge from verifier
	calculatedChallenge := p.calculateCodeChallenge(codeVerifier)

	// Compare with expected challenge
	return calculatedChallenge == expectedCodeChallenge
}

// generateCodeVerifier generates a cryptographically secure code verifier
func (p *PKCEService) generateCodeVerifier() (string, error) {
	// Generate random bytes
	bytes := make([]byte, CodeVerifierLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Convert to allowed characters
	var result strings.Builder
	result.Grow(CodeVerifierLength)

	for _, b := range bytes {
		// Use modulo to map byte to allowed character
		charIndex := int(b) % len(codeVerifierChars)
		result.WriteByte(codeVerifierChars[charIndex])
	}

	return result.String(), nil
}

// calculateCodeChallenge calculates code challenge using S256 method
func (p *PKCEService) calculateCodeChallenge(codeVerifier string) string {
	// Calculate SHA256 hash
	hash := sha256.Sum256([]byte(codeVerifier))

	// Encode using base64url (without padding)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// isValidCodeVerifier validates code verifier format according to RFC 7636
func (p *PKCEService) isValidCodeVerifier(codeVerifier string) bool {
	// Check length (43-128 characters)
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return false
	}

	// Check allowed characters only
	for _, char := range codeVerifier {
		if !strings.ContainsRune(codeVerifierChars, char) {
			return false
		}
	}

	return true
}

// IsValidCodeChallenge validates code challenge format
func (p *PKCEService) IsValidCodeChallenge(codeChallenge string) bool {
	if codeChallenge == "" {
		return false
	}

	// Try to decode as base64url
	_, err := base64.RawURLEncoding.DecodeString(codeChallenge)
	return err == nil
}

// IsValidCodeChallengeMethod validates code challenge method
func (p *PKCEService) IsValidCodeChallengeMethod(method string) bool {
	// RFC 7636 defines "plain" and "S256", but we only support S256
	return method == "S256"
}
