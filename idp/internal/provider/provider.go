package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"

	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres/sqlc"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/user"
	"github.com/lab-matsuura/oidc-ssf/pkg/ssf"
)

type OIDCProvider struct {
	OAuth2      fosite.OAuth2Provider
	Storage     *postgres.PostgresStore
	Signer      jwt.Signer
	PrivateKey  *rsa.PrivateKey
	KeyID       string // RFC 7638 JWK Thumbprint
	UserService *user.Service
	Queries     *sqlc.Queries
	IssuerURL   string
}

// Config holds provider configuration
type Config struct {
	PostgresConfig         postgres.Config
	IssuerURL              string
	PrivateKeyPath         string // Path to RSA private key PEM file (optional, generates new key if not set)
	GlobalSecret           string // Secret for HMAC operations (optional, generates random if not set)
	SeedTestClients        bool   // Seed test client on startup (default: false)
	SeedConformanceClients bool   // Seed OIDC conformance suite clients on startup (default: false)
}

// loadOrGenerateKey loads an RSA private key from file, or generates a new one
func loadOrGenerateKey(keyPath string) (*rsa.PrivateKey, error) {
	// If no path specified, generate a new key (development mode)
	if keyPath == "" {
		log.Println("WARNING: No RSA_PRIVATE_KEY_PATH specified, generating ephemeral key (not for production)")
		return rsa.GenerateKey(rand.Reader, 2048)
	}

	// Try to load existing key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Key file doesn't exist, generate and save new key
			log.Printf("Key file not found at %s, generating new key...", keyPath)
			return generateAndSaveKey(keyPath)
		}
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Parse PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from key file")
	}

	// Parse private key (try PKCS#8 first, then PKCS#1)
	var privateKey *rsa.PrivateKey
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
	} else if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		privateKey = key
	} else {
		return nil, fmt.Errorf("failed to parse private key: not PKCS#8 or PKCS#1 format")
	}

	log.Printf("Loaded RSA private key from %s", keyPath)
	return privateKey, nil
}

// generateAndSaveKey generates a new RSA key and saves it to file
func generateAndSaveKey(keyPath string) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode to PKCS#8 format
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Create PEM block
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	// Write to file with restrictive permissions (owner read/write only)
	file, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create key file: %w", err)
	}
	defer func() { _ = file.Close() }()

	if err := pem.Encode(file, pemBlock); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}

	log.Printf("Generated and saved new RSA private key to %s", keyPath)
	return privateKey, nil
}

// loadOrGenerateGlobalSecret loads a global secret from config, or generates a random one
func loadOrGenerateGlobalSecret(secret string) ([]byte, error) {
	if secret != "" {
		// Validate minimum length (32 bytes recommended for HMAC-SHA256)
		if len(secret) < 32 {
			return nil, fmt.Errorf("FOSITE_GLOBAL_SECRET must be at least 32 characters")
		}
		return []byte(secret), nil
	}

	// Generate random secret for development
	log.Println("WARNING: No FOSITE_GLOBAL_SECRET specified, generating ephemeral secret (not for production)")
	randomSecret := make([]byte, 32)
	if _, err := rand.Read(randomSecret); err != nil {
		return nil, fmt.Errorf("failed to generate random secret: %w", err)
	}
	return randomSecret, nil
}

func NewOIDCProvider(ctx context.Context, cfg Config) (*OIDCProvider, error) {
	// Set default issuer URL if not provided
	issuerURL := cfg.IssuerURL
	if issuerURL == "" {
		issuerURL = "http://localhost:8080"
	}

	// Load or generate RSA key for signing
	privateKey, err := loadOrGenerateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load/generate RSA key: %w", err)
	}

	// Compute Key ID (RFC 7638 JWK Thumbprint)
	keyID, err := ssf.ComputeJWKThumbprint(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute key ID: %w", err)
	}
	log.Printf("Computed Key ID (RFC 7638 thumbprint): %s", keyID)

	// Load or generate global secret for HMAC operations
	globalSecret, err := loadOrGenerateGlobalSecret(cfg.GlobalSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to load/generate global secret: %w", err)
	}

	// Connect to PostgreSQL
	pool, err := postgres.Connect(ctx, cfg.PostgresConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}

	// Create PostgreSQL store
	pgStore := postgres.NewPostgresStore(pool)

	// Seed test client (optional, for development)
	if cfg.SeedTestClients {
		if err := pgStore.SeedTestClient(ctx); err != nil {
			return nil, fmt.Errorf("failed to seed test client: %w", err)
		}
		log.Println("Seeded test client (test-client)")
	}

	// Seed conformance suite clients (optional, for OIDC certification testing)
	if cfg.SeedConformanceClients {
		if err := pgStore.SeedConformanceClients(ctx); err != nil {
			return nil, fmt.Errorf("failed to seed conformance clients: %w", err)
		}
		log.Println("Seeded OIDC conformance suite clients")
	}

	// Initialize queries and user service
	queries := sqlc.New(pool)
	userSvc := user.NewService(queries)

	// Configure fosite
	fositeConfig := &fosite.Config{
		IDTokenIssuer:              issuerURL,
		AccessTokenLifespan:        time.Hour,
		RefreshTokenLifespan:       time.Hour * 24 * 30,
		AuthorizeCodeLifespan:      time.Minute * 10,
		SendDebugMessagesToClients: true,
		EnforcePKCE:                false, // Allow optional PKCE
		GlobalSecret:               globalSecret,
	}

	// Create OAuth2 provider with OpenID Connect and PKCE support
	oauth2Provider := compose.ComposeAllEnabled(
		fositeConfig,
		pgStore,
		privateKey,
	)

	return &OIDCProvider{
		OAuth2:      oauth2Provider,
		Storage:     pgStore,
		Signer:      nil, // We'll handle signing through fosite directly
		PrivateKey:  privateKey,
		KeyID:       keyID,
		UserService: userSvc,
		Queries:     queries,
		IssuerURL:   issuerURL,
	}, nil
}

// GetPublicKey returns the public key for JWKS endpoint
func (p *OIDCProvider) GetPublicKey() *rsa.PublicKey {
	if p.PrivateKey != nil {
		return &p.PrivateKey.PublicKey
	}
	return nil
}

// AuthorizeRequestFromHTTP creates an authorize request from HTTP request
func (p *OIDCProvider) AuthorizeRequestFromHTTP(r *http.Request) (fosite.AuthorizeRequester, error) {
	ctx := r.Context()
	return p.OAuth2.NewAuthorizeRequest(ctx, r)
}

// CreateAuthorizeResponse creates an authorize response
func (p *OIDCProvider) CreateAuthorizeResponse(r *http.Request, ar fosite.AuthorizeRequester, session fosite.Session) (fosite.AuthorizeResponder, error) {
	ctx := r.Context()
	resp, err := p.OAuth2.NewAuthorizeResponse(ctx, ar, session)
	return resp, err
}

// CreateSession creates a new session for a user
// nonce: the nonce from the authorization request (required for OIDC compliance)
// scopes: the granted scopes to determine which claims to include
func (p *OIDCProvider) CreateSession(ctx context.Context, username string, clientID string, nonce string, scopes []string) *openid.DefaultSession {
	// Build extra claims based on granted scopes
	extra := make(map[string]interface{})

	// Only include profile claims if 'profile' scope is granted
	hasProfileScope := false
	hasEmailScope := false
	for _, scope := range scopes {
		if scope == "profile" {
			hasProfileScope = true
		}
		if scope == "email" {
			hasEmailScope = true
		}
	}

	// Get user from DB for claims
	user, err := p.Queries.GetUserByUsername(ctx, username)
	if err != nil {
		// User not found - cannot create session without valid user
		log.Printf("CreateSession: user not found: %s", username)
		return nil
	}

	// Convert pgtype.UUID to string for sub claim (RFC 9493 iss_sub format)
	userID := uuid.UUID(user.ID.Bytes).String()

	if hasProfileScope {
		if user.DisplayName != nil && *user.DisplayName != "" {
			extra["name"] = *user.DisplayName
		} else {
			extra["name"] = username
		}
		// Include role in profile claims for SSF token-claims-change propagation
		extra["role"] = user.Role
		// Include preferred_username for RP to display
		extra["preferred_username"] = username
	}
	if hasEmailScope {
		extra["email"] = user.Email
		extra["email_verified"] = user.EmailVerified
	}

	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:    p.IssuerURL,
			Subject:   userID, // Use UUID as sub (RFC 9493 compliant)
			Audience:  []string{clientID},
			Nonce:     nonce, // Set nonce from authorization request
			ExpiresAt: time.Now().Add(time.Hour),
			IssuedAt:  time.Now(),
			Extra:     extra,
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:   time.Now().Add(time.Hour),
			fosite.RefreshToken:  time.Now().Add(time.Hour * 24 * 30),
			fosite.AuthorizeCode: time.Now().Add(time.Minute * 10),
		},
		Username: username,
		Subject:  userID, // Use UUID as sub
	}
}
