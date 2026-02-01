package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"

	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres/sqlc"
)

// PostgresStore implements fosite storage interfaces using PostgreSQL
type PostgresStore struct {
	db      *pgxpool.Pool
	queries *sqlc.Queries
}

// NewPostgresStore creates a new PostgreSQL storage backend
func NewPostgresStore(db *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{
		db:      db,
		queries: sqlc.New(db),
	}
}

// GetDB returns the underlying database pool
func (s *PostgresStore) GetDB() *pgxpool.Pool {
	return s.db
}

// =============================================================================
// Client Storage
// =============================================================================

// GetClient implements fosite.Storage
func (s *PostgresStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	client, err := s.queries.GetClient(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	return &fosite.DefaultClient{
		ID:            client.ID,
		Secret:        client.Secret,
		RedirectURIs:  unmarshalStringArray(client.RedirectUris),
		GrantTypes:    unmarshalStringArray(client.GrantTypes),
		ResponseTypes: unmarshalStringArray(client.ResponseTypes),
		Scopes:        unmarshalStringArray(client.Scopes),
		Public:        client.Public,
	}, nil
}

// CreateClient creates a new client (not part of fosite interface, but useful for setup)
func (s *PostgresStore) CreateClient(ctx context.Context, client *fosite.DefaultClient) error {
	redirectURIs, err := marshalJSON(client.RedirectURIs)
	if err != nil {
		return fmt.Errorf("failed to marshal redirect URIs: %w", err)
	}

	grantTypes, err := marshalJSON(client.GrantTypes)
	if err != nil {
		return fmt.Errorf("failed to marshal grant types: %w", err)
	}

	responseTypes, err := marshalJSON(client.ResponseTypes)
	if err != nil {
		return fmt.Errorf("failed to marshal response types: %w", err)
	}

	scopes, err := marshalJSON(client.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal scopes: %w", err)
	}

	return s.queries.CreateClient(ctx, sqlc.CreateClientParams{
		ID:            client.ID,
		Secret:        client.Secret,
		RedirectUris:  redirectURIs,
		GrantTypes:    grantTypes,
		ResponseTypes: responseTypes,
		Scopes:        scopes,
		Public:        client.Public,
	})
}

// =============================================================================
// Authorization Code Storage
// =============================================================================

// CreateAuthorizeCodeSession implements fosite.AuthorizeCodeStorage
func (s *PostgresStore) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	data, err := SerializeRequest(req)
	if err != nil {
		return fmt.Errorf("failed to serialize request: %w", err)
	}

	expiresAt := req.GetSession().GetExpiresAt(fosite.AuthorizeCode)

	return s.queries.CreateAuthorizeCode(ctx, sqlc.CreateAuthorizeCodeParams{
		Code:        code,
		Active:      true,
		RequestData: data,
		ExpiresAt:   pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
}

// GetAuthorizeCodeSession implements fosite.AuthorizeCodeStorage
func (s *PostgresStore) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	row, err := s.queries.GetAuthorizeCode(ctx, code)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get authorize code: %w", err)
	}

	if !row.Active {
		return nil, fosite.ErrInvalidatedAuthorizeCode
	}

	// Extract client ID and get client
	clientID, err := extractClientIDFromSerialized(row.RequestData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract client ID: %w", err)
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	return DeserializeRequest(row.RequestData, client)
}

// InvalidateAuthorizeCodeSession implements fosite.AuthorizeCodeStorage
func (s *PostgresStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return s.queries.InvalidateAuthorizeCode(ctx, code)
}

// =============================================================================
// Access Token Storage
// =============================================================================

// CreateAccessTokenSession implements fosite.AccessTokenStorage
func (s *PostgresStore) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	data, err := SerializeRequest(req)
	if err != nil {
		return fmt.Errorf("failed to serialize request: %w", err)
	}

	expiresAt := req.GetSession().GetExpiresAt(fosite.AccessToken)

	return s.queries.CreateAccessToken(ctx, sqlc.CreateAccessTokenParams{
		Signature:   signature,
		RequestData: data,
		RequestID:   req.GetID(),
		ExpiresAt:   pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
}

// GetAccessTokenSession implements fosite.AccessTokenStorage
func (s *PostgresStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	row, err := s.queries.GetAccessToken(ctx, signature)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	clientID, err := extractClientIDFromSerialized(row.RequestData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract client ID: %w", err)
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	return DeserializeRequest(row.RequestData, client)
}

// DeleteAccessTokenSession implements fosite.AccessTokenStorage
func (s *PostgresStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.queries.DeleteAccessToken(ctx, signature)
}

// RevokeAccessToken implements fosite.TokenRevocationStorage
func (s *PostgresStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.queries.DeleteAccessTokenByRequestID(ctx, requestID)
}

// =============================================================================
// Refresh Token Storage
// =============================================================================

// CreateRefreshTokenSession implements fosite.RefreshTokenStorage
func (s *PostgresStore) CreateRefreshTokenSession(ctx context.Context, signature string, accessTokenSignature string, req fosite.Requester) error {
	data, err := SerializeRequest(req)
	if err != nil {
		return fmt.Errorf("failed to serialize request: %w", err)
	}

	expiresAt := req.GetSession().GetExpiresAt(fosite.RefreshToken)

	var accessTokenSig *string
	if accessTokenSignature != "" {
		accessTokenSig = &accessTokenSignature
	}

	return s.queries.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		Signature:            signature,
		Active:               true,
		RequestData:          data,
		RequestID:            req.GetID(),
		AccessTokenSignature: accessTokenSig,
		ExpiresAt:            pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
}

// GetRefreshTokenSession implements fosite.RefreshTokenStorage
func (s *PostgresStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	row, err := s.queries.GetRefreshToken(ctx, signature)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	if !row.Active {
		return nil, fosite.ErrInactiveToken
	}

	clientID, err := extractClientIDFromSerialized(row.RequestData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract client ID: %w", err)
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	return DeserializeRequest(row.RequestData, client)
}

// DeleteRefreshTokenSession implements fosite.RefreshTokenStorage
func (s *PostgresStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.queries.DeleteRefreshToken(ctx, signature)
}

// RevokeRefreshToken implements fosite.TokenRevocationStorage
func (s *PostgresStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.queries.InvalidateRefreshTokenByRequestID(ctx, requestID)
}

// RevokeRefreshTokenMaybeGracePeriod implements fosite.TokenRevocationStorage (same as RevokeRefreshToken for now)
func (s *PostgresStore) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	return s.RevokeRefreshToken(ctx, requestID)
}

// RotateRefreshToken implements fosite.TokenRevocationStorage
func (s *PostgresStore) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	// Revoke both refresh token and access token
	if err := s.RevokeRefreshToken(ctx, requestID); err != nil {
		return err
	}
	return s.RevokeAccessToken(ctx, requestID)
}

// =============================================================================
// OpenID Connect Storage
// =============================================================================

// CreateOpenIDConnectSession implements fosite.OpenIDConnectRequestStorage
func (s *PostgresStore) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) error {
	data, err := SerializeRequest(req)
	if err != nil {
		return fmt.Errorf("failed to serialize request: %w", err)
	}

	return s.queries.CreateOIDCSession(ctx, sqlc.CreateOIDCSessionParams{
		AuthorizeCode: authorizeCode,
		RequestData:   data,
	})
}

// GetOpenIDConnectSession implements fosite.OpenIDConnectRequestStorage
func (s *PostgresStore) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) (fosite.Requester, error) {
	row, err := s.queries.GetOIDCSession(ctx, authorizeCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get OIDC session: %w", err)
	}

	clientID, err := extractClientIDFromSerialized(row.RequestData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract client ID: %w", err)
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	return DeserializeRequest(row.RequestData, client)
}

// DeleteOpenIDConnectSession implements fosite.OpenIDConnectRequestStorage
func (s *PostgresStore) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return s.queries.DeleteOIDCSession(ctx, authorizeCode)
}

// =============================================================================
// PKCE Storage
// =============================================================================

// CreatePKCERequestSession implements fosite.PKCERequestStorage
func (s *PostgresStore) CreatePKCERequestSession(ctx context.Context, code string, req fosite.Requester) error {
	data, err := SerializeRequest(req)
	if err != nil {
		return fmt.Errorf("failed to serialize request: %w", err)
	}

	return s.queries.CreatePKCESession(ctx, sqlc.CreatePKCESessionParams{
		Code:        code,
		RequestData: data,
	})
}

// GetPKCERequestSession implements fosite.PKCERequestStorage
func (s *PostgresStore) GetPKCERequestSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	row, err := s.queries.GetPKCESession(ctx, code)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get PKCE session: %w", err)
	}

	clientID, err := extractClientIDFromSerialized(row.RequestData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract client ID: %w", err)
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	return DeserializeRequest(row.RequestData, client)
}

// DeletePKCERequestSession implements fosite.PKCERequestStorage
func (s *PostgresStore) DeletePKCERequestSession(ctx context.Context, code string) error {
	return s.queries.DeletePKCESession(ctx, code)
}

// =============================================================================
// JWT Blacklist Storage
// =============================================================================

// ClientAssertionJWTValid implements fosite.ClientAssertionJWTStorage
func (s *PostgresStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	exists, err := s.queries.IsJTIBlacklisted(ctx, jti)
	if err != nil {
		return fmt.Errorf("failed to check JTI: %w", err)
	}

	if exists {
		return fosite.ErrJTIKnown
	}

	return nil
}

// SetClientAssertionJWT implements fosite.ClientAssertionJWTStorage
func (s *PostgresStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	// First cleanup expired JTIs
	if err := s.queries.CleanupExpiredJTIs(ctx); err != nil {
		// Log but don't fail on cleanup error
		fmt.Printf("warning: failed to cleanup expired JTIs: %v\n", err)
	}

	return s.queries.BlacklistJTI(ctx, sqlc.BlacklistJTIParams{
		Jti:       jti,
		ExpiresAt: pgtype.Timestamptz{Time: exp, Valid: true},
	})
}

// IsJWTUsed implements fosite.JWTProfileStorage
func (s *PostgresStore) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	return s.queries.IsJTIBlacklisted(ctx, jti)
}

// MarkJWTUsedForTime implements fosite.JWTProfileStorage
func (s *PostgresStore) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	return s.SetClientAssertionJWT(ctx, jti, exp)
}

// =============================================================================
// PAR (Pushed Authorization Request) Storage
// =============================================================================

// CreatePARSession implements fosite.PARStorage
func (s *PostgresStore) CreatePARSession(ctx context.Context, requestURI string, request fosite.AuthorizeRequester) error {
	data, err := SerializeAuthorizeRequest(request)
	if err != nil {
		return fmt.Errorf("failed to serialize PAR request: %w", err)
	}

	// PAR sessions typically expire quickly (e.g., 90 seconds)
	expiresAt := time.Now().Add(90 * time.Second)

	return s.queries.CreatePARSession(ctx, sqlc.CreatePARSessionParams{
		RequestUri:  requestURI,
		RequestData: data,
		ExpiresAt:   pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
}

// GetPARSession implements fosite.PARStorage
func (s *PostgresStore) GetPARSession(ctx context.Context, requestURI string) (fosite.AuthorizeRequester, error) {
	row, err := s.queries.GetPARSession(ctx, requestURI)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get PAR session: %w", err)
	}

	clientID, err := extractClientIDFromSerialized(row.RequestData)
	if err != nil {
		return nil, fmt.Errorf("failed to extract client ID: %w", err)
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	return DeserializeAuthorizeRequest(row.RequestData, client)
}

// DeletePARSession implements fosite.PARStorage
func (s *PostgresStore) DeletePARSession(ctx context.Context, requestURI string) error {
	return s.queries.DeletePARSession(ctx, requestURI)
}

// =============================================================================
// User Authentication (simple stub - user management not implemented)
// =============================================================================

// Authenticate implements fosite.ResourceOwnerPasswordCredentialsGrantStorage
// This is a stub implementation since user management is handled at the application layer
func (s *PostgresStore) Authenticate(ctx context.Context, username string, password string) (subject string, err error) {
	// User authentication is handled by the application layer (login handler)
	// This method is required by fosite interfaces but not used in our current implementation
	return "", fmt.Errorf("password grant not supported - use authorization code flow")
}

// =============================================================================
// Public Key Management (JWT Grant - not implemented)
// =============================================================================

// GetPublicKey implements RFC7523KeyStorage
// Stub implementation - public key management not implemented
func (s *PostgresStore) GetPublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	return nil, fosite.ErrNotFound
}

// GetPublicKeys implements RFC7523KeyStorage
// Stub implementation - public key management not implemented
func (s *PostgresStore) GetPublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	return nil, fosite.ErrNotFound
}

// GetPublicKeyScopes implements RFC7523KeyStorage
// Stub implementation - public key management not implemented
func (s *PostgresStore) GetPublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	return nil, fosite.ErrNotFound
}

// =============================================================================
// Helper/Utility Methods (not part of fosite interfaces)
// =============================================================================

// SeedTestClient creates or updates the default test clients (test-client and test-client-2)
func (s *PostgresStore) SeedTestClient(ctx context.Context) error {
	grantTypes := []string{"authorization_code", "refresh_token", "client_credentials"}
	scopes := []string{"openid", "profile", "email", "ssf:manage"}

	// Test client 1 (RP - Push)
	redirectURIs1 := []string{"http://localhost:8081/callback"}
	if additionalURIs := os.Getenv("OIDC_ADDITIONAL_REDIRECT_URIS"); additionalURIs != "" {
		for _, uri := range strings.Split(additionalURIs, ",") {
			if trimmed := strings.TrimSpace(uri); trimmed != "" {
				redirectURIs1 = append(redirectURIs1, trimmed)
			}
		}
	}
	if err := s.seedClient(ctx, "test-client", "test-secret", redirectURIs1, grantTypes, scopes); err != nil {
		return fmt.Errorf("failed to seed test-client: %w", err)
	}

	// Test client 2 (RP2 - Poll)
	redirectURIs2 := []string{"http://localhost:8082/callback"}
	if additionalURIs := os.Getenv("OIDC_ADDITIONAL_REDIRECT_URIS_2"); additionalURIs != "" {
		for _, uri := range strings.Split(additionalURIs, ",") {
			if trimmed := strings.TrimSpace(uri); trimmed != "" {
				redirectURIs2 = append(redirectURIs2, trimmed)
			}
		}
	}
	if err := s.seedClient(ctx, "test-client-2", "test-secret-2", redirectURIs2, grantTypes, scopes); err != nil {
		return fmt.Errorf("failed to seed test-client-2: %w", err)
	}

	return nil
}

// seedClient creates or updates a single test client
func (s *PostgresStore) seedClient(ctx context.Context, clientID, clientSecret string, redirectURIs, grantTypes, scopes []string) error {
	// Check if client exists
	_, err := s.GetClient(ctx, clientID)
	if err == nil {
		// Client exists - update config
		return s.updateClientConfig(ctx, clientID, redirectURIs, grantTypes, scopes)
	}
	if !errors.Is(err, fosite.ErrNotFound) {
		return fmt.Errorf("failed to check if client exists: %w", err)
	}

	// Hash the secret
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash secret: %w", err)
	}

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  redirectURIs,
		GrantTypes:    grantTypes,
		ResponseTypes: []string{"code", "token", "id_token"},
		Scopes:        scopes,
		Public:        false,
	}

	return s.CreateClient(ctx, client)
}

// updateClientConfig updates the redirect URIs, grant types, and scopes for an existing client
func (s *PostgresStore) updateClientConfig(ctx context.Context, clientID string, redirectURIs []string, grantTypes []string, scopes []string) error {
	redirectURIsJSON, err := marshalJSON(redirectURIs)
	if err != nil {
		return fmt.Errorf("failed to marshal redirect URIs: %w", err)
	}

	grantTypesJSON, err := marshalJSON(grantTypes)
	if err != nil {
		return fmt.Errorf("failed to marshal grant types: %w", err)
	}

	scopesJSON, err := marshalJSON(scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal scopes: %w", err)
	}

	_, err = s.db.Exec(ctx,
		"UPDATE clients SET redirect_uris = $1, grant_types = $2, scopes = $3, updated_at = NOW() WHERE id = $4",
		redirectURIsJSON, grantTypesJSON, scopesJSON, clientID)
	if err != nil {
		return fmt.Errorf("failed to update client config: %w", err)
	}
	return nil
}

// SeedConformanceClients creates or updates OIDC Conformance Suite test clients
func (s *PostgresStore) SeedConformanceClients(ctx context.Context) error {
	// Conformance Suite callback URL pattern
	// The alias will be set during test configuration
	conformanceCallbacks := []string{
		"https://www.certification.openid.net/test/a/ssf-oidc-provider/callback",
		"https://staging.certification.openid.net/test/a/ssf-oidc-provider/callback",
		"https://localhost.emobix.co.uk:8443/test/a/ssf-oidc-provider/callback",
	}

	// Define conformance test clients
	clients := []struct {
		id     string
		secret string
	}{
		{"conformance-basic-1", "conformance-secret-1"},
		{"conformance-basic-2", "conformance-secret-2"},
		{"conformance-post", "conformance-secret-post"},
	}

	grantTypes := []string{"authorization_code", "refresh_token", "client_credentials"}
	conformanceScopes := []string{"openid", "profile", "email"}

	for _, c := range clients {
		// Check if client already exists
		_, err := s.GetClient(ctx, c.id)
		if err == nil {
			// Client exists - update config
			if err := s.updateClientConfig(ctx, c.id, conformanceCallbacks, grantTypes, conformanceScopes); err != nil {
				return fmt.Errorf("failed to update conformance client %s: %w", c.id, err)
			}
			continue
		}
		if !errors.Is(err, fosite.ErrNotFound) {
			return fmt.Errorf("failed to check if conformance client %s exists: %w", c.id, err)
		}

		// Hash the secret
		hashedSecret, err := bcrypt.GenerateFromPassword([]byte(c.secret), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash secret for %s: %w", c.id, err)
		}

		client := &fosite.DefaultClient{
			ID:            c.id,
			Secret:        hashedSecret,
			RedirectURIs:  conformanceCallbacks,
			GrantTypes:    []string{"authorization_code", "refresh_token", "client_credentials"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email"},
			Public:        false,
		}

		if err := s.CreateClient(ctx, client); err != nil {
			return fmt.Errorf("failed to create conformance client %s: %w", c.id, err)
		}
	}

	return nil
}
