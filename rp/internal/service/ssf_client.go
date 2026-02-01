package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lab-matsuura/oidc-ssf/rp/internal/config"
	"github.com/lab-matsuura/oidc-ssf/rp/internal/storage/postgres/sqlc"
)

// SSFClient handles communication with the IdP's SSF API
type SSFClient struct {
	cfg        *config.Config
	httpClient *http.Client
	queries    *sqlc.Queries

	// In-memory token cache (not stored in DB for security)
	tokenCache  string
	tokenExpiry time.Time
	tokenMutex  sync.RWMutex

	// Cached stream ID
	streamID   string
	streamLock sync.RWMutex
}

// NewSSFClient creates a new SSF client
func NewSSFClient(cfg *config.Config, queries *sqlc.Queries) *SSFClient {
	return &SSFClient{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		queries:    queries,
	}
}

// Subject represents an SSF subject identifier
type Subject struct {
	Format string `json:"format"`
	Iss    string `json:"iss,omitempty"`
	Sub    string `json:"sub,omitempty"`
	Email  string `json:"email,omitempty"`
	ID     string `json:"id,omitempty"`
}

// TokenResponse represents the OAuth token response
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// StreamConfig represents a stream configuration response
type streamConfig struct {
	StreamID        string   `json:"stream_id"`
	Status          string   `json:"status"`
	EventsDelivered []string `json:"events_delivered"`
}

// GetAccessToken retrieves an access token using Client Credentials grant
// Tokens are cached in-memory (not persisted to DB for security reasons)
func (c *SSFClient) GetAccessToken(ctx context.Context) (string, error) {
	// Check cache first
	c.tokenMutex.RLock()
	if c.tokenCache != "" && time.Now().Before(c.tokenExpiry.Add(-5*time.Minute)) {
		token := c.tokenCache
		c.tokenMutex.RUnlock()
		return token, nil
	}
	c.tokenMutex.RUnlock()

	// Request new token
	token, expiresIn, err := c.requestNewToken(ctx)
	if err != nil {
		return "", err
	}

	// Update cache
	c.tokenMutex.Lock()
	c.tokenCache = token
	c.tokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	c.tokenMutex.Unlock()

	log.Printf("SSF Client: Obtained new access token (expires in %d seconds)", expiresIn)
	return token, nil
}

// requestNewToken requests a new token from the IdP using Client Credentials grant
func (c *SSFClient) requestNewToken(ctx context.Context) (string, int, error) {
	tokenURL := c.cfg.GetTokenURL()

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.cfg.ClientID)
	data.Set("client_secret", c.cfg.ClientSecret)
	data.Set("scope", "ssf:manage") // SSF management scope

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", 0, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", 0, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Default expiry if not provided
	expiresIn := tokenResp.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 3600 // Default 1 hour
	}

	return tokenResp.AccessToken, expiresIn, nil
}

// EnsureStream ensures a stream exists and returns its ID
// The stream ID is cached both in-memory and in DB
func (c *SSFClient) EnsureStream(ctx context.Context) (string, error) {
	// Check in-memory cache
	c.streamLock.RLock()
	if c.streamID != "" {
		streamID := c.streamID
		c.streamLock.RUnlock()
		return streamID, nil
	}
	c.streamLock.RUnlock()

	// Check DB
	ssfConfig, err := c.queries.GetSSFConfig(ctx)
	if err == nil && ssfConfig.StreamID != nil && *ssfConfig.StreamID != "" {
		c.streamLock.Lock()
		c.streamID = *ssfConfig.StreamID
		c.streamLock.Unlock()
		log.Printf("SSF Client: Using existing stream from DB: %s", *ssfConfig.StreamID)
		return *ssfConfig.StreamID, nil
	}

	// Create new stream
	streamID, err := c.createStream(ctx)
	if err != nil {
		return "", err
	}

	// Save to DB
	_, err = c.queries.UpsertSSFConfig(ctx, &streamID)
	if err != nil {
		log.Printf("SSF Client: Warning - failed to persist stream ID: %v", err)
	}

	// Cache in memory
	c.streamLock.Lock()
	c.streamID = streamID
	c.streamLock.Unlock()

	log.Printf("SSF Client: Created new stream: %s", streamID)
	return streamID, nil
}

// createStream creates a new SSF stream at the IdP
func (c *SSFClient) createStream(ctx context.Context) (string, error) {
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get access token: %w", err)
	}

	// Determine the RP's receiver endpoint URL
	receiverURL := c.getReceiverEndpointURL()

	createReq := map[string]interface{}{
		"delivery": map[string]interface{}{
			"method":       "urn:ietf:rfc:8935", // Push delivery
			"endpoint_url": receiverURL,
		},
		"events_requested": []string{
			"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
			"https://schemas.openid.net/secevent/caep/event-type/credential-change",
			"https://schemas.openid.net/secevent/caep/event-type/token-claims-change",
			"https://schemas.openid.net/secevent/risc/event-type/account-disabled",
			"https://schemas.openid.net/secevent/risc/event-type/account-enabled",
		},
		"description": "RP SSF Stream (auto-created)",
	}

	body, _ := json.Marshal(createReq)
	streamURL := c.cfg.IssuerURL + "/ssf/stream"

	req, err := http.NewRequestWithContext(ctx, "POST", streamURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create stream request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("stream creation request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("stream creation failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var streamResp streamConfig
	if err := json.NewDecoder(resp.Body).Decode(&streamResp); err != nil {
		return "", fmt.Errorf("failed to decode stream response: %w", err)
	}

	return streamResp.StreamID, nil
}

// AddSubject registers a subject with the SSF stream
func (c *SSFClient) AddSubject(ctx context.Context, streamID string, subject *Subject) error {
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}

	subjectMap := c.subjectToMap(subject)
	addReq := map[string]interface{}{
		"stream_id": streamID,
		"subject":   subjectMap,
		"verified":  true,
	}

	body, _ := json.Marshal(addReq)
	addSubjectURL := c.cfg.IssuerURL + "/ssf/subjects:add"

	req, err := http.NewRequestWithContext(ctx, "POST", addSubjectURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create add subject request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("add subject request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add subject failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	log.Printf("SSF Client: Added subject to stream %s: %s", streamID, subject.Sub)
	return nil
}

// RemoveSubject removes a subject from the SSF stream
func (c *SSFClient) RemoveSubject(ctx context.Context, streamID string, subject *Subject) error {
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}

	subjectMap := c.subjectToMap(subject)
	removeReq := map[string]interface{}{
		"stream_id": streamID,
		"subject":   subjectMap,
	}

	body, _ := json.Marshal(removeReq)
	removeSubjectURL := c.cfg.IssuerURL + "/ssf/subjects:remove"

	req, err := http.NewRequestWithContext(ctx, "POST", removeSubjectURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create remove subject request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("remove subject request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remove subject failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	log.Printf("SSF Client: Removed subject from stream %s: %s", streamID, subject.Sub)
	return nil
}

// subjectToMap converts a Subject to a map for JSON serialization
func (c *SSFClient) subjectToMap(subject *Subject) map[string]interface{} {
	m := map[string]interface{}{
		"format": subject.Format,
	}

	switch subject.Format {
	case "iss_sub":
		if subject.Iss != "" {
			m["iss"] = subject.Iss
		}
		if subject.Sub != "" {
			m["sub"] = subject.Sub
		}
	case "email":
		if subject.Email != "" {
			m["email"] = subject.Email
		}
	case "opaque":
		if subject.ID != "" {
			m["id"] = subject.ID
		}
	}

	return m
}

// getReceiverEndpointURL returns the RP's SSF receiver endpoint URL
func (c *SSFClient) getReceiverEndpointURL() string {
	// Use environment variable or construct from redirect URI
	// The redirect URI is http://localhost:8081/callback, so base URL is http://localhost:8081
	baseURL := strings.TrimSuffix(c.cfg.RedirectURI, "/callback")
	return baseURL + "/ssf/receiver"
}
