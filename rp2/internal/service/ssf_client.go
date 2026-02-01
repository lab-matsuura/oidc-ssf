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

	"github.com/lab-matsuura/oidc-ssf/rp2/internal/config"
	"github.com/lab-matsuura/oidc-ssf/rp2/internal/storage/postgres/sqlc"
)

// SSFClient handles communication with the IdP's SSF API
// This client uses Poll-based delivery (RFC 8936)
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

// NewSSFClient creates a new SSF client for Poll-based delivery
func NewSSFClient(cfg *config.Config, queries *sqlc.Queries) *SSFClient {
	// For long polling, use longer timeout to accommodate server's 30s wait
	timeout := 30 * time.Second
	if cfg.SSFPollMode == "long" {
		timeout = 40 * time.Second
	}

	return &SSFClient{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: timeout},
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

// PollRequest represents RFC 8936 Poll request body
type PollRequest struct {
	// MaxEvents is the maximum number of SETs to return (optional)
	MaxEvents int `json:"maxEvents,omitempty"`
	// ReturnImmediately indicates short polling vs long polling (optional, default false)
	ReturnImmediately bool `json:"returnImmediately,omitempty"`
	// Ack contains JTI values of SETs being acknowledged (optional)
	Ack []string `json:"ack,omitempty"`
	// SetErrs contains error reports for SETs that could not be processed (optional)
	SetErrs map[string]SetError `json:"setErrs,omitempty"`
}

// SetError represents an error for a specific SET (RFC 8936)
type SetError struct {
	Err         string `json:"err"`
	Description string `json:"description"`
}

// PollResponse represents RFC 8936 Poll response body
type PollResponse struct {
	// Sets contains the SETs keyed by JTI
	Sets map[string]string `json:"sets"`
	// MoreAvailable indicates if more SETs are available
	MoreAvailable bool `json:"moreAvailable,omitempty"`
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

	log.Printf("SSF Client: Requesting token from %s for client %s", tokenURL, c.cfg.ClientID)

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

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("failed to decode token response: %w (body: %.200s)", err, string(body))
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

	log.Printf("SSF Client: Created new Poll stream: %s", streamID)
	return streamID, nil
}

// createStream creates a new SSF stream at the IdP using Poll delivery (RFC 8936)
func (c *SSFClient) createStream(ctx context.Context) (string, error) {
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get access token: %w", err)
	}

	// RFC 8936: Poll-based delivery - no endpoint_url needed
	createReq := map[string]any{
		"delivery": map[string]any{
			"method": "urn:ietf:rfc:8936", // Poll delivery (RFC 8936)
		},
		"events_requested": []string{
			"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
			"https://schemas.openid.net/secevent/caep/event-type/credential-change",
			"https://schemas.openid.net/secevent/caep/event-type/token-claims-change",
			"https://schemas.openid.net/secevent/risc/event-type/account-disabled",
			"https://schemas.openid.net/secevent/risc/event-type/account-enabled",
		},
		"description": "RP2 SSF Stream - Poll delivery (auto-created)",
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

// Poll performs RFC 8936 Poll request to fetch pending SETs
func (c *SSFClient) Poll(ctx context.Context, streamID string, acks []string) (*PollResponse, error) {
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	// RFC 8936: POST to poll endpoint with JSON body
	// ReturnImmediately: true = short polling, false = long polling
	returnImmediately := c.cfg.SSFPollMode != "long"
	pollReq := PollRequest{
		MaxEvents:         100,
		ReturnImmediately: returnImmediately,
		Ack:               acks,
	}

	body, _ := json.Marshal(pollReq)

	// RFC 8936: Poll endpoint URL should include stream_id
	pollURL := c.cfg.IssuerURL + "/ssf/poll/" + streamID

	req, err := http.NewRequestWithContext(ctx, "POST", pollURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create poll request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("poll failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var pollResp PollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
		return nil, fmt.Errorf("failed to decode poll response: %w", err)
	}

	return &pollResp, nil
}

// AddSubject registers a subject with the SSF stream
func (c *SSFClient) AddSubject(ctx context.Context, streamID string, subject *Subject) error {
	token, err := c.GetAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}

	subjectMap := c.subjectToMap(subject)
	addReq := map[string]any{
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
	removeReq := map[string]any{
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
func (c *SSFClient) subjectToMap(subject *Subject) map[string]any {
	m := map[string]any{
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
