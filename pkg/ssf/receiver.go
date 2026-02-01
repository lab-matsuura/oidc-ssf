package ssf

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// ErrDuplicateJTI indicates a SET with a duplicate JTI was received
var ErrDuplicateJTI = fmt.Errorf("duplicate JTI: replay attack detected")

// Receiver handles the reception of Security Event Tokens
type Receiver struct {
	jwksCache     *jwk.Cache        // Auto-refreshing JWKS cache
	jwksURIs      map[string]string // issuer -> jwks_uri mapping
	eventHandlers map[string]EventHandler
	receivedSETs  []ReceivedSET
	seenJTIs      map[string]time.Time // JTI -> received time for deduplication
	mu            sync.RWMutex
	httpClient    *http.Client
	jwksCacheTTL  time.Duration
	ctx           context.Context
	cancel        context.CancelFunc
}

// EventHandler is a function that handles a specific event type
type EventHandler func(eventType string, event any, set *SET) error

// ReceivedSET represents a received and validated SET
type ReceivedSET struct {
	SET         *SET
	ReceivedAt  time.Time
	RawToken    string
	Issuer      string
	ProcessedAt *time.Time
}

// ReceiverConfig configures the receiver
type ReceiverConfig struct {
	JWKSCacheTTL time.Duration // How long to cache JWKS (default: 1 hour)
	HTTPTimeout  time.Duration // HTTP client timeout (default: 10 seconds)
}

// NewReceiver creates a new SSF receiver
func NewReceiver(config *ReceiverConfig) *Receiver {
	if config == nil {
		config = &ReceiverConfig{}
	}
	if config.JWKSCacheTTL == 0 {
		config.JWKSCacheTTL = 1 * time.Hour
	}
	if config.HTTPTimeout == 0 {
		config.HTTPTimeout = 10 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create JWKS cache with auto-refresh
	cache := jwk.NewCache(ctx)

	return &Receiver{
		jwksCache:     cache,
		jwksURIs:      make(map[string]string),
		eventHandlers: make(map[string]EventHandler),
		receivedSETs:  make([]ReceivedSET, 0),
		seenJTIs:      make(map[string]time.Time),
		jwksCacheTTL:  config.JWKSCacheTTL,
		httpClient: &http.Client{
			Timeout: config.HTTPTimeout,
		},
		ctx:    ctx,
		cancel: cancel,
	}
}

// RegisterEventHandler registers a handler for a specific event type
func (r *Receiver) RegisterEventHandler(eventType string, handler EventHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eventHandlers[eventType] = handler
}

// RegisterDefaultHandler registers a handler for all unhandled event types
func (r *Receiver) RegisterDefaultHandler(handler EventHandler) {
	r.RegisterEventHandler("*", handler)
}

// ReceiveSET processes an incoming SET token with mandatory signature verification
func (r *Receiver) ReceiveSET(token string) (*ReceivedSET, error) {
	// Split JWT into parts to extract issuer before verification
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode payload to get issuer
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	issuer, ok := claims["iss"].(string)
	if !ok || issuer == "" {
		return nil, fmt.Errorf("missing or invalid issuer")
	}

	// Get JWKS for this issuer
	keySet, err := r.getJWKS(issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS for issuer %s: %w", issuer, err)
	}

	// Verify signature using jwx library
	payload, err := jws.Verify([]byte(token), jws.WithKeySet(keySet))
	if err != nil {
		return nil, fmt.Errorf("failed to verify SET signature: %w", err)
	}

	// Parse the verified payload into SET
	set, err := parseSETFromPayload(payload, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SET: %w", err)
	}

	// Check for duplicate JTI (replay attack protection)
	if set.JTI != "" {
		r.mu.Lock()
		if _, exists := r.seenJTIs[set.JTI]; exists {
			r.mu.Unlock()
			return nil, ErrDuplicateJTI
		}
		// Mark JTI as seen
		r.seenJTIs[set.JTI] = time.Now()
		r.mu.Unlock()
	}

	// Store the received SET
	received := ReceivedSET{
		SET:        set,
		ReceivedAt: time.Now(),
		RawToken:   token,
		Issuer:     issuer,
	}

	r.mu.Lock()
	r.receivedSETs = append(r.receivedSETs, received)
	receivedIndex := len(r.receivedSETs) - 1
	r.mu.Unlock()

	// Process events
	if err := r.processEvents(set); err != nil {
		return &r.receivedSETs[receivedIndex], fmt.Errorf("error processing events: %w", err)
	}

	// Mark as processed
	now := time.Now()
	r.mu.Lock()
	r.receivedSETs[receivedIndex].ProcessedAt = &now
	r.mu.Unlock()

	return &r.receivedSETs[receivedIndex], nil
}

// getJWKS retrieves the JWKS for an issuer, using cache with auto-refresh
func (r *Receiver) getJWKS(issuer string) (jwk.Set, error) {
	r.mu.RLock()
	jwksURI, exists := r.jwksURIs[issuer]
	r.mu.RUnlock()

	if !exists {
		// Fetch SSF configuration to get jwks_uri
		var err error
		jwksURI, err = r.fetchJWKSURI(issuer)
		if err != nil {
			return nil, err
		}

		// Register the JWKS URL with the cache
		if err := r.jwksCache.Register(jwksURI,
			jwk.WithMinRefreshInterval(r.jwksCacheTTL/2),
			jwk.WithRefreshInterval(r.jwksCacheTTL),
		); err != nil {
			return nil, fmt.Errorf("failed to register JWKS URL: %w", err)
		}

		r.mu.Lock()
		r.jwksURIs[issuer] = jwksURI
		r.mu.Unlock()

		log.Printf("SSF: Registered JWKS endpoint for issuer %s: %s", issuer, jwksURI)
	}

	// Get the keyset from cache (auto-refreshes if needed)
	keySet, err := r.jwksCache.Get(r.ctx, jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from cache: %w", err)
	}

	return keySet, nil
}

// fetchJWKSURI fetches the jwks_uri from the issuer's SSF configuration
func (r *Receiver) fetchJWKSURI(issuer string) (string, error) {
	configURL := strings.TrimSuffix(issuer, "/") + "/.well-known/ssf-configuration"

	resp, err := r.httpClient.Get(configURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch SSF configuration from %s: %w", configURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("SSF configuration returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read SSF configuration: %w", err)
	}

	var config struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		return "", fmt.Errorf("failed to parse SSF configuration: %w", err)
	}

	if config.JWKSURI == "" {
		return "", fmt.Errorf("jwks_uri not found in SSF configuration")
	}

	return config.JWKSURI, nil
}

// parseSETFromPayload parses the verified JWT payload into a SET structure
func parseSETFromPayload(payload []byte, issuer string) (*SET, error) {
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	set := &SET{
		Issuer: issuer,
		JTI:    getStringFromClaimsAny(claims, "jti"),
		TXN:    getStringFromClaimsAny(claims, "txn"),
	}

	// Parse sub_id (SSF 1.0 format)
	if subIDRaw, ok := claims["sub_id"].(map[string]any); ok {
		set.SubID = parseSubIDAny(subIDRaw)
	}

	// Parse audience
	if aud, ok := claims["aud"]; ok {
		switch v := aud.(type) {
		case string:
			set.Audience = []string{v}
		case []any:
			for _, a := range v {
				if s, ok := a.(string); ok {
					set.Audience = append(set.Audience, s)
				}
			}
		}
	}

	// Parse timestamps
	if iat, ok := claims["iat"].(float64); ok {
		set.IssuedAt = time.Unix(int64(iat), 0)
	}

	// Parse events
	if events, ok := claims["events"].(map[string]any); ok {
		set.Events = events
	}

	return set, nil
}

// Helper functions for parsing with 'any' type
func getStringFromClaimsAny(claims map[string]any, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

func parseSubIDAny(raw map[string]any) *SubID {
	return &SubID{
		Format:      getStringFromClaimsAny(raw, "format"),
		Email:       getStringFromClaimsAny(raw, "email"),
		PhoneNumber: getStringFromClaimsAny(raw, "phone_number"),
		Iss:         getStringFromClaimsAny(raw, "iss"),
		Sub:         getStringFromClaimsAny(raw, "sub"),
		ID:          getStringFromClaimsAny(raw, "id"),
	}
}

// processEvents processes all events in a SET
func (r *Receiver) processEvents(set *SET) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var errors []error

	for eventType, eventData := range set.Events {
		// Look for specific handler
		handler, exists := r.eventHandlers[eventType]
		if !exists {
			// Look for default handler
			handler, exists = r.eventHandlers["*"]
		}

		if exists && handler != nil {
			if err := handler(eventType, eventData, set); err != nil {
				errors = append(errors, fmt.Errorf("handler error for %s: %w", eventType, err))
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("multiple handler errors: %v", errors)
	}

	return nil
}
