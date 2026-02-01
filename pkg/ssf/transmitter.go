package ssf

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"
)

// DeliveryMethod represents the SET delivery method
type DeliveryMethod string

const (
	DeliveryMethodPush DeliveryMethod = "push" // RFC 8935
	DeliveryMethodPoll DeliveryMethod = "poll" // RFC 8936
)

// SetError represents an error for a specific SET (RFC 8936)
type SetError struct {
	Err         string `json:"err"`
	Description string `json:"description,omitempty"`
}

// PollResponse represents RFC 8936 poll response
type PollResponse struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable,omitempty"`
}

// Transmitter handles the transmission of Security Event Tokens
// This is a stateless transmitter - all state management (streams, queues) is handled by the caller
type Transmitter struct {
	privateKey *rsa.PrivateKey
	keyID      string
	httpClient *http.Client
}

// TransmissionResult represents the result of a transmission attempt
type TransmissionResult struct {
	Success     bool
	StatusCode  int
	Error       error
	ReceiverURL string
	SETJTI      string
}

// NewTransmitter creates a new SSF transmitter with optimized HTTP transport
func NewTransmitter(privateKey *rsa.PrivateKey, keyID string) *Transmitter {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     50,
		IdleConnTimeout:     90 * time.Second,
	}

	return &Transmitter{
		privateKey: privateKey,
		keyID:      keyID,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

// GetPrivateKey returns the transmitter's private key for JWT signing
func (t *Transmitter) GetPrivateKey() *rsa.PrivateKey {
	return t.privateKey
}

// GetKeyID returns the transmitter's key ID for JWT signing
func (t *Transmitter) GetKeyID() string {
	return t.keyID
}

// TransmitEvent immediately transmits a SET to a specific receiver
// If authHeader is provided (non-empty), it will be included in the request
func (t *Transmitter) TransmitEvent(set *SET, receiverURL, authHeader string) (*TransmissionResult, error) {
	// Convert SET to JWT
	token, err := set.ToJWT(t.privateKey, t.keyID)
	if err != nil {
		return &TransmissionResult{
			Success:     false,
			Error:       fmt.Errorf("failed to generate JWT: %w", err),
			ReceiverURL: receiverURL,
			SETJTI:      set.JTI,
		}, err
	}

	// Create HTTP request with raw JWT as body (RFC 8935)
	req, err := http.NewRequest("POST", receiverURL, bytes.NewBufferString(token))
	if err != nil {
		return &TransmissionResult{
			Success:     false,
			Error:       fmt.Errorf("failed to create request: %w", err),
			ReceiverURL: receiverURL,
			SETJTI:      set.JTI,
		}, err
	}

	// RFC 8935: Content-Type MUST be application/secevent+jwt
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")

	// Set authorization header if provided
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	// Send request
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return &TransmissionResult{
			Success:     false,
			Error:       fmt.Errorf("failed to send request: %w", err),
			ReceiverURL: receiverURL,
			SETJTI:      set.JTI,
		}, err
	}
	defer func() { _ = resp.Body.Close() }()

	result := &TransmissionResult{
		Success:     resp.StatusCode >= 200 && resp.StatusCode < 300,
		StatusCode:  resp.StatusCode,
		ReceiverURL: receiverURL,
		SETJTI:      set.JTI,
	}

	if !result.Success {
		result.Error = fmt.Errorf("receiver returned status code: %d", resp.StatusCode)
	}

	return result, nil
}

// TransmitPreSignedToken transmits an already-signed SET token to a receiver
// Use this when the JWT is pre-signed and stored (e.g., in a database queue)
func (t *Transmitter) TransmitPreSignedToken(token, jti, receiverURL, authHeader string) *TransmissionResult {
	// Create HTTP request with raw JWT as body (RFC 8935)
	req, err := http.NewRequest("POST", receiverURL, bytes.NewBufferString(token))
	if err != nil {
		return &TransmissionResult{
			Success:     false,
			Error:       fmt.Errorf("failed to create request: %w", err),
			ReceiverURL: receiverURL,
			SETJTI:      jti,
		}
	}

	// RFC 8935: Content-Type MUST be application/secevent+jwt
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")

	// Set authorization header if provided
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	// Send request using optimized HTTP client
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return &TransmissionResult{
			Success:     false,
			Error:       fmt.Errorf("failed to send request: %w", err),
			ReceiverURL: receiverURL,
			SETJTI:      jti,
		}
	}
	defer func() { _ = resp.Body.Close() }()

	result := &TransmissionResult{
		Success:     resp.StatusCode >= 200 && resp.StatusCode < 300,
		StatusCode:  resp.StatusCode,
		ReceiverURL: receiverURL,
		SETJTI:      jti,
	}

	if !result.Success {
		result.Error = fmt.Errorf("receiver returned status code: %d", resp.StatusCode)
	}

	return result
}
