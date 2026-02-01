package ssf

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"time"
)

// SET represents a Security Event Token as defined in RFC 8417 and SSF 1.0
// Note: SSF 1.0 prohibits "sub" and "exp" claims. Use "sub_id" instead of "sub".
type SET struct {
	Issuer   string                 `json:"iss"`
	SubID    *SubID                 `json:"sub_id,omitempty"` // SSF 1.0 requires sub_id instead of sub
	Audience []string               `json:"aud"`
	IssuedAt time.Time              `json:"iat"`
	JTI      string                 `json:"jti"`
	Events   map[string]interface{} `json:"events"`
	TXN      string                 `json:"txn,omitempty"` // Transaction identifier
}

// SubID represents the subject identifier as per SSF 1.0 specification
type SubID struct {
	Format      string `json:"format"`
	Email       string `json:"email,omitempty"`
	PhoneNumber string `json:"phone_number,omitempty"`
	Iss         string `json:"iss,omitempty"` // For iss_sub format
	Sub         string `json:"sub,omitempty"` // For iss_sub format
	ID          string `json:"id,omitempty"`  // For opaque format
}

// RISC (Risk and Incident Sharing and Coordination) event types
// See: https://openid.net/specs/openid-risc-1_0-final.html
const (
	// Account events
	EventTypeAccountCredentialChangeRequired = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"
	EventTypeAccountPurged                   = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
	EventTypeAccountDisabled                 = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	EventTypeAccountEnabled                  = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"

	// Identifier events
	EventTypeIdentifierChanged  = "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"
	EventTypeIdentifierRecycled = "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled"

	// Credential events
	EventTypeCredentialCompromise = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"

	// Opt-in/out events
	EventTypeOptIn           = "https://schemas.openid.net/secevent/risc/event-type/opt-in"
	EventTypeOptOutInitiated = "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated"
	EventTypeOptOutCancelled = "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled"
	EventTypeOptOutEffective = "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective"

	// Recovery events
	EventTypeRecoveryActivated          = "https://schemas.openid.net/secevent/risc/event-type/recovery-activated"
	EventTypeRecoveryInformationChanged = "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed"

	// Deprecated: Use CAEP session-revoked instead
	EventTypeSessionsRevoked = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"
)

// CAEP (Continuous Access Evaluation Profile) event types
// See: https://openid.net/specs/openid-caep-1_0-final.html
const (
	EventTypeCAEPSessionRevoked       = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EventTypeCAEPTokenClaimsChange    = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
	EventTypeCAEPCredentialChange     = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	EventTypeCAEPAssuranceLevelChange = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
	EventTypeCAEPDeviceCompliance     = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
)

// Recommended event types (prefer CAEP over deprecated RISC equivalents)
const (
	// EventTypeSessionRevoked - Use CAEP session-revoked (RISC sessions-revoked is deprecated)
	EventTypeSessionRevoked = EventTypeCAEPSessionRevoked

	// EventTypeCredentialChange - Use CAEP credential-change
	EventTypeCredentialChange = EventTypeCAEPCredentialChange

	// EventTypeTokenClaimsChange - Use CAEP token-claims-change
	EventTypeTokenClaimsChange = EventTypeCAEPTokenClaimsChange
)

// SessionRevokedEvent represents a session revocation event
type SessionRevokedEvent struct {
	Subject     SubjectIdentifier `json:"subject"`
	EventTime   int64             `json:"event_time,omitempty"`
	ReasonAdmin string            `json:"reason_admin,omitempty"`
	ReasonUser  string            `json:"reason_user,omitempty"`
}

// CredentialChangeEvent represents a credential change event
type CredentialChangeEvent struct {
	Subject        SubjectIdentifier `json:"subject"`
	EventTime      int64             `json:"event_time,omitempty"`
	CredentialType string            `json:"credential_type,omitempty"`
	ChangeType     string            `json:"change_type,omitempty"`
}

// TokenClaimsChangeEvent represents a token claims change event (CAEP)
// Used when user attributes (e.g., role) change and the RP should update its local state
type TokenClaimsChangeEvent struct {
	Subject        SubjectIdentifier      `json:"subject"`
	EventTime      int64                  `json:"event_time,omitempty"`
	Claims         map[string]interface{} `json:"claims,omitempty"`          // New claim values
	PreviousClaims map[string]interface{} `json:"previous_claims,omitempty"` // Previous claim values (optional)
}

// SubjectIdentifier represents the subject of a security event
type SubjectIdentifier struct {
	SubjectType string                 `json:"subject_type"`
	Provider    string                 `json:"provider,omitempty"`
	ID          string                 `json:"id,omitempty"`
	Email       string                 `json:"email,omitempty"`
	Identifiers map[string]interface{} `json:",inline"`
}

// NewSET creates a new Security Event Token
// Note: SSF 1.0 spec prohibits the use of "exp" claim in SETs
func NewSET(issuer string, audience []string, eventType string, event interface{}) *SET {
	now := time.Now()
	events := make(map[string]interface{})
	events[eventType] = event

	return &SET{
		Issuer:   issuer,
		Audience: audience,
		IssuedAt: now,
		JTI:      generateJTI(),
		Events:   events,
		TXN:      generateTXN(),
	}
}

// SubjectIdentifier returns the subject identifier from SubID (SSF 1.0)
// Returns empty string if SubID is not set or format is unknown
func (s *SET) SubjectIdentifier() string {
	if s.SubID == nil {
		return ""
	}

	switch s.SubID.Format {
	case "iss_sub":
		return s.SubID.Sub
	case "email":
		return s.SubID.Email
	case "opaque":
		return s.SubID.ID
	case "phone_number":
		return s.SubID.PhoneNumber
	default:
		return ""
	}
}

// ToJWT converts the SET to a JWT token
// keyID should be the RFC 7638 JWK Thumbprint of the signing key
func (s *SET) ToJWT(privateKey *rsa.PrivateKey, keyID string) (string, error) {
	// Create header
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "secevent+jwt",
		"kid": keyID,
	}

	// Create payload
	// Note: SSF 1.0 spec prohibits "exp" and "sub" claims
	payload := map[string]interface{}{
		"iss":    s.Issuer,
		"aud":    s.Audience,
		"iat":    s.IssuedAt.Unix(),
		"jti":    s.JTI,
		"events": s.Events,
	}

	if s.TXN != "" {
		payload["txn"] = s.TXN
	}

	// sub_id is used instead of sub in SSF 1.0
	if s.SubID != nil {
		payload["sub_id"] = s.SubID
	}

	// Encode header and payload
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signing input
	signingInput := headerB64 + "." + payloadB64

	// Sign
	hashed := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Combine all parts
	return signingInput + "." + signatureB64, nil
}

// Helper functions

func generateJTI() string {
	return generateRandomString(16)
}

func generateTXN() string {
	return generateRandomString(16)
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}
