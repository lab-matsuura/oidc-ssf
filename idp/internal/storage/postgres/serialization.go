package postgres

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

// SerializedRequest represents a serialized fosite.Requester for database storage
type SerializedRequest struct {
	ID                string              `json:"id"`
	RequestedAt       time.Time           `json:"requested_at"`
	ClientID          string              `json:"client_id"`
	RequestedScopes   []string            `json:"requested_scopes"`
	GrantedScopes     []string            `json:"granted_scopes"`
	RequestedAudience []string            `json:"requested_audience"`
	GrantedAudience   []string            `json:"granted_audience"`
	Form              map[string][]string `json:"form"`
	Session           json.RawMessage     `json:"session"`
	SessionType       string              `json:"session_type"`
}

// SerializeRequest converts fosite.Requester to []byte for database storage
func SerializeRequest(req fosite.Requester) ([]byte, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	sr := SerializedRequest{
		ID:                req.GetID(),
		RequestedAt:       req.GetRequestedAt(),
		ClientID:          req.GetClient().GetID(),
		RequestedScopes:   req.GetRequestedScopes(),
		GrantedScopes:     req.GetGrantedScopes(),
		RequestedAudience: req.GetRequestedAudience(),
		GrantedAudience:   req.GetGrantedAudience(),
		Form:              req.GetRequestForm(),
	}

	// Serialize session
	session := req.GetSession()
	if session != nil {
		sessionData, err := json.Marshal(session)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal session: %w", err)
		}
		sr.Session = sessionData

		// Detect session type for proper deserialization
		switch session.(type) {
		case *openid.DefaultSession:
			sr.SessionType = "openid.DefaultSession"
		default:
			sr.SessionType = "fosite.DefaultSession"
		}
	}

	data, err := json.Marshal(sr)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	return data, nil
}

// DeserializeRequest converts []byte back to fosite.Requester
func DeserializeRequest(data []byte, client fosite.Client) (fosite.Requester, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	var sr SerializedRequest
	if err := json.Unmarshal(data, &sr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}

	req := &fosite.Request{
		ID:                sr.ID,
		RequestedAt:       sr.RequestedAt,
		Client:            client,
		RequestedScope:    sr.RequestedScopes,
		GrantedScope:      sr.GrantedScopes,
		RequestedAudience: sr.RequestedAudience,
		GrantedAudience:   sr.GrantedAudience,
		Form:              sr.Form,
	}

	// Deserialize session based on type
	if len(sr.Session) > 0 {
		switch sr.SessionType {
		case "openid.DefaultSession":
			session := &openid.DefaultSession{}
			if err := json.Unmarshal(sr.Session, session); err != nil {
				return nil, fmt.Errorf("failed to unmarshal openid session: %w", err)
			}
			req.Session = session
		default:
			session := &fosite.DefaultSession{}
			if err := json.Unmarshal(sr.Session, session); err != nil {
				return nil, fmt.Errorf("failed to unmarshal default session: %w", err)
			}
			req.Session = session
		}
	}

	return req, nil
}

// SerializeAuthorizeRequest converts fosite.AuthorizeRequester to []byte
// For PAR sessions and authorize codes, we use the same serialization as regular requests
func SerializeAuthorizeRequest(req fosite.AuthorizeRequester) ([]byte, error) {
	return SerializeRequest(req)
}

// DeserializeAuthorizeRequest converts []byte back to fosite.AuthorizeRequester
func DeserializeAuthorizeRequest(data []byte, client fosite.Client) (fosite.AuthorizeRequester, error) {
	req, err := DeserializeRequest(data, client)
	if err != nil {
		return nil, err
	}

	// fosite.Request implements fosite.AuthorizeRequester
	if ar, ok := req.(fosite.AuthorizeRequester); ok {
		return ar, nil
	}

	// Wrap in AuthorizeRequest if needed
	if r, ok := req.(*fosite.Request); ok {
		return &fosite.AuthorizeRequest{Request: *r}, nil
	}

	return nil, fmt.Errorf("unable to convert to AuthorizeRequester")
}
