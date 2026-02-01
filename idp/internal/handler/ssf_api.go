package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/provider"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres/sqlc"
	"github.com/lab-matsuura/oidc-ssf/pkg/ssf"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

// Helper to convert string to *string
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// getClientIDFromContext extracts client_id from context (set by RequireAuth middleware)
func getClientIDFromContext(ctx context.Context) string {
	if cid, ok := ctx.Value(clientIDKey).(string); ok {
		return cid
	}
	return ""
}

// verifyStreamOwnership checks if the stream belongs to the requesting client.
// Returns the stream if ownership is verified.
// For security, returns "not_found" error for both non-existent and unauthorized streams
// to prevent stream ID enumeration.
func (h *SSFAPIHandler) verifyStreamOwnership(ctx context.Context, pgID pgtype.UUID) (*sqlc.SsfStream, error) {
	stream, err := h.Queries.GetSSFStream(ctx, pgID)
	if err != nil {
		return nil, fmt.Errorf("not_found")
	}

	clientID := getClientIDFromContext(ctx)
	if clientID == "" {
		return nil, fmt.Errorf("not_found")
	}

	// Check ownership - stream must belong to the requesting client
	// Admin-created streams (ClientID == nil) are not accessible via API
	if stream.ClientID == nil || *stream.ClientID != clientID {
		return nil, fmt.Errorf("not_found")
	}

	return &stream, nil
}

// ProblemDetails represents an RFC 7807 Problem Details response
type ProblemDetails struct {
	Type   string `json:"type"`
	Status int    `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

// writeProblem sends an RFC 7807 Problem Details response
func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	problem := ProblemDetails{
		Type:   "about:blank",
		Status: status,
		Title:  title,
		Detail: detail,
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem)
}

// Common problem responses
func writeBadRequest(w http.ResponseWriter, detail string) {
	writeProblem(w, http.StatusBadRequest, "Bad Request", detail)
}

func writeUnauthorized(w http.ResponseWriter, detail string) {
	writeProblem(w, http.StatusUnauthorized, "Unauthorized", detail)
}

func writeNotFound(w http.ResponseWriter, detail string) {
	writeProblem(w, http.StatusNotFound, "Not Found", detail)
}

func writeConflict(w http.ResponseWriter, detail string) {
	writeProblem(w, http.StatusConflict, "Conflict", detail)
}

func writeInternalError(w http.ResponseWriter, detail string) {
	writeProblem(w, http.StatusInternalServerError, "Internal Server Error", detail)
}

// SupportedEventTypes lists all event types this transmitter supports
var SupportedEventTypes = []string{
	// RISC events
	ssf.EventTypeSessionRevoked,
	ssf.EventTypeCredentialChange,
	ssf.EventTypeAccountDisabled,
	ssf.EventTypeAccountEnabled,
	ssf.EventTypeAccountPurged,
	ssf.EventTypeIdentifierChanged,
	// CAEP events
	ssf.EventTypeCAEPSessionRevoked,
	ssf.EventTypeCAEPTokenClaimsChange,
	ssf.EventTypeCAEPCredentialChange,
	ssf.EventTypeCAEPAssuranceLevelChange,
	ssf.EventTypeCAEPDeviceCompliance,
	// SSF verification
	"https://schemas.openid.net/secevent/ssf/event-type/verification",
}

const (
	PollTimeout = 30 * time.Second
)

// SSFAPIConfig holds SSF configuration options
type SSFAPIConfig struct {
	DefaultSubjects  string // "ALL" or "NONE"
	ParallelDelivery bool   // Enable parallel event delivery in background processor
}

// SSFAPIHandler handles SSF specification-compliant API endpoints
type SSFAPIHandler struct {
	Provider    *provider.OIDCProvider
	Transmitter *ssf.Transmitter
	Queries     *sqlc.Queries
	IssuerURL   string
	ClientURL   string
	Config      SSFAPIConfig

	// Long polling support
	pollWaiters map[string][]chan struct{} // streamID -> waiting channels
	pollMu      sync.RWMutex
}

// NewSSFAPIHandler creates a new SSF API handler
func NewSSFAPIHandler(p *provider.OIDCProvider, q *sqlc.Queries, issuerURL, clientURL string, cfg SSFAPIConfig) *SSFAPIHandler {
	transmitter := ssf.NewTransmitter(p.PrivateKey, p.KeyID)

	// Validate config defaults
	if cfg.DefaultSubjects == "" {
		cfg.DefaultSubjects = "NONE"
	}

	return &SSFAPIHandler{
		Provider:    p,
		Transmitter: transmitter,
		Queries:     q,
		IssuerURL:   issuerURL,
		ClientURL:   clientURL,
		Config:      cfg,
		pollWaiters: make(map[string][]chan struct{}),
	}
}

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const clientIDKey contextKey = "client_id"

// RequireAuth is a middleware that validates Bearer tokens for SSF API endpoints
func (h *SSFAPIHandler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeUnauthorized(w, "Missing Authorization header")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_request\"")
			writeUnauthorized(w, "Invalid Authorization header format")
			return
		}

		token := parts[1]

		// Validate the token using fosite's IntrospectToken
		_, ar, err := h.Provider.OAuth2.IntrospectToken(
			r.Context(),
			token,
			fosite.AccessToken,
			&openid.DefaultSession{},
		)
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
			writeUnauthorized(w, "Invalid token")
			return
		}

		// Store client_id in context for stream ownership verification
		clientID := ar.GetClient().GetID()
		ctx := context.WithValue(r.Context(), clientIDKey, clientID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// RegisterRoutes registers SSF API routes
func (h *SSFAPIHandler) RegisterRoutes(router *mux.Router) {
	// Transmitter Configuration Discovery (public endpoint)
	router.HandleFunc("/.well-known/ssf-configuration", h.HandleConfiguration).Methods("GET")

	// Stream Configuration API (requires authentication)
	// PUT = Replace (full replacement), PATCH = Update (partial update)
	router.HandleFunc("/ssf/stream", h.RequireAuth(h.HandleStream)).Methods("GET", "POST", "PUT", "PATCH", "DELETE")

	// Stream Status API (requires authentication)
	router.HandleFunc("/ssf/status", h.RequireAuth(h.HandleStatus)).Methods("GET", "POST")

	// Subject Management API (requires authentication)
	router.HandleFunc("/ssf/subjects:add", h.RequireAuth(h.HandleAddSubject)).Methods("POST")
	router.HandleFunc("/ssf/subjects:remove", h.RequireAuth(h.HandleRemoveSubject)).Methods("POST")

	// Verification API (requires authentication)
	router.HandleFunc("/ssf/verify", h.RequireAuth(h.HandleVerify)).Methods("POST")

	// Poll Delivery API (RFC 8936) - requires authentication
	// SSF 1.0 spec: Poll endpoint URLs MUST be unique per stream
	router.HandleFunc("/ssf/poll/{stream_id}", h.RequireAuth(h.HandlePoll)).Methods("POST")
	router.HandleFunc("/ssf/poll", h.RequireAuth(h.HandlePoll)).Methods("POST") // Fallback for client_id lookup

	// Internal benchmark endpoint (should be protected in production)
	router.HandleFunc("/ssf/internal/emit", h.HandleInternalEmit).Methods("POST")
}

// AuthorizationScheme represents an authorization scheme for SSF API
type AuthorizationScheme struct {
	SpecURN string `json:"spec_urn"`
}

// TransmitterConfiguration represents the SSF transmitter configuration
type TransmitterConfiguration struct {
	Issuer                   string                `json:"issuer"`
	JWKSURI                  string                `json:"jwks_uri"`
	SpecVersion              string                `json:"spec_version,omitempty"`
	DeliveryMethodsSupported []string              `json:"delivery_methods_supported,omitempty"`
	ConfigurationEndpoint    string                `json:"configuration_endpoint,omitempty"`
	StatusEndpoint           string                `json:"status_endpoint,omitempty"`
	AddSubjectEndpoint       string                `json:"add_subject_endpoint,omitempty"`
	RemoveSubjectEndpoint    string                `json:"remove_subject_endpoint,omitempty"`
	VerificationEndpoint     string                `json:"verification_endpoint,omitempty"`
	AuthorizationSchemes     []AuthorizationScheme `json:"authorization_schemes,omitempty"`
	EventsSupported          []string              `json:"events_supported,omitempty"`
	DefaultSubjects          string                `json:"default_subjects,omitempty"`
}

// HandleConfiguration handles GET /.well-known/ssf-configuration
func (h *SSFAPIHandler) HandleConfiguration(w http.ResponseWriter, r *http.Request) {
	config := TransmitterConfiguration{
		Issuer:                   h.IssuerURL,
		JWKSURI:                  h.IssuerURL + "/jwks",
		SpecVersion:              "1_0-final",
		DeliveryMethodsSupported: []string{"urn:ietf:rfc:8935", "urn:ietf:rfc:8936"},
		ConfigurationEndpoint:    h.IssuerURL + "/ssf/stream",
		StatusEndpoint:           h.IssuerURL + "/ssf/status",
		AddSubjectEndpoint:       h.IssuerURL + "/ssf/subjects:add",
		RemoveSubjectEndpoint:    h.IssuerURL + "/ssf/subjects:remove",
		VerificationEndpoint:     h.IssuerURL + "/ssf/verify",
		AuthorizationSchemes: []AuthorizationScheme{
			{SpecURN: "urn:ietf:rfc:6749"},
		},
		EventsSupported: SupportedEventTypes,
		DefaultSubjects: h.Config.DefaultSubjects,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(config)
}

// StreamConfiguration represents a stream configuration
// Note: events_supported is provided in Transmitter Metadata, not in individual stream configs
type StreamConfiguration struct {
	StreamID        string    `json:"stream_id,omitempty"`
	Iss             string    `json:"iss,omitempty"`
	Aud             []string  `json:"aud,omitempty"`
	Delivery        *Delivery `json:"delivery,omitempty"`
	EventsSupported []string  `json:"events_supported,omitempty"`
	EventsRequested []string  `json:"events_requested,omitempty"`
	EventsDelivered []string  `json:"events_delivered,omitempty"`
	Status          string    `json:"status,omitempty"`
	Description     string    `json:"description,omitempty"`
	CreatedAt       string    `json:"created_at,omitempty"`
	UpdatedAt       string    `json:"updated_at,omitempty"`
}

// Delivery represents the delivery configuration
type Delivery struct {
	Method              string `json:"method"`
	EndpointURL         string `json:"endpoint_url,omitempty"`
	AuthorizationHeader string `json:"authorization_header,omitempty"` // For Push delivery authentication
}

// CreateStreamRequest represents a stream creation request
type CreateStreamRequest struct {
	Delivery        *Delivery `json:"delivery"`
	EventsRequested []string  `json:"events_requested,omitempty"`
	Description     string    `json:"description,omitempty"`
}

// HandleStream handles stream configuration CRUD
func (h *SSFAPIHandler) HandleStream(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		h.handleGetStream(w, r)
	case "POST":
		h.handleCreateStream(w, r)
	case "PUT":
		h.handleReplaceStream(w, r)
	case "PATCH":
		h.handleUpdateStream(w, r)
	case "DELETE":
		h.handleDeleteStream(w, r)
	}
}

func (h *SSFAPIHandler) handleGetStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	streamID := r.URL.Query().Get("stream_id")

	// Get client_id from context for filtering
	clientID := getClientIDFromContext(ctx)

	if streamID == "" {
		// List streams owned by this client only
		var streams []sqlc.SsfStream
		var err error
		if clientID != "" {
			streams, err = h.Queries.GetSSFStreamByClientID(ctx, &clientID)
		} else {
			// No client_id means no streams (should not happen with RequireAuth)
			streams = []sqlc.SsfStream{}
		}
		if err != nil {
			writeInternalError(w, "Failed to list streams")
			return
		}

		configs := make([]StreamConfiguration, 0, len(streams))
		for _, s := range streams {
			configs = append(configs, h.streamToConfig(s))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(configs)
		return
	}

	// Get single stream with ownership verification
	id, err := uuid.Parse(streamID)
	if err != nil {
		writeBadRequest(w, "Invalid stream_id")
		return
	}

	stream, err := h.verifyStreamOwnership(ctx, pgtype.UUID{Bytes: id, Valid: true})
	if err != nil {
		writeNotFound(w, "Stream not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(h.streamToConfig(*stream))
}

func (h *SSFAPIHandler) handleCreateStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req CreateStreamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.Delivery == nil {
		writeBadRequest(w, "delivery is required")
		return
	}

	// Get client_id from context (set by RequireAuth middleware)
	var clientID *string
	if cid, ok := ctx.Value(clientIDKey).(string); ok {
		clientID = &cid
	}

	// Check if stream already exists for this client (409 Conflict per OIDSSF-8.1.1.1)
	if clientID != nil {
		existingStreams, err := h.Queries.GetSSFStreamByClientID(ctx, clientID)
		if err == nil && len(existingStreams) > 0 {
			writeConflict(w, "A stream configuration already exists for this client")
			return
		}
	}

	deliveryMethod := "urn:ietf:rfc:8935"
	if req.Delivery.Method != "" {
		deliveryMethod = req.Delivery.Method
	}

	// For Push delivery, endpoint_url is required
	// For Poll delivery, endpoint_url is not required (transmitter provides poll endpoint)
	isPollDelivery := deliveryMethod == "urn:ietf:rfc:8936"
	if !isPollDelivery && req.Delivery.EndpointURL == "" {
		writeBadRequest(w, "delivery.endpoint_url is required for push delivery")
		return
	}

	// Calculate events_delivered (intersection of supported and requested)
	eventsDelivered := intersectEventTypes(SupportedEventTypes, req.EventsRequested)
	if len(eventsDelivered) == 0 && len(req.EventsRequested) > 0 {
		// If requested but none match, use all supported
		eventsDelivered = SupportedEventTypes
	} else if len(req.EventsRequested) == 0 {
		// If not specified, deliver all supported events
		eventsDelivered = SupportedEventTypes
	}

	// Default audience from endpoint URL or client ID
	var audience []string
	if req.Delivery.EndpointURL != "" {
		audience = []string{req.Delivery.EndpointURL}
	}

	// For Poll delivery, use client_id as audience if no endpoint_url
	if clientID != nil && isPollDelivery && len(audience) == 0 {
		audience = []string{*clientID}
	}

	// For Poll delivery, endpoint_url is generated dynamically in streamToConfig as /ssf/poll/{stream_id}
	// For Push delivery, use the provided endpoint_url from the receiver
	endpointURL := req.Delivery.EndpointURL
	if isPollDelivery {
		endpointURL = "" // Not stored in DB; generated dynamically per SSF 1.0 spec
	}

	stream, err := h.Queries.CreateSSFStream(ctx, sqlc.CreateSSFStreamParams{
		ClientID:            clientID,
		Audience:            audience,
		DeliveryMethod:      deliveryMethod,
		EndpointUrl:         endpointURL,
		AuthorizationHeader: strPtr(req.Delivery.AuthorizationHeader),
		EventsRequested:     req.EventsRequested,
		EventsDelivered:     eventsDelivered,
		Description:         strPtr(req.Description),
	})
	if err != nil {
		writeInternalError(w, "Failed to create stream")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(h.streamToConfig(stream))
}

// ReplaceStreamRequest represents a stream replacement request (PUT)
type ReplaceStreamRequest struct {
	StreamID        string    `json:"stream_id"`
	Delivery        *Delivery `json:"delivery"`
	EventsRequested []string  `json:"events_requested,omitempty"`
	Description     string    `json:"description,omitempty"`
}

func (h *SSFAPIHandler) handleReplaceStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req ReplaceStreamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.StreamID == "" {
		writeBadRequest(w, "stream_id is required")
		return
	}

	id, err := uuid.Parse(req.StreamID)
	if err != nil {
		writeBadRequest(w, "Invalid stream_id")
		return
	}

	pgID := pgtype.UUID{Bytes: id, Valid: true}

	// Verify stream ownership
	existingStream, err := h.verifyStreamOwnership(ctx, pgID)
	if err != nil {
		writeNotFound(w, "Stream not found")
		return
	}

	// Validate delivery configuration
	if req.Delivery == nil {
		writeBadRequest(w, "delivery is required")
		return
	}

	deliveryMethod := "urn:ietf:rfc:8935"
	if req.Delivery.Method != "" {
		deliveryMethod = req.Delivery.Method
	}

	isPollDelivery := deliveryMethod == "urn:ietf:rfc:8936"
	if !isPollDelivery && req.Delivery.EndpointURL == "" {
		writeBadRequest(w, "delivery.endpoint_url is required for push delivery")
		return
	}

	// Calculate events_delivered
	eventsDelivered := intersectEventTypes(SupportedEventTypes, req.EventsRequested)
	if len(eventsDelivered) == 0 {
		eventsDelivered = SupportedEventTypes
	}

	// Set audience
	var audience []string
	if req.Delivery.EndpointURL != "" {
		audience = []string{req.Delivery.EndpointURL}
	} else if existingStream.ClientID != nil {
		audience = []string{*existingStream.ClientID}
	}

	// For Poll delivery, endpoint_url is generated dynamically in streamToConfig as /ssf/poll/{stream_id}
	endpointURL := req.Delivery.EndpointURL
	if isPollDelivery {
		endpointURL = "" // Not stored in DB; generated dynamically per SSF 1.0 spec
	}

	// Replace the stream configuration
	err = h.Queries.UpdateSSFStream(ctx, sqlc.UpdateSSFStreamParams{
		ID:                  pgID,
		Audience:            audience,
		EndpointUrl:         endpointURL,
		AuthorizationHeader: strPtr(req.Delivery.AuthorizationHeader),
		EventsRequested:     req.EventsRequested,
		EventsDelivered:     eventsDelivered,
		Description:         strPtr(req.Description),
	})
	if err != nil {
		writeInternalError(w, "Failed to replace stream")
		return
	}

	// Get updated stream
	stream, _ := h.Queries.GetSSFStream(ctx, pgID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(h.streamToConfig(stream))
}

func (h *SSFAPIHandler) handleUpdateStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		StreamID            string   `json:"stream_id"`
		EventsRequested     []string `json:"events_requested,omitempty"`
		Description         string   `json:"description,omitempty"`
		EndpointURL         string   `json:"endpoint_url,omitempty"`
		AuthorizationHeader string   `json:"authorization_header,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.StreamID == "" {
		writeBadRequest(w, "stream_id is required")
		return
	}

	id, err := uuid.Parse(req.StreamID)
	if err != nil {
		writeBadRequest(w, "Invalid stream_id")
		return
	}

	pgID := pgtype.UUID{Bytes: id, Valid: true}

	// Verify stream ownership
	stream, err := h.verifyStreamOwnership(ctx, pgID)
	if err != nil {
		writeNotFound(w, "Stream not found")
		return
	}

	// Update fields
	audience := stream.Audience
	endpointURL := stream.EndpointUrl
	eventsRequested := stream.EventsRequested
	description := stream.Description
	authHeader := stream.AuthorizationHeader

	if req.EndpointURL != "" {
		endpointURL = req.EndpointURL
		audience = []string{req.EndpointURL}
	}

	if len(req.EventsRequested) > 0 {
		eventsRequested = req.EventsRequested
	}

	if req.Description != "" {
		description = strPtr(req.Description)
	}

	if req.AuthorizationHeader != "" {
		authHeader = strPtr(req.AuthorizationHeader)
	}

	eventsDelivered := intersectEventTypes(SupportedEventTypes, eventsRequested)
	if len(eventsDelivered) == 0 {
		eventsDelivered = SupportedEventTypes
	}

	err = h.Queries.UpdateSSFStream(ctx, sqlc.UpdateSSFStreamParams{
		ID:                  pgID,
		Audience:            audience,
		EndpointUrl:         endpointURL,
		AuthorizationHeader: authHeader,
		EventsRequested:     eventsRequested,
		EventsDelivered:     eventsDelivered,
		Description:         description,
	})
	if err != nil {
		writeInternalError(w, "Failed to update stream")
		return
	}

	// Get updated stream
	updatedStream, _ := h.Queries.GetSSFStream(ctx, pgID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(h.streamToConfig(updatedStream))
}

func (h *SSFAPIHandler) handleDeleteStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	streamID := r.URL.Query().Get("stream_id")

	if streamID == "" {
		writeBadRequest(w, "stream_id is required")
		return
	}

	id, err := uuid.Parse(streamID)
	if err != nil {
		writeBadRequest(w, "Invalid stream_id")
		return
	}

	pgID := pgtype.UUID{Bytes: id, Valid: true}

	// Verify stream ownership before deleting (also serves as 404 check per OIDSSF-8.1.1.5)
	_, err = h.verifyStreamOwnership(ctx, pgID)
	if err != nil {
		writeNotFound(w, "Stream not found")
		return
	}

	err = h.Queries.DeleteSSFStream(ctx, pgID)
	if err != nil {
		writeInternalError(w, "Failed to delete stream")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// StreamStatus represents a stream status
type StreamStatus struct {
	StreamID string `json:"stream_id"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
}

// HandleStatus handles stream status management
func (h *SSFAPIHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == "GET" {
		streamID := r.URL.Query().Get("stream_id")
		if streamID == "" {
			writeBadRequest(w, "stream_id is required")
			return
		}

		id, err := uuid.Parse(streamID)
		if err != nil {
			writeBadRequest(w, "Invalid stream_id")
			return
		}

		// Verify stream ownership
		stream, err := h.verifyStreamOwnership(ctx, pgtype.UUID{Bytes: id, Valid: true})
		if err != nil {
			writeNotFound(w, "Stream not found")
			return
		}

		status := StreamStatus{
			StreamID: streamID,
			Status:   stream.Status,
		}
		if stream.StatusReason != nil {
			status.Reason = *stream.StatusReason
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
		return
	}

	// POST - update status
	var req StreamStatus
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.StreamID == "" {
		writeBadRequest(w, "stream_id is required")
		return
	}

	if req.Status != "enabled" && req.Status != "paused" && req.Status != "disabled" {
		writeBadRequest(w, "status must be one of: enabled, paused, disabled")
		return
	}

	id, err := uuid.Parse(req.StreamID)
	if err != nil {
		writeBadRequest(w, "Invalid stream_id")
		return
	}

	pgID := pgtype.UUID{Bytes: id, Valid: true}

	// Verify stream ownership
	stream, err := h.verifyStreamOwnership(ctx, pgID)
	if err != nil {
		writeNotFound(w, "Stream not found")
		return
	}

	// Validate state transition
	if !isValidStateTransition(stream.Status, req.Status) {
		writeBadRequest(w, fmt.Sprintf("Invalid state transition from '%s' to '%s'", stream.Status, req.Status))
		return
	}

	err = h.Queries.UpdateSSFStreamStatus(ctx, sqlc.UpdateSSFStreamStatusParams{
		ID:           pgID,
		Status:       req.Status,
		StatusReason: strPtr(req.Reason),
	})
	if err != nil {
		writeInternalError(w, "Failed to update status")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(req)
}

// SubjectRequest represents a subject add/remove request
type SubjectRequest struct {
	StreamID string                 `json:"stream_id"`
	Subject  map[string]interface{} `json:"subject"`
	Verified bool                   `json:"verified,omitempty"`
}

// HandleAddSubject handles adding a subject to a stream
func (h *SSFAPIHandler) HandleAddSubject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.StreamID == "" || req.Subject == nil {
		writeBadRequest(w, "stream_id and subject are required")
		return
	}

	streamUUID, err := uuid.Parse(req.StreamID)
	if err != nil {
		writeBadRequest(w, "Invalid stream_id")
		return
	}

	pgID := pgtype.UUID{Bytes: streamUUID, Valid: true}

	// Verify stream ownership
	_, err = h.verifyStreamOwnership(ctx, pgID)
	if err != nil {
		writeNotFound(w, "Stream not found")
		return
	}

	format, _ := req.Subject["format"].(string)
	identifier := extractSubjectIdentifier(req.Subject)

	if format == "" || identifier == "" {
		writeBadRequest(w, "subject must have format and identifier")
		return
	}

	_, err = h.Queries.CreateSSFStreamSubject(ctx, sqlc.CreateSSFStreamSubjectParams{
		StreamID:          pgID,
		SubjectFormat:     format,
		SubjectIdentifier: identifier,
		Verified:          req.Verified,
	})
	if err != nil {
		writeInternalError(w, "Failed to add subject")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HandleRemoveSubject handles removing a subject from a stream
func (h *SSFAPIHandler) HandleRemoveSubject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.StreamID == "" || req.Subject == nil {
		writeBadRequest(w, "stream_id and subject are required")
		return
	}

	streamUUID, err := uuid.Parse(req.StreamID)
	if err != nil {
		writeBadRequest(w, "Invalid stream_id")
		return
	}

	pgID := pgtype.UUID{Bytes: streamUUID, Valid: true}

	// Verify stream ownership
	_, err = h.verifyStreamOwnership(ctx, pgID)
	if err != nil {
		writeNotFound(w, "Stream not found")
		return
	}

	format, _ := req.Subject["format"].(string)
	identifier := extractSubjectIdentifier(req.Subject)

	err = h.Queries.DeleteSSFStreamSubject(ctx, sqlc.DeleteSSFStreamSubjectParams{
		StreamID:          pgID,
		SubjectFormat:     format,
		SubjectIdentifier: identifier,
	})
	if err != nil {
		writeInternalError(w, "Failed to remove subject")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// VerifyRequest represents a verification request
type VerifyRequest struct {
	StreamID string `json:"stream_id"`
	State    string `json:"state,omitempty"`
}

// HandleVerify handles verification event requests
func (h *SSFAPIHandler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.StreamID == "" {
		writeBadRequest(w, "stream_id is required")
		return
	}

	streamUUID, err := uuid.Parse(req.StreamID)
	if err != nil {
		writeBadRequest(w, "Invalid stream_id")
		return
	}

	pgID := pgtype.UUID{Bytes: streamUUID, Valid: true}

	// Verify stream ownership
	stream, err := h.verifyStreamOwnership(ctx, pgID)
	if err != nil {
		writeNotFound(w, "Stream not found")
		return
	}

	if stream.Status != "enabled" {
		writeConflict(w, "Stream is not enabled")
		return
	}

	// Create verification event
	verificationEvent := map[string]interface{}{}
	if req.State != "" {
		verificationEvent["state"] = req.State
	}

	set := ssf.NewSET(
		h.IssuerURL,
		stream.Audience,
		"https://schemas.openid.net/secevent/ssf/event-type/verification",
		verificationEvent,
	)

	// SSF requires sub_id in all SETs including verification events
	// Use opaque format with stream_id as the identifier
	set.SubID = &ssf.SubID{
		Format: "opaque",
		ID:     req.StreamID,
	}

	// Create signed JWT token
	token, err := set.ToJWT(h.Transmitter.GetPrivateKey(), h.Transmitter.GetKeyID())
	if err != nil {
		writeInternalError(w, "Failed to create verification event")
		return
	}

	// Create event record
	payload, _ := json.Marshal(set)
	ssfEvent, err := h.Queries.CreateSSFEvent(ctx, sqlc.CreateSSFEventParams{
		EventType:         "https://schemas.openid.net/secevent/ssf/event-type/verification",
		SubjectIdentifier: strPtr(req.StreamID),
		Payload:           payload,
	})
	if err != nil {
		writeInternalError(w, "Failed to create verification event")
		return
	}

	// Create delivery record
	_, err = h.Queries.CreateSSFEventDelivery(ctx, sqlc.CreateSSFEventDeliveryParams{
		EventID:  ssfEvent.ID,
		StreamID: stream.ID,
		Jti:      set.JTI,
		SetToken: token,
		Status:   "queued",
	})
	if err != nil {
		writeInternalError(w, "Failed to store verification event")
		return
	}

	// Notify waiting poll clients for Poll delivery streams
	if stream.DeliveryMethod == "urn:ietf:rfc:8936" {
		h.NotifyPollWaiters(req.StreamID)
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleInternalEmit handles internal event emission for benchmarking
// POST /ssf/internal/emit
// This endpoint is for internal/benchmark use only and should be protected in production.
func (h *SSFAPIHandler) HandleInternalEmit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EventType string                 `json:"event_type"`
		SubjectID string                 `json:"subject_id"`
		EventData map[string]interface{} `json:"event_data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "Invalid request body")
		return
	}

	if req.EventType == "" || req.SubjectID == "" {
		writeBadRequest(w, "event_type and subject_id are required")
		return
	}

	result, err := h.EmitEventForSubject(r.Context(), req.EventType, req.SubjectID, req.EventData)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "Internal Server Error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// registerPollWaiter registers a waiting channel for long polling and returns cleanup function
func (h *SSFAPIHandler) registerPollWaiter(streamID string) (chan struct{}, func()) {
	ch := make(chan struct{}, 1) // Buffer 1 to prevent sender blocking

	h.pollMu.Lock()
	h.pollWaiters[streamID] = append(h.pollWaiters[streamID], ch)
	h.pollMu.Unlock()

	// Cleanup function to remove channel from waiters
	cleanup := func() {
		h.pollMu.Lock()
		defer h.pollMu.Unlock()
		waiters := h.pollWaiters[streamID]
		for i, w := range waiters {
			if w == ch {
				h.pollWaiters[streamID] = append(waiters[:i], waiters[i+1:]...)
				break
			}
		}
		if len(h.pollWaiters[streamID]) == 0 {
			delete(h.pollWaiters, streamID)
		}
	}

	return ch, cleanup
}

// NotifyPollWaiters notifies all waiting poll clients for a stream
func (h *SSFAPIHandler) NotifyPollWaiters(streamID string) {
	h.pollMu.RLock()
	waiters := h.pollWaiters[streamID]
	h.pollMu.RUnlock()

	for _, ch := range waiters {
		select {
		case ch <- struct{}{}:
		default: // Already notified, skip
		}
	}
}

// PollRequest represents RFC 8936 poll request (handler-level)
type PollRequestBody struct {
	StreamID          string                  `json:"stream_id"`
	Ack               []string                `json:"ack,omitempty"`
	SetErrs           map[string]ssf.SetError `json:"setErrs,omitempty"`
	MaxEvents         int                     `json:"maxEvents,omitempty"`
	ReturnImmediately bool                    `json:"returnImmediately,omitempty"`
}

// HandlePoll handles RFC 8936 Poll requests
// SSF 1.0 spec: Poll endpoint URLs MUST be unique per stream for a given Receiver
func (h *SSFAPIHandler) HandlePoll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req PollRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Empty body is valid for initial poll (RFC 8936)
		req = PollRequestBody{}
	}

	// Priority for stream identification:
	// 1. URL path variable (spec-compliant: /ssf/poll/{stream_id})
	// 2. Request body stream_id
	// 3. Query parameter stream_id
	// 4. Fallback: client_id lookup (single stream only)
	streamID := mux.Vars(r)["stream_id"]
	if streamID == "" {
		streamID = req.StreamID
	}
	if streamID == "" {
		streamID = r.URL.Query().Get("stream_id")
	}

	var stream *sqlc.SsfStream

	if streamID != "" {
		// Explicit stream_id provided - verify ownership
		streamUUID, err := uuid.Parse(streamID)
		if err != nil {
			writeBadRequest(w, "Invalid stream_id")
			return
		}
		pgID := pgtype.UUID{Bytes: streamUUID, Valid: true}
		stream, err = h.verifyStreamOwnership(ctx, pgID)
		if err != nil {
			writeNotFound(w, "Stream not found")
			return
		}
	} else {
		// No stream_id - fallback to client_id lookup
		clientID := getClientIDFromContext(ctx)
		if clientID == "" {
			writeBadRequest(w, "Unable to identify stream: no stream_id provided and no client_id in token")
			return
		}
		streams, err := h.Queries.GetSSFStreamByClientID(ctx, &clientID)
		if err != nil || len(streams) == 0 {
			writeNotFound(w, "No stream found for this client")
			return
		}
		if len(streams) > 1 {
			// Multiple streams exist - require explicit stream_id
			writeBadRequest(w, "Multiple streams exist for this client. Please specify stream_id in the URL path: /ssf/poll/{stream_id}")
			return
		}
		// Single stream - use it
		stream = &streams[0]
		streamID = uuidToString(stream.ID)
	}

	if stream.DeliveryMethod != "urn:ietf:rfc:8936" {
		writeBadRequest(w, "Stream is not configured for poll delivery")
		return
	}

	if stream.Status != "enabled" {
		writeConflict(w, "Stream is not enabled")
		return
	}

	// Process acknowledgments - mark as acked in database
	if len(req.Ack) > 0 {
		if err := h.Queries.AckSSFDeliveries(ctx, sqlc.AckSSFDeliveriesParams{
			StreamID: stream.ID,
			Column2:  req.Ack,
		}); err != nil {
			// Log but continue - acks are best-effort
			fmt.Printf("Poll: Failed to acknowledge SETs: %v\n", err)
		}
	}

	// Process error reports (RFC 8936: transmitter should log but not retry)
	for jti, setErr := range req.SetErrs {
		fmt.Printf("Poll: SET error reported for JTI %s: %s - %s\n", jti, setErr.Err, setErr.Description)
		// Mark as acked to remove from poll queue
		_ = h.Queries.AckSSFDelivery(ctx, sqlc.AckSSFDeliveryParams{
			StreamID: stream.ID,
			Jti:      jti,
		})
	}

	// Determine max events to return
	maxEvents := req.MaxEvents
	if maxEvents <= 0 {
		maxEvents = 100 // Default max
	}

	// Fetch pending SETs from database
	pollEvents, err := h.Queries.GetPollSSFDeliveries(ctx, sqlc.GetPollSSFDeliveriesParams{
		StreamID: stream.ID,
		Limit:    int32(maxEvents + 1), // +1 to check if more available
	})
	if err != nil {
		writeInternalError(w, "Failed to fetch poll events")
		return
	}

	// Long polling: wait if no events and returnImmediately is false
	if len(pollEvents) == 0 && !req.ReturnImmediately {
		ch, cleanup := h.registerPollWaiter(streamID)
		defer cleanup()

		select {
		case <-ch:
			// Notification received - re-query database
			pollEvents, err = h.Queries.GetPollSSFDeliveries(ctx, sqlc.GetPollSSFDeliveriesParams{
				StreamID: stream.ID,
				Limit:    int32(maxEvents + 1),
			})
			if err != nil {
				writeInternalError(w, "Failed to fetch poll events")
				return
			}
		case <-time.After(PollTimeout):
			// Timeout - return empty response
		case <-ctx.Done():
			// Client disconnected
			return
		}
	}

	// Build response
	sets := make(map[string]string)
	moreAvailable := false

	for i, event := range pollEvents {
		if i >= maxEvents {
			moreAvailable = true
			break
		}
		sets[event.Jti] = event.SetToken
	}

	pollResp := &ssf.PollResponse{
		Sets:          sets,
		MoreAvailable: moreAvailable,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(pollResp)
}

// LoadStreamsFromDB loads all enabled streams from database and adds to transmitter
func (h *SSFAPIHandler) LoadStreamsFromDB(ctx context.Context) error {
	streams, err := h.Queries.ListSSFStreamsByStatus(ctx, "enabled")
	if err != nil {
		return err
	}

	log.Printf("SSF: Loaded %d streams from database", len(streams))
	return nil
}

// Helper functions

func (h *SSFAPIHandler) streamToConfig(s sqlc.SsfStream) StreamConfiguration {
	streamID := uuidToString(s.ID)

	// For Poll delivery, generate unique endpoint URL per stream (SSF 1.0 spec requirement)
	endpointURL := s.EndpointUrl
	if s.DeliveryMethod == "urn:ietf:rfc:8936" {
		endpointURL = h.IssuerURL + "/ssf/poll/" + streamID
	}

	config := StreamConfiguration{
		StreamID: streamID,
		Iss:      h.IssuerURL,
		Aud:      s.Audience,
		Delivery: &Delivery{
			Method:      s.DeliveryMethod,
			EndpointURL: endpointURL,
		},
		EventsSupported: SupportedEventTypes,
		EventsRequested: s.EventsRequested,
		EventsDelivered: s.EventsDelivered,
		Status:          s.Status,
		CreatedAt:       s.CreatedAt.Time.Format(time.RFC3339),
		UpdatedAt:       s.UpdatedAt.Time.Format(time.RFC3339),
	}
	if s.Description != nil {
		config.Description = *s.Description
	}
	return config
}

// createEventAndDelivery creates an event record and its delivery record
// Returns the delivery ID for immediate delivery processing
func (h *SSFAPIHandler) createEventAndDelivery(ctx context.Context, streamID pgtype.UUID, eventType, jti, subjectID, setToken string, payload []byte, status string) (pgtype.UUID, error) {
	// Create event record
	ssfEvent, err := h.Queries.CreateSSFEvent(ctx, sqlc.CreateSSFEventParams{
		EventType:         eventType,
		SubjectIdentifier: strPtr(subjectID),
		Payload:           payload,
	})
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("failed to create event: %w", err)
	}

	// Create delivery record
	delivery, err := h.Queries.CreateSSFEventDelivery(ctx, sqlc.CreateSSFEventDeliveryParams{
		EventID:  ssfEvent.ID,
		StreamID: streamID,
		Jti:      jti,
		SetToken: setToken,
		Status:   status,
	})
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("failed to create delivery: %w", err)
	}

	return delivery.ID, nil
}

// processDeliveryByID locks and processes a delivery by ID
// Uses FOR UPDATE SKIP LOCKED to avoid conflicts with DB poller
// Returns nil if delivery is already being processed or completed
func (h *SSFAPIHandler) processDeliveryByID(ctx context.Context, deliveryID pgtype.UUID) error {
	// Lock and fetch delivery atomically
	// Returns no rows if: already locked by poller, not queued, or not push delivery
	delivery, err := h.Queries.LockSSFEventDeliveryForProcessing(ctx, deliveryID)
	if err != nil {
		// No rows = already processed or locked by poller, not an error
		return nil
	}

	// Convert to GetPendingSSFDeliveriesRow for processOneDelivery
	row := sqlc.GetPendingSSFDeliveriesRow(delivery)

	// Process the delivery
	sent, _ := h.processOneDelivery(ctx, row)
	if !sent {
		return fmt.Errorf("delivery not sent")
	}

	return nil
}

func uuidToString(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	u, _ := uuid.FromBytes(id.Bytes[:])
	return u.String()
}

func intersectEventTypes(supported, requested []string) []string {
	if len(requested) == 0 {
		return supported
	}

	supportedSet := make(map[string]bool)
	for _, e := range supported {
		supportedSet[e] = true
	}

	result := make([]string, 0)
	for _, e := range requested {
		if supportedSet[e] {
			result = append(result, e)
		}
	}
	return result
}

func extractSubjectIdentifier(subject map[string]interface{}) string {
	// Try common identifier fields
	if email, ok := subject["email"].(string); ok {
		return email
	}
	if phone, ok := subject["phone_number"].(string); ok {
		return phone
	}
	if id, ok := subject["id"].(string); ok {
		return id
	}
	if sub, ok := subject["sub"].(string); ok {
		return sub
	}
	return ""
}

// isValidStateTransition validates stream state transitions according to SSF spec
// Valid transitions:
//   - enabled → paused (pause stream)
//   - enabled → disabled (disable stream)
//   - paused → enabled (resume stream)
//   - paused → disabled (disable stream)
//   - disabled → enabled (re-enable stream)
//
// Invalid transitions:
//   - disabled → paused (must go through enabled first)
func isValidStateTransition(from, to string) bool {
	// Same state is always allowed (no-op)
	if from == to {
		return true
	}

	switch from {
	case "enabled":
		// enabled can transition to paused or disabled
		return to == "paused" || to == "disabled"
	case "paused":
		// paused can transition to enabled (resume) or disabled
		return to == "enabled" || to == "disabled"
	case "disabled":
		// disabled can only transition to enabled (re-enable)
		return to == "enabled"
	default:
		// Unknown state
		return false
	}
}

// MaxConcurrentDeliveries limits the number of concurrent goroutines for parallel delivery
const MaxConcurrentDeliveries = 50

// ProcessPendingEvents fetches pending deliveries from DB and transmits them
// This is the background processor for Push delivery (async)
// Uses parallel processing with worker pool for high throughput
func (h *SSFAPIHandler) ProcessPendingEvents(ctx context.Context) (int, int) {
	// Fetch pending deliveries (up to 100 at a time)
	// Uses FOR UPDATE SKIP LOCKED for safe multi-instance processing
	deliveries, err := h.Queries.GetPendingSSFDeliveries(ctx, 100)
	if err != nil {
		return 0, 0
	}

	if len(deliveries) == 0 {
		return 0, 0
	}

	// Process deliveries in parallel if configured
	if h.Config.ParallelDelivery {
		return h.processDeliveriesParallel(ctx, deliveries)
	}
	return h.processDeliveriesSequential(ctx, deliveries)
}

// processDeliveriesParallel processes deliveries using a worker pool
func (h *SSFAPIHandler) processDeliveriesParallel(ctx context.Context, deliveries []sqlc.GetPendingSSFDeliveriesRow) (int, int) {
	type result struct {
		sent   bool
		failed bool
	}

	results := make(chan result, len(deliveries))
	sem := make(chan struct{}, MaxConcurrentDeliveries)

	for _, delivery := range deliveries {
		sem <- struct{}{} // Acquire semaphore
		go func(d sqlc.GetPendingSSFDeliveriesRow) {
			defer func() { <-sem }() // Release semaphore
			sent, failed := h.processOneDelivery(ctx, d)
			results <- result{sent: sent, failed: failed}
		}(delivery)
	}

	// Collect results
	sent := 0
	failed := 0
	for i := 0; i < len(deliveries); i++ {
		r := <-results
		if r.sent {
			sent++
		}
		if r.failed {
			failed++
		}
	}

	return sent, failed
}

// processDeliveriesSequential processes deliveries one at a time
func (h *SSFAPIHandler) processDeliveriesSequential(ctx context.Context, deliveries []sqlc.GetPendingSSFDeliveriesRow) (int, int) {
	sent := 0
	failed := 0

	for _, delivery := range deliveries {
		s, f := h.processOneDelivery(ctx, delivery)
		if s {
			sent++
		}
		if f {
			failed++
		}
	}

	return sent, failed
}

// processOneDelivery processes a single delivery and returns (sent, failed)
func (h *SSFAPIHandler) processOneDelivery(ctx context.Context, delivery sqlc.GetPendingSSFDeliveriesRow) (bool, bool) {
	// Use pre-signed token from delivery record
	var authHeader string
	if delivery.AuthorizationHeader != nil {
		authHeader = *delivery.AuthorizationHeader
	}

	// Transmit using the shared Transmitter (connection pooling)
	result := h.Transmitter.TransmitPreSignedToken(
		delivery.SetToken,
		delivery.Jti,
		delivery.EndpointUrl,
		authHeader,
	)

	if result.Success {
		_ = h.Queries.MarkSSFDeliverySent(ctx, delivery.ID)
		return true, false
	}

	// Failed - calculate exponential backoff
	backoffSeconds := 60 * (1 << delivery.Attempts)
	if backoffSeconds > 3600 {
		backoffSeconds = 3600
	}

	var errMsg string
	if result.Error != nil {
		errMsg = result.Error.Error()
	} else {
		errMsg = fmt.Sprintf("status code: %d", result.StatusCode)
	}

	_ = h.Queries.MarkSSFDeliveryFailed(ctx, sqlc.MarkSSFDeliveryFailedParams{
		ID:        delivery.ID,
		LastError: strPtr(errMsg),
		Column3:   int32(backoffSeconds),
	})
	return false, true
}

// StartDBQueueProcessor starts a background goroutine that processes pending events
func (h *SSFAPIHandler) StartDBQueueProcessor(ctx context.Context, interval time.Duration) chan struct{} {
	stop := make(chan struct{})

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				h.ProcessPendingEvents(ctx)
			case <-stop:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	return stop
}

// ===================
// Subject-based Event Emission
// ===================

// EmitResult contains the result of an event emission
type EmitResult struct {
	StreamCount  int    `json:"stream_count"`
	SuccessCount int    `json:"success_count"`
	FailureCount int    `json:"failure_count"`
	DurationMs   int64  `json:"duration_ms"`
	Error        string `json:"error,omitempty"` // First error encountered
}

// EmitEventForSubject emits an event to all streams that have subscribed to the given subject.
// This is the main entry point for subject-based event filtering as per SSF specification.
// Events are queued asynchronously for delivery:
//   - Push streams: queued with status "queued", then immediately delivered via goroutine
//   - Poll streams: stored with status "sent" for client polling
//
// Returns EmitResult with queuing information.
func (h *SSFAPIHandler) EmitEventForSubject(ctx context.Context, eventType string, subjectID string, eventData map[string]interface{}) (*EmitResult, error) {
	startTime := time.Now()

	// Query streams that have this subject registered
	streams, err := h.Queries.GetStreamsBySubjectIdentifier(ctx, subjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get streams for subject: %w", err)
	}

	result := &EmitResult{
		StreamCount: len(streams),
	}

	if len(streams) == 0 {
		result.DurationMs = time.Since(startTime).Milliseconds()
		return result, nil
	}

	if eventData == nil {
		eventData = make(map[string]interface{})
	}

	// Collect Push delivery IDs for immediate delivery
	var pushDeliveryIDs []pgtype.UUID
	// Collect Poll stream IDs for notification
	var pollStreamIDs []string

	// Queue events for each stream
	for _, stream := range streams {
		streamID := uuid.UUID(stream.ID.Bytes).String()

		// Create SET for this stream
		set := ssf.NewSET(h.IssuerURL, []string{}, eventType, eventData)
		set.SubID = &ssf.SubID{
			Format: "iss_sub",
			Iss:    h.IssuerURL,
			Sub:    subjectID,
		}
		if stream.ClientID != nil {
			set.Audience = []string{*stream.ClientID}
		}

		// Create signed JWT token
		token, err := set.ToJWT(h.Transmitter.GetPrivateKey(), h.Transmitter.GetKeyID())
		if err != nil {
			result.FailureCount++
			if result.Error == "" {
				result.Error = "failed to create JWT: " + err.Error()
			}
			continue
		}

		// Marshal SET payload
		payload, err := json.Marshal(set)
		if err != nil {
			result.FailureCount++
			if result.Error == "" {
				result.Error = "failed to marshal SET: " + err.Error()
			}
			continue
		}

		// Determine status based on delivery method
		isPushDelivery := stream.DeliveryMethod == "urn:ietf:rfc:8935"
		status := "queued"
		if !isPushDelivery {
			status = "sent"
		}

		// Create event and delivery records
		deliveryID, err := h.createEventAndDelivery(ctx, stream.ID, eventType, set.JTI, subjectID, token, payload, status)
		if err != nil {
			result.FailureCount++
			if result.Error == "" {
				result.Error = "failed to create event: " + err.Error()
			}
		} else {
			result.SuccessCount++
			if isPushDelivery {
				pushDeliveryIDs = append(pushDeliveryIDs, deliveryID)
			} else {
				pollStreamIDs = append(pollStreamIDs, streamID)
			}
		}
	}

	result.DurationMs = time.Since(startTime).Milliseconds()

	// Process immediate delivery for Push streams
	for _, deliveryID := range pushDeliveryIDs {
		if err := h.processDeliveryByID(ctx, deliveryID); err != nil {
			log.Printf("SSF: Initial delivery failed (will retry via polling): %v", err)
		}
	}

	// Notify waiting poll clients for Poll streams
	for _, pollStreamID := range pollStreamIDs {
		h.NotifyPollWaiters(pollStreamID)
	}

	return result, nil
}

// EmitEventToStream emits an event directly to a specific stream.
// Used for testing and direct stream targeting (e.g., from Portal UI).
// Unlike EmitEventForSubject, this targets a specific stream regardless of subject subscription.
func (h *SSFAPIHandler) EmitEventToStream(ctx context.Context, streamID string, eventType string, subjectID string, eventData map[string]interface{}) (*EmitResult, error) {
	startTime := time.Now()

	// Parse stream ID
	streamUUID, err := uuid.Parse(streamID)
	if err != nil {
		return nil, fmt.Errorf("invalid stream ID: %w", err)
	}

	// Get stream details
	stream, err := h.Queries.GetSSFStream(ctx, pgtype.UUID{Bytes: streamUUID, Valid: true})
	if err != nil {
		return nil, fmt.Errorf("stream not found: %w", err)
	}

	if stream.Status != "enabled" {
		return nil, fmt.Errorf("stream is not enabled")
	}

	result := &EmitResult{
		StreamCount: 1,
	}

	if eventData == nil {
		eventData = make(map[string]interface{})
	}

	// Create SET
	set := ssf.NewSET(h.IssuerURL, []string{}, eventType, eventData)
	if subjectID != "" {
		set.SubID = &ssf.SubID{
			Format: "iss_sub",
			Iss:    h.IssuerURL,
			Sub:    subjectID,
		}
	}
	if stream.ClientID != nil {
		set.Audience = []string{*stream.ClientID}
	}

	// Create signed JWT token
	token, err := set.ToJWT(h.Transmitter.GetPrivateKey(), h.Transmitter.GetKeyID())
	if err != nil {
		result.FailureCount++
		result.Error = "failed to create JWT: " + err.Error()
		result.DurationMs = time.Since(startTime).Milliseconds()
		return result, nil
	}

	// Marshal SET payload
	payload, err := json.Marshal(set)
	if err != nil {
		result.FailureCount++
		result.Error = "failed to marshal SET: " + err.Error()
		result.DurationMs = time.Since(startTime).Milliseconds()
		return result, nil
	}

	// Determine status based on delivery method
	isPushDelivery := stream.DeliveryMethod == "urn:ietf:rfc:8935"
	status := "queued"
	if !isPushDelivery {
		status = "sent"
	}

	// Create event and delivery records
	deliveryID, err := h.createEventAndDelivery(ctx, stream.ID, eventType, set.JTI, subjectID, token, payload, status)
	if err != nil {
		result.FailureCount++
		result.Error = "failed to create event: " + err.Error()
	} else {
		result.SuccessCount++
		if isPushDelivery {
			if err := h.processDeliveryByID(ctx, deliveryID); err != nil {
				log.Printf("SSF: Initial delivery failed (will retry via polling): %v", err)
			}
		} else {
			h.NotifyPollWaiters(streamID)
		}
	}

	result.DurationMs = time.Since(startTime).Milliseconds()
	return result, nil
}
