package handler

import (
	"crypto/rsa"
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/handler"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/portal"
	"github.com/lab-matsuura/oidc-ssf/idp/internal/storage/postgres/sqlc"
	"github.com/lab-matsuura/oidc-ssf/pkg/ssf"
)

// SupportedEventTypes for admin UI
var SupportedEventTypes = []EventTypeInfo{
	{URI: ssf.EventTypeCAEPSessionRevoked, Name: "Session Revoked", Description: "User session has been terminated"},
	{URI: ssf.EventTypeCAEPCredentialChange, Name: "Credential Change", Description: "User credentials have been changed"},
	{URI: ssf.EventTypeCAEPTokenClaimsChange, Name: "Token Claims Change", Description: "Token claims have changed"},
	{URI: ssf.EventTypeCAEPAssuranceLevelChange, Name: "Assurance Level Change", Description: "User assurance level has changed"},
	{URI: ssf.EventTypeCAEPDeviceCompliance, Name: "Device Compliance", Description: "Device compliance status has changed"},
	{URI: ssf.EventTypeAccountDisabled, Name: "Account Disabled", Description: "User account has been disabled"},
	{URI: ssf.EventTypeAccountEnabled, Name: "Account Enabled", Description: "User account has been enabled"},
	{URI: ssf.EventTypeAccountPurged, Name: "Account Purged", Description: "User account has been deleted"},
	{URI: ssf.EventTypeIdentifierChanged, Name: "Identifier Changed", Description: "User identifier has changed"},
	{URI: ssf.EventTypeCredentialCompromise, Name: "Credential Compromise", Description: "User credentials may have been compromised"},
}

type EventTypeInfo struct {
	URI         string
	Name        string
	Description string
}

type SSFHandler struct {
	queries       *sqlc.Queries
	templates     *template.Template
	issuerURL     string
	privateKey    *rsa.PrivateKey
	keyID         string
	ssfAPIHandler *handler.SSFAPIHandler
}

func NewSSFHandler(queries *sqlc.Queries, templates *template.Template, issuerURL string, privateKey *rsa.PrivateKey, keyID string) *SSFHandler {
	return &SSFHandler{
		queries:    queries,
		templates:  templates,
		issuerURL:  issuerURL,
		privateKey: privateKey,
		keyID:      keyID,
	}
}

// SetSSFAPIHandler sets the SSF API handler for event emission
func (h *SSFHandler) SetSSFAPIHandler(ssfAPIHandler *handler.SSFAPIHandler) {
	h.ssfAPIHandler = ssfAPIHandler
}

type StreamView struct {
	ID              string
	Audience        []string
	DeliveryMethod  string
	EndpointURL     string
	EventsRequested []string
	EventsDelivered []string
	Status          string
	StatusReason    string
	Description     string
	CreatedAt       string
	UpdatedAt       string
	EventCount      int64
}

type EventLogView struct {
	ID                string
	StreamID          string
	EventType         string
	EventTypeName     string
	JTI               string
	SubjectIdentifier string
	Status            string
	Attempts          int32
	LastError         string
	CreatedAt         string
	SentAt            string
}

func convertStream(s sqlc.SsfStream) StreamView {
	createdAt := ""
	if s.CreatedAt.Valid {
		createdAt = s.CreatedAt.Time.Format("2006-01-02 15:04")
	}
	updatedAt := ""
	if s.UpdatedAt.Valid {
		updatedAt = s.UpdatedAt.Time.Format("2006-01-02 15:04")
	}

	view := StreamView{
		ID:              uuidToString(s.ID),
		Audience:        s.Audience,
		DeliveryMethod:  s.DeliveryMethod,
		EndpointURL:     s.EndpointUrl,
		EventsRequested: s.EventsRequested,
		EventsDelivered: s.EventsDelivered,
		Status:          s.Status,
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}

	if s.StatusReason != nil {
		view.StatusReason = *s.StatusReason
	}
	if s.Description != nil {
		view.Description = *s.Description
	}

	return view
}

func convertEventDelivery(e sqlc.ListSSFEventDeliveriesByStreamRow) EventLogView {
	createdAt := ""
	if e.CreatedAt.Valid {
		createdAt = e.CreatedAt.Time.Format("2006-01-02 15:04:05")
	}
	sentAt := ""
	if e.SentAt.Valid {
		sentAt = e.SentAt.Time.Format("2006-01-02 15:04:05")
	}

	view := EventLogView{
		ID:        uuidToString(e.ID),
		StreamID:  uuidToString(e.StreamID),
		EventType: e.EventType,
		JTI:       e.Jti,
		Status:    e.Status,
		Attempts:  e.Attempts,
		CreatedAt: createdAt,
		SentAt:    sentAt,
	}

	for _, et := range SupportedEventTypes {
		if et.URI == e.EventType {
			view.EventTypeName = et.Name
			break
		}
	}
	if view.EventTypeName == "" {
		view.EventTypeName = e.EventType
	}

	if e.SubjectIdentifier != nil {
		view.SubjectIdentifier = *e.SubjectIdentifier
	}
	if e.LastError != nil {
		view.LastError = *e.LastError
	}

	return view
}

func convertEventDeliveryFiltered(e sqlc.ListSSFEventDeliveriesFilteredRow) EventLogView {
	createdAt := ""
	if e.CreatedAt.Valid {
		createdAt = e.CreatedAt.Time.Format("2006-01-02 15:04:05")
	}
	sentAt := ""
	if e.SentAt.Valid {
		sentAt = e.SentAt.Time.Format("2006-01-02 15:04:05")
	}

	view := EventLogView{
		ID:        uuidToString(e.ID),
		StreamID:  uuidToString(e.StreamID),
		EventType: e.EventType,
		JTI:       e.Jti,
		Status:    e.Status,
		Attempts:  e.Attempts,
		CreatedAt: createdAt,
		SentAt:    sentAt,
	}

	for _, et := range SupportedEventTypes {
		if et.URI == e.EventType {
			view.EventTypeName = et.Name
			break
		}
	}
	if view.EventTypeName == "" {
		view.EventTypeName = e.EventType
	}

	if e.SubjectIdentifier != nil {
		view.SubjectIdentifier = *e.SubjectIdentifier
	}
	if e.LastError != nil {
		view.LastError = *e.LastError
	}

	return view
}

func uuidToString(id pgtype.UUID) string {
	if !id.Valid {
		return ""
	}
	u, _ := uuid.FromBytes(id.Bytes[:])
	return u.String()
}

func (h *SSFHandler) baseData(r *http.Request) map[string]any {
	user := portal.GetCurrentUser(r.Context())
	displayName := user.Username
	if user.DisplayName != nil && *user.DisplayName != "" {
		displayName = *user.DisplayName
	}
	return map[string]any{
		"User":        user,
		"DisplayName": displayName,
		"IsAdmin":     portal.IsAdmin(r.Context()),
	}
}

func (h *SSFHandler) List(w http.ResponseWriter, r *http.Request) {
	streams, err := h.queries.ListSSFStreams(r.Context())
	if err != nil {
		http.Error(w, "Failed to list streams", http.StatusInternalServerError)
		return
	}

	views := make([]StreamView, 0, len(streams))
	for _, s := range streams {
		view := convertStream(s)
		count, _ := h.queries.CountSSFEventDeliveriesByStream(r.Context(), s.ID)
		view.EventCount = count
		views = append(views, view)
	}

	data := h.baseData(r)
	data["Streams"] = views
	data["IssuerURL"] = h.issuerURL

	_ = h.templates.ExecuteTemplate(w, "portal_ssf_list.html", data)
}

func (h *SSFHandler) New(w http.ResponseWriter, r *http.Request) {
	data := h.baseData(r)
	data["EventTypes"] = SupportedEventTypes
	_ = h.templates.ExecuteTemplate(w, "portal_ssf_create.html", data)
}

func (h *SSFHandler) Create(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	deliveryMethod := r.FormValue("delivery_method")
	endpointURL := r.FormValue("endpoint_url")
	description := r.FormValue("description")
	eventsRequested := r.Form["events_requested"]

	// Validate delivery method
	if deliveryMethod != "urn:ietf:rfc:8935" && deliveryMethod != "urn:ietf:rfc:8936" {
		http.Error(w, "Invalid delivery method", http.StatusBadRequest)
		return
	}

	// Push requires endpoint URL, Poll does not
	if deliveryMethod == "urn:ietf:rfc:8935" && endpointURL == "" {
		http.Error(w, "Endpoint URL is required for Push delivery", http.StatusBadRequest)
		return
	}
	// Clear endpoint URL for Poll delivery
	if deliveryMethod == "urn:ietf:rfc:8936" {
		endpointURL = ""
	}

	eventsDelivered := eventsRequested
	if len(eventsDelivered) == 0 {
		for _, et := range SupportedEventTypes {
			eventsDelivered = append(eventsDelivered, et.URI)
		}
	}

	var descPtr *string
	if description != "" {
		descPtr = &description
	}

	authHeader := r.FormValue("authorization_header")
	var authHeaderPtr *string
	if authHeader != "" {
		authHeaderPtr = &authHeader
	}

	// Set audience based on delivery method
	audience := []string{}
	if endpointURL != "" {
		audience = []string{endpointURL}
	}

	_, err := h.queries.CreateSSFStream(r.Context(), sqlc.CreateSSFStreamParams{
		ClientID:            nil,
		Audience:            audience,
		DeliveryMethod:      deliveryMethod,
		EndpointUrl:         endpointURL,
		AuthorizationHeader: authHeaderPtr,
		EventsRequested:     eventsRequested,
		EventsDelivered:     eventsDelivered,
		Description:         descPtr,
	})
	if err != nil {
		http.Error(w, "Failed to create stream: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/portal/ssf", http.StatusSeeOther)
}

func (h *SSFHandler) Edit(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	streamID := vars["id"]

	id, err := uuid.Parse(streamID)
	if err != nil {
		http.Error(w, "Invalid stream ID", http.StatusBadRequest)
		return
	}

	stream, err := h.queries.GetSSFStream(r.Context(), pgtype.UUID{Bytes: id, Valid: true})
	if err != nil {
		http.Error(w, "Stream not found", http.StatusNotFound)
		return
	}

	view := convertStream(stream)

	logs, _ := h.queries.ListSSFEventDeliveriesByStream(r.Context(), sqlc.ListSSFEventDeliveriesByStreamParams{
		StreamID: stream.ID,
		Limit:    10,
		Offset:   0,
	})

	logViews := make([]EventLogView, 0, len(logs))
	for _, l := range logs {
		logViews = append(logViews, convertEventDelivery(l))
	}

	selectedEvents := make(map[string]bool)
	for _, e := range stream.EventsDelivered {
		selectedEvents[e] = true
	}

	data := h.baseData(r)
	data["Stream"] = view
	data["EventTypes"] = SupportedEventTypes
	data["SelectedEvents"] = selectedEvents
	data["EventLogs"] = logViews

	_ = h.templates.ExecuteTemplate(w, "portal_ssf_edit.html", data)
}

func (h *SSFHandler) Update(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	streamID := vars["id"]

	id, err := uuid.Parse(streamID)
	if err != nil {
		http.Error(w, "Invalid stream ID", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	pgID := pgtype.UUID{Bytes: id, Valid: true}

	stream, err := h.queries.GetSSFStream(r.Context(), pgID)
	if err != nil {
		http.Error(w, "Stream not found", http.StatusNotFound)
		return
	}

	deliveryMethod := r.FormValue("delivery_method")
	endpointURL := r.FormValue("endpoint_url")
	description := r.FormValue("description")
	eventsRequested := r.Form["events_requested"]

	// Validate delivery method
	if deliveryMethod == "" {
		deliveryMethod = stream.DeliveryMethod
	}
	if deliveryMethod != "urn:ietf:rfc:8935" && deliveryMethod != "urn:ietf:rfc:8936" {
		http.Error(w, "Invalid delivery method", http.StatusBadRequest)
		return
	}

	// Push requires endpoint URL, Poll does not
	if deliveryMethod == "urn:ietf:rfc:8935" && endpointURL == "" {
		endpointURL = stream.EndpointUrl
		if endpointURL == "" {
			http.Error(w, "Endpoint URL is required for Push delivery", http.StatusBadRequest)
			return
		}
	}
	// Clear endpoint URL for Poll delivery
	if deliveryMethod == "urn:ietf:rfc:8936" {
		endpointURL = ""
	}

	eventsDelivered := eventsRequested
	if len(eventsDelivered) == 0 {
		for _, et := range SupportedEventTypes {
			eventsDelivered = append(eventsDelivered, et.URI)
		}
	}

	var descPtr *string
	if description != "" {
		descPtr = &description
	}

	authHeader := r.FormValue("authorization_header")
	var authHeaderPtr *string
	if authHeader != "" {
		authHeaderPtr = &authHeader
	}

	// Set audience based on delivery method
	audience := []string{}
	if endpointURL != "" {
		audience = []string{endpointURL}
	}

	err = h.queries.UpdateSSFStream(r.Context(), sqlc.UpdateSSFStreamParams{
		ID:                  pgID,
		Audience:            audience,
		DeliveryMethod:      deliveryMethod,
		EndpointUrl:         endpointURL,
		AuthorizationHeader: authHeaderPtr,
		EventsRequested:     eventsRequested,
		EventsDelivered:     eventsDelivered,
		Description:         descPtr,
	})
	if err != nil {
		http.Error(w, "Failed to update stream", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/portal/ssf/"+streamID, http.StatusSeeOther)
}

func (h *SSFHandler) Delete(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	streamID := vars["id"]

	id, err := uuid.Parse(streamID)
	if err != nil {
		http.Error(w, "Invalid stream ID", http.StatusBadRequest)
		return
	}

	err = h.queries.DeleteSSFStream(r.Context(), pgtype.UUID{Bytes: id, Valid: true})
	if err != nil {
		http.Error(w, "Failed to delete stream", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/portal/ssf", http.StatusSeeOther)
}

func (h *SSFHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	streamID := vars["id"]

	id, err := uuid.Parse(streamID)
	if err != nil {
		http.Error(w, "Invalid stream ID", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	status := r.FormValue("status")
	reason := r.FormValue("reason")

	if status != "enabled" && status != "paused" && status != "disabled" {
		http.Error(w, "Invalid status", http.StatusBadRequest)
		return
	}

	var reasonPtr *string
	if reason != "" {
		reasonPtr = &reason
	}

	err = h.queries.UpdateSSFStreamStatus(r.Context(), sqlc.UpdateSSFStreamStatusParams{
		ID:           pgtype.UUID{Bytes: id, Valid: true},
		Status:       status,
		StatusReason: reasonPtr,
	})
	if err != nil {
		http.Error(w, "Failed to update status", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/portal/ssf/"+streamID, http.StatusSeeOther)
}

func (h *SSFHandler) EventLogs(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit := int32(50)
	offset := int32((page - 1) * int(limit))

	statusFilter := r.URL.Query().Get("status")
	eventTypeFilter := r.URL.Query().Get("event_type")
	streamFilter := r.URL.Query().Get("stream_id")

	var streamID pgtype.UUID
	if streamFilter != "" {
		if id, err := uuid.Parse(streamFilter); err == nil {
			streamID = pgtype.UUID{Bytes: id, Valid: true}
		}
	}

	var statusPtr, eventTypePtr *string
	if statusFilter != "" {
		statusPtr = &statusFilter
	}
	if eventTypeFilter != "" {
		eventTypePtr = &eventTypeFilter
	}

	logs, err := h.queries.ListSSFEventDeliveriesFiltered(r.Context(), sqlc.ListSSFEventDeliveriesFilteredParams{
		StreamID:  streamID,
		Status:    statusPtr,
		EventType: eventTypePtr,
		Limit:     limit,
		Offset:    offset,
	})
	if err != nil {
		http.Error(w, "Failed to list event logs", http.StatusInternalServerError)
		return
	}

	total, _ := h.queries.CountSSFEventDeliveriesFiltered(r.Context(), sqlc.CountSSFEventDeliveriesFilteredParams{
		StreamID:  streamID,
		Status:    statusPtr,
		EventType: eventTypePtr,
	})

	views := make([]EventLogView, 0, len(logs))
	for _, l := range logs {
		views = append(views, convertEventDeliveryFiltered(l))
	}

	streams, _ := h.queries.ListSSFStreams(r.Context())
	streamViews := make([]StreamView, 0, len(streams))
	for _, s := range streams {
		streamViews = append(streamViews, convertStream(s))
	}

	stats, _ := h.queries.GetSSFDeliveryStats(r.Context())

	totalPages := int((total + int64(limit) - 1) / int64(limit))
	pages := make([]int, totalPages)
	for i := range pages {
		pages[i] = i + 1
	}

	data := h.baseData(r)
	data["EventLogs"] = views
	data["Streams"] = streamViews
	data["EventTypes"] = SupportedEventTypes
	data["StatusFilter"] = statusFilter
	data["EventTypeFilter"] = eventTypeFilter
	data["StreamFilter"] = streamFilter
	data["CurrentPage"] = page
	data["TotalPages"] = totalPages
	data["TotalEvents"] = total
	data["ShowPagination"] = totalPages > 1
	data["HasPrevPage"] = page > 1
	data["HasNextPage"] = page < totalPages
	data["PrevPage"] = page - 1
	data["NextPage"] = page + 1
	data["Pages"] = pages
	data["Stats"] = map[string]int64{
		"Total":   stats.TotalDeliveries,
		"Sent":    stats.SentCount,
		"Failed":  stats.FailedCount,
		"Pending": stats.PendingCount,
	}

	_ = h.templates.ExecuteTemplate(w, "portal_ssf_log.html", data)
}

func (h *SSFHandler) SendVerification(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	streamID := vars["id"]

	id, err := uuid.Parse(streamID)
	if err != nil {
		http.Error(w, "Invalid stream ID", http.StatusBadRequest)
		return
	}

	stream, err := h.queries.GetSSFStream(r.Context(), pgtype.UUID{Bytes: id, Valid: true})
	if err != nil {
		http.Error(w, "Stream not found", http.StatusNotFound)
		return
	}

	if stream.Status != "enabled" {
		http.Error(w, "Stream is not enabled", http.StatusConflict)
		return
	}

	state := time.Now().Format("20060102150405")

	// Build proper SET with verification event
	eventType := "https://schemas.openid.net/secevent/ssf/event-type/verification"
	verificationEvent := map[string]interface{}{
		"state": state,
	}

	set := ssf.NewSET(h.issuerURL, stream.Audience, eventType, verificationEvent)
	// Use opaque format with stream_id as identifier for verification events
	set.SubID = &ssf.SubID{
		Format: "opaque",
		ID:     streamID,
	}

	// Sign JWT token
	setToken, err := set.ToJWT(h.privateKey, h.keyID)
	if err != nil {
		http.Error(w, "Failed to sign verification event", http.StatusInternalServerError)
		return
	}

	payload, err := json.Marshal(set)
	if err != nil {
		http.Error(w, "Failed to create verification event", http.StatusInternalServerError)
		return
	}

	// Create event record
	ssfEvent, err := h.queries.CreateSSFEvent(r.Context(), sqlc.CreateSSFEventParams{
		EventType:         eventType,
		SubjectIdentifier: nil,
		Payload:           payload,
	})
	if err != nil {
		http.Error(w, "Failed to create event", http.StatusInternalServerError)
		return
	}

	// Create delivery record
	_, err = h.queries.CreateSSFEventDelivery(r.Context(), sqlc.CreateSSFEventDeliveryParams{
		EventID:  ssfEvent.ID,
		StreamID: stream.ID,
		Jti:      set.JTI,
		SetToken: setToken,
		Status:   "queued",
	})
	if err != nil {
		http.Error(w, "Failed to create delivery", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/portal/ssf/"+streamID+"?verification=sent&state="+state, http.StatusSeeOther)
}

func (h *SSFHandler) SendTestEvent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	streamID := vars["id"]

	if h.ssfAPIHandler == nil {
		http.Error(w, "SSF API handler not configured", http.StatusInternalServerError)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	eventType := r.FormValue("event_type")
	subject := r.FormValue("subject")

	validEventType := false
	for _, et := range SupportedEventTypes {
		if et.URI == eventType {
			validEventType = true
			break
		}
	}
	if !validEventType {
		http.Error(w, "Invalid event type", http.StatusBadRequest)
		return
	}

	// Look up user by username to get their actual sub (UUID) for proper SSF subject identification
	var subjectID string
	if subject != "" {
		user, err := h.queries.GetUserByUsername(r.Context(), subject)
		if err != nil {
			http.Error(w, "User not found: "+subject, http.StatusBadRequest)
			return
		}
		subjectID = uuidToString(user.ID)
	}

	// Build event data
	eventData := map[string]any{
		"event_timestamp": time.Now().Unix(),
	}

	// Use EmitEventToStream for proper Push/Poll delivery
	result, err := h.ssfAPIHandler.EmitEventToStream(r.Context(), streamID, eventType, subjectID, eventData)
	if err != nil {
		http.Error(w, "Failed to send test event: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if result.SuccessCount == 0 {
		errMsg := result.Error
		if errMsg == "" {
			errMsg = "unknown error"
		}
		http.Error(w, "Failed to deliver test event: "+errMsg, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/portal/ssf/"+streamID+"?test_event=sent", http.StatusSeeOther)
}
