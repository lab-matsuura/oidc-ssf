package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"github.com/lab-matsuura/oidc-ssf/pkg/ssf"
	"github.com/lab-matsuura/oidc-ssf/rp/internal/service"
)

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

// SSFHandler handles SSF-related endpoints for the client
type SSFHandler struct {
	Receiver       *ssf.Receiver
	SessionService *service.SessionService
	UserService    *service.UserService
	ExpectedToken  string // Expected authorization header for Push delivery validation
}

// NewSSFHandler creates a new SSF handler for the client
func NewSSFHandler(sessionService *service.SessionService, userService *service.UserService) *SSFHandler {
	handler := &SSFHandler{
		Receiver:       ssf.NewReceiver(&ssf.ReceiverConfig{}),
		SessionService: sessionService,
		UserService:    userService,
		ExpectedToken:  os.Getenv("SSF_RECEIVER_TOKEN"), // Optional: validate Push delivery auth
	}

	if handler.ExpectedToken != "" {
		log.Printf("SSF: Authorization header validation enabled")
	} else {
		log.Printf("SSF: Authorization header validation disabled (set SSF_RECEIVER_TOKEN to enable)")
	}

	// Register event handlers with access to session service
	handler.Receiver.RegisterEventHandler(ssf.EventTypeSessionRevoked, handler.handleSessionRevoked)
	handler.Receiver.RegisterEventHandler(ssf.EventTypeCredentialChange, handler.handleCredentialChange)
	handler.Receiver.RegisterEventHandler(ssf.EventTypeTokenClaimsChange, handler.handleTokenClaimsChange)
	handler.Receiver.RegisterEventHandler(ssf.EventTypeAccountDisabled, handler.handleAccountDisabled)
	handler.Receiver.RegisterDefaultHandler(handler.handleDefaultEvent)

	return handler
}

// SetProviderPublicKey sets the provider's public key for SET verification
// In a real implementation, this would fetch the key from JWKS endpoint
func (h *SSFHandler) SetProviderPublicKey() {
	// For demo purposes, we'll skip signature verification
	// In production, you would fetch the key from the provider's JWKS endpoint
	log.Println("SSF: Public key verification disabled for demo")
}

// RegisterRoutes registers SSF-related routes
func (h *SSFHandler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/ssf/receiver", h.HandleReceiveSET).Methods("POST", "OPTIONS")
}

// HandleReceiveSET handles incoming SETs
func (h *SSFHandler) HandleReceiveSET(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// Handle preflight
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Validate authorization header if configured
	if h.ExpectedToken != "" {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Printf("SSF: Missing Authorization header")
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Missing Authorization header")
			return
		}
		if authHeader != h.ExpectedToken {
			log.Printf("SSF: Invalid Authorization header")
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "Invalid authorization token")
			return
		}
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("SSF: Failed to read request body: %v", err)
		writeProblem(w, http.StatusBadRequest, "Bad Request", "Failed to read request body")
		return
	}

	// Determine SET token based on Content-Type
	var setToken string
	contentType := r.Header.Get("Content-Type")

	if strings.HasPrefix(contentType, "application/secevent+jwt") {
		// RFC 8935: Raw JWT in body
		setToken = string(body)
	} else {
		// Legacy: JSON format {"set": "<jwt>"}
		var req struct {
			SET string `json:"set"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			log.Printf("SSF: Failed to decode request: %v", err)
			writeProblem(w, http.StatusBadRequest, "Bad Request", "Invalid request body")
			return
		}
		setToken = req.SET
	}

	if setToken == "" {
		log.Printf("SSF: Empty SET token")
		writeProblem(w, http.StatusBadRequest, "Bad Request", "Missing SET token")
		return
	}

	// Process the SET
	received, err := h.Receiver.ReceiveSET(setToken)
	if err != nil {
		log.Printf("SSF: Failed to process SET: %v", err)
		// Check for duplicate JTI error
		if errors.Is(err, ssf.ErrDuplicateJTI) {
			writeProblem(w, http.StatusConflict, "Conflict", "Duplicate JTI: this SET has already been received")
			return
		}
		writeProblem(w, http.StatusBadRequest, "Bad Request", fmt.Sprintf("Failed to process SET: %v", err))
		return
	}

	log.Printf("SSF: Successfully received SET (JTI: %s) with events: %v",
		received.SET.JTI, received.SET.Events)

	// RFC 8935: Return 202 Accepted with empty body
	w.WriteHeader(http.StatusAccepted)
}

// Event handlers

func (h *SSFHandler) handleSessionRevoked(eventType string, event any, set *ssf.SET) error {
	log.Printf("SESSION REVOKED: Event: %+v, SET JTI: %s", event, set.JTI)

	// Extract username from SET or event subject
	userSub := set.SubjectIdentifier()
	if userSub == "" {
		log.Printf("SESSION REVOKED: No user identifier found in event")
		return nil
	}

	// Revoke all sessions for this user
	count, err := h.SessionService.RevokeSessionsByUserSub(context.Background(), userSub)
	if err != nil {
		log.Printf("Error revoking sessions for user %s: %v", userSub, err)
		return err
	}
	log.Printf("Revoked %d sessions for user: %s", count, userSub)

	return nil
}

func (h *SSFHandler) handleCredentialChange(eventType string, event any, set *ssf.SET) error {
	log.Printf("CREDENTIAL CHANGE: Event: %+v, SET JTI: %s", event, set.JTI)

	// Extract username from SET or event subject
	userSub := set.SubjectIdentifier()
	if userSub == "" {
		log.Printf("CREDENTIAL CHANGE: No user identifier found in event")
		return nil
	}

	// Revoke all sessions for this user
	count, err := h.SessionService.RevokeSessionsByUserSub(context.Background(), userSub)
	if err != nil {
		log.Printf("Error revoking sessions for user %s: %v", userSub, err)
		return err
	}
	log.Printf("Revoked %d sessions for user %s due to credential change", count, userSub)

	return nil
}

func (h *SSFHandler) handleTokenClaimsChange(eventType string, event any, set *ssf.SET) error {
	log.Printf("TOKEN CLAIMS CHANGE: Event: %+v, SET JTI: %s", event, set.JTI)

	eventMap, ok := event.(map[string]interface{})
	if !ok {
		return nil
	}

	// Extract user sub from SET or event subject
	userSub := set.SubjectIdentifier()
	if userSub == "" {
		log.Printf("TOKEN CLAIMS CHANGE: No user identifier found in event")
		return nil
	}

	// Extract new role from claims and update user
	if claims, ok := eventMap["claims"].(map[string]interface{}); ok {
		if newRole, ok := claims["role"].(string); ok {
			err := h.UserService.UpdateUserRole(context.Background(), userSub, newRole)
			if err != nil {
				log.Printf("Error updating role for user %s: %v", userSub, err)
				return err
			}
			log.Printf("Updated role to '%s' for user: %s", newRole, userSub)
		}
	}

	return nil
}

func (h *SSFHandler) handleAccountDisabled(eventType string, event any, set *ssf.SET) error {
	log.Printf("ACCOUNT DISABLED: Event: %+v, SET JTI: %s", event, set.JTI)

	// Extract username from SET or event subject
	userSub := set.SubjectIdentifier()
	if userSub == "" {
		log.Printf("ACCOUNT DISABLED: No user identifier found in event")
		return nil
	}

	// Revoke all sessions for this disabled user
	count, err := h.SessionService.RevokeSessionsByUserSub(context.Background(), userSub)
	if err != nil {
		log.Printf("Error revoking sessions for disabled user %s: %v", userSub, err)
		return err
	}
	log.Printf("Revoked %d sessions for disabled user: %s", count, userSub)

	return nil
}

func (h *SSFHandler) handleDefaultEvent(eventType string, event any, set *ssf.SET) error {
	log.Printf("RECEIVED EVENT: Type: %s, Event: %+v, SET JTI: %s", eventType, event, set.JTI)
	return nil
}
