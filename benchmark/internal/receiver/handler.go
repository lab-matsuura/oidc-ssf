package receiver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ReceiveLog represents a single SET reception record
type ReceiveLog struct {
	JTI         string `json:"jti"`
	RPID        string `json:"rp_id"`
	ReceiveTime int64  `json:"receive_time_us"` // microseconds since epoch
	IATTime     int64  `json:"iat_time_us"`     // iat from SET in microseconds
	LatencyUS   int64  `json:"latency_us"`      // receive_time - iat in microseconds
}

// Handler handles incoming SET deliveries
type Handler struct {
	mu       sync.Mutex
	logFile  *os.File
	encoder  *json.Encoder
	received int64
}

// NewHandler creates a new receiver handler
// If logPath is empty, outputs to stdout (for Cloud Logging)
func NewHandler(logPath string) (*Handler, error) {
	h := &Handler{}

	if logPath != "" {
		// Local mode: write to file
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		h.logFile = f
		h.encoder = json.NewEncoder(f)
	}
	// Cloud mode: logFile remains nil, will write to stdout

	return h, nil
}

// Close closes the log file
func (h *Handler) Close() error {
	if h.logFile != nil {
		return h.logFile.Close()
	}
	return nil
}

// ServeHTTP handles POST /rp/{rp_id}/receiver
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	receiveTime := time.Now().UnixMicro()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract rp_id from path: /rp/{rp_id}/receiver
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "rp" || parts[2] != "receiver" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	rpID := parts[1]

	// Read JWT body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// Parse JWT to extract jti and iat
	jti, iat, err := extractJTIAndIAT(string(body))
	if err != nil {
		log.Printf("Warning: failed to parse JWT: %v", err)
		http.Error(w, "Invalid JWT", http.StatusBadRequest)
		return
	}

	// Calculate latency
	iatMicro := iat * 1_000_000 // seconds to microseconds
	latency := receiveTime - iatMicro

	// Log the reception
	logEntry := ReceiveLog{
		JTI:         jti,
		RPID:        rpID,
		ReceiveTime: receiveTime,
		IATTime:     iatMicro,
		LatencyUS:   latency,
	}

	h.mu.Lock()
	if h.logFile != nil {
		// Local mode: write to file
		_ = h.encoder.Encode(logEntry)
	} else {
		// Cloud mode: write to stdout for Cloud Logging
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"severity": "INFO",
			"message":  "SET_RECEIVED",
			"data":     logEntry,
		})
	}
	h.received++
	count := h.received
	h.mu.Unlock()

	if count%1000 == 0 {
		log.Printf("Received %d SETs", count)
	}

	w.WriteHeader(http.StatusAccepted)
}

// GetReceivedCount returns the number of received SETs
func (h *Handler) GetReceivedCount() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.received
}

// extractJTIAndIAT extracts jti and iat from a JWT without verification
func extractJTIAndIAT(jwt string) (string, int64, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", 0, fmt.Errorf("invalid JWT format")
	}

	// Decode payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims struct {
		JTI string `json:"jti"`
		IAT int64  `json:"iat"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", 0, fmt.Errorf("failed to parse claims: %w", err)
	}

	return claims.JTI, claims.IAT, nil
}
