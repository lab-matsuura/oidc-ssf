package driver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// SetupConfig contains configuration for test data setup
type SetupConfig struct {
	RPCount      int    // Number of RPs (streams) to create
	UserCount    int    // Number of users to create
	ReceiverURL  string // Base URL of Mock SET Receiver
	DeliveryMode string // "push" or "poll"
	IdPURL       string // IdP URL for token acquisition
	TokensFile   string // Path to save tokens file
}

// SetupResult contains the result of setup
type SetupResult struct {
	UserIDs      []string
	StreamIDs    []string
	StreamTokens map[string]string // stream_id -> access_token
}

// BenchmarkClient represents a benchmark OAuth client
type BenchmarkClient struct {
	ID     string
	Secret string
}

// SetupTestData creates test data for benchmarking
func SetupTestData(ctx context.Context, db *sql.DB, cfg SetupConfig) (*SetupResult, error) {
	log.Printf("Setting up test data: %d RPs, %d users, mode=%s", cfg.RPCount, cfg.UserCount, cfg.DeliveryMode)

	// Clean existing benchmark data
	if err := cleanBenchmarkData(ctx, db); err != nil {
		return nil, fmt.Errorf("failed to clean data: %w", err)
	}

	// Create benchmark users
	userIDs, err := createBenchmarkUsers(ctx, db, cfg.UserCount)
	if err != nil {
		return nil, fmt.Errorf("failed to create users: %w", err)
	}
	log.Printf("Created %d users", len(userIDs))

	// Create benchmark OAuth clients (one per RP)
	clients, err := createBenchmarkClients(ctx, db, cfg.RPCount)
	if err != nil {
		return nil, fmt.Errorf("failed to create clients: %w", err)
	}
	log.Printf("Created %d OAuth clients", len(clients))

	// Create benchmark streams with client_id
	streamIDs, err := createBenchmarkStreams(ctx, db, cfg, clients)
	if err != nil {
		return nil, fmt.Errorf("failed to create streams: %w", err)
	}
	log.Printf("Created %d streams", len(streamIDs))

	// Get access tokens for each client
	streamTokens, err := getTokensForClients(ctx, cfg.IdPURL, clients, streamIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to get tokens: %w", err)
	}
	log.Printf("Acquired %d access tokens", len(streamTokens))

	// Save tokens to file
	if cfg.TokensFile != "" {
		if err := saveTokensToFile(streamTokens, cfg.TokensFile); err != nil {
			return nil, fmt.Errorf("failed to save tokens: %w", err)
		}
		log.Printf("Tokens saved to %s", cfg.TokensFile)
	}

	// Register all users to all streams
	if err := registerSubjects(ctx, db, streamIDs, userIDs); err != nil {
		return nil, fmt.Errorf("failed to register subjects: %w", err)
	}
	log.Printf("Registered %d subjects to %d streams", len(userIDs), len(streamIDs))

	return &SetupResult{
		UserIDs:      userIDs,
		StreamIDs:    streamIDs,
		StreamTokens: streamTokens,
	}, nil
}

func cleanBenchmarkData(ctx context.Context, db *sql.DB) error {
	queries := []string{
		`DELETE FROM ssf_event_deliveries WHERE stream_id IN (SELECT id FROM ssf_streams WHERE endpoint_url LIKE '%benchmark%' OR endpoint_url LIKE '%:9090%')`,
		`DELETE FROM ssf_stream_subjects WHERE stream_id IN (SELECT id FROM ssf_streams WHERE endpoint_url LIKE '%benchmark%' OR endpoint_url LIKE '%:9090%')`,
		`DELETE FROM ssf_streams WHERE endpoint_url LIKE '%benchmark%' OR endpoint_url LIKE '%:9090%'`,
		`DELETE FROM users WHERE username LIKE 'bench_user_%'`,
		`DELETE FROM clients WHERE id LIKE 'bench_client_%'`,
	}

	for _, q := range queries {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func createBenchmarkUsers(ctx context.Context, db *sql.DB, count int) ([]string, error) {
	userIDs := make([]string, count)

	for i := 0; i < count; i++ {
		id := uuid.New().String()
		username := fmt.Sprintf("bench_user_%d", i)
		email := fmt.Sprintf("bench_user_%d@benchmark.local", i)

		_, err := db.ExecContext(ctx, `
			INSERT INTO users (id, username, email, password_hash, account_status, role)
			VALUES ($1, $2, $3, 'benchmark', 'active', 'user')
		`, id, username, email)
		if err != nil {
			return nil, err
		}
		userIDs[i] = id // Use UUID as subject identifier
	}

	return userIDs, nil
}

func createBenchmarkClients(ctx context.Context, db *sql.DB, count int) ([]BenchmarkClient, error) {
	clients := make([]BenchmarkClient, count)

	for i := 0; i < count; i++ {
		clientID := fmt.Sprintf("bench_client_%d", i)
		clientSecret := fmt.Sprintf("bench_secret_%d", i)

		// Hash the secret with bcrypt
		hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash secret: %w", err)
		}

		_, err = db.ExecContext(ctx, `
			INSERT INTO clients (id, secret, redirect_uris, grant_types, response_types, scopes, public)
			VALUES ($1, $2, '[]', '["client_credentials"]', '["token"]', '["openid","ssf:manage"]', false)
		`, clientID, hashedSecret)
		if err != nil {
			return nil, err
		}

		clients[i] = BenchmarkClient{
			ID:     clientID,
			Secret: clientSecret,
		}
	}

	return clients, nil
}

func createBenchmarkStreams(ctx context.Context, db *sql.DB, cfg SetupConfig, clients []BenchmarkClient) ([]string, error) {
	streamIDs := make([]string, cfg.RPCount)

	deliveryMethod := "urn:ietf:rfc:8935" // Push
	if cfg.DeliveryMode == "poll" {
		deliveryMethod = "urn:ietf:rfc:8936" // Poll
	}

	for i := 0; i < cfg.RPCount; i++ {
		id := uuid.New().String()
		endpointURL := fmt.Sprintf("%s/rp/rp_%d/receiver", cfg.ReceiverURL, i)
		clientID := clients[i].ID

		_, err := db.ExecContext(ctx, `
			INSERT INTO ssf_streams (id, client_id, endpoint_url, delivery_method, status, events_requested, events_delivered, audience)
			VALUES ($1, $2, $3, $4, 'enabled',
				ARRAY['https://schemas.openid.net/secevent/caep/event-type/session-revoked'],
				ARRAY['https://schemas.openid.net/secevent/caep/event-type/session-revoked'],
				ARRAY[$5])
		`, id, clientID, endpointURL, deliveryMethod, clientID)
		if err != nil {
			return nil, err
		}
		streamIDs[i] = id
	}

	return streamIDs, nil
}

func getTokensForClients(ctx context.Context, idpURL string, clients []BenchmarkClient, streamIDs []string) (map[string]string, error) {
	streamTokens := make(map[string]string)
	tokenURL := idpURL + "/token"

	httpClient := &http.Client{}

	for i, client := range clients {
		streamID := streamIDs[i]

		// Prepare client_credentials request
		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("scope", "openid ssf:manage")

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(client.ID, client.Secret)

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to request token for %s: %w", client.ID, err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("token request failed for %s: HTTP %d: %s", client.ID, resp.StatusCode, string(body))
		}

		var tokenResp struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			return nil, fmt.Errorf("failed to decode token response: %w", err)
		}

		streamTokens[streamID] = tokenResp.AccessToken
	}

	return streamTokens, nil
}

func saveTokensToFile(streamTokens map[string]string, filePath string) error {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := json.MarshalIndent(streamTokens, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// LoadTokensFromFile loads stream tokens from a JSON file
func LoadTokensFromFile(filePath string) (map[string]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var streamTokens map[string]string
	if err := json.Unmarshal(data, &streamTokens); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tokens: %w", err)
	}

	return streamTokens, nil
}

func registerSubjects(ctx context.Context, db *sql.DB, streamIDs, userIDs []string) error {
	// Batch insert for efficiency
	for _, streamID := range streamIDs {
		for _, userID := range userIDs {
			_, err := db.ExecContext(ctx, `
				INSERT INTO ssf_stream_subjects (stream_id, subject_format, subject_identifier, verified)
				VALUES ($1, 'iss_sub', $2, true)
				ON CONFLICT DO NOTHING
			`, streamID, userID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// CleanupTestData removes all benchmark test data
func CleanupTestData(ctx context.Context, db *sql.DB) error {
	return cleanBenchmarkData(ctx, db)
}
