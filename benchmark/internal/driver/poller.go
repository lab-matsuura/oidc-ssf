package driver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PollConfig contains configuration for poll benchmarking
type PollConfig struct {
	IdPURL       string            // IdP base URL
	StreamTokens map[string]string // stream_id -> access_token
	Timeout      time.Duration     // Total polling timeout
	LogPath      string            // Path to write receive logs
}

// PollResult contains the poll benchmark result
type PollResult struct {
	TotalStreams  int
	TotalReceived int64
	TotalPolls    int64
	StartTime     time.Time
	EndTime       time.Time
	DurationMS    int64
}

// PollLog represents a single poll receive record (same format as ReceiveLog)
type PollLog struct {
	JTI         string `json:"jti"`
	StreamID    string `json:"stream_id"`
	ReceiveTime int64  `json:"receive_time_us"`
	IATTime     int64  `json:"iat_time_us"`
	LatencyUS   int64  `json:"latency_us"`
}

// RunPollBenchmark starts Long Polling on all streams and records received SETs
func RunPollBenchmark(ctx context.Context, cfg PollConfig) (*PollResult, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}

	result := &PollResult{
		TotalStreams: len(cfg.StreamTokens),
		StartTime:    time.Now(),
	}

	// Open log file
	logFile, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	defer func() { _ = logFile.Close() }()

	var mu sync.Mutex
	encoder := json.NewEncoder(logFile)

	var received, polls int64
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: cfg.Timeout + 10*time.Second, // Extra buffer for network
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: len(cfg.StreamTokens),
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Context with timeout
	pollCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	log.Printf("Starting Long Polling on %d streams (timeout=%v)", len(cfg.StreamTokens), cfg.Timeout)

	for streamID, token := range cfg.StreamTokens {
		wg.Add(1)
		go func(streamID, token string) {
			defer wg.Done()

			var pendingAcks []string // JTIs to ACK in the next poll

			for {
				select {
				case <-pollCtx.Done():
					return
				default:
				}

				sets, err := pollOnce(pollCtx, client, cfg.IdPURL, token, streamID, pendingAcks)
				atomic.AddInt64(&polls, 1)
				pendingAcks = nil // Clear after sending

				if err != nil {
					if pollCtx.Err() != nil {
						return // Context cancelled, exit gracefully
					}
					log.Printf("Poll error on stream %s: %v", streamID, err)
					time.Sleep(100 * time.Millisecond)
					continue
				}

				if len(sets) > 0 {
					receiveTime := time.Now().UnixMicro()

					mu.Lock()
					for jti, token := range sets {
						iat, err := extractIATFromJWT(token)
						if err != nil {
							continue
						}

						iatMicro := iat * 1_000_000
						latency := receiveTime - iatMicro

						entry := PollLog{
							JTI:         jti,
							StreamID:    streamID,
							ReceiveTime: receiveTime,
							IATTime:     iatMicro,
							LatencyUS:   latency,
						}
						_ = encoder.Encode(entry)
						atomic.AddInt64(&received, 1)

						// Queue for ACK in next poll
						pendingAcks = append(pendingAcks, jti)
					}
					mu.Unlock()

					currentReceived := atomic.LoadInt64(&received)
					if currentReceived%100 == 0 {
						log.Printf("Poll received: %d SETs", currentReceived)
					}
				}
			}
		}(streamID, token)
	}

	wg.Wait()

	result.EndTime = time.Now()
	result.TotalReceived = received
	result.TotalPolls = polls
	result.DurationMS = result.EndTime.Sub(result.StartTime).Milliseconds()

	return result, nil
}

func pollOnce(ctx context.Context, client *http.Client, idpURL, accessToken, streamID string, acks []string) (map[string]string, error) {
	url := fmt.Sprintf("%s/ssf/poll/%s", idpURL, streamID)

	payload := map[string]any{
		"returnImmediately": false, // Long polling
		"maxEvents":         100,
	}
	if len(acks) > 0 {
		payload["ack"] = acks
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Sets          map[string]string `json:"sets"`
		MoreAvailable bool              `json:"moreAvailable"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Sets, nil
}

// extractIATFromJWT extracts iat claim from a JWT without verification
func extractIATFromJWT(jwt string) (int64, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return 0, fmt.Errorf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims struct {
		IAT int64 `json:"iat"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, fmt.Errorf("failed to parse claims: %w", err)
	}

	return claims.IAT, nil
}
