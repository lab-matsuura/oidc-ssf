package driver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// EmitConfig contains configuration for event emission
type EmitConfig struct {
	IdPURL      string   // IdP base URL
	UserIDs     []string // List of user IDs to emit events for
	Concurrency int      // Number of concurrent emitters
}

// EmitResult contains the result of event emission
type EmitResult struct {
	TotalUsers   int
	TotalEmitted int64
	TotalFailed  int64
	StartTime    time.Time
	EndTime      time.Time
	DurationMS   int64
	EventsPerSec float64
}

// EmitEvents emits session-revoked events for all users
func EmitEvents(ctx context.Context, cfg EmitConfig) (*EmitResult, error) {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}

	result := &EmitResult{
		TotalUsers: len(cfg.UserIDs),
		StartTime:  time.Now(),
	}

	var emitted, failed int64
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, cfg.Concurrency)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: cfg.Concurrency,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	log.Printf("Emitting events for %d users (concurrency=%d)", len(cfg.UserIDs), cfg.Concurrency)

emitLoop:
	for i, userID := range cfg.UserIDs {
		select {
		case <-ctx.Done():
			break emitLoop
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(userID string, idx int) {
			defer wg.Done()
			defer func() { <-semaphore }()

			if err := emitSessionRevoked(ctx, client, cfg.IdPURL, userID); err != nil {
				atomic.AddInt64(&failed, 1)
				if atomic.LoadInt64(&failed) <= 10 {
					log.Printf("Failed to emit for user %s: %v", userID, err)
				}
			} else {
				atomic.AddInt64(&emitted, 1)
			}

			if (idx+1)%1000 == 0 {
				log.Printf("Progress: %d/%d emitted", atomic.LoadInt64(&emitted), len(cfg.UserIDs))
			}
		}(userID, i)
	}

	wg.Wait()

	result.EndTime = time.Now()
	result.TotalEmitted = emitted
	result.TotalFailed = failed
	result.DurationMS = result.EndTime.Sub(result.StartTime).Milliseconds()
	if result.DurationMS > 0 {
		result.EventsPerSec = float64(emitted) * 1000 / float64(result.DurationMS)
	}

	return result, nil
}

func emitSessionRevoked(ctx context.Context, client *http.Client, idpURL, userID string) error {
	// Use internal emit endpoint (no auth required)
	url := fmt.Sprintf("%s/ssf/internal/emit", idpURL)

	payload := map[string]interface{}{
		"event_type": "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
		"subject_id": userID,
		"event_data": map[string]interface{}{
			"reason_admin": "benchmark_test",
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
