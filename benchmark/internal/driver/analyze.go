package driver

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// ReceiveLog matches the receiver's log format
type ReceiveLog struct {
	JTI         string `json:"jti"`
	RPID        string `json:"rp_id"`
	ReceiveTime int64  `json:"receive_time_us"`
	IATTime     int64  `json:"iat_time_us"`
	LatencyUS   int64  `json:"latency_us"`
}

// AnalysisResult contains the analysis results
type AnalysisResult struct {
	TotalReceived int `json:"total_received"`
	UniqueJTIs    int `json:"unique_jtis"`
	UniqueRPs     int `json:"unique_rps"`

	// Latency stats in milliseconds
	LatencyP50MS  float64 `json:"latency_p50_ms"`
	LatencyP95MS  float64 `json:"latency_p95_ms"`
	LatencyP99MS  float64 `json:"latency_p99_ms"`
	LatencyMinMS  float64 `json:"latency_min_ms"`
	LatencyMaxMS  float64 `json:"latency_max_ms"`
	LatencyMeanMS float64 `json:"latency_mean_ms"`

	// Timing
	FirstReceiveUS int64   `json:"first_receive_us"`
	LastReceiveUS  int64   `json:"last_receive_us"`
	DurationMS     float64 `json:"duration_ms"`

	// Throughput
	ThroughputPerSec float64 `json:"throughput_per_sec"`
}

// AnalyzeResults reads the receive log and computes statistics
func AnalyzeResults(logPath string) (*AnalysisResult, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var logs []ReceiveLog
	jtis := make(map[string]bool)
	rps := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var log ReceiveLog
		if err := json.Unmarshal(scanner.Bytes(), &log); err != nil {
			continue // Skip invalid lines
		}
		logs = append(logs, log)
		jtis[log.JTI] = true
		rps[log.RPID] = true
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read log file: %w", err)
	}

	if len(logs) == 0 {
		return &AnalysisResult{}, nil
	}

	// Extract latencies
	latencies := make([]int64, len(logs))
	var sum int64
	firstReceive, lastReceive := logs[0].ReceiveTime, logs[0].ReceiveTime

	for i, log := range logs {
		latencies[i] = log.LatencyUS
		sum += log.LatencyUS
		if log.ReceiveTime < firstReceive {
			firstReceive = log.ReceiveTime
		}
		if log.ReceiveTime > lastReceive {
			lastReceive = log.ReceiveTime
		}
	}

	// Sort for percentiles
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	result := &AnalysisResult{
		TotalReceived:  len(logs),
		UniqueJTIs:     len(jtis),
		UniqueRPs:      len(rps),
		LatencyMinMS:   float64(latencies[0]) / 1000,
		LatencyMaxMS:   float64(latencies[len(latencies)-1]) / 1000,
		LatencyMeanMS:  float64(sum) / float64(len(latencies)) / 1000,
		LatencyP50MS:   float64(percentile(latencies, 50)) / 1000,
		LatencyP95MS:   float64(percentile(latencies, 95)) / 1000,
		LatencyP99MS:   float64(percentile(latencies, 99)) / 1000,
		FirstReceiveUS: firstReceive,
		LastReceiveUS:  lastReceive,
		DurationMS:     float64(lastReceive-firstReceive) / 1000,
	}

	if result.DurationMS > 0 {
		result.ThroughputPerSec = float64(len(logs)) * 1000 / result.DurationMS
	}

	return result, nil
}

func percentile(sorted []int64, p int) int64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := (len(sorted) - 1) * p / 100
	return sorted[idx]
}

// PrintAnalysisResult prints the analysis result in a formatted way
func PrintAnalysisResult(r *AnalysisResult) {
	fmt.Println("=== Benchmark Results ===")
	fmt.Printf("Total Received:    %d SETs\n", r.TotalReceived)
	fmt.Printf("Unique JTIs:       %d\n", r.UniqueJTIs)
	fmt.Printf("Unique RPs:        %d\n", r.UniqueRPs)
	fmt.Println()
	fmt.Println("Latency (ms):")
	fmt.Printf("  Min:    %.2f\n", r.LatencyMinMS)
	fmt.Printf("  P50:    %.2f\n", r.LatencyP50MS)
	fmt.Printf("  P95:    %.2f\n", r.LatencyP95MS)
	fmt.Printf("  P99:    %.2f\n", r.LatencyP99MS)
	fmt.Printf("  Max:    %.2f\n", r.LatencyMaxMS)
	fmt.Printf("  Mean:   %.2f\n", r.LatencyMeanMS)
	fmt.Println()
	fmt.Printf("Duration:          %.2f ms\n", r.DurationMS)
	fmt.Printf("Throughput:        %.2f SETs/sec\n", r.ThroughputPerSec)
}
